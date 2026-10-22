import Darwin
import Foundation
import OSLog

/// A key the agent offers, as `ssh-add -L` lists it.
public struct SSHIdentity: Sendable, Hashable {
    public let keyBlob: Data
    public let comment: String

    public init(keyBlob: Data, comment: String) {
        self.keyBlob = keyBlob
        self.comment = comment
    }
}

/// Decides what each SSH client sees and may sign.
public protocol SSHAgentHandler: Sendable {
    func identities(client: SSHClient, session: SSHSession, connection: UUID) async -> [SSHIdentity]
    /// The signature in SSH wire format, or nil to refuse.
    func sign(keyBlob: Data, data: Data, flags: UInt32, client: SSHClient, session: SSHSession, connection: UUID) async -> Data?
    func connectionClosed(_ connection: UUID) async
}

/// An ssh-agent on a Unix socket, speaking the protocol `ssh`, `git` and
/// `ssh-add` use (draft-miller-ssh-agent): listing keys and signing.
///
/// It uses plain POSIX sockets rather than Network.framework so it can ask
/// the kernel which process connected, and only serves the user's own processes.
public final class SSHAgentServer: @unchecked Sendable {
    public enum Status: Equatable, Sendable {
        case stopped
        case listening
        case failed(String)
    }

    private static let logger = Logger(subsystem: "io.github.grievouz.deskwarden", category: "ssh-agent")

    public let socketPath: String
    private let handler: SSHAgentHandler
    private let knownHosts: URL
    private let queue = DispatchQueue(label: "io.github.grievouz.deskwarden.ssh-agent")

    // Only touched on `queue`.
    private var acceptSource: DispatchSourceRead?
    private var connections: [UUID: SSHAgentConnection] = [:]

    public var onStatusChange: (@Sendable (Status) -> Void)?

    /// `knownHosts` names servers in prompts; ~/.ssh/known_hosts by default.
    public init(socketPath: String, handler: SSHAgentHandler, knownHosts: URL? = nil) {
        self.socketPath = socketPath
        self.handler = handler
        self.knownHosts = knownHosts ?? KnownHosts.defaultFile
    }

    public static var defaultSocketPath: String {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".deskwarden/ssh-agent.sock").path
    }

    public func start() {
        queue.async { self.listen() }
    }

    public func stop() {
        queue.async {
            self.tearDown()
            for connection in self.connections.values {
                connection.cancel()
            }
            self.connections.removeAll()
            self.onStatusChange?(.stopped)
        }
    }

    private func listen() {
        tearDown()
        let directory = URL(fileURLWithPath: socketPath).deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch {
            onStatusChange?(.failed("\(error)"))
            return
        }
        chmod(directory.path, 0o700)
        unlink(socketPath)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8CString)
        guard fd >= 0, pathBytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            if fd >= 0 { close(fd) }
            onStatusChange?(.failed("Socket path is too long: \(socketPath)"))
            return
        }
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes.map { UInt8(bitPattern: $0) })
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, chmod(socketPath, 0o600) == 0, Darwin.listen(fd, 16) == 0 else {
            let message = String(cString: strerror(errno))
            close(fd)
            onStatusChange?(.failed(message))
            return
        }

        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.accept(on: fd) }
        source.setCancelHandler { close(fd) }
        source.resume()
        acceptSource = source
        onStatusChange?(.listening)
    }

    private func tearDown() {
        acceptSource?.cancel()
        acceptSource = nil
        unlink(socketPath)
    }

    private func accept(on listener: Int32) {
        let fd = Darwin.accept(listener, nil, nil)
        guard fd >= 0 else { return }
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        guard let peer = PeerProcess.credentials(of: fd), peer.uid == getuid() else {
            Self.logger.notice("Refused an SSH agent connection from another user")
            close(fd)
            return
        }
        guard let client = PeerProcess.client(pid: peer.pid) else {
            Self.logger.notice("Refused an SSH agent connection whose process couldn't be identified")
            close(fd)
            return
        }
        let id = UUID()
        let connection = SSHAgentConnection(id: id, fd: fd, client: client, handler: handler, knownHosts: knownHosts, queue: queue)
        connection.onClose = { [weak self] in
            guard let self else { return }
            self.queue.async { self.connections[id] = nil }
        }
        connections[id] = connection
        connection.start()
    }
}

/// One client of the agent. Requests are answered one at a time, in order.
final class SSHAgentConnection: @unchecked Sendable {
    private enum MessageType {
        static let failure: UInt8 = 5
        static let success: UInt8 = 6
        static let requestIdentities: UInt8 = 11
        static let identitiesAnswer: UInt8 = 12
        static let signRequest: UInt8 = 13
        static let signResponse: UInt8 = 14
        static let extensionRequest: UInt8 = 27
    }

    private let id: UUID
    private let fd: Int32
    private let client: SSHClient
    private let handler: SSHAgentHandler
    private let knownHosts: URL
    private let queue: DispatchQueue

    // Only touched by the frame-handling task.
    private var session = SSHSession()

    // Only touched on `queue`.
    private var source: DispatchSourceRead?
    private var decoder = FrameDecoder()
    private var frames: AsyncStream<Data>.Continuation?

    var onClose: (@Sendable () -> Void)?

    init(id: UUID, fd: Int32, client: SSHClient, handler: SSHAgentHandler, knownHosts: URL, queue: DispatchQueue) {
        self.id = id
        self.fd = fd
        self.client = client
        self.handler = handler
        self.knownHosts = knownHosts
        self.queue = queue
    }

    func start() {
        let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
        frames = continuation
        Task { [self] in
            for await frame in stream {
                write(FrameDecoder.encode(await respond(to: frame)))
            }
            await handler.connectionClosed(id)
        }
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        source.setEventHandler { [weak self] in self?.readAvailable() }
        source.setCancelHandler { [fd] in close(fd) }
        source.resume()
        self.source = source
    }

    func cancel() {
        source?.cancel()
        source = nil
        frames?.finish()
        frames = nil
        onClose?()
        onClose = nil
    }

    private func readAvailable() {
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        let count = read(fd, &buffer, buffer.count)
        guard count > 0 else {
            cancel()
            return
        }
        decoder.append(Data(buffer[..<count]))
        do {
            while let frame = try decoder.nextFrame() {
                frames?.yield(frame)
            }
        } catch {
            cancel()
        }
    }

    private func write(_ data: Data) {
        data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                guard written > 0 else { return }
                offset += written
            }
        }
    }

    private func respond(to frame: Data) async -> Data {
        var reader = SSHReader(frame)
        var response = SSHWriter()
        do {
            switch try reader.readByte() {
            case MessageType.requestIdentities:
                let identities = await handler.identities(client: client, session: session, connection: id)
                response.write(MessageType.identitiesAnswer)
                response.write(UInt32(identities.count))
                for identity in identities {
                    response.writeString(identity.keyBlob)
                    response.writeString(identity.comment)
                }
            case MessageType.signRequest:
                let keyBlob = try reader.readString()
                let data = try reader.readString()
                let flags = reader.isAtEnd ? 0 : try reader.readUInt32()
                guard let signature = await handler.sign(keyBlob: keyBlob, data: data, flags: flags, client: client, session: session, connection: id) else {
                    return Data([MessageType.failure])
                }
                response.write(MessageType.signResponse)
                response.writeString(signature)
            case MessageType.extensionRequest where try reader.readText() == "session-bind@openssh.com":
                return Data([session.bind(&reader, knownHosts: knownHosts) ? MessageType.success : MessageType.failure])
            default:
                // Adding or removing keys, locking the agent and other
                // extensions aren't supported; clients carry on.
                return Data([MessageType.failure])
            }
        } catch {
            return Data([MessageType.failure])
        }
        return response.data
    }
}
