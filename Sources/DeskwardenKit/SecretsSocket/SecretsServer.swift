import Foundation
import Network
import Security
import Synchronization

/// Serves vault values to external applications over a Unix socket.
///
/// Connections use TLS 1.2 with ECDHE-PSK-CHACHA20-POLY1305: every
/// application's key is registered as a pre-shared key, so only a client
/// holding one can finish the handshake, and ephemeral ECDH gives each
/// connection forward secrecy. TLS 1.3 isn't used because Node can't do
/// TLS 1.3 with external PSKs.
///
/// Network.framework doesn't tell the server which PSK a client used, so after
/// the handshake the client also proves which key it holds by answering a
/// challenge (see `SecretsConnection`).
public final class SecretsServer: @unchecked Sendable {
    public enum Status: Equatable, Sendable {
        case stopped
        case noApplications
        case listening
        case failed(String)
    }

    public let socketPath: String
    private let secrets: SecretProvider
    private let approvals: ApprovalProvider
    private let queue = DispatchQueue(label: "io.github.grievouz.deskwarden.secrets-server")

    // Only touched on `queue`.
    private var listener: NWListener?
    private var applications: [String: ExternalApplication] = [:]
    private var listenerKeys: Set<String>?
    private var connections: [ObjectIdentifier: SecretsConnection] = [:]
    /// The applications as they are now, so a change in what one may access
    /// applies to its open connections too.
    private let current = Mutex<[String: ExternalApplication]>([:])

    public var onStatusChange: (@Sendable (Status) -> Void)?
    /// Called with an application id each time a client authenticates as it.
    public var onApplicationUsed: (@Sendable (String) -> Void)?

    public init(socketPath: String, secrets: SecretProvider, approvals: ApprovalProvider) {
        self.socketPath = socketPath
        self.secrets = secrets
        self.approvals = approvals
    }

    public static var defaultSocketPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".deskwarden/secrets.sock").path
    }

    /// Starts listening, or restarts with a new set of applications.
    /// Connections from applications no longer in the set are closed.
    public func start(applications: [ExternalApplication]) {
        queue.async { self.restart(applications: applications) }
    }

    public func stop() {
        queue.async {
            self.tearDown()
            self.listenerKeys = nil
            for connection in self.connections.values {
                connection.cancel()
            }
            self.connections.removeAll()
            self.onStatusChange?(.stopped)
        }
    }

    private func restart(applications: [ExternalApplication]) {
        // SSH clients have no key, so they can't use this socket.
        let applications = applications.filter { $0.secret != nil }
        self.applications = Dictionary(uniqueKeysWithValues: applications.map { ($0.id, $0) })
        current.withLock { $0 = self.applications }
        // Only a change of keys needs a new listener.
        let keys = Set(applications.compactMap { app in app.secret.map { "\(app.id):\($0.base64EncodedString())" } })
        if listener != nil, keys == listenerKeys { return }
        listenerKeys = keys
        tearDown()
        // Unauthenticated connections hold the old set, so they go too.
        for connection in connections.values where connection.applicationId.map({ self.applications[$0] == nil }) ?? true {
            connection.cancel()
        }
        guard !applications.isEmpty else {
            onStatusChange?(.noApplications)
            return
        }
        do {
            try prepareSocketDirectory()
            let listener = try NWListener(using: parameters(for: applications))
            listener.stateUpdateHandler = { [weak self] state in self?.listenerStateChanged(state) }
            listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            listener.start(queue: queue)
            self.listener = listener
        } catch {
            onStatusChange?(.failed("\(error)"))
        }
    }

    private func tearDown() {
        listener?.cancel()
        listener = nil
        unlink(socketPath)
    }

    private func listenerStateChanged(_ state: NWListener.State) {
        switch state {
        case .ready:
            chmod(socketPath, 0o600)
            onStatusChange?(.listening)
        case .failed(let error):
            onStatusChange?(.failed("\(error)"))
        default:
            break
        }
    }

    private func accept(_ nwConnection: NWConnection) {
        let connection = SecretsConnection(
            connection: nwConnection,
            queue: queue,
            applications: applications,
            currentApplication: { [weak self] id in self?.current.withLock { $0[id] } },
            secrets: secrets,
            approvals: approvals
        )
        let id = ObjectIdentifier(connection)
        connection.onAuthenticated = { [weak self] applicationId in self?.onApplicationUsed?(applicationId) }
        connection.onClose = { [weak self] in
            guard let self else { return }
            self.queue.async { self.connections[id] = nil }
        }
        connections[id] = connection
        connection.start()
    }

    /// The socket lives in a directory only the user can enter, and the socket
    /// itself is chmodded to 0600 once it exists.
    private func prepareSocketDirectory() throws {
        let directory = URL(fileURLWithPath: socketPath).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        chmod(directory.path, 0o700)
        unlink(socketPath)
    }

    private func parameters(for applications: [ExternalApplication]) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let options = tls.securityProtocolOptions
        for application in applications {
            guard let secret = application.secret else { continue }
            sec_protocol_options_add_pre_shared_key(options, secret.dispatchData, Data(application.id.utf8).dispatchData)
        }
        sec_protocol_options_append_tls_ciphersuite(
            options,
            tls_ciphersuite_t(rawValue: UInt16(TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256))!
        )
        sec_protocol_options_set_min_tls_protocol_version(options, .TLSv12)
        sec_protocol_options_set_max_tls_protocol_version(options, .TLSv12)

        let parameters = NWParameters(tls: tls)
        parameters.requiredLocalEndpoint = .unix(path: socketPath)
        return parameters
    }
}

extension Data {
    var dispatchData: __DispatchData {
        withUnsafeBytes { DispatchData(bytes: $0) } as __DispatchData
    }
}
