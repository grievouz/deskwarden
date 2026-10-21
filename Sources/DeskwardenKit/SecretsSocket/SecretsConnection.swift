import CryptoKit
import Foundation
import Network

/// One client on the secrets socket.
///
/// Bytes arrive on the server's queue and are cut into frames there; frames
/// are then handled one at a time by a single task, so a client that fires
/// many `get`s at once sees them answered in order and approvals never race.
final class SecretsConnection: @unchecked Sendable {
    private enum State {
        case awaitingAuth
        case authenticated(ExternalApplication, ClientInfo?)
        case closed
    }

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let applications: [String: ExternalApplication]
    private let secrets: SecretProvider
    private let approvals: ApprovalProvider
    private let nonce = randomBytes(32)
    private let id = UUID()

    // Only touched on `queue`.
    private var decoder = FrameDecoder()
    private var frames: AsyncStream<Data>.Continuation?

    // Only touched by the frame-handling task.
    private var state = State.awaitingAuth
    /// Once a request is denied, or unlocking for it is turned down, the rest
    /// of the connection is too, so a client firing many requests doesn't
    /// keep prompting.
    private var denied = false
    private var unlockDeclined = false

    /// The application the client authenticated as. Read from `queue`.
    private(set) var applicationId: String?

    var onAuthenticated: (@Sendable (String) -> Void)?
    var onClose: (@Sendable () -> Void)?

    init(
        connection: NWConnection,
        queue: DispatchQueue,
        applications: [String: ExternalApplication],
        secrets: SecretProvider,
        approvals: ApprovalProvider
    ) {
        self.connection = connection
        self.queue = queue
        self.applications = applications
        self.secrets = secrets
        self.approvals = approvals
    }

    func start() {
        let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
        frames = continuation
        Task { [self] in
            for await frame in stream {
                await handle(frame)
            }
            await approvals.connectionClosed(id)
        }
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.send(.challenge(nonce: self.nonce))
                self.receive()
            case .failed, .cancelled:
                self.close()
            default:
                break
            }
        }
        connection.start(queue: queue)
    }

    func cancel() {
        connection.cancel()
    }

    private func close() {
        frames?.finish()
        frames = nil
        onClose?()
        onClose = nil
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data {
                self.decoder.append(data)
                do {
                    while let frame = try self.decoder.nextFrame() {
                        self.frames?.yield(frame)
                    }
                } catch {
                    self.connection.cancel()
                    return
                }
            }
            if isComplete || error != nil {
                self.connection.cancel()
            } else {
                self.receive()
            }
        }
    }

    private func send(_ message: ServerMessage) {
        guard let payload = try? JSONEncoder().encode(message) else { return }
        connection.send(content: FrameDecoder.encode(payload), completion: .idempotent)
    }

    private func handle(_ frame: Data) async {
        let message: ClientMessage
        do {
            message = try JSONDecoder().decode(ClientMessage.self, from: frame)
        } catch {
            send(.error(id: nil, code: .badRequest, message: "Could not parse message"))
            return
        }

        switch (state, message) {
        case (.awaitingAuth, .auth(let auth)):
            authenticate(auth)
        case (.authenticated(let application, let client), .get(let get)):
            await serve(get, application: application, client: client)
        case (.awaitingAuth, .get(let get)):
            send(.error(id: get.id, code: .unauthorized, message: "Authenticate first"))
        case (.authenticated, .auth), (.closed, _):
            send(.error(id: nil, code: .badRequest, message: "Unexpected message"))
        }
    }

    private func authenticate(_ auth: ClientMessage.Auth) {
        guard let application = applications[auth.keyId],
              HMAC<SHA256>.isValidAuthenticationCode(
                  auth.proof,
                  authenticating: SecretsProtocol.authContext + nonce,
                  using: SymmetricKey(data: application.secret)
              )
        else {
            state = .closed
            send(.error(id: nil, code: .unauthorized, message: "Unknown key; the application may have been removed"))
            connection.cancel()
            return
        }
        state = .authenticated(application, auth.client)
        queue.async { self.applicationId = application.id }
        onAuthenticated?(application.id)
        send(.ready)
    }

    private func serve(_ get: ClientMessage.Get, application: ExternalApplication, client: ClientInfo?) async {
        let request = ApprovalRequest(
            applicationId: application.id,
            applicationName: application.name,
            connectionId: id,
            client: client,
            path: get.path
        )
        // Unlocking asks for Touch ID, which then also verifies this request.
        var verified = false
        if await secrets.isLocked {
            guard !unlockDeclined, await secrets.unlock(for: request) else {
                unlockDeclined = true
                send(Self.errorMessage(for: .locked, requestId: get.id))
                return
            }
            await approvals.record(request)
            verified = true
        }
        if !denied, !verified {
            denied = await !approvals.approve(request)
        }
        guard !denied else {
            send(.error(id: get.id, code: .denied, message: "Access was denied in Deskwarden"))
            return
        }
        do {
            let value = try await secrets.value(at: get.path, field: get.field ?? "password")
            send(.value(id: get.id, value: value))
        } catch {
            send(Self.errorMessage(for: error, requestId: get.id))
        }
    }

    private static func errorMessage(for error: SecretLookupError, requestId: String) -> ServerMessage {
        switch error {
        case .locked:
            .error(id: requestId, code: .locked, message: "The vault is locked")
        case .notFound(let path):
            .error(id: requestId, code: .notFound, message: "No item at \"\(path)\"")
        case .ambiguous(let path, let count):
            .error(id: requestId, code: .ambiguous, message: "\(count) items match \"\(path)\"; use a folder path or the item id")
        case .fieldNotFound(let field):
            .error(id: requestId, code: .fieldNotFound, message: "The item has no field \"\(field)\"")
        }
    }
}
