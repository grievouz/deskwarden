import Foundation
import OSLog

/// An SSH key item from the vault, as the agent offers it.
public struct SSHKeyEntry: Sendable, Hashable {
    public let id: String
    public let name: String
    public let publicKeyBlob: Data

    public init(id: String, name: String, publicKeyBlob: Data) {
        self.id = id
        self.name = name
        self.publicKeyBlob = publicKeyBlob
    }
}

/// Where the agent's keys come from.
public protocol SSHKeyProvider: Sendable {
    var isLocked: Bool { get async }
    /// Tries to unlock, e.g. with Touch ID. Returns whether the vault is unlocked now.
    func unlock(reason: String) async -> Bool
    func sshKeys() async -> [SSHKeyEntry]
    /// The key in OpenSSH format, decrypted only for the signature at hand.
    func sshPrivateKey(id: String) async -> String?
}

/// The external applications SSH clients are recognized as.
public protocol SSHApplicationRegistry: Sendable {
    func application(for client: SSHClient) async -> ExternalApplication?
    func addApplication(for client: SSHClient) async -> ExternalApplication?
    func markUsed(_ application: ExternalApplication) async
}

/// Who may use the agent's keys.
///
/// Listing keys never asks. Signing follows the verification setting, like
/// secrets requests, with approvals remembered per key and server, except:
/// - an app's first use always asks, and adds it to the external applications;
/// - keys selected for an app sign without asking;
/// - a forwarded agent always asks, and never uses or adds to what's remembered;
/// - unlocking a locked vault takes one Touch ID prompt, which also counts as
///   letting the app use the keys on that connection.
///
/// Once a client is refused, the rest of its connection is too, so it can't
/// keep prompting by offering one key after another.
public actor SSHAccess: SSHAgentHandler {
    private static let logger = Logger(subsystem: "io.github.grievouz.deskwarden", category: "ssh-agent")

    private let keys: SSHKeyProvider
    private let applications: SSHApplicationRegistry
    private let approvals: ApprovalProvider
    private let prompt: TouchIDApprover.Prompt
    private var refused: Set<UUID> = []
    /// Connections whose unlock prompt already let the app in.
    private var unlockedFor: Set<UUID> = []

    public init(
        keys: SSHKeyProvider,
        applications: SSHApplicationRegistry,
        approvals: ApprovalProvider,
        prompt: @escaping TouchIDApprover.Prompt = TouchIDApprover.touchID
    ) {
        self.keys = keys
        self.applications = applications
        self.approvals = approvals
        self.prompt = prompt
    }

    public func identities(client: SSHClient, session: SSHSession, connection: UUID) async -> [SSHIdentity] {
        guard await ensureUnlocked(client: client, session: session, connection: connection) else { return [] }
        return await keys.sshKeys().map { SSHIdentity(keyBlob: $0.publicKeyBlob, comment: $0.name) }
    }

    public func sign(keyBlob: Data, data: Data, flags: UInt32, client: SSHClient, session: SSHSession, connection: UUID) async -> Data? {
        guard !refused.contains(connection), await ensureUnlocked(client: client, session: session, connection: connection),
              let key = await keys.sshKeys().first(where: { $0.publicKeyBlob == keyBlob })
        else { return nil }

        guard let application = await authorize(key, client: client, session: session, connection: connection) else {
            refused.insert(connection)
            return nil
        }
        do {
            guard let pem = await keys.sshPrivateKey(id: key.id) else { return nil }
            let signature = try OpenSSHPrivateKey(pem: pem).sign(data, flags: flags)
            await applications.markUsed(application)
            return signature
        } catch {
            Self.logger.error("Couldn't sign with an SSH key: \(String(describing: error), privacy: .public)")
            return nil
        }
    }

    public func connectionClosed(_ connection: UUID) async {
        refused.remove(connection)
        unlockedFor.remove(connection)
        await approvals.connectionClosed(connection)
    }

    private func ensureUnlocked(client: SSHClient, session: SSHSession, connection: UUID) async -> Bool {
        guard await keys.isLocked else { return true }
        guard !refused.contains(connection) else { return false }
        // A forwarded agent only unlocks; it doesn't let the app in.
        if let origin = session.forwardedFrom {
            guard await keys.unlock(reason: "unlock your vault for a forwarded connection from \(origin.displayName)") else {
                refused.insert(connection)
                return false
            }
            return true
        }
        let existing = await applications.application(for: client)
        let reason = existing == nil
            ? "unlock your vault and let \(client.appName) use your SSH keys\(Self.suffix(client.via))"
            : "unlock your vault so \(client.appName) can use your SSH keys"
        guard await keys.unlock(reason: reason) else {
            refused.insert(connection)
            return false
        }
        if existing == nil, await applications.addApplication(for: client) == nil {
            return false
        }
        unlockedFor.insert(connection)
        return true
    }

    /// The application the client is recognized as, if it may sign with `key`.
    private func authorize(_ key: SSHKeyEntry, client: SSHClient, session: SSHSession, connection: UUID) async -> ExternalApplication? {
        let action = Self.action(keyName: key.name, client: client, session: session)
        // Remembered per key and server; a forwarded agent never is.
        let scope = "\(key.id)@\(session.destination?.hostKeyFingerprint ?? "local")"
        let remember = !session.isForwarded

        guard let application = await applications.application(for: client) else {
            // An app's first use always asks, whatever the verification setting.
            let first = ApprovalRequest(applicationId: "", applicationName: client.appName, connectionId: connection, client: nil, action: action)
            guard await prompt(first), let application = await applications.addApplication(for: client) else { return nil }
            await approvals.record(Self.request(application, connection: connection, action: action, scope: scope, remember: remember))
            return application
        }
        let request = Self.request(application, connection: connection, action: action, scope: scope, remember: remember)
        if remember, unlockedFor.contains(connection) {
            await approvals.record(request)
            return application
        }
        if remember, application.allowed?.itemIds.contains(key.id) == true {
            return application
        }
        return await approvals.approve(request) ? application : nil
    }

    private static func request(_ application: ExternalApplication, connection: UUID, action: String, scope: String, remember: Bool) -> ApprovalRequest {
        ApprovalRequest(
            applicationId: application.id,
            applicationName: application.name,
            connectionId: connection,
            client: nil,
            action: action,
            scope: scope,
            remember: remember
        )
    }

    /// E.g. `use your SSH key “GitHub” to sign in to github.com (git → ssh)`.
    static func action(keyName: String, client: SSHClient, session: SSHSession) -> String {
        var action = "use your SSH key “\(keyName)”"
        if let origin = session.forwardedFrom {
            action += " for a forwarded connection from \(origin.displayName)"
            if let destination = session.destination {
                action += " to \(destination.displayName)"
            }
        } else if let destination = session.destination {
            action += " to sign in to \(destination.displayName)"
        }
        return action + suffix(client.via)
    }

    private static func suffix(_ via: String) -> String {
        via.isEmpty ? "" : " (\(via))"
    }
}
