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
/// secrets requests, except that an app's first use always asks and adds it to
/// the external applications. A locked vault is unlocked with one Touch ID
/// prompt that also counts as letting the app use the keys. Once a client is
/// refused, the rest of its connection is too, so it can't keep prompting by
/// offering one key after another.
public actor SSHAccess: SSHAgentHandler {
    private static let logger = Logger(subsystem: "io.github.grievouz.deskwarden", category: "ssh-agent")

    private let keys: SSHKeyProvider
    private let applications: SSHApplicationRegistry
    private let approvals: ApprovalProvider
    private let prompt: TouchIDApprover.Prompt
    private var refused: Set<UUID> = []

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

        let action = Self.action(keyName: key.name, client: client, session: session)
        guard let application = await authorize(client: client, connection: connection, action: action, remember: !session.isForwarded) else {
            refused.insert(connection)
            return nil
        }
        do {
            guard let pem = await keys.sshPrivateKey(id: key.id) else { return nil }
            let signature = try OpenSSHPrivateKey(pem: pem).sign(data, flags: flags)
            await applications.markUsed(application)
            return signature
        } catch {
            Self.logger.error("Couldn't sign with \(key.name, privacy: .public): \(String(describing: error), privacy: .public)")
            return nil
        }
    }

    public func connectionClosed(_ connection: UUID) async {
        refused.remove(connection)
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
        let application: ExternalApplication
        if let existing {
            application = existing
        } else if let added = await applications.addApplication(for: client) {
            application = added
        } else {
            return false
        }
        await approvals.record(Self.request(application, connection: connection, action: "use your SSH keys"))
        return true
    }

    /// The application the client is recognized as, if it may sign.
    /// `remember` is false for forwarded agents, which always ask.
    private func authorize(client: SSHClient, connection: UUID, action: String, remember: Bool) async -> ExternalApplication? {
        if let application = await applications.application(for: client) {
            let request = Self.request(application, connection: connection, action: action, remember: remember)
            return await approvals.approve(request) ? application : nil
        }
        // An app's first use always asks, whatever the verification setting.
        let first = ApprovalRequest(applicationId: "", applicationName: client.appName, connectionId: connection, client: nil, action: action)
        guard await prompt(first), let application = await applications.addApplication(for: client) else { return nil }
        await approvals.record(Self.request(application, connection: connection, action: action, remember: remember))
        return application
    }

    private static func request(_ application: ExternalApplication, connection: UUID, action: String, remember: Bool = true) -> ApprovalRequest {
        ApprovalRequest(applicationId: application.id, applicationName: application.name, connectionId: connection, client: nil, action: action, remember: remember)
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
