import Foundation
import LocalAuthentication

public struct ApprovalRequest: Sendable {
    public let applicationId: String
    public let applicationName: String
    /// Identifies one connection, for policies that approve a connection at a time.
    public let connectionId: UUID
    public let client: ClientInfo?
    /// What the requester wants to do, completing "let varlock …": e.g.
    /// `read Infra/Stripe` or `use your SSH key “GitHub” (git → ssh)`.
    public let action: String
    /// False for requests that must not use or count toward a remembered
    /// approval, such as signatures for a forwarded agent.
    public let remember: Bool

    public init(applicationId: String, applicationName: String, connectionId: UUID, client: ClientInfo?, action: String, remember: Bool = true) {
        self.applicationId = applicationId
        self.applicationName = applicationName
        self.connectionId = connectionId
        self.client = client
        self.action = action
        self.remember = remember
    }

    /// Who's asking, for prompts: the application as the user registered it,
    /// plus the client's self-reported working directory as context.
    public var requester: String {
        guard let cwd = client?.cwd else { return applicationName }
        return "\(applicationName) in \(URL(fileURLWithPath: cwd).lastPathComponent)"
    }
}

public protocol ApprovalProvider: Sendable {
    func approve(_ request: ApprovalRequest) async -> Bool
    /// Counts a Touch ID prompt shown for another reason, such as unlocking
    /// the vault for this request, as verifying it.
    func record(_ request: ApprovalRequest) async
    func connectionClosed(_ connectionId: UUID) async
}

extension ApprovalProvider {
    public func record(_ request: ApprovalRequest) async {}
    public func connectionClosed(_ connectionId: UUID) async {}
}

/// Always answers the same way. For tests and the socket harness.
public struct FixedApprover: ApprovalProvider {
    let approved: Bool

    public init(approved: Bool) {
        self.approved = approved
    }

    public func approve(_ request: ApprovalRequest) async -> Bool {
        approved
    }
}

/// How often an application's requests need Touch ID.
public enum VerificationPolicy: Sendable, Hashable {
    case everyRequest
    /// The first request from each application after the vault is unlocked;
    /// it isn't asked again until the vault locks.
    case firstRequest
    /// Once per application, then not again until the interval has passed.
    case interval(Duration)
    case never
}

/// Asks for Touch ID, falling back to the account password, as often as the
/// policy says.
public actor TouchIDApprover: ApprovalProvider {
    public typealias Prompt = @Sendable (ApprovalRequest) async -> Bool

    public private(set) var policy: VerificationPolicy
    private let prompt: Prompt
    private var approvedApplications: Set<String> = []
    private var approvedAt: [String: ContinuousClock.Instant] = [:]
    private var pending: [String: Task<Bool, Never>] = [:]

    public init(policy: VerificationPolicy, prompt: @escaping Prompt = TouchIDApprover.touchID) {
        self.policy = policy
        self.prompt = prompt
    }

    public func setPolicy(_ policy: VerificationPolicy) {
        self.policy = policy
        forgetApprovals()
    }

    /// Makes the next request from every application ask again. The app calls
    /// this when the vault locks.
    public func forgetApprovals() {
        approvedApplications.removeAll()
        approvedAt.removeAll()
    }

    // `async` like the protocol's default, so calls on the actor itself don't
    // resolve to that no-op default instead.
    public func record(_ request: ApprovalRequest) async {
        guard request.remember else { return }
        switch policy {
        case .firstRequest: approvedApplications.insert(request.applicationId)
        case .interval: approvedAt[request.applicationId] = .now
        case .everyRequest, .never: break
        }
    }

    public func approve(_ request: ApprovalRequest) async -> Bool {
        if !request.remember {
            return policy == .never ? true : await prompt(request)
        }
        switch policy {
        case .never:
            return true
        case .everyRequest:
            return await prompt(request)
        case .firstRequest:
            if approvedApplications.contains(request.applicationId) { return true }
            let approved = await sharedPrompt(for: request, key: request.applicationId)
            if approved { approvedApplications.insert(request.applicationId) }
            return approved
        case .interval(let interval):
            if let at = approvedAt[request.applicationId], at.duration(to: .now) < interval { return true }
            let approved = await sharedPrompt(for: request, key: request.applicationId)
            if approved { approvedAt[request.applicationId] = .now }
            return approved
        }
    }

    /// Requests waiting on the same approval share one prompt.
    private func sharedPrompt(for request: ApprovalRequest, key: String) async -> Bool {
        if let task = pending[key] {
            return await task.value
        }
        let task = Task { [prompt] in await prompt(request) }
        pending[key] = task
        let approved = await task.value
        pending[key] = nil
        return approved
    }

    public static let touchID: Prompt = { request in
        let context = LAContext()
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason(for: request))) ?? false
    }

    /// Completes the system prompt's "Deskwarden is trying to …".
    static func reason(for request: ApprovalRequest) -> String {
        "let \(request.requester) \(request.action)"
    }
}
