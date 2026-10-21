import AppKit
import DeskwardenAccount
import DeskwardenKit
import Foundation
import Observation
import OSLog
import ServiceManagement

enum RequestVerification: String, CaseIterable, Identifiable {
    case everyRequest
    case firstRequest
    case every5Minutes
    case every15Minutes
    case everyHour
    case never

    var id: String { rawValue }

    var label: String {
        switch self {
        case .everyRequest: "Every request"
        case .firstRequest: "First request only"
        case .every5Minutes: "Every 5 minutes"
        case .every15Minutes: "Every 15 minutes"
        case .everyHour: "Every hour"
        case .never: "Never"
        }
    }

    var policy: VerificationPolicy {
        switch self {
        case .everyRequest: .everyRequest
        case .firstRequest: .firstRequest
        case .every5Minutes: .interval(.seconds(5 * 60))
        case .every15Minutes: .interval(.seconds(15 * 60))
        case .everyHour: .interval(.seconds(60 * 60))
        case .never: .never
        }
    }
}

@MainActor
@Observable
final class AppModel {
    private enum DefaultsKey {
        static let secretsSocketEnabled = "secretsSocketEnabled"
        static let sshAgentEnabled = "sshAgentEnabled"
        static let requestVerification = "requestVerification"
        static let deviceIdentifier = "deviceIdentifier"
    }

    nonisolated private static let logger = Logger(subsystem: "io.github.grievouz.deskwarden", category: "app")

    let account: AccountManager
    private(set) var applications: [ExternalApplication] = []
    private(set) var keychainError: String?
    private(set) var launchAtLoginError: String?

    var sshAgentEnabled: Bool {
        didSet { defaults.set(sshAgentEnabled, forKey: DefaultsKey.sshAgentEnabled) }
    }

    var secretsSocketEnabled: Bool {
        didSet {
            defaults.set(secretsSocketEnabled, forKey: DefaultsKey.secretsSocketEnabled)
            applySecretsSocket()
        }
    }

    var requestVerification: RequestVerification {
        didSet {
            defaults.set(requestVerification.rawValue, forKey: DefaultsKey.requestVerification)
            let policy = requestVerification.policy
            Task { await approver.setPolicy(policy) }
        }
    }

    var launchAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            do {
                if newValue {
                    try SMAppService.mainApp.register()
                } else {
                    try SMAppService.mainApp.unregister()
                }
                launchAtLoginError = nil
            } catch {
                launchAtLoginError = error.localizedDescription
            }
        }
    }

    private let secretsServer: SecretsServer
    private let approver: TouchIDApprover
    private let applicationStore: ApplicationStore = KeychainApplicationStore()
    private let defaults = UserDefaults.standard
    private var wakeObserver: NSObjectProtocol?

    init() {
        defaults.register(defaults: [
            DefaultsKey.secretsSocketEnabled: true,
            DefaultsKey.requestVerification: RequestVerification.firstRequest.rawValue,
        ])
        sshAgentEnabled = defaults.bool(forKey: DefaultsKey.sshAgentEnabled)
        secretsSocketEnabled = defaults.bool(forKey: DefaultsKey.secretsSocketEnabled)
        let verification = defaults.string(forKey: DefaultsKey.requestVerification)
            .flatMap(RequestVerification.init(rawValue:)) ?? .firstRequest
        requestVerification = verification

        // Identifies this Mac to Bitwarden, so it's recognized as a known device.
        let deviceIdentifier = defaults.string(forKey: DefaultsKey.deviceIdentifier) ?? {
            let identifier = UUID().uuidString.lowercased()
            UserDefaults.standard.set(identifier, forKey: DefaultsKey.deviceIdentifier)
            return identifier
        }()
        account = AccountManager(deviceIdentifier: deviceIdentifier)

        let approver = TouchIDApprover(policy: verification.policy)
        self.approver = approver
        secretsServer = SecretsServer(
            socketPath: SecretsServer.defaultSocketPath,
            secrets: account.secretProvider,
            approvals: approver
        )
        account.onLock = {
            Task { await approver.forgetApprovals() }
        }
        secretsServer.onStatusChange = { status in
            if case .failed(let message) = status {
                Self.logger.error("Secrets socket failed: \(message, privacy: .public)")
            }
        }
        secretsServer.onApplicationUsed = { [weak self] applicationId in
            Task { @MainActor in self?.markUsed(applicationId) }
        }

        loadApplications()
        applySecretsSocket()

        // The periodic check can be hours late after sleep.
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in await self?.account.syncIfChanged() }
        }
    }

    var isUnlocked: Bool {
        if case .unlocked = account.status { true } else { false }
    }

    var menuBarSymbol: String {
        isUnlocked ? "lock.open" : "lock"
    }

    var statusTitle: String {
        switch account.status {
        case .signedOut: "Not signed in"
        case .locked(let email, _): "\(email) · Locked"
        case .unlocked(let email, _): "\(email) · Unlocked"
        }
    }

    // MARK: - External applications

    func addApplication(name: String) -> ExternalApplication {
        let application = ExternalApplication.generate(name: name)
        applications.append(application)
        persistApplications()
        applySecretsSocket()
        return application
    }

    func removeApplication(id: ExternalApplication.ID) {
        applications.removeAll { $0.id == id }
        persistApplications()
        applySecretsSocket()
    }

    private func loadApplications() {
        do {
            applications = try applicationStore.load()
            keychainError = nil
        } catch {
            keychainError = "\(error)"
            Self.logger.error("Couldn't load external applications: \(error, privacy: .public)")
        }
    }

    private func persistApplications() {
        do {
            try applicationStore.save(applications)
            keychainError = nil
        } catch {
            keychainError = "\(error)"
            Self.logger.error("Couldn't save external applications: \(error, privacy: .public)")
        }
    }

    private func markUsed(_ applicationId: String) {
        guard let index = applications.firstIndex(where: { $0.id == applicationId }) else { return }
        applications[index].lastUsedAt = .now
        persistApplications()
    }

    private func applySecretsSocket() {
        if secretsSocketEnabled {
            secretsServer.start(applications: applications)
        } else {
            secretsServer.stop()
        }
    }
}
