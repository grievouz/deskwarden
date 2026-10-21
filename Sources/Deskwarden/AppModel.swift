import DeskwardenKit
import Foundation
import Observation
import OSLog
import ServiceManagement

enum VaultState {
    case signedOut
    case locked
    case unlocked
}

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
    }

    nonisolated private static let logger = Logger(subsystem: "io.github.grievouz.deskwarden", category: "app")

    private(set) var vaultState = VaultState.signedOut
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

        approver = TouchIDApprover(policy: verification.policy)
        // Until Bitwarden sign-in exists there is no vault, so every request reports it as locked.
        secretsServer = SecretsServer(
            socketPath: SecretsServer.defaultSocketPath,
            secrets: IndexSecretProvider(index: nil),
            approvals: approver
        )
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
    }

    var menuBarSymbol: String {
        vaultState == .unlocked ? "lock.open" : "lock"
    }

    var statusTitle: String {
        switch vaultState {
        case .signedOut: "Not signed in"
        case .locked: "Locked"
        case .unlocked: "Unlocked"
        }
    }

    func lock() {
        Task { await approver.forgetApprovals() }
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
