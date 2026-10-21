import DeskwardenAccount
import SwiftUI

struct AccountSection: View {
    @Bindable var model: AppModel

    var body: some View {
        switch model.account.status {
        case .signedOut:
            LoginSection(account: model.account)
        case .locked(let email, let server):
            Section {
                LabeledContent("Signed in as", value: email)
                LabeledContent("Server", value: server.displayName)
                UnlockForm(account: model.account)
                LogOutButton(account: model.account)
            } header: {
                Text("Account")
            }
        case .unlocked(let email, let server):
            Section {
                LabeledContent("Signed in as", value: email)
                LabeledContent("Server", value: server.displayName)
                LabeledContent("Last synced") {
                    if model.account.isSyncing {
                        Text("Syncing…")
                    } else if let lastSyncedAt = model.account.lastSyncedAt {
                        Text(lastSyncedAt, format: .relative(presentation: .named))
                    } else {
                        Text("Never")
                    }
                }
                if let error = model.account.syncError {
                    Text(error).foregroundStyle(.red)
                }
                HStack {
                    LogOutButton(account: model.account)
                    Spacer()
                    Button("Sync Now") {
                        Task { await model.account.sync() }
                    }
                    .disabled(model.account.isSyncing)
                    Button("Lock") { model.account.lock() }
                }
            } header: {
                Text("Account")
            } footer: {
                Text("The vault syncs automatically when it changes.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct LogOutButton: View {
    let account: AccountManager
    @State private var isConfirming = false

    var body: some View {
        Button("Log Out…") { isConfirming = true }
            .confirmationDialog("Log out of Bitwarden?", isPresented: $isConfirming) {
                Button("Log Out", role: .destructive) { account.logOut() }
            } message: {
                Text("Deskwarden forgets this account and its cached vault. External applications keep their keys.")
            }
    }
}

/// Email and master password, then two-step login or the new-device code
/// when the server asks for them.
private struct LoginSection: View {
    enum Server: String, CaseIterable, Identifiable {
        case unitedStates = "bitwarden.com"
        case europe = "bitwarden.eu"
        case selfHosted = "Self-hosted"

        var id: String { rawValue }
    }

    enum Step: Equatable {
        case credentials
        case twoFactor([TwoFactorMethod], emailHint: String?)
        case newDeviceCode
    }

    let account: AccountManager

    @State private var server = Server.unitedStates
    @State private var serverURL = ""
    @State private var email = ""
    @State private var password = ""
    @State private var step = Step.credentials
    @State private var method = TwoFactorMethod.authenticator
    @State private var code = ""
    @State private var rememberDevice = false
    @State private var isWorking = false
    @State private var error: String?
    @State private var notice: String?

    var body: some View {
        Section {
            switch step {
            case .credentials:
                credentialFields
            case .twoFactor(let methods, let emailHint):
                twoFactorFields(methods: methods, emailHint: emailHint)
            case .newDeviceCode:
                Text("Bitwarden emailed a verification code to \(email).")
                TextField("Verification code", text: $code)
                    .textContentType(.oneTimeCode)
                    .onSubmit(submit)
            }
            if let notice {
                Text(notice).foregroundStyle(.secondary)
            }
            if let error {
                Text(error).foregroundStyle(.red)
            }
            buttons
        } header: {
            Text("Account")
        }
    }

    @ViewBuilder private var credentialFields: some View {
        Picker("Server", selection: $server) {
            ForEach(Server.allCases) { server in
                Text(server.rawValue).tag(server)
            }
        }
        if server == .selfHosted {
            TextField("Server URL", text: $serverURL, prompt: Text("https://vault.example.com"))
                .textContentType(.URL)
        }
        TextField("Email", text: $email)
            .textContentType(.username)
        SecureField("Master password", text: $password)
            .textContentType(.password)
            .onSubmit(submit)
    }

    @ViewBuilder private func twoFactorFields(methods: [TwoFactorMethod], emailHint: String?) -> some View {
        let supported = methods.filter(\.isSupported)
        if supported.isEmpty {
            Text("This account only offers \(methods.map(\.displayName).joined(separator: ", ")) for two-step login. Deskwarden supports an authenticator app or email.")
        } else {
            if supported.count > 1 {
                Picker("Method", selection: $method) {
                    ForEach(supported, id: \.self) { method in
                        Text(method.displayName).tag(method)
                    }
                }
            }
            if method == .email, let emailHint {
                Text("Enter the code sent to \(emailHint).")
            }
            TextField(method == .email ? "Email code" : "Authenticator code", text: $code)
                .textContentType(.oneTimeCode)
                .onSubmit(submit)
            Toggle("Remember this Mac", isOn: $rememberDevice)
        }
    }

    private var buttons: some View {
        HStack {
            if step != .credentials {
                Button("Cancel", role: .cancel, action: reset)
            }
            if case .twoFactor = step, method == .email {
                Button("Send Code") { run { try await account.sendTwoFactorEmail(); notice = "Code sent." } }
            }
            if step == .newDeviceCode {
                Button("Resend Code") { run { try await account.resendNewDeviceCode(); notice = "Code sent." } }
            }
            Spacer()
            if isWorking {
                ProgressView().controlSize(.small)
            }
            Button(step == .credentials ? "Log In" : "Continue", action: submit)
                .keyboardShortcut(.defaultAction)
                .disabled(!canSubmit || isWorking)
        }
    }

    private var canSubmit: Bool {
        switch step {
        case .credentials:
            !email.isEmpty && !password.isEmpty && (server != .selfHosted || selfHostedURL != nil)
        case .twoFactor(let methods, _):
            !code.isEmpty && methods.contains(where: \.isSupported)
        case .newDeviceCode:
            !code.isEmpty
        }
    }

    private var selfHostedURL: URL? {
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespaces)),
              url.scheme == "https" || url.scheme == "http",
              url.host() != nil
        else { return nil }
        return url
    }

    private func submit() {
        guard canSubmit, !isWorking else { return }
        run {
            let progress: LoginProgress
            switch step {
            case .credentials:
                let server: BitwardenServer = switch self.server {
                case .unitedStates: .unitedStates
                case .europe: .europe
                case .selfHosted: .selfHosted(selfHostedURL!)
                }
                progress = try await account.logIn(server: server, email: email, password: password)
            case .twoFactor:
                progress = try await account.continueLogin(twoFactor: TwoFactorAnswer(method: method, code: code, remember: rememberDevice))
            case .newDeviceCode:
                progress = try await account.continueLogin(newDeviceCode: code)
            }
            code = ""
            notice = nil
            switch progress {
            case .signedIn:
                password = ""
                step = .credentials
            case .needsTwoFactor(let methods, let emailHint):
                method = methods.first(where: \.isSupported) ?? .authenticator
                step = .twoFactor(methods, emailHint: emailHint)
            case .needsNewDeviceCode:
                step = .newDeviceCode
            }
        }
    }

    private func reset() {
        account.cancelLogin()
        step = .credentials
        code = ""
        error = nil
        notice = nil
    }

    private func run(_ work: @escaping () async throws -> Void) {
        isWorking = true
        error = nil
        Task {
            do {
                try await work()
            } catch {
                self.error = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            isWorking = false
        }
    }
}
