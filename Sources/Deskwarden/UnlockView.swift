import DeskwardenAccount
import SwiftUI

/// The small window the menu's Unlock… opens.
struct UnlockView: View {
    static let windowID = "unlock"

    @Bindable var model: AppModel
    @Environment(\.dismissWindow) private var dismissWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if case .locked(let email, let server) = model.account.status {
                Text("Unlock your vault")
                    .font(.headline)
                Text("\(email) on \(server.displayName)")
                    .foregroundStyle(.secondary)
                UnlockForm(account: model.account)
            } else {
                Text("Your vault is unlocked.")
                HStack {
                    Spacer()
                    Button("Close") { dismissWindow(id: Self.windowID) }
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: 360)
        .onChange(of: model.isUnlocked) { _, unlocked in
            if unlocked { dismissWindow(id: Self.windowID) }
        }
    }
}

/// A master password field and Unlock button, used by the unlock window and Settings.
struct UnlockForm: View {
    let account: AccountManager
    @State private var password = ""
    @State private var isWorking = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            SecureField("Master password", text: $password)
                .textContentType(.password)
                .onSubmit(unlock)
            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            HStack {
                if isWorking {
                    ProgressView().controlSize(.small)
                }
                Button("Unlock", action: unlock)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || isWorking)
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty, !isWorking else { return }
        isWorking = true
        error = nil
        Task {
            do throws(AccountError) {
                try await account.unlock(password: password)
                password = ""
            } catch {
                self.error = error.errorDescription
            }
            isWorking = false
        }
    }
}
