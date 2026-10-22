import SwiftUI

struct GeneralSection: View {
    @Bindable var model: AppModel

    var body: some View {
        Section("General") {
            Toggle(isOn: $model.sshAgentEnabled) {
                Text("SSH agent")
                Text("Serves the SSH keys in your vault to ssh, git and anything else using SSH_AUTH_SOCK. Turning it on sets that up, with IdentityAgent in ~/.ssh/config; turning it off undoes it.")
            }
            if let error = model.sshSetupError {
                Text(error).foregroundStyle(.red)
            }

            Toggle(isOn: $model.secretsSocketEnabled) {
                Text("Secrets socket")
                Text("Lets external applications read vault items by path.")
            }

            Picker(selection: $model.requestVerification) {
                Text(RequestVerification.everyRequest.label).tag(RequestVerification.everyRequest)
                Text(RequestVerification.firstRequest.label).tag(RequestVerification.firstRequest)
                Divider()
                Text(RequestVerification.every5Minutes.label).tag(RequestVerification.every5Minutes)
                Text(RequestVerification.every15Minutes.label).tag(RequestVerification.every15Minutes)
                Text(RequestVerification.everyHour.label).tag(RequestVerification.everyHour)
                Divider()
                Text(RequestVerification.never.label).tag(RequestVerification.never)
            } label: {
                Text("Verify requests")
                Text("How often requests from SSH clients and external applications need Touch ID.")
            }

            Toggle("Lock when the Mac sleeps", isOn: $model.lockOnSleep)
            Toggle("Lock when the screen locks", isOn: $model.lockOnScreenLock)

            Toggle("Open at login", isOn: $model.launchAtLogin)
            if let error = model.launchAtLoginError {
                Text(error).foregroundStyle(.red)
            }
        }
    }
}
