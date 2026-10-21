import AppKit
import SwiftUI

struct MenuContent: View {
    @Bindable var model: AppModel
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        Text(model.statusTitle)

        Divider()

        Toggle("SSH Agent", isOn: $model.sshAgentEnabled)
            .disabled(true)
        Toggle("Secrets Socket", isOn: $model.secretsSocketEnabled)

        Divider()

        Button("Lock Now") { model.lock() }
            .disabled(model.vaultState != .unlocked)
        Button("Sync Now") {}
            .disabled(model.vaultState != .unlocked)

        Divider()

        Button("Settings…") {
            NSApp.activate()
            openSettings()
        }
        .keyboardShortcut(",")
        Button("Quit Deskwarden") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}
