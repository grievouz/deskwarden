import AppKit
import SwiftUI

struct MenuContent: View {
    @Bindable var model: AppModel
    @Environment(\.openSettings) private var openSettings
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.statusTitle)

        switch model.account.status {
        case .signedOut:
            Button("Log In…") { showSettings() }
        case .locked:
            if model.account.canUnlockWithTouchID {
                Button("Unlock with Touch ID") {
                    Task {
                        if await model.unlockWithTouchID() { showUnlockWindow() }
                    }
                }
            } else {
                Button("Unlock…") { showUnlockWindow() }
            }
        case .unlocked:
            EmptyView()
        }

        Divider()

        Toggle("SSH Agent", isOn: $model.sshAgentEnabled)
            .disabled(true)
        Toggle("Secrets Socket", isOn: $model.secretsSocketEnabled)

        Divider()

        Button("Lock Now") { model.account.lock() }
            .keyboardShortcut("l")
            .disabled(!model.isUnlocked)
        Button("Sync Now") {
            Task { await model.account.sync() }
        }
        .disabled(!model.isUnlocked || model.account.isSyncing)

        Divider()

        Button("Settings…") { showSettings() }
            .keyboardShortcut(",")
        Button("Quit Deskwarden") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }

    private func showSettings() {
        NSApp.activate()
        openSettings()
    }

    private func showUnlockWindow() {
        NSApp.activate()
        openWindow(id: UnlockView.windowID)
    }
}
