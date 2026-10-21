import AppKit
import SwiftUI

@main
struct DeskwardenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuContent(model: model)
        } label: {
            MenuBarIcon()
        }
        .menuBarExtraStyle(.menu)

        Settings {
            SettingsView(model: model)
        }

        Window("Unlock Deskwarden", id: UnlockView.windowID) {
            UnlockView(model: model)
        }
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(.suppressed)
    }
}

/// `MenuBarIcon.pdf` from the app bundle if there is one (see
/// scripts/fetch-bitwarden-icons.sh), otherwise an SF Symbol.
private struct MenuBarIcon: View {
    private static let image: NSImage? = {
        let image = NSImage(named: "MenuBarIcon")
        image?.isTemplate = true
        return image
    }()

    var body: some View {
        if let image = Self.image {
            Image(nsImage: image)
        } else {
            Image(systemName: "lock.shield")
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // The bundled app sets LSUIElement; `swift run` has no Info.plist.
        NSApp.setActivationPolicy(.accessory)

        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(windowBecameKey(_:)), name: NSWindow.didBecomeKeyNotification, object: nil)
        center.addObserver(self, selector: #selector(windowWillClose(_:)), name: NSWindow.willCloseNotification, object: nil)
    }

    // While Settings or the unlock window is open, Deskwarden shows in the
    // Dock and ⌘-Tab like a normal app, so the window can be found and closed.

    @objc private func windowBecameKey(_ notification: Notification) {
        updateActivationPolicy(closing: nil)
    }

    @objc private func windowWillClose(_ notification: Notification) {
        updateActivationPolicy(closing: notification.object as? NSWindow)
    }

    private func updateActivationPolicy(closing: NSWindow?) {
        let hasWindow = NSApp.windows.contains { window in
            window !== closing && window.isVisible && window.styleMask.contains(.titled)
        }
        let policy: NSApplication.ActivationPolicy = hasWindow ? .regular : .accessory
        guard NSApp.activationPolicy() != policy else { return }
        NSApp.setActivationPolicy(policy)
        if policy == .regular {
            NSApp.activate()
        }
    }
}
