import AppKit
import SwiftUI

@main
struct DeskwardenApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    var body: some Scene {
        MenuBarExtra("Deskwarden", systemImage: model.menuBarSymbol) {
            MenuContent(model: model)
        }
        .menuBarExtraStyle(.menu)

        Settings {
            SettingsView(model: model)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // The bundled app sets LSUIElement; `swift run` has no Info.plist.
        NSApp.setActivationPolicy(.accessory)
    }
}
