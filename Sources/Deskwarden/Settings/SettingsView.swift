import SwiftUI

struct SettingsView: View {
    @Bindable var model: AppModel

    var body: some View {
        Form {
            AccountSection()
            GeneralSection(model: model)
            ApplicationsSection(model: model)
        }
        .formStyle(.grouped)
        .frame(width: 540, height: 720)
    }
}
