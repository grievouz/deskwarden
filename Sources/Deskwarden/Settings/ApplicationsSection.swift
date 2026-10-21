import AppKit
import DeskwardenKit
import SwiftUI

struct ApplicationsSection: View {
    @Bindable var model: AppModel
    @State private var isAdding = false
    @State private var applicationToRemove: ExternalApplication?

    var body: some View {
        Section {
            if model.applications.isEmpty {
                Text("No applications yet")
                    .foregroundStyle(.secondary)
            }
            ForEach(model.applications) { application in
                LabeledContent {
                    Button("Remove…") { applicationToRemove = application }
                } label: {
                    Text(application.name)
                    if let lastUsedAt = application.lastUsedAt {
                        Text("Last used \(lastUsedAt, format: .relative(presentation: .named))")
                    } else {
                        Text("Never used")
                    }
                }
            }
            HStack {
                Spacer()
                Button("Add Application…") { isAdding = true }
            }
            .sheet(isPresented: $isAdding) {
                AddApplicationSheet(model: model)
            }
            .confirmationDialog(
                "Remove “\(applicationToRemove?.name ?? "")”?",
                isPresented: Binding(get: { applicationToRemove != nil }, set: { if !$0 { applicationToRemove = nil } }),
                presenting: applicationToRemove
            ) { application in
                Button("Remove", role: .destructive) {
                    model.removeApplication(id: application.id)
                }
            } message: { _ in
                Text("It will be disconnected, and its key will stop working.")
            }
        } header: {
            Text("External Applications")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text("Each application connects to the secrets socket with its own key.")
                    .foregroundStyle(.secondary)
                if let error = model.keychainError {
                    Text(error).foregroundStyle(.red)
                }
            }
        }
    }
}

private struct AddApplicationSheet: View {
    @Bindable var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var application: ExternalApplication?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let application {
                Text("Key for “\(application.name)”")
                    .font(.headline)
                Text("This is the only time the key is shown.")
                    .foregroundStyle(.secondary)
                HStack {
                    Text(application.key)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(application.key, forType: .string)
                    }
                }
                .padding(8)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                HStack {
                    Spacer()
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                }
            } else {
                Text("New external application")
                    .font(.headline)
                TextField("Name", text: $name)
                HStack {
                    Spacer()
                    Button("Cancel", role: .cancel) { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("Add") { application = model.addApplication(name: name) }
                        .keyboardShortcut(.defaultAction)
                        .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}
