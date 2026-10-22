import AppKit
import DeskwardenAccount
import DeskwardenKit
import SwiftUI

struct ApplicationsSection: View {
    private enum Access: Hashable {
        case askForAnything
        case selectedOnly
    }

    @Bindable var model: AppModel
    @State private var isAdding = false
    @State private var applicationToRemove: ExternalApplication?
    @State private var editingAccess: ExternalApplication?

    private static func subtitle(for application: ExternalApplication) -> String {
        var parts: [String] = []
        if application.process != nil {
            parts.append("SSH client")
        }
        if let allowed = application.allowed {
            parts.append(summary(of: allowed, isSSHClient: application.process != nil))
        }
        parts.append(application.lastUsedAt.map { "Last used \($0.formatted(.relative(presentation: .named)))" } ?? "Never used")
        return parts.joined(separator: " · ")
    }

    private static func summary(of selection: AccessSelection, isSSHClient: Bool) -> String {
        if isSSHClient {
            return selection.itemIds.count == 1 ? "1 key selected" : "\(selection.itemIds.count) keys selected"
        }
        var parts: [String] = []
        if !selection.folderIds.isEmpty {
            parts.append(selection.folderIds.count == 1 ? "1 folder" : "\(selection.folderIds.count) folders")
        }
        if !selection.itemIds.isEmpty {
            parts.append(selection.itemIds.count == 1 ? "1 item" : "\(selection.itemIds.count) items")
        }
        return parts.isEmpty ? "Nothing selected" : parts.joined(separator: ", ") + " selected"
    }

    private func access(for application: ExternalApplication) -> Binding<Access> {
        Binding(
            get: { application.allowed == nil ? .askForAnything : .selectedOnly },
            set: { access in
                switch access {
                case .askForAnything:
                    model.setAllowed(nil, for: application.id)
                case .selectedOnly:
                    model.setAllowed(application.allowed ?? AccessSelection(), for: application.id)
                    editingAccess = model.applications.first { $0.id == application.id }
                }
            }
        )
    }

    var body: some View {
        Section {
            if model.applications.isEmpty {
                Text("No applications yet")
                    .foregroundStyle(.secondary)
            }
            ForEach(model.applications) { application in
                LabeledContent {
                    HStack {
                        Picker("Access", selection: access(for: application)) {
                            Text("Ask for anything").tag(Access.askForAnything)
                            Text("Selected only").tag(Access.selectedOnly)
                        }
                        .labelsHidden()
                        .fixedSize()
                        if application.allowed != nil {
                            Button("Edit…") { editingAccess = application }
                        }
                        Button("Remove…") { applicationToRemove = application }
                    }
                } label: {
                    Text(application.name)
                    Text(Self.subtitle(for: application))
                }
            }
            HStack {
                Spacer()
                Button("Add Application…") { isAdding = true }
            }
            .sheet(isPresented: $isAdding) {
                AddApplicationSheet(model: model)
            }
            .sheet(item: $editingAccess) { application in
                AccessSheet(model: model, application: application)
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
                Text("Applications you add get a key for the secrets socket. SSH clients are added when you first let them use a key. With Selected only, the chosen items or keys don't ask; anything else still does.")
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
                    Text(application.key ?? "")
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(application.key ?? "", forType: .string)
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

/// Chooses what an application may use without a prompt: folders and items,
/// or SSH keys for an SSH client. Anything else still asks.
private struct AccessSheet: View {
    @Bindable var model: AppModel
    let application: ExternalApplication
    @Environment(\.dismiss) private var dismiss
    @State private var selection: AccessSelection
    @State private var catalog: VaultCatalog?
    @State private var isLoading = true
    @State private var search = ""

    init(model: AppModel, application: ExternalApplication) {
        self.model = model
        self.application = application
        _selection = State(initialValue: application.allowed ?? AccessSelection())
    }

    private var isSSHClient: Bool {
        application.process != nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("What \(application.name) can use without asking")
                .font(.headline)
            Text("Anything else still asks for Touch ID.")
                .foregroundStyle(.secondary)

            if let catalog {
                if !isSSHClient {
                    TextField("Search", text: $search)
                        .textFieldStyle(.roundedBorder)
                }
                List {
                    if isSSHClient {
                        Section("SSH keys") {
                            ForEach(catalog.sshKeys, id: \.id) { key in
                                Toggle(key.name, isOn: toggle(\.itemIds, key.id))
                            }
                        }
                    } else {
                        let folders = catalog.folders.filter(matches)
                        if !folders.isEmpty {
                            Section("Folders") {
                                ForEach(folders) { folder in
                                    Toggle(folder.name, isOn: toggle(\.folderIds, folder.id))
                                }
                            }
                        }
                        Section("Items") {
                            ForEach(catalog.items.filter(matches), id: \.id) { item in
                                Toggle(isOn: toggle(\.itemIds, item.id)) {
                                    Text(item.name)
                                    Text(item.folder ?? "No folder")
                                }
                            }
                        }
                    }
                }
                .frame(height: 320)
            } else if !isLoading {
                HStack {
                    Text("Unlock the vault to choose.")
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Unlock with Touch ID") {
                        Task {
                            _ = await model.unlockWithTouchID()
                            await load()
                        }
                    }
                    .disabled(!model.account.canUnlockWithTouchID)
                }
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    model.setAllowed(selection, for: application.id)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(catalog == nil)
            }
        }
        .padding(20)
        .frame(width: 480)
        .task { await load() }
    }

    private func load() async {
        catalog = await model.account.catalog()
        isLoading = false
    }

    private func matches(_ folder: VaultCatalog.Folder) -> Bool {
        search.isEmpty || folder.name.localizedCaseInsensitiveContains(search)
    }

    private func matches(_ item: VaultEntry) -> Bool {
        search.isEmpty || item.name.localizedCaseInsensitiveContains(search) || (item.folder?.localizedCaseInsensitiveContains(search) ?? false)
    }

    private func toggle(_ ids: WritableKeyPath<AccessSelection, Set<String>>, _ id: String) -> Binding<Bool> {
        Binding(
            get: { selection[keyPath: ids].contains(id) },
            set: { isOn in
                if isOn {
                    selection[keyPath: ids].insert(id)
                } else {
                    selection[keyPath: ids].remove(id)
                }
            }
        )
    }
}
