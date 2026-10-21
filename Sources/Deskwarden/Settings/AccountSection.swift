import SwiftUI

struct AccountSection: View {
    enum Server: String, CaseIterable, Identifiable {
        case us = "bitwarden.com"
        case eu = "bitwarden.eu"
        case selfHosted = "Self-hosted"

        var id: String { rawValue }
    }

    @State private var server = Server.us
    @State private var serverURL = ""
    @State private var email = ""
    @State private var password = ""

    var body: some View {
        Section {
            Picker("Server", selection: $server) {
                ForEach(Server.allCases) { server in
                    Text(server.rawValue).tag(server)
                }
            }
            if server == .selfHosted {
                TextField("Server URL", text: $serverURL, prompt: Text("https://vault.example.com"))
            }
            TextField("Email", text: $email)
                .textContentType(.username)
            SecureField("Master password", text: $password)
                .textContentType(.password)
            HStack {
                Spacer()
                Button("Log In") {}
                    .disabled(true)
            }
        } header: {
            Text("Account")
        } footer: {
            Text("Signing in to Bitwarden isn't built yet.")
                .foregroundStyle(.secondary)
        }
    }
}
