// Runs the real secrets socket against fixture items, so clients such as the
// varlock plugin can be tested end to end without the app, a vault or Touch ID.
//
//   SocketHarness <socket-path>
//
// Prints `READY <key>` once listening. DESKWARDEN_HARNESS_DENY=1 denies
// every approval and DESKWARDEN_HARNESS_LOCKED=1 behaves like a locked vault.
import DeskwardenKit
import Foundation

let arguments = CommandLine.arguments
guard arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: SocketHarness <socket-path>\n".utf8))
    exit(64)
}
let environment = ProcessInfo.processInfo.environment

let fixtures = [
    VaultItem(
        id: "5f0c6d1e-2b8a-4c3e-9a51-1d2f3e4a5b6c",
        name: "Postgres prod",
        folder: "Infra",
        username: "app",
        password: "pg-secret",
        fields: ["Port": "5432"]
    ),
    VaultItem(id: "7a1b2c3d-0000-4000-8000-000000000001", name: "Stripe", folder: "Infra", password: "sk_test_infra"),
    VaultItem(id: "7a1b2c3d-0000-4000-8000-000000000002", name: "Stripe", folder: "Personal", password: "sk_test_personal"),
    VaultItem(id: "7a1b2c3d-0000-4000-8000-000000000003", name: "Deploy notes", notes: "line one\nline two"),
]

let application = ExternalApplication.generate(name: "harness")
let server = SecretsServer(
    socketPath: arguments[1],
    secrets: StaticSecretProvider(items: environment["DESKWARDEN_HARNESS_LOCKED"] == "1" ? nil : fixtures),
    approvals: FixedApprover(approved: environment["DESKWARDEN_HARNESS_DENY"] != "1")
)
server.onStatusChange = { status in
    switch status {
    case .listening:
        print("READY \(application.key)")
        fflush(stdout)
    case .failed(let message):
        FileHandle.standardError.write(Data("failed: \(message)\n".utf8))
        exit(1)
    case .stopped, .noApplications:
        break
    }
}
server.start(applications: [application])
dispatchMain()
