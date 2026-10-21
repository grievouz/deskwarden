import Foundation
import Synchronization
import Testing
@testable import DeskwardenKit

/// The agent driven by the system's OpenSSH: `ssh-add -L` lists its keys and
/// `ssh-keygen -Y sign` signs through it, checked with `ssh-keygen -Y verify`.
@Suite(.serialized)
struct SSHAgentTests {
    @Test func listsAndSignsWithEveryKeyType() async throws {
        let keys = try [["-t", "ed25519"], ["-t", "ecdsa", "-b", "256"], ["-t", "rsa", "-b", "3072"]].enumerated().map { index, arguments in
            try TestKeys.generate(arguments, comment: "key \(index)")
        }
        let agent = try await TestAgent.start(keys: keys)
        defer { agent.stop() }

        let listed = try TestKeys.run("/usr/bin/ssh-add", ["-L"], environment: agent.environment)
        for key in keys {
            #expect(listed.contains(String(key.publicKeyLine.split(separator: " ")[1])))
        }

        for key in keys {
            try agent.signAndVerify(with: key)
        }
        // The first signature asked and added the client; the rest followed the setting.
        #expect(agent.prompts.count == 1)
        #expect(await agent.registry.applications.count == 1)
    }

    @Test func refusedFirstUseFailsAndAddsNothing() async throws {
        let key = try TestKeys.generate(["-t", "ed25519"], comment: "key")
        let agent = try await TestAgent.start(keys: [key], promptAnswer: false)
        defer { agent.stop() }

        #expect(throws: TestKeys.ToolFailed.self) {
            try agent.signAndVerify(with: key)
        }
        #expect(await agent.registry.applications.isEmpty)
    }

    @Test func unlocksALockedVaultToList() async throws {
        let key = try TestKeys.generate(["-t", "ed25519"], comment: "key")
        let agent = try await TestAgent.start(keys: [key], locked: true)
        defer { agent.stop() }

        let listed = try TestKeys.run("/usr/bin/ssh-add", ["-L"], environment: agent.environment)
        #expect(listed.contains(String(key.publicKeyLine.split(separator: " ")[1])))
        #expect(agent.keys.unlocks.withLock { $0 } == 1)
        // Unlocking counted as letting the client in, so it was added without another prompt.
        #expect(await agent.registry.applications.count == 1)
        #expect(agent.prompts.count == 0)
    }

    @Test func identifiesTheConnectingProcess() async throws {
        let key = try TestKeys.generate(["-t", "ed25519"], comment: "key")
        // Locked, so listing goes through the registry, which sees the client.
        let agent = try await TestAgent.start(keys: [key], locked: true)
        defer { agent.stop() }

        _ = try TestKeys.run("/usr/bin/ssh-add", ["-L"], environment: agent.environment)
        let client = try #require(await agent.registry.lastClient)
        #expect(client.chain.first?.name == "ssh-add")
        #expect(client.chain.first?.path == "/usr/bin/ssh-add")
        #expect(!client.appName.isEmpty)
    }
}

private final class TestAgent: Sendable {
    let server: SSHAgentServer
    let directory: URL
    let keys: FakeKeys
    let registry: FakeRegistry
    let prompts: PromptCounter

    var environment: [String: String] {
        ["SSH_AUTH_SOCK": server.socketPath]
    }

    private init(server: SSHAgentServer, directory: URL, keys: FakeKeys, registry: FakeRegistry, prompts: PromptCounter) {
        self.server = server
        self.directory = directory
        self.keys = keys
        self.registry = registry
        self.prompts = prompts
    }

    static func start(keys generated: [TestKeys.Generated], locked: Bool = false, promptAnswer: Bool = true) async throws -> TestAgent {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dw-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let keys = FakeKeys(keys: generated, locked: locked)
        let registry = FakeRegistry()
        let prompts = PromptCounter(answer: promptAnswer)
        let access = SSHAccess(keys: keys, applications: registry, approvals: FixedApprover(approved: true), prompt: prompts.prompt)
        let server = SSHAgentServer(socketPath: directory.appendingPathComponent("agent.sock").path, handler: access)
        await withCheckedContinuation { continuation in
            let resumed = Mutex(false)
            server.onStatusChange = { status in
                guard status != .stopped, !resumed.withLock({ let was = $0; $0 = true; return was }) else { return }
                continuation.resume()
            }
            server.start()
        }
        return TestAgent(server: server, directory: directory, keys: keys, registry: registry, prompts: prompts)
    }

    func stop() {
        server.stop()
        try? FileManager.default.removeItem(at: directory)
    }

    /// Signs a file through the agent with only the public key on disk, then verifies it.
    func signAndVerify(with key: TestKeys.Generated) throws {
        let publicKey = key.directory.appendingPathComponent("key.pub").path
        try? FileManager.default.removeItem(at: key.directory.appendingPathComponent("key"))
        let message = key.directory.appendingPathComponent("message")
        try Data("signed through the agent".utf8).write(to: message)
        try TestKeys.run("/usr/bin/ssh-keygen", ["-Y", "sign", "-f", publicKey, "-n", "test", message.path], environment: environment)

        let signers = key.directory.appendingPathComponent("allowed_signers")
        try Data("test@deskwarden \(key.publicKeyLine)\n".utf8).write(to: signers)
        let verified = try TestKeys.run(
            "/usr/bin/ssh-keygen",
            ["-Y", "verify", "-f", signers.path, "-I", "test@deskwarden", "-n", "test", "-s", message.path + ".sig"],
            input: Data("signed through the agent".utf8)
        )
        #expect(verified.contains("Good"))
    }
}

private final class FakeKeys: SSHKeyProvider {
    let entries: [SSHKeyEntry]
    let privateKeys: [String: String]
    let locked: Mutex<Bool>
    let unlocks = Mutex(0)

    init(keys: [TestKeys.Generated], locked: Bool) {
        entries = keys.enumerated().map { SSHKeyEntry(id: "\($0.offset)", name: "key \($0.offset)", publicKeyBlob: $0.element.publicKeyBlob) }
        privateKeys = Dictionary(uniqueKeysWithValues: keys.enumerated().map { ("\($0.offset)", $0.element.privateKey) })
        self.locked = Mutex(locked)
    }

    var isLocked: Bool {
        locked.withLock { $0 }
    }

    func unlock(reason: String) async -> Bool {
        unlocks.withLock { $0 += 1 }
        locked.withLock { $0 = false }
        return true
    }

    func sshKeys() async -> [SSHKeyEntry] {
        isLocked ? [] : entries
    }

    func sshPrivateKey(id: String) async -> String? {
        privateKeys[id]
    }
}

private actor FakeRegistry: SSHApplicationRegistry {
    private(set) var applications: [ExternalApplication] = []
    private(set) var lastClient: SSHClient?

    func application(for client: SSHClient) -> ExternalApplication? {
        lastClient = client
        return applications.first { $0.process?.matches(client.identity) == true }
    }

    func addApplication(for client: SSHClient) -> ExternalApplication? {
        let application = ExternalApplication.sshClient(client)
        applications.append(application)
        return application
    }

    func markUsed(_ application: ExternalApplication) {}
}

private final class PromptCounter: Sendable {
    let answer: Bool
    private let prompts = Mutex(0)

    init(answer: Bool) {
        self.answer = answer
    }

    var count: Int { prompts.withLock { $0 } }

    var prompt: TouchIDApprover.Prompt {
        { [self] _ in
            prompts.withLock { $0 += 1 }
            return answer
        }
    }
}
