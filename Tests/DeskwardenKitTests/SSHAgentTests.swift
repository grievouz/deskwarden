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

    @Test func selectedKeysSignWithoutAsking() async throws {
        let keys = try [try TestKeys.generate(["-t", "ed25519"], comment: "key 0"), try TestKeys.generate(["-t", "ed25519"], comment: "key 1")]
        let agent = try await TestAgent.start(keys: keys, policy: .everyRequest)
        defer { agent.stop() }

        // First use asks and adds the client.
        try agent.signAndVerify(with: keys[0])
        #expect(agent.prompts.count == 1)
        await agent.registry.setAllowed(AccessSelection(itemIds: ["0"]))

        try agent.signAndVerify(with: keys[0])
        #expect(agent.prompts.count == 1)
        // A key that isn't selected still asks.
        try agent.signAndVerify(with: keys[1])
        #expect(agent.prompts.count == 2)
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

    /// `ssh -A` to a real sshd on localhost: logging in signs locally, then the
    /// server signs through the forwarded agent, which must ask even though the
    /// app was just approved.
    @Test(.enabled(if: FileManager.default.isExecutableFile(atPath: "/usr/sbin/sshd")))
    func forwardedAgentRequestsAlwaysAsk() async throws {
        let key = try TestKeys.generate(["-t", "ed25519"], comment: "key")
        let server = try TestSSHServer.start(authorizing: key)
        defer { server.stop() }
        let agent = try await TestAgent.start(keys: [key], policy: .firstRequest, knownHosts: server.knownHosts)
        defer { agent.stop() }

        let message = key.directory.appendingPathComponent("message")
        try Data("signed on the server".utf8).write(to: message)
        try server.run("ssh-keygen -Y sign -f \(key.directory.path)/key.pub -n test \(message.path)", agent: agent, forwardAgent: true)
        #expect(FileManager.default.fileExists(atPath: message.path + ".sig"))

        let actions = agent.prompts.actions
        #expect(actions.count == 2)
        #expect(actions.first?.contains("to sign in to 127.0.0.1") == true)
        #expect(actions.last?.contains("for a forwarded connection from 127.0.0.1") == true)

        // Logging in again doesn't ask: local approvals are still remembered.
        try server.run("true", agent: agent, forwardAgent: false)
        #expect(agent.prompts.count == 2)
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

    /// `policy` puts a real verification policy in front of the prompt;
    /// without one, every approval past an app's first use is granted.
    static func start(
        keys generated: [TestKeys.Generated],
        locked: Bool = false,
        promptAnswer: Bool = true,
        policy: VerificationPolicy? = nil,
        knownHosts: URL? = nil
    ) async throws -> TestAgent {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dw-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let keys = FakeKeys(keys: generated, locked: locked)
        let registry = FakeRegistry()
        let prompts = PromptCounter(answer: promptAnswer)
        let approvals: ApprovalProvider = policy.map { TouchIDApprover(policy: $0, prompt: prompts.prompt) } ?? FixedApprover(approved: true)
        let access = SSHAccess(keys: keys, applications: registry, approvals: approvals, prompt: prompts.prompt)
        let server = SSHAgentServer(socketPath: directory.appendingPathComponent("agent.sock").path, handler: access, knownHosts: knownHosts)
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

    func setAllowed(_ selection: AccessSelection?) {
        for index in applications.indices {
            applications[index].allowed = selection
        }
    }
}

private final class PromptCounter: Sendable {
    let answer: Bool
    private let prompts = Mutex<[String]>([])

    init(answer: Bool) {
        self.answer = answer
    }

    var count: Int { prompts.withLock { $0.count } }
    /// What each prompt asked to allow.
    var actions: [String] { prompts.withLock { $0 } }

    var prompt: TouchIDApprover.Prompt {
        { [self] request in
            prompts.withLock { $0.append(request.action) }
            return answer
        }
    }
}

/// An unprivileged sshd on localhost that lets the test user in with one key.
private struct TestSSHServer {
    let directory: URL
    let port: Int
    let process: Process

    var knownHosts: URL { directory.appendingPathComponent("known_hosts") }

    static func start(authorizing key: TestKeys.Generated) throws -> TestSSHServer {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dw-sshd-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try TestKeys.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", directory.appendingPathComponent("host_key").path])
        try Data((key.publicKeyLine + "\n").utf8).write(to: directory.appendingPathComponent("authorized_keys"))
        let port = Int.random(in: 30000...39999)
        let config = """
        Port \(port)
        ListenAddress 127.0.0.1
        HostKey \(directory.path)/host_key
        AuthorizedKeysFile \(directory.path)/authorized_keys
        PidFile \(directory.path)/sshd.pid
        UsePAM no
        StrictModes no
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        AllowAgentForwarding yes
        """
        try Data(config.utf8).write(to: directory.appendingPathComponent("sshd_config"))
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
        process.arguments = ["-D", "-f", directory.appendingPathComponent("sshd_config").path, "-E", directory.appendingPathComponent("sshd.log").path]
        try process.run()
        // Wait for it to listen.
        for _ in 0..<50 where !FileManager.default.fileExists(atPath: directory.appendingPathComponent("sshd.pid").path) {
            Thread.sleep(forTimeInterval: 0.1)
        }
        return TestSSHServer(directory: directory, port: port, process: process)
    }

    @discardableResult
    func run(_ command: String, agent: TestAgent, forwardAgent: Bool) throws -> String {
        try TestKeys.run("/usr/bin/ssh", [
            "-F", "/dev/null",
            "-o", "IdentityAgent=\(agent.server.socketPath)",
            "-o", "ForwardAgent=\(forwardAgent ? "yes" : "no")",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=\(knownHosts.path)",
            "-o", "BatchMode=yes",
            "-p", String(port), "127.0.0.1", command,
        ], environment: agent.environment)
    }

    /// `waitUntilExit` needs the run loop of the thread that launched sshd,
    /// which an async test doesn't keep, so this waits on the pid instead.
    func stop() {
        let pid = process.processIdentifier
        kill(pid, SIGTERM)
        var status: Int32 = 0
        _ = waitpid(pid, &status, 0)
        try? FileManager.default.removeItem(at: directory)
    }
}
