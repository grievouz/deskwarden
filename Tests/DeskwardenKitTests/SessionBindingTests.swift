import Foundation
import Testing
@testable import DeskwardenKit

struct SessionBindingTests {
    @Test(arguments: [
        ["-t", "ed25519"],
        ["-t", "ecdsa", "-b", "256"],
        ["-t", "ecdsa", "-b", "384"],
        ["-t", "ecdsa", "-b", "521"],
        ["-t", "rsa", "-b", "2048"],
    ])
    func verifiesHostKeySignatures(arguments: [String]) throws {
        let hostKey = try OpenSSHPrivateKey(pem: TestKeys.generate(arguments, comment: "").privateKey)
        let sessionID = Data("exchange hash".utf8)
        let signature = try hostKey.sign(sessionID, flags: OpenSSHPrivateKey.rsaSHA256Flag)
        #expect(SSHPublicKey.verify(signature, of: sessionID, with: hostKey.publicKeyBlob))
        #expect(!SSHPublicKey.verify(signature, of: Data("another session".utf8), with: hostKey.publicKeyBlob))
    }

    @Test func refusesSHA1RSABindings() throws {
        let hostKey = try OpenSSHPrivateKey(pem: TestKeys.generate(["-t", "rsa", "-b", "2048"], comment: "").privateKey)
        let sessionID = Data("exchange hash".utf8)
        #expect(!SSHPublicKey.verify(try hostKey.sign(sessionID, flags: 0), of: sessionID, with: hostKey.publicKeyBlob))
    }

    @Test func bindsAndNamesTheServer() throws {
        let hostKey = try OpenSSHPrivateKey(pem: TestKeys.generate(["-t", "ed25519"], comment: "").privateKey)
        let knownHosts = try writeKnownHosts("[build.example]:2222,10.0.0.5 \(base64(hostKey))\n")
        var session = SSHSession()

        var forwarded = try bindRequest(hostKey, session: "one", forwarding: true)
        #expect(session.bind(&forwarded, knownHosts: knownHosts))
        #expect(session.isForwarded)
        #expect(session.forwardedFrom?.hostName == "build.example")
        #expect(session.destination == nil)

        // The forwarded agent then logs in to a further server.
        var hop = try bindRequest(hostKey, session: "two", forwarding: false)
        #expect(session.bind(&hop, knownHosts: knownHosts))
        #expect(session.destination?.hostName == "build.example")

        // Bound for logging in: no further binding.
        var after = try bindRequest(hostKey, session: "three", forwarding: true)
        #expect(!session.bind(&after, knownHosts: knownHosts))
    }

    @Test func refusesForgedAndRepeatedBindings() throws {
        let hostKey = try OpenSSHPrivateKey(pem: TestKeys.generate(["-t", "ed25519"], comment: "").privateKey)
        let other = try OpenSSHPrivateKey(pem: TestKeys.generate(["-t", "ed25519"], comment: "").privateKey)
        let knownHosts = URL(fileURLWithPath: "/nonexistent")
        var session = SSHSession()

        // Signed by a different key than the one claimed.
        var writer = SSHWriter()
        writer.writeString(hostKey.publicKeyBlob)
        writer.writeString(Data("one".utf8))
        writer.writeString(try other.sign(Data("one".utf8), flags: 0))
        writer.write(UInt8(1))
        var forged = SSHReader(writer.data)
        #expect(!session.bind(&forged, knownHosts: knownHosts))

        var first = try bindRequest(hostKey, session: "one", forwarding: true)
        #expect(session.bind(&first, knownHosts: knownHosts))
        var replayed = try bindRequest(hostKey, session: "one", forwarding: true)
        #expect(!session.bind(&replayed, knownHosts: knownHosts))
        #expect(session.forwardedFrom?.hostName == nil)
    }

    @Test func readsKnownHosts() throws {
        let hostKey = try OpenSSHPrivateKey(pem: TestKeys.generate(["-t", "ed25519"], comment: "").privateKey)
        let file = try writeKnownHosts("""
        # comment
        |1|aGFzaGVk|aGFzaA== \(base64(hostKey))
        @revoked github.com \(base64(hostKey))
        github.com,140.82.121.4 \(base64(hostKey))

        """)
        #expect(KnownHosts.hostName(for: hostKey.publicKeyBlob, in: file) == "github.com")
        #expect(KnownHosts.hostName(for: Data("other".utf8), in: file) == nil)
    }

    private func bindRequest(_ hostKey: OpenSSHPrivateKey, session: String, forwarding: Bool) throws -> SSHReader {
        var writer = SSHWriter()
        writer.writeString(hostKey.publicKeyBlob)
        writer.writeString(Data(session.utf8))
        writer.writeString(try hostKey.sign(Data(session.utf8), flags: OpenSSHPrivateKey.rsaSHA256Flag))
        writer.write(UInt8(forwarding ? 1 : 0))
        return SSHReader(writer.data)
    }

    private func base64(_ key: OpenSSHPrivateKey) -> String {
        var reader = SSHReader(key.publicKeyBlob)
        return "\((try? reader.readText()) ?? "") \(key.publicKeyBlob.base64EncodedString())"
    }

    private func writeKnownHosts(_ contents: String) throws -> URL {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("dw-known-hosts-\(UUID().uuidString)")
        try Data(contents.utf8).write(to: file)
        return file
    }
}
