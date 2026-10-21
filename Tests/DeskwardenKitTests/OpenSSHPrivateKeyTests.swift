import CryptoKit
import Foundation
import Security
import Testing
@testable import DeskwardenKit

/// Keys made by the system's ssh-keygen, parsed and used to sign, with the
/// signatures checked against the public keys.
struct OpenSSHPrivateKeyTests {
    @Test(arguments: [
        ["-t", "ed25519"],
        ["-t", "ecdsa", "-b", "256"],
        ["-t", "ecdsa", "-b", "384"],
        ["-t", "ecdsa", "-b", "521"],
        ["-t", "rsa", "-b", "2048"],
        ["-t", "rsa", "-b", "3072"],
    ])
    func parsesAndSigns(arguments: [String]) throws {
        let generated = try TestKeys.generate(arguments, comment: "test key")
        let key = try OpenSSHPrivateKey(pem: generated.privateKey)
        #expect(key.publicKeyBlob == generated.publicKeyBlob)
        #expect(key.comment == "test key")

        let message = Data("data to sign".utf8)
        for flags in [0, OpenSSHPrivateKey.rsaSHA256Flag, OpenSSHPrivateKey.rsaSHA512Flag] {
            #expect(try verify(key.sign(message, flags: flags), of: message, key: key, flags: flags))
        }
    }

    @Test func rejectsEncryptedKeys() throws {
        let generated = try TestKeys.generate(["-t", "ed25519"], comment: "", passphrase: "secret")
        #expect(throws: OpenSSHPrivateKey.ParseError.encrypted) {
            try OpenSSHPrivateKey(pem: generated.privateKey)
        }
    }

    @Test func rejectsOtherFormats() {
        #expect(throws: OpenSSHPrivateKey.ParseError.notOpenSSHFormat) {
            try OpenSSHPrivateKey(pem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----")
        }
    }

    @Test func bigUIntRemainder() {
        // 2^100 + 12345 mod 1_000_003, checked independently.
        let dividend = BigUInt(Data([0x10] + [UInt8](repeating: 0, count: 10) + [0x30, 0x39]))
        #expect(dividend % BigUInt(Data([0x0F, 0x42, 0x43])) == BigUInt(Data([0x04, 0x0C, 0xEE])))
        #expect(BigUInt(Data([0x01, 0x00])) - BigUInt(1) == BigUInt(Data([0xFF])))
    }

    /// Checks a signature in SSH wire format with CryptoKit or the Security framework.
    private func verify(_ signature: Data, of message: Data, key: OpenSSHPrivateKey, flags: UInt32) throws -> Bool {
        var reader = SSHReader(signature)
        let algorithm = try reader.readText()
        let bytes = try reader.readString()
        switch key.key {
        case .ed25519(let privateKey):
            return algorithm == "ssh-ed25519" && privateKey.publicKey.isValidSignature(bytes, for: message)
        case .p256(let privateKey):
            return try algorithm == "ecdsa-sha2-nistp256"
                && privateKey.publicKey.isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: ecdsaRaw(bytes, size: 32)), for: message)
        case .p384(let privateKey):
            return try algorithm == "ecdsa-sha2-nistp384"
                && privateKey.publicKey.isValidSignature(P384.Signing.ECDSASignature(rawRepresentation: ecdsaRaw(bytes, size: 48)), for: message)
        case .p521(let privateKey):
            return try algorithm == "ecdsa-sha2-nistp521"
                && privateKey.publicKey.isValidSignature(P521.Signing.ECDSASignature(rawRepresentation: ecdsaRaw(bytes, size: 66)), for: message)
        case .rsa(let privateKey):
            let (expected, secAlgorithm): (String, SecKeyAlgorithm) =
                if flags & OpenSSHPrivateKey.rsaSHA512Flag != 0 { ("rsa-sha2-512", .rsaSignatureMessagePKCS1v15SHA512) }
                else if flags & OpenSSHPrivateKey.rsaSHA256Flag != 0 { ("rsa-sha2-256", .rsaSignatureMessagePKCS1v15SHA256) }
                else { ("ssh-rsa", .rsaSignatureMessagePKCS1v15SHA1) }
            return algorithm == expected
                && SecKeyVerifySignature(SecKeyCopyPublicKey(privateKey)!, secAlgorithm, message as CFData, bytes as CFData, nil)
        }
    }

    private func ecdsaRaw(_ blob: Data, size: Int) throws -> Data {
        var reader = SSHReader(blob)
        return try reader.readMPInt().leftPadded(to: size) + reader.readMPInt().leftPadded(to: size)
    }
}

enum TestKeys {
    struct Generated {
        let directory: URL
        let privateKey: String
        let publicKeyLine: String
        let publicKeyBlob: Data
    }

    static func generate(_ arguments: [String], comment: String, passphrase: String = "") throws -> Generated {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("dw-keys-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("key").path
        try run("/usr/bin/ssh-keygen", ["-q", "-N", passphrase, "-C", comment, "-f", path] + arguments)
        let publicKeyLine = try String(contentsOfFile: path + ".pub", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let blob = Data(base64Encoded: String(publicKeyLine.split(separator: " ")[1]))!
        return Generated(directory: directory, privateKey: try String(contentsOfFile: path, encoding: .utf8), publicKeyLine: publicKeyLine, publicKeyBlob: blob)
    }

    @discardableResult
    static func run(_ tool: String, _ arguments: [String], environment: [String: String] = [:], input: Data? = nil) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        let stdin = Pipe()
        process.standardInput = stdin
        try process.run()
        if let input { stdin.fileHandleForWriting.write(input) }
        try stdin.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw ToolFailed(message: "\(tool) \(arguments.joined(separator: " ")) exited \(process.terminationStatus): \(text)")
        }
        return text
    }

    struct ToolFailed: Error, CustomStringConvertible {
        let message: String
        var description: String { message }
    }
}
