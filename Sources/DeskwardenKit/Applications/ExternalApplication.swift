import Foundation
import Security

/// An application allowed to use Deskwarden: either one with a key for the
/// secrets socket, or an SSH client recognized by its process.
///
/// A key application is configured with a single string, `dwk_<id>_<secret>`.
/// The id is the TLS PSK identity and the secret is the PSK itself, so the
/// same string both authenticates the application and keys the encryption.
/// SSH clients can't present a key, so they're added when first approved and
/// recognized by `process` after that.
public struct ExternalApplication: Codable, Identifiable, Hashable, Sendable {
    public static let keyPrefix = "dwk_"
    static let secretLength = 32

    public let id: String
    public var name: String
    public let secret: Data?
    public let process: ProcessIdentity?
    /// What the application may use without a prompt while the vault is
    /// unlocked. `nil` means it's asked about anything, per Verify requests.
    public var allowed: AccessSelection?
    public let createdAt: Date
    public var lastUsedAt: Date?

    public init(
        id: String,
        name: String,
        secret: Data?,
        process: ProcessIdentity? = nil,
        allowed: AccessSelection? = nil,
        createdAt: Date = .now,
        lastUsedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.secret = secret
        self.process = process
        self.allowed = allowed
        self.createdAt = createdAt
        self.lastUsedAt = lastUsedAt
    }

    public static func generate(name: String) -> ExternalApplication {
        ExternalApplication(id: newID(), name: name, secret: randomBytes(secretLength))
    }

    public static func sshClient(_ client: SSHClient) -> ExternalApplication {
        ExternalApplication(id: newID(), name: client.appName, secret: nil, process: client.identity)
    }

    private static func newID() -> String {
        randomBytes(8).map { String(format: "%02x", $0) }.joined()
    }

    /// The string a key application is configured with.
    public var key: String? {
        secret.map { "\(Self.keyPrefix)\(id)_\($0.base64URLEncodedString())" }
    }

    public static func parse(key: String) -> (id: String, secret: Data)? {
        guard key.hasPrefix(keyPrefix) else { return nil }
        let parts = key.dropFirst(keyPrefix.count).split(separator: "_", maxSplits: 1)
        guard parts.count == 2,
              let secret = Data(base64URLEncoded: String(parts[1])),
              secret.count == secretLength
        else { return nil }
        return (String(parts[0]), secret)
    }
}

func randomBytes(_ count: Int) -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
    return data
}

extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}
