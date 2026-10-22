import CryptoKit
import Foundation
import Security

/// What `session-bind@openssh.com` told the agent about a connection: which
/// server it's for, and whether it carries an agent forwarded to that server.
///
/// OpenSSH (8.9 and later) binds each agent connection before using it: to
/// the server it's logging in to, or, for a forwarded agent, to the server the
/// agent was forwarded to. The server's host key signs the session
/// identifier, so a client can't claim a server it isn't talking to.
public struct SessionBinding: Sendable, Hashable {
    public let hostKeyFingerprint: String
    /// The host's name from known_hosts, when it's listed by name rather than hashed.
    public let hostName: String?
    public let isForwarding: Bool

    public var displayName: String {
        hostName ?? "an unknown server (\(hostKeyFingerprint))"
    }
}

/// The bindings of one agent connection, in order. A forwarded agent used to
/// log in further gets one binding per hop.
public struct SSHSession: Sendable, Hashable {
    public private(set) var bindings: [SessionBinding] = []
    private var sessionIdentifiers: Set<Data> = []

    public init() {}

    /// Requests on this connection come from a server the agent was forwarded to.
    public var isForwarded: Bool {
        bindings.contains(where: \.isForwarding)
    }

    /// The server the agent was forwarded to, if it was.
    public var forwardedFrom: SessionBinding? {
        bindings.first(where: \.isForwarding)
    }

    /// The server being logged in to, if the connection is bound for that.
    public var destination: SessionBinding? {
        bindings.last.flatMap { $0.isForwarding ? nil : $0 }
    }

    /// Records a `session-bind@openssh.com` request. Like OpenSSH's own agent,
    /// refuses a bad signature, a repeated session, and binding a connection
    /// again after it was bound for logging in.
    mutating func bind(_ request: inout SSHReader, knownHosts: URL) -> Bool {
        guard let hostKey = try? request.readString(),
              let sessionIdentifier = try? request.readString(),
              let signature = try? request.readString(),
              let forwarding = try? request.readByte(),
              !sessionIdentifiers.contains(sessionIdentifier),
              bindings.last?.isForwarding != false,
              SSHPublicKey.verify(signature, of: sessionIdentifier, with: hostKey)
        else { return false }
        sessionIdentifiers.insert(sessionIdentifier)
        bindings.append(SessionBinding(
            hostKeyFingerprint: SSHPublicKey.fingerprint(hostKey),
            hostName: KnownHosts.hostName(for: hostKey, in: knownHosts),
            isForwarding: forwarding != 0
        ))
        return true
    }
}

enum SSHPublicKey {
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    static func fingerprint(_ keyBlob: Data) -> String {
        "SHA256:" + Data(SHA256.hash(data: keyBlob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    /// Checks an SSH-format signature against a public key in wire format.
    static func verify(_ signature: Data, of data: Data, with keyBlob: Data) -> Bool {
        do {
            var key = SSHReader(keyBlob)
            var sig = SSHReader(signature)
            let keyType = try key.readText()
            let algorithm = try sig.readText()
            let bytes = try sig.readString()
            switch keyType {
            case "ssh-ed25519":
                guard algorithm == keyType else { return false }
                return try Curve25519.Signing.PublicKey(rawRepresentation: key.readString()).isValidSignature(bytes, for: data)
            case "ecdsa-sha2-nistp256":
                guard algorithm == keyType else { return false }
                _ = try key.readText()
                return try P256.Signing.PublicKey(x963Representation: key.readString())
                    .isValidSignature(P256.Signing.ECDSASignature(rawRepresentation: ecdsaRaw(bytes, size: 32)), for: data)
            case "ecdsa-sha2-nistp384":
                guard algorithm == keyType else { return false }
                _ = try key.readText()
                return try P384.Signing.PublicKey(x963Representation: key.readString())
                    .isValidSignature(P384.Signing.ECDSASignature(rawRepresentation: ecdsaRaw(bytes, size: 48)), for: data)
            case "ecdsa-sha2-nistp521":
                guard algorithm == keyType else { return false }
                _ = try key.readText()
                return try P521.Signing.PublicKey(x963Representation: key.readString())
                    .isValidSignature(P521.Signing.ECDSASignature(rawRepresentation: ecdsaRaw(bytes, size: 66)), for: data)
            case "ssh-rsa":
                let secAlgorithm: SecKeyAlgorithm
                switch algorithm {
                case "rsa-sha2-256": secAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
                case "rsa-sha2-512": secAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
                default: return false // SHA-1 signatures aren't accepted for binding.
                }
                let exponent = try key.readMPInt()
                let modulus = try key.readMPInt()
                let der = DER.sequence([DER.integer(modulus), DER.integer(exponent)])
                guard let publicKey = SecKeyCreateWithData(der as CFData, [
                    kSecAttrKeyType: kSecAttrKeyTypeRSA,
                    kSecAttrKeyClass: kSecAttrKeyClassPublic,
                ] as CFDictionary, nil) else { return false }
                return SecKeyVerifySignature(publicKey, secAlgorithm, data as CFData, bytes as CFData, nil)
            default:
                return false
            }
        } catch {
            return false
        }
    }

    private static func ecdsaRaw(_ blob: Data, size: Int) throws -> Data {
        var reader = SSHReader(blob)
        return try reader.readMPInt().leftPadded(to: size) + reader.readMPInt().leftPadded(to: size)
    }
}

enum KnownHosts {
    static var defaultFile: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/known_hosts")
    }

    /// The first name a host key is listed under. Hashed entries can't be read back.
    static func hostName(for keyBlob: Data, in file: URL) -> String? {
        guard let contents = try? String(contentsOf: file, encoding: .utf8) else { return nil }
        for line in contents.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 3, !fields[0].hasPrefix("@"), !fields[0].hasPrefix("#"),
                  Data(base64Encoded: String(fields[2])) == keyBlob
            else { continue }
            for host in fields[0].split(separator: ",") where !host.hasPrefix("|") {
                // "[host]:port" for servers on another port.
                if host.hasPrefix("["), let end = host.firstIndex(of: "]") {
                    return String(host[host.index(after: host.startIndex)..<end])
                }
                return String(host)
            }
        }
        return nil
    }
}
