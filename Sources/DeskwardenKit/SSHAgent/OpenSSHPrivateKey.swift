import CryptoKit
import Foundation
import Security

/// An unencrypted private key in OpenSSH's own format, the way Bitwarden
/// stores SSH keys, that can sign for the agent.
public struct OpenSSHPrivateKey: Sendable {
    public enum ParseError: Error, Equatable {
        case notOpenSSHFormat
        case encrypted
        case unsupportedKeyType(String)
        case malformed
    }

    enum Key: @unchecked Sendable {
        case ed25519(Curve25519.Signing.PrivateKey)
        case p256(P256.Signing.PrivateKey)
        case p384(P384.Signing.PrivateKey)
        case p521(P521.Signing.PrivateKey)
        case rsa(SecKey)
    }

    /// The public key in SSH wire format, as `ssh-add -L` shows it base64-encoded.
    public let publicKeyBlob: Data
    public let comment: String
    let key: Key

    public init(pem: String) throws(ParseError) {
        let body = pem
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
            .joined()
        guard pem.contains("BEGIN OPENSSH PRIVATE KEY"), let data = Data(base64Encoded: body) else {
            throw .notOpenSSHFormat
        }
        do {
            (publicKeyBlob, comment, key) = try Self.parse(data)
        } catch let error as ParseError {
            throw error
        } catch {
            throw .malformed
        }
    }

    private static let magic = Data("openssh-key-v1\0".utf8)

    private static func parse(_ data: Data) throws -> (Data, String, Key) {
        guard data.starts(with: magic) else { throw ParseError.notOpenSSHFormat }
        var reader = SSHReader(data.dropFirst(magic.count))
        let cipher = try reader.readText()
        _ = try reader.readText() // kdf name
        _ = try reader.readString() // kdf options
        guard cipher == "none" else { throw ParseError.encrypted }
        guard try reader.readUInt32() == 1 else { throw ParseError.malformed }
        let publicKeyBlob = try reader.readString()

        var secret = SSHReader(try reader.readString())
        guard try secret.readUInt32() == secret.readUInt32() else { throw ParseError.malformed }
        let type = try secret.readText()
        let key: Key
        switch type {
        case "ssh-ed25519":
            _ = try secret.readString() // public key
            let privateKey = try secret.readString() // seed followed by public key
            guard privateKey.count == 64 else { throw ParseError.malformed }
            key = .ed25519(try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey.prefix(32)))
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
            _ = try secret.readText() // curve name
            _ = try secret.readString() // public point
            let scalar = try secret.readMPInt()
            switch type {
            case "ecdsa-sha2-nistp256": key = .p256(try P256.Signing.PrivateKey(rawRepresentation: scalar.leftPadded(to: 32)))
            case "ecdsa-sha2-nistp384": key = .p384(try P384.Signing.PrivateKey(rawRepresentation: scalar.leftPadded(to: 48)))
            default: key = .p521(try P521.Signing.PrivateKey(rawRepresentation: scalar.leftPadded(to: 66)))
            }
        case "ssh-rsa":
            let n = try secret.readMPInt(), e = try secret.readMPInt(), d = try secret.readMPInt()
            let iqmp = try secret.readMPInt(), p = try secret.readMPInt(), q = try secret.readMPInt()
            key = .rsa(try rsaKey(n: n, e: e, d: d, p: p, q: q, iqmp: iqmp))
        default:
            throw ParseError.unsupportedKeyType(type)
        }
        let comment = try secret.readText()
        return (publicKeyBlob, comment, key)
    }

    /// Builds a Security framework key from OpenSSH's RSA fields. PKCS #1 also
    /// wants d mod (p - 1) and d mod (q - 1), which OpenSSH doesn't store;
    /// OpenSSH's iqmp is PKCS #1's coefficient.
    private static func rsaKey(n: Data, e: Data, d: Data, p: Data, q: Data, iqmp: Data) throws -> SecKey {
        let one = BigUInt(1)
        let dP = BigUInt(d) % (BigUInt(p) - one)
        let dQ = BigUInt(d) % (BigUInt(q) - one)
        let der = DER.sequence([
            DER.integer(Data([0])), DER.integer(n), DER.integer(e), DER.integer(d),
            DER.integer(p), DER.integer(q), DER.integer(dP.bigEndianBytes), DER.integer(dQ.bigEndianBytes), DER.integer(iqmp),
        ])
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(der as CFData, [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ] as CFDictionary, &error) else {
            throw ParseError.malformed
        }
        return key
    }

    // MARK: - Signing

    /// Agent sign-request flags asking for SHA-2 instead of SHA-1 with RSA keys.
    public static let rsaSHA256Flag: UInt32 = 0x02
    public static let rsaSHA512Flag: UInt32 = 0x04

    public struct SigningError: Error {}

    /// A signature in SSH wire format: the algorithm name, then the signature.
    public func sign(_ data: Data, flags: UInt32) throws -> Data {
        var signature = SSHWriter()
        switch key {
        case .ed25519(let key):
            signature.writeString("ssh-ed25519")
            signature.writeString(try key.signature(for: data))
        case .p256(let key):
            signature.writeString("ecdsa-sha2-nistp256")
            signature.writeString(Self.ecdsaBlob(try key.signature(for: data).rawRepresentation))
        case .p384(let key):
            signature.writeString("ecdsa-sha2-nistp384")
            signature.writeString(Self.ecdsaBlob(try key.signature(for: data).rawRepresentation))
        case .p521(let key):
            signature.writeString("ecdsa-sha2-nistp521")
            signature.writeString(Self.ecdsaBlob(try key.signature(for: data).rawRepresentation))
        case .rsa(let key):
            let (name, algorithm): (String, SecKeyAlgorithm) =
                if flags & Self.rsaSHA512Flag != 0 { ("rsa-sha2-512", .rsaSignatureMessagePKCS1v15SHA512) }
                else if flags & Self.rsaSHA256Flag != 0 { ("rsa-sha2-256", .rsaSignatureMessagePKCS1v15SHA256) }
                else { ("ssh-rsa", .rsaSignatureMessagePKCS1v15SHA1) }
            guard let bytes = SecKeyCreateSignature(key, algorithm, data as CFData, nil) else { throw SigningError() }
            signature.writeString(name)
            signature.writeString(bytes as Data)
        }
        return signature.data
    }

    /// ECDSA signatures are two mpints, r and s, inside the signature string.
    private static func ecdsaBlob(_ raw: Data) -> Data {
        var blob = SSHWriter()
        blob.writeMPInt(raw.prefix(raw.count / 2))
        blob.writeMPInt(raw.suffix(raw.count / 2))
        return blob.data
    }
}

extension Data {
    func leftPadded(to length: Int) -> Data {
        count >= length ? suffix(length) : Data(repeating: 0, count: length - count) + self
    }
}

/// Just enough DER to write an RSAPrivateKey.
enum DER {
    static func integer(_ magnitude: Data) -> Data {
        var bytes = Data(magnitude.drop { $0 == 0 })
        if bytes.isEmpty || bytes.first! & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        return element(tag: 0x02, bytes)
    }

    static func sequence(_ elements: [Data]) -> Data {
        element(tag: 0x30, elements.reduce(Data(), +))
    }

    private static func element(tag: UInt8, _ contents: Data) -> Data {
        var data = Data([tag])
        if contents.count < 0x80 {
            data.append(UInt8(contents.count))
        } else {
            let length = withUnsafeBytes(of: UInt32(contents.count).bigEndian) { Data($0) }.drop { $0 == 0 }
            data.append(0x80 | UInt8(length.count))
            data.append(contentsOf: length)
        }
        data.append(contents)
        return data
    }
}

/// Unsigned arbitrary-precision integers with only what RSA key import needs:
/// subtracting one and a remainder.
struct BigUInt: Equatable {
    /// 32-bit limbs, least significant first, without leading zero limbs.
    private(set) var limbs: [UInt32]

    init(_ value: UInt32) {
        limbs = value == 0 ? [] : [value]
    }

    init(_ bigEndian: Data) {
        var limbs: [UInt32] = []
        var bytes = Array(bigEndian)
        while !bytes.isEmpty {
            let chunk = bytes.suffix(4)
            bytes.removeLast(chunk.count)
            limbs.append(chunk.reduce(0) { $0 << 8 | UInt32($1) })
        }
        self.limbs = limbs
        trim()
    }

    var bigEndianBytes: Data {
        var data = Data()
        for limb in limbs.reversed() {
            data.append(contentsOf: [UInt8(limb >> 24), UInt8(limb >> 16 & 0xFF), UInt8(limb >> 8 & 0xFF), UInt8(limb & 0xFF)])
        }
        return Data(data.drop { $0 == 0 })
    }

    private var bitWidth: Int {
        guard let top = limbs.last else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    private func bit(_ index: Int) -> Bool {
        limbs[index / 32] >> (index % 32) & 1 == 1
    }

    private mutating func trim() {
        while limbs.last == 0 { limbs.removeLast() }
    }

    static func - (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        precondition(lhs >= rhs, "BigUInt subtraction would go negative")
        var result = lhs
        var borrow: UInt64 = 0
        for index in result.limbs.indices {
            let subtrahend = UInt64(index < rhs.limbs.count ? rhs.limbs[index] : 0) + borrow
            let minuend = UInt64(result.limbs[index])
            borrow = minuend < subtrahend ? 1 : 0
            result.limbs[index] = UInt32(truncatingIfNeeded: minuend &+ (borrow << 32) &- subtrahend)
        }
        result.trim()
        return result
    }

    /// Remainder by binary long division: shift in one bit of the dividend at
    /// a time and subtract the divisor whenever it fits.
    static func % (lhs: BigUInt, rhs: BigUInt) -> BigUInt {
        precondition(!rhs.limbs.isEmpty, "BigUInt division by zero")
        var remainder = BigUInt(0)
        for index in stride(from: lhs.bitWidth - 1, through: 0, by: -1) {
            remainder.shiftLeftOne(inserting: lhs.bit(index))
            if remainder >= rhs {
                remainder = remainder - rhs
            }
        }
        return remainder
    }

    private mutating func shiftLeftOne(inserting bit: Bool) {
        var carry: UInt32 = bit ? 1 : 0
        for index in limbs.indices {
            let next = limbs[index] >> 31
            limbs[index] = limbs[index] << 1 | carry
            carry = next
        }
        if carry != 0 { limbs.append(carry) }
    }

    static func >= (lhs: BigUInt, rhs: BigUInt) -> Bool {
        if lhs.limbs.count != rhs.limbs.count { return lhs.limbs.count > rhs.limbs.count }
        for index in lhs.limbs.indices.reversed() where lhs.limbs[index] != rhs.limbs[index] {
            return lhs.limbs[index] > rhs.limbs[index]
        }
        return true
    }
}
