import CryptoKit
import Foundation
import LocalAuthentication

public enum TouchIDError: Error, Equatable, Sendable {
    /// No Touch ID on this Mac right now (none enrolled, lid closed, locked out).
    case unavailable
    case cancelled
    /// The user chose the prompt's "Use Master Password" button.
    case fallbackToPassword
    /// The sealing key no longer works, e.g. fingerprints changed since it was made.
    case invalidated
    case failed(String)
}

/// Seals and opens the vault's user key so that only Touch ID on this Mac can
/// open it again.
protocol UserKeyProtector: Sendable {
    var isAvailable: Bool { get }
    func seal(_ userKey: String) throws(TouchIDError) -> Data
    func open(_ sealed: Data, reason: String) async throws(TouchIDError) -> String
}

/// The sealing format, independent of where the private key lives: ECIES with
/// P-256, HKDF-SHA256 and AES-GCM.
struct SealedUserKey: Codable {
    static let info = Data("deskwarden-touch-id-unlock-v1".utf8)

    /// The Secure Enclave key, in the encrypted form only this Mac's enclave can use.
    let enclaveKey: Data
    let ephemeralPublicKey: Data
    let box: Data

    static func seal(_ userKey: String, to recipient: P256.KeyAgreement.PublicKey, enclaveKey: Data) throws -> SealedUserKey {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let key = derive(try ephemeral.sharedSecretFromKeyAgreement(with: recipient))
        let box = try AES.GCM.seal(Data(userKey.utf8), using: key)
        return SealedUserKey(enclaveKey: enclaveKey, ephemeralPublicKey: ephemeral.publicKey.x963Representation, box: box.combined!)
    }

    func open(agreeingWith agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret) throws -> String {
        let key = Self.derive(try agree(P256.KeyAgreement.PublicKey(x963Representation: ephemeralPublicKey)))
        let data = try AES.GCM.open(AES.GCM.SealedBox(combined: box), using: key)
        return String(decoding: data, as: UTF8.self)
    }

    private static func derive(_ secret: SharedSecret) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: info, outputByteCount: 32)
    }
}

/// Keeps the sealing key in the Secure Enclave, usable only after Touch ID and
/// only with the fingerprints enrolled when it was made. Needs no keychain
/// entitlement: CryptoKit hands back the key as an opaque blob to store.
struct SecureEnclaveKeyProtector: UserKeyProtector {
    var isAvailable: Bool {
        SecureEnclave.isAvailable && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    func seal(_ userKey: String) throws(TouchIDError) -> Data {
        guard isAvailable else { throw .unavailable }
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil
        ) else { throw .failed("couldn't create the access control") }
        do {
            let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            let sealed = try SealedUserKey.seal(userKey, to: enclaveKey.publicKey, enclaveKey: enclaveKey.dataRepresentation)
            return try JSONEncoder().encode(sealed)
        } catch {
            throw .failed("\(error)")
        }
    }

    func open(_ data: Data, reason: String) async throws(TouchIDError) -> String {
        guard let sealed = try? JSONDecoder().decode(SealedUserKey.self, from: data) else { throw .invalidated }
        let context = LAContext()
        context.localizedFallbackTitle = "Use Master Password"
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel: throw .cancelled
            case .userFallback: throw .fallbackToPassword
            case .authenticationFailed, .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .notInteractive: throw .unavailable
            default: throw .failed(error.localizedDescription)
            }
        } catch {
            throw .failed(error.localizedDescription)
        }
        // The context is already authenticated, so using the key doesn't prompt again.
        do {
            let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: sealed.enclaveKey, authenticationContext: context)
            return try sealed.open { try enclaveKey.sharedSecretFromKeyAgreement(with: $0) }
        } catch {
            throw .invalidated
        }
    }
}
