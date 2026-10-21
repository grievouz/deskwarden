import CryptoKit
import Foundation
import Testing
@testable import DeskwardenAccount

/// The sealing format with a software key in place of the Secure Enclave one.
struct SealedUserKeyTests {
    @Test func opensWithTheRecipientKey() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let sealed = try SealedUserKey.seal("user-key-b64", to: recipient.publicKey, enclaveKey: Data())
        #expect(try sealed.open { try recipient.sharedSecretFromKeyAgreement(with: $0) } == "user-key-b64")
    }

    @Test func doesNotOpenWithAnotherKey() throws {
        let sealed = try SealedUserKey.seal("user-key-b64", to: P256.KeyAgreement.PrivateKey().publicKey, enclaveKey: Data())
        let other = P256.KeyAgreement.PrivateKey()
        #expect(throws: (any Error).self) {
            try sealed.open { try other.sharedSecretFromKeyAgreement(with: $0) }
        }
    }

    @Test func survivesEncoding() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let sealed = try SealedUserKey.seal("user-key-b64", to: recipient.publicKey, enclaveKey: Data([1, 2, 3]))
        let decoded = try JSONDecoder().decode(SealedUserKey.self, from: JSONEncoder().encode(sealed))
        #expect(decoded.enclaveKey == Data([1, 2, 3]))
        #expect(try decoded.open { try recipient.sharedSecretFromKeyAgreement(with: $0) } == "user-key-b64")
    }
}
