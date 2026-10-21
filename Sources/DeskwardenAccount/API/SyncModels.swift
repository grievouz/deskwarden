import Foundation

// The parts of `GET /api/sync` Deskwarden uses. Every string that holds vault
// data is still encrypted (an EncString); the SDK decrypts them.

struct SyncResponse: Decodable {
    let profile: Profile
    let folders: [Folder]
    let ciphers: [Cipher]
    let userDecryption: UserDecryption?

    struct Profile: Decodable {
        let id: String
        let email: String
        let privateKey: String?
        let accountKeys: AccountKeys?
        let organizations: [Organization]?
        let organizationsNew: [Organization]?
    }

    struct UserDecryption: Decodable {
        let masterPasswordUnlock: MasterPasswordUnlockModel?
        let v2UpgradeToken: UpgradeToken?
    }

    struct Organization: Decodable {
        let id: String
        let key: String?
    }

    struct Folder: Decodable {
        let id: String
        let name: String
        let revisionDate: Date
    }

    struct Cipher: Decodable {
        let id: String
        let organizationId: String?
        let folderId: String?
        let collectionIds: [String]?
        let key: String?
        let name: String?
        let notes: String?
        let type: UInt8
        let login: Login?
        let secureNote: SecureNote?
        let sshKey: SSHKey?
        let favorite: Bool
        let reprompt: UInt8?
        let organizationUseTotp: Bool
        let edit: Bool
        let viewPassword: Bool
        let fields: [Field]?
        let creationDate: Date
        let deletedDate: Date?
        let revisionDate: Date
        let archivedDate: Date?
        let data: String?
    }

    struct Login: Decodable {
        let username: String?
        let password: String?
        let passwordRevisionDate: Date?
        let uris: [LoginURI]?
        let totp: String?
        let autofillOnPageLoad: Bool?
    }

    struct LoginURI: Decodable {
        let uri: String?
        let match: UInt8?
        let uriChecksum: String?
    }

    struct Field: Decodable {
        let name: String?
        let value: String?
        let type: UInt8
        let linkedId: UInt32?
    }

    struct SecureNote: Decodable {
        let type: UInt8
    }

    struct SSHKey: Decodable {
        let privateKey: String
        let publicKey: String?
        let keyFingerprint: String?
    }
}

/// The account's key material for V2 encryption (signing keys and a signed
/// security state). Absent on V1 accounts, which only have `privateKey`.
struct AccountKeys: Codable, Hashable {
    let publicKeyEncryptionKeyPair: PublicKeyEncryptionKeyPair
    let signatureKeyPair: SignatureKeyPair?
    let securityState: SecurityState?

    struct PublicKeyEncryptionKeyPair: Codable, Hashable {
        let wrappedPrivateKey: String
        let publicKey: String?
        let signedPublicKey: String?
    }

    struct SignatureKeyPair: Codable, Hashable {
        let wrappedSigningKey: String
        let verifyingKey: String?
    }

    struct SecurityState: Codable, Hashable {
        let securityState: String?
        let securityVersion: Int?
    }
}

/// Lets an account mid-way through the V1 to V2 encryption upgrade unlock
/// with either user key.
struct UpgradeToken: Codable, Hashable {
    let wrappedUserKey1: String
    let wrappedUserKey2: String
}
