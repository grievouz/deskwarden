import Foundation

/// Two-step login methods, by the server's numbering.
public enum TwoFactorMethod: Int, Sendable, Hashable, CaseIterable {
    case authenticator = 0
    case email = 1
    case duo = 2
    case yubiKey = 3
    case remember = 5
    case organizationDuo = 6
    case webAuthn = 7

    /// The methods a desktop app without a browser can complete.
    public var isSupported: Bool {
        self == .authenticator || self == .email
    }

    public var displayName: String {
        switch self {
        case .authenticator: "Authenticator app"
        case .email: "Email"
        case .duo, .organizationDuo: "Duo"
        case .yubiKey: "YubiKey"
        case .remember: "Remembered device"
        case .webAuthn: "Passkey or security key"
        }
    }
}

struct PreloginResponse: Decodable {
    let kdfSettings: KdfSettingsModel?
    let salt: String?
    // Older servers only send these.
    let kdf: Int?
    let kdfIterations: UInt32?
    let kdfMemory: UInt32?
    let kdfParallelism: UInt32?

    struct KdfSettingsModel: Decodable {
        let kdfType: Int
        let iterations: UInt32
        let memory: UInt32?
        let parallelism: UInt32?
    }

    var settings: KdfSettings? {
        if let kdfSettings, let kind = KdfSettings.Kind(rawValue: kdfSettings.kdfType) {
            return KdfSettings(kind: kind, iterations: kdfSettings.iterations, memory: kdfSettings.memory, parallelism: kdfSettings.parallelism)
        }
        if let kdf, let kdfIterations, let kind = KdfSettings.Kind(rawValue: kdf) {
            return KdfSettings(kind: kind, iterations: kdfIterations, memory: kdfMemory, parallelism: kdfParallelism)
        }
        return nil
    }
}

struct TokenResponse: Decodable {
    let access_token: String
    let expires_in: Int
    let refresh_token: String?
    let key: String?
    let privateKey: String?
    let accountKeys: AccountKeys?
    /// Sent when the user asked to remember the device after two-step login.
    let twoFactorToken: String?
    let userDecryptionOptions: UserDecryptionOptions?

    struct UserDecryptionOptions: Decodable {
        let hasMasterPassword: Bool?
        let masterPasswordUnlock: MasterPasswordUnlockModel?
    }
}

/// What unlocking with the master password needs. The token response and
/// every sync include it; the sync's copy is current after a password or KDF change.
struct MasterPasswordUnlockModel: Decodable {
    let kdf: KdfSettingsModel
    let masterKeyEncryptedUserKey: String
    let salt: String

    struct KdfSettingsModel: Decodable {
        let kdfType: Int
        let iterations: UInt32
        let memory: UInt32?
        let parallelism: UInt32?
    }

    var kdfSettings: KdfSettings? {
        KdfSettings.Kind(rawValue: kdf.kdfType).map {
            KdfSettings(kind: $0, iterations: kdf.iterations, memory: kdf.memory, parallelism: kdf.parallelism)
        }
    }
}

/// An error body from the identity server's token endpoint. Two-step login
/// is signalled by `TwoFactorProviders2`, a new-device check by `device_error`.
struct TokenErrorResponse: Decodable {
    let error: String?
    let error_description: String?
    let errorModel: ErrorModel?
    let twoFactorProviders2: [String: TwoFactorDetails?]?

    struct ErrorModel: Decodable {
        let message: String?
    }

    struct TwoFactorDetails: Decodable {
        let email: String?
    }
}

/// An error body from the API server.
struct APIErrorResponse: Decodable {
    let message: String?
}
