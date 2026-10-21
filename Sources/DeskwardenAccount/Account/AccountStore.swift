import DeskwardenKit
import Foundation

/// KDF settings as the server reports them. Kept in Deskwarden's own format so
/// a stored account survives SDK updates.
struct KdfSettings: Codable, Hashable, Sendable {
    enum Kind: Int, Codable, Sendable {
        case pbkdf2 = 0
        case argon2id = 1
    }

    let kind: Kind
    let iterations: UInt32
    /// MiB, Argon2id only.
    let memory: UInt32?
    let parallelism: UInt32?
}

/// What's needed to unlock the vault again without the server: everything
/// here is either public or encrypted with the master key or user key.
struct StoredAccount: Codable, Sendable {
    let server: BitwardenServer
    let userId: String
    let email: String
    var kdf: KdfSettings
    var salt: String
    var masterKeyWrappedUserKey: String
    var privateKey: String
    var accountKeys: AccountKeys?
    var v2UpgradeToken: UpgradeToken?
    var lastSyncedAt: Date?

    /// Takes the key material from a sync, which is current after a password,
    /// KDF or encryption upgrade on another device.
    mutating func updateKeys(from sync: SyncResponse) {
        if let unlock = sync.userDecryption?.masterPasswordUnlock, let kdf = unlock.kdfSettings {
            self.kdf = kdf
            salt = unlock.salt
            masterKeyWrappedUserKey = unlock.masterKeyEncryptedUserKey
        }
        if let keys = sync.profile.accountKeys {
            accountKeys = keys
            privateKey = keys.publicKeyEncryptionKeyPair.wrappedPrivateKey
        } else if let privateKey = sync.profile.privateKey {
            self.privateKey = privateKey
        }
        v2UpgradeToken = sync.userDecryption?.v2UpgradeToken
    }
}

/// Files under ~/Library/Application Support/Deskwarden, readable only by the
/// user, plus the refresh token in the login keychain.
struct AccountStore: Sendable {
    let directory: URL
    let keychainService: String
    private var refreshToken: KeychainItem { KeychainItem(service: keychainService, account: "refresh-token") }

    init(directory: URL = AccountStore.defaultDirectory, keychainService: String = KeychainItem.defaultService) {
        self.directory = directory
        self.keychainService = keychainService
    }

    /// The "remember this Mac" token from two-step login. Kept across logouts,
    /// like the official clients do.
    func rememberedTwoFactorToken(for email: String) -> KeychainItem {
        KeychainItem(service: keychainService, account: "two-factor-remember:\(BitwardenAPI.legacySalt(for: email))")
    }

    static var defaultDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Deskwarden", isDirectory: true)
    }

    private var accountFile: URL { directory.appendingPathComponent("account.json") }
    /// The last `/api/sync` response, still encrypted, for unlocking offline.
    private var vaultFile: URL { directory.appendingPathComponent("vault.json") }

    func loadAccount() throws -> StoredAccount? {
        guard FileManager.default.fileExists(atPath: accountFile.path) else { return nil }
        return try JSONDecoder().decode(StoredAccount.self, from: Data(contentsOf: accountFile))
    }

    func save(_ account: StoredAccount) throws {
        try write(JSONEncoder().encode(account), to: accountFile)
    }

    func loadVault() -> Data? {
        try? Data(contentsOf: vaultFile)
    }

    func saveVault(_ data: Data) throws {
        try write(data, to: vaultFile)
    }

    func loadRefreshToken() throws -> String? {
        try refreshToken.read().map { String(decoding: $0, as: UTF8.self) }
    }

    func saveRefreshToken(_ token: String) throws {
        try refreshToken.write(Data(token.utf8), label: "Deskwarden Bitwarden session")
    }

    /// Forgets the account entirely.
    func clear() throws {
        try? FileManager.default.removeItem(at: accountFile)
        try? FileManager.default.removeItem(at: vaultFile)
        try refreshToken.delete()
    }

    private func write(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
