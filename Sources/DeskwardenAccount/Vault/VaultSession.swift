@preconcurrency import BitwardenSdk
import DeskwardenKit
import Foundation
import OSLog

public enum UnlockError: Error, Equatable, Sendable, LocalizedError {
    case wrongPassword
    /// The Touch ID prompt was dismissed.
    case cancelled
    /// Touch ID can't unlock right now; the master password still can, and turns Touch ID back on.
    case needsMasterPassword
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .wrongPassword: "The master password is wrong."
        case .cancelled: nil
        case .needsMasterPassword: "Unlock with your master password to turn Touch ID back on."
        case .failed(let message): "Couldn't unlock the vault: \(message)"
        }
    }
}

/// An unlocked vault: an SDK client holding the user's keys, the encrypted
/// items from the last sync, and an index of their names.
///
/// Only names and folders are decrypted up front. A value is decrypted when
/// a client asks for it, so secrets don't sit in memory as plain text.
actor VaultSession {
    private static let logger = Logger(subsystem: "io.github.grievouz.deskwarden", category: "vault")

    private let client: Client
    private var index = VaultIndex(entries: [])
    private var entries: [VaultEntry] = []
    /// Folder names by id.
    private(set) var folderNames: [String: String] = [:]
    private var ciphers: [String: BitwardenSdk.Cipher] = [:]
    /// SSH key items with their public keys, which aren't secret, decrypted.
    private(set) var sshKeys: [SSHKeyEntry] = []

    private init(client: Client) {
        self.client = client
    }

    static func makeClient(server: BitwardenServer, deviceIdentifier: String) -> Client {
        Client(
            tokenProvider: NoTokens(),
            settings: ClientSettings(
                identityUrl: server.identityURL.absoluteString,
                apiUrl: server.apiURL.absoluteString,
                userAgent: BitwardenAPI.userAgent,
                deviceType: .macOsDesktop,
                deviceIdentifier: deviceIdentifier,
                bitwardenClientVersion: BitwardenAPI.clientVersion,
                bitwardenPackageType: nil
            ),
            managedSettings: ManagedSettingsBindingClient()
        )
    }

    /// The hash the server checks at login. The master password itself never leaves the Mac.
    static func serverPasswordHash(salt: String, password: String, kdf: KdfSettings) async throws(UnlockError) -> String {
        let client = makeClient(server: .unitedStates, deviceIdentifier: "")
        do {
            return try await client.auth().hashPassword(email: salt, password: password, kdfParams: kdf.sdk, purpose: .serverAuthorization)
        } catch {
            throw .failed("\(error)")
        }
    }

    static func unlock(_ account: StoredAccount, password: String, deviceIdentifier: String) async throws(UnlockError) -> VaultSession {
        let method = InitUserCryptoMethod.masterPasswordUnlock(
            password: password,
            masterPasswordUnlock: MasterPasswordUnlockData(
                kdf: account.kdf.sdk,
                masterKeyWrappedUserKey: account.masterKeyWrappedUserKey,
                salt: account.salt,
                containedKeyId: nil
            )
        )
        do {
            return try await unlock(account, method: method, deviceIdentifier: deviceIdentifier)
        } catch BitwardenSdk.BitwardenError.EncryptionSettings(.Crypto) {
            // A wrong master password derives a key that can't decrypt the user key.
            throw .wrongPassword
        } catch {
            logger.error("Unlock failed: \(String(describing: error), privacy: .public)")
            throw .failed("\(error)")
        }
    }

    /// Unlocks with the user key itself, as opened by Touch ID.
    static func unlock(_ account: StoredAccount, userKey: String, deviceIdentifier: String) async throws(UnlockError) -> VaultSession {
        do {
            return try await unlock(account, method: .decryptedKey(decryptedUserKey: userKey), deviceIdentifier: deviceIdentifier)
        } catch {
            // E.g. the user key was rotated on another device since it was sealed.
            logger.error("Unlock with the stored user key failed: \(String(describing: error), privacy: .public)")
            throw .needsMasterPassword
        }
    }

    private static func unlock(_ account: StoredAccount, method: InitUserCryptoMethod, deviceIdentifier: String) async throws -> VaultSession {
        let client = makeClient(server: account.server, deviceIdentifier: deviceIdentifier)
        try await client.crypto().initializeUserCrypto(req: InitUserCryptoRequest(
            userId: account.userId,
            kdfParams: account.kdf.sdk,
            email: account.email,
            accountCryptographicState: account.cryptographicState,
            method: method,
            upgradeToken: account.v2UpgradeToken.map {
                V2UpgradeToken(wrappedUserKey1: $0.wrappedUserKey1, wrappedUserKey2: $0.wrappedUserKey2)
            }
        ))
        return VaultSession(client: client)
    }

    /// The decrypted user key, to seal for Touch ID unlock.
    func userKey() async throws -> String {
        try await client.crypto().getUserEncryptionKey()
    }

    /// Replaces the items with those from a sync response.
    func load(_ sync: SyncResponse) async throws {
        let organizations = sync.profile.organizationsNew ?? sync.profile.organizations ?? []
        let organizationKeys = Dictionary(
            organizations.compactMap { org in org.key.map { (org.id, $0) } },
            uniquingKeysWith: { first, _ in first }
        )
        if !organizationKeys.isEmpty {
            try await client.crypto().initializeOrgCrypto(req: InitOrgCryptoRequest(organizationKeys: organizationKeys))
        }

        let folders = try client.vault().folders().decryptList(folders: sync.folders.map(BitwardenSdk.Folder.init))
        let folderNames = Dictionary(folders.compactMap { folder in folder.id.map { ($0, folder.name) } }, uniquingKeysWith: { first, _ in first })

        let encrypted = sync.ciphers.compactMap(BitwardenSdk.Cipher.init)
        let result = try await client.vault().ciphers().decryptListWithFailures(ciphers: encrypted)
        if !result.failures.isEmpty {
            Self.logger.error("\(result.failures.count) vault items couldn't be decrypted")
        }

        entries = result.successes.compactMap { item in
            guard let id = item.id, item.deletedDate == nil else { return nil }
            return VaultEntry(id: id, name: item.name, folder: item.folderId.flatMap { folderNames[$0] }, folderId: item.folderId)
        }
        index = VaultIndex(entries: entries)
        self.folderNames = folderNames
        ciphers = Dictionary(encrypted.compactMap { cipher in cipher.id.map { ($0, cipher) } }, uniquingKeysWith: { first, _ in first })

        var sshKeys: [SSHKeyEntry] = []
        for cipher in encrypted where cipher.type == .sshKey && cipher.deletedDate == nil {
            guard let id = cipher.id,
                  let view = try? await client.vault().ciphers().decrypt(cipher: cipher),
                  let publicKey = view.sshKey?.publicKey,
                  let blob = Self.publicKeyBlob(publicKey)
            else { continue }
            sshKeys.append(SSHKeyEntry(id: id, name: view.name, publicKeyBlob: blob))
        }
        self.sshKeys = sshKeys
    }

    /// The private key of an SSH key item, in OpenSSH format.
    func sshPrivateKey(id: String) async -> String? {
        guard let cipher = ciphers[id] else { return nil }
        return try? await client.vault().ciphers().decrypt(cipher: cipher).sshKey?.privateKey
    }

    /// The wire-format key from a public key line such as `ssh-ed25519 AAAA… comment`.
    static func publicKeyBlob(_ line: String) -> Data? {
        let fields = line.split(separator: " ")
        guard fields.count >= 2 else { return nil }
        return Data(base64Encoded: String(fields[1]))
    }

    var itemCount: Int {
        ciphers.count
    }

    func entry(at path: String) throws(SecretLookupError) -> VaultEntry {
        try index.entry(at: path)
    }

    /// What there is to choose from when selecting what an application may use.
    var catalog: VaultCatalog {
        let sshKeyIds = Set(sshKeys.map(\.id))
        return VaultCatalog(
            folders: folderNames.map { VaultCatalog.Folder(id: $0.key, name: $0.value) }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending },
            items: entries.filter { !sshKeyIds.contains($0.id) }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending },
            sshKeys: sshKeys.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        )
    }

    func value(at path: String, field: String) async throws(SecretLookupError) -> String {
        let entry = try index.entry(at: path)
        guard let cipher = ciphers[entry.id] else { throw .notFound(path) }
        let view: CipherView
        do {
            view = try await client.vault().ciphers().decrypt(cipher: cipher)
        } catch {
            Self.logger.error("Couldn't decrypt \(entry.id, privacy: .public): \(String(describing: error), privacy: .public)")
            throw .notFound(path)
        }
        return try VaultItem(view, folder: entry.folder).value(of: field)
    }
}

extension VaultItem {
    init(_ view: CipherView, folder: String?) {
        let fields = (view.fields ?? []).reduce(into: [String: String]()) { fields, field in
            if let name = field.name, let value = field.value, fields[name] == nil {
                fields[name] = value
            }
        }
        self.init(
            id: view.id ?? "",
            name: view.name,
            folder: folder,
            username: view.login?.username,
            password: view.login?.password,
            notes: view.notes,
            fields: fields
        )
    }
}

extension KdfSettings {
    var sdk: Kdf {
        switch kind {
        case .pbkdf2:
            .pbkdf2(iterations: iterations)
        case .argon2id:
            .argon2id(iterations: iterations, memory: memory ?? 64, parallelism: parallelism ?? 4)
        }
    }
}

extension StoredAccount {
    var cryptographicState: WrappedAccountCryptographicState {
        if let keys = accountKeys,
           let signingKey = keys.signatureKeyPair?.wrappedSigningKey,
           let signedPublicKey = keys.publicKeyEncryptionKeyPair.signedPublicKey,
           let securityState = keys.securityState?.securityState {
            return .v2(
                privateKey: keys.publicKeyEncryptionKeyPair.wrappedPrivateKey,
                signedPublicKey: signedPublicKey,
                signingKey: signingKey,
                securityState: securityState
            )
        }
        return .v1(privateKey: privateKey)
    }
}

/// Deskwarden makes its own API requests, so the SDK client never needs a token.
private final class NoTokens: ClientManagedTokens {
    func getAccessToken() async -> String? {
        nil
    }
}
