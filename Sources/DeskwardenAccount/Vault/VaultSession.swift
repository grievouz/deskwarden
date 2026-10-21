@preconcurrency import BitwardenSdk
import DeskwardenKit
import Foundation
import OSLog

public enum UnlockError: Error, Equatable, Sendable, LocalizedError {
    case wrongPassword
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .wrongPassword: "The master password is wrong."
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
    private var ciphers: [String: BitwardenSdk.Cipher] = [:]

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
        let client = makeClient(server: account.server, deviceIdentifier: deviceIdentifier)
        let request = InitUserCryptoRequest(
            userId: account.userId,
            kdfParams: account.kdf.sdk,
            email: account.email,
            accountCryptographicState: account.cryptographicState,
            method: .masterPasswordUnlock(
                password: password,
                masterPasswordUnlock: MasterPasswordUnlockData(
                    kdf: account.kdf.sdk,
                    masterKeyWrappedUserKey: account.masterKeyWrappedUserKey,
                    salt: account.salt,
                    containedKeyId: nil
                )
            ),
            upgradeToken: account.v2UpgradeToken.map {
                V2UpgradeToken(wrappedUserKey1: $0.wrappedUserKey1, wrappedUserKey2: $0.wrappedUserKey2)
            }
        )
        do {
            try await client.crypto().initializeUserCrypto(req: request)
        } catch BitwardenSdk.BitwardenError.EncryptionSettings(.Crypto) {
            // A wrong master password derives a key that can't decrypt the user key.
            throw .wrongPassword
        } catch {
            logger.error("Unlock failed: \(String(describing: error), privacy: .public)")
            throw .failed("\(error)")
        }
        return VaultSession(client: client)
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

        index = VaultIndex(entries: result.successes.compactMap { item in
            guard let id = item.id, item.deletedDate == nil else { return nil }
            return VaultEntry(id: id, name: item.name, folder: item.folderId.flatMap { folderNames[$0] })
        })
        ciphers = Dictionary(encrypted.compactMap { cipher in cipher.id.map { ($0, cipher) } }, uniquingKeysWith: { first, _ in first })
    }

    var itemCount: Int {
        ciphers.count
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
