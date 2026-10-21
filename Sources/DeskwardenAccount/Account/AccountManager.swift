import DeskwardenKit
import Foundation
import Observation
import OSLog
import Synchronization

public enum AccountStatus: Equatable, Sendable {
    case signedOut
    case locked(email: String, server: BitwardenServer)
    case unlocked(email: String, server: BitwardenServer)
}

/// Where a login stands after a step.
public enum LoginProgress: Equatable, Sendable {
    case signedIn
    case needsTwoFactor([TwoFactorMethod], emailHint: String?)
    case needsNewDeviceCode
}

public enum AccountError: Error, Equatable, Sendable, LocalizedError {
    case bitwarden(BitwardenError)
    case unlock(UnlockError)
    case storage(String)
    case noLoginInProgress

    public var errorDescription: String? {
        switch self {
        case .bitwarden(let error): error.errorDescription
        case .unlock(let error): error.errorDescription
        case .storage(let message): "Couldn't save the account: \(message)"
        case .noLoginInProgress: "Start the login again."
        }
    }
}

/// The Bitwarden account: logging in, unlocking, keeping the vault in sync,
/// locking and logging out. The secrets socket reads the unlocked vault
/// through `secretProvider`.
@MainActor
@Observable
public final class AccountManager {
    private static let logger = Logger(subsystem: "io.github.grievouz.deskwarden", category: "account")
    /// How often to ask the server whether the vault changed.
    static let syncCheckInterval = Duration.seconds(60)

    public private(set) var status = AccountStatus.signedOut
    public private(set) var lastSyncedAt: Date?
    public private(set) var syncError: String?
    public private(set) var isSyncing = false
    /// Whether the vault can be unlocked with Touch ID. It becomes true after
    /// the first unlock with the master password on this Mac.
    public private(set) var canUnlockWithTouchID = false

    public let secretProvider = VaultSecretProvider()
    /// Called after locking or logging out, e.g. to forget Touch ID approvals.
    public var onLock: (() -> Void)?

    private let store: AccountStore
    private let keyProtector: UserKeyProtector
    private let deviceIdentifier: String
    private var account: StoredAccount?
    private var pendingLogin: PendingLogin?
    private var accessToken: AccessToken?
    private var lastRevisionDate: Date?
    private var syncTask: Task<Void, Never>?
    private var pendingUnlock: Task<Bool, Never>?

    private struct PendingLogin {
        let api: BitwardenAPI
        let email: String
        let password: String
        let kdf: KdfSettings
        let salt: String
        let masterPasswordHash: String
    }

    private struct AccessToken {
        let value: String
        let expiresAt: Date
    }

    public convenience init(deviceIdentifier: String) {
        self.init(store: AccountStore(), keyProtector: SecureEnclaveKeyProtector(), deviceIdentifier: deviceIdentifier)
    }

    init(store: AccountStore, keyProtector: UserKeyProtector, deviceIdentifier: String) {
        self.store = store
        self.keyProtector = keyProtector
        self.deviceIdentifier = deviceIdentifier
        do {
            account = try store.loadAccount()
            lastSyncedAt = account?.lastSyncedAt
        } catch {
            Self.logger.error("Couldn't read the stored account: \(error, privacy: .public)")
        }
        if let account {
            status = .locked(email: account.email, server: account.server)
            canUnlockWithTouchID = store.loadSealedUserKey() != nil
        }
        secretProvider.setUnlockHandler { [weak self] reason in
            await self?.unlock(reason: reason) ?? false
        }
    }

    // MARK: - Logging in

    public func logIn(server: BitwardenServer, email: String, password: String) async throws(AccountError) -> LoginProgress {
        let email = email.trimmingCharacters(in: .whitespacesAndNewlines)
        let api = BitwardenAPI(server: server, deviceIdentifier: deviceIdentifier)
        do {
            let (kdf, salt) = try await api.prelogin(email: email)
            let hash = try await VaultSession.serverPasswordHash(salt: salt, password: password, kdf: kdf)
            pendingLogin = PendingLogin(api: api, email: email, password: password, kdf: kdf, salt: salt, masterPasswordHash: hash)
        } catch let error as BitwardenError {
            throw .bitwarden(error)
        } catch let error as UnlockError {
            throw .unlock(error)
        } catch {
            throw .storage("\(error)")
        }
        var grant = PasswordGrant(email: email, masterPasswordHash: pendingLogin!.masterPasswordHash)
        if let remembered = try? store.rememberedTwoFactorToken(for: email).read() {
            grant.twoFactor = TwoFactorAnswer(method: .remember, code: String(decoding: remembered, as: UTF8.self), remember: false)
        }
        return try await attemptLogin(grant)
    }

    public func continueLogin(twoFactor answer: TwoFactorAnswer) async throws(AccountError) -> LoginProgress {
        guard let pendingLogin else { throw .noLoginInProgress }
        var grant = PasswordGrant(email: pendingLogin.email, masterPasswordHash: pendingLogin.masterPasswordHash)
        grant.twoFactor = answer
        return try await attemptLogin(grant)
    }

    public func continueLogin(newDeviceCode code: String) async throws(AccountError) -> LoginProgress {
        guard let pendingLogin else { throw .noLoginInProgress }
        var grant = PasswordGrant(email: pendingLogin.email, masterPasswordHash: pendingLogin.masterPasswordHash)
        grant.newDeviceCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        return try await attemptLogin(grant)
    }

    public func sendTwoFactorEmail() async throws(AccountError) {
        guard let pendingLogin else { throw .noLoginInProgress }
        do {
            try await pendingLogin.api.sendTwoFactorEmail(email: pendingLogin.email, masterPasswordHash: pendingLogin.masterPasswordHash)
        } catch {
            throw .bitwarden(error)
        }
    }

    public func resendNewDeviceCode() async throws(AccountError) {
        guard let pendingLogin else { throw .noLoginInProgress }
        do {
            try await pendingLogin.api.resendNewDeviceCode(email: pendingLogin.email, masterPasswordHash: pendingLogin.masterPasswordHash)
        } catch {
            throw .bitwarden(error)
        }
    }

    public func cancelLogin() {
        pendingLogin = nil
    }

    private func attemptLogin(_ grant: PasswordGrant) async throws(AccountError) -> LoginProgress {
        guard let pending = pendingLogin else { throw .noLoginInProgress }
        let token: TokenResponse
        do {
            token = try await pending.api.requestToken(grant)
        } catch .twoFactorRequired(let methods, let emailHint) {
            // A remembered device that's no longer accepted shouldn't be tried again.
            if grant.twoFactor?.method == .remember {
                try? store.rememberedTwoFactorToken(for: pending.email).delete()
            }
            return .needsTwoFactor(methods.filter { $0 != .remember }, emailHint: emailHint)
        } catch .newDeviceVerificationRequired {
            return .needsNewDeviceCode
        } catch {
            throw .bitwarden(error)
        }
        try await completeLogin(token, pending: pending)
        return .signedIn
    }

    private func completeLogin(_ token: TokenResponse, pending: PendingLogin) async throws(AccountError) {
        guard let userId = JWT.claim("sub", in: token.access_token),
              let refreshToken = token.refresh_token
        else {
            throw .bitwarden(.unexpectedResponse("the login response had no user or refresh token"))
        }
        let unlock = token.userDecryptionOptions?.masterPasswordUnlock
        guard let userKey = unlock?.masterKeyEncryptedUserKey ?? token.key,
              let privateKey = token.accountKeys?.publicKeyEncryptionKeyPair.wrappedPrivateKey ?? token.privateKey
        else {
            throw .bitwarden(.unexpectedResponse("the login response had no account keys"))
        }
        let account = StoredAccount(
            server: pending.api.server,
            userId: userId,
            email: pending.email,
            kdf: unlock?.kdfSettings ?? pending.kdf,
            salt: unlock?.salt ?? pending.salt,
            masterKeyWrappedUserKey: userKey,
            privateKey: privateKey,
            accountKeys: token.accountKeys,
            v2UpgradeToken: nil,
            lastSyncedAt: nil
        )

        let session: VaultSession
        do {
            session = try await VaultSession.unlock(account, password: pending.password, deviceIdentifier: deviceIdentifier)
        } catch {
            throw .unlock(error)
        }
        do {
            try store.save(account)
            try store.saveRefreshToken(refreshToken)
            if let remember = token.twoFactorToken {
                try store.rememberedTwoFactorToken(for: pending.email).write(Data(remember.utf8), label: "Deskwarden remembered two-step login")
            }
        } catch {
            throw .storage("\(error)")
        }

        pendingLogin = nil
        self.account = account
        accessToken = AccessToken(value: token.access_token, expiresAt: .now.addingTimeInterval(TimeInterval(token.expires_in)))
        lastRevisionDate = nil
        await sealUserKey(from: session)
        await activate(session)
        await sync()
    }

    // MARK: - Unlocking and locking

    public func unlock(password: String) async throws(AccountError) {
        guard let account else { throw .noLoginInProgress }
        let session: VaultSession
        do {
            session = try await VaultSession.unlock(account, password: password, deviceIdentifier: deviceIdentifier)
        } catch {
            throw .unlock(error)
        }
        await sealUserKey(from: session)
        await open(session)
    }

    /// Asks for Touch ID and unlocks with the user key it opens.
    public func unlockWithTouchID(reason: String = "unlock your vault") async throws(AccountError) {
        guard let account, let sealed = store.loadSealedUserKey() else { throw .unlock(.needsMasterPassword) }
        let userKey: String
        do {
            userKey = try await keyProtector.open(sealed, reason: reason)
        } catch .cancelled {
            throw .unlock(.cancelled)
        } catch .invalidated {
            Self.logger.notice("The Touch ID key no longer works; the master password will set up a new one")
            forgetSealedUserKey()
            throw .unlock(.needsMasterPassword)
        } catch {
            Self.logger.notice("Touch ID unlock didn't work: \(String(describing: error), privacy: .public)")
            throw .unlock(.needsMasterPassword)
        }
        let session: VaultSession
        do {
            session = try await VaultSession.unlock(account, userKey: userKey, deviceIdentifier: deviceIdentifier)
        } catch {
            forgetSealedUserKey()
            throw .unlock(error)
        }
        await open(session)
    }

    /// Unlocks with Touch ID for a request that arrived while locked, such as
    /// a secret or an SSH signature. Requests arriving together share one prompt.
    func unlock(reason: String) async -> Bool {
        if case .unlocked = status { return true }
        guard case .locked = status, canUnlockWithTouchID else { return false }
        if let pendingUnlock {
            return await pendingUnlock.value
        }
        let task = Task { () -> Bool in
            do {
                try await unlockWithTouchID(reason: reason)
                return true
            } catch {
                return false
            }
        }
        pendingUnlock = task
        defer { pendingUnlock = nil }
        return await task.value
    }

    private func open(_ session: VaultSession) async {
        // The cached vault makes the items available right away, even
        // offline, so the sync can finish in the background.
        if let data = store.loadVault(), let cached = try? BitwardenJSON.decoder().decode(SyncResponse.self, from: data),
           (try? await session.load(cached)) != nil {
            await activate(session)
            Task { await sync() }
        } else {
            await activate(session)
            await sync()
        }
    }

    /// Keeps the user key, sealed for Touch ID, so later unlocks don't need the
    /// master password. Replaces any earlier one, e.g. after fingerprints changed.
    private func sealUserKey(from session: VaultSession) async {
        guard keyProtector.isAvailable else { return }
        do {
            let sealed = try keyProtector.seal(await session.userKey())
            try store.saveSealedUserKey(sealed)
            canUnlockWithTouchID = true
        } catch {
            Self.logger.error("Couldn't set up Touch ID unlock: \(String(describing: error), privacy: .public)")
        }
    }

    private func forgetSealedUserKey() {
        store.removeSealedUserKey()
        canUnlockWithTouchID = false
    }

    public func lock() {
        guard let account else { return }
        deactivate()
        status = .locked(email: account.email, server: account.server)
        onLock?()
    }

    public func logOut() {
        deactivate()
        do {
            try store.clear()
        } catch {
            Self.logger.error("Couldn't clear the stored account: \(error, privacy: .public)")
        }
        account = nil
        accessToken = nil
        lastSyncedAt = nil
        syncError = nil
        canUnlockWithTouchID = false
        status = .signedOut
        onLock?()
    }

    private func activate(_ session: VaultSession) async {
        guard let account else { return }
        secretProvider.session = session
        status = .unlocked(email: account.email, server: account.server)
        syncTask?.cancel()
        syncTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: Self.syncCheckInterval)
                guard !Task.isCancelled else { return }
                await self?.syncIfChanged()
            }
        }
    }

    private func deactivate() {
        syncTask?.cancel()
        syncTask = nil
        secretProvider.session = nil
    }

    // MARK: - Syncing

    /// Syncs if the server says the vault changed since the last sync.
    public func syncIfChanged() async {
        guard case .unlocked = status, let account, !isSyncing else { return }
        let api = BitwardenAPI(server: account.server, deviceIdentifier: deviceIdentifier)
        do {
            let revision = try await withAccessToken { token throws(BitwardenError) in try await api.revisionDate(accessToken: token) }
            if let lastRevisionDate, revision <= lastRevisionDate { return }
        } catch {
            handleSyncError(error)
            return
        }
        await sync()
    }

    /// Downloads the whole vault and replaces the unlocked items with it.
    public func sync() async {
        guard case .unlocked = status, var account, let session = secretProvider.session, !isSyncing else { return }
        isSyncing = true
        defer { isSyncing = false }
        let api = BitwardenAPI(server: account.server, deviceIdentifier: deviceIdentifier)
        do {
            let revision = try? await withAccessToken { token throws(BitwardenError) in try await api.revisionDate(accessToken: token) }
            let (data, response) = try await withAccessToken { token throws(BitwardenError) in try await api.sync(accessToken: token) }
            try await session.load(response)
            try? store.saveVault(data)
            account.updateKeys(from: response)
            account.lastSyncedAt = .now
            try? store.save(account)
            self.account = account
            lastSyncedAt = account.lastSyncedAt
            lastRevisionDate = revision
            syncError = nil
        } catch {
            handleSyncError(error)
        }
    }

    private func handleSyncError(_ error: Error) {
        if case BitwardenError.sessionExpired = error {
            Self.logger.notice("Refresh token rejected; logging out")
            logOut()
            syncError = BitwardenError.sessionExpired.errorDescription
            return
        }
        Self.logger.error("Sync failed: \(String(describing: error), privacy: .public)")
        syncError = (error as? LocalizedError)?.errorDescription ?? "\(error)"
    }

    /// Runs a request with a current access token, refreshing it once if the
    /// server rejects it anyway.
    private func withAccessToken<T>(_ request: (String) async throws(BitwardenError) -> T) async throws(BitwardenError) -> T {
        do {
            return try await request(validAccessToken())
        } catch .server(status: 401, _) {
            accessToken = nil
            return try await request(validAccessToken())
        }
    }

    private func validAccessToken() async throws(BitwardenError) -> String {
        // Refresh a little early, as the official clients do.
        if let accessToken, accessToken.expiresAt.timeIntervalSinceNow > 5 * 60 {
            return accessToken.value
        }
        guard let account, let refreshToken = try? store.loadRefreshToken() else {
            throw .sessionExpired
        }
        let response = try await BitwardenAPI(server: account.server, deviceIdentifier: deviceIdentifier).refresh(refreshToken: refreshToken)
        if let rotated = response.refresh_token, rotated != refreshToken {
            try? store.saveRefreshToken(rotated)
        }
        accessToken = AccessToken(value: response.access_token, expiresAt: .now.addingTimeInterval(TimeInterval(response.expires_in)))
        return response.access_token
    }
}

/// Lets the secrets socket and the SSH agent use whichever vault is unlocked
/// right now, and unlock it with Touch ID when a request arrives while it's locked.
public final class VaultSecretProvider: SecretProvider, SSHKeyProvider {
    private let current = Mutex<VaultSession?>(nil)
    private let unlockHandler = Mutex<(@Sendable (String) async -> Bool)?>(nil)

    var session: VaultSession? {
        get { current.withLock { $0 } }
        set { current.withLock { $0 = newValue } }
    }

    func setUnlockHandler(_ handler: @escaping @Sendable (String) async -> Bool) {
        unlockHandler.withLock { $0 = handler }
    }

    public var isLocked: Bool {
        session == nil
    }

    public func unlock(for request: ApprovalRequest) async -> Bool {
        await unlock(reason: "unlock your vault so \(request.requester) can \(request.action)")
    }

    public func unlock(reason: String) async -> Bool {
        guard let handler = unlockHandler.withLock({ $0 }) else { return false }
        return await handler(reason)
    }

    public func sshKeys() async -> [SSHKeyEntry] {
        await session?.sshKeys ?? []
    }

    public func sshPrivateKey(id: String) async -> String? {
        await session?.sshPrivateKey(id: id)
    }

    public func value(at path: String, field: String) async throws(SecretLookupError) -> String {
        guard let session else { throw .locked }
        return try await session.value(at: path, field: field)
    }
}

enum JWT {
    /// Reads a string claim from a JWT's payload without verifying it; the
    /// token came straight from the server over TLS.
    static func claim(_ name: String, in token: String) -> String? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var payload = parts[1].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
        guard let data = Data(base64Encoded: payload),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return object[name] as? String
    }
}
