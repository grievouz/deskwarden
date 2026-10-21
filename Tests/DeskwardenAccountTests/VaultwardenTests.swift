@preconcurrency import BitwardenSdk
import DeskwardenKit
import Foundation
import Testing
@testable import DeskwardenAccount

/// End to end against a real server: register, log in, sync items another
/// client added, read them, lock, unlock, relaunch and log out.
///
///     scripts/vaultwarden.sh start
///     DESKWARDEN_TEST_SERVER=http://127.0.0.1:8222 swift test --filter Vaultwarden
private let testServerURL = ProcessInfo.processInfo.environment["DESKWARDEN_TEST_SERVER"].flatMap(URL.init(string:))

@Suite(.enabled(if: testServerURL != nil, "Set DESKWARDEN_TEST_SERVER to a Vaultwarden URL"), .serialized)
@MainActor
struct VaultwardenTests {
    let server = BitwardenServer.selfHosted(testServerURL ?? URL(string: "http://127.0.0.1:8222")!)
    let password = "correct horse battery staple"
    let deviceIdentifier = UUID().uuidString.lowercased()

    @Test(arguments: [
        KdfSettings(kind: .pbkdf2, iterations: 600_000, memory: nil, parallelism: nil),
        KdfSettings(kind: .argon2id, iterations: 3, memory: 64, parallelism: 4),
    ])
    func logInSyncLockUnlockAndLogOut(kdf: KdfSettings) async throws {
        let email = "deskwarden-\(UUID().uuidString.prefix(8).lowercased())@example.test"
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("deskwarden-\(UUID().uuidString)")
        let store = AccountStore(directory: directory, keychainService: "io.github.grievouz.deskwarden.tests")
        defer {
            try? store.clear()
            try? FileManager.default.removeItem(at: directory)
        }
        let testClient = TestClient(server: server, deviceIdentifier: deviceIdentifier)
        try await testClient.register(email: email, password: password, kdf: kdf)

        let manager = AccountManager(store: store, deviceIdentifier: deviceIdentifier)
        #expect(try await manager.logIn(server: server, email: email, password: password) == .signedIn)
        #expect(manager.status == .unlocked(email: email, server: server))
        #expect(manager.syncError == nil)

        try await testClient.addItems(email: email, password: password)
        await manager.sync()
        #expect(manager.syncError == nil)

        let secrets = manager.secretProvider
        #expect(try await secrets.value(at: "Infra/Postgres", field: "password") == "pg-secret")
        #expect(try await secrets.value(at: "Postgres", field: "username") == "app")
        #expect(try await secrets.value(at: "Infra/Postgres", field: "port") == "5432")
        #expect(try await secrets.value(at: "Deploy notes", field: "notes") == "line one\nline two")
        await #expect(throws: SecretLookupError.notFound("Infra/Nope")) {
            try await secrets.value(at: "Infra/Nope", field: "password")
        }

        // The periodic check only syncs when the server's revision date moved.
        try await Task.sleep(for: .milliseconds(1100))
        try await testClient.addLogin(email: email, password: password, name: "Stripe", secret: "sk_test_new")
        await manager.syncIfChanged()
        #expect(manager.syncError == nil)
        #expect(try await secrets.value(at: "Stripe", field: "password") == "sk_test_new")

        manager.lock()
        #expect(secrets.isLocked)
        await #expect(throws: AccountError.unlock(.wrongPassword)) {
            try await manager.unlock(password: "not it")
        }
        try await manager.unlock(password: password)
        #expect(try await secrets.value(at: "Infra/Postgres", field: "password") == "pg-secret")
        manager.lock()

        // A relaunch starts locked and unlocks from the stored account.
        let relaunched = AccountManager(store: store, deviceIdentifier: deviceIdentifier)
        #expect(relaunched.status == .locked(email: email, server: server))
        try await relaunched.unlock(password: password)
        #expect(try await relaunched.secretProvider.value(at: "Infra/Postgres", field: "password") == "pg-secret")

        relaunched.logOut()
        #expect(relaunched.status == .signedOut)
        #expect(try store.loadAccount() == nil)
        #expect(try store.loadRefreshToken() == nil)
        #expect(relaunched.secretProvider.isLocked)
    }

    @Test func wrongPasswordIsRejectedAtLogIn() async throws {
        let email = "deskwarden-\(UUID().uuidString.prefix(8).lowercased())@example.test"
        let kdf = KdfSettings(kind: .pbkdf2, iterations: 600_000, memory: nil, parallelism: nil)
        try await TestClient(server: server, deviceIdentifier: deviceIdentifier).register(email: email, password: password, kdf: kdf)
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("deskwarden-\(UUID().uuidString)")
        let store = AccountStore(directory: directory, keychainService: "io.github.grievouz.deskwarden.tests")
        defer { try? FileManager.default.removeItem(at: directory) }

        let manager = AccountManager(store: store, deviceIdentifier: deviceIdentifier)
        await #expect {
            try await manager.logIn(server: server, email: email, password: "wrong password")
        } throws: { error in
            guard case AccountError.bitwarden(.loginRejected) = error else { return false }
            return true
        }
        #expect(manager.status == .signedOut)
    }
}

/// Plays the part of another Bitwarden client: registers the account and
/// adds encrypted items through the API.
private struct TestClient {
    let server: BitwardenServer
    let deviceIdentifier: String

    func register(email: String, password: String, kdf: KdfSettings) async throws {
        // Without mail, Vaultwarden returns the verification token instead of emailing it.
        let verification = try await postRaw(
            server.identityURL.appending(path: "accounts/register/send-verification-email"),
            body: ["email": email, "name": "Deskwarden test"],
            accessToken: nil
        )
        let client = VaultSession.makeClient(server: server, deviceIdentifier: deviceIdentifier)
        let keys = try client.auth().makeRegisterKeys(email: email, password: password, kdf: kdf.sdk)
        var body: [String: Any] = [
            "email": email,
            "emailVerificationToken": String(decoding: verification, as: UTF8.self),
            "name": "Deskwarden test",
            "kdf": kdf.kind.rawValue,
            "kdfIterations": kdf.iterations,
            "key": keys.encryptedUserKey,
            "masterPasswordHash": keys.masterPasswordHash,
            "keys": ["encryptedPrivateKey": keys.keys.private, "publicKey": keys.keys.public],
        ]
        if kdf.kind == .argon2id {
            body["kdfMemory"] = kdf.memory
            body["kdfParallelism"] = kdf.parallelism
        }
        _ = try await post(server.identityURL.appending(path: "accounts/register/finish"), body: body, accessToken: nil)
    }

    func addItems(email: String, password: String) async throws {
        let (client, token) = try await logIn(email: email, password: password)
        let folder = try client.vault().folders().encrypt(folder: FolderView(id: nil, name: "Infra", revisionDate: .now))
        let folderResponse = try await post(server.apiURL.appending(path: "folders"), body: ["name": folder.name], accessToken: token)
        let folderId = try #require(folderResponse["id"] as? String)

        try await addLogin(client: client, token: token, folderId: folderId, name: "Postgres",
                           username: "app", password: "pg-secret", fields: [("Port", "5432")])
        try await addNote(client: client, token: token, name: "Deploy notes", notes: "line one\nline two")
    }

    func addLogin(email: String, password: String, name: String, secret: String) async throws {
        let (client, token) = try await logIn(email: email, password: password)
        try await addLogin(client: client, token: token, folderId: nil, name: name, username: "", password: secret, fields: [])
    }

    /// A separate, unlocked SDK client and access token, like another device would have.
    private func logIn(email: String, password: String) async throws -> (Client, String) {
        let api = BitwardenAPI(server: server, deviceIdentifier: UUID().uuidString.lowercased())
        let (kdf, salt) = try await api.prelogin(email: email)
        let hash = try await VaultSession.serverPasswordHash(salt: salt, password: password, kdf: kdf)
        let token = try await api.requestToken(PasswordGrant(email: email, masterPasswordHash: hash))

        let client = VaultSession.makeClient(server: server, deviceIdentifier: deviceIdentifier)
        try await client.crypto().initializeUserCrypto(req: InitUserCryptoRequest(
            userId: JWT.claim("sub", in: token.access_token),
            kdfParams: kdf.sdk,
            email: email,
            accountCryptographicState: .v1(privateKey: try #require(token.privateKey)),
            method: .masterPasswordUnlock(
                password: password,
                masterPasswordUnlock: MasterPasswordUnlockData(kdf: kdf.sdk, masterKeyWrappedUserKey: try #require(token.key), salt: salt, containedKeyId: nil)
            ),
            upgradeToken: nil
        ))
        return (client, token.access_token)
    }

    private func addLogin(client: Client, token: String, folderId: String?, name: String, username: String, password: String, fields: [(String, String)]) async throws {
        let view = cipherView(
            type: .login,
            name: name,
            folderId: folderId,
            login: LoginView(username: username, password: password, passwordRevisionDate: nil, uris: nil, totp: nil, autofillOnPageLoad: nil, fido2Credentials: nil),
            fields: fields.map { FieldView(name: $0.0, value: $0.1, type: .text, linkedId: nil) }
        )
        let context = try await client.vault().ciphers().encrypt(cipherView: view)
        let cipher = context.cipher
        try await postCipher(cipher, encryptedFor: context.encryptedFor, token: token, extra: [
            "login": ["username": cipher.login?.username as Any, "password": cipher.login?.password as Any],
        ])
    }

    private func addNote(client: Client, token: String, name: String, notes: String) async throws {
        let view = cipherView(type: .secureNote, name: name, notes: notes, secureNote: SecureNoteView(type: .generic))
        let context = try await client.vault().ciphers().encrypt(cipherView: view)
        let cipher = context.cipher
        try await postCipher(cipher, encryptedFor: context.encryptedFor, token: token, extra: ["secureNote": ["type": 0]])
    }

    private func postCipher(_ cipher: BitwardenSdk.Cipher, encryptedFor: String, token: String, extra: [String: Any]) async throws {
        var body: [String: Any] = [
            "type": cipher.type.rawValue,
            "encryptedFor": encryptedFor,
            "folderId": cipher.folderId as Any,
            "name": try #require(cipher.name),
            "notes": cipher.notes as Any,
            "key": cipher.key as Any,
            "favorite": false,
            "reprompt": 0,
            "fields": (cipher.fields ?? []).map { ["type": $0.type.rawValue, "name": $0.name as Any, "value": $0.value as Any] },
        ]
        body.merge(extra) { _, new in new }
        _ = try await post(server.apiURL.appending(path: "ciphers"), body: body, accessToken: token)
    }

    private func cipherView(
        type: BitwardenSdk.CipherType,
        name: String,
        folderId: String? = nil,
        notes: String? = nil,
        login: LoginView? = nil,
        secureNote: SecureNoteView? = nil,
        fields: [FieldView]? = nil
    ) -> CipherView {
        CipherView(
            id: nil, organizationId: nil, folderId: folderId, collectionIds: [], key: nil, name: name, notes: notes,
            type: type, login: login, identity: nil, card: nil, secureNote: secureNote, sshKey: nil, bankAccount: nil,
            driversLicense: nil, passport: nil, favorite: false, reprompt: .none, organizationUseTotp: false, edit: true,
            permissions: nil, viewPassword: true, localData: nil, attachments: nil, attachmentDecryptionFailures: nil,
            fields: fields, passwordHistory: nil, creationDate: .now, deletedDate: nil, revisionDate: .now,
            archivedDate: nil, partial: false
        )
    }

    private func post(_ url: URL, body: [String: Any], accessToken: String?) async throws -> [String: Any] {
        let data = try await postRaw(url, body: body, accessToken: accessToken)
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }

    private func postRaw(_ url: URL, body: [String: Any], accessToken: String?) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            Issue.record("POST \(url.path()) failed with \(status): \(String(decoding: data, as: UTF8.self))\nbody: \(String(decoding: request.httpBody ?? Data(), as: UTF8.self))")
            throw URLError(.badServerResponse)
        }
        return data
    }
}
