import Foundation

public enum BitwardenError: Error, Equatable, Sendable, LocalizedError {
    case loginRejected(String)
    case twoFactorRequired([TwoFactorMethod], emailHint: String?)
    case newDeviceVerificationRequired
    /// The refresh token was rejected; the user has to log in again.
    case sessionExpired
    case server(status: Int, message: String)
    case network(String)
    case unexpectedResponse(String)

    public var errorDescription: String? {
        switch self {
        case .loginRejected(let message): message
        case .twoFactorRequired: "Two-step login is required."
        case .newDeviceVerificationRequired: "Enter the verification code Bitwarden emailed you."
        case .sessionExpired: "Your Bitwarden session expired. Log in again."
        case .server(let status, let message): "The server said \(message) (\(status))."
        case .network(let message): "Couldn't reach the server: \(message)"
        case .unexpectedResponse(let message): "Unexpected response from the server: \(message)"
        }
    }
}

struct PasswordGrant: Sendable {
    let email: String
    let masterPasswordHash: String
    var twoFactor: TwoFactorAnswer?
    var newDeviceCode: String?
}

public struct TwoFactorAnswer: Sendable {
    public let method: TwoFactorMethod
    public let code: String
    public let remember: Bool

    public init(method: TwoFactorMethod, code: String, remember: Bool) {
        self.method = method
        self.code = code
        self.remember = remember
    }
}

/// Talks to a Bitwarden (or Vaultwarden) server's identity and API endpoints.
/// Deskwarden presents itself as a macOS desktop client, the same way the
/// SDK's own requests do.
struct BitwardenAPI: Sendable {
    static let clientId = "desktop"
    static let deviceType = 7 // MacOsDesktop
    static let deviceName = "macos"
    static let userAgent = "Deskwarden/0.1.0 (macOS)"
    /// Servers gate some encryption formats on the client version, so this
    /// tracks a current desktop release rather than Deskwarden's own version.
    static let clientVersion = "2026.9.0"

    let server: BitwardenServer
    let deviceIdentifier: String
    var session: URLSession = .shared

    // MARK: - Identity

    func prelogin(email: String) async throws(BitwardenError) -> (kdf: KdfSettings, salt: String) {
        let body = try encodeJSON(["email": email])
        var response: PreloginResponse
        do {
            response = try await send(post(server.identityURL.appending(path: "accounts/prelogin/password"), json: body))
        } catch .server(status: 404, _) {
            response = try await send(post(server.identityURL.appending(path: "accounts/prelogin"), json: body))
        }
        guard let kdf = response.settings else {
            throw .unexpectedResponse("prelogin had no KDF settings")
        }
        return (kdf, response.salt ?? Self.legacySalt(for: email))
    }

    /// The salt servers used before sending one: the trimmed, lowercased email.
    static func legacySalt(for email: String) -> String {
        email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    func requestToken(_ grant: PasswordGrant) async throws(BitwardenError) -> TokenResponse {
        var fields = [
            "grant_type": "password",
            "username": grant.email,
            "password": grant.masterPasswordHash,
            "scope": "api offline_access",
            "client_id": Self.clientId,
            "deviceType": String(Self.deviceType),
            "deviceIdentifier": deviceIdentifier,
            "deviceName": Self.deviceName,
        ]
        if let twoFactor = grant.twoFactor {
            fields["twoFactorToken"] = twoFactor.code
            fields["twoFactorProvider"] = String(twoFactor.method.rawValue)
            fields["twoFactorRemember"] = twoFactor.remember ? "1" : "0"
        }
        if let code = grant.newDeviceCode {
            // The iOS app sends the emailed code both ways; servers accept either.
            fields["newdeviceotp"] = code
            fields["twoFactorToken"] = code
            fields["twoFactorProvider"] = String(TwoFactorMethod.email.rawValue)
            fields["twoFactorRemember"] = "0"
        }
        return try await sendTokenRequest(post(server.identityURL.appending(path: "connect/token"), form: fields))
    }

    func refresh(refreshToken: String) async throws(BitwardenError) -> TokenResponse {
        let request = post(server.identityURL.appending(path: "connect/token"), form: [
            "grant_type": "refresh_token",
            "client_id": Self.clientId,
            "refresh_token": refreshToken,
        ])
        do {
            return try await sendTokenRequest(request)
        } catch .loginRejected {
            throw .sessionExpired
        }
    }

    // MARK: - API

    /// The raw body, so it can be cached as is, and its parsed form.
    func sync(accessToken: String) async throws(BitwardenError) -> (data: Data, response: SyncResponse) {
        var components = URLComponents(url: server.apiURL.appending(path: "sync"), resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "excludeDomains", value: "true")]
        let data = try await sendRaw(get(components.url!, accessToken: accessToken))
        return (data, try decode(SyncResponse.self, from: data))
    }

    /// When the account's vault last changed, to skip syncs that would change nothing.
    func revisionDate(accessToken: String) async throws(BitwardenError) -> Date {
        let data = try await sendRaw(get(server.apiURL.appending(path: "accounts/revision-date"), accessToken: accessToken))
        guard let milliseconds = Double(String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw .unexpectedResponse("revision date wasn't a number")
        }
        return Date(timeIntervalSince1970: milliseconds / 1000)
    }

    func sendTwoFactorEmail(email: String, masterPasswordHash: String) async throws(BitwardenError) {
        let body = try encodeJSON([
            "email": email,
            "masterPasswordHash": masterPasswordHash,
            "deviceIdentifier": deviceIdentifier,
        ])
        _ = try await sendRaw(post(server.apiURL.appending(path: "two-factor/send-email-login"), json: body))
    }

    func resendNewDeviceCode(email: String, masterPasswordHash: String) async throws(BitwardenError) {
        let body = try encodeJSON(["email": email, "masterPasswordHash": masterPasswordHash])
        _ = try await sendRaw(post(server.apiURL.appending(path: "accounts/resend-new-device-otp"), json: body))
    }

    // MARK: - Requests

    private func baseRequest(_ url: URL, method: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(String(Self.deviceType), forHTTPHeaderField: "Device-Type")
        request.setValue("desktop", forHTTPHeaderField: "Bitwarden-Client-Name")
        request.setValue(Self.clientVersion, forHTTPHeaderField: "Bitwarden-Client-Version")
        request.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
        return request
    }

    private func get(_ url: URL, accessToken: String) -> URLRequest {
        var request = baseRequest(url, method: "GET")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        return request
    }

    private func post(_ url: URL, json: Data) -> URLRequest {
        var request = baseRequest(url, method: "POST")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = json
        return request
    }

    private func post(_ url: URL, form: [String: String]) -> URLRequest {
        var request = baseRequest(url, method: "POST")
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(form.sorted { $0.key < $1.key }
            .map { "\($0.key.formEncoded)=\($0.value.formEncoded)" }
            .joined(separator: "&").utf8)
        return request
    }

    private func encodeJSON(_ value: [String: String]) throws(BitwardenError) -> Data {
        do {
            return try JSONEncoder().encode(value)
        } catch {
            throw .unexpectedResponse("couldn't encode request")
        }
    }

    private func send<T: Decodable>(_ request: URLRequest) async throws(BitwardenError) -> T {
        try decode(T.self, from: try await sendRaw(request))
    }

    private func sendRaw(_ request: URLRequest) async throws(BitwardenError) -> Data {
        let (data, status) = try await perform(request)
        guard (200..<300).contains(status) else {
            let message = (try? BitwardenJSON.decoder().decode(APIErrorResponse.self, from: data))?.message
            throw .server(status: status, message: message ?? HTTPURLResponse.localizedString(forStatusCode: status))
        }
        return data
    }

    /// The token endpoint reports two-step login, new-device checks and bad
    /// passwords as 400s with an OAuth error body.
    private func sendTokenRequest(_ request: URLRequest) async throws(BitwardenError) -> TokenResponse {
        let (data, status) = try await perform(request)
        if (200..<300).contains(status) {
            return try decode(TokenResponse.self, from: data)
        }
        guard let error = try? BitwardenJSON.decoder().decode(TokenErrorResponse.self, from: data) else {
            throw .server(status: status, message: HTTPURLResponse.localizedString(forStatusCode: status))
        }
        throw Self.tokenError(error, status: status)
    }

    static func tokenError(_ error: TokenErrorResponse, status: Int) -> BitwardenError {
        if let providers = error.twoFactorProviders2 {
            let methods = providers.keys.compactMap { Int($0).flatMap(TwoFactorMethod.init(rawValue:)) }
                .sorted { $0.rawValue < $1.rawValue }
            let emailHint = providers[String(TwoFactorMethod.email.rawValue)]??.email
            return .twoFactorRequired(methods, emailHint: emailHint)
        }
        if error.error == "device_error" {
            return .newDeviceVerificationRequired
        }
        // Bitwarden says invalid_grant, Vaultwarden leaves `error` empty; both
        // put the reason (wrong password, disabled account, …) in the message.
        let message = error.errorModel?.message ?? error.error_description ?? ""
        if status == 400 {
            return .loginRejected(message.isEmpty ? "The email or password is wrong." : message)
        }
        return .server(status: status, message: message.isEmpty ? (error.error ?? "unknown error") : message)
    }

    private func perform(_ request: URLRequest) async throws(BitwardenError) -> (Data, Int) {
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw BitwardenError.unexpectedResponse("not an HTTP response")
            }
            return (data, http.statusCode)
        } catch let error as BitwardenError {
            throw error
        } catch {
            throw .network(error.localizedDescription)
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws(BitwardenError) -> T {
        do {
            return try BitwardenJSON.decoder().decode(T.self, from: data)
        } catch {
            throw .unexpectedResponse("couldn't read \(T.self): \(error)")
        }
    }
}

extension String {
    var formEncoded: String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return addingPercentEncoding(withAllowedCharacters: allowed) ?? self
    }
}
