import Foundation

/// Wire messages of the secrets socket. Each one is a JSON object sent as a
/// single frame; see `FrameDecoder`.
///
/// After the TLS handshake the server sends `challenge`, the client answers
/// with `auth`, and once the server replies `ready` the client may send any
/// number of `get` requests, matched to responses by `id`.
enum ClientMessage: Decodable {
    case auth(Auth)
    case get(Get)

    struct Auth: Decodable {
        let keyId: String
        /// HMAC-SHA256 over `authContext + nonce`, keyed with the application's secret.
        let proof: Data
        let client: ClientInfo?
    }

    struct Get: Decodable {
        let id: String
        let path: String
        let field: String?
    }

    private enum CodingKeys: String, CodingKey { case type }

    init(from decoder: Decoder) throws {
        let type = try decoder.container(keyedBy: CodingKeys.self).decode(String.self, forKey: .type)
        switch type {
        case "auth": self = .auth(try Auth(from: decoder))
        case "get": self = .get(try Get(from: decoder))
        default:
            throw DecodingError.dataCorrupted(.init(codingPath: [CodingKeys.type], debugDescription: "unknown type \(type)"))
        }
    }
}

/// What the client says about itself. Self-reported, so it only labels the
/// Touch ID prompt and is never used for access decisions.
public struct ClientInfo: Codable, Sendable, Hashable {
    public let name: String?
    public let pid: Int32?
    public let cwd: String?

    public init(name: String?, pid: Int32?, cwd: String?) {
        self.name = name
        self.pid = pid
        self.cwd = cwd
    }
}

enum ServerMessage: Encodable {
    case challenge(nonce: Data)
    case ready
    case value(id: String, value: String)
    case error(id: String?, code: ErrorCode, message: String)

    enum ErrorCode: String, Encodable {
        case badRequest = "bad_request"
        case unauthorized
        case locked
        case denied
        case notFound = "not_found"
        case ambiguous
        case fieldNotFound = "field_not_found"
    }

    private enum CodingKeys: String, CodingKey { case type, version, nonce, id, value, code, message }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .challenge(let nonce):
            try container.encode("challenge", forKey: .type)
            try container.encode(SecretsProtocol.version, forKey: .version)
            try container.encode(nonce, forKey: .nonce)
        case .ready:
            try container.encode("ready", forKey: .type)
        case .value(let id, let value):
            try container.encode("value", forKey: .type)
            try container.encode(id, forKey: .id)
            try container.encode(value, forKey: .value)
        case .error(let id, let code, let message):
            try container.encode("error", forKey: .type)
            try container.encodeIfPresent(id, forKey: .id)
            try container.encode(code, forKey: .code)
            try container.encode(message, forKey: .message)
        }
    }
}

enum SecretsProtocol {
    static let version = 1
    static let authContext = Data("deskwarden-auth-v1".utf8)
}
