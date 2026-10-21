import Foundation

/// Which Bitwarden server an account lives on.
public enum BitwardenServer: Codable, Hashable, Sendable {
    case unitedStates
    case europe
    /// The base URL of a self-hosted Bitwarden or Vaultwarden server.
    case selfHosted(URL)

    public var identityURL: URL {
        switch self {
        case .unitedStates: URL(string: "https://identity.bitwarden.com")!
        case .europe: URL(string: "https://identity.bitwarden.eu")!
        case .selfHosted(let base): base.appendingPathComponent("identity")
        }
    }

    public var apiURL: URL {
        switch self {
        case .unitedStates: URL(string: "https://api.bitwarden.com")!
        case .europe: URL(string: "https://api.bitwarden.eu")!
        case .selfHosted(let base): base.appendingPathComponent("api")
        }
    }

    public var displayName: String {
        switch self {
        case .unitedStates: "bitwarden.com"
        case .europe: "bitwarden.eu"
        case .selfHosted(let base): base.host() ?? base.absoluteString
        }
    }
}
