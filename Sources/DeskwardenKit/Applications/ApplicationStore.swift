import Foundation

public protocol ApplicationStore: Sendable {
    func load() throws -> [ExternalApplication]
    func save(_ applications: [ExternalApplication]) throws
}

/// Keeps all external applications in a single login-keychain item.
///
/// The server needs the raw secrets to configure TLS, so they can't be stored
/// as hashes. One item holding a JSON array avoids the file-based keychain's
/// refusal to return data for multi-item queries.
public struct KeychainApplicationStore: ApplicationStore {
    // The item's original name, kept so existing applications keep their keys.
    let item = KeychainItem(account: "socket-keys")

    public init() {}

    public func load() throws -> [ExternalApplication] {
        guard let data = try item.read() else { return [] }
        return try JSONDecoder().decode([ExternalApplication].self, from: data)
    }

    public func save(_ applications: [ExternalApplication]) throws {
        try item.write(JSONEncoder().encode(applications), label: "Deskwarden external applications")
    }
}
