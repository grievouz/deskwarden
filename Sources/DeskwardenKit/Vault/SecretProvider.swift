import Foundation

/// Where the secrets socket gets values from.
public protocol SecretProvider: Sendable {
    /// Checked before asking for approval, so a locked vault fails without a prompt.
    var isLocked: Bool { get async }
    func value(at path: String, field: String) async throws(SecretLookupError) -> String
}

/// Serves a fixed set of items. Used by tests and the socket harness.
public struct StaticSecretProvider: SecretProvider {
    let items: [String: VaultItem]?
    let index: VaultIndex?

    /// `nil` behaves like a locked vault.
    public init(items: [VaultItem]?) {
        self.items = items.map { Dictionary(uniqueKeysWithValues: $0.map { ($0.id, $0) }) }
        self.index = items.map { VaultIndex(entries: $0.map(\.entry)) }
    }

    public var isLocked: Bool {
        index == nil
    }

    public func value(at path: String, field: String) async throws(SecretLookupError) -> String {
        guard let index, let items else { throw .locked }
        let entry = try index.entry(at: path)
        guard let item = items[entry.id] else { throw .notFound(path) }
        return try item.value(of: field)
    }
}
