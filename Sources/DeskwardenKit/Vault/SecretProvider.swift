import Foundation

/// Where the secrets socket gets values from.
public protocol SecretProvider: Sendable {
    /// Checked before asking for approval, so a locked vault fails without a prompt.
    var isLocked: Bool { get async }
    func value(at path: String, field: String) async throws(SecretLookupError) -> String
}

/// Serves a fixed set of items. Used by tests and the socket harness, and by
/// the app until it can unlock a real Bitwarden vault.
public struct IndexSecretProvider: SecretProvider {
    let index: VaultIndex?

    /// `nil` behaves like a locked vault.
    public init(index: VaultIndex?) {
        self.index = index
    }

    public var isLocked: Bool {
        index == nil
    }

    public func value(at path: String, field: String) async throws(SecretLookupError) -> String {
        guard let index else { throw .locked }
        return try index.value(at: path, field: field)
    }
}
