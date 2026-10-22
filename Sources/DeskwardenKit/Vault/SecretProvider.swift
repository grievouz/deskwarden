import Foundation
import Synchronization

/// Where the secrets socket gets values from.
public protocol SecretProvider: Sendable {
    /// Checked before asking for approval, so a locked vault fails without a prompt.
    var isLocked: Bool { get async }
    /// Tries to unlock for a request that arrived while locked, e.g. with
    /// Touch ID. Returns whether the vault is unlocked now.
    func unlock(for request: ApprovalRequest) async -> Bool
    /// Finds the item at a path without decrypting anything, so access can
    /// be decided per item before its value is read.
    func entry(at path: String) async throws(SecretLookupError) -> VaultEntry
    /// Folder ids and names, for selections that include nested folders.
    func folderNames() async -> [String: String]
    func value(at path: String, field: String) async throws(SecretLookupError) -> String
}

extension SecretProvider {
    public func unlock(for request: ApprovalRequest) async -> Bool {
        false
    }
}

/// Serves a fixed set of items. Used by tests and the socket harness.
public final class StaticSecretProvider: SecretProvider {
    let items: [String: VaultItem]
    let index: VaultIndex
    private let unlockable: Bool
    private let locked: Mutex<Bool>

    /// `locked` behaves like a locked vault; `unlockable` lets a request unlock it.
    public init(items: [VaultItem], locked: Bool = false, unlockable: Bool = false) {
        self.items = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
        self.index = VaultIndex(entries: items.map(\.entry))
        self.locked = Mutex(locked)
        self.unlockable = unlockable
    }

    public var isLocked: Bool {
        locked.withLock { $0 }
    }

    public func unlock(for request: ApprovalRequest) async -> Bool {
        guard unlockable else { return !isLocked }
        locked.withLock { $0 = false }
        return true
    }

    public func entry(at path: String) async throws(SecretLookupError) -> VaultEntry {
        guard !isLocked else { throw .locked }
        return try index.entry(at: path)
    }

    public func folderNames() async -> [String: String] {
        Dictionary(items.values.compactMap { item in item.entry.folderId.map { ($0, item.folder ?? $0) } }, uniquingKeysWith: { first, _ in first })
    }

    public func value(at path: String, field: String) async throws(SecretLookupError) -> String {
        guard !isLocked else { throw .locked }
        let entry = try index.entry(at: path)
        guard let item = items[entry.id] else { throw .notFound(path) }
        return try item.value(of: field)
    }
}
