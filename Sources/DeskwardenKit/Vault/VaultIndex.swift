import Foundation

/// A decrypted vault item, reduced to what the secrets socket can hand out.
public struct VaultItem: Sendable, Hashable {
    public let id: String
    public let name: String
    public let folder: String?
    public let username: String?
    public let password: String?
    public let notes: String?
    public let fields: [String: String]

    public init(
        id: String,
        name: String,
        folder: String? = nil,
        username: String? = nil,
        password: String? = nil,
        notes: String? = nil,
        fields: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.folder = folder
        self.username = username
        self.password = password
        self.notes = notes
        self.fields = fields
    }
}

public enum SecretLookupError: Error, Equatable, Sendable {
    case locked
    case notFound(String)
    case ambiguous(String, count: Int)
    case fieldNotFound(String)
}

/// Resolves `Folder/Item` paths and field names against a set of vault items.
///
/// A path is split at its last `/`: everything before it is the folder name
/// (Bitwarden spells nested folders as `Parent/Child`), the rest is the item
/// name. A path without `/` matches the item by name in any folder, and an
/// item id always matches exactly. Names compare case-sensitively; more than
/// one match is an error rather than a guess.
public struct VaultIndex: Sendable {
    let items: [VaultItem]

    public init(items: [VaultItem]) {
        self.items = items
    }

    public func item(at path: String) throws(SecretLookupError) -> VaultItem {
        if let byId = items.first(where: { $0.id.caseInsensitiveCompare(path) == .orderedSame }) {
            return byId
        }
        let matches: [VaultItem]
        if let slash = path.lastIndex(of: "/") {
            let folder = String(path[..<slash])
            let name = String(path[path.index(after: slash)...])
            matches = items.filter { $0.folder == folder && $0.name == name }
        } else {
            matches = items.filter { $0.name == path }
        }
        switch matches.count {
        case 0: throw .notFound(path)
        case 1: return matches[0]
        default: throw .ambiguous(path, count: matches.count)
        }
    }

    /// `password`, `username` and `notes` read the built-in fields; anything
    /// else is a custom field, matched case-insensitively.
    public func value(at path: String, field: String = "password") throws(SecretLookupError) -> String {
        let item = try item(at: path)
        let value: String? = switch field.lowercased() {
        case "password": item.password
        case "username": item.username
        case "notes": item.notes
        default: item.fields.first { $0.key.caseInsensitiveCompare(field) == .orderedSame }?.value
        }
        guard let value else { throw .fieldNotFound(field) }
        return value
    }
}
