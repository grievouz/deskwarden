import Foundation

/// What the index needs to resolve a path: an item's id, name and folder name.
/// No secrets, so an unlocked vault can keep the index in memory and decrypt
/// values only when they're asked for.
public struct VaultEntry: Sendable, Hashable {
    public let id: String
    public let name: String
    public let folder: String?
    public let folderId: String?

    public init(id: String, name: String, folder: String?, folderId: String? = nil) {
        self.id = id
        self.name = name
        self.folder = folder
        self.folderId = folderId
    }
}

/// A decrypted vault item, reduced to what the secrets socket can hand out.
public struct VaultItem: Sendable, Hashable {
    public let id: String
    public let name: String
    public let folder: String?
    public let folderId: String?
    public let username: String?
    public let password: String?
    public let notes: String?
    public let fields: [String: String]

    public init(
        id: String,
        name: String,
        folder: String? = nil,
        folderId: String? = nil,
        username: String? = nil,
        password: String? = nil,
        notes: String? = nil,
        fields: [String: String] = [:]
    ) {
        self.id = id
        self.name = name
        self.folder = folder
        self.folderId = folderId
        self.username = username
        self.password = password
        self.notes = notes
        self.fields = fields
    }

    public var entry: VaultEntry {
        // Fixtures without folder ids use the folder name as one.
        VaultEntry(id: id, name: name, folder: folder, folderId: folderId ?? folder)
    }

    /// `password`, `username` and `notes` read the built-in fields; anything
    /// else is a custom field, matched case-insensitively.
    public func value(of field: String) throws(SecretLookupError) -> String {
        let value: String? = switch field.lowercased() {
        case "password": password
        case "username": username
        case "notes": notes
        default: fields.first { $0.key.caseInsensitiveCompare(field) == .orderedSame }?.value
        }
        guard let value else { throw .fieldNotFound(field) }
        return value
    }
}

public enum SecretLookupError: Error, Equatable, Sendable {
    case locked
    case notFound(String)
    case ambiguous(String, count: Int)
    case fieldNotFound(String)
}

/// Resolves `Folder/Item` paths against a set of vault entries.
///
/// A path is split at its last `/`: everything before it is the folder name
/// (Bitwarden spells nested folders as `Parent/Child`), the rest is the item
/// name. A path without `/` matches the item by name in any folder, and an
/// item id always matches exactly. Names compare case-sensitively; more than
/// one match is an error rather than a guess.
public struct VaultIndex: Sendable {
    let entries: [VaultEntry]

    public init(entries: [VaultEntry]) {
        self.entries = entries
    }

    public func entry(at path: String) throws(SecretLookupError) -> VaultEntry {
        if let byId = entries.first(where: { $0.id.caseInsensitiveCompare(path) == .orderedSame }) {
            return byId
        }
        let matches: [VaultEntry]
        if let slash = path.lastIndex(of: "/") {
            let folder = String(path[..<slash])
            let name = String(path[path.index(after: slash)...])
            matches = entries.filter { $0.folder == folder && $0.name == name }
        } else {
            matches = entries.filter { $0.name == path }
        }
        switch matches.count {
        case 0: throw .notFound(path)
        case 1: return matches[0]
        default: throw .ambiguous(path, count: matches.count)
        }
    }
}
