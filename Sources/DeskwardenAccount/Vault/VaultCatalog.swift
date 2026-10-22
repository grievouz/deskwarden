import DeskwardenKit
import Foundation

/// The folders, items and SSH keys of the unlocked vault, names only.
public struct VaultCatalog: Sendable {
    public struct Folder: Sendable, Hashable, Identifiable {
        public let id: String
        public let name: String
    }

    public let folders: [Folder]
    /// Items other than SSH keys.
    public let items: [VaultEntry]
    public let sshKeys: [SSHKeyEntry]
}
