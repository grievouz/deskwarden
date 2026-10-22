import Foundation

/// Folders and items an application may use without a prompt. A folder
/// includes the folders nested in it (Bitwarden spells those `Parent/Child`).
/// SSH keys are vault items, so an SSH client's selection is item ids.
public struct AccessSelection: Codable, Hashable, Sendable {
    public var folderIds: Set<String>
    public var itemIds: Set<String>

    public init(folderIds: Set<String> = [], itemIds: Set<String> = []) {
        self.folderIds = folderIds
        self.itemIds = itemIds
    }

    public var isEmpty: Bool {
        folderIds.isEmpty && itemIds.isEmpty
    }

    /// `folderNames` maps folder ids to their current names, for nesting.
    public func allows(_ entry: VaultEntry, folderNames: [String: String]) -> Bool {
        if itemIds.contains(entry.id) { return true }
        if let folderId = entry.folderId, folderIds.contains(folderId) { return true }
        guard let folder = entry.folder else { return false }
        return folderIds.contains { id in
            folderNames[id].map { folder.hasPrefix($0 + "/") } ?? false
        }
    }
}
