import Foundation
import Testing
@testable import DeskwardenKit

struct AccessSelectionTests {
    let folderNames = ["infra": "Infra", "databases": "Infra/Databases", "personal": "Personal"]

    func entry(_ id: String, folder: String? = nil, folderId: String? = nil) -> VaultEntry {
        VaultEntry(id: id, name: id, folder: folder, folderId: folderId)
    }

    @Test func allowsSelectedItems() {
        let selection = AccessSelection(itemIds: ["a"])
        #expect(selection.allows(entry("a"), folderNames: folderNames))
        #expect(!selection.allows(entry("b"), folderNames: folderNames))
    }

    @Test func allowsItemsInSelectedFoldersAndTheirSubfolders() {
        let selection = AccessSelection(folderIds: ["infra"])
        #expect(selection.allows(entry("a", folder: "Infra", folderId: "infra"), folderNames: folderNames))
        #expect(selection.allows(entry("b", folder: "Infra/Databases", folderId: "databases"), folderNames: folderNames))
        #expect(!selection.allows(entry("c", folder: "Personal", folderId: "personal"), folderNames: folderNames))
        #expect(!selection.allows(entry("d"), folderNames: folderNames))
    }

    @Test func doesNotTreatANamePrefixAsAParentFolder() {
        let selection = AccessSelection(folderIds: ["infra"])
        let names = folderNames.merging(["infrastructure": "Infrastructure"]) { $1 }
        #expect(!selection.allows(entry("a", folder: "Infrastructure", folderId: "infrastructure"), folderNames: names))
    }

    @Test func selectingASubfolderLeavesItsParentOut() {
        let selection = AccessSelection(folderIds: ["databases"])
        #expect(!selection.allows(entry("a", folder: "Infra", folderId: "infra"), folderNames: folderNames))
    }

    @Test func applicationsSavedBeforeSelectionsStillDecode() throws {
        let application = ExternalApplication.generate(name: "varlock")
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(application)) as! [String: Any]
        json["allowed"] = nil
        let decoded = try JSONDecoder().decode(ExternalApplication.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(decoded.allowed == nil)

        var selected = application
        selected.allowed = AccessSelection(folderIds: ["infra"], itemIds: ["a"])
        let roundTripped = try JSONDecoder().decode(ExternalApplication.self, from: JSONEncoder().encode(selected))
        #expect(roundTripped.allowed == selected.allowed)
    }
}
