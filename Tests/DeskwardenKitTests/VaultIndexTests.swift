import Testing
@testable import DeskwardenKit

struct VaultIndexTests {
    let index = VaultIndex(items: [
        VaultItem(id: "id-pg", name: "Postgres", folder: "Infra/DB", username: "app", password: "pg", fields: ["Port": "5432"]),
        VaultItem(id: "id-stripe-1", name: "Stripe", folder: "Infra", password: "infra"),
        VaultItem(id: "id-stripe-2", name: "Stripe", folder: "Personal", password: "personal"),
        VaultItem(id: "id-notes", name: "Notes", notes: "hello"),
    ])

    @Test func resolvesNestedFolderPath() throws {
        #expect(try index.value(at: "Infra/DB/Postgres") == "pg")
    }

    @Test func resolvesNameWithoutFolder() throws {
        #expect(try index.value(at: "Postgres", field: "username") == "app")
    }

    @Test func folderDisambiguatesSameName() throws {
        #expect(try index.value(at: "Personal/Stripe") == "personal")
    }

    @Test func ambiguousNameIsAnError() {
        #expect(throws: SecretLookupError.ambiguous("Stripe", count: 2)) {
            try index.value(at: "Stripe")
        }
    }

    @Test func itemIdAlwaysMatches() throws {
        #expect(try index.value(at: "id-stripe-2") == "personal")
    }

    @Test func customFieldsMatchCaseInsensitively() throws {
        #expect(try index.value(at: "Infra/DB/Postgres", field: "port") == "5432")
    }

    @Test func missingFieldIsAnError() {
        #expect(throws: SecretLookupError.fieldNotFound("password")) {
            try index.value(at: "Notes")
        }
    }

    @Test func missingItemIsAnError() {
        #expect(throws: SecretLookupError.notFound("Infra/Nope")) {
            try index.value(at: "Infra/Nope")
        }
    }
}
