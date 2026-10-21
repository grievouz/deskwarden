import Testing
@testable import DeskwardenKit

struct VaultIndexTests {
    let items = [
        VaultItem(id: "id-pg", name: "Postgres", folder: "Infra/DB", username: "app", password: "pg", fields: ["Port": "5432"]),
        VaultItem(id: "id-stripe-1", name: "Stripe", folder: "Infra", password: "infra"),
        VaultItem(id: "id-stripe-2", name: "Stripe", folder: "Personal", password: "personal"),
        VaultItem(id: "id-notes", name: "Notes", notes: "hello"),
    ]

    var index: VaultIndex { VaultIndex(entries: items.map(\.entry)) }
    var provider: StaticSecretProvider { StaticSecretProvider(items: items) }

    @Test func resolvesNestedFolderPath() throws {
        #expect(try index.entry(at: "Infra/DB/Postgres").id == "id-pg")
    }

    @Test func resolvesNameWithoutFolder() async throws {
        #expect(try await provider.value(at: "Postgres", field: "username") == "app")
    }

    @Test func folderDisambiguatesSameName() async throws {
        #expect(try await provider.value(at: "Personal/Stripe", field: "password") == "personal")
    }

    @Test func ambiguousNameIsAnError() {
        #expect(throws: SecretLookupError.ambiguous("Stripe", count: 2)) {
            try index.entry(at: "Stripe")
        }
    }

    @Test func itemIdAlwaysMatches() throws {
        #expect(try index.entry(at: "id-stripe-2").folder == "Personal")
    }

    @Test func customFieldsMatchCaseInsensitively() throws {
        #expect(try items[0].value(of: "port") == "5432")
    }

    @Test func missingFieldIsAnError() {
        #expect(throws: SecretLookupError.fieldNotFound("password")) {
            try items[3].value(of: "password")
        }
    }

    @Test func missingItemIsAnError() {
        #expect(throws: SecretLookupError.notFound("Infra/Nope")) {
            try index.entry(at: "Infra/Nope")
        }
    }

    @Test func lockedProviderReportsLocked() async {
        await #expect(throws: SecretLookupError.locked) {
            try await StaticSecretProvider(items: items, locked: true).value(at: "Postgres", field: "password")
        }
    }
}
