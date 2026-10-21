import Foundation
import Testing
@testable import DeskwardenKit

struct ExternalApplicationTests {
    @Test func keyRoundTrips() throws {
        let application = ExternalApplication.generate(name: "varlock")
        let key = try #require(application.key)
        let parsed = try #require(ExternalApplication.parse(key: key))
        #expect(parsed.id == application.id)
        #expect(parsed.secret == application.secret)
        #expect(application.key?.hasPrefix("dwk_") == true)
    }

    @Test func generatedApplicationsDiffer() {
        let a = ExternalApplication.generate(name: "a")
        let b = ExternalApplication.generate(name: "b")
        #expect(a.id != b.id)
        #expect(a.secret != b.secret)
    }

    @Test(arguments: [
        "",
        "dwk_",
        "dwk_abc",
        "xyz_0011223344556677_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        // secret too short
        "dwk_0011223344556677_AAAA",
    ])
    func rejectsMalformedKeys(key: String) {
        #expect(ExternalApplication.parse(key: key) == nil)
    }
}
