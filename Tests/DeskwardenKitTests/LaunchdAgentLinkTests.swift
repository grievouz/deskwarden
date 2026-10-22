import Darwin
import Foundation
import Testing
@testable import DeskwardenKit

struct LaunchdAgentLinkTests {
    @Test(arguments: [
        ("/var/run/com.apple.launchd.FTeMNRI4Vc/Listeners", true),
        ("/private/var/run/com.apple.launchd.FTeMNRI4Vc/Listeners", true),
        ("/private/tmp/com.apple.launchd.abc123/Listeners", true),
        ("/Users/me/.bitwarden-ssh-agent.sock", false),
        ("/var/run/com.apple.launchd.x/Listeners/../../etc", false),
        ("", false),
    ])
    func recognizesOnlyLaunchdSockets(path: String, expected: Bool) {
        #expect(LaunchdAgentLink.isLaunchdSocket(path) == expected)
    }

    @Test func replacesTheSocketAndRemovesOnlyItsOwnLink() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dw-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let socketPath = directory.appendingPathComponent("Listeners").path
        try makeSocket(at: socketPath)
        let link = LaunchdAgentLink(path: socketPath)
        let target = "/Users/me/.deskwarden/ssh-agent.sock"

        #expect(!link.isLinked)
        try link.link(to: target)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: socketPath) == target)
        try link.link(to: target)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: socketPath) == target)

        // Someone else's link stays.
        try link.unlink(from: "/elsewhere.sock")
        #expect(link.isLinked)
        try link.unlink(from: target)
        #expect((try? FileManager.default.attributesOfItem(atPath: socketPath)) == nil)
    }

    @Test func replacesADanglingLink() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dw-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let socketPath = directory.appendingPathComponent("Listeners").path
        try FileManager.default.createSymbolicLink(atPath: socketPath, withDestinationPath: "/gone.sock")

        try LaunchdAgentLink(path: socketPath).link(to: "/new.sock")
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: socketPath) == "/new.sock")
    }

    private func makeSocket(at path: String) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { close(fd) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(path.utf8CString).map { UInt8(bitPattern: $0) }) }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        #expect(result == 0)
    }
}
