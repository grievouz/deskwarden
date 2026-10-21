import Foundation
import Testing
@testable import DeskwardenKit

struct SSHConfigFileTests {
    let socket = "~/.deskwarden/ssh-agent.sock"

    @Test(arguments: [
        "",
        "Host github.com\n  User git\n",
        "Include ~/.orbstack/ssh/config\n\nHost *.internal\n  IdentityAgent ~/other.sock\n",
    ])
    func addingThenRemovingRestoresTheFile(original: String) {
        let added = SSHConfigFile.adding(socketPath: socket, to: original)
        #expect(added.hasPrefix(original))
        #expect(added.hasSuffix("Host *\n  IdentityAgent \(socket)\n\(SSHConfigFile.end)\n"))
        #expect(SSHConfigFile.removing(from: added) == original)
    }

    @Test func addingTwiceKeepsOneBlock() {
        let once = SSHConfigFile.adding(socketPath: socket, to: "Host a\n  User b\n")
        let twice = SSHConfigFile.adding(socketPath: socket, to: once)
        #expect(twice == once)
    }

    @Test func keepsWhatTheUserAddedAfterTheBlock() {
        let added = SSHConfigFile.adding(socketPath: socket, to: "Host a\n  User b\n") + "Host c\n  User d\n"
        #expect(SSHConfigFile.removing(from: added) == "Host a\n  User b\n\nHost c\n  User d\n")
    }

    @Test func installsAndUninstallsAFile() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("dw-ssh-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = SSHConfigFile(url: directory.appendingPathComponent(".ssh/config"))

        try file.install(socketPath: socket)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.url.path)
        #expect((attributes[.posixPermissions] as? Int) == 0o600)
        #expect(try String(contentsOf: file.url, encoding: .utf8).contains("IdentityAgent \(socket)"))

        // A file that only had the block goes away again.
        try file.uninstall()
        #expect(!FileManager.default.fileExists(atPath: file.url.path))
    }

    @Test func writesThroughASymlink() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("dw-ssh-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let real = directory.appendingPathComponent("dotfiles-ssh-config")
        try Data("Host a\n  User b\n".utf8).write(to: real)
        let link = directory.appendingPathComponent("config")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)

        let file = SSHConfigFile(url: link)
        try file.install(socketPath: socket)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == real.path)
        #expect(try String(contentsOf: real, encoding: .utf8).contains("IdentityAgent"))
        try file.uninstall()
        #expect(try String(contentsOf: real, encoding: .utf8) == "Host a\n  User b\n")
    }
}
