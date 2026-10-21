import Foundation

/// Points OpenSSH at the agent through `~/.ssh/config`, in a marked block
/// Deskwarden adds when the agent is turned on and removes when it's turned off.
///
/// `IdentityAgent` reaches every `ssh` run, including ones from apps opened in
/// the Dock that don't see a shell's `SSH_AUTH_SOCK`. The block goes at the
/// end, so an `IdentityAgent` set for specific hosts earlier in the file wins.
public struct SSHConfigFile: Sendable {
    static let begin = "# Added by Deskwarden. Turning off its SSH agent removes this."
    static let end = "# End of Deskwarden"

    public let url: URL

    public init(url: URL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")) {
        self.url = url
    }

    public func install(socketPath: String) throws {
        try update { Self.adding(socketPath: socketPath, to: $0) }
    }

    public func uninstall() throws {
        try update { Self.removing(from: $0) }
    }

    /// Writes through a symlink rather than replacing it, since dotfile
    /// managers often link `~/.ssh/config`.
    private func update(_ change: (String) -> String) throws {
        let target = url.resolvingSymlinksInPath()
        let exists = FileManager.default.fileExists(atPath: target.path)
        let contents = exists ? try String(contentsOf: target, encoding: .utf8) : ""
        let updated = change(contents)
        guard updated != contents else { return }

        if updated.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            // Nothing but our block was there.
            if exists { try FileManager.default.removeItem(at: target) }
            return
        }
        let directory = target.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Data(updated.utf8).write(to: target)
        if !exists {
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        }
    }

    /// The config with the block at the end, replacing an earlier one.
    static func adding(socketPath: String, to contents: String) -> String {
        var config = removing(from: contents)
        if !config.isEmpty {
            if !config.hasSuffix("\n") { config += "\n" }
            config += "\n"
        }
        return config + """
        \(begin)
        Host *
          IdentityAgent \(socketPath)
        \(end)

        """
    }

    /// The config without the block or the blank line separating it.
    static func removing(from contents: String) -> String {
        var lines = contents.components(separatedBy: "\n")
        guard let start = lines.firstIndex(of: begin),
              let finish = lines[start...].firstIndex(of: end)
        else { return contents }
        lines.removeSubrange(start...finish)
        if start > 0, start <= lines.count, lines[start - 1].isEmpty, start == lines.count || lines[start].isEmpty {
            lines.remove(at: start - 1)
        }
        return lines.joined(separator: "\n")
    }
}
