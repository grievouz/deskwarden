import Foundation

/// Points the agent socket launchd gives every process in the login session
/// (their `SSH_AUTH_SOCK`) at Deskwarden's agent, so everything that reads
/// `SSH_AUTH_SOCK` reaches it: shells, apps opened from the Dock and
/// processes that are already running, for `ssh-add`, git's SSH commit
/// signing and the like. It's the approach 1Password documents for its agent.
///
/// launchd picks a new path at every login and the link lives under
/// /var/run, which is cleared at reboot, so the app links it again each time
/// it starts. Unlinking leaves the path empty until the next login, when
/// macOS's own agent is back.
public struct LaunchdAgentLink: Sendable {
    public enum LinkError: Error, LocalizedError {
        case noLaunchdSocket

        public var errorDescription: String? {
            "launchd didn't provide an SSH_AUTH_SOCK to link"
        }
    }

    public let path: String

    public init(path: String) {
        self.path = path
    }

    /// The session's launchd socket, if `SSH_AUTH_SOCK` is one. Anything else
    /// isn't touched.
    public static func current() -> LaunchdAgentLink? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["getenv", "SSH_AUTH_SOCK"]
        let output = Pipe()
        process.standardOutput = output
        guard (try? process.run()) != nil else { return nil }
        let path = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        process.waitUntilExit()
        return isLaunchdSocket(path) ? LaunchdAgentLink(path: path) : nil
    }

    static func isLaunchdSocket(_ path: String) -> Bool {
        path.wholeMatch(of: /(\/private)?\/(var\/run|tmp)\/com\.apple\.launchd\.[A-Za-z0-9]+\/Listeners/) != nil
    }

    public var isLinked: Bool {
        isLinked(to: nil)
    }

    private func isLinked(to target: String?) -> Bool {
        guard let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: path) else { return false }
        return target.map { destination == $0 } ?? true
    }

    /// Replaces launchd's socket, or an earlier link, with a link to `target`.
    public func link(to target: String) throws {
        guard !isLinked(to: target) else { return }
        // Not `fileExists`, which follows links and misses a dangling one.
        if (try? FileManager.default.attributesOfItem(atPath: path)) != nil {
            try FileManager.default.removeItem(atPath: path)
        }
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)
    }

    /// Removes the link if it's Deskwarden's, and leaves anything else alone.
    public func unlink(from target: String) throws {
        guard isLinked(to: target) else { return }
        try FileManager.default.removeItem(atPath: path)
    }
}
