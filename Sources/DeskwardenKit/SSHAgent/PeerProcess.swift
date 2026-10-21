import Darwin
import Foundation
import Security

/// One process between an SSH client and the app it runs in.
public struct ProcessDescription: Sendable, Hashable {
    public let pid: pid_t
    public let name: String
    public let path: String
}

/// How an app that used the SSH agent is recognized next time: by developer
/// team and bundle identifier when it's signed by one, otherwise by path and
/// code hash, so an unsigned binary that changes is asked about again.
public struct ProcessIdentity: Codable, Hashable, Sendable {
    public let path: String
    public let bundleIdentifier: String?
    public let teamIdentifier: String?
    public let codeHash: Data?

    public init(path: String, bundleIdentifier: String?, teamIdentifier: String?, codeHash: Data?) {
        self.path = path
        self.bundleIdentifier = bundleIdentifier
        self.teamIdentifier = teamIdentifier
        self.codeHash = codeHash
    }

    public func matches(_ other: ProcessIdentity) -> Bool {
        if let teamIdentifier {
            return teamIdentifier == other.teamIdentifier && bundleIdentifier == other.bundleIdentifier
        }
        return path == other.path && codeHash == other.codeHash
    }
}

/// The process that connected to the SSH agent, and the app it belongs to.
///
/// The connecting process is almost always `ssh`, which says nothing about
/// who's asking, so the agent walks up its parents to the app it was started
/// from: the outermost `.app` bundle, such as a terminal or an editor. Without
/// one, e.g. under a tmux server, it's the topmost process below launchd.
public struct SSHClient: Sendable {
    /// The connecting process first, then its parents.
    public let chain: [ProcessDescription]
    public let appName: String
    public let identity: ProcessIdentity
    /// The commands between the app and the agent, e.g. `git → ssh`, with shells left out.
    public let via: String

    public init(chain: [ProcessDescription], appName: String, identity: ProcessIdentity, via: String) {
        self.chain = chain
        self.appName = appName
        self.identity = identity
        self.via = via
    }
}

enum PeerProcess {
    private static let shells: Set<String> = ["login", "sh", "bash", "zsh", "fish", "dash", "tcsh", "csh", "nu", "xonsh", "elvish"]

    /// The connecting process and its user, from the kernel.
    static func credentials(of socket: Int32) -> (pid: pid_t, uid: uid_t)? {
        var pid: pid_t = 0
        var length = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0 else { return nil }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(socket, &uid, &gid) == 0 else { return nil }
        return (pid, uid)
    }

    static func client(pid: pid_t) -> SSHClient? {
        var chain: [ProcessDescription] = []
        var current = pid
        while current > 1, chain.count < 64, let path = path(of: current) {
            chain.append(ProcessDescription(pid: current, name: URL(fileURLWithPath: path).lastPathComponent, path: path))
            guard let parent = parent(of: current) else { break }
            current = parent
        }
        guard let top = chain.last else { return nil }

        let appIndex = chain.firstIndex { $0.path.contains(".app/") }
        let owner = appIndex.map { chain[$0] } ?? top
        let between = chain[..<(appIndex ?? chain.count - 1)]
        let via = between.reversed().map(\.name).filter { !shells.contains($0) }.joined(separator: " → ")
        let signing = signingInformation(pid: owner.pid)

        if appIndex != nil, let range = owner.path.range(of: ".app/") {
            let bundlePath = String(owner.path[..<range.lowerBound]) + ".app"
            let bundle = Bundle(path: bundlePath)
            let name = bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
                ?? URL(fileURLWithPath: bundlePath).deletingPathExtension().lastPathComponent
            return SSHClient(
                chain: chain,
                appName: name,
                identity: ProcessIdentity(
                    path: bundlePath,
                    bundleIdentifier: bundle?.bundleIdentifier ?? signing.identifier,
                    teamIdentifier: signing.team,
                    codeHash: signing.team == nil ? signing.codeHash : nil
                ),
                via: via
            )
        }
        return SSHClient(
            chain: chain,
            appName: owner.name,
            identity: ProcessIdentity(
                path: owner.path,
                bundleIdentifier: signing.identifier,
                teamIdentifier: signing.team,
                codeHash: signing.team == nil ? signing.codeHash : nil
            ),
            via: via
        )
    }

    private static func path(of pid: pid_t) -> String? {
        var buffer = [UInt8](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = Int(proc_pidpath(pid, &buffer, UInt32(buffer.count)))
        guard length > 0 else { return nil }
        return String(decoding: buffer[..<length], as: UTF8.self)
    }

    private static func parent(of pid: pid_t) -> pid_t? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return pid_t(info.pbi_ppid)
    }

    /// The team is only trusted when the running code's signature is valid.
    private static func signingInformation(pid: pid_t) -> (team: String?, identifier: String?, codeHash: Data?) {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) == errSecSuccess,
              let code
        else { return (nil, nil, nil) }
        let valid = SecCodeCheckValidity(code, [], nil) == errSecSuccess
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any]
        else { return (nil, nil, nil) }
        return (
            valid ? info[kSecCodeInfoTeamIdentifier as String] as? String : nil,
            info[kSecCodeInfoIdentifier as String] as? String,
            info[kSecCodeInfoUnique as String] as? Data
        )
    }
}
