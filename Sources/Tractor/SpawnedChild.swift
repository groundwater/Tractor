import Darwin
import Foundation

/// Resolves Tractor's default output locations and ensures they exist.
enum TractorPaths {
    private static let appGroupID = "group.com.jacobgroundwater.Tractor"

    private static func uniqueStamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let stamp = formatter.string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let pid = ProcessInfo.processInfo.processIdentifier
        return "\(stamp)-\(pid)"
    }

    static func appGroupContainer() throws -> URL {
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            throw NSError(domain: "TractorPaths", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Cannot resolve Tractor app group container. Install Tractor first, then retry.",
            ])
        }
        return url
    }

    static func appGroupTracesDirectory() throws -> URL {
        let dir = try appGroupContainer().appendingPathComponent("traces", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        return dir
    }

    static func userTracesDirectory() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let dir = support.appendingPathComponent("Tractor/traces", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    static func sharedLogPath() throws -> String {
        try appGroupContainer().appendingPathComponent("tractor.db").path
    }

    /// e.g. trace-2026-05-12T18-04-21Z.db
    static func defaultLogPath(prefix: String) throws -> String {
        try appGroupTracesDirectory().appendingPathComponent("\(prefix)-\(uniqueStamp()).db").path
    }

    static func defaultJSONPath(prefix: String) throws -> String {
        try userTracesDirectory().appendingPathComponent("\(prefix)-\(uniqueStamp()).jsonl").path
    }
}

/// Spawns a child process that blocks until the parent unblocks it. Used so the
/// parent can register the child's PID with the ES sysext before the child calls
/// execve() — otherwise the AUTH_EXEC event for the root command can arrive
/// before the sysext knows it should track it.
enum SpawnedChild {
    /// Parses a user-supplied command string. If it contains shell metacharacters
    /// we run it under `/bin/sh -c`; otherwise we split on whitespace and execve directly.
    /// `argvOverride`, when set, skips parsing — used by `tractor exec` which already has argv.
    static func argv(for command: String, argvOverride: [String]? = nil) -> [String] {
        if let argvOverride = argvOverride { return argvOverride }
        let shellMetas: Set<Character> = ["|", "&", ";", "<", ">", "(", ")", "$", "`", "\\", "\"", "'", "*", "?", "[", "]", "{", "}", "~"]
        if command.contains(where: { shellMetas.contains($0) }) {
            return ["/bin/sh", "-c", command]
        }
        return command.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
    }

    enum StdioMode {
        case inherit            // tractor exec — child uses our stdin/stdout/stderr
        case devNull            // trace --exec — TUI owns the terminal; discard child output
    }

    /// Fork, set up stdio, block child on a pipe read, return the child's PID.
    /// Call `release(pid)` once you've registered the PID upstream to let the child execve.
    /// On exec failure, child writes 1 byte of errno to `errPipeRead` then _exit's.
    struct Pending {
        let pid: pid_t
        let release: () -> Void           // close the gate pipe so child execs
        let argv: [String]
    }

    static func fork(argv: [String], stdio: StdioMode) throws -> Pending {
        var gate: [Int32] = [-1, -1]
        guard pipe(&gate) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno),
                          userInfo: [NSLocalizedDescriptionKey: "pipe failed: \(String(cString: strerror(errno)))"])
        }

        let pid = tractor_fork()
        if pid < 0 {
            close(gate[0]); close(gate[1])
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno),
                          userInfo: [NSLocalizedDescriptionKey: "fork failed: \(String(cString: strerror(errno)))"])
        }

        if pid == 0 {
            // Child
            close(gate[1])
            // Block until parent closes write end.
            var byte: UInt8 = 0
            _ = read(gate[0], &byte, 1)
            close(gate[0])

            if case .devNull = stdio {
                let devnull = open("/dev/null", O_RDWR)
                if devnull >= 0 {
                    dup2(devnull, 0); dup2(devnull, 1); dup2(devnull, 2)
                    if devnull > 2 { close(devnull) }
                }
            }

            // Build argv for execvp
            let cArgs = argv.map { strdup($0) } + [UnsafeMutablePointer<CChar>?(nil)]
            _ = cArgs.withUnsafeBufferPointer { buf in
                execvp(argv[0], buf.baseAddress!)
            }
            // execvp returned → failure
            let msg = "tractor: failed to exec \(argv[0]): \(String(cString: strerror(errno)))\n"
            _ = msg.withCString { write(2, $0, strlen($0)) }
            _exit(127)
        }

        // Parent
        close(gate[0])
        let writeFD = gate[1]
        return Pending(pid: pid, release: { close(writeFD) }, argv: argv)
    }
}
