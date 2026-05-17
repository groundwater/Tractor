import Darwin
import Foundation
import os.log

private let treeLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.ES", category: "tree")

/// Authoritative in-memory map of every process the ES daemon has seen.
///
/// Seeded once at startup with `proc_listallpids`, then kept fresh by
/// `NOTIFY_EXEC` and `NOTIFY_EXIT` calls from `ESDaemon`. Exposed to JS
/// programs as `getProc(pid)` and `getAncestry(pid)` — both synchronous
/// pointer-chase reads, no syscalls.
///
/// Dead entries linger for `deadGraceSeconds` so a probe that fires
/// racing an exit (e.g. exec event for a child whose parent just died)
/// still resolves to a complete chain.
final class ProcessTree {
    struct Entry {
        let pid: Int32
        let ppid: Int32
        let name: String       // basename of exe (or comm fallback)
        let exe: String        // full path, or "" if unknown
        let startedAt: Date
        var deadAt: Date?      // nil while alive
    }

    static let deadGraceSeconds: TimeInterval = 5

    private let lock = NSLock()
    private var byPid: [Int32: Entry] = [:]

    // MARK: - Updates

    /// Snapshot every currently-running process via `sysctl(KERN_PROC_ALL)`.
    /// We use sysctl instead of `proc_listallpids` because the latter, when
    /// called from inside a system extension, only returns a subset of
    /// processes (observed: ~150 out of ~640 on a typical desktop). sysctl
    /// returns the full kproc table regardless of caller context.
    func seed() {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var len = 0
        if sysctl(&mib, UInt32(mib.count), nil, &len, nil, 0) != 0 || len == 0 {
            os_log("ProcessTree.seed: sysctl sizing failed", log: treeLog, type: .error)
            return
        }
        let buf = UnsafeMutableRawPointer.allocate(byteCount: len, alignment: 16)
        defer { buf.deallocate() }
        if sysctl(&mib, UInt32(mib.count), buf, &len, nil, 0) != 0 {
            os_log("ProcessTree.seed: sysctl fetch failed", log: treeLog, type: .error)
            return
        }
        let stride = MemoryLayout<kinfo_proc>.stride
        let count = len / stride
        let now = Date()
        var pathBuf = [CChar](repeating: 0, count: 4096)
        let kprocs = buf.bindMemory(to: kinfo_proc.self, capacity: count)

        lock.lock()
        for i in 0..<count {
            let kp = kprocs[i]
            let pid = kp.kp_proc.p_pid
            if pid <= 0 { continue }
            let ppid = kp.kp_eproc.e_ppid

            // p_comm is the kernel-truncated 16-char short name; the full
            // exe path comes from proc_pidpath (per-pid syscall, cheap).
            let comm = withUnsafeBytes(of: kp.kp_proc.p_comm) { raw in
                String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
            }
            var exe = ""
            let n = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
            if n > 0 { exe = String(cString: pathBuf) }

            let name: String
            if !exe.isEmpty, let slash = exe.lastIndex(of: "/") {
                name = String(exe[exe.index(after: slash)...])
            } else if !exe.isEmpty {
                name = exe
            } else {
                name = comm
            }

            byPid[pid] = Entry(pid: pid, ppid: ppid, name: name,
                               exe: exe, startedAt: now, deadAt: nil)
        }
        let total = byPid.count
        lock.unlock()
        os_log("ProcessTree.seed: populated %{public}d entries from sysctl",
               log: treeLog, type: .default, total)
    }

    /// Insert/replace from a NOTIFY_EXEC event.
    func recordExec(pid: Int32, ppid: Int32, exePath: String) {
        let name: String
        if let slash = exePath.lastIndex(of: "/") {
            name = String(exePath[exePath.index(after: slash)...])
        } else {
            name = exePath
        }
        let entry = Entry(pid: pid, ppid: ppid, name: name,
                          exe: exePath, startedAt: Date(), deadAt: nil)
        lock.lock()
        byPid[pid] = entry
        lock.unlock()
    }

    /// Mark a pid as exited; the entry stays in the map for
    /// `deadGraceSeconds` so racing probes still resolve.
    func recordExit(pid: Int32) {
        lock.lock()
        if var entry = byPid[pid] {
            entry.deadAt = Date()
            byPid[pid] = entry
        }
        lock.unlock()
    }

    /// Remove all entries that exited more than `deadGraceSeconds` ago.
    /// Cheap; call from a 1Hz timer in ESDaemon.
    func prune() {
        let cutoff = Date().addingTimeInterval(-Self.deadGraceSeconds)
        lock.lock()
        for (pid, entry) in byPid {
            if let deadAt = entry.deadAt, deadAt < cutoff {
                byPid.removeValue(forKey: pid)
            }
        }
        lock.unlock()
    }

    /// Number of entries currently held (alive + dead-in-grace). Diagnostic.
    func size() -> Int {
        lock.lock(); defer { lock.unlock() }
        return byPid.count
    }

    /// Pids of every live (non-dead-in-grace) entry. Pure dict iteration,
    /// no syscalls. ESDaemon populates the tree on AUTH_EXEC so freshly-
    /// auth'd procs (including siblings of an exec'ing process) are
    /// already present.
    func livePids() -> [Int32] {
        lock.lock()
        var out: [Int32] = []
        out.reserveCapacity(byPid.count)
        for (pid, e) in byPid where e.deadAt == nil {
            out.append(pid)
        }
        lock.unlock()
        return out
    }

    /// Full per-entry snapshot of the tree as JS-friendly dicts.
    /// Tree-only — no per-pid syscalls. For CPU/mem/threads call
    /// `getProcStats(pid)` separately.
    func listProcs() -> [[String: Any]] {
        lock.lock()
        var out: [[String: Any]] = []
        out.reserveCapacity(byPid.count)
        for (_, e) in byPid {
            out.append(entryToDict(e))
        }
        lock.unlock()
        return out
    }

    /// Probe one (pid, fd) for pipe-ness. Returns `{handle, peerhandle}`
    /// when the fd is a pipe, nil otherwise. Single `proc_pidfdinfo`
    /// syscall — cheap enough to call in a tight loop.
    func fdPipeInfo(pid: Int32, fd: Int32) -> [String: Any]? {
        var info = pipe_fdinfo()
        let size = Int32(MemoryLayout<pipe_fdinfo>.size)
        let r = proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, &info, size)
        guard r == size else { return nil }
        // Both ends of a kernel pipe share the same vst_ino — reliable
        // match across processes. peerhandle is sometimes 0 depending on
        // macOS version, so callers should treat it as a fallback.
        return [
            "handle":     Int(bitPattern: UInt(info.pipeinfo.pipe_handle)),
            "peerhandle": Int(bitPattern: UInt(info.pipeinfo.pipe_peerhandle)),
            "inode":      Int(bitPattern: UInt(info.pipeinfo.pipe_stat.vst_ino)),
        ]
    }

    // MARK: - Reads (called from JS engine queue)

    /// Single-pid lookup. Returns a JS-friendly dict, or nil if unknown.
    func proc(pid: Int32) -> [String: Any]? {
        lock.lock()
        let e = byPid[pid]
        lock.unlock()
        guard let e = e else { return nil }
        return entryToDict(e)
    }

    /// Walk up the parent chain from `pid` (inclusive) until we hit
    /// `pid <= 1` or an unknown ppid. Bounded by `maxDepth` to defend
    /// against cycles in pathological cases.
    func ancestry(pid: Int32, maxDepth: Int = 32) -> [[String: Any]] {
        var out: [[String: Any]] = []
        lock.lock()
        var current = pid
        var depth = 0
        var seen = Set<Int32>()
        while depth < maxDepth, current > 0, !seen.contains(current),
              let e = byPid[current] {
            seen.insert(current)
            out.append(entryToDict(e))
            if e.ppid == current { break }   // self-parent (launchd)
            current = e.ppid
            depth += 1
        }
        lock.unlock()
        return out
    }

    /// Names along the ancestor chain — pre-baked because the cheapest
    /// JS-side test ("did `curl` ever appear above me?") is `arr.includes`.
    func ancestryNames(pid: Int32, maxDepth: Int = 32) -> [String] {
        var out: [String] = []
        lock.lock()
        var current = pid
        var depth = 0
        var seen = Set<Int32>()
        while depth < maxDepth, current > 0, !seen.contains(current),
              let e = byPid[current] {
            seen.insert(current)
            out.append(e.name)
            if e.ppid == current { break }
            current = e.ppid
            depth += 1
        }
        lock.unlock()
        return out
    }

    private func entryToDict(_ e: Entry) -> [String: Any] {
        var d: [String: Any] = [
            "pid": Int(e.pid),
            "ppid": Int(e.ppid),
            "name": e.name,
            "exe": e.exe,
            "started_at_ms": Int(e.startedAt.timeIntervalSince1970 * 1000),
        ]
        if let dead = e.deadAt {
            d["dead_at_ms"] = Int(dead.timeIntervalSince1970 * 1000)
        }
        return d
    }
}
