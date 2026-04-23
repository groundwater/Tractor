import Foundation

/// Tracks a set of PIDs forming a process tree. Thread-safe.
final class ProcessTree {
    private let lock = NSLock()
    private var pids: Set<pid_t> = []

    /// Seed the tree with initial root PIDs
    func addRoots(_ roots: [pid_t]) {
        lock.lock()
        defer { lock.unlock() }
        for pid in roots {
            pids.insert(pid)
        }
    }

    /// Record a new child if its parent is tracked. Returns true if added.
    @discardableResult
    func trackIfChild(pid: pid_t, ppid: pid_t) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard pids.contains(ppid) else { return false }
        pids.insert(pid)
        return true
    }

    /// Check if a PID is in the tracked tree
    func contains(_ pid: pid_t) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return pids.contains(pid)
    }

    /// Remove a PID (e.g. on exit)
    func remove(_ pid: pid_t) {
        lock.lock()
        defer { lock.unlock() }
        pids.remove(pid)
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return pids.count
    }

    var snapshot: Set<pid_t> {
        lock.lock()
        defer { lock.unlock() }
        return pids
    }
}

// MARK: - Process Discovery

/// Find running PIDs whose executable path or process name contains the given pattern (case-insensitive)
func findProcessesByName(_ pattern: String) -> [pid_t] {
    var results: [pid_t] = []
    let lowerPattern = pattern.lowercased()

    var pids = [pid_t](repeating: 0, count: 4096)
    let count = proc_listallpids(&pids, Int32(MemoryLayout<pid_t>.size * pids.count))
    guard count > 0 else { return [] }

    for i in 0..<Int(count) {
        let pid = pids[i]
        if pid <= 0 { continue }

        // Try proc_pidpath first, fall back to proc_name
        var matched = false
        var pathBuf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let pathLen = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
        if pathLen > 0 {
            let path = String(cString: pathBuf).lowercased()
            matched = path.contains(lowerPattern)
        }
        if !matched {
            var nameBuf = [CChar](repeating: 0, count: 256)
            proc_name(pid, &nameBuf, UInt32(nameBuf.count))
            let name = String(cString: nameBuf).lowercased()
            matched = !name.isEmpty && name.contains(lowerPattern)
        }
        if matched {
            results.append(pid)
        }
    }
    return results
}

/// Find running PIDs whose executable path exactly matches the given path
func findProcessesByExactPath(_ targetPath: String) -> [pid_t] {
    var results: [pid_t] = []

    var pids = [pid_t](repeating: 0, count: 4096)
    let count = proc_listallpids(&pids, Int32(MemoryLayout<pid_t>.size * pids.count))
    guard count > 0 else { return [] }

    for i in 0..<Int(count) {
        let pid = pids[i]
        if pid <= 0 { continue }

        var pathBuf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let pathLen = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
        if pathLen > 0 {
            let path = String(cString: pathBuf)
            if path == targetPath {
                results.append(pid)
            }
        }
    }
    return results
}

/// Build full descendant tree from a set of root PIDs using current process list
func expandProcessTree(roots: [pid_t]) -> [pid_t] {
    var tracked = Set(roots)
    // Build parent -> children map
    var parentMap: [pid_t: [pid_t]] = [:]

    var pids = [pid_t](repeating: 0, count: 4096)
    let count = proc_listallpids(&pids, Int32(MemoryLayout<pid_t>.size * pids.count))
    guard count > 0 else { return roots }

    for i in 0..<Int(count) {
        let pid = pids[i]
        if pid <= 0 { continue }
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        if size > 0 {
            parentMap[pid_t(info.pbi_ppid), default: []].append(pid)
        }
    }

    // BFS from roots
    var queue = roots
    while !queue.isEmpty {
        let current = queue.removeFirst()
        if let children = parentMap[current] {
            for child in children where !tracked.contains(child) {
                tracked.insert(child)
                queue.append(child)
            }
        }
    }

    return Array(tracked)
}

/// Get path, ppid, and argv for an already-running process
func getProcessInfo(_ pid: pid_t) -> (path: String, ppid: pid_t, argv: String) {
    var pathBuf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    let pathLen = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
    var path: String
    if pathLen > 0 {
        path = String(cString: pathBuf)
    } else {
        // Fallback to proc_name when path is unavailable
        var nameBuf = [CChar](repeating: 0, count: 256)
        proc_name(pid, &nameBuf, UInt32(nameBuf.count))
        let name = String(cString: nameBuf)
        path = name.isEmpty ? "?" : name
    }

    var info = proc_bsdinfo()
    let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
    let ppid: pid_t = size > 0 ? pid_t(info.pbi_ppid) : 0

    // Get argv from procargs2
    var argmax: Int = 0
    var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
    var argmaxSize = MemoryLayout<Int>.size
    sysctl(&mib, 2, &argmax, &argmaxSize, nil, 0)

    var procArgs = [UInt8](repeating: 0, count: argmax)
    var procArgsSize = argmax
    var mib2: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    guard sysctl(&mib2, 3, &procArgs, &procArgsSize, nil, 0) == 0, procArgsSize > MemoryLayout<Int32>.size else {
        return (path, ppid, path)
    }

    // procargs2 layout: [argc: Int32][exec_path\0][padding\0...][argv0\0][argv1\0]...
    let argc = procArgs.withUnsafeBytes { $0.load(as: Int32.self) }
    var offset = MemoryLayout<Int32>.size

    // Skip exec path
    while offset < procArgsSize && procArgs[offset] != 0 { offset += 1 }
    // Skip null padding
    while offset < procArgsSize && procArgs[offset] == 0 { offset += 1 }

    // Read argv
    var args: [String] = []
    for _ in 0..<argc {
        guard offset < procArgsSize else { break }
        var end = offset
        while end < procArgsSize && procArgs[end] != 0 { end += 1 }
        let arg = String(bytes: procArgs[offset..<end], encoding: .utf8) ?? ""
        args.append(arg)
        offset = end + 1
    }

    let argv = args.joined(separator: " ")
    return (path, ppid, argv)
}

/// Get argv as an array for a process
func getProcessArgs(_ pid: pid_t) -> [String] {
    var argmax: Int = 0
    var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
    var argmaxSize = MemoryLayout<Int>.size
    sysctl(&mib, 2, &argmax, &argmaxSize, nil, 0)

    var procArgs = [UInt8](repeating: 0, count: argmax)
    var procArgsSize = argmax
    var mib2: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    guard sysctl(&mib2, 3, &procArgs, &procArgsSize, nil, 0) == 0, procArgsSize > MemoryLayout<Int32>.size else {
        return []
    }

    let argc = procArgs.withUnsafeBytes { $0.load(as: Int32.self) }
    var offset = MemoryLayout<Int32>.size

    while offset < procArgsSize && procArgs[offset] != 0 { offset += 1 }
    while offset < procArgsSize && procArgs[offset] == 0 { offset += 1 }

    var args: [String] = []
    for _ in 0..<argc {
        guard offset < procArgsSize else { break }
        var end = offset
        while end < procArgsSize && procArgs[end] != 0 { end += 1 }
        let arg = String(bytes: procArgs[offset..<end], encoding: .utf8) ?? ""
        args.append(arg)
        offset = end + 1
    }
    return args
}

/// Get environment variables for a process from KERN_PROCARGS2
func getProcessEnv(_ pid: pid_t) -> [String] {
    var argmax: Int = 0
    var mib: [Int32] = [CTL_KERN, KERN_ARGMAX]
    var argmaxSize = MemoryLayout<Int>.size
    sysctl(&mib, 2, &argmax, &argmaxSize, nil, 0)

    var procArgs = [UInt8](repeating: 0, count: argmax)
    var procArgsSize = argmax
    var mib2: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    guard sysctl(&mib2, 3, &procArgs, &procArgsSize, nil, 0) == 0, procArgsSize > MemoryLayout<Int32>.size else {
        return []
    }

    // procargs2 layout: [argc: Int32][exec_path\0][padding\0...][argv0\0][argv1\0]...[env0\0][env1\0]...
    let argc = procArgs.withUnsafeBytes { $0.load(as: Int32.self) }
    var offset = MemoryLayout<Int32>.size

    // Skip exec path
    while offset < procArgsSize && procArgs[offset] != 0 { offset += 1 }
    // Skip null padding
    while offset < procArgsSize && procArgs[offset] == 0 { offset += 1 }

    // Skip argv
    for _ in 0..<argc {
        guard offset < procArgsSize else { return [] }
        while offset < procArgsSize && procArgs[offset] != 0 { offset += 1 }
        offset += 1
    }

    // Read env vars (everything after argv until end)
    var envVars: [String] = []
    while offset < procArgsSize {
        var end = offset
        while end < procArgsSize && procArgs[end] != 0 { end += 1 }
        if end > offset {
            if let env = String(bytes: procArgs[offset..<end], encoding: .utf8) {
                envVars.append(env)
            }
        }
        offset = end + 1
    }
    return envVars
}
