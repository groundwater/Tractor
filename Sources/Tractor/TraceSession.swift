import Foundation

// MARK: - Options & roots

struct TraceOptions {
    var logToSQLite: Bool = false
    var logFilePath: String? = nil
    var net: Bool = false
    var mitm: Bool = false
    var mitmCAPaths: TrustCA.CAPaths? = nil
}

struct TraceRoots {
    var names: [String] = []
    var pids: [pid_t] = []
    var paths: [String] = []
}

enum TraceSessionError: LocalizedError {
    case endpointSecurityUnavailable
    case mitmRequiresCAPaths
    case alreadyStarted
    case notStarted

    var errorDescription: String? {
        switch self {
        case .endpointSecurityUnavailable:
            return "Endpoint Security extension is not active."
        case .mitmRequiresCAPaths:
            return "MITM requires CA paths."
        case .alreadyStarted:
            return "TraceSession already started."
        case .notStarted:
            return "TraceSession is not started."
        }
    }
}

// MARK: - Session

/// Owns the ES/Flow XPC clients, optional SQLite logger, and the ProcessTree.
/// The caller provides a `primarySink` (TUI, JSON, or a GUI-backed sink) and
/// can subscribe to forwarded callbacks for additional bookkeeping.
final class TraceSession {
    // Public state
    let tree: ProcessTree
    private(set) var sqliteLog: SQLiteLog?

    /// Gate SQLite writes at runtime without restarting the session.
    /// Used by the GUI's Record toggle.
    func setSQLiteRecordingEnabled(_ enabled: Bool) {
        sqliteLog?.isEnabled = enabled
    }

    /// Reset the SQLiteLog's recorded-event counter (used when the GUI
    /// starts a fresh recording session).
    func resetSQLiteRecordedCount() {
        sqliteLog?.resetRecordedCount()
    }

    /// Total number of events written to the SQLite trace DB since the
    /// last reset. Shown in the GUI footer while recording.
    var sqliteRecordedCount: Int { sqliteLog?.recordedCount ?? 0 }
    private(set) var isRunning = false
    private var initialOrdered: [pid_t] = []

    // Forwarded callbacks. Set before start().
    var onExec: ((pid_t, pid_t, String, String, uid_t) -> Void)?
    var onFileOp: ((String, pid_t, pid_t, String, uid_t, [String: String]) -> Void)?
    var onExit: ((pid_t, pid_t, String, uid_t, Int32) -> Void)?
    var onTrackedPidsChanged: ((Set<pid_t>) -> Void)?
    var onBytesUpdate: ((pid_t, String, UInt16, Int64, Int64, UInt64) -> Void)?
    var onConnectionClosed: ((pid_t, String, UInt16, UInt64) -> Void)?
    var onTraffic: ((pid_t, String, UInt16, String, Data, UInt64) -> Void)?
    var onConnectionError: ((Error) -> Void)?
    var onMessage: ((String) -> Void)?

    // Internals
    private let primarySink: EventSink
    private var sink: EventSink
    private var esClient: ESXPCClient?
    private var flowClient: FlowXPCClient?

    init(primarySink: EventSink, tree: ProcessTree = ProcessTree()) {
        self.primarySink = primarySink
        self.sink = primarySink
        self.tree = tree
    }

    /// Starts ES (always) and NE/MITM if requested. Resolves initial roots and
    /// seeds the ProcessTree + sysext tracker patterns.
    func start(roots: TraceRoots, options: TraceOptions) throws {
        guard !isRunning else { throw TraceSessionError.alreadyStarted }
        guard ESXPCClient.isAvailable() else { throw TraceSessionError.endpointSecurityUnavailable }
        if options.mitm && options.mitmCAPaths == nil {
            throw TraceSessionError.mitmRequiresCAPaths
        }

        // Compose sink with SQLite if requested.
        if options.logToSQLite || options.logFilePath != nil {
            let dbPath = try options.logFilePath ?? TractorPaths.sharedLogPath()
            let log = try SQLiteLog(path: dbPath)
            self.sqliteLog = log
            self.sink = MultiSink([primarySink, log])
            onMessage?("Tractor: logging to \(log.path)")
        }

        // Resolve initial roots and seed the tree in BFS order (parents before
        // children) so consumers see correct parentage when `seedSinkFromTree`
        // fires synthetic onExec events.
        var initialRoots: [pid_t] = []
        for n in roots.names {
            initialRoots.append(contentsOf: findProcessesByName(n))
        }
        initialRoots.append(contentsOf: roots.pids)
        for p in roots.paths {
            initialRoots.append(contentsOf: findProcessesByExactPath(p))
        }
        if !initialRoots.isEmpty {
            initialOrdered = bfsExpand(roots: initialRoots, excluding: [])
            tree.addRoots(initialOrdered)
        }

        // Set up ES client.
        let esClient = ESXPCClient()
        self.esClient = esClient

        esClient.onConnectionError = { [weak self] error in
            self?.onConnectionError?(error)
        }
        // Consumer callback fires BEFORE the sink — preserves original ordering
        // where e.g. TUI tracker-group bookkeeping completes before render.
        esClient.onExec = { [weak self] pid, ppid, process, argv, user in
            guard let self = self else { return }
            self.tree.trackIfChild(pid: pid, ppid: ppid)
            self.tree.addRoots([pid])
            self.onExec?(pid, ppid, process, argv, user)
            self.sink.onExec(pid: pid, ppid: ppid, process: process, argv: argv, user: user)
        }
        esClient.onFileOp = { [weak self] type, pid, ppid, process, user, details in
            guard let self = self else { return }
            self.onFileOp?(type, pid, ppid, process, user, details)
            self.sink.onFileOp(type: type, pid: pid, ppid: ppid, process: process, user: user, details: details)
        }
        esClient.onExit = { [weak self] pid, ppid, process, user, exitStatus in
            guard let self = self else { return }
            self.onExit?(pid, ppid, process, user, exitStatus)
            self.sink.onExit(pid: pid, ppid: ppid, process: process, user: user, exitStatus: exitStatus)
            self.tree.remove(pid)
        }

        esClient.start()
        esClient.setTrackerPatterns(names: roots.names, paths: roots.paths)
        esClient.addTrackedPids(tree.snapshot)

        // Optional network/MITM.
        if options.net || options.mitm {
            try startFlowClient(options: options, esClient: esClient)
        }

        isRunning = true
    }

    func stop() {
        guard isRunning else { return }
        esClient?.stop()
        esClient = nil
        flowClient?.stop()
        flowClient = nil
        sqliteLog?.close()
        sqliteLog = nil
        isRunning = false
    }

    /// Try to (re)start the network FlowXPCClient against the running session.
    /// Used when the user activates the NE *after* the trace session is up:
    /// the original `startFlowClient` call already returned no-op'd because
    /// the sysext wasn't yet available, so without this they'd have to
    /// relaunch the whole app. Idempotent.
    @discardableResult
    func tryStartFlowClient() -> Bool {
        guard isRunning, flowClient == nil, let esClient = esClient else { return false }
        guard FlowXPCClient.isAvailable() else { return false }
        do {
            try startFlowClient(options: TraceOptions(net: true), esClient: esClient)
            return flowClient != nil
        } catch {
            onMessage?("Tractor: failed to start network capture (\(error.localizedDescription))")
            return false
        }
    }

    // MARK: - Live mutation

    func setTrackerPatterns(names: [String], paths: [String]) {
        esClient?.setTrackerPatterns(names: names, paths: paths)
    }

    func addTrackedPids(_ pids: Set<pid_t>) {
        esClient?.addTrackedPids(pids)
    }

    func addTrackedPidsSync(_ pids: [pid_t], timeout: TimeInterval = 2.0) {
        esClient?.addTrackedPidsSync(pids, timeout: timeout)
    }

    func registerExecRoot(pid: pid_t) {
        tree.addRoots([pid])
        esClient?.addTrackedPidsSync([pid])
    }

    /// Attach to an already-running process tree: discover existing descendants
    /// in BFS order (parents before children), register them with ES, then fire
    /// synthetic onExec events. Use for live-add of a running target.
    func attachExisting(roots: [pid_t]) {
        let ordered = bfsExpand(roots: roots, excluding: tree.snapshot)
        guard !ordered.isEmpty else { return }
        tree.addRoots(ordered)
        esClient?.addTrackedPidsSync(ordered)
        let myUID = uid_t(getuid())
        for pid in ordered {
            let (execPath, ppid, argv) = getProcessInfo(pid)
            onExec?(pid, ppid, execPath, argv, myUID)
            sink.onExec(pid: pid, ppid: ppid, process: execPath, argv: argv, user: myUID)
        }
    }

    /// BFS-expand a set of root PIDs to all currently-running descendants,
    /// preserving parent-before-child ordering. Excludes PIDs already known.
    private func bfsExpand(roots: [pid_t], excluding: Set<pid_t>) -> [pid_t] {
        let initial = roots.filter { !excluding.contains($0) }
        guard !initial.isEmpty else { return [] }

        var pidsBuf = [pid_t](repeating: 0, count: 8192)
        let count = proc_listallpids(&pidsBuf, Int32(MemoryLayout<pid_t>.size * pidsBuf.count))
        var parentToChildren: [pid_t: [pid_t]] = [:]
        if count > 0 {
            for i in 0..<Int(count) {
                let pid = pidsBuf[i]
                if pid <= 0 { continue }
                var info = proc_bsdinfo()
                let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info,
                                        Int32(MemoryLayout<proc_bsdinfo>.size))
                if size > 0 {
                    parentToChildren[pid_t(info.pbi_ppid), default: []].append(pid)
                }
            }
        }

        var ordered: [pid_t] = []
        var visited = excluding
        var queue = initial
        while !queue.isEmpty {
            let current = queue.removeFirst()
            if visited.contains(current) { continue }
            visited.insert(current)
            ordered.append(current)
            if let kids = parentToChildren[current] {
                for k in kids where !visited.contains(k) { queue.append(k) }
            }
        }
        return ordered
    }

    func attachExisting(paths: [String]) {
        var roots: [pid_t] = []
        for p in paths where !p.isEmpty {
            roots.append(contentsOf: findProcessesByExactPath(p))
        }
        if !roots.isEmpty { attachExisting(roots: roots) }
    }

    /// Fire `sink.onExec` for every PID seeded by start(), in BFS order so
    /// parents precede their descendants. Idempotent — clears the queue after.
    func seedSinkFromTree() {
        let myUID = uid_t(getuid())
        for pid in initialOrdered {
            let (execPath, ppid, argv) = getProcessInfo(pid)
            onExec?(pid, ppid, execPath, argv, myUID)
            sink.onExec(pid: pid, ppid: ppid, process: execPath, argv: argv, user: myUID)
        }
        initialOrdered.removeAll()
    }

    // MARK: - Flow client setup

    private func startFlowClient(options: TraceOptions, esClient: ESXPCClient) throws {
        guard FlowXPCClient.isAvailable() else {
            let suffix = options.mitm
                ? "Tractor: network extension is not active; continuing without network capture or MITM."
                : "Tractor: network extension is not active; continuing without network capture."
            onMessage?(suffix)
            return
        }

        let flowClient = FlowXPCClient(sink: sink)
        self.flowClient = flowClient

        if options.mitm {
            guard let caPaths = options.mitmCAPaths else {
                throw TraceSessionError.mitmRequiresCAPaths
            }
            let certPEM = try String(contentsOfFile: caPaths.certPath, encoding: .utf8)
            let keyPEM = try String(contentsOfFile: caPaths.keyPath, encoding: .utf8)
            flowClient.setupMITM(caCertPEM: certPEM, caKeyPEM: keyPEM)
        }

        flowClient.onConnectionError = { [weak self] error in
            self?.onMessage?("Tractor: network extension unavailable, continuing without network capture (\(error.localizedDescription)).")
            self?.flowClient?.stop()
            self?.flowClient = nil
            self?.esClient?.onTrackedPidsChanged = nil
        }

        flowClient.start()
        flowClient.updateWatchList(tree.snapshot)

        esClient.onTrackedPidsChanged = { [weak self] pids in
            self?.flowClient?.updateWatchList(pids)
            self?.onTrackedPidsChanged?(pids)
        }

        flowClient.onBytesUpdate = { [weak self] pid, host, port, bytesOut, bytesIn, flowID in
            self?.onBytesUpdate?(pid, host, port, bytesOut, bytesIn, flowID)
        }
        flowClient.onConnectionClosed = { [weak self] pid, host, port, flowID in
            self?.onConnectionClosed?(pid, host, port, flowID)
        }
        flowClient.onTraffic = { [weak self] pid, host, port, direction, data, flowID in
            guard let self = self else { return }
            self.onTraffic?(pid, host, port, direction, data, flowID)
            let logContent = String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1) ?? "<binary>"
            self.sqliteLog?.logTraffic(pid: pid, host: host, port: port,
                                        direction: direction, content: logContent)
        }

        if options.mitm {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak flowClient] in
                flowClient?.setMITMEnabled(true)
            }
        }
    }
}
