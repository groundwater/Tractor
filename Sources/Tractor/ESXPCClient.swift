import Foundation

// endpointsecurityd auto-registers <team-id>.<bundle-id>.xpc on activation.
private let esXPCServiceName = "3FGZQE8AW3.com.jacobgroundwater.Tractor.ES.xpc"

/// XPC protocol matching the TractorES sysext's exported interface.
@objc protocol TractorESXPC {
    func addTrackedPids(_ pids: [Int32])
    func addTrackedPidsSync(_ pids: [Int32], reply: @escaping () -> Void)
    func setTrackerPatterns(names: [String], paths: [String])
    func pollEvents(reply: @escaping (Data) -> Void)
    func pollTrackedPids(reply: @escaping ([Int32]) -> Void)
    func loadProgram(name: String, source: String, args: [String], reply: @escaping (String?) -> Void)
    func unloadProgramByName(_ name: String, reply: @escaping () -> Void)
    func listPrograms(reply: @escaping (Data) -> Void)
    func pollEmits(reply: @escaping (Data) -> Void)
    func pollPanels(reply: @escaping (Data) -> Void)
    func setTerminalSize(cols: Int, rows: Int)
    func evaluateFlow(_ context: Data, reply: @escaping (Bool) -> Void)
    func notifyFlowClose(_ context: Data)
    func notifyFlowBytes(_ context: Data)
}

/// Decoded program metadata for the GUI Scripts tab.
struct LoadedProgramInfo {
    let name: String
    let source: String
    let probes: [String]
    let loadedAt: Date
}

/// One JS `emit(channel, obj)` record from the sysext, decoded for display.
struct EmitRecord: Identifiable {
    let id: UUID = UUID()
    let time: Date
    let program: String       // host-tagged via _program
    let channel: String
    /// Compact JSON of the payload keys other than channel/kind/ts/_program.
    let payloadJSON: String
}

extension EmitRecord {
    /// Decodes one emits-ring entry (the dictionary shape produced by
    /// ESReporter.reportEmit).
    init(ringEntry entry: [String: Any]) {
        let ts = entry["ts"] as? Double ?? Date().timeIntervalSince1970
        var payload = entry
        for k in ["kind", "channel", "ts", "_program"] { payload.removeValue(forKey: k) }
        // sortedKeys keeps the column stable across records; without it the
        // dictionary order jitters row to row.
        let json: String
        if let d = try? JSONSerialization.data(withJSONObject: payload,
                                               options: [.sortedKeys, .withoutEscapingSlashes]),
           let s = String(data: d, encoding: .utf8) {
            json = s
        } else {
            json = "{}"
        }
        self.init(time: Date(timeIntervalSince1970: ts),
                  program: entry["_program"] as? String ?? "?",
                  channel: entry["channel"] as? String ?? "?",
                  payloadJSON: json)
    }
}

/// One `render(panel, text)` update. CLI repaints by (program, panel) key.
struct PanelUpdate {
    let program: String
    let panel: String
    let text: String
    let time: Date
}

/// Connects to the TractorES sysext, seeds it with tracked PIDs and patterns,
/// and polls for ES events (exec/fileop/exit). The host wires `onExec` etc.
/// to drive the sink (TUI / JSON / SQLite).
final class ESXPCClient {
    private var connection: NSXPCConnection?
    private var proxy: TractorESXPC?
    private var eventTimer: DispatchSourceTimer?
    private var pidsTimer: DispatchSourceTimer?
    private var panelsTimer: DispatchSourceTimer?
    private var emitsTimer: DispatchSourceTimer?

    /// Most recently observed tracked-PID set on the sysext side. Used by the
    /// CLI to mirror into the NE sysext's watch list when `--net` is on.
    private(set) var trackedPids: Set<pid_t> = []

    var onExec: ((pid_t, pid_t, String, String, uid_t) -> Void)?
    var onFileOp: ((String, pid_t, pid_t, String, uid_t, [String: String]) -> Void)?
    var onExit: ((pid_t, pid_t, String, uid_t, Int32) -> Void)?
    /// Fired when the loaded JS program calls `emit(channel, obj)`. The
    /// payload preserves the keys the program supplied. NOTE: this comes
    /// from the legacy event-buffer ring (drained on read). For UI
    /// consumers that want lossless per-emit delivery alongside other
    /// readers, prefer `onEmitRecord`.
    var onEmit: ((String, [String: Any]) -> Void)?
    /// Fired for every emit from the cursor-based emits ring (no drain
    /// races with other consumers). Set this on long-lived clients that
    /// share the daemon with other GUIs / CLIs.
    var onEmitRecord: ((EmitRecord) -> Void)?
    /// Fired when a JS program calls `render(panel, text)`. Each invocation
    /// is the latest *state* of a named panel, not a stream event.
    var onPanel: ((PanelUpdate) -> Void)?
    /// Called whenever the tracked-PID set changes on the sysext side.
    var onTrackedPidsChanged: ((Set<pid_t>) -> Void)?
    var onConnectionError: ((Error) -> Void)?

    static func isAvailable(timeout: TimeInterval = 1.0) -> Bool {
        let sem = DispatchSemaphore(value: 0)
        var available = false

        let conn = NSXPCConnection(machServiceName: esXPCServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: TractorESXPC.self)
        conn.resume()

        let proxy = conn.remoteObjectProxyWithErrorHandler { _ in
            sem.signal()
        } as? TractorESXPC
        proxy?.pollTrackedPids { _ in
            available = true
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + timeout)
        conn.invalidate()
        return available
    }

    func start() {
        let conn = NSXPCConnection(machServiceName: esXPCServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: TractorESXPC.self)
        conn.invalidationHandler = { [weak self] in
            let err = NSError(
                domain: NSCocoaErrorDomain,
                code: NSXPCConnectionInvalid,
                userInfo: [NSLocalizedDescriptionKey: "Endpoint Security extension connection was invalidated."]
            )
            self?.onConnectionError?(err)
        }
        conn.resume()
        connection = conn
        proxy = conn.remoteObjectProxyWithErrorHandler { [weak self] error in
            self?.onConnectionError?(error)
        } as? TractorESXPC

        let events = DispatchSource.makeTimerSource(queue: .main)
        events.schedule(deadline: .now() + 0.05, repeating: .milliseconds(100))
        events.setEventHandler { [weak self] in self?.pollEvents() }
        eventTimer = events
        events.resume()

        let pids = DispatchSource.makeTimerSource(queue: .main)
        pids.schedule(deadline: .now() + 0.5, repeating: .milliseconds(500))
        pids.setEventHandler { [weak self] in self?.pollTrackedPids() }
        pidsTimer = pids
        pids.resume()

        // Panels poll runs faster (100ms) so terminal repaints feel snappy.
        let panels = DispatchSource.makeTimerSource(queue: .main)
        panels.schedule(deadline: .now() + 0.2, repeating: .milliseconds(100))
        panels.setEventHandler { [weak self] in self?.pollPanels() }
        panelsTimer = panels
        panels.resume()

        // Cursor-based emits ring poll. This connection has its own
        // server-side cursor, so we receive each emit exactly once and
        // never race with other GUI/CLI consumers (unlike the legacy
        // pollEvents path which drains a shared buffer).
        let emits = DispatchSource.makeTimerSource(queue: .main)
        emits.schedule(deadline: .now() + 0.2, repeating: .milliseconds(200))
        emits.setEventHandler { [weak self] in self?.pollEmitsCursor() }
        emitsTimer = emits
        emits.resume()
    }

    func stop() {
        drainEventsSync()
        cancelTimers()
        connection?.invalidate()
        connection = nil
        proxy = nil
    }

    /// Async variant of `stop()` for UI callers: the final drain blocks for up
    /// to a second waiting on the sysext, so it runs off the main thread.
    /// Event handlers for drained events still fire on main before `completion`.
    func stopAsync(completion: (() -> Void)? = nil) {
        cancelTimers()
        let conn = connection
        connection = nil
        proxy = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let payload = Self.drainEvents(over: conn, timeout: 1.0)
            DispatchQueue.main.async {
                if !payload.isEmpty { self?.handleEvents(payload) }
                conn?.invalidate()
                completion?()
            }
        }
    }

    private func cancelTimers() {
        eventTimer?.cancel(); eventTimer = nil
        pidsTimer?.cancel(); pidsTimer = nil
        panelsTimer?.cancel(); panelsTimer = nil
        emitsTimer?.cancel(); emitsTimer = nil
    }

    func addTrackedPids(_ pids: Set<pid_t>) {
        proxy?.addTrackedPids(Array(pids))
    }

    /// Synchronous variant — blocks until the sysext acknowledges. Used by
    /// `--exec` to guarantee the child PID is in the tracked set before the
    /// child calls execve(), so the sysext's AUTH_EXEC handler sees it.
    func addTrackedPidsSync(_ pids: [pid_t], timeout: TimeInterval = 2.0) {
        let sem = DispatchSemaphore(value: 0)
        let syncProxy = connection?.synchronousRemoteObjectProxyWithErrorHandler { _ in
            sem.signal()
        } as? TractorESXPC
        guard let syncProxy = syncProxy else { return }
        syncProxy.addTrackedPidsSync(pids) { sem.signal() }
        _ = sem.wait(timeout: .now() + timeout)
    }

    /// Drain any queued ES events before teardown. This closes the race where
    /// very short `tractor exec` children can exit before the first timer poll.
    /// Blocks the calling thread for up to `timeout`.
    func drainEventsSync(timeout: TimeInterval = 1.0) {
        let payload = Self.drainEvents(over: connection, timeout: timeout)
        if !payload.isEmpty {
            handleEvents(payload)
        }
    }

    private static func drainEvents(over connection: NSXPCConnection?, timeout: TimeInterval) -> Data {
        let sem = DispatchSemaphore(value: 0)
        var payload = Data()
        let syncProxy = connection?.synchronousRemoteObjectProxyWithErrorHandler { _ in
            sem.signal()
        } as? TractorESXPC
        guard let syncProxy = syncProxy else { return payload }
        syncProxy.pollEvents { data in
            payload = data
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + timeout)
        return payload
    }

    func setTrackerPatterns(names: [String], paths: [String]) {
        proxy?.setTrackerPatterns(names: names, paths: paths)
    }

    func setTerminalSize(cols: Int, rows: Int) {
        proxy?.setTerminalSize(cols: cols, rows: rows)
    }

    /// One-shot fetch of all currently-loaded programs. Used by the GUI
    /// Scripts tab; no persistent connection required.
    static func fetchPrograms(timeout: TimeInterval = 1.0) -> [LoadedProgramInfo] {
        let sem = DispatchSemaphore(value: 0)
        var result: [LoadedProgramInfo] = []

        let conn = NSXPCConnection(machServiceName: esXPCServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: TractorESXPC.self)
        conn.resume()
        let proxy = conn.remoteObjectProxyWithErrorHandler { _ in
            sem.signal()
        } as? TractorESXPC
        proxy?.listPrograms { data in
            defer { sem.signal() }
            guard !data.isEmpty,
                  let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
            else { return }
            for obj in arr {
                guard let name = obj["name"] as? String,
                      let source = obj["source"] as? String,
                      let probes = obj["probes"] as? [String],
                      let ts = obj["loadedAt"] as? Double else { continue }
                result.append(LoadedProgramInfo(name: name, source: source,
                                                probes: probes,
                                                loadedAt: Date(timeIntervalSince1970: ts)))
            }
        }
        _ = sem.wait(timeout: .now() + timeout)
        conn.invalidate()
        return result
    }

    /// Forward an NE-originated flow evaluation to the ES sysext. The CLI
    /// acts as relay because NE can't reach the ES mach service from inside
    /// its sandbox. Async; reply propagates the deny verdict back to NE.
    func evaluateFlow(_ context: Data, reply: @escaping (Bool) -> Void) {
        guard let proxy = proxy else { reply(false); return }
        proxy.evaluateFlow(context, reply: reply)
    }

    /// Forward a flow-close notification to ES (fire-and-forget).
    func notifyFlowClose(_ context: Data) {
        proxy?.notifyFlowClose(context)
    }

    /// Forward a periodic flow-bytes update to ES (fire-and-forget).
    func notifyFlowBytes(_ context: Data) {
        proxy?.notifyFlowBytes(context)
    }

    /// Submit a JS probe program to the sysext under `name`. Blocks until
    /// compiled. Returns nil on success, or an error string. Reloading an
    /// existing `name` replaces atomically.
    func loadProgram(name: String, source: String, args: [String] = [],
                     timeout: TimeInterval = 5.0) -> String? {
        let sem = DispatchSemaphore(value: 0)
        var result: String? = "no XPC proxy"
        let syncProxy = connection?.synchronousRemoteObjectProxyWithErrorHandler { err in
            result = "XPC error: \(err.localizedDescription)"
            sem.signal()
        } as? TractorESXPC
        guard let syncProxy = syncProxy else { return result }
        syncProxy.loadProgram(name: name, source: source, args: args) { err in
            result = err
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + timeout)
        return result
    }

    /// Unload by name. Blocks briefly for confirmation.
    func unloadProgram(name: String, timeout: TimeInterval = 2.0) {
        let sem = DispatchSemaphore(value: 0)
        let syncProxy = connection?.synchronousRemoteObjectProxyWithErrorHandler { _ in
            sem.signal()
        } as? TractorESXPC
        syncProxy?.unloadProgramByName(name) { sem.signal() }
        _ = sem.wait(timeout: .now() + timeout)
    }

    // MARK: - Private

    private func pollEvents() {
        proxy?.pollEvents { [weak self] data in
            DispatchQueue.main.async { self?.handleEvents(data) }
        }
    }

    private func pollEmitsCursor() {
        proxy?.pollEmits { [weak self] data in
            DispatchQueue.main.async { self?.handleEmitsRing(data) }
        }
    }

    private func handleEmitsRing(_ data: Data) {
        guard !data.isEmpty,
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return }
        for entry in arr {
            onEmitRecord?(EmitRecord(ringEntry: entry))
        }
    }

    private func pollTrackedPids() {
        proxy?.pollTrackedPids { [weak self] pids in
            DispatchQueue.main.async { self?.handleTrackedPids(pids) }
        }
    }

    private func pollPanels() {
        proxy?.pollPanels { [weak self] data in
            DispatchQueue.main.async { self?.handlePanels(data) }
        }
    }

    private func handlePanels(_ data: Data) {
        guard !data.isEmpty,
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]],
              !arr.isEmpty else { return }
        // Dedup per (program, panel) — only the latest update matters.
        var latest: [String: PanelUpdate] = [:]
        for entry in arr {
            guard let program = entry["_program"] as? String,
                  let panel = entry["panel"] as? String,
                  let text = entry["text"] as? String else { continue }
            let ts = entry["ts"] as? Double ?? Date().timeIntervalSince1970
            latest["\(program)\u{0}\(panel)"] =
                PanelUpdate(program: program, panel: panel, text: text,
                            time: Date(timeIntervalSince1970: ts))
        }
        for (_, upd) in latest { onPanel?(upd) }
    }

    private func handleTrackedPids(_ pids: [Int32]) {
        let set = Set(pids)
        if set != trackedPids {
            trackedPids = set
            onTrackedPidsChanged?(set)
        }
    }

    private func handleEvents(_ data: Data) {
        guard let events = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return }
        for event in events {
            let pid = (event["pid"] as? Int).map { Int32($0) } ?? -1
            let ppid = (event["ppid"] as? Int).map { Int32($0) } ?? 0
            let process = event["process"] as? String ?? ""
            let user = (event["user"] as? Int).map { uid_t($0) } ?? 0

            switch event["kind"] as? String {
            case "exec":
                let argv = event["argv"] as? String ?? ""
                onExec?(pid, ppid, process, argv, user)
            case "fileop":
                let type = event["fileop"] as? String ?? ""
                var details: [String: String] = [:]
                for k in ["path", "from", "to"] {
                    if let v = event[k] as? String { details[k] = v }
                }
                onFileOp?(type, pid, ppid, process, user, details)
            case "exit":
                let exitStatus = (event["exitStatus"] as? Int).map { Int32($0) } ?? 0
                onExit?(pid, ppid, process, user, exitStatus)
            case "emit":
                let channel = event["channel"] as? String ?? ""
                var payload = event
                payload.removeValue(forKey: "kind")
                payload.removeValue(forKey: "channel")
                onEmit?(channel, payload)
            default:
                continue
            }
        }
    }
}
