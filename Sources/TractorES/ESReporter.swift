import Foundation
import os.log

private let xpcLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.ES", category: "xpc")
// `endpointsecurityd` auto-registers each ES sysext's mach service with
// launchd as `<team-id>.<bundle-id>.xpc`. The team ID prefix is added by
// the system at sysext activation time — we have to match that exact name.
private let xpcServiceName = "3FGZQE8AW3.com.jacobgroundwater.Tractor.ES.xpc"

/// XPC protocol: CLI calls these methods on the ES sysext.
@objc protocol TractorESXPC {
    func addTrackedPids(_ pids: [Int32])
    /// Synchronous variant — used by `--exec` so we don't release the spawned
    /// child until the sysext has the pid in its tracked set.
    func addTrackedPidsSync(_ pids: [Int32], reply: @escaping () -> Void)
    func setTrackerPatterns(names: [String], paths: [String])
    func pollEvents(reply: @escaping (Data) -> Void)
    /// CLI subscribes to PID-set changes so it can mirror them into the NE
    /// sysext's watch list (only used when `--net` is on).
    func pollTrackedPids(reply: @escaping ([Int32]) -> Void)
    /// Load (or replace) a JS probe program by `name`. Reply returns nil
    /// on success or an error message. Up to 10 programs may be loaded
    /// simultaneously; reloading an existing name replaces it atomically.
    /// `args` is exposed to the program as the `args` JS global (string array).
    func loadProgram(name: String, source: String, args: [String], reply: @escaping (String?) -> Void)
    /// Unload a program by name. No-op if not loaded.
    func unloadProgramByName(_ name: String, reply: @escaping () -> Void)
    /// Returns metadata about all loaded programs as a JSON array:
    ///   [{"name": "...", "source": "...", "probes": [...], "loadedAt": ...}]
    func listPrograms(reply: @escaping (Data) -> Void)

    /// Drains the GUI emits ring and returns the records as a JSON array.
    /// Independent buffer from pollEvents; safe to call concurrently with
    /// the CLI's polling loop.
    func pollEmits(reply: @escaping (Data) -> Void)

    /// Drains the panel-updates ring. CLI deduplicates by (program, panel)
    /// keeping only the latest text before repainting the terminal.
    func pollPanels(reply: @escaping (Data) -> Void)

    /// CLI reports its current terminal size so JS programs can adapt
    /// rendered output. Sent on connect and on SIGWINCH. Last writer wins.
    func setTerminalSize(cols: Int, rows: Int)

    /// Network flow evaluation entry point. Called *synchronously* by the
    /// TractorNE sysext when a new TCP flow is about to be handled, so the
    /// JS engine can evaluate `ne:flow:new` probes and return an allow/deny
    /// verdict. `context` is a JSON-encoded `{pid,process,host,port,direction}`
    /// dictionary; the reply is true if the JS program denied the flow.
    func evaluateFlow(_ context: Data, reply: @escaping (Bool) -> Void)
    /// Fire-and-forget close notification. JS-engine fires `ne:flow:close`
    /// with byte totals. `context` is JSON `{pid,host,port,bytesOut,bytesIn,flowID}`.
    func notifyFlowClose(_ context: Data)
    /// Fire-and-forget periodic byte update. JS-engine fires `ne:flow:bytes`.
    func notifyFlowBytes(_ context: Data)
}

/// Hosts the XPC listener for the TractorES sysext and buffers ES events.
/// Owns the lifetime of the underlying ESDaemon.
final class ESReporter: NSObject, NSXPCListenerDelegate, TractorESXPC {
    private var listener: NSXPCListener?
    private let bufferLock = NSLock()
    private var eventRing: [(id: UInt64, entry: [String: Any])] = []
    private var eventNextID: UInt64 = 1
    private var eventCursors: [ObjectIdentifier: UInt64] = [:]
    private let eventRingMax = 5000

    /// Capped append-only ring of `emit(channel, obj)` records. Each
    /// record has a monotonic id. Readers track their own cursor so
    /// multiple clients (multiple `tractor program` sessions + the GUI)
    /// can independently consume the same stream without one stealing
    /// records the other never saw.
    private let emitsLock = NSLock()
    private var emitsRing: [(id: UInt64, entry: [String: Any])] = []
    private var emitsNextID: UInt64 = 1
    private var emitsCursors: [ObjectIdentifier: UInt64] = [:]
    private let emitsRingMax = 1000

    /// Panel updates from `render(panel, text)`. Same cursor model as
    /// emits — each client gets the records since its last poll.
    private let panelsLock = NSLock()
    private var panelsRing: [(id: UInt64, entry: [String: Any])] = []
    private var panelsNextID: UInt64 = 1
    private var panelsCursors: [ObjectIdentifier: UInt64] = [:]
    private let panelsRingMax = 500

    private var esDaemon: ESDaemon?
    private let pidLock = NSLock()
    /// Snapshot of tracked PIDs published to the CLI on demand.
    private var publishedPids: Set<Int32> = []

    /// Reference-counted active XPC connections. The daemon (and JS engine)
    /// stays alive as long as ANY client is connected — the GUI polls
    /// programInfo() with short-lived connections that must not tear down
    /// the daemon out from under a long-lived `tractor program` session.
    private let clientLock = NSLock()
    private var clientCount = 0

    // Program-loader tracking is now per-program inside JSEngine.
    // Connection invalidation calls JSEngine.unloadPrograms(loadedBy:)
    // which drops any programs that connection had loaded.

    func connect() {
        os_log("connecting XPC listener on %{public}@", log: xpcLog, type: .default, xpcServiceName)
        let l = NSXPCListener(machServiceName: xpcServiceName)
        l.delegate = self
        l.resume()
        listener = l
        os_log("XPC listener started", log: xpcLog, type: .default)
    }

    func disconnect() {
        listener?.invalidate()
        listener = nil
        esDaemon?.stop()
        esDaemon = nil
        clientLock.lock(); clientCount = 0; clientLock.unlock()
    }

    // MARK: - NSXPCListenerDelegate

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: TractorESXPC.self)
        connection.exportedObject = self
        let connectionID = ObjectIdentifier(connection)
        // Seed every cursor to "now" so a new (or reconnecting) client only
        // sees records produced after it connected, not the ring backlog.
        bufferLock.lock()
        eventCursors[connectionID] = eventNextID - 1
        bufferLock.unlock()
        emitsLock.lock()
        emitsCursors[connectionID] = emitsNextID - 1
        emitsLock.unlock()
        panelsLock.lock()
        panelsCursors[connectionID] = panelsNextID - 1
        panelsLock.unlock()
        connection.invalidationHandler = { [weak self] in
            guard let self = self else { return }
            self.clientLock.lock()
            self.clientCount -= 1
            let remaining = self.clientCount
            self.clientLock.unlock()

            // Drop any programs this connection loaded. Other programs
            // (loaded by other clients) keep running.
            self.esDaemon?.unloadPrograms(loadedBy: connectionID)

            // Drop this client's cursors so we don't leak memory on
            // long-running daemons with many short-lived connections.
            self.emitsLock.lock(); self.emitsCursors.removeValue(forKey: connectionID); self.emitsLock.unlock()
            self.panelsLock.lock(); self.panelsCursors.removeValue(forKey: connectionID); self.panelsLock.unlock()
            self.bufferLock.lock(); self.eventCursors.removeValue(forKey: connectionID); self.bufferLock.unlock()

            os_log("client disconnected (remaining: %{public}d)", log: xpcLog, type: .default, remaining)
            if remaining <= 0 {
                // Keep the daemon alive across "no clients" windows so
                // rapid connect/disconnect (isAvailable() + start() back
                // to back, GUI polling, etc.) doesn't race with daemon
                // recreate. Just clear ephemeral buffers.
                os_log("no clients left — daemon stays running, buffers cleared",
                       log: xpcLog, type: .default)
                self.bufferLock.lock()
                self.eventRing.removeAll()
                self.eventCursors.removeAll()
                self.bufferLock.unlock()
                self.pidLock.lock(); self.publishedPids.removeAll(); self.pidLock.unlock()
            }
        }
        connection.resume()
        clientLock.lock()
        clientCount += 1
        let total = clientCount
        clientLock.unlock()
        if esDaemon == nil {
            let daemon = ESDaemon(reporter: self)
            esDaemon = daemon
            daemon.start()
        }
        os_log("client connected (total: %{public}d)", log: xpcLog, type: .default, total)
        return true
    }

    // MARK: - TractorESXPC

    func addTrackedPids(_ pids: [Int32]) {
        esDaemon?.addTrackedPids(pids)
    }

    func addTrackedPidsSync(_ pids: [Int32], reply: @escaping () -> Void) {
        esDaemon?.addTrackedPids(pids)
        reply()
    }

    func setTrackerPatterns(names: [String], paths: [String]) {
        esDaemon?.setTrackerPatterns(names: names, paths: paths)
    }

    func pollEvents(reply: @escaping (Data) -> Void) {
        let connID = NSXPCConnection.current().map { ObjectIdentifier($0) }
        bufferLock.lock()
        let cursor = connID.flatMap { eventCursors[$0] } ?? 0
        var events: [[String: Any]] = []
        var maxID = cursor
        for (id, entry) in eventRing where id > cursor {
            events.append(entry)
            if id > maxID { maxID = id }
        }
        if let connID = connID { eventCursors[connID] = maxID }
        bufferLock.unlock()
        guard !events.isEmpty else { reply(Data("[]".utf8)); return }
        if let data = try? JSONSerialization.data(withJSONObject: events) {
            reply(data)
        } else {
            let valid = events.filter { JSONSerialization.isValidJSONObject($0) }
            reply((try? JSONSerialization.data(withJSONObject: valid)) ?? Data("[]".utf8))
        }
    }

    func pollTrackedPids(reply: @escaping ([Int32]) -> Void) {
        pidLock.lock()
        let pids = Array(publishedPids)
        pidLock.unlock()
        reply(pids)
    }

    func evaluateFlow(_ context: Data, reply: @escaping (Bool) -> Void) {
        guard let daemon = esDaemon,
              let dict = try? JSONSerialization.jsonObject(with: context) as? [String: Any]
        else { reply(false); return }
        let denied = daemon.handleNetworkFlow(context: dict)
        reply(denied)
    }

    func notifyFlowClose(_ context: Data) {
        guard let daemon = esDaemon,
              let dict = try? JSONSerialization.jsonObject(with: context) as? [String: Any]
        else { return }
        daemon.handleNetworkFlowClose(context: dict)
    }

    func notifyFlowBytes(_ context: Data) {
        guard let daemon = esDaemon,
              let dict = try? JSONSerialization.jsonObject(with: context) as? [String: Any]
        else { return }
        daemon.handleNetworkFlowBytes(context: dict)
    }

    func loadProgram(name: String, source: String, args: [String], reply: @escaping (String?) -> Void) {
        guard let daemon = esDaemon else { reply("ES daemon not running"); return }
        let loader = NSXPCConnection.current().map { ObjectIdentifier($0) }
        reply(daemon.loadProgram(name: name, source: source, args: args, loaderConnectionID: loader))
    }

    func unloadProgramByName(_ name: String, reply: @escaping () -> Void) {
        esDaemon?.unloadProgram(name: name)
        reply()
    }

    func listPrograms(reply: @escaping (Data) -> Void) {
        guard let daemon = esDaemon else { reply(Data("[]".utf8)); return }
        let infos = daemon.listPrograms()
        let arr: [[String: Any]] = infos.map {
            [
                "name": $0.name,
                "source": $0.source,
                "probes": $0.probeNames,
                "loadedAt": $0.loadedAt.timeIntervalSince1970,
            ]
        }
        reply((try? JSONSerialization.data(withJSONObject: arr)) ?? Data("[]".utf8))
    }

    func pollEmits(reply: @escaping (Data) -> Void) {
        let connID = NSXPCConnection.current().map { ObjectIdentifier($0) }
        emitsLock.lock()
        let cursor = connID.flatMap { emitsCursors[$0] } ?? 0
        var out: [[String: Any]] = []
        var maxID = cursor
        for (id, entry) in emitsRing where id > cursor {
            out.append(entry)
            if id > maxID { maxID = id }
        }
        if let connID = connID { emitsCursors[connID] = maxID }
        emitsLock.unlock()
        guard !out.isEmpty else { reply(Data("[]".utf8)); return }
        if let data = try? JSONSerialization.data(withJSONObject: out) {
            reply(data)
        } else {
            reply(Data("[]".utf8))
        }
    }

    func setTerminalSize(cols: Int, rows: Int) {
        esDaemon?.setTerminalSize(cols: cols, rows: rows)
    }

    func pollPanels(reply: @escaping (Data) -> Void) {
        let connID = NSXPCConnection.current().map { ObjectIdentifier($0) }
        panelsLock.lock()
        let cursor = connID.flatMap { panelsCursors[$0] } ?? 0
        var out: [[String: Any]] = []
        var maxID = cursor
        for (id, entry) in panelsRing where id > cursor {
            out.append(entry)
            if id > maxID { maxID = id }
        }
        if let connID = connID { panelsCursors[connID] = maxID }
        panelsLock.unlock()
        guard !out.isEmpty else { reply(Data("[]".utf8)); return }
        if let data = try? JSONSerialization.data(withJSONObject: out) {
            reply(data)
        } else {
            reply(Data("[]".utf8))
        }
    }

    /// Append a panel-update record. Same lifecycle as emit but a distinct
    /// ring + semantic (current state of a named panel, not stream event).
    func reportPanel(panel: String, program: String, text: String) {
        let entry: [String: Any] = [
            "kind": "panel",
            "_program": program,
            "panel": panel,
            "text": text,
            "ts": Date().timeIntervalSince1970,
        ]
        panelsLock.lock()
        let id = panelsNextID
        panelsNextID += 1
        panelsRing.append((id, entry))
        if panelsRing.count > panelsRingMax + panelsRingMax / 4 {
            panelsRing.removeFirst(panelsRing.count - panelsRingMax)
        }
        panelsLock.unlock()
    }


    // MARK: - Called from ESDaemon

    private func appendEvent(_ event: [String: Any]) {
        bufferLock.lock()
        let id = eventNextID
        eventNextID += 1
        eventRing.append((id, event))
        // Trim in batches — removeFirst shifts the whole array, so doing it
        // on every append once at capacity makes the hot path O(n) per event.
        if eventRing.count > eventRingMax + eventRingMax / 4 {
            eventRing.removeFirst(eventRing.count - eventRingMax)
        }
        bufferLock.unlock()
    }

    func didUpdateTrackedPids(_ pids: Set<Int32>) {
        pidLock.lock()
        publishedPids = pids
        pidLock.unlock()
    }

    func reportExec(pid: Int32, ppid: Int32, process: String, argv: String, user: UInt32) {
        let event: [String: Any] = [
            "kind": "exec", "pid": pid, "ppid": ppid,
            "process": process, "argv": argv, "user": user,
        ]
        appendEvent(event)
    }

    func reportFileOp(type: String, pid: Int32, ppid: Int32, process: String, user: UInt32, details: [String: String]) {
        var event: [String: Any] = [
            "kind": "fileop", "fileop": type, "pid": pid, "ppid": ppid,
            "process": process, "user": user,
        ]
        for (k, v) in details { event[k] = v }
        appendEvent(event)
    }

    /// Output channel for JS `emit(channel, obj)` calls. Buffered alongside
    /// other ES events and drained by the CLI via the existing pollEvents
    /// XPC call. Also appended to the GUI emits ring. `program` is the
    /// name of the program that emitted, auto-tagged by the host as
    /// `_program` in the record so the GUI/CLI can filter on it.
    func reportEmit(channel: String, program: String, payload: [String: Any]) {
        var event: [String: Any] = [
            "kind": "emit",
            "channel": channel,
            "_program": program,
        ]
        // Avoid clobbering the meta keys if the program emitted them.
        for (k, v) in payload where k != "kind" && k != "channel" && k != "_program" {
            // Only include JSON-serializable values.
            if JSONSerialization.isValidJSONObject([k: v]) || v is String || v is NSNumber || v is Bool {
                event[k] = v
            }
        }
        appendEvent(event)

        // GUI ring: same record + a server-side timestamp. Capped, drops oldest.
        var ringEntry = event
        ringEntry["ts"] = Date().timeIntervalSince1970
        emitsLock.lock()
        let id = emitsNextID
        emitsNextID += 1
        emitsRing.append((id, ringEntry))
        if emitsRing.count > emitsRingMax + emitsRingMax / 4 {
            emitsRing.removeFirst(emitsRing.count - emitsRingMax)
        }
        emitsLock.unlock()
    }

    func reportExit(pid: Int32, ppid: Int32, process: String, user: UInt32, exitStatus: Int32) {
        let event: [String: Any] = [
            "kind": "exit", "pid": pid, "ppid": ppid,
            "process": process, "user": user, "exitStatus": exitStatus,
        ]
        appendEvent(event)
    }
}
