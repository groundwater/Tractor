import Foundation
import os.log

private let xpcLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "xpc")
private let xpcServiceName = "group.com.jacobgroundwater.Tractor"

/// XPC protocol: CLI calls these methods on the sysext
@objc protocol TractorNEXPC {
    func updateWatchList(_ pids: [Int32])
    func pollEvents(reply: @escaping (Data) -> Void)
    func setMITMEnabled(_ enabled: Bool)
    func getCACertPEM(reply: @escaping (String) -> Void)
    /// When set, NE intercepts every outbound TCP flow regardless of pid
    /// watch list. Used by `tractor program` so the loaded JS sees all
    /// flows via `ne:flow:new` and the user opts in per-flow.
    func setInterceptAll(_ enabled: Bool)
    /// Called by `tractor program` after it sets up its exported
    /// FlowEvalBridge. Tells NE "route evaluateFlow callbacks to me."
    /// Without this, NE would use the generic cliProxy (last-wins across
    /// clients), which may point to a GUI connection that has no
    /// exported evaluator object.
    func claimEvaluator()
    // Flow streaming: CLI sends data back to a flow
    func flowData(id: UInt64, data: Data)
    func closeFlow(id: UInt64)
}

/// Reverse XPC protocol: sysext calls these methods on the CLI
@objc protocol TractorCLIXPC {
    func generateP12(hostname: NSString, reply: @escaping (Data) -> Void)
    // Flow streaming (kept for future use)
    func openFlow(id: UInt64, host: NSString, port: UInt16, pid: Int32)
    func flowData(id: UInt64, data: Data)
    func closeFlow(id: UInt64)
    /// JS flow evaluation. NE can't reach the ES sysext directly (sandbox),
    /// so the CLI relays: NE → CLI → ES → reply. Sync from NE's view.
    func evaluateFlow(_ context: Data, reply: @escaping (Bool) -> Void)
    /// Fire-and-forget end-of-flow notification with byte totals. CLI
    /// relays to ES which fires the `ne:flow:close` probe.
    func notifyFlowClose(_ context: Data)
    /// Fire-and-forget periodic byte update during a flow. CLI relays to
    /// ES → `ne:flow:bytes` probe. Cumulative counters; JS derives deltas.
    func notifyFlowBytes(_ context: Data)
}

/// Hosts an XPC listener in the sysext (system domain).
/// The CLI connects with NSXPCConnection(machServiceName:, options: .privileged).
final class FlowReporter: NSObject, NSXPCListenerDelegate, TractorNEXPC {
    private var listener: NSXPCListener?
    private let pidLock = NSLock()
    private var watchedPids: Set<Int32> = []
    private let bufferLock = NSLock()
    private var eventBuffer: [[String: Any]] = []
    private var hasClient = false
    private(set) var mitmEnabled = false
    /// See setInterceptAll. Read on the NE flow-handling path.
    private(set) var interceptAll = false
    /// Connection claimed by `tractor program` for JS flow evaluation
    /// callbacks. Distinct from cliProxy so multiple CLI clients can be
    /// connected without one stomping the evaluator.
    private var evaluatorProxy: TractorCLIXPC?
    private let evaluatorLock = NSLock()
    private(set) var cliProxy: TractorCLIXPC?

    /// Active flow relays, keyed by flow ID
    private var flowRelays: [UInt64: FlowRelay] = [:]
    private let relayLock = NSLock()

    private var excludedPids: Set<Int32> = []

    func isWatched(_ pid: Int32) -> Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        guard hasClient else { return false }
        if excludedPids.contains(pid) { return false }
        if interceptAll { return true }
        return watchedPids.contains(pid)
    }

    func excludePid(_ pid: Int32) {
        pidLock.lock()
        excludedPids.insert(pid)
        pidLock.unlock()
    }

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
        pidLock.lock()
        watchedPids.removeAll()
        pidLock.unlock()
        hasClient = false
    }

    // MARK: - NSXPCListenerDelegate

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let iface = NSXPCInterface(with: TractorNEXPC.self)
        connection.exportedInterface = iface
        connection.exportedObject = self
        // Bidirectional: also set up reverse interface so we can call the CLI
        connection.remoteObjectInterface = NSXPCInterface(with: TractorCLIXPC.self)
        // We may use this proxy as the evaluator if the client claims it.
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            os_log("CLI reverse proxy error: %{public}@", log: xpcLog, type: .error, error.localizedDescription)
        } as? TractorCLIXPC
        connection.invalidationHandler = { [weak self] in
            guard let self = self else { return }
            os_log("CLI disconnected — clearing watch list", log: xpcLog, type: .default)
            self.pidLock.lock()
            self.watchedPids.removeAll()
            self.pidLock.unlock()
            self.bufferLock.lock()
            self.eventBuffer.removeAll()
            self.bufferLock.unlock()
            self.hasClient = false
            self.cliProxy = nil
            // Drop the evaluator if it was this client.
            self.evaluatorLock.lock()
            if let claimed = self.evaluatorProxy as AnyObject?, let p = proxy as AnyObject?, claimed === p {
                self.evaluatorProxy = nil
            }
            self.evaluatorLock.unlock()
            self.onWatchListChanged?(false)
        }
        connection.resume()
        hasClient = true
        cliProxy = proxy
        os_log("CLI connected via XPC", log: xpcLog, type: .default)
        return true
    }

    // MARK: - TractorNEXPC

    /// Called when the watch list changes — set by TransparentProxy
    var onWatchListChanged: ((Bool) -> Void)?

    func updateWatchList(_ pids: [Int32]) {
        pidLock.lock()
        watchedPids = Set(pids)
        let count = watchedPids.count
        pidLock.unlock()
        os_log("watch list updated — %d PIDs", log: xpcLog, type: .default, count)
        onWatchListChanged?(count > 0)
    }

    func pollEvents(reply: @escaping (Data) -> Void) {
        bufferLock.lock()
        let events = eventBuffer
        eventBuffer.removeAll()
        bufferLock.unlock()

        guard !events.isEmpty else {
            reply(Data("[]".utf8))
            return
        }
        // Filter out events that can't be serialized (e.g. traffic with bad chars)
        var validEvents = events
        if let data = try? JSONSerialization.data(withJSONObject: events) {
            reply(data)
        } else {
            // Serialization failed — try each event individually, drop bad ones
            validEvents = events.filter { JSONSerialization.isValidJSONObject($0) }
            if let data = try? JSONSerialization.data(withJSONObject: validEvents) {
                reply(data)
            } else {
                reply(Data("[]".utf8))
            }
        }
    }

    // MARK: - Event buffering (called from handleNewFlow/TCPBridge)

    func reportFlow(pid: Int32, host: String, port: String, proto: String, flowID: UInt64) {
        let event: [String: Any] = ["pid": pid, "host": host, "port": port, "proto": proto, "flowID": flowID]
        bufferLock.lock()
        eventBuffer.append(event)
        bufferLock.unlock()
    }

    func reportBytes(pid: Int32, host: String, port: String, proto: String,
                     bytesOut: Int64, bytesIn: Int64, closed: Bool = false, flowID: UInt64) {
        var event: [String: Any] = ["pid": pid, "host": host, "port": port, "proto": proto, "bytesOut": bytesOut, "bytesIn": bytesIn, "flowID": flowID]
        if closed { event["closed"] = true }
        bufferLock.lock()
        eventBuffer.append(event)
        bufferLock.unlock()

        // Notify the JS evaluator (best-effort). `ne:flow:bytes` for
        // periodic in-flight updates; `ne:flow:close` for the final.
        evaluatorLock.lock()
        let cli = evaluatorProxy
        evaluatorLock.unlock()
        guard let cli = cli else { return }
        let ctx: [String: Any] = [
            "pid": pid, "host": host, "port": Int(port) ?? 0,
            "protocol": proto,
            "bytesOut": bytesOut, "bytesIn": bytesIn, "flowID": flowID,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: ctx) else { return }
        if closed {
            cli.notifyFlowClose(data)
        } else {
            cli.notifyFlowBytes(data)
        }
    }

    func reportTraffic(pid: Int32, host: String, port: String, direction: String, data: Data, flowID: UInt64) {
        // Split large payloads into 48KB chunks (≈65KB base64), base64-encode for JSON transport
        let chunkSize = 49152
        var offset = 0
        bufferLock.lock()
        while offset < data.count {
            let end = min(offset + chunkSize, data.count)
            let slice = data[offset..<end]
            let b64 = slice.base64EncodedString()
            let event: [String: Any] = ["pid": pid, "host": host, "port": port, "traffic": direction, "contentBase64": b64, "flowID": flowID]
            eventBuffer.append(event)
            offset = end
        }
        if data.isEmpty {
            let event: [String: Any] = ["pid": pid, "host": host, "port": port, "traffic": direction, "contentBase64": "", "flowID": flowID]
            eventBuffer.append(event)
        }
        bufferLock.unlock()
    }

    // MARK: - MITM XPC methods

    func setMITMEnabled(_ enabled: Bool) {
        os_log("MITM %{public}@", log: xpcLog, type: .default, enabled ? "enabled" : "disabled")
        mitmEnabled = enabled
    }

    func claimEvaluator() {
        guard let conn = NSXPCConnection.current() else { return }
        let proxy = conn.remoteObjectProxyWithErrorHandler { error in
            os_log("evaluator proxy error: %{public}@", log: xpcLog, type: .error, error.localizedDescription)
        } as? TractorCLIXPC
        evaluatorLock.lock()
        evaluatorProxy = proxy
        evaluatorLock.unlock()
        os_log("evaluator claimed by client", log: xpcLog, type: .default)
    }

    func setInterceptAll(_ enabled: Bool) {
        os_log("interceptAll %{public}@", log: xpcLog, type: .default, enabled ? "on" : "off")
        interceptAll = enabled
        // Force NE to recompute its network rules. With interceptAll on we
        // need the wildcard TCP rule installed even if watchedPids is empty.
        onWatchListChanged?(interceptAll || !watchedPids.isEmpty)
    }

    func getCACertPEM(reply: @escaping (String) -> Void) {
        reply("")  // CA is now generated by the CLI, not the sysext
    }

    /// Ask the CLI (synchronously) whether the loaded JS program denies a
    /// new flow. The CLI relays to the ES sysext where the JS engine runs.
    /// Fails open: if no evaluator is claimed or the call errors/times out,
    /// the flow is allowed.
    func evaluateFlow(pid: Int32, process: String, host: String, port: UInt16,
                      direction: String, proto: String,
                      timeout: TimeInterval = 2.0) -> Bool {
        evaluatorLock.lock()
        let cli = evaluatorProxy
        evaluatorLock.unlock()
        guard let cli = cli else { return false }
        let ctx: [String: Any] = [
            "pid": pid, "process": process, "host": host,
            "port": Int(port), "direction": direction,
            "protocol": proto,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: ctx) else { return false }
        let sem = DispatchSemaphore(value: 0)
        var denied = false
        cli.evaluateFlow(data) { d in
            denied = d
            sem.signal()
        }
        if sem.wait(timeout: .now() + timeout) == .timedOut {
            os_log("evaluateFlow timed out — failing open", log: xpcLog, type: .error)
            return false
        }
        return denied
    }

    /// Ask the CLI to generate a PKCS12 for a hostname (synchronous).
    func requestP12(hostname: String) -> Data? {
        guard let cli = cliProxy else {
            fatalError("FlowReporter.requestP12(\(hostname)): cliProxy is nil")
        }
        let sem = DispatchSemaphore(value: 0)
        var result: Data?
        cli.generateP12(hostname: hostname as NSString) { data in
            result = data
            sem.signal()
        }
        let waitResult = sem.wait(timeout: .now() + 10)
        if waitResult == .timedOut {
            fatalError("FlowReporter.requestP12(\(hostname)): timed out after 10s")
        }
        return result
    }

    // MARK: - Flow relay management

    func registerRelay(_ relay: FlowRelay) {
        relayLock.lock()
        flowRelays[relay.id] = relay
        relayLock.unlock()
    }

    func unregisterRelay(id: UInt64) {
        relayLock.lock()
        flowRelays.removeValue(forKey: id)
        relayLock.unlock()
    }

    // MARK: - Flow streaming (CLI → sysext)

    func flowData(id: UInt64, data: Data) {
        relayLock.lock()
        let relay = flowRelays[id]
        relayLock.unlock()
        guard let relay = relay else { return }
        relay.receiveFromCLI(data)
    }

    func closeFlow(id: UInt64) {
        relayLock.lock()
        let relay = flowRelays[id]
        relayLock.unlock()
        relay?.close()
    }
}
