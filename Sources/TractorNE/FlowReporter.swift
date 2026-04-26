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
        connection.invalidationHandler = { [weak self] in
            os_log("CLI disconnected — clearing watch list", log: xpcLog, type: .default)
            self?.pidLock.lock()
            self?.watchedPids.removeAll()
            self?.pidLock.unlock()
            self?.hasClient = false
            self?.cliProxy = nil
            self?.onWatchListChanged?(false)
        }
        connection.resume()
        hasClient = true
        cliProxy = connection.remoteObjectProxyWithErrorHandler { error in
            os_log("CLI reverse proxy error: %{public}@", log: xpcLog, type: .error, error.localizedDescription)
        } as? TractorCLIXPC
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

    func reportBytes(pid: Int32, host: String, port: String, bytesOut: Int64, bytesIn: Int64, closed: Bool = false, flowID: UInt64) {
        var event: [String: Any] = ["pid": pid, "host": host, "port": port, "bytesOut": bytesOut, "bytesIn": bytesIn, "flowID": flowID]
        if closed { event["closed"] = true }
        bufferLock.lock()
        eventBuffer.append(event)
        bufferLock.unlock()
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

    func getCACertPEM(reply: @escaping (String) -> Void) {
        reply("")  // CA is now generated by the CLI, not the sysext
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
