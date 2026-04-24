import Foundation
import os.log

private let xpcLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "xpc")
private let xpcServiceName = "group.com.jacobgroundwater.Tractor"

/// XPC protocol: CLI calls these methods on the sysext
@objc protocol TractorNEXPC {
    func updateWatchList(_ pids: [Int32])
    func pollEvents(reply: @escaping (Data) -> Void)
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

    func isWatched(_ pid: Int32) -> Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        guard hasClient else { return false }
        return watchedPids.contains(pid)
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
        connection.invalidationHandler = { [weak self] in
            os_log("CLI disconnected — clearing watch list", log: xpcLog, type: .default)
            self?.pidLock.lock()
            self?.watchedPids.removeAll()
            self?.pidLock.unlock()
            self?.hasClient = false
            self?.onWatchListChanged?(false)
        }
        connection.resume()
        hasClient = true
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

        guard !events.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: events) else {
            reply(Data("[]".utf8))
            return
        }
        reply(data)
    }

    // MARK: - Event buffering (called from handleNewFlow/TCPBridge)

    func reportFlow(pid: Int32, process: String, host: String, port: String, proto: String) {
        let event: [String: Any] = ["pid": pid, "host": host, "port": port, "proto": proto]
        bufferLock.lock()
        eventBuffer.append(event)
        bufferLock.unlock()
    }

    func reportBytes(pid: Int32, host: String, port: String, bytesOut: Int64, bytesIn: Int64) {
        let event: [String: Any] = ["pid": pid, "host": host, "port": port, "bytesOut": bytesOut, "bytesIn": bytesIn]
        bufferLock.lock()
        eventBuffer.append(event)
        bufferLock.unlock()
    }
}
