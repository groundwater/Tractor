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
}

/// Hosts the XPC listener for the TractorES sysext and buffers ES events.
/// Owns the lifetime of the underlying ESDaemon.
final class ESReporter: NSObject, NSXPCListenerDelegate, TractorESXPC {
    private var listener: NSXPCListener?
    private let bufferLock = NSLock()
    private var eventBuffer: [[String: Any]] = []
    private var hasClient = false
    private var esDaemon: ESDaemon?
    private let pidLock = NSLock()
    /// Snapshot of tracked PIDs published to the CLI on demand.
    private var publishedPids: Set<Int32> = []

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
        hasClient = false
    }

    // MARK: - NSXPCListenerDelegate

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: TractorESXPC.self)
        connection.exportedObject = self
        connection.invalidationHandler = { [weak self] in
            guard let self = self else { return }
            os_log("CLI disconnected — stopping ES daemon", log: xpcLog, type: .default)
            self.esDaemon?.stop()
            self.esDaemon = nil
            self.bufferLock.lock(); self.eventBuffer.removeAll(); self.bufferLock.unlock()
            self.pidLock.lock(); self.publishedPids.removeAll(); self.pidLock.unlock()
            self.hasClient = false
        }
        connection.resume()
        hasClient = true
        if esDaemon == nil {
            let daemon = ESDaemon(reporter: self)
            esDaemon = daemon
            daemon.start()
        }
        os_log("CLI connected", log: xpcLog, type: .default)
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
        bufferLock.lock()
        let events = eventBuffer
        eventBuffer.removeAll()
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

    // MARK: - Called from ESDaemon

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
        bufferLock.lock(); eventBuffer.append(event); bufferLock.unlock()
    }

    func reportFileOp(type: String, pid: Int32, ppid: Int32, process: String, user: UInt32, details: [String: String]) {
        var event: [String: Any] = [
            "kind": "fileop", "fileop": type, "pid": pid, "ppid": ppid,
            "process": process, "user": user,
        ]
        for (k, v) in details { event[k] = v }
        bufferLock.lock(); eventBuffer.append(event); bufferLock.unlock()
    }

    func reportExit(pid: Int32, ppid: Int32, process: String, user: UInt32, exitStatus: Int32) {
        let event: [String: Any] = [
            "kind": "exit", "pid": pid, "ppid": ppid,
            "process": process, "user": user, "exitStatus": exitStatus,
        ]
        bufferLock.lock(); eventBuffer.append(event); bufferLock.unlock()
    }
}
