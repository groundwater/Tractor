import EndpointSecurity
import Foundation
import os.log

private let esLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.ES", category: "es")

/// Endpoint Security client hosted inside the TractorES sysext. The CLI seeds
/// initial tracked PIDs and tracker patterns via XPC; the daemon then extends
/// the tree itself on AUTH_EXEC (no synchronous round-trip to the CLI), and
/// streams exec/file/exit events back through the ESReporter event buffer.
///
/// Running ES inside the sysext means the user doesn't have to grant Full Disk
/// Access — the sysext's approval flow already authorises the ES entitlement.
final class ESDaemon {
    private weak var reporter: ESReporter?
    private var client: OpaquePointer?

    private let lock = NSLock()
    private var trackedPids: Set<Int32> = []
    private var namePatterns: [String] = []
    private var pathPatterns: [String] = []

    init(reporter: ESReporter) {
        self.reporter = reporter
    }

    // MARK: - State updates from CLI (via XPC, thread-safe)

    func addTrackedPids(_ pids: [Int32]) {
        lock.lock()
        for p in pids { trackedPids.insert(p) }
        let snapshot = trackedPids
        lock.unlock()
        reporter?.didUpdateTrackedPids(snapshot)
    }

    func setTrackerPatterns(names: [String], paths: [String]) {
        lock.lock()
        namePatterns = names.map { $0.lowercased() }
        pathPatterns = paths
        lock.unlock()
    }

    func currentTrackedPids() -> Set<Int32> {
        lock.lock()
        defer { lock.unlock() }
        return trackedPids
    }

    private func contains(_ pid: Int32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return trackedPids.contains(pid)
    }

    /// Returns true if newly tracked, false if already tracked.
    @discardableResult
    private func trackIfChild(pid: Int32, ppid: Int32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard trackedPids.contains(ppid) else { return false }
        if trackedPids.contains(pid) { return false }
        trackedPids.insert(pid)
        return true
    }

    @discardableResult
    private func addByPattern(pid: Int32, path: String) -> Bool {
        lock.lock()
        let names = namePatterns
        let paths = pathPatterns
        lock.unlock()
        let pathLower = path.lowercased()
        let matches = names.contains(where: { pathLower.contains($0) }) ||
                      paths.contains(where: { path == $0 })
        guard matches else { return false }
        lock.lock()
        let inserted = trackedPids.insert(pid).inserted
        lock.unlock()
        return inserted
    }

    private func remove(_ pid: Int32) {
        lock.lock()
        trackedPids.remove(pid)
        let snapshot = trackedPids
        lock.unlock()
        reporter?.didUpdateTrackedPids(snapshot)
    }

    // MARK: - Lifecycle

    func start() {
        guard client == nil else { return }

        let result = es_new_client(&client) { [weak self] esClient, message in
            self?.handleEvent(esClient: esClient, message: message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let esClient = client else {
            os_log("es_new_client failed: %d", log: esLog, type: .error, result.rawValue)
            return
        }

        // Mute our own process so we don't see our own activity.
        var selfToken = audit_token_t()
        var size = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), withUnsafeMutablePointer(to: &selfToken) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(size)) { $0 }
        }, &size)
        es_mute_process(esClient, &selfToken)

        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
            ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_EXIT,
        ]
        let subResult = es_subscribe(esClient, events, UInt32(events.count))
        if subResult != ES_RETURN_SUCCESS {
            os_log("es_subscribe failed", log: esLog, type: .error)
            return
        }
        os_log("ES daemon started", log: esLog, type: .default)
    }

    func stop() {
        if let c = client {
            es_delete_client(c)
            client = nil
        }
        lock.lock()
        trackedPids.removeAll()
        namePatterns.removeAll()
        pathPatterns.removeAll()
        lock.unlock()
        os_log("ES daemon stopped", log: esLog, type: .default)
    }

    // MARK: - Event handling

    private func handleEvent(esClient: OpaquePointer?, message: UnsafePointer<es_message_t>) {
        let proc = message.pointee.process
        let info = esProcessInfo(proc)
        let isAuth = message.pointee.action_type == ES_ACTION_TYPE_AUTH

        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            let target = message.pointee.event.exec.target
            let targetInfo = esProcessInfo(target)

            // Track if the parent is in our tree; allow execution either way.
            var tracked = self.contains(targetInfo.pid) || trackIfChild(pid: targetInfo.pid, ppid: targetInfo.ppid)
            if !tracked {
                tracked = addByPattern(pid: targetInfo.pid, path: targetInfo.path)
            }
            if isAuth, let esClient = esClient {
                es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
            }
            guard tracked else { return }

            // Notify reporter that the tracked-PID set changed so the NE side
            // can refresh its watch decisions before the new process makes any
            // network connections.
            reporter?.didUpdateTrackedPids(currentTrackedPids())

            // Collect argv
            let execEventPtr: UnsafePointer<es_event_exec_t> = {
                let rawMsg = UnsafeRawPointer(message)
                let eventOffset = MemoryLayout<es_message_t>.offset(of: \es_message_t.event)!
                return (rawMsg + eventOffset).assumingMemoryBound(to: es_event_exec_t.self)
            }()
            let argc = es_exec_arg_count(execEventPtr)
            var argv: [String] = []
            for i in 0..<argc {
                argv.append(esString(es_exec_arg(execEventPtr, i)))
            }
            reporter?.reportExec(pid: targetInfo.pid, ppid: targetInfo.ppid,
                                 process: targetInfo.path,
                                 argv: argv.joined(separator: " "),
                                 user: targetInfo.uid)

        case ES_EVENT_TYPE_NOTIFY_OPEN:
            guard contains(info.pid) else { return }
            let path = esString(message.pointee.event.open.file.pointee.path)
            reporter?.reportFileOp(type: "open", pid: info.pid, ppid: info.ppid,
                                    process: info.path, user: info.uid,
                                    details: ["path": path])

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            guard contains(info.pid) else { return }
            let path = esString(message.pointee.event.write.target.pointee.path)
            reporter?.reportFileOp(type: "write", pid: info.pid, ppid: info.ppid,
                                    process: info.path, user: info.uid,
                                    details: ["path": path])

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            guard contains(info.pid) else { return }
            let path = esString(message.pointee.event.unlink.target.pointee.path)
            reporter?.reportFileOp(type: "unlink", pid: info.pid, ppid: info.ppid,
                                    process: info.path, user: info.uid,
                                    details: ["path": path])

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            guard contains(info.pid) else { return }
            let src = esString(message.pointee.event.rename.source.pointee.path)
            var dst = ""
            if message.pointee.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                dst = esString(message.pointee.event.rename.destination.existing_file.pointee.path)
            } else {
                let dir = esString(message.pointee.event.rename.destination.new_path.dir.pointee.path)
                let filename = esString(message.pointee.event.rename.destination.new_path.filename)
                dst = dir + "/" + filename
            }
            reporter?.reportFileOp(type: "rename", pid: info.pid, ppid: info.ppid,
                                    process: info.path, user: info.uid,
                                    details: ["from": src, "to": dst])

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            guard contains(info.pid) else { return }
            if message.pointee.event.close.modified {
                let path = esString(message.pointee.event.close.target.pointee.path)
                reporter?.reportFileOp(type: "write", pid: info.pid, ppid: info.ppid,
                                        process: info.path, user: info.uid,
                                        details: ["path": path])
            }

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            if contains(info.pid) {
                let stat = message.pointee.event.exit.stat
                reporter?.reportExit(pid: info.pid, ppid: info.ppid,
                                      process: info.path, user: info.uid,
                                      exitStatus: stat)
                remove(info.pid)
            }

        default:
            break
        }
    }
}

// MARK: - ES helpers (sysext copies — CLI's copies in ESClient.swift are removed)

private func esString(_ token: es_string_token_t) -> String {
    if token.length == 0 { return "" }
    return String(cString: token.data)
}

private func esProcessInfo(_ proc: UnsafePointer<es_process_t>) -> (path: String, pid: Int32, ppid: Int32, uid: UInt32) {
    let path = esString(proc.pointee.executable.pointee.path)
    let pid = audit_token_to_pid(proc.pointee.audit_token)
    let ppid = proc.pointee.ppid
    let uid = audit_token_to_euid(proc.pointee.audit_token)
    return (path, pid, ppid, uid)
}
