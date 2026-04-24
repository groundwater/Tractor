import EndpointSecurity
import Foundation

struct ESError: Error, CustomStringConvertible {
    let message: String
    var description: String { message }
}

/// Wraps the ES client, filters events to a tracked process tree, and emits to an EventSink
final class ESClient {
    private var client: OpaquePointer?
    private let tree: ProcessTree
    private let sink: EventSink
    /// Patterns to auto-discover new matching processes (name substring, lowercased)
    var tracePatterns: [String] = []
    /// Exact paths to auto-discover new matching processes
    var pathPatterns: [String] = []
    /// Lock for dynamic pattern updates
    private let patternLock = NSLock()

    /// Called after a tracked PID is added to the tree but before allowing execution.
    /// Use this to push the PID to the network extension so it's watched before
    /// the process can make any network connections.
    var onBeforeAllow: ((pid_t) -> Void)?

    init(tree: ProcessTree, sink: EventSink) {
        self.tree = tree
        self.sink = sink
    }

    func updatePatterns(trackers: [TrackerGroup]) {
        patternLock.lock()
        defer { patternLock.unlock() }
        tracePatterns = trackers.compactMap { $0.kind == .name ? $0.value.lowercased() : nil }
        pathPatterns = trackers.compactMap { $0.kind == .path ? $0.value : nil }
        // PID trackers don't need auto-discovery patterns — they're tracked directly
    }

    func start() throws {
        let tree = self.tree
        let sink = self.sink
        let patternLock = self.patternLock

        let result = es_new_client(&client) { [weak self] esClient, message in
            let proc = message.pointee.process
            let info = esProcessInfo(proc)

            let isAuth = message.pointee.action_type == ES_ACTION_TYPE_AUTH

            switch message.pointee.event_type {
            case ES_EVENT_TYPE_AUTH_EXEC:
                let target = message.pointee.event.exec.target
                let targetInfo = esProcessInfo(target)

                // Track if the parent (ppid) is in our tree
                var tracked = tree.contains(targetInfo.ppid) || tree.contains(targetInfo.pid)
                if tracked {
                    tree.trackIfChild(pid: targetInfo.pid, ppid: targetInfo.ppid)
                    // Inherit group membership from parent
                    if let tui = sink as? TUI {
                        tui.inheritGroupMembership(child: targetInfo.pid, parent: targetInfo.ppid)
                    }
                }

                // Auto-discover new processes by name/path patterns
                if !tracked {
                    patternLock.lock()
                    let namePatterns = self?.tracePatterns ?? []
                    let exactPaths = self?.pathPatterns ?? []
                    patternLock.unlock()

                    let path = targetInfo.path
                    let pathLower = path.lowercased()
                    if namePatterns.contains(where: { pathLower.contains($0) }) ||
                       exactPaths.contains(where: { path == $0 }) {
                        tree.addRoots([targetInfo.pid])
                        tracked = true
                        // Register with matching tracker groups
                        if let tui = sink as? TUI {
                            let name = (path as NSString).lastPathComponent
                            tui.matchProcessToGroups(pid: targetInfo.pid, name: name, path: path)
                        }
                    }
                }

                // Notify network extension before allowing, so the PID is
                // watched before the process can make any connections.
                if tracked, let hook = self?.onBeforeAllow {
                    hook(targetInfo.pid)
                }

                // Always allow — we're observing, not blocking
                if isAuth {
                    es_respond_auth_result(esClient, message, ES_AUTH_RESULT_ALLOW, false)
                }

                guard tracked else { return }

                // Get argv
                let execEventPtr: UnsafePointer<es_event_exec_t> = {
                    let rawMsg = UnsafeRawPointer(message)
                    let eventOffset = MemoryLayout<es_message_t>.offset(of: \es_message_t.event)!
                    return (rawMsg + eventOffset).assumingMemoryBound(to: es_event_exec_t.self)
                }()
                let argc = es_exec_arg_count(execEventPtr)
                var argv: [String] = []
                for i in 0..<argc {
                    let arg = es_exec_arg(execEventPtr, i)
                    argv.append(esString(arg))
                }

                sink.onExec(
                    pid: targetInfo.pid,
                    ppid: targetInfo.ppid,
                    process: targetInfo.path,
                    argv: argv.joined(separator: " "),
                    user: targetInfo.uid
                )

            case ES_EVENT_TYPE_NOTIFY_OPEN:
                guard tree.contains(info.pid) else { return }
                let filePath = esString(message.pointee.event.open.file.pointee.path)
                sink.onFileOp(
                    type: "open", pid: info.pid, ppid: info.ppid,
                    process: info.path, user: info.uid,
                    details: ["path": filePath]
                )

            case ES_EVENT_TYPE_NOTIFY_WRITE:
                guard tree.contains(info.pid) else { return }
                let filePath = esString(message.pointee.event.write.target.pointee.path)
                sink.onFileOp(
                    type: "write", pid: info.pid, ppid: info.ppid,
                    process: info.path, user: info.uid,
                    details: ["path": filePath]
                )

            case ES_EVENT_TYPE_NOTIFY_UNLINK:
                guard tree.contains(info.pid) else { return }
                let filePath = esString(message.pointee.event.unlink.target.pointee.path)
                sink.onFileOp(
                    type: "unlink", pid: info.pid, ppid: info.ppid,
                    process: info.path, user: info.uid,
                    details: ["path": filePath]
                )

            case ES_EVENT_TYPE_NOTIFY_RENAME:
                guard tree.contains(info.pid) else { return }
                let src = esString(message.pointee.event.rename.source.pointee.path)
                var dst = ""
                if message.pointee.event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                    dst = esString(message.pointee.event.rename.destination.existing_file.pointee.path)
                } else {
                    let dir = esString(message.pointee.event.rename.destination.new_path.dir.pointee.path)
                    let filename = esString(message.pointee.event.rename.destination.new_path.filename)
                    dst = dir + "/" + filename
                }
                sink.onFileOp(
                    type: "rename", pid: info.pid, ppid: info.ppid,
                    process: info.path, user: info.uid,
                    details: ["from": src, "to": dst]
                )

            case ES_EVENT_TYPE_NOTIFY_CLOSE:
                guard tree.contains(info.pid) else { return }
                if message.pointee.event.close.modified {
                    let filePath = esString(message.pointee.event.close.target.pointee.path)
                    sink.onFileOp(
                        type: "write", pid: info.pid, ppid: info.ppid,
                        process: info.path, user: info.uid,
                        details: ["path": filePath]
                    )
                }

            case ES_EVENT_TYPE_NOTIFY_EXIT:
                if tree.contains(info.pid) {
                    let stat = message.pointee.event.exit.stat
                    sink.onExit(
                        pid: info.pid, ppid: info.ppid,
                        process: info.path, user: info.uid,
                        exitStatus: stat
                    )
                    tree.remove(info.pid)
                }

            default:
                break
            }
        }

        guard result == ES_NEW_CLIENT_RESULT_SUCCESS else {
            var detail = "es_new_client failed: \(result.rawValue)"
            switch result {
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                detail += " — missing endpoint-security entitlement"
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                detail += " — not permitted (grant Full Disk Access or disable SIP)"
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                detail += " — not privileged (run with sudo)"
            default:
                break
            }
            throw ESError(message: detail)
        }

        guard let esClient = client else {
            throw ESError(message: "es_new_client returned success but client is nil")
        }

        // Mute our own process so we never generate recursive events
        // (e.g. tracing "Tractor" by name while --log writes to SQLite)
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
        guard subResult == ES_RETURN_SUCCESS else {
            throw ESError(message: "es_subscribe failed")
        }
    }

    func stop() {
        if let c = client {
            es_delete_client(c)
            client = nil
        }
    }
}

// MARK: - ES Helpers

func esString(_ token: es_string_token_t) -> String {
    if token.length == 0 { return "" }
    return String(cString: token.data)
}

func esProcessInfo(_ proc: UnsafePointer<es_process_t>) -> (path: String, pid: pid_t, ppid: pid_t, uid: uid_t) {
    let path = esString(proc.pointee.executable.pointee.path)
    let pid = audit_token_to_pid(proc.pointee.audit_token)
    let ppid = proc.pointee.ppid
    let uid = audit_token_to_euid(proc.pointee.audit_token)
    return (path, pid, ppid, uid)
}
