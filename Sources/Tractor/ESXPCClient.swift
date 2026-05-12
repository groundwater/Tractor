import Foundation

// endpointsecurityd auto-registers <team-id>.<bundle-id>.xpc on activation.
private let esXPCServiceName = "3FGZQE8AW3.com.jacobgroundwater.Tractor.ES.xpc"

/// XPC protocol matching the TractorES sysext's exported interface.
@objc protocol TractorESXPC {
    func addTrackedPids(_ pids: [Int32])
    func setTrackerPatterns(names: [String], paths: [String])
    func pollEvents(reply: @escaping (Data) -> Void)
    func pollTrackedPids(reply: @escaping ([Int32]) -> Void)
}

/// Connects to the TractorES sysext, seeds it with tracked PIDs and patterns,
/// and polls for ES events (exec/fileop/exit). The host wires `onExec` etc.
/// to drive the sink (TUI / JSON / SQLite).
final class ESXPCClient {
    private var connection: NSXPCConnection?
    private var proxy: TractorESXPC?
    private var eventTimer: DispatchSourceTimer?
    private var pidsTimer: DispatchSourceTimer?

    /// Most recently observed tracked-PID set on the sysext side. Used by the
    /// CLI to mirror into the NE sysext's watch list when `--net` is on.
    private(set) var trackedPids: Set<pid_t> = []

    var onExec: ((pid_t, pid_t, String, String, uid_t) -> Void)?
    var onFileOp: ((String, pid_t, pid_t, String, uid_t, [String: String]) -> Void)?
    var onExit: ((pid_t, pid_t, String, uid_t, Int32) -> Void)?
    /// Called whenever the tracked-PID set changes on the sysext side.
    var onTrackedPidsChanged: ((Set<pid_t>) -> Void)?

    func start() {
        let conn = NSXPCConnection(machServiceName: esXPCServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: TractorESXPC.self)
        conn.invalidationHandler = { /* normal on shutdown */ }
        conn.resume()
        connection = conn
        proxy = conn.remoteObjectProxyWithErrorHandler { _ in } as? TractorESXPC

        let events = DispatchSource.makeTimerSource(queue: .main)
        events.schedule(deadline: .now() + 0.5, repeating: .milliseconds(200))
        events.setEventHandler { [weak self] in self?.pollEvents() }
        eventTimer = events
        events.resume()

        let pids = DispatchSource.makeTimerSource(queue: .main)
        pids.schedule(deadline: .now() + 0.5, repeating: .milliseconds(500))
        pids.setEventHandler { [weak self] in self?.pollTrackedPids() }
        pidsTimer = pids
        pids.resume()
    }

    func stop() {
        eventTimer?.cancel(); eventTimer = nil
        pidsTimer?.cancel(); pidsTimer = nil
        connection?.invalidate()
        connection = nil
        proxy = nil
    }

    func addTrackedPids(_ pids: Set<pid_t>) {
        proxy?.addTrackedPids(Array(pids))
    }

    func setTrackerPatterns(names: [String], paths: [String]) {
        proxy?.setTrackerPatterns(names: names, paths: paths)
    }

    // MARK: - Private

    private func pollEvents() {
        proxy?.pollEvents { [weak self] data in
            DispatchQueue.main.async { self?.handleEvents(data) }
        }
    }

    private func pollTrackedPids() {
        proxy?.pollTrackedPids { [weak self] pids in
            DispatchQueue.main.async { self?.handleTrackedPids(pids) }
        }
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
            default:
                continue
            }
        }
    }
}
