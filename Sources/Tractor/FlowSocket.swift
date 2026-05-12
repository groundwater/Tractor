import Foundation

private let xpcServiceName = "group.com.jacobgroundwater.Tractor"

/// XPC protocol matching the sysext's exported interface
@objc protocol TractorNEXPC {
    func pollEvents(reply: @escaping (Data) -> Void)
    func setMITMEnabled(_ enabled: Bool)
    func getCACertPEM(reply: @escaping (String) -> Void)
    func flowData(id: UInt64, data: Data)
    func closeFlow(id: UInt64)
    func addTrackedPids(_ pids: [Int32])
    func setTrackerPatterns(names: [String], paths: [String])
    func setNetworkWatchingEnabled(_ enabled: Bool)
}

/// Reverse XPC protocol: sysext calls these methods on the CLI
@objc protocol TractorCLIXPC {
    func generateP12(hostname: NSString, reply: @escaping (Data) -> Void)
    func openFlow(id: UInt64, host: NSString, port: UInt16, pid: Int32)
    func flowData(id: UInt64, data: Data)
    func closeFlow(id: UInt64)
}

/// Connects to the TractorNE sysext via XPC and polls for flow events.
final class FlowXPCClient {
    private let sink: EventSink
    private var connection: NSXPCConnection?
    private var proxy: TractorNEXPC?
    private var pollTimer: DispatchSourceTimer?
    private(set) var mitmProxy: MITMProxy?

    var onBytesUpdate: ((pid_t, String, UInt16, Int64, Int64, UInt64) -> Void)?
    var onConnectionClosed: ((pid_t, String, UInt16, UInt64) -> Void)?
    var onTraffic: ((pid_t, String, UInt16, String, Data, UInt64) -> Void)?
    /// ES exec event — the sysext signals that a new PID was added to the tracked tree.
    var onExec: ((pid_t, pid_t, String, String, uid_t) -> Void)?
    /// ES file operation event (open/write/unlink/rename/close).
    var onFileOp: ((String, pid_t, pid_t, String, uid_t, [String: String]) -> Void)?
    /// ES exit event.
    var onExit: ((pid_t, pid_t, String, uid_t, Int32) -> Void)?
    // Local endpoint not available from NEAppProxyTCPFlow API

    init(sink: EventSink) {
        self.sink = sink
    }

    func start() {
        let conn = NSXPCConnection(machServiceName: xpcServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: TractorNEXPC.self)
        // Bidirectional: export our interface so sysext can call us
        conn.exportedInterface = NSXPCInterface(with: TractorCLIXPC.self)
        // Set exported object BEFORE resume so it's ready when sysext calls us
        if let mitmProxy = mitmProxy {
            conn.exportedObject = mitmProxy
        }
        conn.invalidationHandler = { /* XPC invalidated — normal on shutdown */ }
        conn.resume()
        connection = conn
        proxy = conn.remoteObjectProxyWithErrorHandler { error in
            // Silently retry on next poll
        } as? TractorNEXPC

        // Start polling
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 0.5, repeating: .milliseconds(200))
        timer.setEventHandler { [weak self] in
            self?.pollEvents()
        }
        pollTimer = timer
        timer.resume()
    }

    /// Set up the MITM proxy and expose it as the XPC exported object.
    /// Must be called after start() and before setMITMEnabled().
    func setupMITM(caCertPEM: String, caKeyPEM: String) {
        let proxy = MITMProxy(caCertPEM: caCertPEM, caKeyPEM: caKeyPEM)

        // Wire: when MITMProxy wants to send data back to sysext
        proxy.sendToSysext = { [weak self] flowID, data in
            self?.proxy?.flowData(id: flowID, data: data)
        }
        proxy.closeSysextFlow = { [weak self] flowID in
            self?.proxy?.closeFlow(id: flowID)
        }
        proxy.onTraffic = { [weak self] pid, host, port, direction, data, flowID in
            self?.onTraffic?(pid, host, port, direction, data, flowID)
        }

        mitmProxy = proxy
    }

    func stop() {
        pollTimer?.cancel()
        pollTimer = nil
        connection?.invalidate()
        connection = nil
        proxy = nil
    }

    /// Seed the sysext's tracked-PID set. The daemon extends the tree itself
    /// from there via AUTH_EXEC; the CLI does not push subsequent updates.
    func addTrackedPids(_ pids: Set<pid_t>) {
        proxy?.addTrackedPids(Array(pids))
    }

    func setTrackerPatterns(names: [String], paths: [String]) {
        proxy?.setTrackerPatterns(names: names, paths: paths)
    }

    func setNetworkWatchingEnabled(_ enabled: Bool) {
        proxy?.setNetworkWatchingEnabled(enabled)
    }

    func setMITMEnabled(_ enabled: Bool) {
        proxy?.setMITMEnabled(enabled)
    }

    func getCACertPEM(completion: @escaping (String) -> Void) {
        proxy?.getCACertPEM { pem in
            DispatchQueue.main.async { completion(pem) }
        }
    }

    // MARK: - Private

    private func pollEvents() {
        proxy?.pollEvents { [weak self] data in
            DispatchQueue.main.async {
                self?.handleEvents(data)
            }
        }
    }

    private func handleEvents(_ data: Data) {
        guard let events = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return }

        for event in events {
            let pid = (event["pid"] as? Int).map { Int32($0) } ?? -1

            // ES events (carry an explicit "kind" field)
            switch event["kind"] as? String {
            case "exec":
                let ppid = (event["ppid"] as? Int).map { Int32($0) } ?? 0
                let process = event["process"] as? String ?? ""
                let argv = event["argv"] as? String ?? ""
                let user = (event["user"] as? Int).map { uid_t($0) } ?? 0
                onExec?(pid, ppid, process, argv, user)
                continue
            case "fileop":
                let ppid = (event["ppid"] as? Int).map { Int32($0) } ?? 0
                let process = event["process"] as? String ?? ""
                let user = (event["user"] as? Int).map { uid_t($0) } ?? 0
                let type = event["fileop"] as? String ?? ""
                var details: [String: String] = [:]
                for k in ["path", "from", "to"] {
                    if let v = event[k] as? String { details[k] = v }
                }
                onFileOp?(type, pid, ppid, process, user, details)
                continue
            case "exit":
                let ppid = (event["ppid"] as? Int).map { Int32($0) } ?? 0
                let process = event["process"] as? String ?? ""
                let user = (event["user"] as? Int).map { uid_t($0) } ?? 0
                let exitStatus = (event["exitStatus"] as? Int).map { Int32($0) } ?? 0
                onExit?(pid, ppid, process, user, exitStatus)
                continue
            default:
                break
            }

            let host = event["host"] as? String ?? ""
            let port = UInt16(event["port"] as? String ?? "0") ?? 0
            let flowID = (event["flowID"] as? UInt64) ?? (event["flowID"] as? Int).map { UInt64($0) } ?? 0

            if let bytesOut = event["bytesOut"] as? Int64,
               let bytesIn = event["bytesIn"] as? Int64 {
                onBytesUpdate?(pid, host, port, bytesOut, bytesIn, flowID)
                if event["closed"] as? Bool == true {
                    onConnectionClosed?(pid, host, port, flowID)
                }
                continue
            }

            if let direction = event["traffic"] as? String {
                let data: Data
                if let b64 = event["contentBase64"] as? String {
                    data = Data(base64Encoded: b64) ?? Data()
                } else if let content = event["content"] as? String {
                    // Legacy fallback: old sysext sending String content
                    data = content.data(using: .isoLatin1) ?? Data()
                } else {
                    continue
                }
                onTraffic?(pid, host, port, direction, data, flowID)
                continue
            }

            if event["proto"] != nil {
                sink.onConnect(pid: pid, ppid: 0, process: "", user: 0,
                               remoteAddr: host, remotePort: port, flowID: flowID)
            }
        }
    }
}
