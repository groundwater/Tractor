import Foundation

private let xpcServiceName = "group.com.jacobgroundwater.Tractor"

/// XPC protocol matching the TractorNE sysext's exported interface
@objc protocol TractorNEXPC {
    func updateWatchList(_ pids: [Int32])
    func pollEvents(reply: @escaping (Data) -> Void)
    func setMITMEnabled(_ enabled: Bool)
    func getCACertPEM(reply: @escaping (String) -> Void)
    func flowData(id: UInt64, data: Data)
    func closeFlow(id: UInt64)
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
    var onConnectionError: ((Error) -> Void)?

    init(sink: EventSink) {
        self.sink = sink
    }

    static func isAvailable(timeout: TimeInterval = 1.0) -> Bool {
        let sem = DispatchSemaphore(value: 0)
        var available = false

        let conn = NSXPCConnection(machServiceName: xpcServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: TractorNEXPC.self)
        conn.resume()

        let proxy = conn.remoteObjectProxyWithErrorHandler { _ in
            sem.signal()
        } as? TractorNEXPC
        proxy?.pollEvents { _ in
            available = true
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + timeout)
        conn.invalidate()
        return available
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
        conn.invalidationHandler = { [weak self] in
            let err = NSError(
                domain: NSCocoaErrorDomain,
                code: NSXPCConnectionInvalid,
                userInfo: [NSLocalizedDescriptionKey: "Network extension connection was invalidated."]
            )
            self?.onConnectionError?(err)
        }
        conn.resume()
        connection = conn
        proxy = conn.remoteObjectProxyWithErrorHandler { [weak self] error in
            self?.onConnectionError?(error)
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

    func updateWatchList(_ pids: Set<pid_t>) {
        proxy?.updateWatchList(Array(pids))
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
