import Foundation

private let xpcServiceName = "group.com.jacobgroundwater.Tractor.xpc"

/// XPC protocol matching the sysext's exported interface
@objc protocol TractorNEXPC {
    func updateWatchList(_ pids: [Int32])
    func pollEvents(reply: @escaping (Data) -> Void)
}

/// Connects to the TractorNE sysext via XPC and polls for flow events.
final class FlowXPCClient {
    private let sink: EventSink
    private var connection: NSXPCConnection?
    private var proxy: TractorNEXPC?
    private var pollTimer: DispatchSourceTimer?

    var onBytesUpdate: ((pid_t, String, UInt16, Int64, Int64) -> Void)?

    init(sink: EventSink) {
        self.sink = sink
    }

    func start() {
        let conn = NSXPCConnection(machServiceName: xpcServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: TractorNEXPC.self)
        conn.invalidationHandler = {
            NSLog("Tractor: XPC connection to sysext invalidated")
        }
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

    // MARK: - Private

    private func pollEvents() {
        proxy?.pollEvents { [weak self] data in
            self?.handleEvents(data)
        }
    }

    private func handleEvents(_ data: Data) {
        guard let events = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return }

        for event in events {
            let pid = (event["pid"] as? Int).map { Int32($0) } ?? -1
            let host = event["host"] as? String ?? ""
            let port = UInt16(event["port"] as? String ?? "0") ?? 0

            if let bytesOut = event["bytesOut"] as? Int64,
               let bytesIn = event["bytesIn"] as? Int64 {
                onBytesUpdate?(pid, host, port, bytesOut, bytesIn)
                continue
            }

            if event["proto"] != nil {
                sink.onConnect(pid: pid, ppid: 0, process: "", user: 0,
                               remoteAddr: host, remotePort: port)
            }
        }
    }
}
