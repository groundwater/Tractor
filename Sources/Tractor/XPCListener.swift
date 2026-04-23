import Foundation

/// Listens for XPC connections from the TractorNE sysext and routes
/// flow events into the EventSink pipeline.
final class XPCFlowListener: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener
    private let sink: EventSink

    init(sink: EventSink) {
        self.sink = sink
        self.listener = NSXPCListener(machServiceName: tractorXPCServiceName)
        super.init()
        listener.delegate = self
    }

    func start() {
        listener.resume()
        fputs("Tractor: XPC listener ready on \(tractorXPCServiceName)\n", stderr)
    }

    func stop() {
        listener.invalidate()
    }

    // MARK: - NSXPCListenerDelegate

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let interface = NSXPCInterface(with: TractorXPCProtocol.self)
        connection.exportedInterface = interface
        connection.exportedObject = XPCFlowHandler(sink: sink)
        connection.resume()
        return true
    }
}

/// Handles incoming flow reports from the sysext.
private final class XPCFlowHandler: NSObject, TractorXPCProtocol {
    private let sink: EventSink

    init(sink: EventSink) {
        self.sink = sink
    }

    func reportFlow(pid: Int32, process: String, remoteHost: String, remotePort: String,
                    proto: String, bytesIn: Int64, bytesOut: Int64) {
        let port = UInt16(remotePort) ?? 0
        sink.onConnect(pid: pid, ppid: 0, process: process, user: 0,
                       remoteAddr: remoteHost, remotePort: port)
    }
}
