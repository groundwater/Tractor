import Foundation
import NetworkExtension
import os.log

private let relayLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "relay")

/// Atomic counter for flow IDs — used by FlowRelay and TransparentProxy
var nextFlowID: UInt64 = 0
let flowIDLock = NSLock()
func allocFlowID() -> UInt64 {
    flowIDLock.lock()
    defer { flowIDLock.unlock() }
    nextFlowID += 1
    return nextFlowID
}

/// Relays raw bytes between an NEAppProxyTCPFlow and the CLI via XPC.
/// No TLS, no crypto — just a pipe. All the smart stuff happens in the CLI.
final class FlowRelay {
    let id: UInt64
    let flow: NEAppProxyTCPFlow
    private let reporter: FlowReporter
    private var tornDown = false

    init(flow: NEAppProxyTCPFlow, reporter: FlowReporter) {
        self.id = allocFlowID()
        self.flow = flow
        self.reporter = reporter
    }

    /// Called after flow.open succeeds. Tells CLI about the flow and starts pumping.
    func start(host: String, port: UInt16, pid: Int32) {
        guard let cli = reporter.cliProxy else {
            fatalError("FlowRelay.start: no CLI proxy — CLI not connected")
        }

        os_log("relay %llu: opened for %{public}@:%d pid=%d", log: relayLog, type: .default,
               id, host, port, pid)

        // Tell CLI about this new flow
        cli.openFlow(id: id, host: host as NSString, port: port, pid: pid)

        // Start reading from the app's flow → forward to CLI
        pumpFromFlow()
    }

    /// Called by FlowReporter when CLI sends data back for this flow.
    func receiveFromCLI(_ data: Data) {
        guard !tornDown else { return }
        flow.write(data) { [weak self] error in
            if let error = error {
                os_log("relay %llu: flow write error: %{public}@", log: relayLog, type: .error,
                       self?.id ?? 0, error.localizedDescription)
                self?.close()
            }
        }
    }

    func close() {
        guard !tornDown else { return }
        tornDown = true
        os_log("relay %llu: closing", log: relayLog, type: .default, id)
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        reporter.unregisterRelay(id: id)
        reporter.cliProxy?.closeFlow(id: id)
    }

    // MARK: - Private

    private func pumpFromFlow() {
        guard !tornDown else { return }
        flow.readData { [weak self] data, error in
            guard let self = self, !self.tornDown else { return }
            if error != nil || data == nil || data!.isEmpty {
                self.close()
                return
            }
            // Forward raw bytes to CLI
            self.reporter.cliProxy?.flowData(id: self.id, data: data!)
            // Keep reading
            self.pumpFromFlow()
        }
    }
}
