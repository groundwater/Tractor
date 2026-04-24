import Foundation
import NetworkExtension
import os.log

private let bridgeLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "bridge")

/// Bridges an NEAppProxyTCPFlow to the remote via NWTCPConnection.
///
/// Uses the deprecated but functional createTCPConnection API which is the
/// NE framework's own async, non-blocking bypass mechanism. All callbacks
/// are handled by the framework — no manual threading.
final class TCPBridge: NSObject {
    private let flow: NEAppProxyTCPFlow
    private let connection: NWTCPConnection
    private let onComplete: (Int64, Int64) -> Void

    var onBytesUpdated: ((Int64, Int64) -> Void)?

    private var bytesOut: Int64 = 0
    private var bytesIn: Int64 = 0
    private var tornDown = false
    private var flowOpen = false
    private var connectionReady = false

    init(flow: NEAppProxyTCPFlow, connection: NWTCPConnection, onComplete: @escaping (Int64, Int64) -> Void) {
        self.flow = flow
        self.connection = connection
        self.onComplete = onComplete
        super.init()

        // KVO with .initial so we catch already-connected state
        connection.addObserver(self, forKeyPath: "state", options: [.new, .initial], context: nil)
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?,
                               change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard keyPath == "state" else { return }
        let state = connection.state
        os_log("bridge state: %d", log: bridgeLog, type: .default, state.rawValue)
        switch state {
        case .connected:
            connection.removeObserver(self, forKeyPath: "state")
            connectionReady = true
            tryStartPumps()
        case .disconnected, .cancelled:
            connection.removeObserver(self, forKeyPath: "state")
            teardown()
        case .invalid:
            connection.removeObserver(self, forKeyPath: "state")
            teardown()
        default:
            break
        }
    }

    func flowDidOpen() {
        flowOpen = true
        tryStartPumps()
    }

    private func tryStartPumps() {
        guard connectionReady, flowOpen, !tornDown else { return }
        os_log("bridge: pumping", log: bridgeLog, type: .default)
        pumpOutbound()
        pumpInbound()
    }

    private func pumpOutbound() {
        flow.readData { [weak self] data, error in
            guard let self = self, !self.tornDown else { return }
            if error != nil || data == nil || data!.isEmpty {
                self.connection.writeClose()
                return
            }
            let chunk = data!
            self.bytesOut += Int64(chunk.count)
            self.onBytesUpdated?(self.bytesOut, self.bytesIn)
            self.connection.write(chunk) { sendError in
                if sendError != nil {
                    self.teardown()
                    return
                }
                self.pumpOutbound()
            }
        }
    }

    private func pumpInbound() {
        connection.readMinimumLength(1, maximumLength: 65536) { [weak self] data, error in
            guard let self = self, !self.tornDown else { return }
            if let error = error {
                self.flow.closeWriteWithError(nil)
                self.teardown()
                return
            }
            guard let data = data, !data.isEmpty else {
                self.flow.closeWriteWithError(nil)
                self.teardown()
                return
            }
            self.bytesIn += Int64(data.count)
            self.onBytesUpdated?(self.bytesOut, self.bytesIn)
            self.flow.write(data) { writeError in
                if writeError != nil {
                    self.teardown()
                    return
                }
                self.pumpInbound()
            }
        }
    }

    func teardown() {
        guard !tornDown else { return }
        tornDown = true
        connection.cancel()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        onComplete(bytesOut, bytesIn)
    }
}
