import Foundation
import NetworkExtension

/// Bridges an NEAppProxyTCPFlow to the remote via NETunnelProviderSession.
///
/// Uses createTCPConnection (from NETunnelProvider) which bypasses the proxy,
/// preventing the sysext from intercepting its own outbound connections.
///
/// Two independent loops:
///   - Outbound: flow.readData → connection.write  (app → remote)
///   - Inbound:  connection.readData → flow.write   (remote → app)
///
/// Tracks byte counts in both directions.
final class TCPBridge: NSObject {
    private let flow: NEAppProxyTCPFlow
    private let connection: NWTCPConnection
    private let onComplete: (Int64, Int64) -> Void

    /// Called on each chunk with cumulative byte counts
    var onBytesUpdated: ((Int64, Int64) -> Void)?

    private var bytesOut: Int64 = 0
    private var bytesIn: Int64 = 0
    private var tornDown = false

    init(flow: NEAppProxyTCPFlow, connection: NWTCPConnection, onComplete: @escaping (Int64, Int64) -> Void) {
        self.flow = flow
        self.connection = connection
        self.onComplete = onComplete
    }

    func start() {
        // Wait for connection to be ready before pumping
        connection.addObserver(self, forKeyPath: "state", options: [.new], context: nil)
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?,
                               change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard keyPath == "state" else { return }
        switch connection.state {
        case .connected:
            connection.removeObserver(self, forKeyPath: "state")
            pumpOutbound()
            pumpInbound()
        case .disconnected, .cancelled:
            connection.removeObserver(self, forKeyPath: "state")
            teardown()
        case .invalid:
            connection.removeObserver(self, forKeyPath: "state")
            NSLog("TractorNE: bridge connection invalid")
            teardown()
        default:
            break
        }
    }

    /// Read from app, send to remote
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
                if let sendError = sendError {
                    NSLog("TractorNE: bridge send error: \(sendError)")
                    self.teardown()
                    return
                }
                self.pumpOutbound()
            }
        }
    }

    /// Read from remote, send to app
    private func pumpInbound() {
        connection.readMinimumLength(1, maximumLength: 65536) { [weak self] data, error in
            guard let self = self, !self.tornDown else { return }
            if let error = error {
                self.flow.closeWriteWithError(nil)
                if !self.tornDown { self.teardown() }
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
                if let writeError = writeError {
                    self.teardown()
                    return
                }
                self.pumpInbound()
            }
        }
    }

    private func teardown() {
        guard !tornDown else { return }
        tornDown = true
        connection.cancel()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        onComplete(bytesOut, bytesIn)
    }
}
