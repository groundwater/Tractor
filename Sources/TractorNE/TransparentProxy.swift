import Foundation
import NetworkExtension

/// Transparent proxy provider that intercepts and relays TCP connections
/// for watched PIDs.
///
/// Each accepted flow is bridged to the remote via an NWConnection.
/// Bytes are counted in both directions and reported to the CLI.
/// Unwatched PIDs return false (OS handles natively, zero overhead).
class TransparentProxy: NETransparentProxyProvider {
    private let reporter = FlowReporter()

    /// Keep strong references to active bridges so they don't get deallocated
    private var activeBridges: [ObjectIdentifier: TCPBridge] = [:]
    private let bridgeLock = NSLock()

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        NSLog("TractorNE: proxy started, connecting to CLI via socket")
        reporter.connect()

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let tcpRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .TCP,
            direction: .outbound
        )

        settings.includedNetworkRules = [tcpRule]

        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                NSLog("TractorNE: failed to set network settings: \(error)")
                completionHandler(error)
                return
            }
            NSLog("TractorNE: network settings applied — proxy mode, filtering by watched PIDs")
            completionHandler(nil)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("TractorNE: proxy stopped, reason: \(reason)")
        reporter.disconnect()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow else {
            return false
        }

        let pid = flow.metaData.sourceAppAuditToken.map { auditTokenPID($0) } ?? -1

        guard reporter.isWatched(pid) else {
            return false
        }

        let remote = tcp.remoteEndpoint as? NWHostEndpoint
        let host = remote?.hostname ?? "?"
        let port = remote?.port ?? "0"
        let portNum = UInt16(port) ?? 0

        guard portNum > 0 else {
            return false  // Can't bridge without a valid port
        }

        // Report connection start
        reporter.reportFlow(pid: pid, process: "", host: host, port: port, proto: "tcp")

        // Create a TCP connection that bypasses the proxy (via NETunnelProvider)
        let endpoint = NWHostEndpoint(hostname: host, port: port)
        let remoteConnection = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)

        // Create bridge: flow ↔ remoteConnection
        class BridgeBox { var bridge: TCPBridge? }
        let box = BridgeBox()

        let bridge = TCPBridge(flow: tcp, connection: remoteConnection) { [weak self] bytesOut, bytesIn in
            self?.reporter.reportBytes(pid: pid, host: host, port: port, bytesOut: bytesOut, bytesIn: bytesIn)

            if let self = self, let b = box.bridge {
                self.bridgeLock.lock()
                self.activeBridges.removeValue(forKey: ObjectIdentifier(b))
                self.bridgeLock.unlock()
            }
        }
        box.bridge = bridge

        // Live byte count updates
        bridge.onBytesUpdated = { [weak self] bytesOut, bytesIn in
            self?.reporter.reportBytes(pid: pid, host: host, port: port, bytesOut: bytesOut, bytesIn: bytesIn)
        }

        bridgeLock.lock()
        activeBridges[ObjectIdentifier(bridge)] = bridge
        bridgeLock.unlock()

        // Open the flow, then start the bridge
        tcp.open(withLocalFlowEndpoint: nil) { error in
            if let error = error {
                NSLog("TractorNE: flow open error for \(host):\(port): \(error)")
                tcp.closeReadWithError(error)
                tcp.closeWriteWithError(error)
                return
            }
            bridge.start()
        }

        return true
    }
}

/// Extract PID from an audit token
private func auditTokenPID(_ token: Data) -> pid_t {
    guard token.count >= 24 else { return -1 }
    return token.withUnsafeBytes { buf in
        buf.load(fromByteOffset: 20, as: Int32.self)
    }
}
