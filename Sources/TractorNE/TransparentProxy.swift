import Foundation
import NetworkExtension

/// Transparent proxy provider that intercepts all TCP/UDP flows.
/// When active, the OS routes every network connection through handleNewFlow().
class TransparentProxy: NETransparentProxyProvider {
    private let reporter = FlowReporter()

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        NSLog("TractorNE: proxy started, connecting to CLI via socket")
        reporter.connect()

        // Tell the OS to route ALL TCP and UDP flows through us
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        // Match all TCP traffic
        let tcpRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .TCP,
            direction: .outbound
        )

        // Match all UDP traffic
        let udpRule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .UDP,
            direction: .outbound
        )

        // Only intercept TCP for now — UDP relay requires a real socket
        // to forward datagrams, and broken UDP kills DNS (and this session).
        // TODO: add UDP interception with proper datagram forwarding
        settings.includedNetworkRules = [tcpRule]

        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                NSLog("TractorNE: failed to set network settings: \(error)")
                completionHandler(error)
                return
            }
            NSLog("TractorNE: network settings applied — intercepting all TCP/UDP")
            completionHandler(nil)
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("TractorNE: proxy stopped, reason: \(reason)")
        reporter.disconnect()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcp = flow as? NEAppProxyTCPFlow {
            let remote = tcp.remoteEndpoint as? NWHostEndpoint
            let pid = flow.metaData.sourceAppAuditToken.map { auditTokenPID($0) } ?? -1
            let host = remote?.hostname ?? "?"
            let port = remote?.port ?? "0"

            reporter.reportFlow(pid: pid, process: "", host: host, port: port, proto: "tcp")

            // Pass-through: open connection to remote and relay bytes
            let endpoint = remote ?? NWHostEndpoint(hostname: "127.0.0.1", port: "0")
            tcp.open(withLocalEndpoint: endpoint) { error in
                if let error = error {
                    NSLog("TractorNE: TCP open error: \(error)")
                    tcp.closeReadWithError(error)
                    tcp.closeWriteWithError(error)
                    return
                }
                self.relayTCP(tcp)
            }
            return true
        }

        // UDP flows are not intercepted (no network rules for UDP).
        // If we receive one anyway, let it pass through.
        if flow is NEAppProxyUDPFlow {
            return false
        }

        return false
    }

    // MARK: - TCP relay

    private func relayTCP(_ flow: NEAppProxyTCPFlow) {
        readTCPLoop(flow)
        writeTCPLoop(flow)
    }

    /// Read from app, write to network
    private func readTCPLoop(_ flow: NEAppProxyTCPFlow) {
        flow.readData { data, error in
            if let error = error {
                NSLog("TractorNE: TCP read error: \(error)")
                flow.closeReadWithError(error)
                return
            }
            guard let data = data, !data.isEmpty else {
                // EOF from app side
                flow.closeWriteWithError(nil)
                return
            }
            flow.write(data) { writeError in
                if let writeError = writeError {
                    NSLog("TractorNE: TCP write error: \(writeError)")
                    flow.closeWriteWithError(writeError)
                    return
                }
                self.readTCPLoop(flow)
            }
        }
    }

    /// Read from network, write to app
    private func writeTCPLoop(_ flow: NEAppProxyTCPFlow) {
        flow.readData { data, error in
            if let error = error {
                flow.closeReadWithError(error)
                return
            }
            guard let data = data, !data.isEmpty else {
                flow.closeReadWithError(nil)
                return
            }
            flow.write(data) { writeError in
                if let writeError = writeError {
                    flow.closeWriteWithError(writeError)
                    return
                }
                self.writeTCPLoop(flow)
            }
        }
    }

    // MARK: - UDP relay

    private func relayUDP(_ flow: NEAppProxyUDPFlow) {
        readUDPLoop(flow)
    }

    private func readUDPLoop(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { datagrams, endpoints, error in
            if let error = error {
                NSLog("TractorNE: UDP read error: \(error)")
                flow.closeReadWithError(error)
                return
            }
            guard let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else {
                flow.closeWriteWithError(nil)
                return
            }
            flow.writeDatagrams(datagrams, sentBy: endpoints) { writeError in
                if let writeError = writeError {
                    NSLog("TractorNE: UDP write error: \(writeError)")
                    flow.closeWriteWithError(writeError)
                    return
                }
                self.readUDPLoop(flow)
            }
        }
    }
}

/// Extract PID from an audit token
private func auditTokenPID(_ token: Data) -> pid_t {
    guard token.count >= 20 else { return -1 }
    return token.withUnsafeBytes { buf in
        // audit_token_t layout: 4 fields of uint32, pid is at index 5 (offset 20)
        // Actually: auid(4), euid(4), egid(4), ruid(4), rgid(4), pid(4), sid(4), tid(4)
        buf.load(fromByteOffset: 20, as: Int32.self)
    }
}
