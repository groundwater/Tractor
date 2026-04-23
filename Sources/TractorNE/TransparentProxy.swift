import Foundation
import NetworkExtension

/// Transparent proxy provider that intercepts all TCP/UDP flows.
/// When active, the OS routes every network connection through handleNewFlow().
class TransparentProxy: NETransparentProxyProvider {

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        NSLog("TractorNE: proxy started")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        NSLog("TractorNE: proxy stopped, reason: \(reason)")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcp = flow as? NEAppProxyTCPFlow {
            let remote = tcp.remoteEndpoint as? NWHostEndpoint
            let pid = flow.metaData.sourceAppAuditToken.map { auditTokenPID($0) } ?? -1
            NSLog("TractorNE: TCP flow pid=\(pid) -> \(remote?.hostname ?? "?"):\(remote?.port ?? "0")")

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

        if let udp = flow as? NEAppProxyUDPFlow {
            let pid = flow.metaData.sourceAppAuditToken.map { auditTokenPID($0) } ?? -1
            NSLog("TractorNE: UDP flow pid=\(pid)")

            let endpoint = NWHostEndpoint(hostname: "0.0.0.0", port: "0")
            udp.open(withLocalEndpoint: endpoint) { error in
                if let error = error {
                    NSLog("TractorNE: UDP open error: \(error)")
                    udp.closeReadWithError(error)
                    udp.closeWriteWithError(error)
                    return
                }
                self.relayUDP(udp)
            }
            return true
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
