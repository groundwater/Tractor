import Foundation
import NetworkExtension

/// Transparent proxy provider that traces TCP connections.
///
/// Operates in trace-only mode: logs connection metadata (PID, remote host,
/// port) for watched PIDs, then returns false to let the OS handle the
/// actual connection natively. No bytes are proxied, no connections are
/// owned, no relay code needed.
///
/// When Tractor exits, all connections continue unaffected because we
/// never took ownership of them.
class TransparentProxy: NETransparentProxyProvider {
    private let reporter = FlowReporter()

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
            NSLog("TractorNE: network settings applied — trace mode, filtering by watched PIDs")
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

        // Only trace flows from watched PIDs
        guard reporter.isWatched(pid) else {
            return false
        }

        // Extract connection metadata
        let remote = tcp.remoteEndpoint as? NWHostEndpoint
        let host = remote?.hostname ?? "?"
        let port = remote?.port ?? "0"

        // Report to CLI
        reporter.reportFlow(pid: pid, process: "", host: host, port: port, proto: "tcp")

        // Return false: we logged the metadata, now let the OS handle
        // the connection natively. No proxying, no relay, no ownership.
        return false
    }
}

/// Extract PID from an audit token
private func auditTokenPID(_ token: Data) -> pid_t {
    guard token.count >= 24 else { return -1 }
    return token.withUnsafeBytes { buf in
        buf.load(fromByteOffset: 20, as: Int32.self)
    }
}
