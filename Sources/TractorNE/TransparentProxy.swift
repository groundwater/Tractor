import Foundation
import NetworkExtension

/// Transparent proxy provider that intercepts TCP flows.
///
/// Starts with TCP interception enabled but only accepts flows from PIDs
/// in the watch list (pushed by the CLI over the Unix socket). If no PIDs
/// are watched, all flows pass through untouched.
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
            NSLog("TractorNE: network settings applied — filtering by watched PIDs")
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
            return false  // Only handle TCP
        }

        let pid = flow.metaData.sourceAppAuditToken.map { auditTokenPID($0) } ?? -1

        // Only intercept flows from watched PIDs
        guard reporter.isWatched(pid) else {
            return false  // Pass through — OS handles it normally
        }

        let remote = tcp.remoteEndpoint as? NWHostEndpoint
        let host = remote?.hostname ?? "?"
        let port = remote?.port ?? "0"

        reporter.reportFlow(pid: pid, process: "", host: host, port: port, proto: "tcp")

        // Open the flow. For transparent proxies, the local endpoint parameter
        // is used by the framework to establish the remote connection.
        tcp.open(withLocalFlowEndpoint: nil) { error in
            if let error = error {
                NSLog("TractorNE: TCP open error for \(host):\(port): \(error)")
                tcp.closeReadWithError(error)
                tcp.closeWriteWithError(error)
            }
            // For transparent proxies, the kernel handles bidirectional
            // relay after open(). No readData/write loops needed.
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
