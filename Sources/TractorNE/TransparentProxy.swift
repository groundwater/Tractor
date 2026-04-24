import Foundation
import NetworkExtension
import os.log

private let log = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "proxy")

class TransparentProxy: NETransparentProxyProvider {
    private let reporter = FlowReporter()

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy called", log: log, type: .default)

        reporter.onWatchListChanged = { [weak self] hasWatchedPids in
            self?.updateNetworkRules(hasWatchedPids: hasWatchedPids)
        }

        reporter.connect()
        os_log("proxy ready — no interception until CLI connects", log: log, type: .default)
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("proxy stopped, reason: %{public}@", log: log, type: .default, String(describing: reason))
        reporter.disconnect()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow else { return false }

        let pid = flow.metaData.sourceAppAuditToken.map { auditTokenPID($0) } ?? -1
        guard reporter.isWatched(pid) else { return false }

        let remote = tcp.remoteEndpoint as? NWHostEndpoint
        let host = remote?.hostname ?? "?"
        let port = remote?.port ?? "0"

        // Trace-only: report metadata, let OS handle the connection
        reporter.reportFlow(pid: pid, process: "", host: host, port: port, proto: "tcp")
        return false
    }

    func updateNetworkRules(hasWatchedPids: Bool) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        if hasWatchedPids {
            let tcpRule = NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0, protocol: .TCP, direction: .outbound)
            settings.includedNetworkRules = [tcpRule]
        } else {
            settings.includedNetworkRules = []
        }
        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                os_log("failed to update network rules: %{public}@", log: log, type: .error, error.localizedDescription)
            }
        }
    }
}

private func auditTokenPID(_ token: Data) -> pid_t {
    guard token.count >= 24 else { return -1 }
    return token.withUnsafeBytes { buf in
        buf.load(fromByteOffset: 20, as: Int32.self)
    }
}
