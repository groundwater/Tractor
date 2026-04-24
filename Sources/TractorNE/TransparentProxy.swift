import Foundation
import NetworkExtension
import os.log

private let log = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "proxy")

class TransparentProxy: NETransparentProxyProvider {
    private let reporter = FlowReporter()
    private var activeBridges: [ObjectIdentifier: TCPBridge] = [:]
    private let bridgeLock = NSLock()

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy called", log: log, type: .default)

        // When watch list changes, enable/disable TCP interception
        reporter.onWatchListChanged = { [weak self] hasWatchedPids in
            self?.updateNetworkRules(hasWatchedPids: hasWatchedPids)
        }

        reporter.connect()
        os_log("proxy ready — no interception until CLI connects", log: log, type: .default)
        completionHandler(nil)
    }

    /// Called when watch list changes — enable TCP interception if PIDs are watched
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
        guard let portNum = UInt16(port), portNum > 0 else { return false }

        reporter.reportFlow(pid: pid, process: "", host: host, port: port, proto: "tcp")

        let endpoint = NWHostEndpoint(hostname: host, port: port)
        let remoteConnection = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)

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

        bridge.onBytesUpdated = { [weak self] bytesOut, bytesIn in
            self?.reporter.reportBytes(pid: pid, host: host, port: port, bytesOut: bytesOut, bytesIn: bytesIn)
        }

        bridgeLock.lock()
        activeBridges[ObjectIdentifier(bridge)] = bridge
        bridgeLock.unlock()

        tcp.open(withLocalFlowEndpoint: nil) { error in
            if let error = error {
                os_log("flow open error: %{public}@", log: log, type: .error, error.localizedDescription)
                tcp.closeReadWithError(error)
                tcp.closeWriteWithError(error)
                return
            }
            bridge.start()
        }
        return true
    }
}

private func auditTokenPID(_ token: Data) -> pid_t {
    guard token.count >= 24 else { return -1 }
    return token.withUnsafeBytes { buf in
        buf.load(fromByteOffset: 20, as: Int32.self)
    }
}
