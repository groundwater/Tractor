import Darwin
import Foundation
import NetworkExtension
import os.log

private let log = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "proxy")

class TransparentProxy: NETransparentProxyProvider {
    private let reporter = FlowReporter()
    private var activeBridges: [ObjectIdentifier: TCPBridge] = [:]
    private let bridgeLock = NSLock()

    /// Cached check for global IPv6 connectivity. Refreshed on proxy start.
    private(set) static var hasGlobalIPv6: Bool = checkGlobalIPv6()

    /// Returns true if any interface has a global-scope IPv6 address
    /// (not loopback, not link-local fe80::/10, not ULA fc00::/7).
    private static func checkGlobalIPv6() -> Bool {
        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0, let first = addrs else { return false }
        defer { freeifaddrs(first) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let ifa = cursor {
            defer { cursor = ifa.pointee.ifa_next }
            guard let sa = ifa.pointee.ifa_addr, sa.pointee.sa_family == AF_INET6 else { continue }
            let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            let b = sin6.sin6_addr.__u6_addr.__u6_addr8
            // Skip loopback (::1)
            if b.0 == 0 && b.1 == 0 && b.2 == 0 && b.3 == 0 &&
               b.4 == 0 && b.5 == 0 && b.6 == 0 && b.7 == 0 &&
               b.8 == 0 && b.9 == 0 && b.10 == 0 && b.11 == 0 &&
               b.12 == 0 && b.13 == 0 && b.14 == 0 && b.15 == 1 { continue }
            // Skip link-local (fe80::/10)
            if b.0 == 0xfe && (b.1 & 0xc0) == 0x80 { continue }
            // Skip ULA (fc00::/7)
            if (b.0 & 0xfe) == 0xfc { continue }
            // Found a global IPv6 address
            os_log("global IPv6 found on %{public}@", log: log, type: .default,
                   String(cString: ifa.pointee.ifa_name))
            return true
        }
        return false
    }

    override func startProxy(options: [String: Any]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("startProxy called", log: log, type: .default)
        TransparentProxy.hasGlobalIPv6 = TransparentProxy.checkGlobalIPv6()
        os_log("global IPv6: %{public}@", log: log, type: .default, TransparentProxy.hasGlobalIPv6 ? "yes" : "no")

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

        let remote = tcp.remoteEndpoint as? NWHostEndpoint
        let pid = flow.metaData.sourceAppAuditToken.map { auditTokenPID($0) } ?? -1
        guard reporter.isWatched(pid) else { return false }

        let host = remote?.hostname ?? "?"
        let port = remote?.port ?? "0"
        guard let portNum = UInt16(port), portNum > 0 else { return false }

        // Always report the flow for visibility
        reporter.reportFlow(pid: pid, host: host, port: port, proto: "tcp")

        // Skip IPv6 flows when the host lacks global IPv6 connectivity.
        // createTCPConnection can't reach global IPv6 addresses without a
        // routable address, and claiming the flow would make the app think
        // the connection succeeded (stalling until timeout). Returning false
        // lets the NE framework reject the flow so the app sees the error
        // immediately.
        if host.contains(":") && !TransparentProxy.hasGlobalIPv6 {
            return false
        }

        // Use createTCPConnection — the NE framework's own async bypass API.
        // Despite being deprecated, it's the only API that creates connections
        // exempt from our own proxy interception.
        let endpoint = NWHostEndpoint(hostname: host, port: port)
        let conn = createTCPConnection(to: endpoint, enableTLS: false, tlsParameters: nil, delegate: nil)

        class BridgeBox { var bridge: TCPBridge? }
        let box = BridgeBox()

        let bridge = TCPBridge(flow: tcp, connection: conn) { [weak self] bytesOut, bytesIn in
            self?.reporter.reportBytes(pid: pid, host: host, port: port, bytesOut: bytesOut, bytesIn: bytesIn, closed: true)
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
                bridge.teardown()
                return
            }
            bridge.flowDidOpen()
        }
        return true
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
