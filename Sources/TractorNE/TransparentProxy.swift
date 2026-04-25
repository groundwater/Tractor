import Darwin
import Foundation
import NetworkExtension
import os.log

private let log = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "proxy")

class TransparentProxy: NETransparentProxyProvider {
    private let reporter = FlowReporter()
    private var activeBridges: [ObjectIdentifier: AnyObject] = [:]
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
        if !reporter.isWatched(pid) {
            os_log("handleNewFlow: pid %d NOT watched, passing through", log: log, type: .default, pid)
            return false
        }

        let host = remote?.hostname ?? "?"
        let port = remote?.port ?? "0"
        guard let portNum = UInt16(port), portNum > 0 else { return false }

        // Skip IPv6 flows when the host lacks global IPv6 connectivity.
        // createTCPConnection can't reach global IPv6 addresses without a
        // routable address, and claiming the flow would make the app think
        // the connection succeeded (stalling until timeout). Returning false
        // lets the NE framework reject the flow so the app sees the error
        // immediately.
        if host.contains(":") && !TransparentProxy.hasGlobalIPv6 {
            return false
        }

        // Decide: MITM or passthrough
        let useMITM = reporter.mitmEnabled && isTLSPort(portNum)

        if useMITM {
            return handleMITMFlow(tcp, pid: pid, host: host, port: port, portNum: portNum)
        }

        reporter.reportFlow(pid: pid, host: host, port: port, proto: "tcp")
        // Passthrough: use createTCPConnection — the NE framework's own async bypass API.
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

    // MARK: - MITM flow handling

    private func handleMITMFlow(_ tcp: NEAppProxyTCPFlow, pid: Int32, host: String, port: String, portNum: UInt16) -> Bool {
        // Open the flow first, read the ClientHello to extract SNI,
        // then ask CLI for a leaf cert identity.
        tcp.open(withLocalFlowEndpoint: nil) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                os_log("MITM flow open error: %{public}@", log: log, type: .error, error.localizedDescription)
                tcp.closeReadWithError(error)
                tcp.closeWriteWithError(error)
                return
            }

            // Read the first chunk — should be the TLS ClientHello
            tcp.readData { firstData, readError in
                guard let firstData = firstData, !firstData.isEmpty else {
                    tcp.closeReadWithError(nil)
                    tcp.closeWriteWithError(nil)
                    return
                }

                // Extract SNI from ClientHello; fall back to the endpoint hostname/IP
                let sniHost = extractSNI(from: firstData) ?? host
                os_log("MITM: SNI=%{public}@ (endpoint=%{public}@)", log: log, type: .default, sniHost, host)

                // Report flow with the correct SNI hostname
                self.reporter.reportFlow(pid: pid, host: sniHost, port: port, proto: "tcp")

                // Ask CLI for a PKCS12 identity for this hostname
                guard let p12Data = self.reporter.requestP12(hostname: sniHost),
                      !p12Data.isEmpty else {
                    fatalError("MITM: CLI returned no P12 for \(sniHost)")
                }
                let options: [String: Any] = [kSecImportExportPassphrase as String: "tractor"]
                var items: CFArray?
                let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
                guard status == errSecSuccess,
                      let array = items as? [[String: Any]],
                      let first = array.first,
                      let identity = first[kSecImportItemIdentity as String] as! SecIdentity? else {
                    fatalError("MITM: SecPKCS12Import failed for \(sniHost): \(status)")
                }
                os_log("MITM: leaf cert for %{public}@ imported", log: log, type: .default, sniHost)

                // Outbound TLS to real server
                let endpoint = NWHostEndpoint(hostname: host, port: port)
                let conn = self.createTCPConnection(to: endpoint, enableTLS: true,
                                                    tlsParameters: nil, delegate: MITMTLSDelegate.shared)

                class MITMBox { var bridge: MITMBridge? }
                let box = MITMBox()

                let bridge = MITMBridge(flow: tcp, connection: conn, identity: identity) { [weak self] bytesOut, bytesIn in
                    self?.reporter.reportBytes(pid: pid, host: sniHost, port: port, bytesOut: bytesOut, bytesIn: bytesIn, closed: true)
                    if let self = self, let b = box.bridge {
                        self.bridgeLock.lock()
                        self.activeBridges.removeValue(forKey: ObjectIdentifier(b))
                        self.bridgeLock.unlock()
                    }
                }
                box.bridge = bridge

                bridge.onBytesUpdated = { [weak self] bytesOut, bytesIn in
                    self?.reporter.reportBytes(pid: pid, host: sniHost, port: port, bytesOut: bytesOut, bytesIn: bytesIn)
                }
                bridge.onHTTPRequest = { [weak self] line in
                    self?.reporter.reportHTTP(pid: pid, host: sniHost, port: port, direction: "request", line: line)
                }
                bridge.onHTTPResponse = { [weak self] line in
                    self?.reporter.reportHTTP(pid: pid, host: sniHost, port: port, direction: "response", line: line)
                }

                self.bridgeLock.lock()
                self.activeBridges[ObjectIdentifier(bridge)] = bridge
                self.bridgeLock.unlock()

                // Feed the ClientHello we already read into the bridge, then start
                bridge.flowDidOpenWithInitialData(firstData)
            }
        }
        return true
    }

    private func isTLSPort(_ port: UInt16) -> Bool {
        // Common TLS ports — MITM these; pass through others as plaintext
        switch port {
        case 443, 8443, 4443: return true
        default: return false
        }
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

/// Handles TLS trust evaluation for outbound MITM connections.
/// The sysext sandbox can't access the system trust store, so SecTrust
/// evaluation fails by default. We accept the server's certificate —
/// we're the MITM proxy, the real validation happened between the app
/// and our fake cert.
final class MITMTLSDelegate: NSObject, NWTCPConnectionAuthenticationDelegate {
    static let shared = MITMTLSDelegate()

    func shouldEvaluateTrust(for connection: NWTCPConnection) -> Bool {
        return true
    }

    func evaluateTrust(for connection: NWTCPConnection,
                       peerCertificateChain: [Any],
                       completionHandler: @escaping (SecTrust) -> Void) {
        let certs = peerCertificateChain.map { $0 as! SecCertificate }
        guard !certs.isEmpty else {
            fatalError("MITMTLSDelegate: empty peer certificate chain")
        }
        os_log("MITMTLSDelegate: evaluateTrust called with %d certs", log: log, type: .default, certs.count)
        var trust: SecTrust?
        // Use basic X509 policy (no hostname check needed for our MITM outbound)
        let policy = SecPolicyCreateBasicX509()
        SecTrustCreateWithCertificates(certs as CFArray, policy, &trust)
        guard let serverTrust = trust else {
            fatalError("MITMTLSDelegate: SecTrustCreateWithCertificates failed")
        }
        // Set the server's own root cert as the anchor — makes any chain trusted.
        // The sysext sandbox can't access the system trust store, so we must
        // explicitly provide anchors.
        SecTrustSetAnchorCertificates(serverTrust, certs as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        completionHandler(serverTrust)
    }

    func shouldProvideIdentity(for connection: NWTCPConnection) -> Bool {
        return false
    }
}

/// Extract Server Name Indication (SNI) from a TLS ClientHello.
private func extractSNI(from data: Data) -> String? {
    guard data.count > 5, data[0] == 0x16 else { return nil } // 0x16 = Handshake
    var offset = 5 // skip record header
    guard data.count > offset + 4, data[offset] == 0x01 else { return nil } // ClientHello
    offset += 4 // skip handshake header
    offset += 34 // skip version(2) + random(32)
    guard offset < data.count else { return nil }
    let sessionIDLen = Int(data[offset])
    offset += 1 + sessionIDLen
    guard offset + 2 <= data.count else { return nil }
    let cipherLen = Int(data[offset]) << 8 | Int(data[offset + 1])
    offset += 2 + cipherLen
    guard offset + 1 <= data.count else { return nil }
    let compLen = Int(data[offset])
    offset += 1 + compLen
    guard offset + 2 <= data.count else { return nil }
    let extLen = Int(data[offset]) << 8 | Int(data[offset + 1])
    offset += 2
    let extEnd = min(offset + extLen, data.count)
    while offset + 4 <= extEnd {
        let extType = Int(data[offset]) << 8 | Int(data[offset + 1])
        let extDataLen = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
        offset += 4
        if extType == 0x0000, extDataLen > 5, offset + extDataLen <= data.count {
            let nameLen = Int(data[offset + 3]) << 8 | Int(data[offset + 4])
            let nameStart = offset + 5
            guard nameStart + nameLen <= data.count else { return nil }
            return String(data: data[nameStart..<nameStart + nameLen], encoding: .utf8)
        }
        offset += extDataLen
    }
    return nil
}

private func auditTokenPID(_ token: Data) -> pid_t {
    guard token.count >= 24 else { return -1 }
    return token.withUnsafeBytes { buf in
        buf.load(fromByteOffset: 20, as: Int32.self)
    }
}
