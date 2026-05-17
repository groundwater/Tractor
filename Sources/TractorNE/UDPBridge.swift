import Foundation
import NetworkExtension
import os.log

private let udpLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "udp")

/// Proxies an NEAppProxyUDPFlow: read datagrams from the app, forward to
/// their destinations via createUDPSession; read replies, write back to
/// the flow tagged with the source endpoint.
///
/// One UDP flow can carry datagrams to multiple remote endpoints (UDP is
/// connectionless), so we maintain a per-destination session map.
/// Byte counts are aggregated across all destinations on the flow.
final class UDPBridge {
    private let flow: NEAppProxyUDPFlow
    private weak var provider: NEAppProxyProvider?
    private let onComplete: (Int64, Int64) -> Void
    var onBytesUpdated: ((Int64, Int64) -> Void)?

    private var sessions: [String: NWUDPSession] = [:]
    private let sessionLock = NSLock()
    private var bytesOut: Int64 = 0
    private var bytesIn: Int64 = 0
    private var tornDown = false

    init(flow: NEAppProxyUDPFlow, provider: NEAppProxyProvider,
         onComplete: @escaping (Int64, Int64) -> Void) {
        self.flow = flow
        self.provider = provider
        self.onComplete = onComplete
    }

    /// Open the flow then start the read-from-app pump. Each datagram
    /// fetches/creates a session and forwards.
    func start() {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            if let error = error {
                os_log("UDP flow open error: %{public}@", log: udpLog, type: .error, error.localizedDescription)
                self?.teardown()
                return
            }
            self?.pumpOutbound()
        }
    }

    func teardown() {
        guard !tornDown else { return }
        tornDown = true
        sessionLock.lock()
        let snapshot = sessions
        sessions.removeAll()
        sessionLock.unlock()
        for (_, s) in snapshot { s.cancel() }
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        onComplete(bytesOut, bytesIn)
    }

    private func pumpOutbound() {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self = self, !self.tornDown else { return }
            if error != nil || datagrams == nil || endpoints == nil || (datagrams?.isEmpty ?? true) {
                self.teardown(); return
            }
            let datagrams = datagrams!
            let endpoints = endpoints!
            guard datagrams.count == endpoints.count else {
                os_log("UDP: datagrams/endpoints length mismatch (%d vs %d)",
                       log: udpLog, type: .error, datagrams.count, endpoints.count)
                self.teardown(); return
            }
            for i in 0..<datagrams.count {
                let datagram = datagrams[i]
                let endpoint = endpoints[i]
                guard let session = self.sessionFor(endpoint) else { continue }
                self.bytesOut += Int64(datagram.count)
                session.writeDatagram(datagram) { writeErr in
                    if let writeErr = writeErr {
                        os_log("UDP write error: %{public}@", log: udpLog,
                               type: .error, writeErr.localizedDescription)
                    }
                }
            }
            self.onBytesUpdated?(self.bytesOut, self.bytesIn)
            // Loop — read more datagrams.
            self.pumpOutbound()
        }
    }

    /// Get-or-create a UDP session for the given destination, with the
    /// reply pump wired up to write back into the flow.
    private func sessionFor(_ endpoint: NWEndpoint) -> NWUDPSession? {
        let key = sessionKey(endpoint)
        sessionLock.lock()
        if let existing = sessions[key] {
            sessionLock.unlock()
            return existing
        }
        guard let provider = provider else { sessionLock.unlock(); return nil }
        let session = provider.createUDPSession(to: endpoint, from: nil)
        sessions[key] = session
        sessionLock.unlock()

        // Reply pump for this destination — write back to the flow with
        // the source endpoint matching where we sent to.
        session.setReadHandler({ [weak self] datagrams, _ in
            guard let self = self, !self.tornDown,
                  let datagrams = datagrams, !datagrams.isEmpty else { return }
            var inbound: Int64 = 0
            for d in datagrams { inbound += Int64(d.count) }
            self.bytesIn += inbound
            let endpoints = [NWEndpoint](repeating: endpoint, count: datagrams.count)
            self.flow.writeDatagrams(datagrams, sentBy: endpoints) { writeErr in
                if let writeErr = writeErr {
                    os_log("UDP flow writeDatagrams error: %{public}@",
                           log: udpLog, type: .error, writeErr.localizedDescription)
                }
            }
            self.onBytesUpdated?(self.bytesOut, self.bytesIn)
        }, maxDatagrams: 32)

        return session
    }

    private func sessionKey(_ endpoint: NWEndpoint) -> String {
        if let host = endpoint as? NWHostEndpoint {
            return "\(host.hostname):\(host.port)"
        }
        return String(describing: endpoint)
    }
}

/// Pull host:port out of an NWEndpoint for reporting. Returns ("?", "0")
/// if the endpoint isn't a hostname endpoint we can read.
func endpointHostPort(_ endpoint: NWEndpoint?) -> (host: String, port: String) {
    if let h = endpoint as? NWHostEndpoint { return (h.hostname, h.port) }
    return ("?", "0")
}
