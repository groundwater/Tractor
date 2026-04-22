import Foundation

/// Captures TLS ClientHello packets on the network interface and extracts
/// SNI (Server Name Indication) hostnames, building an IP -> hostname map.
final class SNISniffer {
    private let lock = NSLock()
    private var sniMap: [String: String] = [:]  // IP -> hostname
    private var pcapHandle: OpaquePointer?
    private var captureThread: Thread?
    private var running = false

    /// Start capturing on the default interface
    func start() {
        running = true
        captureThread = Thread { [weak self] in
            self?.captureLoop()
        }
        captureThread?.qualityOfService = .utility
        captureThread?.start()
    }

    func stop() {
        running = false
        if let handle = pcapHandle {
            pcap_breakloop(handle)
        }
    }

    /// Look up hostname for an IP
    func hostname(for ip: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return sniMap[ip]
    }

    private func captureLoop() {
        var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))

        // Find first non-loopback interface
        var devs: UnsafeMutablePointer<pcap_if_t>?
        guard pcap_findalldevs(&devs, &errbuf) == 0, devs != nil else { return }
        defer { pcap_freealldevs(devs) }
        var device = "en0"  // fallback
        var dev = devs
        while let d = dev {
            let name = String(cString: d.pointee.name)
            let flags = d.pointee.flags
            // Skip loopback, pick first UP interface
            if flags & UInt32(PCAP_IF_LOOPBACK) == 0 && flags & UInt32(PCAP_IF_UP) != 0 {
                device = name
                break
            }
            dev = d.pointee.next
        }

        // Open for capture
        guard let handle = pcap_open_live(device, 1500, 0, 100, &errbuf) else {
            fputs("SNISniffer: failed to open \(device): \(String(cString: errbuf))\n", stderr)
            return
        }
        pcapHandle = handle

        // BPF filter: TCP to port 443, capture only SYN and first data packets
        var filter = bpf_program()
        let filterStr = "tcp dst port 443"
        if pcap_compile(handle, &filter, filterStr, 1, UInt32(PCAP_NETMASK_UNKNOWN)) == 0 {
            pcap_setfilter(handle, &filter)
            pcap_freecode(&filter)
        }

        // Capture loop
        while running {
            var header: UnsafeMutablePointer<pcap_pkthdr>?
            var data: UnsafePointer<UInt8>?
            let ret = pcap_next_ex(handle, &header, &data)
            if ret == 1, let hdr = header, let pkt = data {
                parsePacket(pkt, length: Int(hdr.pointee.caplen))
            } else if ret == -2 {
                break  // pcap_breakloop called
            }
        }

        pcap_close(handle)
        pcapHandle = nil
    }

    private func parsePacket(_ data: UnsafePointer<UInt8>, length: Int) {
        // Ethernet header: 14 bytes
        guard length > 14 else { return }
        let etherType = UInt16(data[12]) << 8 | UInt16(data[13])
        guard etherType == 0x0800 else { return }  // IPv4 only for now

        // IP header
        let ipOffset = 14
        guard length > ipOffset + 20 else { return }
        let ipHeaderLen = Int(data[ipOffset] & 0x0F) * 4
        let protocol_ = data[ipOffset + 9]
        guard protocol_ == 6 else { return }  // TCP

        // Destination IP
        let dstIP = "\(data[ipOffset + 16]).\(data[ipOffset + 17]).\(data[ipOffset + 18]).\(data[ipOffset + 19])"

        // TCP header
        let tcpOffset = ipOffset + ipHeaderLen
        guard length > tcpOffset + 20 else { return }
        let tcpHeaderLen = Int(data[tcpOffset + 12] >> 4) * 4

        // TLS payload
        let tlsOffset = tcpOffset + tcpHeaderLen
        guard length > tlsOffset + 5 else { return }

        // Check for TLS handshake (content type 0x16) and ClientHello (handshake type 0x01)
        guard data[tlsOffset] == 0x16 else { return }  // Handshake
        guard length > tlsOffset + 9 else { return }
        guard data[tlsOffset + 5] == 0x01 else { return }  // ClientHello

        // Parse ClientHello for SNI extension
        if let sni = extractSNI(data + tlsOffset, length: length - tlsOffset) {
            lock.lock()
            sniMap[dstIP] = sni
            lock.unlock()
        }
    }

    /// Parse TLS ClientHello and extract the SNI hostname
    private func extractSNI(_ data: UnsafePointer<UInt8>, length: Int) -> String? {
        // TLS record: [type(1)][version(2)][length(2)][handshake...]
        guard length > 5 else { return nil }
        let recordLen = Int(data[3]) << 8 | Int(data[4])
        let handshake = data + 5
        let hsLen = min(recordLen, length - 5)

        // Handshake: [type(1)][length(3)][version(2)][random(32)][session_id_len(1)][session_id...]
        guard hsLen > 38 else { return nil }
        var offset = 1 + 3 + 2 + 32  // skip type, length, version, random = 38

        // Session ID
        guard offset < hsLen else { return nil }
        let sessionIdLen = Int(handshake[offset])
        offset += 1 + sessionIdLen

        // Cipher suites
        guard offset + 2 <= hsLen else { return nil }
        let cipherSuitesLen = Int(handshake[offset]) << 8 | Int(handshake[offset + 1])
        offset += 2 + cipherSuitesLen

        // Compression methods
        guard offset + 1 <= hsLen else { return nil }
        let compMethodsLen = Int(handshake[offset])
        offset += 1 + compMethodsLen

        // Extensions
        guard offset + 2 <= hsLen else { return nil }
        let extensionsLen = Int(handshake[offset]) << 8 | Int(handshake[offset + 1])
        offset += 2

        let extensionsEnd = min(offset + extensionsLen, hsLen)
        while offset + 4 <= extensionsEnd {
            let extType = Int(handshake[offset]) << 8 | Int(handshake[offset + 1])
            let extLen = Int(handshake[offset + 2]) << 8 | Int(handshake[offset + 3])
            offset += 4

            if extType == 0x0000 {  // SNI extension
                // SNI: [list_length(2)][type(1)][name_length(2)][name...]
                guard offset + 5 <= extensionsEnd else { return nil }
                let nameLen = Int(handshake[offset + 3]) << 8 | Int(handshake[offset + 4])
                let nameStart = offset + 5
                guard nameStart + nameLen <= extensionsEnd else { return nil }
                let nameBytes = UnsafeBufferPointer(start: handshake + nameStart, count: nameLen)
                return String(bytes: nameBytes, encoding: .utf8)
            }

            offset += extLen
        }

        return nil
    }
}
