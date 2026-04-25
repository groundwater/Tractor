import Foundation
import Network
import Security

/// Handles MITM for all intercepted flows. Receives raw TLS bytes from the
/// sysext via XPC, terminates TLS (fake cert), captures plaintext, forwards
/// to the real server, and sends encrypted responses back.
final class MITMProxy: NSObject, TractorCLIXPC {
    private var sessions: [UInt64: MITMSession] = [:]
    private let sessionsLock = NSLock()
    private let caCertPEM: String
    private let caKeyPEM: String

    /// Called with plaintext traffic chunks (pid, host, port, direction "up"/"down", content)
    var onTraffic: ((pid_t, String, UInt16, String, String, UInt64) -> Void)?
    /// Send data back to sysext
    var sendToSysext: ((UInt64, Data) -> Void)?
    /// Notify sysext to close a flow
    var closeSysextFlow: ((UInt64) -> Void)?

    init(caCertPEM: String, caKeyPEM: String) {
        self.caCertPEM = caCertPEM
        self.caKeyPEM = caKeyPEM
    }

    // MARK: - TractorCLIXPC

    func openFlow(id: UInt64, host: NSString, port: UInt16, pid: Int32) {
        let hostname = host as String
        // logged silently — TUI shows connection rows

        // Generate leaf cert PKCS12 for this hostname
        let p12Data: Data
        do {
            p12Data = try createP12ForHostname( hostname)
        } catch {
            fatalError("MITMProxy: P12 generation failed for \(hostname): \(error)")
        }

        // Import PKCS12 to get SecIdentity
        let options: [String: Any] = [kSecImportExportPassphrase as String: "tractor"]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess,
              let array = items as? [[String: Any]],
              let first = array.first,
              let identity = first[kSecImportItemIdentity as String] as! SecIdentity? else {
            fatalError("MITMProxy: SecPKCS12Import failed for \(hostname): OSStatus \(status)")
        }

        let session = MITMSession(
            id: id, hostname: hostname, port: port, pid: pid,
            identity: identity,
            sendToSysext: { [weak self] data in
                self?.sendToSysext?(id, data)
            },
            onClose: { [weak self] in
                self?.closeSysextFlow?(id)
                self?.sessionsLock.lock()
                self?.sessions.removeValue(forKey: id)
                self?.sessionsLock.unlock()
            },
            onPlaintext: { [weak self] direction, content in
                self?.onTraffic?(pid, hostname, port, direction, content, id)
            }
        )

        sessionsLock.lock()
        sessions[id] = session
        sessionsLock.unlock()

        session.start()
    }

    func flowData(id: UInt64, data: Data) {
        sessionsLock.lock()
        let session = sessions[id]
        sessionsLock.unlock()
        session?.receiveFromApp(data)
    }

    func closeFlow(id: UInt64) {
        sessionsLock.lock()
        let session = sessions.removeValue(forKey: id)
        sessionsLock.unlock()
        session?.close()
    }

    // MARK: - P12 generation via openssl

    private var p12Cache: [String: Data] = [:]
    private let p12CacheLock = NSLock()

    // MARK: - TractorCLIXPC: generateP12 (called by sysext)

    func generateP12(hostname: NSString, reply: @escaping (Data) -> Void) {
        let host = hostname as String
        // P12 generation — no log needed, leaf cert import logged by sysext
        DispatchQueue.global().async { [self] in
            do {
                let data = try self.createP12ForHostname(host)
                // P12 generated successfully
                reply(data)
            } catch {
                fatalError("MITMProxy: P12 generation failed for \(host): \(error)")
            }
        }
    }

    private func createP12ForHostname(_ hostname: String) throws -> Data {
        p12CacheLock.lock()
        if let cached = p12Cache[hostname] {
            p12CacheLock.unlock()
            return cached
        }
        p12CacheLock.unlock()

        let tmpDir = NSTemporaryDirectory() + "tractor-mitm-\(UUID().uuidString)/"
        try FileManager.default.createDirectory(atPath: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmpDir) }

        let caKeyPath = tmpDir + "ca.key"
        let caCertPath = tmpDir + "ca.crt"
        let leafKeyPath = tmpDir + "leaf.key"
        let leafCsrPath = tmpDir + "leaf.csr"
        let leafCertPath = tmpDir + "leaf.crt"
        let p12Path = tmpDir + "leaf.p12"
        let extPath = tmpDir + "ext.cnf"

        try caKeyPEM.write(toFile: caKeyPath, atomically: true, encoding: .utf8)
        try caCertPEM.write(toFile: caCertPath, atomically: true, encoding: .utf8)
        try runOpenSSL(["ecparam", "-genkey", "-name", "prime256v1", "-out", leafKeyPath])
        try runOpenSSL(["req", "-new", "-key", leafKeyPath, "-out", leafCsrPath,
                        "-subj", "/CN=\(hostname)"])
        try "subjectAltName=DNS:\(hostname)".write(toFile: extPath, atomically: true, encoding: .utf8)
        try runOpenSSL(["x509", "-req", "-sha256", "-in", leafCsrPath, "-CA", caCertPath, "-CAkey", caKeyPath,
                        "-CAcreateserial", "-out", leafCertPath, "-days", "365", "-extfile", extPath])
        try runOpenSSL(["pkcs12", "-export", "-out", p12Path, "-inkey", leafKeyPath,
                        "-in", leafCertPath, "-passout", "pass:tractor"])

        let data = try Data(contentsOf: URL(fileURLWithPath: p12Path))

        p12CacheLock.lock()
        p12Cache[hostname] = data
        p12CacheLock.unlock()

        return data
    }

    private func runOpenSSL(_ args: [String]) throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        proc.arguments = args
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            fatalError("openssl \(args.first ?? "") failed with exit code \(proc.terminationStatus)")
        }
    }
}

// MARK: - Per-flow MITM session

/// Handles a single MITM'd connection:
///   App ←TLS(fake cert)→ [this session] ←TLS(real)→ Remote server
final class MITMSession {
    let id: UInt64
    let hostname: String
    let port: UInt16
    let pid: Int32
    private let identity: SecIdentity
    private let sendToSysext: (Data) -> Void
    private let onClose: () -> Void
    private let onPlaintext: (String, String) -> Void  // (direction "up"/"down", content)

    private var sslContext: SSLContext?
    var sslReadBuffer = Data()       // accessed by C callbacks
    var sslWriteBuffer = Data()      // accessed by C callbacks
    private var handshakeComplete = false
    private var tornDown = false

    // Real server connection
    private var serverConnection: NWConnection?

    init(id: UInt64, hostname: String, port: UInt16, pid: Int32,
         identity: SecIdentity,
         sendToSysext: @escaping (Data) -> Void,
         onClose: @escaping () -> Void,
         onPlaintext: @escaping (String, String) -> Void) {
        self.id = id
        self.hostname = hostname
        self.port = port
        self.pid = pid
        self.identity = identity
        self.sendToSysext = sendToSysext
        self.onClose = onClose
        self.onPlaintext = onPlaintext
    }

    func start() {
        // Set up Secure Transport as TLS server (fake cert toward the app)
        guard let ctx = SSLCreateContext(nil, SSLProtocolSide.serverSide, SSLConnectionType.streamType) else {
            fatalError("MITMSession \(id): SSLCreateContext failed")
        }
        sslContext = ctx

        let selfPtr = Unmanaged.passUnretained(self).toOpaque()
        SSLSetConnection(ctx, selfPtr)
        SSLSetIOFuncs(ctx, mitmSessionSSLRead, mitmSessionSSLWrite)

        let certStatus = SSLSetCertificate(ctx, [identity] as CFArray)
        if certStatus != errSecSuccess {
            fatalError("MITMSession \(id): SSLSetCertificate failed: \(certStatus)")
        }

        // Connect to the real server
        let tlsOptions = NWProtocolTLS.Options()
        let tcpOptions = NWProtocolTCP.Options()
        let params = NWParameters(tls: tlsOptions, tcp: tcpOptions)
        let conn = NWConnection(host: NWEndpoint.Host(hostname), port: NWEndpoint.Port(rawValue: port)!, using: params)
        serverConnection = conn

        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                // server connection ready
                self.pumpFromServer()
            case .failed(let error):
                fatalError("MITMSession \(self.id): server connection failed: \(error)")
            case .cancelled:
                break
            default:
                break
            }
        }
        conn.start(queue: .main)
    }

    /// Called when raw TLS bytes arrive from the app (via sysext XPC).
    func receiveFromApp(_ data: Data) {
        guard !tornDown else { return }
        sslReadBuffer.append(data)
        driveSSL()
    }

    func close() {
        guard !tornDown else { return }
        tornDown = true
        if let ctx = sslContext {
            SSLClose(ctx)
            sslContext = nil
        }
        serverConnection?.cancel()
        serverConnection = nil
    }

    // MARK: - SSL state machine

    private func driveSSL() {
        guard let ctx = sslContext, !tornDown else { return }

        if !handshakeComplete {
            let status = SSLHandshake(ctx)
            if status == noErr {
                // TLS handshake complete
                handshakeComplete = true
                flushSSLWriteBuffer()
                driveSSL() // try reading plaintext now
            } else if status == errSSLWouldBlock {
                flushSSLWriteBuffer()
            } else {
                // Client rejected our cert (e.g. CA not trusted) — not a bug, just close
                // Client rejected cert — close silently
                close()
                onClose()
            }
            return
        }

        // Handshake done — read plaintext from app
        var allPlaintext = Data()
        while true {
            var buf = [UInt8](repeating: 0, count: 65536)
            var processed = 0
            let status = SSLRead(ctx, &buf, buf.count, &processed)
            if processed > 0 {
                allPlaintext.append(contentsOf: buf[..<processed])
            }
            if status != noErr { break }
        }

        if !allPlaintext.isEmpty {
            // Report plaintext to TUI
            if let text = String(data: allPlaintext, encoding: .utf8) {
                onPlaintext("up", text)
            }

            // Forward plaintext to real server
            serverConnection?.send(content: allPlaintext, completion: .contentProcessed { [weak self] error in
                if let error = error {
                    // server send error
                    self?.close()
                    self?.onClose()
                }
            })
        }

        flushSSLWriteBuffer()
    }

    /// Pump data from real server → encrypt → send back to app via sysext
    private func pumpFromServer() {
        guard !tornDown else { return }
        serverConnection?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self, !self.tornDown else { return }
            if let error = error {
                // server receive error
                self.close()
                self.onClose()
                return
            }
            guard let data = data, !data.isEmpty else {
                if isComplete { self.close(); self.onClose() }
                return
            }

            // Report plaintext to TUI
            if let text = String(data: data, encoding: .utf8) {
                self.onPlaintext("down", text)
            }

            // Encrypt via SSL and send to app
            guard let ctx = self.sslContext else { return }
            data.withUnsafeBytes { buf in
                var written = 0
                let ptr = buf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                while written < data.count {
                    var processed = 0
                    let status = SSLWrite(ctx, ptr + written, data.count - written, &processed)
                    written += processed
                    if status != noErr && status != errSSLWouldBlock { break }
                }
            }
            self.flushSSLWriteBuffer()

            // Keep reading
            self.pumpFromServer()
        }
    }

    private func flushSSLWriteBuffer() {
        guard !sslWriteBuffer.isEmpty else { return }
        let data = sslWriteBuffer
        sslWriteBuffer = Data()
        sendToSysext(data)
    }
}

// MARK: - Secure Transport callbacks for MITMSession

private func mitmSessionSSLRead(_ connection: SSLConnectionRef,
                                 _ data: UnsafeMutableRawPointer,
                                 _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let session = Unmanaged<MITMSession>.fromOpaque(connection).takeUnretainedValue()
    let available = session.sslReadBuffer.count
    if available == 0 {
        dataLength.pointee = 0
        return errSSLWouldBlock
    }
    let requested = dataLength.pointee
    let toRead = min(requested, available)
    session.sslReadBuffer.copyBytes(to: data.assumingMemoryBound(to: UInt8.self), count: toRead)
    session.sslReadBuffer.removeFirst(toRead)
    dataLength.pointee = toRead
    return toRead < requested ? errSSLWouldBlock : noErr
}

private func mitmSessionSSLWrite(_ connection: SSLConnectionRef,
                                  _ data: UnsafeRawPointer,
                                  _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let session = Unmanaged<MITMSession>.fromOpaque(connection).takeUnretainedValue()
    let count = dataLength.pointee
    session.sslWriteBuffer.append(data.assumingMemoryBound(to: UInt8.self), count: count)
    dataLength.pointee = count
    return noErr
}

private func extractFirstLine(from data: Data) -> String? {
    guard let idx = data.firstIndex(of: 0x0A) else { return nil }
    var end = idx
    if end > data.startIndex && data[data.index(before: end)] == 0x0D {
        end = data.index(before: end)
    }
    return String(data: data[data.startIndex..<end], encoding: .utf8)
}
