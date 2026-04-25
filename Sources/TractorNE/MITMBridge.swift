import Foundation
import NetworkExtension
import Security
import os.log

private let mitmLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "mitm")

/// Bridges an NEAppProxyTCPFlow through a TLS MITM:
///
///   App ←TLS(fake cert)→ MITMBridge ←TLS(real)→ Remote
///
/// Client side: Secure Transport in server mode with a dynamically-generated
/// certificate (SecIdentity from PKCS12 import — no keychain needed).
///
/// Server side: NWTCPConnection with enableTLS:true — reads/writes plaintext.
final class MITMBridge: NSObject {

    // MARK: - State

    private enum State {
        case setup
        case handshaking
        case streaming
        case tornDown
    }

    private let flow: NEAppProxyTCPFlow
    private let connection: NWTCPConnection
    private let identity: SecIdentity
    private let onComplete: (Int64, Int64) -> Void

    var onBytesUpdated: ((Int64, Int64) -> Void)?
    /// Reports decrypted plaintext: (direction "up"/"down", content)
    var onPlaintext: ((String, String) -> Void)?

    private var bytesOut: Int64 = 0
    private var bytesIn: Int64 = 0
    private var state: State = .setup
    private var flowOpen = false
    private var connectionReady = false

    // Secure Transport
    private var sslContext: SSLContext?

    // Buffers for bridging async flow I/O ↔ synchronous SSL callbacks
    private var sslReadBuffer = Data()
    private var sslWriteBuffer = Data()

    // HTTP line capture
    // (removed old HTTP line capture — now using onPlaintext for full content)

    init(flow: NEAppProxyTCPFlow, connection: NWTCPConnection,
         identity: SecIdentity, onComplete: @escaping (Int64, Int64) -> Void) {
        self.flow = flow
        self.connection = connection
        self.identity = identity
        self.onComplete = onComplete
        super.init()

        connection.addObserver(self, forKeyPath: "state", options: [.new, .initial], context: nil)
    }

    // MARK: - Connection state observation

    override func observeValue(forKeyPath keyPath: String?, of object: Any?,
                               change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard keyPath == "state" else { return }
        let s = connection.state
        os_log("MITM bridge: connection state = %d", log: mitmLog, type: .default, s.rawValue)
        switch s {
        case .connected:
            connection.removeObserver(self, forKeyPath: "state")
            connectionReady = true
            tryStart()
        case .waiting:
            // Connection attempted but failed — waiting to retry.
            // This likely means enableTLS:true is failing (cert validation? self-interception?)
            connection.removeObserver(self, forKeyPath: "state")
            fatalError("MITMBridge: outbound TLS connection entered .waiting state — the TLS connection to the real server failed. This may mean createTCPConnection(enableTLS:true) is being intercepted by our own proxy, or the server TLS handshake failed.")
        case .disconnected, .cancelled, .invalid:
            connection.removeObserver(self, forKeyPath: "state")
            fatalError("MITMBridge: outbound TLS connection failed (state=\(s.rawValue))")
        default:
            break
        }
    }

    func flowDidOpen() {
        os_log("MITM bridge: flow opened", log: mitmLog, type: .default)
        flowOpen = true
        tryStart()
    }

    /// Called when the flow was already opened and the first data (ClientHello) was pre-read.
    func flowDidOpenWithInitialData(_ data: Data) {
        os_log("MITM bridge: flow opened with %d initial bytes", log: mitmLog, type: .default, data.count)
        flowOpen = true
        sslReadBuffer.append(data)
        tryStart()
    }

    // MARK: - Startup

    private func tryStart() {
        guard flowOpen, connectionReady, state == .setup else { return }
        os_log("MITM bridge: starting handshake", log: mitmLog, type: .default)

        guard let ctx = SSLCreateContext(nil, SSLProtocolSide.serverSide, SSLConnectionType.streamType) else {
            os_log("MITM: SSLCreateContext failed", log: mitmLog, type: .error)
            teardown()
            return
        }
        sslContext = ctx

        let selfPtr = Unmanaged.passUnretained(self).toOpaque()
        SSLSetConnection(ctx, selfPtr)
        SSLSetIOFuncs(ctx, mitmSSLRead, mitmSSLWrite)

        let identityArray = [identity] as CFArray
        let certStatus = SSLSetCertificate(ctx, identityArray)
        if certStatus != errSecSuccess {
            os_log("MITM: SSLSetCertificate failed: %d", log: mitmLog, type: .error, certStatus)
            teardown()
            return
        }

        state = .handshaking
        // If we have pre-loaded data (ClientHello), drive SSL immediately
        if !sslReadBuffer.isEmpty {
            driveSSL()
        } else {
            readFromFlowAndDriveSSL()
        }
    }

    // MARK: - Event-driven SSL pump

    private func readFromFlowAndDriveSSL() {
        guard state == .handshaking || state == .streaming else { return }
        flow.readData { [weak self] data, error in
            guard let self = self, self.state != .tornDown else { return }
            if error != nil || data == nil || data!.isEmpty {
                self.teardown()
                return
            }
            self.sslReadBuffer.append(data!)
            self.driveSSL()
        }
    }

    private func flushWriteBuffer(then next: @escaping () -> Void) {
        guard !sslWriteBuffer.isEmpty else { next(); return }
        let chunk = sslWriteBuffer
        sslWriteBuffer = Data()
        flow.write(chunk) { [weak self] error in
            guard let self = self, self.state != .tornDown else { return }
            if error != nil { self.teardown(); return }
            next()
        }
    }

    private func driveSSL() {
        guard let ctx = sslContext else { return }

        switch state {
        case .handshaking:
            let status = SSLHandshake(ctx)
            switch status {
            case noErr:
                os_log("MITM: handshake complete", log: mitmLog, type: .default)
                state = .streaming
                flushWriteBuffer { [weak self] in
                    self?.readFromFlowAndDriveSSL()
                    self?.pumpInbound()
                }
            case errSSLWouldBlock:
                flushWriteBuffer { [weak self] in
                    self?.readFromFlowAndDriveSSL()
                }
            default:
                os_log("MITM: handshake failed: %d", log: mitmLog, type: .error, status)
                teardown()
            }

        case .streaming:
            os_log("MITM: driveSSL streaming, sslReadBuffer=%d bytes", log: mitmLog, type: .default, sslReadBuffer.count)
            var allPlaintext = Data()
            var lastStatus: OSStatus = noErr
            while true {
                var chunk = [UInt8](repeating: 0, count: 65536)
                var processed = 0
                lastStatus = SSLRead(ctx, &chunk, chunk.count, &processed)
                if processed > 0 {
                    allPlaintext.append(contentsOf: chunk[..<processed])
                }
                if lastStatus != noErr { break }
            }

            os_log("MITM: SSLRead got %d bytes, lastStatus=%d", log: mitmLog, type: .default, allPlaintext.count, lastStatus)
            if !allPlaintext.isEmpty {
                bytesOut += Int64(allPlaintext.count)
                onBytesUpdated?(bytesOut, bytesIn)

                if let text = String(data: allPlaintext, encoding: .utf8) {
                    os_log("MITM: reporting %d chars plaintext UP", log: mitmLog, type: .default, text.count)
                    onPlaintext?("up", text)
                }

                connection.write(allPlaintext) { [weak self] error in
                    if error != nil { self?.teardown() }
                }
            }

            switch lastStatus {
            case errSSLWouldBlock:
                flushWriteBuffer { [weak self] in
                    self?.readFromFlowAndDriveSSL()
                }
            case errSSLClosedGraceful, errSSLClosedAbort:
                connection.writeClose()
                teardown()
            default:
                os_log("MITM: SSLRead error: %d", log: mitmLog, type: .error, lastStatus)
                teardown()
            }

        default:
            break
        }
    }

    // MARK: - Inbound pump (server → client)

    private func pumpInbound() {
        guard state == .streaming else { return }
        connection.readMinimumLength(1, maximumLength: 65536) { [weak self] data, error in
            guard let self = self, self.state != .tornDown else { return }
            if error != nil || data == nil || data!.isEmpty {
                self.teardown()
                return
            }
            let plaintext = data!
            os_log("MITM: pumpInbound got %d bytes from server", log: mitmLog, type: .default, plaintext.count)
            self.bytesIn += Int64(plaintext.count)
            self.onBytesUpdated?(self.bytesOut, self.bytesIn)

            if let text = String(data: plaintext, encoding: .utf8) {
                os_log("MITM: reporting %d chars plaintext DOWN", log: mitmLog, type: .default, text.count)
                self.onPlaintext?("down", text)
            } else {
                os_log("MITM: pumpInbound data not valid UTF-8", log: mitmLog, type: .default)
            }

            guard let ctx = self.sslContext else { return }
            var totalWritten = 0
            plaintext.withUnsafeBytes { buf in
                let ptr = buf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                while totalWritten < plaintext.count {
                    var processed = 0
                    let status = SSLWrite(ctx, ptr + totalWritten,
                                          plaintext.count - totalWritten, &processed)
                    totalWritten += processed
                    if status != noErr && status != errSSLWouldBlock { break }
                }
            }

            self.flushWriteBuffer { [weak self] in
                self?.pumpInbound()
            }
        }
    }

    // MARK: - Teardown

    func teardown() {
        guard state != .tornDown else { return }
        state = .tornDown
        if let ctx = sslContext {
            SSLClose(ctx)
            sslContext = nil
        }
        connection.cancel()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        onComplete(bytesOut, bytesIn)
    }
}

// MARK: - Secure Transport C callbacks

private func mitmSSLRead(_ connection: SSLConnectionRef,
                          _ data: UnsafeMutableRawPointer,
                          _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let bridge = Unmanaged<MITMBridge>.fromOpaque(connection).takeUnretainedValue()
    let available = bridge.sslReadBufferCount

    if available == 0 {
        dataLength.pointee = 0
        return errSSLWouldBlock
    }

    let requested = dataLength.pointee
    let toRead = min(requested, available)
    bridge.consumeSSLReadBuffer(into: data, count: toRead)
    dataLength.pointee = toRead

    return toRead < requested ? errSSLWouldBlock : noErr
}

private func mitmSSLWrite(_ connection: SSLConnectionRef,
                           _ data: UnsafeRawPointer,
                           _ dataLength: UnsafeMutablePointer<Int>) -> OSStatus {
    let bridge = Unmanaged<MITMBridge>.fromOpaque(connection).takeUnretainedValue()
    let count = dataLength.pointee
    bridge.appendSSLWriteBuffer(from: data, count: count)
    dataLength.pointee = count
    return noErr
}

// MARK: - Buffer accessors

extension MITMBridge {
    var sslReadBufferCount: Int { sslReadBuffer.count }

    func consumeSSLReadBuffer(into dest: UnsafeMutableRawPointer, count: Int) {
        sslReadBuffer.copyBytes(to: dest.assumingMemoryBound(to: UInt8.self), count: count)
        sslReadBuffer.removeFirst(count)
    }

    func appendSSLWriteBuffer(from src: UnsafeRawPointer, count: Int) {
        sslWriteBuffer.append(src.assumingMemoryBound(to: UInt8.self), count: count)
    }
}

