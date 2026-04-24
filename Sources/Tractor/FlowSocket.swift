import Foundation

/// Well-known socket path for sysext ↔ CLI communication.
let tractorSocketPath = "/tmp/tractor-flow.sock"

/// Bidirectional Unix domain socket bridge to the TractorNE sysext.
///
/// - CLI → Sysext: `{"watch": [pid1, pid2, ...]}` — set the PID filter
/// - Sysext → CLI: `{"flow": {...}}` — report an intercepted flow
final class FlowSocketListener {
    private let sink: EventSink
    private var listenSocket: Int32 = -1
    private var listenSource: DispatchSourceRead?
    private var clientFds: [Int32] = []
    private var clientSources: [Int32: DispatchSourceRead] = [:]
    private var lastWatchMessage: Data?  // cached so new connections get current state

    /// Called when the sysext reports final byte counts for a closed connection.
    var onBytesUpdate: ((pid_t, String, UInt16, Int64, Int64) -> Void)?  // (pid, host, port, out, in)

    init(sink: EventSink) {
        self.sink = sink
    }

    func start() {
        unlink(tractorSocketPath)

        listenSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenSocket >= 0 else {
            fputs("Tractor: failed to create socket: \(errno)\n", stderr)
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = tractorSocketPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: 104) { dst in
                pathBytes.withUnsafeBufferPointer { src in
                    memcpy(dst, src.baseAddress!, min(src.count, 104))
                }
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(listenSocket, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            fputs("Tractor: bind failed: \(errno)\n", stderr)
            close(listenSocket)
            return
        }

        chmod(tractorSocketPath, 0o777)

        guard Darwin.listen(listenSocket, 5) == 0 else {
            fputs("Tractor: listen failed: \(errno)\n", stderr)
            close(listenSocket)
            return
        }

        fcntl(listenSocket, F_SETFL, O_NONBLOCK)

        let source = DispatchSource.makeReadSource(fileDescriptor: listenSocket, queue: .main)
        source.setEventHandler { [weak self] in
            self?.acceptClient()
        }
        source.setCancelHandler { [weak self] in
            if let fd = self?.listenSocket, fd >= 0 { close(fd) }
        }
        listenSource = source
        source.resume()

        // Don't log to stderr in TUI mode — it clobbers ncurses
    }

    func stop() {
        listenSource?.cancel()
        listenSource = nil
        for (fd, source) in clientSources {
            source.cancel()
            close(fd)
        }
        clientFds.removeAll()
        clientSources.removeAll()
        unlink(tractorSocketPath)
    }

    /// Push updated PID watch list to all connected sysext clients.
    func updateWatchList(_ pids: Set<pid_t>) {
        let pidArray = pids.map { Int($0) }
        guard let data = try? JSONSerialization.data(withJSONObject: ["watch": pidArray]),
              var msg = String(data: data, encoding: .utf8) else { return }
        msg += "\n"
        let msgData = Data(msg.utf8)
        lastWatchMessage = msgData

        for fd in clientFds {
            sendToClient(fd, data: msgData)
        }
    }

    // MARK: - Private

    private func sendToClient(_ fd: Int32, data: Data) {
        data.withUnsafeBytes { buf in
            _ = write(fd, buf.baseAddress!, buf.count)
        }
    }

    private func acceptClient() {
        let clientFd = Darwin.accept(listenSocket, nil, nil)
        guard clientFd >= 0 else { return }

        fcntl(clientFd, F_SETFL, O_NONBLOCK)
        clientFds.append(clientFd)
        // sysext connected

        // Send current watch list immediately
        if let msg = lastWatchMessage {
            sendToClient(clientFd, data: msg)
        }

        var buffer = Data()

        let source = DispatchSource.makeReadSource(fileDescriptor: clientFd, queue: .main)
        source.setEventHandler { [weak self] in
            var buf = [UInt8](repeating: 0, count: 8192)
            let n = read(clientFd, &buf, buf.count)
            if n <= 0 {
                source.cancel()
                close(clientFd)
                self?.clientFds.removeAll { $0 == clientFd }
                self?.clientSources.removeValue(forKey: clientFd)
                // sysext disconnected
                return
            }
            buffer.append(contentsOf: buf[..<n])

            while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[buffer.index(after: newline)...])
                self?.handleLine(line)
            }
        }
        source.setCancelHandler {
            close(clientFd)
        }
        clientSources[clientFd] = source
        source.resume()
    }

    private func handleLine(_ data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let pid = json["pid"] as? Int32 ?? -1
        let host = json["host"] as? String ?? ""
        let port = UInt16(json["port"] as? String ?? "0") ?? 0

        // Byte count update (connection closed)
        if let bytesOut = json["bytesOut"] as? Int64,
           let bytesIn = json["bytesIn"] as? Int64 {
            onBytesUpdate?(pid, host, port, bytesOut, bytesIn)
            return
        }

        // New connection event
        let process = json["process"] as? String ?? ""
        sink.onConnect(pid: pid, ppid: 0, process: process, user: 0,
                       remoteAddr: host, remotePort: port)
    }
}
