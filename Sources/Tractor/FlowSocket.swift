import Foundation

/// Well-known socket path for sysext → CLI flow events.
let tractorSocketPath = "/tmp/tractor-flow.sock"

/// Listens on a Unix domain socket for flow events from the TractorNE sysext.
/// Each connected client sends newline-delimited JSON. Events are forwarded to the EventSink.
final class FlowSocketListener {
    private let sink: EventSink
    private var listenSocket: Int32 = -1
    private var listenSource: DispatchSourceRead?
    private var clients: [Int32: DispatchSourceRead] = [:]

    init(sink: EventSink) {
        self.sink = sink
    }

    func start() {
        // Remove stale socket
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
            let bound = ptr.withMemoryRebound(to: CChar.self, capacity: 104) { dst in
                pathBytes.withUnsafeBufferPointer { src in
                    memcpy(dst, src.baseAddress!, min(src.count, 104))
                }
            }
            _ = bound
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

        // Make socket world-writable so the sysext (running as root) can connect
        chmod(tractorSocketPath, 0o777)

        guard Darwin.listen(listenSocket, 5) == 0 else {
            fputs("Tractor: listen failed: \(errno)\n", stderr)
            close(listenSocket)
            return
        }

        // Set non-blocking
        fcntl(listenSocket, F_SETFL, O_NONBLOCK)

        let source = DispatchSource.makeReadSource(fileDescriptor: listenSocket, queue: .main)
        source.setEventHandler { [weak self] in
            self?.acceptClient()
        }
        source.setCancelHandler { [weak self] in
            if let fd = self?.listenSocket, fd >= 0 {
                close(fd)
            }
        }
        listenSource = source
        source.resume()

        fputs("Tractor: flow socket listening on \(tractorSocketPath)\n", stderr)
    }

    func stop() {
        listenSource?.cancel()
        listenSource = nil
        for (fd, source) in clients {
            source.cancel()
            close(fd)
        }
        clients.removeAll()
        unlink(tractorSocketPath)
    }

    private func acceptClient() {
        let clientFd = Darwin.accept(listenSocket, nil, nil)
        guard clientFd >= 0 else { return }

        fcntl(clientFd, F_SETFL, O_NONBLOCK)
        fputs("Tractor: sysext connected (fd=\(clientFd))\n", stderr)

        var buffer = Data()

        let source = DispatchSource.makeReadSource(fileDescriptor: clientFd, queue: .main)
        source.setEventHandler { [weak self] in
            var buf = [UInt8](repeating: 0, count: 8192)
            let n = read(clientFd, &buf, buf.count)
            if n <= 0 {
                // EOF or error
                source.cancel()
                close(clientFd)
                self?.clients.removeValue(forKey: clientFd)
                fputs("Tractor: sysext disconnected (fd=\(clientFd))\n", stderr)
                return
            }
            buffer.append(contentsOf: buf[..<n])

            // Process complete lines
            while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[buffer.index(after: newline)...])
                self?.handleLine(line)
            }
        }
        source.setCancelHandler {
            close(clientFd)
        }
        clients[clientFd] = source
        source.resume()
    }

    private func handleLine(_ data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let pid = json["pid"] as? Int32 ?? -1
        let process = json["process"] as? String ?? ""
        let host = json["host"] as? String ?? ""
        let port = UInt16(json["port"] as? String ?? "0") ?? 0
        let proto = json["proto"] as? String ?? ""

        sink.onConnect(pid: pid, ppid: 0, process: process, user: 0,
                       remoteAddr: host, remotePort: port)
    }
}
