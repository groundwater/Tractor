import Foundation

/// Sends flow events to the Tractor CLI over a Unix domain socket.
/// Each event is a JSON line. Reconnects automatically if the connection drops.
final class FlowReporter {
    private let socketPath = "/tmp/tractor-flow.sock"
    private var fd: Int32 = -1
    private let lock = NSLock()

    func connect() {
        lock.lock()
        defer { lock.unlock() }

        if fd >= 0 { return } // already connected

        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            NSLog("TractorNE: socket() failed: \(errno)")
            fd = -1
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: 104) { dst in
                pathBytes.withUnsafeBufferPointer { src in
                    memcpy(dst, src.baseAddress!, min(src.count, 104))
                }
            }
        }

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        if result != 0 {
            NSLog("TractorNE: connect() failed: \(errno)")
            close(fd)
            fd = -1
            return
        }

        NSLog("TractorNE: connected to CLI socket")
    }

    func disconnect() {
        lock.lock()
        defer { lock.unlock() }
        if fd >= 0 {
            close(fd)
            fd = -1
        }
    }

    func reportFlow(pid: Int32, process: String, host: String, port: String, proto: String) {
        // Build JSON manually to avoid overhead
        let json = "{\"pid\":\(pid),\"process\":\"\(escapeJSON(process))\",\"host\":\"\(escapeJSON(host))\",\"port\":\"\(escapeJSON(port))\",\"proto\":\"\(proto)\"}\n"

        lock.lock()
        defer { lock.unlock() }

        if fd < 0 {
            // Try to connect
            lock.unlock()
            connect()
            lock.lock()
        }

        guard fd >= 0 else { return }

        let data = [UInt8](json.utf8)
        let written = write(fd, data, data.count)
        if written <= 0 {
            // Connection lost
            close(fd)
            fd = -1
        }
    }

    private func escapeJSON(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
