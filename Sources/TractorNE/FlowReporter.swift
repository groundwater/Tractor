import Foundation

/// Bidirectional socket connection to the Tractor CLI.
///
/// - Reads `{"watch": [pid1, pid2, ...]}` commands from the CLI
/// - Sends `{"pid":N,"host":"...","port":"...","proto":"tcp"}` flow events back
///
/// The watched PID set is thread-safe and checked by TransparentProxy.handleNewFlow.
final class FlowReporter {
    private let socketPath = "/tmp/tractor-flow.sock"
    private var fd: Int32 = -1
    private let writeLock = NSLock()

    /// Currently watched PIDs. Empty = intercept nothing.
    private let pidLock = NSLock()
    private var watchedPids: Set<Int32> = []

    /// Called on the read thread when the watch list changes.
    var onWatchListChanged: (() -> Void)?

    /// Check if a PID is in the watch list.
    /// Returns false if the CLI socket is disconnected — no CLI means no interception.
    func isWatched(_ pid: Int32) -> Bool {
        writeLock.lock()
        let connected = fd >= 0
        writeLock.unlock()
        guard connected else { return false }

        pidLock.lock()
        defer { pidLock.unlock() }
        return watchedPids.contains(pid)
    }

    /// Whether any PIDs are being watched.
    var hasWatchedPids: Bool {
        pidLock.lock()
        defer { pidLock.unlock() }
        return !watchedPids.isEmpty
    }

    func connect() {
        writeLock.lock()
        defer { writeLock.unlock() }

        if fd >= 0 { return }

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

        // Start reading commands on a background thread
        let readFd = fd
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.readLoop(readFd)
        }
    }

    func disconnect() {
        writeLock.lock()
        let oldFd = fd
        fd = -1
        writeLock.unlock()

        if oldFd >= 0 { close(oldFd) }

        pidLock.lock()
        watchedPids.removeAll()
        pidLock.unlock()
    }

    func reportBytes(pid: Int32, host: String, port: String, bytesOut: Int64, bytesIn: Int64) {
        let json = "{\"pid\":\(pid),\"host\":\"\(escapeJSON(host))\",\"port\":\"\(escapeJSON(port))\",\"bytesOut\":\(bytesOut),\"bytesIn\":\(bytesIn)}\n"
        sendJSON(json)
    }

    func reportFlow(pid: Int32, process: String, host: String, port: String, proto: String) {
        let json = "{\"pid\":\(pid),\"process\":\"\(escapeJSON(process))\",\"host\":\"\(escapeJSON(host))\",\"port\":\"\(escapeJSON(port))\",\"proto\":\"\(proto)\"}\n"
        sendJSON(json)
    }

    private func sendJSON(_ json: String) {
        writeLock.lock()
        defer { writeLock.unlock() }

        guard fd >= 0 else { return }

        var data = Array(json.utf8)
        var total = 0
        while total < data.count {
            let written = data.withUnsafeBytes { buf in
                write(fd, buf.baseAddress! + total, data.count - total)
            }
            if written <= 0 {
                close(fd)
                fd = -1
                return
            }
            total += written
        }
    }

    // MARK: - Read loop

    private func readLoop(_ readFd: Int32) {
        var buffer = Data()
        var buf = [UInt8](repeating: 0, count: 4096)

        // Use poll() so we can detect socket close within 1 second
        while true {
            var pfd = pollfd(fd: readFd, events: Int16(POLLIN | POLLHUP), revents: 0)
            let pollResult = poll(&pfd, 1, 1000)  // 1 second timeout

            if pollResult < 0 {
                break  // poll error
            }

            if pollResult == 0 {
                // Timeout — check if socket is still valid
                var error: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                let gso = getsockopt(readFd, SOL_SOCKET, SO_ERROR, &error, &len)
                if gso != 0 || error != 0 {
                    break  // socket dead
                }
                continue  // poll again
            }

            if pfd.revents & Int16(POLLHUP | POLLERR) != 0 {
                break  // other end closed
            }

            let n = read(readFd, &buf, buf.count)
            if n <= 0 {
                break  // EOF or error
            }

            buffer.append(contentsOf: buf[..<n])

            while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[buffer.index(after: newline)...])
                handleCommand(line)
            }
        }

        NSLog("TractorNE: CLI socket disconnected — clearing watch list")
        pidLock.lock()
        watchedPids.removeAll()
        pidLock.unlock()

        writeLock.lock()
        if fd == readFd { fd = -1 }
        writeLock.unlock()

        onWatchListChanged?()
    }

    private func handleCommand(_ data: Data) {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        if let pids = json["watch"] as? [Int] {
            pidLock.lock()
            watchedPids = Set(pids.map { Int32($0) })
            let count = watchedPids.count
            pidLock.unlock()

            NSLog("TractorNE: watch list updated — \(count) PIDs")
            onWatchListChanged?()
        }
    }

    private func escapeJSON(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\")
         .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
