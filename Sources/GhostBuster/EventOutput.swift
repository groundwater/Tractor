import Foundation

struct AgentEvent: Encodable {
    let timestamp: String
    let type: String
    let pid: Int32
    let ppid: Int32
    let process: String
    let user: uid_t
    let details: [String: String]
}

/// Thread-safe JSON-line output to stdout
final class EventOutput: EventSink {
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    private let dateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private let lock = NSLock()

    func now() -> String {
        dateFormatter.string(from: Date())
    }

    private func emit(_ event: AgentEvent) {
        guard let data = try? encoder.encode(event),
              let line = String(data: data, encoding: .utf8) else { return }
        lock.lock()
        print(line)
        fflush(stdout)
        lock.unlock()
    }

    // MARK: - EventSink

    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t) {
        emit(AgentEvent(
            timestamp: now(), type: "exec",
            pid: pid, ppid: ppid, process: process, user: user,
            details: ["argv": argv]
        ))
    }

    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String]) {
        emit(AgentEvent(
            timestamp: now(), type: type,
            pid: pid, ppid: ppid, process: process, user: user,
            details: details
        ))
    }

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16) {
        emit(AgentEvent(
            timestamp: now(), type: "connect",
            pid: pid, ppid: ppid, process: process, user: user,
            details: ["addr": remoteAddr, "port": "\(remotePort)"]
        ))
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t) {
        emit(AgentEvent(
            timestamp: now(), type: "exit",
            pid: pid, ppid: ppid, process: process, user: user,
            details: [:]
        ))
    }
}
