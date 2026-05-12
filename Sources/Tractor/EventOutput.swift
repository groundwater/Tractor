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

/// Thread-safe JSON-line output to stdout (or a file, when `output` is set)
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
    private let output: FileHandle?     // nil = stdout

    init(output: FileHandle? = nil) {
        self.output = output
    }

    func close() {
        if let output = output, output !== FileHandle.standardOutput {
            try? output.close()
        }
    }

    func now() -> String {
        dateFormatter.string(from: Date())
    }

    private func emit(_ event: AgentEvent) {
        guard var data = try? encoder.encode(event) else { return }
        data.append(0x0A) // newline
        lock.lock()
        if let output = output {
            try? output.write(contentsOf: data)
        } else {
            FileHandle.standardOutput.write(data)
        }
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

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16, flowID: UInt64) {
        emit(AgentEvent(
            timestamp: now(), type: "connect",
            pid: pid, ppid: ppid, process: process, user: user,
            details: ["addr": remoteAddr, "port": "\(remotePort)"]
        ))
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t, exitStatus: Int32 = 0) {
        emit(AgentEvent(
            timestamp: now(), type: "exit",
            pid: pid, ppid: ppid, process: process, user: user,
            details: [:]
        ))
    }
}
