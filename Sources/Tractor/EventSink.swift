import Foundation

/// Protocol for receiving ES events — implemented by both JSON output and TUI
protocol EventSink: AnyObject {
    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t)
    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String])
    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16)
    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t, exitStatus: Int32)
}
