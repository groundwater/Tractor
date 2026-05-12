import ArgumentParser
import Darwin
import Foundation

/// `tractor exec [--log-file PATH] [--json-file PATH] -- cmd args...`
///
/// Runs a command with stdio inherited and records its activity (exec/file/exit
/// events) into a SQLite database, a JSONL file, or both. Exits with the child's
/// exit code. No TUI, no network interception.
struct Exec: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "exec",
        abstract: "Run a command with stdio passthrough and record its activity"
    )

    @Option(name: .long, help: "Explicit SQLite database path (default: Tractor app group shared database)")
    var logFile: String?

    @Option(name: .long, help: "Write JSON-lines events to this file")
    var jsonFile: String?

    @Argument(parsing: .captureForPassthrough,
              help: "Command and arguments to run (use -- to separate from tractor flags)")
    var command: [String] = []

    func run() throws {
        let argv = Self.normalizedCommand(command)

        guard !argv.isEmpty else {
            throw ValidationError("Provide a command to run (use -- to separate flags, e.g. tractor exec -- ls -la)")
        }

        // Resolve outputs.
        var sinks: [EventSink] = []
        var sqliteLog: SQLiteLog?
        let dbPath = try (logFile ?? TractorPaths.sharedLogPath())
        let s = try SQLiteLog(path: dbPath)
        sqliteLog = s
        sinks.append(s)
        fputs("Tractor: logging to \(s.path)\n", stderr)
        var jsonOutput: EventOutput?
        if let jsonPath = jsonFile {
            // Open file for append/create
            let url = URL(fileURLWithPath: jsonPath)
            FileManager.default.createFile(atPath: url.path, contents: nil)
            let handle = try FileHandle(forWritingTo: url)
            try handle.seekToEnd()
            let out = EventOutput(output: handle)
            jsonOutput = out
            sinks.append(out)
            fputs("Tractor: JSON events to \(jsonPath)\n", stderr)
        }
        let sink: EventSink = sinks.count == 1 ? sinks[0] : MultiSink(sinks)

        // Fork the child blocked on the gate.
        let pending = try SpawnedChild.fork(argv: argv, stdio: .inherit)

        // Start ES, seed tracked PID, then release the gate.
        let tree = ProcessTree()
        tree.addRoots([pending.pid])

        let esClient = ESXPCClient()
        esClient.onExec = { [weak tree] pid, ppid, process, argv, user in
            tree?.trackIfChild(pid: pid, ppid: ppid)
            tree?.addRoots([pid])
            sink.onExec(pid: pid, ppid: ppid, process: process, argv: argv, user: user)
        }
        esClient.onFileOp = { type, pid, ppid, process, user, details in
            sink.onFileOp(type: type, pid: pid, ppid: ppid, process: process, user: user, details: details)
        }
        esClient.onExit = { [weak tree] pid, ppid, process, user, exitStatus in
            sink.onExit(pid: pid, ppid: ppid, process: process, user: user, exitStatus: exitStatus)
            tree?.remove(pid)
        }
        esClient.start()
        esClient.addTrackedPidsSync([pending.pid])
        pending.release()

        // Forward SIGINT/SIGTERM to the child group so Ctrl-C works.
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        let sigint = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigint.setEventHandler { kill(pending.pid, SIGINT) }
        sigint.resume()
        let sigterm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigterm.setEventHandler { kill(pending.pid, SIGTERM) }
        sigterm.resume()

        // Reap the child on a background thread, then post exit back to main.
        let exitCodeBox = ExitCodeBox()
        DispatchQueue.global().async {
            var status: Int32 = 0
            _ = waitpid(pending.pid, &status, 0)
            let code: Int32
            if (status & 0x7f) == 0 {           // exited normally
                code = (status >> 8) & 0xff
            } else {
                code = 128 + (status & 0x7f)    // killed by signal
            }
            exitCodeBox.set(code)

            // Give ES a moment to drain final events, then shut down.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                esClient.stop()
                sqliteLog?.close()
                jsonOutput?.close()
                Foundation.exit(exitCodeBox.get())
            }
        }

        dispatchMain()
    }

    private static func normalizedCommand(_ raw: [String]) -> [String] {
        let trimmed = raw.first == "--" ? Array(raw.dropFirst()) : raw
        guard trimmed.count == 1 else { return trimmed }
        return SpawnedChild.argv(for: trimmed[0])
    }
}

private final class ExitCodeBox {
    private var code: Int32 = 0
    private let lock = NSLock()
    func set(_ c: Int32) { lock.lock(); code = c; lock.unlock() }
    func get() -> Int32 { lock.lock(); defer { lock.unlock() }; return code }
}
