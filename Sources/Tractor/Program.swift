import ArgumentParser
import Foundation

/// Persistent bidirectional XPC connection to TractorNE for the lifetime
/// of `tractor program`. Two responsibilities:
///   1. Toggle NE's intercept-all flag so all TCP flows reach the JS engine.
///   2. Host an exported `evaluateFlow` endpoint so NE can call back via
///      reverse XPC to ask whether to deny a flow. We forward to ES.
///
/// The connection must stay alive — NE clears its `hasClient` flag on
/// invalidation, which would silently turn off interception.
private let neServiceName = "group.com.jacobgroundwater.Tractor"

private final class FlowEvalBridge: NSObject, TractorCLIXPC {
    private let esClient: ESXPCClient
    init(es: ESXPCClient) {
        self.esClient = es
    }
    // The methods NE actually calls — relay to ES.
    func evaluateFlow(_ context: Data, reply: @escaping (Bool) -> Void) {
        esClient.evaluateFlow(context, reply: reply)
    }
    func notifyFlowClose(_ context: Data) {
        esClient.notifyFlowClose(context)
    }
    func notifyFlowBytes(_ context: Data) {
        esClient.notifyFlowBytes(context)
    }
    // Stubs — `tractor program` doesn't do MITM or flow streaming.
    func generateP12(hostname: NSString, reply: @escaping (Data) -> Void) { reply(Data()) }
    func openFlow(id: UInt64, host: NSString, port: UInt16, pid: Int32) {}
    func flowData(id: UInt64, data: Data) {}
    func closeFlow(id: UInt64) {}
}

private final class NEInterceptHandle {
    let conn: NSXPCConnection
    let bridge: FlowEvalBridge

    init?(es: ESXPCClient) {
        let c = NSXPCConnection(machServiceName: neServiceName, options: .privileged)
        c.remoteObjectInterface = NSXPCInterface(with: TractorNEXPC.self)
        c.exportedInterface = NSXPCInterface(with: TractorCLIXPC.self)
        let b = FlowEvalBridge(es: es)
        c.exportedObject = b
        c.resume()
        self.conn = c
        self.bridge = b
    }

    func setInterceptAll(_ on: Bool) {
        guard let proxy = conn.remoteObjectProxyWithErrorHandler({ _ in }) as? TractorNEXPC else { return }
        proxy.setInterceptAll(on)
    }

    func claimEvaluator() {
        guard let proxy = conn.remoteObjectProxyWithErrorHandler({ _ in }) as? TractorNEXPC else { return }
        proxy.claimEvaluator()
    }

    func close() {
        conn.invalidate()
    }
}

private func enableNetIntercept(es: ESXPCClient) -> NEInterceptHandle? {
    guard let h = NEInterceptHandle(es: es) else { return nil }
    h.claimEvaluator()
    h.setInterceptAll(true)
    fputs("(network extension: intercept-all enabled)\n", stderr)
    return h
}

/// `tractor program <file.js>` — submit a JS probe program to the Endpoint
/// Security extension and stream every `emit(channel, obj)` record it
/// produces to stdout as ndjson. The binary is rule-agnostic; all behavior
/// lives in the submitted source.
struct Program: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "program",
        abstract: "Load a JavaScript probe program into the ES extension and stream its emits"
    )

    @Argument(help: "Path to a .js source file")
    var file: String

    @Option(name: .long, help: "Program name (defaults to file basename without extension)")
    var name: String?

    @Argument(parsing: .unconditionalRemaining,
              help: "Arguments passed to the JS program as the `args` global (string array).")
    var scriptArgs: [String] = []

    func run() throws {
        let source: String
        do {
            source = try String(contentsOfFile: file, encoding: .utf8)
        } catch {
            throw ValidationError("Cannot read \(file): \(error.localizedDescription)")
        }

        // Default name from file basename, no extension.
        let programName = name ?? (file as NSString).lastPathComponent
            .components(separatedBy: ".").dropLast().joined(separator: ".")
            .ifEmpty(or: (file as NSString).lastPathComponent)

        guard ESXPCClient.isAvailable() else {
            throw ValidationError("Endpoint Security extension is not active. Run `sudo tractor activate endpoint-security` first.")
        }

        let client = ESXPCClient()
        client.onConnectionError = { err in
            fputs("Tractor: lost Endpoint Security connection: \(err.localizedDescription)\n", stderr)
            Foundation.exit(1)
        }
        client.onEmit = { channel, payload in
            // Only surface emits from THIS session's program — other
            // `tractor program` sessions and the GUI see the same stream
            // via per-connection cursors, so server-side they each get
            // every record; we filter to ours.
            let prog = payload["_program"] as? String ?? "?"
            guard prog == programName else { return }
            // Convention: if the program supplied a `line` string field,
            // print just that (prefixed with channel + program name).
            if let pretty = payload["line"] as? String {
                print("[\(prog)/\(channel)] \(pretty)")
                return
            }
            var line: [String: Any] = ["channel": channel]
            for (k, v) in payload { line[k] = v }
            guard let data = try? JSONSerialization.data(withJSONObject: line),
                  let s = String(data: data, encoding: .utf8) else { return }
            print(s)
        }

        // Panels: maintain `(program, panel) → text`. On any update,
        // clear the terminal and reprint every panel. Only when stdout
        // is a TTY — otherwise just print the latest panel inline so
        // pipes / redirects still see something useful.
        let isTTY = isatty(fileno(stdout)) != 0
        let panelStore = PanelStore()
        client.onPanel = { upd in
            // Same isolation as onEmit — only render panels from our
            // own program so multiple CLIs don't paint over each other.
            guard upd.program == programName else { return }
            panelStore.update(upd)
            if isTTY {
                panelStore.renderTTY()
            } else {
                print("[\(upd.program)/render:\(upd.panel)] \(upd.text)")
            }
        }
        client.start()

        // Tell the engine our terminal size so `terminalCols()` /
        // `terminalRows()` globals reflect reality. Refresh on SIGWINCH.
        if isTTY {
            let (cols, rows) = currentTerminalSize()
            client.setTerminalSize(cols: cols, rows: rows)
            signal(SIGWINCH, SIG_IGN)
            let winchSrc = DispatchSource.makeSignalSource(signal: SIGWINCH, queue: .main)
            winchSrc.setEventHandler { [weak client] in
                let (c, r) = currentTerminalSize()
                client?.setTerminalSize(cols: c, rows: r)
            }
            winchSrc.resume()
            // Keep the source alive for the program's lifetime.
            // The signal handler captures it via setEventHandler closure
            // implicitly; storing in an extra `signalSrc` slot below.
            activeWinch = winchSrc
        }

        let neHandle = enableNetIntercept(es: client)

        if let err = client.loadProgram(name: programName, source: source, args: scriptArgs) {
            fputs("program load failed: \(err)\n", stderr)
            client.stop()
            Foundation.exit(1)
        }
        let argsSuffix = scriptArgs.isEmpty ? "" : " (\(scriptArgs.count) arg\(scriptArgs.count == 1 ? "" : "s"))"
        fputs("program '\(programName)' loaded from \(file)\(argsSuffix). Ctrl-C to stop.\n", stderr)

        signal(SIGINT, SIG_IGN)
        let sigSrc = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigSrc.setEventHandler {
            if let h = neHandle {
                h.setInterceptAll(false)
                h.close()
            }
            client.stop()
            panelStore.exitAltScreenIfEntered()
            Foundation.exit(0)
        }
        sigSrc.resume()

        dispatchMain()
    }
}

private extension String {
    func ifEmpty(or fallback: String) -> String { isEmpty ? fallback : self }
}

/// Holds the active SIGWINCH dispatch source so it stays alive past
/// `Program.run()`'s scope (referenced by `dispatchMain`).
private var activeWinch: DispatchSourceSignal?

/// Query the controlling terminal's current size via TIOCGWINSZ on
/// stdout. Returns (cols, rows). Defaults to (80, 24) if the ioctl
/// fails (e.g. stdout is not a TTY).
private func currentTerminalSize() -> (cols: Int, rows: Int) {
    var ws = winsize()
    if ioctl(fileno(stdout), TIOCGWINSZ, &ws) == 0, ws.ws_col > 0, ws.ws_row > 0 {
        return (Int(ws.ws_col), Int(ws.ws_row))
    }
    return (80, 24)
}

/// Holds the latest text for every `(program, panel)` and renders them
/// in a deterministic order. On TTY, enters the **alternate screen
/// buffer** (`\x1b[?1049h`) on first render so updates feel like `top`
/// — no scrollback accumulation; original terminal contents restored
/// on exit. Call `exitAltScreenIfEntered()` before `_exit`/`exit`.
private final class PanelStore {
    private var panels: [String: String] = [:]      // "<program>\0<panel>" → text
    private var order: [String] = []                // insertion order, stable
    private var enteredAltScreen = false

    func update(_ upd: PanelUpdate) {
        let key = "\(upd.program)\u{0}\(upd.panel)"
        if panels[key] == nil { order.append(key) }
        panels[key] = upd.text
    }

    func renderTTY() {
        var out = ""
        if !enteredAltScreen {
            // \x1b[?1049h = enter alternate screen buffer (top-style).
            out += "\u{1b}[?1049h"
            enteredAltScreen = true
        }
        // \x1b[?25l = hide cursor; \x1b[H = cursor home; \x1b[2J = clear.
        out += "\u{1b}[?25l\u{1b}[H\u{1b}[2J"
        for key in order {
            guard let text = panels[key] else { continue }
            let sep = key.split(separator: "\u{0}", maxSplits: 1)
            let program = String(sep.first ?? "")
            let panel = sep.count > 1 ? String(sep[1]) : ""
            out += "\u{1b}[1m[\(program) / \(panel)]\u{1b}[0m\n"   // bold header
            out += text
            if !text.hasSuffix("\n") { out += "\n" }
            out += "\n"
        }
        out += "\u{1b}[?25h"  // show cursor again
        FileHandle.standardOutput.write(out.data(using: .utf8) ?? Data())
    }

    /// Restore the original terminal contents. Call before exiting so
    /// the user's prior shell scrollback isn't replaced by a blank panel.
    func exitAltScreenIfEntered() {
        guard enteredAltScreen else { return }
        // \x1b[?1049l = leave alternate screen buffer.
        FileHandle.standardOutput.write("\u{1b}[?25h\u{1b}[?1049l".data(using: .utf8) ?? Data())
        enteredAltScreen = false
    }
}

/// `tractor programs` — list / unload loaded programs.
struct Programs: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "programs",
        abstract: "List or unload currently-loaded probe programs",
        subcommands: [ProgramsList.self, ProgramsUnload.self],
        defaultSubcommand: ProgramsList.self
    )
}

struct ProgramsList: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "list", abstract: "List loaded programs")
    func run() throws {
        let progs = ESXPCClient.fetchPrograms(timeout: 1.5)
        if progs.isEmpty {
            fputs("(no programs loaded)\n", stderr)
            return
        }
        let df = DateFormatter()
        df.dateStyle = .none
        df.timeStyle = .medium
        for p in progs {
            print("\(p.name)\t\(p.probes.count) probes\tloaded \(df.string(from: p.loadedAt))")
            for n in p.probes { print("  · \(n)") }
        }
    }
}

struct ProgramsUnload: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "unload", abstract: "Unload a loaded program by name")
    @Argument(help: "Program name to unload")
    var name: String
    func run() throws {
        guard ESXPCClient.isAvailable() else {
            throw ValidationError("Endpoint Security extension is not active.")
        }
        let client = ESXPCClient()
        client.start()
        client.unloadProgram(name: name)
        client.stop()
        fputs("unloaded '\(name)' (if it was loaded)\n", stderr)
    }
}
