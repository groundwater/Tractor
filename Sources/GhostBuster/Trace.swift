import ArgumentParser
import CoreGraphics
import Darwin.ncurses
import Foundation

/// Globals for signal-safe cleanup
private var activeTUI: TUI?
private var activeESClient: ESClient?
private var activeInputSource: DispatchSourceTimer?

struct Trace: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Trace an AI agent's full process tree and activity"
    )

    @Option(name: .shortAndLong, help: "Agent to trace: claude, codex")
    var agent: String?

    @Option(name: .shortAndLong, help: "Specific PID to trace (including all descendants)")
    var pid: Int32?

    @Flag(help: "Output JSON lines instead of the interactive TUI")
    var json: Bool = false

    func run() throws {
        guard agent != nil || pid != nil else {
            throw ValidationError("Provide --agent or --pid")
        }

        let tree = ProcessTree()

        // Resolve root PIDs
        var roots: [pid_t] = []
        var agentLabel = "PID \(pid ?? 0)"

        if let pidVal = pid {
            roots.append(pidVal)
        }

        if let agentName = agent {
            guard let kind = AgentKind(rawValue: agentName.lowercased()) else {
                throw ValidationError("Unknown agent: \(agentName). Options: \(AgentKind.allCases.map(\.rawValue).joined(separator: ", "))")
            }
            agentLabel = agentName
            let found = findAgentPIDs(kind)
            if found.isEmpty {
                fputs("WARNING: No running \(agentName) processes found. Will watch for new ones.\n", stderr)
            } else {
                fputs("Found \(found.count) \(agentName) process(es): \(found)\n", stderr)
                roots.append(contentsOf: found)
            }
        }

        // Expand to full tree
        var expanded: [pid_t] = []
        if !roots.isEmpty {
            expanded = expandProcessTree(roots: roots)
            fputs("Tracking \(expanded.count) processes (including descendants)\n", stderr)
            tree.addRoots(expanded)
        }

        // Create sink: TUI or JSON
        let sink: EventSink
        var tui: TUI?

        if json {
            sink = EventOutput()
        } else {
            let t = TUI()
            t.excludeSelf()
            t.start(header: "GhostBuster - tracing \(agentLabel)")
            tui = t
            sink = t
        }

        // Seed the sink with already-running processes
        for trackedPid in expanded {
            let (path, ppid, argv) = getProcessInfo(trackedPid)
            sink.onExec(
                pid: trackedPid, ppid: ppid,
                process: path, argv: argv,
                user: uid_t(getuid())
            )
        }

        // Start ES client
        let esClient = ESClient(tree: tree, sink: sink)
        // Set agent patterns for auto-discovery of new instances
        if let agentName = agent, let kind = AgentKind(rawValue: agentName.lowercased()) {
            esClient.agentPatterns = kind.processPatterns
        }

        // Store refs for signal handler cleanup
        activeTUI = tui
        activeESClient = esClient

        signal(SIGINT) { _ in
            activeInputSource?.cancel()
            activeTUI?.stop()
            activeESClient?.stop()
            Foundation.exit(0)
        }

        do {
            try esClient.start()
        } catch {
            tui?.stop()
            throw error
        }

        if json {
            fputs("GhostBuster: tracing started. JSON output on stdout.\n", stderr)
        }

        // In TUI mode, also check for 'q' keypress to quit
        if let t = tui {
            let quitSource = DispatchSource.makeTimerSource(queue: .main)
            quitSource.schedule(deadline: .now(), repeating: .milliseconds(100))
            quitSource.setEventHandler {
                while true {
                    let ch = wgetch(stdscr)
                    guard ch != -1 else { break }

                    switch ch {
                    case 32:  // space
                        t.togglePause()
                    case 259: // KEY_UP
                        if CGEventSource.flagsState(.combinedSessionState).contains(.maskShift) {
                            t.shiftMoveUp()
                        } else {
                            t.moveUp()
                        }
                    case 258: // KEY_DOWN
                        if CGEventSource.flagsState(.combinedSessionState).contains(.maskShift) {
                            t.shiftMoveDown()
                        } else {
                            t.moveDown()
                        }
                    case 261: // KEY_RIGHT
                        t.disclose()
                    case 260: // KEY_LEFT
                        t.collapse()
                    case 43: // '+' - disclose all descendants
                        t.discloseAll()
                    case 45: // '-' - collapse all descendants
                        t.collapseAll()
                    case 10, 13: // Enter/Return
                        if CGEventSource.flagsState(.combinedSessionState).contains(.maskShift) {
                            t.discloseAll()
                        } else {
                            t.toggleDisclose()
                        }
                    case 27: // ESC
                        t.clearSelection()
                    case 113: // 'q'
                        activeInputSource?.cancel()
                        t.stop()
                        esClient.stop()
                        Foundation.exit(0)
                    default:
                        break
                    }
                }
            }
            activeInputSource = quitSource
            quitSource.resume()
        }

        dispatchMain()
    }
}
