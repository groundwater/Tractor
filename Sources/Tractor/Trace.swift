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
            t.start(header: "Tractor - tracing \(agentLabel)")
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
            fputs("Tractor: tracing started. JSON output on stdout.\n", stderr)
        }

        // In TUI mode, also check for 'q' keypress to quit
        if let t = tui {
            let quitSource = DispatchSource.makeTimerSource(queue: .main)
            quitSource.schedule(deadline: .now(), repeating: .milliseconds(100))
            quitSource.setEventHandler {
                while true {
                    let ch = wgetch(stdscr)
                    guard ch != -1 else { break }

                    // Sample config modal intercepts keys
                    if t.isSampleConfigOpen {
                        switch ch {
                        case 259: t.sampleConfigUp()
                        case 258: t.sampleConfigDown()
                        case 260: t.sampleConfigLeft()
                        case 261: t.sampleConfigRight()
                        case 10, 13: t.sampleConfigStart()
                        case 27: t.sampleConfigCancel()
                        default: break
                        }
                        continue
                    }

                    // Track modal
                    if t.isTrackModalOpen {
                        switch ch {
                        case 259: t.trackModalUp()
                        case 258: t.trackModalDown()
                        case 10, 13: t.trackModalConfirm()
                        case 27: t.trackModalCancel()
                        default: t.trackModalType(ch)
                        }
                        continue
                    }

                    // Wait config modal
                    if t.isWaitConfigOpen {
                        switch ch {
                        case 260: t.waitConfigLeft()
                        case 261: t.waitConfigRight()
                        case 10, 13: t.waitConfigStart()
                        case 27: t.waitConfigCancel()
                        default: break
                        }
                        continue
                    }

                    // Kill modal
                    if t.isKillMode {
                        switch ch {
                        case 259: t.killModalUp()
                        case 258: t.killModalDown()
                        case 10, 13: t.killModalConfirm()
                        case 27, 107: t.enterKillMode() // esc or k = cancel
                        default: break
                        }
                        continue
                    }

                    // Menu navigation when open
                    if t.isMenuOpen {
                        switch ch {
                        case 259: t.menuUp()          // UP
                        case 258: t.menuDown()        // DOWN
                        case 260: t.menuLeft()        // LEFT
                        case 261: t.menuRight()       // RIGHT
                        case 10, 13: t.menuSelect()   // Enter
                        case 27: t.closeMenu()        // ESC
                        case 102: t.toggleMenu(.file)    // f
                        case 101: t.toggleMenu(.edit)    // e
                        case 109: t.toggleMenu(.sample)   // m
                        case 116: t.toggleMenu(.network) // t
                        case 121: t.toggleMenu(.files)   // y
                        case 112: t.toggleContextMenu() // p
                        case 118: t.toggleMenu(.view)    // v
                        default:
                            // Shortcut keys still work while menu is open
                            t.executeShortcut(ch)
                        }
                        continue
                    }

                    switch ch {
                    case 32:  // space
                        t.togglePause()
                    case 259: // KEY_UP
                        t.moveUp()
                    case 258: // KEY_DOWN
                        t.moveDown()
                    case 261: // KEY_RIGHT
                        t.disclose()
                    case 260: // KEY_LEFT
                        t.collapse()
                    case 10, 13: // Enter
                        t.toggleDisclose()
                    case 102: // 'f' - File menu
                        t.toggleMenu(.file)
                    case 101: // 'e' - Edit menu
                        t.toggleMenu(.edit)
                    case 112: // 'p' - Process/context menu
                        t.toggleContextMenu()
                    case 109: // 'm' - Sample menu
                        t.toggleMenu(.sample)
                    case 116: // 't' - Network menu
                        t.toggleMenu(.network)
                    case 121: // 'y' - FileSystem menu
                        t.toggleMenu(.files)
                    case 118: // 'v' - View menu
                        t.toggleMenu(.view)
                    case 105, 100, 110, 122, 107, 115, 119, 108, 114, 120:
                        // i, d, n, z, k, s, w, l, r, x — all routed through executeShortcut for flash
                        t.executeShortcut(ch)
                    case 63: // '?'
                        t.toggleHints()
                    case 27: // ESC
                        t.clearSelection()
                    case 104: // 'h'
                        t.toggleViewMode()
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
