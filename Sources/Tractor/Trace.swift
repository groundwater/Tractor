import ArgumentParser
import CoreGraphics
import Darwin.ncurses
import Foundation

/// Globals for signal-safe cleanup
private var activeTUI: TUI?
private var activeESClient: ESClient?
private var activeInputSource: DispatchSourceTimer?
private var activeSQLiteLog: SQLiteLog?
private var activeFlowClient: FlowXPCClient?

private func exitAfterRestoringTerminal(message: String, code: Int32 = 1) {
    activeInputSource?.cancel()
    activeTUI?.stop()
    activeESClient?.stop()
    activeSQLiteLog?.close()
    // Close the XPC connection — the sysext detects the disconnect
    // and clears its watch list, stopping all interception.
    activeFlowClient?.stop()
    activeFlowClient = nil
    if !message.isEmpty {
        fputs("\n\(message)\n", stderr)
        fflush(stderr)
    }
    Foundation.exit(code)
}

struct Trace: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Trace a process tree and its activity"
    )

    @Option(name: .shortAndLong, help: "Process name to trace (substring match, repeatable)")
    var name: [String] = []

    @Option(name: .shortAndLong, help: "Specific PID to trace including all descendants (repeatable)")
    var pid: [Int32] = []

    @Option(name: .long, help: "Exact executable path to trace (repeatable)")
    var path: [String] = []

    @Argument(help: "PIDs to trace (all remaining arguments are treated as PIDs until --)")
    var pids: [Int32] = []

    @Flag(help: "Output JSON lines instead of the interactive TUI")
    var json: Bool = false

    @Option(name: .long, help: "Auto-expand criteria (e.g. file:cud,proc:e,net:crw)")
    var expand: String?

    @Flag(name: .long, help: "Log events to a SQLite database in the current directory")
    var log: Bool = false

    @Option(name: .long, help: "Path to SQLite database file (implies --log)")
    var logFile: String?

    @Flag(name: .long, help: "Activate network extension to intercept all TCP/UDP flows")
    var net: Bool = false

    func run() throws {
        guard !name.isEmpty || !pid.isEmpty || !path.isEmpty else {
            throw ValidationError("Provide at least one --name, --pid, or --path")
        }

        let tree = ProcessTree()

        // Build header label from all trackers
        var labels: [String] = []
        for n in name { labels.append(n) }
        for p in pid { labels.append("PID \(p)") }
        for p in pids { labels.append("PID \(p)") }
        for p in path { labels.append(p) }
        let agentLabel = labels.joined(separator: ", ")

        // Create sink: TUI or JSON
        let primarySink: EventSink
        let sink: EventSink
        var tui: TUI?

        if json {
            primarySink = EventOutput()
        } else {
            let t = TUI()
            if let expandSpec = expand {
                t.expandCriteria = try ExpandCriteria.parse(expandSpec)
                t.expandSpecified = true
            }
            t.excludeSelf()
            t.processTree = tree
            t.start(header: "Tractor - tracing \(agentLabel)")
            tui = t
            primarySink = t
        }

        // Optionally add SQLite logging
        if log || logFile != nil {
            let dbPath: String
            if let explicit = logFile {
                dbPath = explicit
            } else {
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime]
                let stamp = formatter.string(from: Date())
                    .replacingOccurrences(of: ":", with: "-")
                dbPath = "trace-\(stamp).db"
            }
            let sqliteLog = try SQLiteLog(path: dbPath)
            activeSQLiteLog = sqliteLog
            fputs("Tractor: logging to \(sqliteLog.path)\n", stderr)
            sink = MultiSink([primarySink, sqliteLog])
        } else {
            sink = primarySink
        }

        // Create tracker groups and seed processes
        if let t = tui {
            for n in name {
                t.addTrackerGroup(kind: .name, value: n)
            }
            for p in pid {
                t.addTrackerGroup(kind: .pid, value: "\(p)")
            }
            for p in pids {
                t.addTrackerGroup(kind: .pid, value: "\(p)")
            }
            for p in path {
                t.addTrackerGroup(kind: .path, value: p)
            }
        } else {
            // JSON mode — just resolve roots directly
            var roots: [pid_t] = []
            for n in name {
                roots.append(contentsOf: findProcessesByName(n))
            }
            for p in pid {
                roots.append(p)
            }
            for p in pids {
                roots.append(p)
            }
            for p in path {
                roots.append(contentsOf: findProcessesByExactPath(p))
            }
            if !roots.isEmpty {
                let expanded = expandProcessTree(roots: roots)
                tree.addRoots(expanded)
                for trackedPid in expanded {
                    let (execPath, ppid, argv) = getProcessInfo(trackedPid)
                    sink.onExec(pid: trackedPid, ppid: ppid, process: execPath, argv: argv, user: uid_t(getuid()))
                }
            }
        }

        // Seed ProcessTree with all tracked PIDs from TUI groups
        if let t = tui {
            for group in t.trackerGroups {
                let groupPids = findPidsForTrackerGroup(group)
                if !groupPids.isEmpty {
                    let expanded = expandProcessTree(roots: groupPids)
                    tree.addRoots(expanded)
                }
            }
        }

        // Start ES client
        let esClient = ESClient(tree: tree, sink: sink)

        // Build initial patterns from all trackers
        if let t = tui {
            esClient.updatePatterns(trackers: t.trackerGroups)
            // Wire up dynamic pattern updates when trackers change
            t.onTrackersChanged = { [weak esClient] trackers in
                esClient?.updatePatterns(trackers: trackers)
            }
            // Network connections are now reported via the NE proxy through
            // FlowSocket → EventSink.onConnect, which reaches both TUI and SQLiteLog
        } else {
            // JSON mode — set patterns directly
            esClient.tracePatterns = name.map { $0.lowercased() }
            esClient.pathPatterns = path
        }

        // Store refs for signal handler cleanup
        activeTUI = tui
        activeESClient = esClient

        signal(SIGINT, SIG_IGN)
        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler {
            exitAfterRestoringTerminal(message: "", code: 0)
        }
        sigintSource.resume()

        do {
            try esClient.start()
        } catch {
            tui?.stop()
            throw error
        }

        if json {
            fputs("Tractor: tracing started. JSON output on stdout.\n", stderr)
        }

        // Activate network extension if requested
        if net {
            let flowClient = FlowXPCClient(sink: sink)
            activeFlowClient = flowClient
            flowClient.start()

            if let t = tui {
                flowClient.onBytesUpdate = { pid, host, port, bytesOut, bytesIn in
                    t.updateConnectionBytes(pid: pid, remoteAddr: host, remotePort: port,
                                            txBytes: UInt64(bytesOut), rxBytes: UInt64(bytesIn))
                }
                flowClient.onConnectionClosed = { pid, host, port in
                    t.markConnectionClosed(pid: pid, remoteAddr: host, remotePort: port)
                }
            }

            flowClient.updateWatchList(tree.snapshot)

            esClient.onBeforeAllow = { [weak flowClient, weak tree] pid in
                guard let fc = flowClient, let t = tree else { return }
                fc.updateWatchList(t.snapshot)
            }
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
                    case 105, 100, 110, 122, 107, 115, 119, 108, 114, 120, 97:
                        // i, d, n, z, k, s, w, l, r, x — all routed through executeShortcut for flash
                        t.executeShortcut(ch)
                    case 126: // '~' - toggle auto mode
                        t.toggleAutoMode()
                    case 63: // '?'
                        t.toggleHints()
                    case 27: // ESC
                        t.clearSelection()
                    case 104: // 'h'
                        t.toggleViewMode()
                    case 113: // 'q'
                        exitAfterRestoringTerminal(message: "", code: 0)
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

/// Resolve PIDs for a tracker group (used during startup)
private func findPidsForTrackerGroup(_ group: TrackerGroup) -> [pid_t] {
    switch group.kind {
    case .name:
        return findProcessesByName(group.value)
    case .pid:
        if let p = Int32(group.value), p > 0 { return [p] }
        return []
    case .path:
        return findProcessesByExactPath(group.value)
    }
}
