import ArgumentParser
import CoreGraphics
import Darwin.ncurses
import Foundation

// KEY_MOUSE constant for ncurses mouse events (0o631 = 409 in decimal)
private let KEY_MOUSE: Int32 = 0o631

/// Globals for signal-safe cleanup
private var activeTUI: TUI?
private var activeInputSource: DispatchSourceTimer?
private var activeSession: TraceSession?

private func exitAfterRestoringTerminal(message: String, code: Int32 = 1) {
    activeInputSource?.cancel()
    activeTUI?.stop()
    activeSession?.stop()
    activeSession = nil
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

    @Option(name: .long, help: "Spawn a command and trace it (repeatable). Shell metacharacters trigger /bin/sh -c.")
    var exec: [String] = []

    @Argument(help: "PIDs to trace (all remaining arguments are treated as PIDs until --)")
    var pids: [Int32] = []

    @Flag(help: "Output JSON lines instead of the interactive TUI")
    var json: Bool = false

    @Option(name: .long, help: "Auto-expand criteria (e.g. file:cud,proc:e,net:crw)")
    var expand: String?

    @Flag(name: .long, help: "Log events to Tractor's shared SQLite database in the app group container")
    var log: Bool = false

    @Option(name: .long, help: "Explicit SQLite database path (implies --log)")
    var logFile: String?

    @Flag(name: .long, help: "Activate network extension to intercept all TCP/UDP flows")
    var net: Bool = false

    @Flag(name: .long, help: "MITM TLS connections to inspect plaintext HTTP traffic (implies --net)")
    var mitm: Bool = false

    func run() throws {
        guard !name.isEmpty || !pid.isEmpty || !path.isEmpty || !pids.isEmpty || !exec.isEmpty else {
            throw ValidationError("Provide at least one --name, --pid, --path, or --exec")
        }
        let mitmCAPaths = mitm ? try TrustCA.requiredExistingCAPaths() : nil

        // Build header label from all trackers
        var labels: [String] = []
        for n in name { labels.append(n) }
        for p in pid { labels.append("PID \(p)") }
        for p in pids { labels.append("PID \(p)") }
        for p in path { labels.append(p) }
        for cmd in exec { labels.append(cmd) }
        let agentLabel = labels.joined(separator: ", ")

        // Create primary sink: TUI or JSON
        let primarySink: EventSink
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
            tui = t
            primarySink = t
        }

        // Build session.
        let session = TraceSession(primarySink: primarySink)
        activeSession = session
        activeTUI = tui
        if let t = tui {
            t.processTree = session.tree
            t.start(header: "Tractor - tracing \(agentLabel)")
        }

        session.onMessage = { msg in
            fputs("\(msg)\n", stderr)
        }
        session.onConnectionError = { error in
            exitAfterRestoringTerminal(
                message: "Tractor: lost Endpoint Security connection: \(error.localizedDescription)",
                code: 1
            )
        }

        // TUI-specific tracker bookkeeping: runs before sink.onExec.
        if let t = tui {
            session.onExec = { [weak t] pid, ppid, process, _, _ in
                guard let t = t else { return }
                t.inheritGroupMembership(child: pid, parent: ppid)
                let name = (process as NSString).lastPathComponent
                t.matchProcessToGroups(pid: pid, name: name, path: process)
            }
        }

        // Tracker groups (TUI) or direct root resolution (JSON).
        let trackerRoots: TraceRoots
        if let t = tui {
            for n in name { t.addTrackerGroup(kind: .name, value: n) }
            for p in pid { t.addTrackerGroup(kind: .pid, value: "\(p)") }
            for p in pids { t.addTrackerGroup(kind: .pid, value: "\(p)") }
            for p in path { t.addTrackerGroup(kind: .path, value: p) }
            trackerRoots = TraceRoots(
                names: t.trackerGroups.compactMap { $0.kind == .name ? $0.value : nil },
                pids: t.trackerGroups.compactMap { $0.kind == .pid ? pid_t($0.value) : nil },
                paths: t.trackerGroups.compactMap { $0.kind == .path ? $0.value : nil }
            )
        } else {
            trackerRoots = TraceRoots(names: name, pids: pid + pids, paths: path)
        }

        let options = TraceOptions(
            logToSQLite: log,
            logFilePath: logFile,
            net: net,
            mitm: mitm,
            mitmCAPaths: mitmCAPaths
        )

        try session.start(roots: trackerRoots, options: options)

        // JSON mode: emit a starting exec for each seeded root so consumers
        // see the initial process state. TUI populates itself via its own paths.
        if json {
            session.seedSinkFromTree()
        }

        // --exec: fork each command, register its PID, release.
        for cmd in exec {
            let argv = SpawnedChild.argv(for: cmd)
            guard !argv.isEmpty else {
                throw ValidationError("--exec value is empty")
            }
            let pending = try SpawnedChild.fork(argv: argv, stdio: .devNull)
            session.registerExecRoot(pid: pending.pid)
            if let t = tui {
                t.addTrackerGroup(kind: .exec, value: "\(pending.pid)", label: cmd)
            }
            pending.release()
            fputs("Tractor: spawned [\(pending.pid)] \(cmd)\n", stderr)
        }

        // TUI tracker-group changes push back to the session.
        if let t = tui {
            t.onTrackersChanged = { [weak session] trackers in
                let names = trackers.compactMap { $0.kind == .name ? $0.value : nil }
                let paths = trackers.compactMap { $0.kind == .path ? $0.value : nil }
                session?.setTrackerPatterns(names: names, paths: paths)
                let pids: [Int32] = trackers.compactMap { $0.kind == .pid ? Int32($0.value) : nil }
                if !pids.isEmpty { session?.addTrackedPids(Set(pids)) }
            }
        }

        // TUI flow callbacks (network display).
        if let t = tui, net || mitm {
            session.onBytesUpdate = { [weak t] pid, host, port, bytesOut, bytesIn, flowID in
                t?.updateConnectionBytes(pid: pid, remoteAddr: host, remotePort: port,
                                          txBytes: UInt64(bytesOut), rxBytes: UInt64(bytesIn), flowID: flowID)
            }
            session.onConnectionClosed = { [weak t] pid, host, port, flowID in
                t?.markConnectionClosed(pid: pid, remoteAddr: host, remotePort: port, flowID: flowID)
            }
            session.onTraffic = { [weak t] pid, host, port, direction, data, flowID in
                let dir: TrafficDirection = direction == "up" ? .up : .down
                t?.appendTraffic(pid: pid, remoteAddr: host, remotePort: port,
                                 direction: dir, data: data, flowID: flowID)
            }
            if mitm {
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak t] in
                    t?.flash("MITM enabled — intercepting TLS on port 443", duration: 5.0)
                }
            }
        }

        signal(SIGINT, SIG_IGN)
        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler {
            exitAfterRestoringTerminal(message: "", code: 0)
        }
        sigintSource.resume()

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

                    // Traffic modal intercepts keys
                    if t.isTrafficModalOpen {
                        switch ch {
                        case 259: t.trafficModalUp()
                        case 258: t.trafficModalDown()
                        case 27, 113, 10, 13: t.trafficModalClose()  // ESC, q, Enter
                        case 0o631: t.trafficModalMouse()  // KEY_MOUSE — scroll wheel in modal
                        default: break
                        }
                        continue
                    }

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
                        case KEY_MOUSE:
                            if let tui = activeTUI { tui.handleMouse() }
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
                    case 105, 100, 110, 122, 107, 115, 119, 108, 114, 120, 97, 98, 104, 99:
                        // i, d, n, z, k, s, w, l, r, x, h, c — all routed through executeShortcut for flash
                        t.executeShortcut(ch)
                    case 126: // '~' - toggle auto mode
                        t.toggleAutoMode()
                    case 63: // '?'
                        t.toggleHints()
                    case 27: // ESC
                        t.clearSelection()
                    case KEY_MOUSE:
                        // Mouse event - handle mouse click
                        if let tui = activeTUI {
                            tui.handleMouse()
                        }
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
    case .pid, .exec:
        if let p = Int32(group.value), p > 0 { return [p] }
        return []
    case .path:
        return findProcessesByExactPath(group.value)
    }
}
