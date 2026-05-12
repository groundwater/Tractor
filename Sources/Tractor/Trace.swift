import ArgumentParser
import CoreGraphics
import Darwin.ncurses
import Foundation

// KEY_MOUSE constant for ncurses mouse events (0o631 = 409 in decimal)
private let KEY_MOUSE: Int32 = 0o631

/// Globals for signal-safe cleanup
private var activeTUI: TUI?
private var activeInputSource: DispatchSourceTimer?
private var activeSQLiteLog: SQLiteLog?
private var activeFlowClient: FlowXPCClient?
private var activeESClient: ESXPCClient?

private func exitAfterRestoringTerminal(message: String, code: Int32 = 1) {
    activeInputSource?.cancel()
    activeTUI?.stop()
    activeSQLiteLog?.close()
    // Close XPC connections — sysexts see the disconnects and stop their daemons.
    activeESClient?.stop()
    activeESClient = nil
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
        guard ESXPCClient.isAvailable() else {
            throw ValidationError("Endpoint Security extension is not active. Run 'sudo tractor activate endpoint-security', approve it in System Settings if prompted, then retry.")
        }
        let mitmCAPaths = mitm ? try TrustCA.requiredExistingCAPaths() : nil

        let tree = ProcessTree()

        // Build header label from all trackers
        var labels: [String] = []
        for n in name { labels.append(n) }
        for p in pid { labels.append("PID \(p)") }
        for p in pids { labels.append("PID \(p)") }
        for p in path { labels.append(p) }
        for cmd in exec { labels.append(cmd) }
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
                dbPath = try TractorPaths.sharedLogPath()
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

        // ES events come from the TractorES sysext; NE flow events from TractorNE.
        let esClient = ESXPCClient()
        activeESClient = esClient
        activeTUI = tui
        esClient.onConnectionError = { error in
            exitAfterRestoringTerminal(
                message: "Tractor: lost Endpoint Security connection: \(error.localizedDescription)",
                code: 1
            )
        }

        // ES exec → mirror into local ProcessTree and feed the sink (TUI + SQLite + JSON)
        esClient.onExec = { [weak tree, weak tui] pid, ppid, process, argv, user in
            tree?.trackIfChild(pid: pid, ppid: ppid)
            tree?.addRoots([pid])
            if let t = tui {
                t.inheritGroupMembership(child: pid, parent: ppid)
                let name = (process as NSString).lastPathComponent
                t.matchProcessToGroups(pid: pid, name: name, path: process)
            }
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
        esClient.setTrackerPatterns(
            names: tui?.trackerGroups.compactMap { $0.kind == .name ? $0.value : nil } ?? name,
            paths: tui?.trackerGroups.compactMap { $0.kind == .path ? $0.value : nil } ?? path
        )
        esClient.addTrackedPids(tree.snapshot)

        // --exec: fork each command, register its PID with the sysext, then release
        // it to call execve. The pipe gate guarantees the sysext sees AUTH_EXEC for
        // a PID that's already in its tracked set.
        for cmd in exec {
            let argv = SpawnedChild.argv(for: cmd)
            guard !argv.isEmpty else {
                throw ValidationError("--exec value is empty")
            }
            let pending = try SpawnedChild.fork(argv: argv, stdio: .devNull)
            tree.addRoots([pending.pid])
            if let t = tui {
                t.addTrackerGroup(kind: .exec, value: "\(pending.pid)", label: cmd)
            }
            esClient.addTrackedPidsSync([pending.pid])
            pending.release()
            fputs("Tractor: spawned [\(pending.pid)] \(cmd)\n", stderr)
        }

        // Push pattern updates whenever the TUI's tracker groups change.
        if let t = tui {
            t.onTrackersChanged = { [weak esClient] trackers in
                let names = trackers.compactMap { $0.kind == .name ? $0.value : nil }
                let paths = trackers.compactMap { $0.kind == .path ? $0.value : nil }
                esClient?.setTrackerPatterns(names: names, paths: paths)
                let pids: [Int32] = trackers.compactMap { $0.kind == .pid ? Int32($0.value) : nil }
                if !pids.isEmpty { esClient?.addTrackedPids(Set(pids)) }
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

        // Activate network extension flow interception (--mitm implies --net).
        if net || mitm {
            if FlowXPCClient.isAvailable() {
                let flowClient = FlowXPCClient(sink: sink)
                activeFlowClient = flowClient

                // Set up MITM exported object BEFORE start (NSXPCConnection requires
                // exportedObject to be configured pre-resume).
                if mitm {
                    guard let caPaths = mitmCAPaths else {
                        throw ValidationError("MITM requires CA files. Run 'sudo tractor activate certificate-root' first.")
                    }
                    let certPEM = try String(contentsOfFile: caPaths.certPath, encoding: .utf8)
                    let keyPEM = try String(contentsOfFile: caPaths.keyPath, encoding: .utf8)
                    flowClient.setupMITM(caCertPEM: certPEM, caKeyPEM: keyPEM)
                }

                flowClient.onConnectionError = { error in
                    fputs("Tractor: network extension unavailable, continuing without network capture (\(error.localizedDescription)).\n", stderr)
                    activeFlowClient?.stop()
                    activeFlowClient = nil
                    esClient.onTrackedPidsChanged = nil
                }

                flowClient.start()
                flowClient.updateWatchList(tree.snapshot)

                // Mirror ES daemon's tracked-PID set into the NE proxy's watch list.
                esClient.onTrackedPidsChanged = { [weak flowClient] pids in
                    flowClient?.updateWatchList(pids)
                }

                if mitm {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                        flowClient.setMITMEnabled(true)
                        if let t = tui {
                            t.flash("MITM enabled — intercepting TLS on port 443", duration: 5.0)
                        }
                    }
                }

                if let t = tui {
                    flowClient.onBytesUpdate = { pid, host, port, bytesOut, bytesIn, flowID in
                        t.updateConnectionBytes(pid: pid, remoteAddr: host, remotePort: port,
                                                txBytes: UInt64(bytesOut), rxBytes: UInt64(bytesIn), flowID: flowID)
                    }
                    flowClient.onConnectionClosed = { pid, host, port, flowID in
                        t.markConnectionClosed(pid: pid, remoteAddr: host, remotePort: port, flowID: flowID)
                    }
                    flowClient.onTraffic = { pid, host, port, direction, data, flowID in
                        let dir: TrafficDirection = direction == "up" ? .up : .down
                        t.appendTraffic(pid: pid, remoteAddr: host, remotePort: port,
                                        direction: dir, data: data, flowID: flowID)
                        let logContent = String(data: data, encoding: .utf8)
                            ?? String(data: data, encoding: .isoLatin1) ?? "<binary>"
                        activeSQLiteLog?.logTraffic(pid: pid, host: host, port: port,
                                                    direction: direction, content: logContent)
                    }
                }
            } else {
                let msg = mitm
                    ? "Tractor: network extension is not active; continuing without network capture or MITM. Run 'sudo tractor activate network-extension' to enable it."
                    : "Tractor: network extension is not active; continuing without network capture. Run 'sudo tractor activate network-extension' to enable it."
                if let t = tui {
                    t.flash(msg, duration: 5.0)
                }
                fputs("\(msg)\n", stderr)
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
