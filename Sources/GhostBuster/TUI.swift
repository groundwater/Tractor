import Darwin.ncurses
import Foundation

private extension Collection {
    subscript(safe index: Index) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}

private extension Array where Element: Hashable {
    func asSet() -> Set<Element> { Set(self) }
}

// MARK: - ncurses helpers (macros that don't bridge to Swift)

private let NCURSES_ATTR_SHIFT: Int32 = 8
private func NCURSES_BITS(_ mask: Int32, _ shift: Int32) -> Int32 {
    mask << (shift + NCURSES_ATTR_SHIFT)
}
private func COLOR_PAIR(_ n: Int32) -> Int32 { NCURSES_BITS(n, 0) }
private let ATTR_REVERSE = NCURSES_BITS(1, 10)  // A_REVERSE
private let ATTR_DIM     = NCURSES_BITS(1, 12)  // A_DIM
private let ATTR_BOLD    = NCURSES_BITS(1, 13)  // A_BOLD

// MARK: - Color scheme

enum TUIColor: Int32 {
    case running = 1
    case exited = 2
    case failed = 3
    case header = 4
    case dim = 5
    case subNet = 6
    case subFile = 7
}

// MARK: - Per-file tracking

struct FileStats {
    var writes: Int = 0
    var unlinks: Int = 0
    var renames: Int = 0
    var lastWrite: Date = Date()

    var total: Int { writes + unlinks + renames }
}

// MARK: - Per-connection tracking

struct ConnectionStats {
    let remoteAddr: String
    let remotePort: UInt16
    var hostname: String?
    var count: Int = 1
    var alive: Bool = true
    var rxBytes: UInt64 = 0
    var txBytes: UInt64 = 0

    var label: String {
        let host = hostname ?? remoteAddr
        return "\(host):\(remotePort)"
    }
}

// MARK: - Process row model

final class ProcessRow {
    let pid: pid_t
    var ppid: pid_t
    var name: String
    var argv: String
    var startTime: Date
    var endTime: Date?
    var exitCode: Int32?
    var fileOps: Int = 0
    var cwd: String = ""
    var disclosed: Bool = false

    /// Per-file stats: path -> FileStats
    var files: [String: FileStats] = [:]

    /// Per-connection stats: "addr:port" -> ConnectionStats
    var connections: [String: ConnectionStats] = [:]

    /// Disk I/O totals from proc_pid_rusage
    var diskBytesRead: UInt64 = 0
    var diskBytesWritten: UInt64 = 0

    var isRunning: Bool { endTime == nil }

    var runtime: TimeInterval {
        let end = endTime ?? Date()
        return end.timeIntervalSince(startTime)
    }

    var runtimeString: String {
        let t = Int(runtime)
        let h = t / 3600
        let m = (t % 3600) / 60
        let s = t % 60
        if h > 0 {
            return String(format: "%d:%02d:%02d", h, m, s)
        }
        return String(format: "%02d:%02d", m, s)
    }

    /// Files with writes, sorted by most recent write first
    var recentWrittenFiles: [(path: String, stats: FileStats)] {
        files.filter { $0.value.writes > 0 }
            .map { ($0.key, $0.value) }
            .sorted { $0.1.lastWrite > $1.1.lastWrite }
    }

    /// All connections, alive first
    var sortedConnections: [(key: String, stats: ConnectionStats)] {
        connections.map { ($0.key, $0.value) }
            .sorted { ($0.1.alive ? 0 : 1, -$0.1.count) < ($1.1.alive ? 0 : 1, -$1.1.count) }
    }

    init(pid: pid_t, ppid: pid_t, name: String, argv: String) {
        self.pid = pid
        self.ppid = ppid
        self.name = name
        self.argv = argv
        self.startTime = Date()
    }
}

// MARK: - TUI

final class TUI: EventSink {
    private var rows: [pid_t: ProcessRow] = [:]
    private let lock = NSLock()
    private var headerText: String = ""
    private var timer: DispatchSourceTimer?
    private var stopped = false
    private var paused = false
    private var selectedIndex = -1
    private var selectedPids: Set<pid_t> = []
    /// Snapshot of visible process list for cursor navigation
    private var visiblePids: [pid_t] = []
    /// Scroll offset — index of first visible process in the list
    private var scrollOffset = 0

    /// PIDs to exclude from display (GhostBuster itself + parents)
    private var excludedPids: Set<pid_t> = []
    /// Our own PID for dynamic child exclusion
    private var selfPid: pid_t = 0

    /// Reverse DNS cache: IP -> hostname (nil = pending, "" = failed)
    private var dnsCache: [String: String] = [:]

    /// Network stats from private framework
    private var netStats: NetworkStats?

    /// SNI sniffer for hostname resolution
    private var sniSniffer: SNISniffer?

    func excludeSelf() {
        selfPid = getpid()
        lock.lock()
        excludedPids.insert(selfPid)
        // Exclude direct parent (sudo) only
        var info = proc_bsdinfo()
        let size = proc_pidinfo(selfPid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        if size > 0 {
            excludedPids.insert(pid_t(info.pbi_ppid))
        }
        lock.unlock()
    }

    private func isExcluded(_ row: ProcessRow) -> Bool {
        if excludedPids.contains(row.pid) { return true }
        // Exclude any process whose parent is us (e.g. subprocesses we spawn)
        if row.ppid == selfPid { return true }
        return false
    }

    func start(header: String) {
        headerText = header

        // Start network stats and SNI sniffer
        netStats = NetworkStats()
        netStats?.start()
        sniSniffer = SNISniffer()
        sniSniffer?.start()

        setlocale(LC_ALL, "")
        initscr()
        cbreak()
        noecho()
        curs_set(0)
        nodelay(stdscr, true)
        keypad(stdscr, true)

        guard has_colors() else {
            endwin()
            fputs("ERROR: Terminal does not support colors\n", stderr)
            Foundation.exit(1)
        }

        start_color()
        use_default_colors()

        init_pair(Int16(TUIColor.running.rawValue), Int16(COLOR_GREEN), -1)
        init_pair(Int16(TUIColor.exited.rawValue),  Int16(COLOR_WHITE), -1)
        init_pair(Int16(TUIColor.failed.rawValue),  Int16(COLOR_RED), -1)
        init_pair(Int16(TUIColor.header.rawValue),  Int16(COLOR_CYAN), -1)
        init_pair(Int16(TUIColor.dim.rawValue),     Int16(COLOR_BLACK), -1)  // bright black = gray
        init_pair(Int16(TUIColor.subNet.rawValue),  Int16(COLOR_YELLOW), -1)
        init_pair(Int16(TUIColor.subFile.rawValue), Int16(COLOR_MAGENTA), -1)

        // Install SIGWINCH handler
        signal(SIGWINCH) { _ in
            endwin()
            refresh()
        }

        // Refresh loop at 1Hz
        let source = DispatchSource.makeTimerSource(queue: .main)
        source.schedule(deadline: .now(), repeating: .seconds(1))
        source.setEventHandler { [weak self] in
            self?.render()
        }
        source.resume()
        timer = source
    }

    func stop() {
        guard !stopped else { return }
        stopped = true
        timer?.cancel()
        timer = nil
        netStats?.stop()
        sniSniffer?.stop()
        endwin()
    }

    func moveUp() {
        if selectedIndex < 0 { selectedIndex = visiblePids.count - 1 }
        else if selectedIndex > 0 { selectedIndex -= 1 }
        selectedPids = [visiblePids[safe: selectedIndex]].compactMap { $0 }.asSet()
        render()
    }

    func moveDown() {
        if selectedIndex < 0 { selectedIndex = 0 }
        else if selectedIndex < visiblePids.count - 1 { selectedIndex += 1 }
        selectedPids = [visiblePids[safe: selectedIndex]].compactMap { $0 }.asSet()
        render()
    }

    func shiftMoveUp() {
        if selectedIndex > 0 {
            // Add current to selection before moving
            if let pid = visiblePids[safe: selectedIndex] { selectedPids.insert(pid) }
            selectedIndex -= 1
            if let pid = visiblePids[safe: selectedIndex] { selectedPids.insert(pid) }
        }
        render()
    }

    func shiftMoveDown() {
        if selectedIndex < visiblePids.count - 1 {
            if let pid = visiblePids[safe: selectedIndex] { selectedPids.insert(pid) }
            selectedIndex += 1
            if let pid = visiblePids[safe: selectedIndex] { selectedPids.insert(pid) }
        }
        render()
    }

    func clearSelection() {
        selectedPids.removeAll()
        selectedIndex = -1
        let wasPaused = paused
        paused = false
        render()
        paused = wasPaused
    }

    func disclose() {
        let pids = effectiveSelection()
        lock.lock()
        for pid in pids { rows[pid]?.disclosed = true }
        lock.unlock()
        render()
    }

    func collapse() {
        let pids = effectiveSelection()
        lock.lock()
        for pid in pids { rows[pid]?.disclosed = false }
        lock.unlock()
        render()
    }

    func toggleDisclose() {
        let pids = effectiveSelection()
        lock.lock()
        for pid in pids {
            if let row = rows[pid] { row.disclosed = !row.disclosed }
        }
        lock.unlock()
        render()
    }

    /// Returns selected PIDs, or just the cursor PID if no multi-selection
    private func effectiveSelection() -> Set<pid_t> {
        if selectedPids.isEmpty, let pid = visiblePids[safe: selectedIndex] {
            return [pid]
        }
        return selectedPids
    }

    func togglePause() {
        paused = !paused
        drawFooter(maxY: getmaxy(stdscr), maxX: getmaxx(stdscr))
        refresh()
    }

    // MARK: - Data updates (called from ES callback thread)

    func addProcess(pid: pid_t, ppid: pid_t, name: String, argv: String) {
        lock.lock()
        defer { lock.unlock() }
        rows[pid] = ProcessRow(pid: pid, ppid: ppid, name: name, argv: argv)
    }

    func markExited(pid: pid_t, exitCode: Int32 = 0) {
        lock.lock()
        defer { lock.unlock() }
        if let row = rows[pid] {
            row.endTime = Date()
            row.exitCode = exitCode
        }
    }

    func recordFileOp(type: String, pid: pid_t, path: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let row = rows[pid] else { return }
        row.fileOps += 1
        guard type != "open" else { return }
        var stats = row.files[path, default: FileStats()]
        switch type {
        case "write":  stats.writes += 1; stats.lastWrite = Date()
        case "unlink": stats.unlinks += 1
        case "rename": stats.writes += 1; stats.lastWrite = Date()
        default: break
        }
        row.files[path] = stats
    }

    func recordConnect(pid: pid_t, remoteAddr: String, remotePort: UInt16) {
        lock.lock()
        defer { lock.unlock() }
        guard let row = rows[pid] else { return }
        let key = "\(remoteAddr):\(remotePort)"
        if var existing = row.connections[key] {
            existing.count += 1
            row.connections[key] = existing
        } else {
            row.connections[key] = ConnectionStats(remoteAddr: remoteAddr, remotePort: remotePort)
        }
    }

    // MARK: - EventSink

    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t) {
        addProcess(pid: pid, ppid: ppid, name: process, argv: argv)
    }

    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String]) {
        // For renames, use the destination path (that's the file that matters)
        let path = details["to"] ?? details["path"] ?? details["from"] ?? "?"
        recordFileOp(type: type, pid: pid, path: path)
    }

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16) {
        recordConnect(pid: pid, remoteAddr: remoteAddr, remotePort: remotePort)
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t) {
        markExited(pid: pid)
    }

    // MARK: - Polling (called during render on main thread)

    private func pollRunningProcesses() {
        lock.lock()
        let running = rows.values.filter { $0.isRunning }
        let pidSet = Set(running.map { $0.pid })
        let pids = Array(pidSet)
        lock.unlock()

        // Refresh network stats from NetworkStatistics.framework
        netStats?.refresh()

        // Update connections from NetworkStats
        for pid in pids {
            let netConns = netStats?.connectionsForPid(pid) ?? []
            let currentKeys = Set(netConns.map { "\($0.remoteAddr):\($0.remotePort)" })

            lock.lock()
            if let row = rows[pid] {
                // Mark stale connections
                for (key, var conn) in row.connections {
                    conn.alive = currentKeys.contains(key)
                    row.connections[key] = conn
                }
                // Update or add connections with byte counts
                for nc in netConns {
                    let key = "\(nc.remoteAddr):\(nc.remotePort)"
                    var conn = row.connections[key] ?? ConnectionStats(remoteAddr: nc.remoteAddr, remotePort: nc.remotePort)
                    conn.rxBytes = nc.rxBytes
                    conn.txBytes = nc.txBytes
                    conn.alive = nc.alive
                    row.connections[key] = conn
                }
                // Prune: keep alive connections + up to 3 most recent dead ones
                let dead = row.connections.filter { !$0.value.alive }
                if dead.count > 3 {
                    let toRemove = dead.sorted { $0.value.txBytes < $1.value.txBytes }
                        .prefix(dead.count - 3)
                    for (key, _) in toRemove {
                        row.connections.removeValue(forKey: key)
                    }
                }
                // Prune: keep only the 20 most recently written files
                if row.files.count > 20 {
                    let sorted = row.files.sorted { $0.value.lastWrite < $1.value.lastWrite }
                    for (path, _) in sorted.prefix(row.files.count - 20) {
                        row.files.removeValue(forKey: path)
                    }
                }
            }
            lock.unlock()
        }

        // Poll CWD for running processes
        for pid in pids {
            var vnodeInfo = proc_vnodepathinfo()
            let size = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vnodeInfo, Int32(MemoryLayout<proc_vnodepathinfo>.size))
            if size > 0 {
                lock.lock()
                if let row = rows[pid], row.cwd.isEmpty {
                    row.cwd = withUnsafePointer(to: vnodeInfo.pvi_cdir.vip_path) {
                        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                            String(cString: $0)
                        }
                    }
                }
                lock.unlock()
            }
        }

        // Poll disk I/O via proc_pid_rusage
        for pid in pids {
            var rusage = rusage_info_v4()
            let ret = withUnsafeMutablePointer(to: &rusage) { ptr in
                ptr.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { rustPtr in
                    proc_pid_rusage(pid, RUSAGE_INFO_V4, rustPtr)
                }
            }
            if ret == 0 {
                lock.lock()
                if let row = rows[pid] {
                    row.diskBytesRead = rusage.ri_diskio_bytesread
                    row.diskBytesWritten = rusage.ri_diskio_byteswritten
                }
                lock.unlock()
            }
        }

        // Resolve DNS for any new IPs
        resolveNewAddresses()
    }

    private func resolveNewAddresses() {
        lock.lock()
        var toResolve: [(addr: String, port: UInt16)] = []
        for row in rows.values {
            for conn in row.connections.values {
                if conn.hostname == nil && dnsCache[conn.remoteAddr] == nil {
                    toResolve.append((conn.remoteAddr, conn.remotePort))
                    dnsCache[conn.remoteAddr] = ""  // Mark as pending
                }
            }
        }
        lock.unlock()

        // Resolve in background
        for item in toResolve {
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let hostname = self?.resolveHost(item.addr, port: item.port)
                self?.lock.lock()
                self?.dnsCache[item.addr] = hostname ?? ""
                // Update all connections with this IP
                if let hostname = hostname, !hostname.isEmpty {
                    for row in self?.rows.values ?? [:].values {
                        for (key, var conn) in row.connections {
                            if conn.remoteAddr == item.addr {
                                conn.hostname = hostname
                                row.connections[key] = conn
                            }
                        }
                    }
                }
                self?.lock.unlock()
            }
        }
    }

    private func resolveHost(_ ip: String, port: UInt16) -> String? {
        // Try SNI sniffer first — has the hostname from the ClientHello
        if let name = sniSniffer?.hostname(for: ip) { return name }
        // Fall back to reverse DNS
        if let name = reverseDNS(ip) { return name }
        return nil
    }

    private func reverseDNS(_ ip: String) -> String? {
        // Try PTR record first
        var hints = addrinfo()
        hints.ai_flags = AI_NUMERICHOST
        hints.ai_family = AF_UNSPEC

        var res: UnsafeMutablePointer<addrinfo>?
        if getaddrinfo(ip, nil, &hints, &res) == 0, let addrInfo = res {
            defer { freeaddrinfo(addrInfo) }
            var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let ret = getnameinfo(
                addrInfo.pointee.ai_addr, addrInfo.pointee.ai_addrlen,
                &hostBuf, socklen_t(hostBuf.count),
                nil, 0, 0
            )
            if ret == 0 {
                let hostname = String(cString: hostBuf)
                if hostname != ip { return hostname }
            }
        }

        return nil
    }

    // MARK: - Rendering

    private func render() {
        guard !paused else { return }
        pollRunningProcesses()

        lock.lock()
        let allRows = Array(rows.values)
        lock.unlock()

        // Filter out GhostBuster's own processes and its children
        let visible = allRows.filter { !isExcluded($0) }

        // Sort: running first (oldest start first), then exited (most recent exit first)
        let running = visible.filter { $0.isRunning }.sorted { $0.startTime < $1.startTime }
        let exited = visible.filter { !$0.isRunning }.sorted { $0.endTime! > $1.endTime! }

        let maxY = getmaxy(stdscr)
        let maxX = getmaxx(stdscr)

        erase()

        // Header
        attron(COLOR_PAIR(TUIColor.header.rawValue) | ATTR_BOLD)
        mvaddstr(0, 0, truncate(headerText, to: Int(maxX)))
        attroff(COLOR_PAIR(TUIColor.header.rawValue) | ATTR_BOLD)

        // Stats line
        let stats = "\(running.count) running, \(exited.count) exited, \(visible.count) total"
        attron(COLOR_PAIR(TUIColor.dim.rawValue) | ATTR_BOLD)
        mvaddstr(1, 0, truncate(stats, to: Int(maxX)))
        attroff(COLOR_PAIR(TUIColor.dim.rawValue) | ATTR_BOLD)

        // Column header
        let colHeader = formatLine(
            pid: "PID", runtime: "TIME", ops: "OPS",
            status: "STATUS", process: "PROCESS",
            maxWidth: Int(maxX)
        )
        attron(ATTR_BOLD)
        mvaddstr(3, 0, colHeader)
        attroff(ATTR_BOLD)

        let availableLines = Int(maxY) - 5  // header(1) + stats(1) + blank(1) + colheader(1) + footer(1)

        // Build visible process list
        let allVisible = running + exited
        visiblePids = allVisible.map { $0.pid }
        // Clamp selection (-1 = no cursor)
        if selectedIndex >= allVisible.count { selectedIndex = max(-1, allVisible.count - 1) }
        let cursorPid: pid_t = (selectedIndex >= 0 && selectedIndex < allVisible.count)
            ? allVisible[selectedIndex].pid : pid_t(-1)

        // Calculate line count per process
        func linesFor(_ row: ProcessRow) -> Int {
            if row.disclosed {
                // 1 (main) + connections + files + overflow indicators
                let conns = row.sortedConnections.count
                let files = row.recentWrittenFiles.count
                return 1 + min(conns, 20) + (conns > 20 ? 1 : 0) + min(files, 20) + (files > 20 ? 1 : 0)
            }
            return 1
        }

        // Adjust scroll offset to keep selectedIndex visible
        if selectedIndex >= 0 {
            // Scroll up if cursor is above viewport
            if selectedIndex < scrollOffset {
                scrollOffset = selectedIndex
            }
            // Scroll down if cursor would be below viewport
            var linesUsed = 0
            for i in scrollOffset...selectedIndex {
                linesUsed += linesFor(allVisible[i])
            }
            while linesUsed > availableLines && scrollOffset < selectedIndex {
                linesUsed -= linesFor(allVisible[scrollOffset])
                scrollOffset += 1
            }
        }
        // Clamp scroll offset
        scrollOffset = max(0, min(scrollOffset, allVisible.count - 1))

        // Render from scrollOffset
        var y: Int32 = 4
        let lastRow = maxY - 2

        for i in scrollOffset..<allVisible.count {
            guard y <= lastRow else { break }
            let row = allVisible[i]
            let isHighlighted = row.pid == cursorPid || selectedPids.contains(row.pid)
            let showSub = row.disclosed

            if showSub {
                y = renderProcessRow(row, y: y, maxX: maxX, maxY: maxY, maxSubRows: Int(lastRow - y), showSubRows: true, highlight: isHighlighted)
            } else {
                y = renderProcessRow(row, y: y, maxX: maxX, maxY: maxY, maxSubRows: 0, showSubRows: false, highlight: isHighlighted)
            }
        }

        // Show scroll indicator if content is clipped
        let totalProcesses = allVisible.count
        if scrollOffset > 0 || y > lastRow {
            // Show on the stats line
        }

        drawFooter(maxY: maxY, maxX: maxX)

        refresh()
    }

    private func drawFooter(maxY: Int32, maxX: Int32) {
        let width = Int(maxX)
        let label: String
        if paused {
            label = "PAUSED"
        } else {
            label = "q: quit  space: pause  \u{2191}\u{2193}: select  shift+\u{2191}\u{2193}: multi  enter: expand  esc: clear"
        }

        let text: String
        if paused {
            let leftPadding = max(0, (width - label.count) / 2)
            text = String(repeating: " ", count: leftPadding) + label
        } else {
            text = label
        }
        let padded = String(text.prefix(width))
            + String(repeating: " ", count: max(0, width - text.count))

        let attr: Int32
        if paused {
            attr = ATTR_REVERSE | ATTR_BOLD
        } else {
            attr = COLOR_PAIR(TUIColor.dim.rawValue) | ATTR_BOLD
        }
        attron(attr)
        mvaddstr(maxY - 1, 0, padded)
        attroff(attr)
    }

    private func renderProcessRow(_ row: ProcessRow, y: Int32, maxX: Int32, maxY: Int32, maxSubRows: Int, showSubRows: Bool, highlight: Bool = false) -> Int32 {
        var y = y

        let status: String
        let color: TUIColor
        if row.isRunning {
            status = "RUN"
            color = .running
        } else if let code = row.exitCode, code != 0 {
            status = "ERR \(code)"
            color = .failed
        } else {
            status = "OK"
            color = .exited
        }

        let hasDetail = !row.connections.isEmpty || !row.files.isEmpty
        let disc = !hasDetail ? "  " : (row.disclosed ? "\u{25BC} " : "\u{25B6} ")
        let processLabel = row.argv.isEmpty ? row.name : row.argv
        let line = formatLine(
            pid: "\(row.pid)",
            runtime: row.runtimeString,
            ops: "\(row.fileOps)",
            status: status,
            process: processLabel,
            maxWidth: Int(maxX) - 2
        )

        var attr = row.isRunning
            ? COLOR_PAIR(color.rawValue)
            : COLOR_PAIR(color.rawValue) | ATTR_DIM
        if highlight { attr |= ATTR_REVERSE }

        attron(attr)
        mvaddstr(y, 0, disc + line)
        attroff(attr)
        y += 1

        guard showSubRows else { return y }

        // Sub-rows: connections (alive = yellow, dead = gray) with byte counts
        let conns = row.sortedConnections
        for (i, conn) in conns.enumerated() {
            guard y < maxY - 1, i < maxSubRows else { break }
            var line = "    -> \(conn.stats.label)"
            if conn.stats.txBytes > 0 || conn.stats.rxBytes > 0 {
                line += "  \u{2191}\(formatBytes(conn.stats.txBytes)) \u{2193}\(formatBytes(conn.stats.rxBytes))"
            }
            let subLine = truncate(line, to: Int(maxX))
            let connAttr = conn.stats.alive
                ? COLOR_PAIR(TUIColor.subNet.rawValue) | ATTR_DIM
                : COLOR_PAIR(TUIColor.exited.rawValue) | ATTR_DIM
            attron(connAttr)
            mvaddstr(y, 0, subLine)
            attroff(connAttr)
            y += 1
        }
        if conns.count > maxSubRows, y < maxY - 1 {
            let moreNet = "    -> ... +\(conns.count - maxSubRows) more"
            attron(COLOR_PAIR(TUIColor.subNet.rawValue) | ATTR_DIM)
            mvaddstr(y, 0, truncate(moreNet, to: Int(maxX)))
            attroff(COLOR_PAIR(TUIColor.subNet.rawValue) | ATTR_DIM)
            y += 1
        }


        // Sub-rows: most recently written files (latest first)
        let writtenFiles = row.recentWrittenFiles
        let showFiles = Array(writtenFiles.prefix(maxSubRows))
        for file in showFiles {
            guard y < maxY - 1 else { break }
            var parts: [String] = []
            parts.append("W:\(file.stats.writes)")
            // Show file size and check if still exists
            var sb = stat()
            let fileExists = stat(file.path, &sb) == 0
            if fileExists && sb.st_size > 0 {
                parts.append(formatBytes(UInt64(sb.st_size)))
            }
            if file.stats.unlinks > 0 { parts.append("D:\(file.stats.unlinks)") }
            if file.stats.renames > 0 { parts.append("MV:\(file.stats.renames)") }
            let statsStr = parts.joined(separator: " ")
            let relPath = relativePath(file.path, cwd: row.cwd)
            let shortPath = shortenPath(relPath, maxLen: Int(maxX) - 12 - statsStr.count)
            let subLine = truncate(
                "    -> \(shortPath)  \(statsStr)",
                to: Int(maxX)
            )
            let fileAttr = fileExists
                ? COLOR_PAIR(TUIColor.subFile.rawValue) | ATTR_DIM
                : COLOR_PAIR(TUIColor.exited.rawValue) | ATTR_DIM
            attron(fileAttr)
            mvaddstr(y, 0, subLine)
            attroff(fileAttr)
            y += 1
        }
        if writtenFiles.count > maxSubRows, y < maxY - 1 {
            let moreFile = "  FILE ... +\(writtenFiles.count - maxSubRows) more"
            attron(COLOR_PAIR(TUIColor.subFile.rawValue) | ATTR_DIM)
            mvaddstr(y, 0, truncate(moreFile, to: Int(maxX)))
            attroff(COLOR_PAIR(TUIColor.subFile.rawValue) | ATTR_DIM)
            y += 1
        }

        return y
    }

    // MARK: - Formatting helpers

    private func formatLine(pid: String, runtime: String, ops: String, status: String, process: String, maxWidth: Int) -> String {
        let prefix = String(format: "%-7s %-6s %-5s %-5s ",
                            (pid as NSString).utf8String!,
                            (runtime as NSString).utf8String!,
                            (ops as NSString).utf8String!,
                            (status as NSString).utf8String!)
        let processWidth = max(10, maxWidth - prefix.count)
        return prefix + truncateProcess(process, to: processWidth)
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes)B" }
        if bytes < 1024 * 1024 { return "\(bytes / 1024)KB" }
        if bytes < 1024 * 1024 * 1024 { return String(format: "%.1fMB", Double(bytes) / (1024 * 1024)) }
        return String(format: "%.1fGB", Double(bytes) / (1024 * 1024 * 1024))
    }

    /// Truncate middle of string, keeping equal start and end
    private func truncate(_ s: String, to maxLen: Int) -> String {
        guard s.count > maxLen, maxLen > 5 else { return s }
        let half = (maxLen - 3) / 2
        return String(s.prefix(half)) + "..." + String(s.suffix(half))
    }

    /// Smart truncation for process command lines:
    /// 1. Always show the binary name (last path component)
    /// 2. Truncate the middle of the directory path
    /// 3. Truncate the middle of arguments
    private func truncateProcess(_ s: String, to maxLen: Int) -> String {
        guard s.count > maxLen, maxLen > 10 else { return s }

        // Split into argv[0] (path) and the rest (arguments)
        let firstSpace = s.firstIndex(of: " ")
        let path = firstSpace != nil ? String(s[s.startIndex..<firstSpace!]) : s
        let args = firstSpace != nil ? String(s[s.index(after: firstSpace!)...]) : ""

        // Get binary name from path
        let binaryName = (path as NSString).lastPathComponent
        let dirPath = (path as NSString).deletingLastPathComponent

        // Budget: binary name is sacred, allocate remaining to dir + args
        let binaryLen = binaryName.count
        let separator = args.isEmpty ? "" : " "
        let overhead = 3 + separator.count  // "..." + space
        let available = maxLen - binaryLen - overhead

        if available <= 0 {
            // Not even room for the binary name
            return truncate(binaryName + separator + args, to: maxLen)
        }

        if args.isEmpty {
            // Path only — truncate directory middle, keep binary
            if dirPath.isEmpty { return binaryName }
            let dirBudget = maxLen - binaryLen - 4  // ".../binary"
            if dirBudget <= 0 { return binaryName }
            let truncDir = truncate(dirPath, to: dirBudget)
            return truncDir + "/" + binaryName
        }

        // Have both path and args — give 1/3 to dir, 2/3 to args
        let dirBudget = max(0, available / 3)
        let argsBudget = available - dirBudget

        var result = ""
        if dirBudget > 3 && !dirPath.isEmpty {
            result = truncate(dirPath, to: dirBudget) + "/"
        }
        result += binaryName + separator
        result += truncate(args, to: argsBudget)

        return result
    }

    /// Make path relative to CWD if it's a descendant, otherwise return absolute
    private func relativePath(_ path: String, cwd: String) -> String {
        guard !cwd.isEmpty else { return path }
        let cwdSlash = cwd.hasSuffix("/") ? cwd : cwd + "/"
        if path.hasPrefix(cwdSlash) {
            return String(path.dropFirst(cwdSlash.count))
        }
        return path
    }

    private func shortenPath(_ path: String, maxLen: Int) -> String {
        guard path.count > maxLen, maxLen > 5 else { return path }
        // Show last path components that fit
        let components = path.split(separator: "/")
        var result = String(components.last ?? Substring(path))
        if result.count > maxLen {
            return truncate(result, to: maxLen)
        }
        // Try adding parent
        if components.count >= 2 {
            let parent = components[components.count - 2]
            let candidate = "\(parent)/\(result)"
            if candidate.count <= maxLen {
                result = candidate
            } else {
                return ".../" + result
            }
        }
        return result
    }
}
