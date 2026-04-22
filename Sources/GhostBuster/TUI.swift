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
private let ATTR_UNDERLINE = NCURSES_BITS(1, 9)  // A_UNDERLINE
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
    case menuBar = 8
    case menuHighlight = 9
}

// MARK: - Sample tree node

final class SampleNode {
    let name: String          // function name or "Thread_N"
    let count: Int            // sample count
    let pct: Int              // percentage of total
    var children: [SampleNode] = []
    var disclosed: Bool = false

    /// Has children worth showing (>= threshold)
    var hasChildren: Bool { !children.isEmpty }

    init(name: String, count: Int, pct: Int) {
        self.name = name
        self.count = count
        self.pct = pct
    }
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
    var isStopped: Bool = false
    var disclosed: Bool = false

    /// Panel visibility (toggled by i/s/w) and disclosure state
    var infoVisible: Bool = false
    var infoDisclosed: Bool = false
    var filesVisible: Bool = false
    var netVisible: Bool = false
    var sampleVisible: Bool = false
    var sampleDisclosed: Bool = false
    var waitVisible: Bool = false
    var waitDisclosed: Bool = false

    /// Sample/wait results stored per-process
    var sampleTree: [SampleNode] = []
    var waitResults: [String] = []
    var isSampling: Bool = false
    var processDisclosed: Bool = false
    var argsDisclosed: Bool = false
    var envDisclosed: Bool = false
    var resourcesDisclosed: Bool = false
    var filesDisclosed: Bool = false
    var netDisclosed: Bool = false

    /// Cached process info (loaded lazily when Process section is disclosed)
    var fullPath: String = ""
    var argvArray: [String] = []
    var envVars: [String] = []
    var infoLoaded: Bool = false

    /// Resource stats (polled only when Resources is disclosed)
    var cpuUser: TimeInterval = 0
    var cpuSys: TimeInterval = 0
    var rss: UInt64 = 0
    var fdCount: Int = 0

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

// MARK: - Display row types for flat cursor navigation

private enum DisplayRow: Equatable {
    case process(pid_t, Int)             // pid, depth (for tree indent)
    case processHeader(pid_t)            // "Process" section
    case processDetail(pid_t, String)    // pid, label (Path:, CWD:, etc)
    case argsHeader(pid_t)
    case argDetail(pid_t, Int)           // pid, arg index
    case envHeader(pid_t)
    case envDetail(pid_t, Int)           // pid, env index
    case resourcesHeader(pid_t)
    case resourceDetail(pid_t, String)   // pid, label
    case filesHeader(pid_t)
    case fileDetail(pid_t, String)       // pid, path
    case netHeader(pid_t)
    case netDetail(pid_t, String)        // pid, connection key
    case separator(pid_t)               // horizontal rule between info and children
    case infoBorderTop(pid_t, Int)      // pid, depth — top of info box
    case infoBorderBottom(pid_t, Int)   // pid, depth — bottom of info box
    case sampleHeader(pid_t)            // "Sample" box header
    case sampleNode(pid_t, [Int])       // pid, path (indices into tree)
    case waitHeader(pid_t)              // "Wait" box header
    case waitLine(pid_t, Int)           // pid, result index
}

// MARK: - Menu system

enum MenuID: Equatable { case file, edit, process, sample, network, files, view }

private struct MenuItem {
    let label: String
    let shortcut: String    // e.g. "s", "" for none
    let key: Int32?         // ASCII code for shortcut, nil for none
    var checked: Bool = false
    var enabled: Bool = true
    var isSeparator: Bool = false

    static func sep() -> MenuItem {
        var m = MenuItem(label: "", shortcut: "", key: nil)
        m.isSeparator = true
        return m
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
    private var showHints = true
    private var killMode = false       // waiting for signal number
    private var showExited = true

    // Menu state
    private var activeMenu: MenuID? = nil
    private var menuItemIndex = 0
    private var menuFlash: MenuID? = nil
    private var menuFlashTime: Date? = nil

    // Sample config modal
    var isSampleConfigOpen = false
    private var sampleDuration = 3
    private var sampleThreshold = 5
    private var sampleMaxDepth = 5
    private var sampleConfigField = 0  // 0=duration, 1=threshold, 2=maxDepth
    private var selectedIndex = 0
    /// Selected display row indices for multi-select
    private var selectedIndices: Set<Int> = []
    /// Flat list of all displayable rows for cursor navigation
    private var displayRows: [DisplayRow] = []
    /// Scroll offset — index of first visible row
    private var scrollOffset = 0

    private enum ViewMode { case flat, tree }
    private var viewMode: ViewMode = .tree

    private struct ColumnLayout {
        let pid: Int
        let time: Int
        let ops: Int
        let status: Int
        let process: Int
    }

    private static let baseColumnLayout = ColumnLayout(pid: 2, time: 10, ops: 17, status: 23, process: 29)

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
        set_escdelay(25)  // 25ms instead of default 1000ms

        // Ensure shifted arrow sequences are registered
        define_key("\u{1b}[1;2D", 393)  // KEY_SLEFT
        define_key("\u{1b}[1;2C", 402)  // KEY_SRIGHT
        define_key("\u{1b}[1;2A", 337)  // KEY_SR (Shift+Up)
        define_key("\u{1b}[1;2B", 336)  // KEY_SF (Shift+Down)

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
        init_pair(Int16(TUIColor.menuBar.rawValue), Int16(COLOR_BLACK), Int16(COLOR_WHITE))
        init_pair(Int16(TUIColor.menuHighlight.rawValue), Int16(COLOR_WHITE), Int16(COLOR_BLUE))

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

    private func isSelectable(_ index: Int) -> Bool {
        guard let dr = displayRows[safe: index] else { return false }
        switch dr {
        case .infoBorderTop, .infoBorderBottom, .separator: return false
        default: return true
        }
    }

    func moveUp() {
        if selectedIndex < 0 { selectedIndex = displayRows.count - 1 }
        else if selectedIndex > 0 { selectedIndex -= 1 }
        // Skip non-selectable rows
        while selectedIndex > 0 && !isSelectable(selectedIndex) { selectedIndex -= 1 }
        selectedIndices.removeAll()
        forceRender()
    }

    func moveDown() {
        if selectedIndex < 0 { selectedIndex = 0 }
        else if selectedIndex < displayRows.count - 1 { selectedIndex += 1 }
        // Skip non-selectable rows
        while selectedIndex < displayRows.count - 1 && !isSelectable(selectedIndex) { selectedIndex += 1 }
        selectedIndices.removeAll()
        forceRender()
    }

    func shiftMoveUp() {
        if selectedIndex < 0 { selectedIndex = displayRows.count - 1 }
        selectedIndices.insert(selectedIndex)
        if selectedIndex > 0 {
            selectedIndex -= 1
            selectedIndices.insert(selectedIndex)
        }
        forceRender()
    }

    func shiftMoveDown() {
        if selectedIndex < 0 { selectedIndex = 0 }
        selectedIndices.insert(selectedIndex)
        if selectedIndex < displayRows.count - 1 {
            selectedIndex += 1
            selectedIndices.insert(selectedIndex)
        }
        forceRender()
    }

    func toggleViewMode() {
        viewMode = viewMode == .flat ? .tree : .flat
        // In tree mode, default all processes to disclosed (expanded)
        if viewMode == .tree {
            lock.lock()
            for row in rows.values { row.disclosed = true }
            lock.unlock()
        }
        selectedIndex = -1
        selectedIndices.removeAll()
        scrollOffset = 0
        forceRender()
    }

    func toggleHints() {
        showHints = !showHints
        forceRender()
    }

    // MARK: - Menu system

    var isMenuOpen: Bool { activeMenu != nil }

    private func processMenuItems() -> [MenuItem] {
        let hasPid = pidForRow(selectedIndex) != nil
        lock.lock()
        let pid = pidForRow(selectedIndex)
        let row = pid != nil ? rows[pid!] : nil
        let isRunning = row?.isRunning ?? false
        let isStopped = row?.isStopped ?? false
        let infoVis = row?.infoVisible ?? false
        let filesVis = row?.filesVisible ?? false
        let netVis = row?.netVisible ?? false
        lock.unlock()
        return [
            MenuItem(label: "Show Info", shortcut: "i", key: 105, checked: infoVis, enabled: hasPid),
            MenuItem(label: "Show Files", shortcut: "d", key: 100, checked: filesVis, enabled: hasPid),
            MenuItem(label: "Show Network", shortcut: "n", key: 110, checked: netVis, enabled: hasPid),
            .sep(),
            MenuItem(label: "Sample", shortcut: "s", key: 115, enabled: hasPid && isRunning),
            MenuItem(label: "Wait", shortcut: "w", key: 119, enabled: hasPid && isRunning),
            .sep(),
            MenuItem(label: "Kill", shortcut: "k", key: 107, enabled: hasPid && isRunning),
            MenuItem(label: isStopped ? "Resume" : "Pause", shortcut: "z", key: 122, enabled: hasPid && isRunning),
        ]
    }

    private func sampleMenuItems() -> [MenuItem] {
        let hasPid = pidForRow(selectedIndex) != nil
        return [
            MenuItem(label: "Resample...", shortcut: "", key: nil, enabled: hasPid),
            MenuItem(label: "Delete...", shortcut: "", key: nil, enabled: hasPid),
            MenuItem(label: "Export...", shortcut: "", key: nil, enabled: false),
        ]
    }

    private func networkMenuItems() -> [MenuItem] {
        return [
            MenuItem(label: "Reverse DNS Lookup", shortcut: "", key: nil, checked: true),
            MenuItem(label: "SNI Inspection", shortcut: "", key: nil, checked: true),
        ]
    }

    private func filesMenuItems() -> [MenuItem] {
        return [
            MenuItem(label: "Show Reads", shortcut: "", key: nil, checked: false),
            MenuItem(label: "Show Writes", shortcut: "", key: nil, checked: true),
        ]
    }

    private func fileMenuItems() -> [MenuItem] {
        return [
            MenuItem(label: "Export...", shortcut: "", key: nil, enabled: false),
        ]
    }

    private func editMenuItems() -> [MenuItem] {
        return [
            MenuItem(label: "Filter", shortcut: "/", key: nil, enabled: false),
            MenuItem(label: "Find", shortcut: "f", key: nil, enabled: false),
            MenuItem(label: "Clear", shortcut: "l", key: 108),
            MenuItem(label: "Copy", shortcut: "c", key: nil, enabled: false),
        ]
    }

    private func viewMenuItems() -> [MenuItem] {
        return [
            MenuItem(label: "Show Exited", shortcut: "", key: nil, checked: showExited),
            .sep(),
            MenuItem(label: "Expand All", shortcut: "", key: nil),
            MenuItem(label: "Collapse All", shortcut: "", key: nil),
            .sep(),
            MenuItem(label: "Columns", shortcut: "▸", key: nil, enabled: false),
        ]
    }

    func toggleContextMenu() {
        toggleMenu(contextMenuID())
    }

    func toggleMenu(_ menu: MenuID) {
        if activeMenu == menu {
            activeMenu = nil
        } else {
            activeMenu = menu
            menuItemIndex = 0
        }
        forceRender()
    }

    func closeMenu() {
        activeMenu = nil
        forceRender()
    }

    func menuUp() {
        guard activeMenu != nil else { return }
        let items = currentMenuItems()
        if menuItemIndex > 0 {
            menuItemIndex -= 1
            if items[safe: menuItemIndex]?.isSeparator == true && menuItemIndex > 0 {
                menuItemIndex -= 1
            }
        }
        forceRender()
    }

    func menuDown() {
        guard activeMenu != nil else { return }
        let items = currentMenuItems()
        if menuItemIndex < items.count - 1 {
            menuItemIndex += 1
            if items[safe: menuItemIndex]?.isSeparator == true && menuItemIndex < items.count - 1 {
                menuItemIndex += 1
            }
        }
        forceRender()
    }

    func menuSelect() {
        guard let menu = activeMenu else { return }
        let items = currentMenuItems()
        guard let item = items[safe: menuItemIndex], item.enabled, !item.isSeparator else { return }

        // Flash the selected item first
        flashMenuItem()

        activeMenu = nil

        if menu == .view {
            if item.label == "Show Exited" {
                showExited = !showExited
            } else if item.label == "Expand All" {
                expandCollapseAll(open: true)
            } else if item.label == "Collapse All" {
                expandCollapseAll(open: false)
            }
            forceRender()
            return
        }

        // Process menu — execute action
        if let key = item.key, let action = shortcutAction(key) {
            action()
        }
        forceRender()
    }

    func toggleFiles() {
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        guard let row = rows[pid] else { lock.unlock(); return }
        row.filesVisible = !row.filesVisible
        row.disclosed = true
        lock.unlock()
        ensureDisclosedAndJump(pid, to: row.filesVisible ? .filesHeader(pid) : nil)
    }

    func toggleNetwork() {
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        guard let row = rows[pid] else { lock.unlock(); return }
        row.netVisible = !row.netVisible
        row.disclosed = true
        lock.unlock()
        ensureDisclosedAndJump(pid, to: row.netVisible ? .netHeader(pid) : nil)
    }

    func expandCollapseAll(open: Bool) {
        lock.lock()
        if selectedIndex >= 0, let pid = pidForRow(selectedIndex) {
            // Scoped to the highlighted process and its descendants
            func setAll(_ pid: pid_t) {
                guard let row = rows[pid] else { return }
                row.disclosed = open
                row.infoDisclosed = open
                row.filesDisclosed = open
                row.netDisclosed = open
                row.sampleDisclosed = open
                row.waitDisclosed = open
                row.processDisclosed = open
                row.argsDisclosed = open
                row.envDisclosed = open
                row.resourcesDisclosed = open
                // Find children
                for (childPid, childRow) in rows where childRow.ppid == pid {
                    setAll(childPid)
                }
            }
            setAll(pid)
        } else {
            // Nothing highlighted — expand/collapse everything
            for row in rows.values {
                row.disclosed = open
                row.infoDisclosed = open
                row.filesDisclosed = open
                row.netDisclosed = open
                row.sampleDisclosed = open
                row.waitDisclosed = open
                row.processDisclosed = open
                row.argsDisclosed = open
                row.envDisclosed = open
                row.resourcesDisclosed = open
            }
        }
        lock.unlock()
    }

    func clearExited() {
        lock.lock()
        let exited = rows.filter { !$0.value.isRunning }
        for (pid, _) in exited { rows.removeValue(forKey: pid) }
        lock.unlock()
        forceRender()
    }

    /// Map of shortcut key → (menu, action)
    private func shortcutAction(_ key: Int32) -> (() -> Void)? {
        switch key {
        case 105: return toggleInfo          // i
        case 100: return toggleFiles         // d
        case 110: return toggleNetwork       // n
        case 115: return sampleProcess       // s
        case 119: return diagnoseWait        // w
        case 107: return enterKillMode       // k
        case 122: return togglePauseProcess  // z
        case 108: return clearExited         // l
        default: return nil
        }
    }

    /// Find which menu owns a shortcut key
    private func menuForShortcut(_ key: Int32) -> MenuID? {
        for menuId in menuOrder {
            let items: [MenuItem]
            switch menuId {
            case .file: items = fileMenuItems()
            case .edit: items = editMenuItems()
            case .process: items = processMenuItems()
            case .sample: items = sampleMenuItems()
            case .network: items = networkMenuItems()
            case .files: items = filesMenuItems()
            case .view: items = viewMenuItems()
            }
            if items.contains(where: { $0.key == key }) { return menuId }
        }
        return nil
    }

    func executeShortcut(_ key: Int32) {
        guard let action = shortcutAction(key) else { return }

        if activeMenu != nil {
            // Menu is open — find the item, jump to it, flash, close, execute
            let items = currentMenuItems()
            if let idx = items.firstIndex(where: { $0.key == key }) {
                menuItemIndex = idx
                flashMenuItem()
            } else {
                // Item not in current menu — find the right menu, open it, flash
                if let menu = menuForShortcut(key) {
                    activeMenu = menu
                    let newItems = currentMenuItems()
                    if let idx = newItems.firstIndex(where: { $0.key == key }) {
                        menuItemIndex = idx
                        flashMenuItem()
                    }
                }
            }
            activeMenu = nil
            action()
        } else {
            // Menu closed — flash the parent menu header, then execute
            if let menu = menuForShortcut(key) {
                flashMenu(menu)
            }
            action()
        }
    }

    /// Flash the currently highlighted menu item (macOS style blink)
    private func flashMenuItem() {
        let savedIndex = menuItemIndex
        for _ in 0..<2 {
            menuItemIndex = savedIndex
            doRender()
            refresh()
            usleep(60_000)
            menuItemIndex = -1  // unhighlight
            doRender()
            refresh()
            usleep(60_000)
        }
        menuItemIndex = savedIndex
    }

    /// Menu order — Process always present, contextual menu added when relevant
    private var menuOrder: [MenuID] {
        let ctx = contextMenuID()
        if ctx == .process {
            return [.file, .edit, .process, .view]
        }
        return [.file, .edit, .process, ctx, .view]
    }

    /// Which context menu to show based on current selection
    private func contextMenuID() -> MenuID {
        guard let dr = displayRows[safe: selectedIndex] else { return .process }
        switch dr {
        case .sampleHeader, .sampleNode: return .sample
        case .netHeader, .netDetail: return .network
        case .filesHeader, .fileDetail: return .files
        default: return .process
        }
    }

    private func currentMenuItems() -> [MenuItem] {
        switch activeMenu {
        case .file: return fileMenuItems()
        case .edit: return editMenuItems()
        case .process: return processMenuItems()
        case .sample: return sampleMenuItems()
        case .network: return networkMenuItems()
        case .files: return filesMenuItems()
        case .view: return viewMenuItems()
        case nil: return []
        }
    }

    func menuLeft() {
        guard let current = activeMenu, let idx = menuOrder.firstIndex(of: current) else { return }
        activeMenu = menuOrder[(idx - 1 + menuOrder.count) % menuOrder.count]
        menuItemIndex = 0
        forceRender()
    }

    func menuRight() {
        guard let current = activeMenu, let idx = menuOrder.firstIndex(of: current) else { return }
        activeMenu = menuOrder[(idx + 1) % menuOrder.count]
        menuItemIndex = 0
        forceRender()
    }

    /// Flash a menu header — non-blocking, shows simultaneously with action
    private func flashMenu(_ menu: MenuID) {
        menuFlash = menu
        let width = Int(getmaxx(stdscr))
        renderMenuBar(y: 1, width: width)
        refresh()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
            self?.menuFlash = nil
            let w = Int(getmaxx(stdscr))
            self?.renderMenuBar(y: 1, width: w)
            refresh()
        }
    }

    /// Ensure process is disclosed, jump cursor to target, and render
    private func ensureDisclosedAndJump(_ pid: pid_t, to target: DisplayRow? = nil) {
        lock.lock()
        rows[pid]?.disclosed = true
        lock.unlock()
        // Build displayRows first (render updates them)
        doRender()
        // Jump to specific target, or fall back to process row
        for (i, r) in displayRows.enumerated() {
            if let t = target, r == t {
                selectedIndex = i
                selectedIndices.removeAll()
                break
            }
            if target == nil, case .process(let p, _) = r, p == pid {
                selectedIndex = i
                selectedIndices.removeAll()
                break
            }
        }
        // Render again with updated cursor position
        forceRender()
    }

    func toggleInfo() {
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        guard let row = rows[pid] else { lock.unlock(); return }
        row.infoVisible = !row.infoVisible
        row.infoDisclosed = row.infoVisible
        row.disclosed = true
        let visible = row.infoVisible
        if row.infoDisclosed && !row.infoLoaded {
            lock.unlock()
            let (path, _, _) = getProcessInfo(pid)
            let args = getProcessArgs(pid)
            let envVars = getProcessEnv(pid)
            lock.lock()
            row.fullPath = path
            row.argvArray = args
            row.envVars = envVars
            row.infoLoaded = true
        }
        lock.unlock()
        ensureDisclosedAndJump(pid, to: visible ? .processHeader(pid) : nil)
    }

    private func runSampleAsync(_ pid: pid_t) {
        lock.lock()
        rows[pid]?.isSampling = true
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let tree = self?.runSample(pid) ?? []
            DispatchQueue.main.async {
                self?.lock.lock()
                self?.rows[pid]?.sampleTree = tree
                self?.rows[pid]?.isSampling = false
                self?.lock.unlock()
                self?.forceRender()
            }
        }
    }

    private func runWaitAsync(_ pid: pid_t) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let results = self?.runWaitDiagnosis(pid) ?? []
            DispatchQueue.main.async {
                self?.lock.lock()
                self?.rows[pid]?.waitResults = results
                self?.lock.unlock()
                self?.forceRender()
            }
        }
    }

    // MARK: - Process actions

    func togglePauseProcess() {
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        guard let row = rows[pid], row.isRunning else { lock.unlock(); return }
        if row.isStopped {
            kill(pid, SIGCONT)
            row.isStopped = false
        } else {
            kill(pid, SIGSTOP)
            row.isStopped = true
        }
        lock.unlock()
        forceRender()
    }

    var isKillMode: Bool { killMode }

    func enterKillMode() {
        killMode = !killMode
        forceRender()
    }

    func sendSignal(_ signal: Int32) {
        guard killMode else { return }
        guard let pid = pidForRow(selectedIndex) else { return }
        kill(pid, signal)
        killMode = false
        forceRender()
    }

    func sampleProcess() {
        guard pidForRow(selectedIndex) != nil else { return }
        // Show config modal
        isSampleConfigOpen = true
        sampleConfigField = 0
        forceRender()
    }

    func sampleConfigUp() {
        if sampleConfigField > 0 { sampleConfigField -= 1 }
        forceRender()
    }

    func sampleConfigDown() {
        if sampleConfigField < 2 { sampleConfigField += 1 }
        forceRender()
    }

    func sampleConfigLeft() {
        switch sampleConfigField {
        case 0: sampleDuration = max(1, sampleDuration - 1)
        case 1: sampleThreshold = max(1, sampleThreshold - 1)
        case 2: sampleMaxDepth = max(1, sampleMaxDepth - 1)
        default: break
        }
        forceRender()
    }

    func sampleConfigRight() {
        switch sampleConfigField {
        case 0: sampleDuration = min(30, sampleDuration + 1)
        case 1: sampleThreshold = min(50, sampleThreshold + 1)
        case 2: sampleMaxDepth = min(20, sampleMaxDepth + 1)
        default: break
        }
        forceRender()
    }

    func sampleConfigCancel() {
        isSampleConfigOpen = false
        forceRender()
    }

    func sampleConfigStart() {
        isSampleConfigOpen = false
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        guard let row = rows[pid] else { lock.unlock(); return }
        row.sampleVisible = true
        row.sampleDisclosed = true
        row.disclosed = true
        lock.unlock()
        runSampleAsync(pid)
        ensureDisclosedAndJump(pid, to: .sampleHeader(pid))
    }

    private func runSample(_ pid: pid_t) -> [SampleNode] {
        let pipe = Pipe()
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sample")
        proc.arguments = ["\(pid)", "\(sampleDuration)"]
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do { try proc.run() } catch { return [SampleNode(name: "sample failed", count: 0, pct: 0)] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        guard let output = String(data: data, encoding: .utf8) else { return [] }
        return parseSampleTree(output)
    }

    private func parseSampleTree(_ output: String) -> [SampleNode] {
        // Parse the call graph, then invert it to show bottom-up
        // (leaf functions at top, callers as children)

        struct RawEntry {
            let depth: Int
            let count: Int
            let name: String  // empty for ??? frames
            let isNamed: Bool
        }

        var entries: [RawEntry] = []
        var inCallGraph = false
        var totalSamples = 0
        var minDepth = Int.max

        for line in output.split(separator: "\n", omittingEmptySubsequences: false) {
            let raw = String(line)
            if raw.contains("Call graph:") { inCallGraph = true; continue }
            if raw.contains("Total number") { inCallGraph = false; continue }
            guard inCallGraph else { continue }

            let chars = Array(raw)
            var numStart = -1
            var numEnd = -1
            for (i, c) in chars.enumerated() {
                if c.isNumber {
                    if numStart == -1 { numStart = i }
                    numEnd = i
                } else if numStart != -1 { break }
            }
            guard numStart >= 0, numEnd >= numStart else { continue }
            let countStr = String(chars[numStart...numEnd])
            guard let count = Int(countStr), count > 0 else { continue }

            let restStart = numEnd + 1
            guard restStart < chars.count else { continue }
            let rest = String(chars[restStart...]).trimmingCharacters(in: .whitespaces)

            let depth = numStart / 2
            let isUnknown = rest.hasPrefix("???")

            if depth < minDepth { minDepth = depth }

            if isUnknown {
                entries.append(RawEntry(depth: depth, count: count, name: "", isNamed: false))
                continue
            }

            let funcName: String
            if let inIdx = rest.range(of: "  (in ") {
                funcName = String(rest[..<inIdx.lowerBound])
            } else if rest.hasPrefix("Thread_") {
                funcName = String(rest.prefix(while: { !$0.isWhitespace }))
            } else {
                funcName = rest
            }

            guard !funcName.isEmpty else { continue }
            entries.append(RawEntry(depth: depth, count: count, name: funcName, isNamed: true))
        }

        // totalSamples = sum of all thread root counts
        for entry in entries where entry.depth == minDepth {
            totalSamples += entry.count
        }
        guard totalSamples > 0 else { return [] }

        // Walk the entries top-down, tracking the stack of named frames.
        // At each leaf (deepest point before depth decreases), record the
        // inverted stack: leaf first, then callers going up.
        // A "leaf" in the sample tree is the last entry before depth decreases.

        // Build bottom-up tree from entries.
        // Walk top-down, maintaining a named stack. At each named leaf,
        // record the inverted stack (leaf → callers).
        // Use max(count) per unique leaf name to avoid double-counting.

        struct LeafInfo {
            var count: Int
            var callerChains: [[String]]
        }
        var leafMap: [String: LeafInfo] = [:]
        var namedStack: [(name: String, depth: Int)] = []

        let boringNames: Set<String> = ["start", "thread_start", "_pthread_start", "_pthread_wqthread", "start_wqthread"]

        for i in 0..<entries.count {
            let entry = entries[i]

            // Pop stack to current depth
            while !namedStack.isEmpty && namedStack.last!.depth >= entry.depth {
                namedStack.removeLast()
            }

            guard entry.isNamed else { continue }
            guard !boringNames.contains(entry.name) else {
                namedStack.append((entry.name, entry.depth))
                continue
            }

            namedStack.append((entry.name, entry.depth))

            // Is this a leaf? (next entry has <= depth or doesn't exist)
            let nextDepth = (i + 1 < entries.count) ? entries[i + 1].depth : 0
            guard nextDepth <= entry.depth else { continue }

            // Record leaf with max count and caller chain
            let callers = Array(namedStack.dropLast().reversed().map { $0.name })
            var info = leafMap[entry.name, default: LeafInfo(count: 0, callerChains: [])]
            info.count += entry.count
            info.callerChains.append(callers)
            leafMap[entry.name] = info
        }

        // Build tree: leaf functions as roots, callers as children
        var roots: [SampleNode] = []
        let sorted = leafMap.sorted { $0.value.count > $1.value.count }

        for (name, info) in sorted {
            let pct = info.count * 100 / totalSamples
            guard pct >= sampleThreshold else { continue }

            let node = SampleNode(name: name, count: info.count, pct: pct)

            // Merge caller chains into a tree (callers shown as children)
            func mergeCallers(_ chains: [[String]], depth: Int) -> [SampleNode] {
                guard depth < sampleMaxDepth else { return [] }
                var groups: [String: [[String]]] = [:]
                for chain in chains where !chain.isEmpty {
                    groups[chain[0], default: []].append(Array(chain.dropFirst()))
                }
                return groups.map { callerName, subChains in
                    let n = SampleNode(name: callerName, count: info.count, pct: pct)
                    n.children = mergeCallers(subChains, depth: depth + 1)
                    return n
                }.sorted { $0.name < $1.name }
            }
            node.children = mergeCallers(info.callerChains, depth: 0)

            roots.append(node)
        }

        // Auto-disclose hot items
        for node in roots where node.pct >= 20 {
            node.disclosed = true
        }

        return roots
    }

    func diagnoseWait() {
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        guard let row = rows[pid] else { lock.unlock(); return }
        row.waitVisible = !row.waitVisible
        row.waitDisclosed = row.waitVisible
        row.disclosed = true
        lock.unlock()
        if row.waitVisible && row.waitResults.isEmpty {
            runWaitAsync(pid)
        }
        ensureDisclosedAndJump(pid, to: row.waitVisible ? .waitHeader(pid) : nil)
    }

    private func runWaitDiagnosis(_ pid: pid_t) -> [String] {
        let pipe = Pipe()
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/sample")
        proc.arguments = ["\(pid)", "1"]
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice

        do { try proc.run() } catch { return ["sample failed: \(error)"] }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        guard let output = String(data: data, encoding: .utf8) else { return [] }

        // Parse: find the deepest named (non-???) frame per thread
        var threadLeafs: [String: Int] = [:]
        var currentLeaf: String? = nil
        var inCallGraph = false

        for line in output.split(separator: "\n") {
            let raw = String(line)
            if raw.contains("Call graph:") { inCallGraph = true; continue }
            guard inCallGraph else { continue }

            // Thread header resets leaf tracking
            if raw.trimmingCharacters(in: .whitespaces).hasPrefix("Thread_") {
                if let leaf = currentLeaf { threadLeafs[leaf, default: 0] += 1 }
                currentLeaf = nil
                continue
            }

            let trimmed = raw.trimmingCharacters(in: CharacterSet(charactersIn: "+!|: \t"))
            guard !trimmed.isEmpty else {
                if let leaf = currentLeaf { threadLeafs[leaf, default: 0] += 1 }
                currentLeaf = nil
                continue
            }

            if let spaceIdx = trimmed.firstIndex(of: " ") {
                let numStr = String(trimmed[..<spaceIdx])
                if let _ = Int(numStr) {
                    let rest = String(trimmed[trimmed.index(after: spaceIdx)...]).trimmingCharacters(in: .whitespaces)
                    if rest.hasPrefix("???") { continue }
                    let funcName: String
                    if let inIdx = rest.range(of: "  (in ") {
                        funcName = String(rest[..<inIdx.lowerBound])
                    } else {
                        funcName = rest
                    }
                    if !funcName.isEmpty && funcName != "start" && funcName != "thread_start" && funcName != "_pthread_start" {
                        currentLeaf = funcName
                    }
                }
            }
        }
        if let leaf = currentLeaf { threadLeafs[leaf, default: 0] += 1 }

        guard !threadLeafs.isEmpty else { return ["No thread info available"] }

        let sorted = threadLeafs.sorted { $0.value > $1.value }
        return sorted.prefix(8).map { name, count in
            let category = categorizeWait(name)
            return "\(count)x \(name) (\(category))"
        }
    }

    private func categorizeWait(_ funcName: String) -> String {
        let lower = funcName.lowercased()
        if lower.contains("kevent") || lower.contains("select") || lower.contains("poll") { return "I/O wait" }
        if lower.contains("ssl_read") || lower.contains("ssl_write") { return "TLS I/O" }
        if lower.contains("recv") || lower.contains("send") { return "network" }
        if lower.contains("read") || lower.contains("write") || lower.contains("pwrite") || lower.contains("pread") { return "disk I/O" }
        if lower.contains("mach_msg") { return "IPC/XPC" }
        if lower.contains("psynch_mutex") || lower.contains("mutex") { return "lock" }
        if lower.contains("semaphore") || lower.contains("dispatch_semaphore") { return "semaphore" }
        if lower.contains("semwait") || lower.contains("sleep") || lower.contains("nanosleep") { return "sleep" }
        if lower.contains("wait4") || lower.contains("waitpid") { return "child wait" }
        if lower.contains("workq") || lower.contains("wqthread") { return "thread pool" }
        return "other"
    }

    func clearSelection() {
        selectedIndices.removeAll()
        selectedIndex = -1
        forceRender()
    }

    func disclose() {
        lock.lock()
        for dr in effectiveDisplayRows() {
            setDisclosure(dr, open: true)
        }
        lock.unlock()
        forceRender()
    }

    func collapse() {
        // For collapse with multi-select, collapse all. For single, use Finder behavior.
        if !selectedIndices.isEmpty {
            lock.lock()
            for dr in effectiveDisplayRows() {
                setDisclosure(dr, open: false)
            }
            lock.unlock()
            forceRender()
            return
        }
        guard let row = displayRows[safe: selectedIndex] else { return }
        lock.lock()
        if isDisclosed(row) {
            setDisclosure(row, open: false)
            lock.unlock()
            forceRender()
        } else if let parent = parentRow(row) {
            lock.unlock()
            jumpToParent(parent)
        } else {
            lock.unlock()
            forceRender()
        }
    }

    private func jumpToParent(_ target: DisplayRow) {
        // For process rows, match by PID regardless of depth
        if case .process(let pid, _) = target {
            for (i, dr) in displayRows.enumerated() {
                if case .process(let p, _) = dr, p == pid {
                    selectedIndex = i
                    selectedIndices.removeAll()
                    break
                }
            }
        } else if let idx = displayRows.firstIndex(of: target) {
            selectedIndex = idx
            selectedIndices.removeAll()
        }
        forceRender()
    }

    func discloseAll() {
        guard let row = displayRows[safe: selectedIndex] else { return }
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        switch row {
        case .process:
            openAllDisclosures(pid)
        case .processHeader:
            rows[pid]?.processDisclosed = true
            rows[pid]?.argsDisclosed = true
            rows[pid]?.envDisclosed = true
            rows[pid]?.resourcesDisclosed = true
        default:
            setDisclosure(row, open: true)
        }
        lock.unlock()
        forceRender()
    }

    func collapseAll() {
        guard let row = displayRows[safe: selectedIndex] else { return }
        guard let pid = pidForRow(selectedIndex) else { return }
        lock.lock()
        if isDisclosed(row) {
            // Close self and all descendants
            switch row {
            case .process:
                closeAllDisclosures(pid)
            case .processHeader:
                rows[pid]?.processDisclosed = false
                rows[pid]?.argsDisclosed = false
                rows[pid]?.envDisclosed = false
                rows[pid]?.resourcesDisclosed = false
            default:
                setDisclosure(row, open: false)
            }
            lock.unlock()
            forceRender()
        } else if let parent = parentRow(row) {
            setDisclosure(parent, open: false)
            lock.unlock()
            jumpToParent(parent)
        } else {
            lock.unlock()
            forceRender()
        }
    }

    func toggleDisclose() {
        lock.lock()
        for dr in effectiveDisplayRows() {
            let open = !isDisclosed(dr)
            setDisclosure(dr, open: open)
        }
        lock.unlock()
        forceRender()
    }

    /// Returns display rows for all highlighted items, or just the cursor if no multi-selection
    private func effectiveDisplayRows() -> [DisplayRow] {
        if selectedIndices.isEmpty {
            if let dr = displayRows[safe: selectedIndex] { return [dr] }
            return []
        }
        return selectedIndices.sorted().compactMap { displayRows[safe: $0] }
    }

    /// Navigate sample tree by path
    private func sampleNodeAt(_ pid: pid_t, path: [Int]) -> SampleNode? {
        guard let row = rows[pid] else { return nil }
        var nodes = row.sampleTree
        var node: SampleNode? = nil
        for idx in path {
            guard idx < nodes.count else { return nil }
            node = nodes[idx]
            nodes = node!.children
        }
        return node
    }

    /// Set a single disclosure flag for a row
    private func setDisclosure(_ row: DisplayRow, open: Bool) {
        switch row {
        case .process(let pid, _):       rows[pid]?.disclosed = open
        case .processHeader(let pid): rows[pid]?.infoDisclosed = open
        case .argsHeader(let pid):    rows[pid]?.argsDisclosed = open
        case .envHeader(let pid):     rows[pid]?.envDisclosed = open
        case .resourcesHeader(let pid): rows[pid]?.resourcesDisclosed = open
        case .filesHeader(let pid):   rows[pid]?.filesDisclosed = open
        case .netHeader(let pid):     rows[pid]?.netDisclosed = open
        case .sampleHeader(let pid): rows[pid]?.sampleDisclosed = open
        case .sampleNode(let pid, let path):
            sampleNodeAt(pid, path: path)?.disclosed = open
        case .waitHeader(let pid): rows[pid]?.waitDisclosed = open
        default: break
        }
    }

    /// Is this row currently disclosed?
    private func isDisclosed(_ row: DisplayRow) -> Bool {
        switch row {
        case .process(let pid, _):       return rows[pid]?.disclosed ?? false
        case .processHeader(let pid): return rows[pid]?.infoDisclosed ?? false
        case .argsHeader(let pid):    return rows[pid]?.argsDisclosed ?? false
        case .envHeader(let pid):     return rows[pid]?.envDisclosed ?? false
        case .resourcesHeader(let pid): return rows[pid]?.resourcesDisclosed ?? false
        case .filesHeader(let pid):   return rows[pid]?.filesDisclosed ?? false
        case .netHeader(let pid):     return rows[pid]?.netDisclosed ?? false
        case .sampleHeader(let pid): return rows[pid]?.sampleDisclosed ?? false
        case .sampleNode(let pid, let path):
            return sampleNodeAt(pid, path: path)?.disclosed ?? false
        case .waitHeader(let pid): return rows[pid]?.waitDisclosed ?? false
        default: return false
        }
    }

    /// Close all disclosure flags for a process
    private func closeAllDisclosures(_ pid: pid_t) {
        guard let r = rows[pid] else { return }
        r.disclosed = false
        r.processDisclosed = false
        r.argsDisclosed = false
        r.envDisclosed = false
        r.resourcesDisclosed = false
        r.filesDisclosed = false
        r.netDisclosed = false
    }

    /// Open all disclosure flags for a process
    private func openAllDisclosures(_ pid: pid_t) {
        guard let r = rows[pid] else { return }
        r.disclosed = true
        r.processDisclosed = true
        r.argsDisclosed = true
        r.envDisclosed = true
        r.resourcesDisclosed = true
        r.filesDisclosed = true
        r.netDisclosed = true
    }

    /// Get parent display row for navigation
    private func parentRow(_ row: DisplayRow) -> DisplayRow? {
        switch row {
        case .process(let pid, let depth):
            // In tree mode, find the parent process by ppid
            if depth > 0 {
                lock.lock()
                let ppid = rows[pid]?.ppid ?? 0
                lock.unlock()
                // Find the parent process row in displayRows
                for dr in displayRows {
                    if case .process(let p, _) = dr, p == ppid { return dr }
                }
            }
            return nil
        case .processHeader(let pid), .filesHeader(let pid), .netHeader(let pid):
            return .process(pid, 0)
        case .argsHeader(let pid), .envHeader(let pid), .resourcesHeader(let pid):
            return .processHeader(pid)
        case .processDetail(let pid, _):
            return .processHeader(pid)
        case .argDetail(let pid, _):
            return .argsHeader(pid)
        case .envDetail(let pid, _):
            return .envHeader(pid)
        case .resourceDetail(let pid, _):
            return .resourcesHeader(pid)
        case .fileDetail(let pid, _):
            return .filesHeader(pid)
        case .netDetail(let pid, _):
            return .netHeader(pid)
        case .separator(let pid):
            return .process(pid, 0)
        case .infoBorderTop(let pid, _), .infoBorderBottom(let pid, _):
            return .process(pid, 0)
        case .sampleHeader(let pid):
            return .process(pid, 0)
        case .sampleNode(let pid, let path):
            if path.count <= 1 { return .sampleHeader(pid) }
            return .sampleNode(pid, Array(path.dropLast()))
        case .waitHeader(let pid):
            return .process(pid, 0)
        case .waitLine(let pid, _):
            return .waitHeader(pid)
        }
    }

    private func pidForRow(_ index: Int) -> pid_t? {
        guard let row = displayRows[safe: index] else { return nil }
        switch row {
        case .process(let pid, _), .processHeader(let pid), .processDetail(let pid, _),
             .argsHeader(let pid), .argDetail(let pid, _),
             .envHeader(let pid), .envDetail(let pid, _),
             .resourcesHeader(let pid), .resourceDetail(let pid, _),
             .filesHeader(let pid), .fileDetail(let pid, _),
             .netHeader(let pid), .netDetail(let pid, _),
             .separator(let pid),
             .infoBorderTop(let pid, _), .infoBorderBottom(let pid, _),
             .sampleHeader(let pid), .sampleNode(let pid, _),
             .waitHeader(let pid), .waitLine(let pid, _):
            return pid
        }
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
        let row = ProcessRow(pid: pid, ppid: ppid, name: name, argv: argv)
        if viewMode == .tree { row.disclosed = true }
        rows[pid] = row
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

        // Load process info lazily when Process section is disclosed
        lock.lock()
        let needsInfo = rows.values.filter { $0.processDisclosed && !$0.infoLoaded }
        lock.unlock()
        for row in needsInfo {
            let (path, _, _) = getProcessInfo(row.pid)
            let args = getProcessArgs(row.pid)
            let envVars = getProcessEnv(row.pid)
            lock.lock()
            row.fullPath = path
            row.argvArray = args
            row.envVars = envVars
            row.infoLoaded = true
            lock.unlock()
        }

        // Poll resources only for processes with Resources disclosed
        lock.lock()
        let needsResources = rows.values.filter { $0.resourcesDisclosed && $0.isRunning }
        lock.unlock()
        for row in needsResources {
            var taskInfo = proc_taskinfo()
            let size = proc_pidinfo(row.pid, PROC_PIDTASKINFO, 0, &taskInfo, Int32(MemoryLayout<proc_taskinfo>.size))
            if size > 0 {
                lock.lock()
                row.cpuUser = TimeInterval(taskInfo.pti_total_user) / 1_000_000_000
                row.cpuSys = TimeInterval(taskInfo.pti_total_system) / 1_000_000_000
                row.rss = UInt64(taskInfo.pti_resident_size)
                lock.unlock()
            }
            let fdSize = proc_pidinfo(row.pid, PROC_PIDLISTFDS, 0, nil, 0)
            if fdSize > 0 {
                lock.lock()
                row.fdCount = Int(fdSize) / MemoryLayout<proc_fdinfo>.size
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
        doRender()
    }

    /// Force render regardless of pause state — for user-initiated actions
    private func forceRender() {
        doRender()
    }

    private func doRender() {
        pollRunningProcesses()

        lock.lock()
        let allRows = Array(rows.values)
        lock.unlock()

        // Filter out GhostBuster's own processes and its children
        let visible = allRows.filter { !isExcluded($0) && (showExited || $0.isRunning) }

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

        // Menu bar on line 1
        renderMenuBar(y: 1, width: Int(maxX))

        let availableLines = Int(maxY) - 5
        let width = Int(maxX)

        // Save current selection identities before rebuilding
        let savedRow = displayRows[safe: selectedIndex]
        let savedSelected = selectedIndices.compactMap { displayRows[safe: $0] }

        // Build display row list based on view mode
        let allVisible = running + exited
        displayRows = []

        switch viewMode {
        case .flat:
            for row in allVisible {
                displayRows.append(.process(row.pid, 0))
                if row.disclosed {
                    appendPanelRows(row, depth: 0)
                }
            }
        case .tree:
            // Build parent->children map
            let pidSet = Set(allVisible.map { $0.pid })
            var childrenOf: [pid_t: [ProcessRow]] = [:]
            var roots: [ProcessRow] = []
            for row in allVisible {
                if pidSet.contains(row.ppid) && row.ppid != row.pid {
                    childrenOf[row.ppid, default: []].append(row)
                } else {
                    roots.append(row)
                }
            }
            func appendTree(_ row: ProcessRow, depth: Int) {
                displayRows.append(.process(row.pid, depth))
                if row.disclosed {
                    // Inline panels
                    appendPanelRows(row, depth: depth)
                    // Child processes
                    let children = childrenOf[row.pid] ?? []
                    for child in children {
                        appendTree(child, depth: depth + 1)
                    }
                }
            }
            for root in roots {
                appendTree(root, depth: 0)
            }
        }

        // Restore selection by identity
        if let saved = savedRow, let idx = displayRows.firstIndex(of: saved) {
            selectedIndex = idx
        }
        // Restore multi-selection by identity
        selectedIndices = Set(savedSelected.compactMap { displayRows.firstIndex(of: $0) })
        // Clamp
        if selectedIndex >= displayRows.count { selectedIndex = max(-1, displayRows.count - 1) }

        let columnLayout = columnLayout(for: displayRows)
        renderColumnHeader(y: 3, width: width, layout: columnLayout)

        // Adjust scroll offset to keep selectedIndex visible
        if selectedIndex >= 0 {
            if selectedIndex < scrollOffset { scrollOffset = selectedIndex }
            if selectedIndex >= scrollOffset + availableLines { scrollOffset = selectedIndex - availableLines + 1 }
        }
        scrollOffset = max(0, min(scrollOffset, max(0, displayRows.count - 1)))

        // Render rows
        var y: Int32 = 4
        let lastRow = maxY - 2


        var currentBoxIndent = -1  // -1 = not in a box, >= 0 = left edge column

        for i in scrollOffset..<displayRows.count {
            guard y <= lastRow else { break }
            let isHighlighted = i == selectedIndex || selectedIndices.contains(i)
            let dr = displayRows[i]
            // Base indent for sub-rows: process depth * 2 chars
            let rowDepth = depthForDisplayRow(at: i)
            let depthIndent = rowDepth * 2

            lock.lock()
            switch dr {
            case .process(let pid, let depth):
                if let row = rows[pid] {
                    lock.unlock()
                    y = renderProcessRow(row, y: y, maxX: maxX, maxY: maxY, maxSubRows: 0, showSubRows: false, highlight: isHighlighted, depth: depth, layout: columnLayout)
                } else { lock.unlock() }

            case .infoBorderTop(_, let depth):
                lock.unlock()
                let boxCol = depth * 2 + 3
                currentBoxIndent = boxCol
                let indent = String(repeating: " ", count: boxCol)
                let boxWidth = max(0, width - boxCol - 2)
                let line = "\(indent)\u{250C}\(String(repeating: "\u{2500}", count: boxWidth))\u{2510}"
                attron(ATTR_DIM)
                mvaddstr(y, 0, String(line.prefix(width)))
                attroff(ATTR_DIM)
                y += 1

            case .infoBorderBottom(_, let depth):
                lock.unlock()
                let boxCol = depth * 2 + 3
                let indent = String(repeating: " ", count: boxCol)
                let boxWidth = max(0, width - boxCol - 2)
                let line = "\(indent)\u{2514}\(String(repeating: "\u{2500}", count: boxWidth))\u{2518}"
                attron(ATTR_DIM)
                mvaddstr(y, 0, String(line.prefix(width)))
                attroff(ATTR_DIM)
                y += 1
                currentBoxIndent = -1

            case .separator(let pid):
                lock.unlock()
                let depth = rows[pid]?.disclosed == true ? 1 : 0
                let indent = String(repeating: "  ", count: depth + 1)
                let lineWidth = max(0, width - indent.count * 2)
                let hr = indent + String(repeating: "\u{2500}", count: lineWidth)
                attron(ATTR_DIM)
                mvaddstr(y, 0, String(hr.prefix(width)))
                attroff(ATTR_DIM)
                y += 1

            case .processHeader(let pid):
                let disc = rows[pid]?.infoDisclosed == true ? "\u{25BC}" : "\u{25B6}"
                lock.unlock()
                let triIndent = depthIndent + 2  // child level
                drawBoxHeader(y: y, disc: disc, title: "Process Info", triIndent: triIndent, color: COLOR_PAIR(TUIColor.header.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1

            case .processDetail(let pid, let key):
                if let row = rows[pid] {
                    let value: String
                    switch key {
                    case "Path":    value = "Path: \(row.fullPath)"
                    case "CWD":     value = "CWD:  \(row.cwd)"
                    case "IDs":     value = "PID: \(row.pid)  PPID: \(row.ppid)  UID: \(getuid())"
                    case "Started": let fmt = DateFormatter(); fmt.dateFormat = "yyyy-MM-dd HH:mm:ss"; value = "Started: \(fmt.string(from: row.startTime))"
                    default:        value = key
                    }
                    lock.unlock()
                    drawLine(y: y, indent: depthIndent + 4, content: value, color: ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                    y += 1
                } else { lock.unlock() }

            case .argsHeader(let pid):
                let count = rows[pid]?.argvArray.count ?? 0
                let disc = rows[pid]?.argsDisclosed == true ? "\u{25BC}" : "\u{25B6}"
                lock.unlock()
                drawLine(y: y, indent: depthIndent + 4, content: "\(disc) Args (\(count))", color: COLOR_PAIR(TUIColor.header.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1

            case .argDetail(let pid, let idx):
                let arg = rows[pid]?.argvArray[safe: idx] ?? ""
                lock.unlock()
                drawLine(y: y, indent: depthIndent + 6, content: arg, color: ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1

            case .envHeader(let pid):
                let count = rows[pid]?.envVars.count ?? 0
                let disc = rows[pid]?.envDisclosed == true ? "\u{25BC}" : "\u{25B6}"
                lock.unlock()
                drawLine(y: y, indent: depthIndent + 4, content: "\(disc) Env (\(count) vars)", color: COLOR_PAIR(TUIColor.header.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1

            case .envDetail(let pid, let idx):
                let env = rows[pid]?.envVars[safe: idx] ?? ""
                lock.unlock()
                // Bold the KEY= part, dim the value
                if let eqIdx = env.firstIndex(of: "=") {
                    let key = String(env[...eqIdx])
                    let val = String(env[env.index(after: eqIdx)...])
                    drawLine(y: y, indent: depthIndent + 6, content: key + val, color: ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                } else {
                    drawLine(y: y, indent: depthIndent + 6, content: env, color: ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                }
                y += 1

            case .resourcesHeader(let pid):
                let disc = rows[pid]?.resourcesDisclosed == true ? "\u{25BC}" : "\u{25B6}"
                lock.unlock()
                drawLine(y: y, indent: depthIndent + 4, content: "\(disc) Resources", color: COLOR_PAIR(TUIColor.header.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1

            case .resourceDetail(let pid, let key):
                if let row = rows[pid] {
                    let value: String
                    switch key {
                    case "CPU":
                        let uMin = Int(row.cpuUser) / 60; let uSec = Int(row.cpuUser) % 60
                        let sMin = Int(row.cpuSys) / 60; let sSec = Int(row.cpuSys) % 60
                        value = "CPU: \(uMin):\(String(format: "%02d", uSec)) user, \(sMin):\(String(format: "%02d", sSec)) sys"
                    case "Memory":  value = "Memory: \(formatBytes(row.rss)) RSS"
                    case "FDs":     value = "FDs: \(row.fdCount) open"
                    case "Disk":    value = "Disk: R:\(formatBytes(row.diskBytesRead)) W:\(formatBytes(row.diskBytesWritten))"
                    default: value = key
                    }
                    lock.unlock()
                    drawLine(y: y, indent: depthIndent + 6, content: value, color: ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                    y += 1
                } else { lock.unlock() }

            case .filesHeader(let pid):
                if let row = rows[pid] {
                    let totalWrites = row.files.values.reduce(0) { $0 + $1.writes }
                    let fileCount = row.recentWrittenFiles.count
                    let disc = row.filesDisclosed ? "\u{25BC}" : "\u{25B6}"
                    lock.unlock()
                    let triIndent = depthIndent + 2
                    drawBoxHeader(y: y, disc: disc, title: "Files (\(fileCount) written, W:\(totalWrites))", triIndent: triIndent, color: COLOR_PAIR(TUIColor.subFile.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                    y += 1
                } else { lock.unlock() }

            case .fileDetail(let pid, let path):
                if let row = rows[pid] {
                    let stats = row.files[path]
                    lock.unlock()
                    var parts: [String] = []
                    if let s = stats {
                        parts.append("W:\(s.writes)")
                        var sb = stat()
                        if stat(path, &sb) == 0 && sb.st_size > 0 { parts.append(formatBytes(UInt64(sb.st_size))) }
                    }
                    let statsStr = parts.joined(separator: " ")
                    let relPath = relativePath(path, cwd: row.cwd)
                    let shortPath = shortenPath(relPath, maxLen: width - 8 - statsStr.count)
                    drawLine(y: y, indent: depthIndent + 4, content: "\(shortPath)  \(statsStr)", color: COLOR_PAIR(TUIColor.subFile.rawValue) | ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                    y += 1
                } else { lock.unlock() }

            case .netHeader(let pid):
                if let row = rows[pid] {
                    let connCount = row.connections.count
                    let totalRx = row.connections.values.reduce(0 as UInt64) { $0 + $1.rxBytes }
                    let totalTx = row.connections.values.reduce(0 as UInt64) { $0 + $1.txBytes }
                    let disc = row.netDisclosed ? "\u{25BC}" : "\u{25B6}"
                    lock.unlock()
                    let triIndent = depthIndent + 2
                    drawBoxHeader(y: y, disc: disc, title: "Network (\(connCount) conn \u{2191}\(formatBytes(totalTx)) \u{2193}\(formatBytes(totalRx)))", triIndent: triIndent, color: COLOR_PAIR(TUIColor.subNet.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                    y += 1
                } else { lock.unlock() }

            case .netDetail(let pid, let key):
                if let row = rows[pid], let conn = row.connections[key] {
                    lock.unlock()
                    // Columnar: HOST:PORT          ↑Up       ↓Down
                    let host = truncate(conn.label, to: 35)
                    let hostPad = String(repeating: " ", count: max(1, 36 - host.count))
                    let up = "\u{2191}\(formatBytes(conn.txBytes))"
                    let upPad = String(repeating: " ", count: max(1, 10 - up.count))
                    let down = "\u{2193}\(formatBytes(conn.rxBytes))"
                    let line = "\(host)\(hostPad)\(up)\(upPad)\(down)"
                    let connColor = conn.alive ? TUIColor.subNet : TUIColor.exited
                    drawLine(y: y, indent: depthIndent + 4, content: line, color: COLOR_PAIR(connColor.rawValue) | ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                    y += 1
                } else { lock.unlock() }

            case .sampleHeader(let pid):
                let disc = rows[pid]?.sampleDisclosed == true ? "\u{25BC}" : "\u{25B6}"
                let status = rows[pid]?.isSampling == true ? "Sampling..." : "Sample (3s)"
                lock.unlock()
                let triIndent = depthIndent + 2
                drawBoxHeader(y: y, disc: disc, title: status, triIndent: triIndent, color: COLOR_PAIR(TUIColor.subNet.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1

            case .sampleNode(let pid, let path):
                if let node = sampleNodeAt(pid, path: path) {
                    let nodeDepth = path.count - 1
                    let disc = node.hasChildren ? (node.disclosed ? "\u{25BC} " : "\u{25B6} ") : "  "
                    let content = "\(disc)\(node.pct)% \(node.name) (\(node.count))"
                    lock.unlock()
                    let indent = depthIndent + 4 + nodeDepth * 2
                    let color = node.pct >= 20 ? COLOR_PAIR(TUIColor.subNet.rawValue) :
                                COLOR_PAIR(TUIColor.header.rawValue)
                    drawLine(y: y, indent: indent, content: content, color: color | ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                    y += 1
                } else { lock.unlock() }

            case .waitHeader(let pid):
                let disc = rows[pid]?.waitDisclosed == true ? "\u{25BC}" : "\u{25B6}"
                lock.unlock()
                let triIndent = depthIndent + 2
                drawBoxHeader(y: y, disc: disc, title: "Wait Diagnosis", triIndent: triIndent, color: COLOR_PAIR(TUIColor.subNet.rawValue) | ATTR_BOLD, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1

            case .waitLine(let pid, let idx):
                let line = rows[pid]?.waitResults[safe: idx] ?? ""
                lock.unlock()
                drawLine(y: y, indent: depthIndent + 4, content: line, color: COLOR_PAIR(TUIColor.subNet.rawValue) | ATTR_DIM, highlighted: isHighlighted, width: width, boxIndent: currentBoxIndent)
                y += 1
            }

        }

        drawFooter(maxY: maxY, maxX: maxX)

        // Menu dropdown overlay
        if let menu = activeMenu {
            renderMenuDropdown(menu: menu, maxY: maxY, maxX: maxX)
        }

        // Sample config modal
        if isSampleConfigOpen {
            renderSampleConfigModal(maxY: maxY, maxX: maxX)
        }

        refresh()
    }

    private func columnLayout(for displayRows: [DisplayRow]) -> ColumnLayout {
        var maxDepth = 0
        var maxPidWidth = 3

        for row in displayRows {
            if case .process(let pid, let depth) = row {
                maxDepth = max(maxDepth, depth)
                maxPidWidth = max(maxPidWidth, String(pid).count)
            }
        }

        // Process rows render as: depth indent + disclosure + PID. Shift the
        // fixed columns right when the deepest visible process needs more room.
        let requiredTimeColumn = maxDepth * 2 + 2 + maxPidWidth + 1
        let shift = max(0, requiredTimeColumn - Self.baseColumnLayout.time)

        return ColumnLayout(
            pid: Self.baseColumnLayout.pid,
            time: Self.baseColumnLayout.time + shift,
            ops: Self.baseColumnLayout.ops + shift,
            status: Self.baseColumnLayout.status + shift,
            process: Self.baseColumnLayout.process + shift
        )
    }

    private func renderColumnHeader(y: Int32, width: Int, layout: ColumnLayout) {
        var headerLine = [Character](repeating: " ", count: width)
        let headers: [(col: Int, text: String)] = [
            (layout.pid, "PID"),
            (layout.time, "TIME"),
            (layout.ops, "OPS"),
            (layout.status, "STATUS"),
            (layout.process, "PROCESS"),
        ]
        for h in headers {
            for (i, c) in h.text.enumerated() where h.col + i < width {
                headerLine[h.col + i] = c
            }
        }
        attron(ATTR_BOLD)
        mvaddstr(y, 0, String(headerLine))
        attroff(ATTR_BOLD)
    }

    private func pid(for row: DisplayRow) -> pid_t? {
        switch row {
        case .process(let pid, _),
             .processHeader(let pid),
             .processDetail(let pid, _),
             .argsHeader(let pid),
             .argDetail(let pid, _),
             .envHeader(let pid),
             .envDetail(let pid, _),
             .resourcesHeader(let pid),
             .resourceDetail(let pid, _),
             .filesHeader(let pid),
             .fileDetail(let pid, _),
             .netHeader(let pid),
             .netDetail(let pid, _),
             .separator(let pid),
             .infoBorderTop(let pid, _),
             .infoBorderBottom(let pid, _),
             .sampleHeader(let pid),
             .sampleNode(let pid, _),
             .waitHeader(let pid),
             .waitLine(let pid, _):
            return pid
        }
    }

    private func depthForDisplayRow(at index: Int) -> Int {
        guard let row = displayRows[safe: index] else { return 0 }

        switch row {
        case .process(_, let depth),
             .infoBorderTop(_, let depth),
             .infoBorderBottom(_, let depth):
            return depth
        default:
            break
        }

        guard let rowPid = pid(for: row), index > 0 else { return 0 }
        for previousIndex in stride(from: index - 1, through: 0, by: -1) {
            switch displayRows[previousIndex] {
            case .process(let pid, let depth) where pid == rowPid:
                return depth
            case .infoBorderTop(let pid, let depth) where pid == rowPid:
                return depth
            default:
                continue
            }
        }
        return 0
    }

    private func drawDisclosureTriangle(_ triangle: String, y: Int32, indent: Int, color: Int32, highlighted: Bool) {
        let attr = highlighted ? (color | ATTR_REVERSE) : color
        attron(attr)
        mvaddstr(y, Int32(indent), triangle)
        attroff(attr)
    }


    private func renderMenuBar(y: Int32, width: Int) {
        let barAttr = COLOR_PAIR(TUIColor.menuBar.rawValue)
        let pad = String(repeating: " ", count: width)
        attron(barAttr)
        mvaddstr(y, 0, pad)
        attroff(barAttr)

        let ctx = contextMenuID()
        var menus: [(before: String, key: String, after: String, id: MenuID)] = [
            ("", "F", "ile", .file),
            ("", "E", "dit", .edit),
            ("", "P", "rocess", .process),
        ]
        if ctx != .process {
            switch ctx {
            case .sample:  menus.append(("Sa", "m", "ple", .sample))
            case .network: menus.append(("Ne", "t", "work", .network))
            case .files:   menus.append(("", "", "FileSystem", .files))
            default: break
            }
        }
        menus.append(("", "V", "iew", .view))

        var x: Int32 = 1
        for menu in menus {
            let isActive = activeMenu == menu.id
            let isFlashing = menuFlash == menu.id
            let baseAttr = (isActive || isFlashing) ? COLOR_PAIR(TUIColor.menuHighlight.rawValue) : barAttr

            attron(baseAttr)
            mvaddstr(y, x, " \(menu.before)")
            attroff(baseAttr)
            // Bold underline on shortcut key
            attron(baseAttr | ATTR_BOLD | ATTR_UNDERLINE)
            addstr(menu.key)
            attroff(baseAttr | ATTR_BOLD | ATTR_UNDERLINE)
            attron(baseAttr)
            addstr("\(menu.after) ")
            attroff(baseAttr)

            x += Int32(menu.before.count + menu.key.count + menu.after.count + 2)
        }
    }

    private func renderMenuDropdown(menu: MenuID, maxY: Int32, maxX: Int32) {
        let items: [MenuItem]
        // Compute X position based on menu order
        // Compute dropdown X by measuring actual menu bar items
        func menuWidth(_ id: MenuID) -> Int {
            switch id {
            case .file: return 6
            case .edit: return 6
            case .process: return 10
            case .sample: return 10
            case .network: return 11
            case .files: return 14
            case .view: return 6
            }
        }
        var dropX: Int32 = 1
        for mid in menuOrder {
            if mid == menu { break }
            dropX += Int32(menuWidth(mid))
        }

        switch menu {
        case .file: items = fileMenuItems()
        case .edit: items = editMenuItems()
        case .process: items = processMenuItems()
        case .sample: items = sampleMenuItems()
        case .network: items = networkMenuItems()
        case .files: items = filesMenuItems()
        case .view: items = viewMenuItems()
        }

        guard !items.isEmpty else { return }

        // Calculate dropdown width
        let maxLabel = items.map { $0.label.count }.max() ?? 0
        let maxShortcut = items.map { $0.shortcut.count }.max() ?? 0
        let dropWidth = maxLabel + maxShortcut + 6  // padding + check + gap
        let dropY: Int32 = 2  // below menu bar

        // Draw border and items
        let hLine = String(repeating: "\u{2500}", count: dropWidth - 2)
        let barAttr = COLOR_PAIR(TUIColor.menuBar.rawValue)

        attron(barAttr)
        mvaddstr(dropY, dropX, "\u{250C}\(hLine)\u{2510}")

        for (idx, item) in items.enumerated() {
            let lineY = dropY + Int32(idx) + 1
            if item.isSeparator {
                mvaddstr(lineY, dropX, "\u{251C}\(String(repeating: "\u{2500}", count: dropWidth - 2))\u{2524}")
                continue
            }

            let isHighlighted = idx == menuItemIndex
            let check = item.checked ? "\u{2713} " : "  "
            let gap = String(repeating: " ", count: max(1, dropWidth - 4 - item.label.count - item.shortcut.count))
            let content = "\(check)\(item.label)\(gap)\(item.shortcut)"
            let padded = String(content.prefix(dropWidth - 2))
                + String(repeating: " ", count: max(0, dropWidth - 2 - content.count))

            let itemAttr: Int32
            if isHighlighted && item.enabled {
                itemAttr = COLOR_PAIR(TUIColor.menuHighlight.rawValue)
            } else if isHighlighted && !item.enabled {
                itemAttr = barAttr | ATTR_DIM  // light gray highlight for disabled
            } else if !item.enabled {
                itemAttr = barAttr | ATTR_DIM
            } else {
                itemAttr = barAttr
            }

            mvaddstr(lineY, dropX, "\u{2502}")
            attron(itemAttr)
            addstr(padded)
            attroff(itemAttr)
            attron(barAttr)
            addstr("\u{2502}")
        }

        let bottomY = dropY + Int32(items.count) + 1
        mvaddstr(bottomY, dropX, "\u{2514}\(hLine)\u{2518}")
        attroff(barAttr)
    }

    private func renderSampleConfigModal(maxY: Int32, maxX: Int32) {
        let mWidth = 40
        let mHeight = 9
        let mX = (Int(maxX) - mWidth) / 2
        let mY = (Int(maxY) - mHeight) / 2

        let barAttr = COLOR_PAIR(TUIColor.menuBar.rawValue)
        let hlAttr = COLOR_PAIR(TUIColor.menuHighlight.rawValue)

        // Border
        let hLine = String(repeating: "\u{2500}", count: mWidth - 2)
        attron(barAttr | ATTR_BOLD)
        mvaddstr(Int32(mY), Int32(mX), "\u{250C}\u{2500} Sample Configuration \(String(repeating: "\u{2500}", count: max(0, mWidth - 24)))\u{2510}")
        for row in 1..<(mHeight - 1) {
            mvaddstr(Int32(mY + row), Int32(mX), "\u{2502}\(String(repeating: " ", count: mWidth - 2))\u{2502}")
        }
        mvaddstr(Int32(mY + mHeight - 1), Int32(mX), "\u{2514}\(hLine)\u{2518}")
        attroff(barAttr | ATTR_BOLD)

        // Fields
        let fields: [(label: String, value: String, unit: String)] = [
            ("Duration:", " \(sampleDuration) ", "seconds"),
            ("Threshold:", " \(sampleThreshold) ", "% min to show"),
            ("Max depth:", " \(sampleMaxDepth) ", "caller levels"),
        ]

        for (i, field) in fields.enumerated() {
            let lineY = Int32(mY + 2 + i)
            let isSelected = i == sampleConfigField
            attron(barAttr)
            mvaddstr(lineY, Int32(mX + 2), " \(field.label)  ")
            attroff(barAttr)

            let valAttr = isSelected ? hlAttr : barAttr
            attron(valAttr)
            addstr("◀\(field.value)▶")
            attroff(valAttr)

            attron(barAttr)
            addstr("  \(field.unit)")
            attroff(barAttr)
        }

        // Footer
        let footer = "Enter: start    Esc: cancel    \u{2191}\u{2193}: field    \u{25C0}\u{25B6}: value"
        attron(barAttr | ATTR_DIM)
        mvaddstr(Int32(mY + mHeight - 2), Int32(mX + 2), String(footer.prefix(mWidth - 4)))
        attroff(barAttr | ATTR_DIM)
    }

    private func drawFooter(maxY: Int32, maxX: Int32) {
        let width = Int(maxX)
        let label: String
        if paused {
            label = "PAUSED"
        } else {
            let mode = viewMode == .tree ? "tree" : "flat"
            label = "q: quit  space: pause  enter: inspect  h: \(mode)  \u{2191}\u{2193}: nav  esc: clear"
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
            attr = COLOR_PAIR(TUIColor.exited.rawValue) | ATTR_DIM
        }
        attron(attr)
        mvaddstr(maxY - 1, 0, padded)
        attroff(attr)
    }

    private func appendPanelRows(_ row: ProcessRow, depth: Int) {
        // Info box (only if visible)
        if row.infoVisible {
            displayRows.append(.infoBorderTop(row.pid, depth))
            displayRows.append(.processHeader(row.pid))
            if row.infoDisclosed {
                appendProcessDisclosures(row)
            }
            displayRows.append(.infoBorderBottom(row.pid, depth))
        }

        // Files box (only if visible)
        if row.filesVisible {
            displayRows.append(.infoBorderTop(row.pid, depth))
            displayRows.append(.filesHeader(row.pid))
            if row.filesDisclosed {
                let files = row.recentWrittenFiles
                for file in files { displayRows.append(.fileDetail(row.pid, file.path)) }
            }
            displayRows.append(.infoBorderBottom(row.pid, depth))
        }

        // Network box (only if visible)
        if row.netVisible {
            displayRows.append(.infoBorderTop(row.pid, depth))
            displayRows.append(.netHeader(row.pid))
            if row.netDisclosed {
                let conns = row.sortedConnections
                for conn in conns { displayRows.append(.netDetail(row.pid, conn.key)) }
            }
            displayRows.append(.infoBorderBottom(row.pid, depth))
        }

        // Sample box (only if visible)
        if row.sampleVisible {
            displayRows.append(.infoBorderTop(row.pid, depth))
            displayRows.append(.sampleHeader(row.pid))
            if row.sampleDisclosed {
                if row.isSampling {
                    displayRows.append(.processDetail(row.pid, "Sampling..."))
                } else if row.sampleTree.isEmpty {
                    displayRows.append(.processDetail(row.pid, "Press s to sample"))
                } else {
                    func appendSampleNodes(_ nodes: [SampleNode], path: [Int]) {
                        for (i, node) in nodes.enumerated() {
                            let nodePath = path + [i]
                            displayRows.append(.sampleNode(row.pid, nodePath))
                            if node.disclosed {
                                appendSampleNodes(node.children, path: nodePath)
                            }
                        }
                    }
                    appendSampleNodes(row.sampleTree, path: [])
                }
            }
            displayRows.append(.infoBorderBottom(row.pid, depth))
        }

        // Wait box (only if visible)
        if row.waitVisible {
            displayRows.append(.infoBorderTop(row.pid, depth))
            displayRows.append(.waitHeader(row.pid))
            if row.waitDisclosed {
                if row.waitResults.isEmpty {
                    displayRows.append(.processDetail(row.pid, "Press w to diagnose"))
                } else {
                    for i in 0..<row.waitResults.count {
                        displayRows.append(.waitLine(row.pid, i))
                    }
                }
            }
            displayRows.append(.infoBorderBottom(row.pid, depth))
        }
    }

    private func appendProcessDisclosures(_ row: ProcessRow) {
        displayRows.append(.processDetail(row.pid, "Path"))
        displayRows.append(.processDetail(row.pid, "CWD"))
        displayRows.append(.processDetail(row.pid, "IDs"))
        displayRows.append(.processDetail(row.pid, "Started"))
        displayRows.append(.argsHeader(row.pid))
        if row.argsDisclosed {
            for i in 0..<row.argvArray.count { displayRows.append(.argDetail(row.pid, i)) }
        }
        displayRows.append(.envHeader(row.pid))
        if row.envDisclosed {
            for i in 0..<row.envVars.count { displayRows.append(.envDetail(row.pid, i)) }
        }
        displayRows.append(.resourcesHeader(row.pid))
        if row.resourcesDisclosed {
            displayRows.append(.resourceDetail(row.pid, "CPU"))
            displayRows.append(.resourceDetail(row.pid, "Memory"))
            displayRows.append(.resourceDetail(row.pid, "FDs"))
            displayRows.append(.resourceDetail(row.pid, "Disk"))
        }
    }


    private func renderProcessRow(_ row: ProcessRow, y: Int32, maxX: Int32, maxY: Int32, maxSubRows: Int, showSubRows: Bool, highlight: Bool = false, depth: Int = 0, layout: ColumnLayout = TUI.baseColumnLayout) -> Int32 {
        let status: String
        let color: TUIColor
        if row.isStopped {
            status = "STOP"
            color = .failed
        } else if row.isRunning {
            status = "RUN"
            color = .running
        } else if let code = row.exitCode, code != 0 {
            status = "ERR \(code)"
            color = .failed
        } else {
            status = "OK"
            color = .exited
        }

        let discIndent = depth * 2
        let disc = row.disclosed ? "\u{25BC} " : "\u{25B6} "
        let processLabel = row.argv.isEmpty ? row.name : row.argv
        let width = Int(maxX)

        var attr = row.isRunning
            ? COLOR_PAIR(color.rawValue)
            : COLOR_PAIR(color.rawValue) | ATTR_DIM
        if highlight { attr |= ATTR_REVERSE }

        // Render indent (no highlight)
        let indentStr = String(repeating: " ", count: discIndent)
        mvaddstr(y, 0, indentStr)

        // Fill from disclosure to end of line with attr (so highlight is continuous)
        attron(attr)
        let fillLen = max(0, width - discIndent)
        addstr(String(repeating: " ", count: fillLen))

        // Now overwrite with actual content at absolute positions
        mvaddstr(y, Int32(discIndent), disc)
        addstr(String(row.pid))

        mvaddstr(y, Int32(layout.time), row.runtimeString)
        mvaddstr(y, Int32(layout.ops), String(row.fileOps))
        mvaddstr(y, Int32(layout.status), status)

        let processWidth = max(5, width - layout.process)
        let truncatedProcess = truncateProcess(processLabel, to: processWidth)
        mvaddstr(y, Int32(layout.process), truncatedProcess)
        attroff(attr)
        return y + 1
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

    /// Render a line with highlighting starting at the indent level
    /// Render a box header line: triangle outside │, title inside, continuous highlight
    private func drawBoxHeader(y: Int32, disc: String, title: String, triIndent: Int, color: Int32, highlighted: Bool, width: Int, boxIndent: Int) {
        guard boxIndent >= 0 else { return }
        let boxLeft = boxIndent  // position of │
        let innerWidth = max(0, width - boxLeft - 2)  // between │ and │
        let titleStr = truncate(title, to: innerWidth)
        let padded = titleStr + String(repeating: " ", count: max(0, innerWidth - titleStr.count))

        // Indent + triangle (no highlight)
        mvaddstr(y, 0, String(repeating: " ", count: triIndent))
        addstr(disc)

        // │ + title + pad + │ — highlighted
        let attr = highlighted ? (color | ATTR_REVERSE) : color
        attron(ATTR_DIM)
        addstr("\u{2502}")
        attroff(ATTR_DIM)
        attron(attr)
        addstr(padded)
        attroff(attr)
        attron(ATTR_DIM)
        addstr("\u{2502}")
        attroff(ATTR_DIM)
    }

    private func drawLine(y: Int32, indent: Int, content: String, color: Int32, highlighted: Bool, width: Int, boxIndent: Int = -1) {
        if boxIndent >= 0 {
            // Draw with box borders
            let boxLeft = String(repeating: " ", count: boxIndent) + "\u{2502} "
            let innerWidth = max(0, width - boxLeft.count - 1)  // -1 for right border
            // indent is absolute; convert to relative inside the box
            let contentIndent = max(0, indent - boxIndent - 2)
            let indentStr = String(repeating: " ", count: contentIndent)
            let contentStr = truncate(content, to: innerWidth - contentIndent)
            let padded = indentStr + contentStr + String(repeating: " ", count: max(0, innerWidth - contentIndent - contentStr.count))
            attron(ATTR_DIM)
            mvaddstr(y, 0, boxLeft)
            attroff(ATTR_DIM)
            let attr = highlighted ? (color | ATTR_REVERSE) : color
            attron(attr)
            addstr(padded)
            attroff(attr)
            attron(ATTR_DIM)
            addstr("\u{2502}")
            attroff(ATTR_DIM)
        } else {
            let indentStr = String(repeating: " ", count: indent)
            let contentStr = truncate(content, to: width - indent)
            let padded = contentStr + String(repeating: " ", count: max(0, width - indent - contentStr.count))
            mvaddstr(y, 0, indentStr)
            let attr = highlighted ? (color | ATTR_REVERSE) : color
            attron(attr)
            addstr(padded)
            attroff(attr)
        }
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
