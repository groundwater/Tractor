import AppKit
import SwiftUI

enum TractorGUIEntry {
    static func run() -> Never {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.mainMenu = delegate.buildMainMenu()
        app.activate(ignoringOtherApps: true)
        app.run()
        exit(0)
    }
}

extension AppDelegate {
    func buildMainMenu() -> NSMenu {
        let mainMenu = NSMenu()
        let appName = ProcessInfo.processInfo.processName

        // App menu
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About \(appName)",
                        action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
                        keyEquivalent: "")
        appMenu.addItem(.separator())
        let settingsItem = NSMenuItem(title: "Settings…",
                                      action: #selector(AppDelegate.openSettings(_:)),
                                      keyEquivalent: ",")
        settingsItem.target = self
        appMenu.addItem(settingsItem)
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Hide \(appName)",
                        action: #selector(NSApplication.hide(_:)),
                        keyEquivalent: "h")
        let hideOthers = NSMenuItem(title: "Hide Others",
                                    action: #selector(NSApplication.hideOtherApplications(_:)),
                                    keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(hideOthers)
        appMenu.addItem(withTitle: "Show All",
                        action: #selector(NSApplication.unhideAllApplications(_:)),
                        keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: "Quit \(appName)",
                        action: #selector(NSApplication.terminate(_:)),
                        keyEquivalent: "q")
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        // Edit menu (so standard cut/copy/paste/select-all work in any text field)
        let editMenuItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editMenu.addItem(.separator())
        let findItem = NSMenuItem(title: "Find",
                                  action: #selector(AppDelegate.focusFilter(_:)),
                                  keyEquivalent: "f")
        findItem.target = self
        editMenu.addItem(findItem)
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        // Process menu
        let processMenuItem = NSMenuItem()
        let processMenu = NSMenu(title: "Process")
        let showExitedItem = NSMenuItem(title: "Show Exited",
                                        action: #selector(AppDelegate.toggleShowExited(_:)),
                                        keyEquivalent: "")
        showExitedItem.target = self
        processMenu.addItem(showExitedItem)
        processMenuItem.submenu = processMenu
        mainMenu.addItem(processMenuItem)

        // Window menu
        let windowMenuItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Minimize",
                           action: #selector(NSWindow.performMiniaturize(_:)),
                           keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoom",
                           action: #selector(NSWindow.performZoom(_:)),
                           keyEquivalent: "")
        windowMenu.addItem(.separator())
        windowMenu.addItem(withTitle: "Close",
                           action: #selector(NSWindow.performClose(_:)),
                           keyEquivalent: "w")
        windowMenuItem.submenu = windowMenu
        mainMenu.addItem(windowMenuItem)
        NSApplication.shared.windowsMenu = windowMenu

        return mainMenu
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow?
    var settingsWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let controller = NSHostingController(rootView: MainView())
        let window = NSWindow(contentViewController: controller)
        window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
        window.title = "Tractor"
        // Persist size + position across launches. AppKit handles save/restore
        // automatically; centers only on the very first launch (no saved frame).
        if !window.setFrameUsingName("TractorMainWindow") {
            window.setContentSize(NSSize(width: 760, height: 640))
            window.center()
        }
        window.setFrameAutosaveName("TractorMainWindow")
        window.makeKeyAndOrderFront(nil)
        self.window = window
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    @MainActor
    @objc func toggleShowExited(_ sender: NSMenuItem) {
        AppPrefs.shared.hideExited.toggle()
    }

    @MainActor
    @objc func focusFilter(_ sender: Any?) {
        NotificationCenter.default.post(name: .focusFilterField, object: nil)
    }

    @MainActor
    @objc func openSettings(_ sender: Any?) {
        if let win = settingsWindow {
            win.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let controller = NSHostingController(rootView: SetupView())
        let win = NSWindow(contentViewController: controller)
        win.styleMask = [.titled, .closable, .miniaturizable, .resizable]
        win.title = "Settings"
        win.setContentSize(NSSize(width: 620, height: 520))
        if !win.setFrameUsingName("TractorSettingsWindow") {
            win.center()
        }
        win.setFrameAutosaveName("TractorSettingsWindow")
        win.isReleasedWhenClosed = false
        win.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        settingsWindow = win
    }

    @MainActor
    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(toggleShowExited(_:)) {
            // "Show Exited" is the inverse of `hideExited` — check on when
            // we are NOT hiding exited rows.
            menuItem.state = AppPrefs.shared.hideExited ? .off : .on
            return true
        }
        return true
    }
}

// MARK: - Target model

enum TargetKind: Hashable {
    case recommended(bundleID: String)
    /// Recommended entry that matches by process name (for CLI binaries that
    /// have no bundle ID, e.g. `claude`).
    case recommendedByName(processName: String)
    case application(bundleID: String)
    case pid(pid_t)
    case custom(id: UUID)
}

struct TraceTarget: Identifiable, Hashable {
    let id: String
    let kind: TargetKind
    let label: String
    let detail: String?
    let icon: NSImage?

    static func == (lhs: TraceTarget, rhs: TraceTarget) -> Bool { lhs.id == rhs.id }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

// MARK: - Trace runner (in-process)

/// Rolling 30s ring buffer of activity samples for the playback timeline.
/// 100ms bins; each bin counts file-op events (disk) and TCP byte deltas
/// (network). Recording state is captured per-bin so the timeline can tint
/// recorded spans red.
@MainActor
final class ActivitySampler: ObservableObject {
    static let binSeconds: TimeInterval = 0.1
    static let windowSeconds: TimeInterval = 30
    static var binCount: Int { Int(windowSeconds / binSeconds) } // 300

    struct Bin: Equatable {
        var disk: Double = 0
        var network: Double = 0
        var recorded: Bool = false
    }

    @Published private(set) var bins: [Bin] =
        Array(repeating: Bin(), count: ActivitySampler.binCount)

    /// Mirrors TraceRunner.isRecording. Stamped onto each new bin as it
    /// rotates in.
    var isRecording: Bool = false

    private var timer: Timer?
    /// Last seen cumulative byte total per flow id, used to derive deltas.
    private var lastBytesPerFlow: [UInt64: Int64] = [:]

    func start() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: Self.binSeconds, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.advance() }
        }
    }

    func stop() {
        timer?.invalidate()
        timer = nil
    }

    func reset() {
        bins = Array(repeating: Bin(), count: Self.binCount)
        lastBytesPerFlow.removeAll()
    }

    private func advance() {
        bins.removeFirst()
        bins.append(Bin(recorded: isRecording))
    }

    func tickDisk() {
        guard !bins.isEmpty else { return }
        bins[bins.count - 1].disk += 1
    }

    func tickBytes(flowID: UInt64, cumulative: Int64) {
        guard !bins.isEmpty else { return }
        let last = lastBytesPerFlow[flowID] ?? 0
        let delta = cumulative - last
        lastBytesPerFlow[flowID] = cumulative
        if delta > 0 {
            bins[bins.count - 1].network += Double(delta)
        }
    }
}

@MainActor
final class TraceRunner: ObservableObject {
    @Published private(set) var isRunning = false
    /// Whether events are being persisted to the SQLite trace DB. Independent
    /// of tracing — tracing is always on once started; recording is the
    /// user-controlled "save to disk" switch, gated by SQLiteLog.isEnabled.
    @Published var isRecording = false {
        didSet {
            session?.setSQLiteRecordingEnabled(isRecording)
            sampler.isRecording = isRecording
            if isRecording && !oldValue {
                session?.resetSQLiteRecordedCount()
            }
        }
    }

    let sampler = ActivitySampler()

    /// Number of events written to the trace DB during the current recording.
    /// Polled by the GUI footer via a TimelineView tick.
    var recordedEventCount: Int { session?.sqliteRecordedCount ?? 0 }
    @Published private(set) var lastMessage: String?
    let live = LiveModel()

    private var session: TraceSession?
    private var sink: LiveSink?
    private var appliedPids: Set<pid_t> = []
    private var appliedPaths: Set<String> = []
    private var appliedNames: Set<String> = []

    /// Idempotent — starts the trace session if it isn't running yet. Safe to
    /// call eagerly on app launch and again later when targets are added.
    func ensureStarted() {
        guard !isRunning else { return }
        start(active: [], runningByBundleID: [:])
    }

    func start(active: [TraceTarget], runningByBundleID: [String: pid_t]) {
        guard !isRunning else { return }

        var pids: [pid_t] = []
        var paths: [String] = []
        var names: [String] = []
        let groups = buildGroups(active: active, runningByBundleID: runningByBundleID)
        for target in active {
            switch target.kind {
            case .application(let bid), .recommended(let bid):
                if let pid = runningByBundleID[bid] { pids.append(pid) }
            case .recommendedByName(let n):
                names.append(n)
                pids.append(contentsOf: findProcessesByName(n))
            case .pid(let pid):
                pids.append(pid)
            case .custom:
                if let p = target.detail { paths.append(p) }
            }
        }

        live.reset()
        live.setGroups(groups)
        let sink = LiveSink(model: live)
        let session = TraceSession(primarySink: sink)
        session.onConnectionError = { [weak self] error in
            Task { @MainActor in
                self?.lastMessage = "lost ES connection: \(error.localizedDescription)"
                self?.stop()
            }
        }
        session.onMessage = { [weak self] msg in
            Task { @MainActor in self?.lastMessage = msg }
        }
        session.onBytesUpdate = { [weak self] pid, host, port, bytesOut, bytesIn, flowID in
            guard let self = self else { return }
            let m = self.live
            DispatchQueue.main.async {
                m.handleBytesUpdate(pid: pid, host: host, port: port,
                                    bytesOut: bytesOut, bytesIn: bytesIn, flowID: flowID)
                self.sampler.tickBytes(flowID: flowID, cumulative: bytesOut + bytesIn)
            }
        }
        session.onFileOp = { [weak self] _, _, _, _, _, _ in
            guard let self = self else { return }
            Task { @MainActor in self.sampler.tickDisk() }
        }
        session.onConnectionClosed = { [weak self] pid, host, port, flowID in
            let m = self?.live
            DispatchQueue.main.async {
                m?.handleConnectionClosed(pid: pid, host: host, port: port, flowID: flowID)
            }
        }

        let roots = TraceRoots(names: names, pids: pids, paths: paths)
        // GUI needs network bytes for the timeline waveform; NE will silently
        // no-op (with a lastMessage) if the network extension isn't activated.
        let options = TraceOptions(logToSQLite: true, net: true)

        do {
            try session.start(roots: roots, options: options)
            session.setSQLiteRecordingEnabled(isRecording)
            session.seedSinkFromTree()
            self.session = session
            self.sink = sink
            self.appliedPids = Set(pids)
            self.appliedPaths = Set(paths)
            self.appliedNames = Set(names)
            self.isRunning = true
            self.lastMessage = nil
            sampler.start()
        } catch {
            self.lastMessage = "failed to start: \(error.localizedDescription)"
        }
    }

    func stop() {
        session?.stop()
        session = nil
        sink = nil
        appliedPids.removeAll()
        appliedPaths.removeAll()
        appliedNames.removeAll()
        isRunning = false
    }

    /// Push the current active-list state to the running session. Safe to call
    /// when stopped — it's a no-op. Adds work; remove is best-effort (the ES
    /// sysext doesn't support pid removal yet, so existing tracked PIDs keep
    /// emitting until their process exits).
    func apply(active: [TraceTarget], runningByBundleID: [String: pid_t]) {
        if !isRunning {
            ensureStarted()
        }
        guard let session = session, isRunning else { return }
        var pids: Set<pid_t> = []
        var paths: Set<String> = []
        var names: Set<String> = []
        for target in active {
            switch target.kind {
            case .application(let bid), .recommended(let bid):
                if let pid = runningByBundleID[bid] { pids.insert(pid) }
            case .recommendedByName(let n):
                names.insert(n)
                for pid in findProcessesByName(n) { pids.insert(pid) }
            case .pid(let pid):
                pids.insert(pid)
            case .custom:
                if let p = target.detail, !p.isEmpty { paths.insert(p) }
            }
        }
        live.setGroups(buildGroups(active: active, runningByBundleID: runningByBundleID))

        // Newly-added targets: expand their existing process tree so already-
        // running descendants are captured. The session fires synthetic onExec
        // events for those so the live view picks them up.
        let newPids = pids.subtracting(appliedPids)
        let newPaths = paths.subtracting(appliedPaths)
        let newNames = names.subtracting(appliedNames)
        if !newPids.isEmpty {
            session.attachExisting(roots: Array(newPids))
            appliedPids.formUnion(newPids)
        }
        if !newPaths.isEmpty {
            session.attachExisting(paths: Array(newPaths))
            appliedPaths.formUnion(newPaths)
        }
        if !newNames.isEmpty {
            appliedNames.formUnion(newNames)
        }
        session.setTrackerPatterns(names: Array(appliedNames), paths: Array(appliedPaths))
    }

    private func buildGroups(active: [TraceTarget], runningByBundleID: [String: pid_t]) -> [TraceGroup] {
        active.map { target in
            let kind: TraceGroup.Kind
            switch target.kind {
            case .application(let bid), .recommended(let bid):
                if let pid = runningByBundleID[bid] { kind = .pid(pid) }
                else { kind = .name(target.label) }
            case .recommendedByName(let n):
                kind = .name(n)
            case .pid(let pid):
                kind = .pid(pid)
            case .custom:
                kind = .path(target.detail ?? "")
            }
            return TraceGroup(id: target.id, label: target.label, kind: kind)
        }
    }
}

// MARK: - Active-list persistence

private enum StoredActiveTarget: Codable, Hashable {
    case recommended(bundleID: String)
    case recommendedByName(processName: String)
    case application(bundleID: String, name: String)
    case custom(id: UUID)
}

private final class ActiveTargetStore {
    private let defaults = UserDefaults.standard
    private let key = "tractor.gui.activeTargets.v1"

    func load() -> [StoredActiveTarget] {
        guard let data = defaults.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([StoredActiveTarget].self, from: data)) ?? []
    }

    func save(_ entries: [StoredActiveTarget]) {
        if let data = try? JSONEncoder().encode(entries) {
            defaults.set(data, forKey: key)
        }
    }
}

// MARK: - Custom target persistence

struct StoredCustomTarget: Codable, Identifiable, Hashable {
    let id: UUID
    var name: String
    var path: String

    func asTarget() -> TraceTarget {
        TraceTarget(
            id: "custom:\(id.uuidString)",
            kind: .custom(id: id),
            label: name,
            detail: path,
            icon: nil
        )
    }
}

private final class CustomTargetStore {
    private let defaults = UserDefaults.standard
    private let key = "tractor.gui.customTargets.v1"

    func load() -> [StoredCustomTarget] {
        guard let data = defaults.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([StoredCustomTarget].self, from: data)) ?? []
    }

    func save(_ targets: [StoredCustomTarget]) {
        if let data = try? JSONEncoder().encode(targets) {
            defaults.set(data, forKey: key)
        }
    }
}

// MARK: - Static recommended list

private struct RecommendedEntry {
    let name: String
    /// Either a bundle ID for a GUI app or a process name for a CLI binary.
    let match: Match

    enum Match: Hashable {
        case bundleID(String)
        case processName(String)
    }
}

private let recommendedEntries: [RecommendedEntry] = [
    .init(name: "Cursor",    match: .bundleID("com.todesktop.230313mzl4w4u92")),
    .init(name: "Claude",    match: .processName("claude")),
    .init(name: "VS Code",   match: .bundleID("com.microsoft.VSCode")),
    .init(name: "Zed",       match: .bundleID("dev.zed.Zed")),
    .init(name: "Windsurf",  match: .bundleID("com.exafunction.windsurf")),
]

// MARK: - View model

@MainActor
final class PickerModel: ObservableObject {
    @Published var active: [TraceTarget] = []
    @Published var customDraftName: String = ""
    @Published var customDraftPath: String = ""
    @Published var pidDraft: String = ""

    @Published private(set) var runningApplications: [TraceTarget] = []
    @Published private(set) var runningByBundleID: [String: pid_t] = [:]
    @Published var savedCustom: [StoredCustomTarget] = []

    private var observers: [NSObjectProtocol] = []
    private let ownBundleID: String? = Bundle.main.bundleIdentifier
    private let customStore = CustomTargetStore()
    private let activeStore = ActiveTargetStore()

    init() {
        savedCustom = customStore.load()
        refreshRunning()
        restoreActiveTargets()
        let nc = NSWorkspace.shared.notificationCenter
        let didLaunch = nc.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refreshRunning() }
        }
        let didTerminate = nc.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refreshRunning() }
        }
        observers = [didLaunch, didTerminate]
    }

    deinit {
        let nc = NSWorkspace.shared.notificationCenter
        for o in observers { nc.removeObserver(o) }
    }

    private func refreshRunning() {
        var byID: [String: pid_t] = [:]
        var targets: [TraceTarget] = []
        for app in NSWorkspace.shared.runningApplications {
            guard app.activationPolicy == .regular else { continue }
            guard let bid = app.bundleIdentifier, bid != ownBundleID else { continue }
            byID[bid] = app.processIdentifier
            let name = app.localizedName ?? bid
            targets.append(TraceTarget(
                id: "app:\(bid)",
                kind: .application(bundleID: bid),
                label: name,
                detail: bid,
                icon: app.icon
            ))
        }
        targets.sort { $0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending }
        self.runningByBundleID = byID
        self.runningApplications = targets
    }

    func contains(_ target: TraceTarget) -> Bool {
        active.contains(where: { $0.id == target.id })
    }

    func add(_ target: TraceTarget) {
        guard !contains(target) else { return }
        active.append(target)
        persistActive()
    }

    func remove(_ target: TraceTarget) {
        active.removeAll { $0.id == target.id }
        persistActive()
    }

    private func persistActive() {
        let stored: [StoredActiveTarget] = active.compactMap { target in
            switch target.kind {
            case .recommended(let bid): return .recommended(bundleID: bid)
            case .recommendedByName(let n): return .recommendedByName(processName: n)
            case .application(let bid): return .application(bundleID: bid, name: target.label)
            case .custom(let id): return .custom(id: id)
            case .pid: return nil // ephemeral, can't survive relaunch
            }
        }
        activeStore.save(stored)
    }

    private func restoreActiveTargets() {
        let stored = activeStore.load()
        guard !stored.isEmpty else { return }
        var restored: [TraceTarget] = []
        let recommended = recommendedTargets()
        let customByID: [UUID: StoredCustomTarget] = Dictionary(uniqueKeysWithValues: savedCustom.map { ($0.id, $0) })
        for entry in stored {
            switch entry {
            case .recommended(let bid):
                if let t = recommended.first(where: {
                    if case .recommended(let b) = $0.kind { return b == bid }
                    return false
                }) {
                    restored.append(t)
                }
            case .recommendedByName(let n):
                if let t = recommended.first(where: {
                    if case .recommendedByName(let pn) = $0.kind { return pn == n }
                    return false
                }) {
                    restored.append(t)
                }
            case .application(let bid, let name):
                restored.append(TraceTarget(
                    id: "app:\(bid)",
                    kind: .application(bundleID: bid),
                    label: name,
                    detail: bid,
                    icon: iconForBundleID(bid)
                ))
            case .custom(let id):
                if let stored = customByID[id] {
                    restored.append(stored.asTarget())
                }
            }
        }
        active = restored
    }

    func recommendedTargets() -> [TraceTarget] {
        recommendedEntries.map { entry in
            switch entry.match {
            case .bundleID(let bid):
                return TraceTarget(
                    id: "rec:\(bid)",
                    kind: .recommended(bundleID: bid),
                    label: entry.name,
                    detail: bid,
                    icon: iconForBundleID(bid)
                )
            case .processName(let pname):
                return TraceTarget(
                    id: "rec-name:\(pname)",
                    kind: .recommendedByName(processName: pname),
                    label: entry.name,
                    detail: "process: \(pname)",
                    icon: nil
                )
            }
        }
    }

    func isRunning(bundleID: String) -> Bool {
        runningByBundleID[bundleID] != nil
    }

    func resolveProcessName(pid: pid_t) -> String? {
        guard pid > 0 else { return nil }
        var nameBuf = [CChar](repeating: 0, count: 256)
        let n = proc_name(pid, &nameBuf, UInt32(nameBuf.count))
        guard n > 0 else { return nil }
        let s = String(cString: nameBuf)
        return s.isEmpty ? nil : s
    }

    func addCustom(name: String, path: String) {
        let entry = StoredCustomTarget(id: UUID(), name: name, path: path)
        savedCustom.append(entry)
        customStore.save(savedCustom)
    }

    func deleteCustom(_ stored: StoredCustomTarget) {
        savedCustom.removeAll { $0.id == stored.id }
        active.removeAll { $0.id == stored.asTarget().id }
        customStore.save(savedCustom)
        persistActive()
    }

    private func iconForBundleID(_ bundleID: String) -> NSImage? {
        if let app = NSWorkspace.shared.runningApplications.first(where: { $0.bundleIdentifier == bundleID }) {
            return app.icon
        }
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) {
            return NSWorkspace.shared.icon(forFile: url.path)
        }
        return nil
    }
}

// MARK: - Root

private struct MainView: View {
    @State private var filter: String = ""
    @ObservedObject private var prefs = AppPrefs.shared

    var body: some View {
        RootView(filter: $filter)
            .frame(minWidth: 720, minHeight: 580)
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        prefs.inspectorShown.toggle()
                    } label: {
                        Image(systemName: "sidebar.right")
                    }
                    .help(prefs.inspectorShown ? "Hide inspector" : "Show inspector")
                }
            }
    }
}

extension Notification.Name {
    static let focusFilterField = Notification.Name("tractor.focusFilterField")
}

/// NSTextField-backed search field. We don't use SwiftUI's TextField + @FocusState
/// here because @FocusState bindings don't reliably propagate into views that
/// live inside a SwiftUI ToolbarItem on macOS — toolbar items render in a
/// detached hosting view. With a real NSTextField we can call
/// `window.makeFirstResponder(field)` directly from the .focusFilterField
/// notification handler.
struct FilterField: NSViewRepresentable {
    @Binding var text: String
    var placeholder: String

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeNSView(context: Context) -> NSSearchField {
        let field = NSSearchField(string: text)
        field.placeholderString = placeholder
        field.delegate = context.coordinator
        field.sendsSearchStringImmediately = true
        field.sendsWholeSearchString = false
        context.coordinator.attach(field: field)
        return field
    }

    func updateNSView(_ nsView: NSSearchField, context: Context) {
        if nsView.stringValue != text {
            nsView.stringValue = text
        }
    }

    final class Coordinator: NSObject, NSSearchFieldDelegate {
        let text: Binding<String>
        private var observer: NSObjectProtocol?

        init(text: Binding<String>) {
            self.text = text
        }

        deinit {
            if let observer = observer {
                NotificationCenter.default.removeObserver(observer)
            }
        }

        func attach(field: NSSearchField) {
            observer = NotificationCenter.default.addObserver(
                forName: .focusFilterField,
                object: nil,
                queue: .main
            ) { [weak field] _ in
                guard let field = field, let window = field.window else { return }
                window.makeFirstResponder(field)
                // Select all so typing replaces existing text — matches the
                // expected ⌘F behavior in most macOS apps.
                if let editor = field.currentEditor() as? NSTextView {
                    editor.selectAll(nil)
                }
            }
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let field = obj.object as? NSSearchField else { return }
            text.wrappedValue = field.stringValue
        }
    }
}

private struct RootView: View {
    @Binding var filter: String
    @StateObject private var model = PickerModel()
    @StateObject private var runner = TraceRunner()
    @ObservedObject private var prefs = AppPrefs.shared
    @State private var pickerSheetShown = false
    @State private var optionsSheetShown = false
    @State private var selection: ProcessTableRow.ID? = nil
    @State private var detailTab: LiveView.DetailTab = .files

    var body: some View {
        VSplitView {
            LiveView(model: runner.live,
                     filter: $filter,
                     selection: $selection,
                     onAddTarget: { pickerSheetShown = true },
                     onDeleteGroup: { groupID in
                        if let target = model.active.first(where: { $0.id == groupID }) {
                            model.remove(target)
                        }
                     })
                .frame(minHeight: 220)
            footer
                .frame(minHeight: 80, idealHeight: 96)
        }
        .inspector(isPresented: $prefs.inspectorShown) {
            DetailPane(model: runner.live, selectionID: selection, tab: $detailTab)
                .inspectorColumnWidth(min: 320, ideal: 400, max: 700)
        }
        .frame(minWidth: 720, minHeight: 520)
        .sheet(isPresented: $pickerSheetShown) {
            PickerSheet(model: model) {
                pickerSheetShown = false
            }
            .frame(minWidth: 640, minHeight: 560)
        }
        .sheet(isPresented: $optionsSheetShown) {
            RecordOptionsSheet(
                options: Binding(
                    get: { prefs.recordOptions },
                    set: { prefs.recordOptions = $0 }
                ),
                onClose: { optionsSheetShown = false }
            )
        }
        .onAppear {
            runner.ensureStarted()
            // Push the restored-from-UserDefaults active list to the session.
            // .onChange below only fires on subsequent changes, not the initial
            // value, so without this the persisted targets would silently
            // never attach to the trace session.
            runner.apply(active: model.active, runningByBundleID: model.runningByBundleID)
        }
        .onChange(of: model.active) { _, _ in
            runner.apply(active: model.active, runningByBundleID: model.runningByBundleID)
        }
    }

    @ViewBuilder
    private var footer: some View {
        HStack(spacing: 10) {
            TimelineMock(sampler: runner.sampler, isRecording: runner.isRecording)
                .frame(maxWidth: .infinity)
            Button("Options…") { optionsSheetShown = true }
            RecordButton(isRecording: runner.isRecording) {
                runner.isRecording.toggle()
            }
            .keyboardShortcut(.return, modifiers: [.command])
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

/// Visual-only mock of the playback timeline. No wiring to LiveModel /
/// SQLite yet — it's just a scrubbable bar so we can iterate on the
/// interaction shape before committing to the underlying replay engine.
private struct TimelineMock: View {
    @ObservedObject var sampler: ActivitySampler
    let isRecording: Bool
    @State private var isPlaying: Bool = false
    @State private var atLive: Bool = true
    @State private var playhead: CGFloat = 1.0  // 0…1 along the bar

    private let barHeight: CGFloat = 44
    /// "Now" sits at 90% of the bar's width. The rightmost 10% is empty
    /// headroom that fills as new samples arrive.
    private let liveX: CGFloat = 0.90

    var body: some View {
        HStack(spacing: 10) {
            Button {
                isPlaying.toggle()
                if isPlaying { atLive = false }
            } label: {
                Image(systemName: isPlaying ? "pause.fill" : "play.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(.primary)

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    // Track background.
                    RoundedRectangle(cornerRadius: 4, style: .continuous)
                        .fill(Color(NSColor.tertiaryLabelColor).opacity(0.25))
                    // Center line.
                    Rectangle()
                        .fill(Color(NSColor.separatorColor).opacity(0.55))
                        .frame(height: 1)
                        .offset(y: geo.size.height / 2 - 0.5)
                    // Waveform — newest sample at the 90% mark, older to the left.
                    Canvas { context, size in
                        let bins = sampler.bins
                        guard !bins.isEmpty else { return }
                        // Map bin index → x. The most-recent bin (last) sits at
                        // liveX * size.width; older bins step leftward.
                        let dataWidth = size.width * liveX
                        let binW = dataWidth / CGFloat(bins.count)
                        let midY = size.height / 2
                        let maxDisk = max(bins.map(\.disk).max() ?? 1, 1)
                        let maxNet = max(bins.map(\.network).max() ?? 1, 1)
                        let maxHalfH = midY - 2
                        for (i, bin) in bins.enumerated() {
                            let x = CGFloat(i) * binW
                            let baseColor: Color = bin.recorded
                                ? Color.red.opacity(0.7)
                                : Color.accentColor.opacity(0.65)
                            let dH = CGFloat(bin.disk / maxDisk) * maxHalfH
                            if dH > 0 {
                                context.fill(
                                    Path(CGRect(x: x, y: midY - dH,
                                                width: max(binW - 0.5, 0.5), height: dH)),
                                    with: .color(baseColor)
                                )
                            }
                            let nH = CGFloat(bin.network / maxNet) * maxHalfH
                            if nH > 0 {
                                context.fill(
                                    Path(CGRect(x: x, y: midY,
                                                width: max(binW - 0.5, 0.5), height: nH)),
                                    with: .color(baseColor)
                                )
                            }
                        }
                    }
                    // Playhead (fixed @ liveX).
                    let headX = liveX * geo.size.width
                    RoundedRectangle(cornerRadius: 1.5, style: .continuous)
                        .fill(isRecording ? Color.red : Color.primary)
                        .frame(width: 2, height: geo.size.height + 4)
                        .offset(x: headX - 1, y: -2)
                }
                .frame(height: barHeight)
                .contentShape(Rectangle())
            }
            .frame(height: barHeight)

            Button {
                atLive = true
                isPlaying = false
                playhead = 1.0
            } label: {
                HStack(spacing: 5) {
                    Circle()
                        .fill(atLive ? Color.red : Color.secondary.opacity(0.4))
                        .frame(width: 7, height: 7)
                    Text(verbatim: "Live")
                        .font(.caption.weight(.semibold))
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(atLive ? Color.secondary.opacity(0.15) : Color.clear,
                            in: Capsule())
            }
            .buttonStyle(.plain)
        }
    }
}

private struct RecordButton: View {
    let isRecording: Bool
    let action: () -> Void
    @State private var pulse = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: isRecording ? "stop.fill" : "circle.fill")
                    .foregroundStyle(Color.red)
                    .shadow(color: isRecording ? Color.red.opacity(pulse ? 0.9 : 0.4) : .clear,
                            radius: isRecording ? (pulse ? 8 : 4) : 0)
                Text(isRecording ? "Stop" : "Record")
            }
            .padding(.horizontal, 10)
        }
        .onAppear { if isRecording { pulse = true } }
        .onChange(of: isRecording) { _, newValue in pulse = newValue }
        .animation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true), value: pulse)
    }
}

private enum PickerCategory: Hashable, CaseIterable {
    case recommended, applications, pids, custom

    var title: String {
        switch self {
        case .recommended:  return "Recommended"
        case .applications: return "Applications"
        case .pids:         return "PIDs"
        case .custom:       return "Custom"
        }
    }

    var systemImage: String {
        switch self {
        case .recommended:  return "star.fill"
        case .applications: return "app.fill"
        case .pids:         return "number"
        case .custom:       return "doc.fill"
        }
    }
}

private struct PickerPane: View {
    @ObservedObject var model: PickerModel
    @Binding var category: PickerCategory
    @Binding var pickSelection: TraceTarget.ID?
    @Binding var pidSelection: Set<pid_t>
    @Binding var pidProcesses: [RunningProcessInfo]

    var body: some View {
        HSplitView {
            List(PickerCategory.allCases, id: \.self, selection: $category) { cat in
                Label(cat.title, systemImage: cat.systemImage).tag(cat)
            }
            .listStyle(.sidebar)
            .frame(minWidth: 160, idealWidth: 200, maxWidth: 260)
            Group {
                switch category {
                case .recommended:  RecommendedCategoryView(model: model, selection: $pickSelection)
                case .applications: ApplicationsCategoryView(model: model, selection: $pickSelection)
                case .pids:         PIDsCategoryView(processes: $pidProcesses, selection: $pidSelection)
                case .custom:       CustomCategoryView(model: model, selection: $pickSelection)
                }
            }
            .frame(minWidth: 380, idealWidth: 520)
        }
        .onChange(of: category) { _, _ in
            pickSelection = nil
            pidSelection.removeAll()
        }
    }
}

// MARK: - Category views (one Table each)

private struct RecommendedCategoryView: View {
    @ObservedObject var model: PickerModel
    @Binding var selection: TraceTarget.ID?

    var body: some View {
        let rows = model.recommendedTargets()
        Table(rows, selection: $selection) {
            TableColumn("Name") { t in
                HStack {
                    statusDot(for: t)
                    Text(t.label)
                    if model.contains(t) {
                        Label("Added", systemImage: "checkmark")
                            .labelStyle(.iconOnly)
                            .foregroundStyle(.secondary)
                            .help("Already added")
                    }
                }
            }
            TableColumn("Bundle ID") { t in
                Text(t.detail ?? "").foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        }
    }

    private func statusDot(for t: TraceTarget) -> some View {
        let running: Bool
        switch t.kind {
        case .recommended(let bid):       running = model.isRunning(bundleID: bid)
        case .recommendedByName(let n):   running = !findProcessesByName(n).isEmpty
        default:                          running = false
        }
        return Circle()
            .fill(running ? Color.green : Color.secondary.opacity(0.4))
            .frame(width: 8, height: 8)
    }
}

private struct ApplicationsCategoryView: View {
    @ObservedObject var model: PickerModel
    @Binding var selection: TraceTarget.ID?
    @State private var search = ""

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Search applications…", text: $search)
                    .textFieldStyle(.roundedBorder)
            }
            .padding(8)
            .background(.bar)
            Divider()
            Table(filtered, selection: $selection) {
                TableColumn("Name") { t in
                    HStack {
                        Circle().fill(Color.green).frame(width: 8, height: 8)
                        Text(t.label)
                        if model.contains(t) {
                            Label("Added", systemImage: "checkmark")
                                .labelStyle(.iconOnly)
                                .foregroundStyle(.secondary)
                                .help("Already added")
                        }
                    }
                }
                TableColumn("Bundle ID") { t in
                    Text(t.detail ?? "").foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
        }
    }

    private var filtered: [TraceTarget] {
        let q = search.lowercased()
        guard !q.isEmpty else { return model.runningApplications }
        return model.runningApplications.filter { $0.label.lowercased().contains(q) }
    }
}

private struct PIDsCategoryView: View {
    @Binding var processes: [RunningProcessInfo]
    @Binding var selection: Set<pid_t>
    @State private var filter: String = ""

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("Filter pid / user / name / args…", text: $filter)
                    .textFieldStyle(.roundedBorder)
                Button {
                    processes = listRunningProcesses()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh process list")
            }
            .padding(8)
            .background(.bar)
            Divider()
            Table(filtered, selection: $selection) {
                TableColumn("PID") { p in
                    Text(verbatim: "\(p.pid)").monospacedDigit().foregroundStyle(.secondary)
                }
                .width(min: 50, ideal: 60, max: 80)
                TableColumn("User") { p in
                    Text(verbatim: p.user).lineLimit(1)
                }
                .width(min: 60, ideal: 90, max: 140)
                TableColumn("Name") { p in
                    Text(verbatim: p.name).lineLimit(1)
                }
                .width(min: 100, ideal: 160)
                TableColumn("Arguments") { p in
                    Text(verbatim: p.argv)
                        .font(.system(.callout, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(p.argv)
                }
            }
        }
        .onAppear {
            if processes.isEmpty {
                processes = listRunningProcesses()
            }
        }
    }

    private var filtered: [RunningProcessInfo] {
        let q = filter.lowercased()
        guard !q.isEmpty else { return processes }
        return processes.filter { p in
            String(p.pid).contains(q)
                || p.user.lowercased().contains(q)
                || p.name.lowercased().contains(q)
                || p.argv.lowercased().contains(q)
        }
    }
}

private struct CustomCategoryView: View {
    @ObservedObject var model: PickerModel
    @Binding var selection: TraceTarget.ID?

    var body: some View {
        VStack(spacing: 0) {
            Grid(alignment: .leading, horizontalSpacing: 6, verticalSpacing: 4) {
                GridRow {
                    Text("Name").frame(width: 50, alignment: .trailing)
                    TextField("Display name", text: $model.customDraftName)
                        .textFieldStyle(.roundedBorder)
                }
                GridRow {
                    Text("Path").frame(width: 50, alignment: .trailing)
                    HStack {
                        TextField("/path/to/binary", text: $model.customDraftPath)
                            .textFieldStyle(.roundedBorder)
                        Button("Browse…") { browse() }
                    }
                }
                GridRow {
                    Color.clear.frame(height: 0)
                    HStack {
                        Spacer()
                        Button("Save") { save() }
                            .disabled(model.customDraftName.isEmpty || model.customDraftPath.isEmpty)
                    }
                }
            }
            .padding(8)
            .background(.bar)
            Divider()
            let savedTargets = model.savedCustom.map { $0.asTarget() }
            if savedTargets.isEmpty {
                ContentUnavailableView("No custom targets",
                                       systemImage: "doc.fill",
                                       description: Text("Save a name + path above to trace an arbitrary binary."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(savedTargets, selection: $selection) {
                    TableColumn("Name") { t in
                        HStack {
                            Text(t.label)
                            if model.contains(t) {
                                Label("Added", systemImage: "checkmark")
                                    .labelStyle(.iconOnly)
                                    .foregroundStyle(.secondary)
                                    .help("Already added")
                            }
                        }
                    }
                    TableColumn("Path") { Text($0.detail ?? "").foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle) }
                }
            }
        }
    }

    private func browse() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            model.customDraftPath = url.path
            if model.customDraftName.isEmpty {
                model.customDraftName = url.lastPathComponent
            }
        }
    }

    private func save() {
        model.addCustom(name: model.customDraftName, path: model.customDraftPath)
        model.customDraftName = ""
        model.customDraftPath = ""
    }
}

private struct PickerSheet: View {
    @ObservedObject var model: PickerModel
    var onClose: () -> Void
    @State private var category: PickerCategory = .recommended
    @State private var pickSelection: TraceTarget.ID? = nil
    @State private var pidSelection: Set<pid_t> = []
    @State private var pidProcesses: [RunningProcessInfo] = []

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Add targets").font(.headline)
                Spacer()
                Button("Cancel", action: onClose)
                    .keyboardShortcut(.cancelAction)
                Button("Add", action: addSelected)
                    .keyboardShortcut(.return, modifiers: [.command])
                    .disabled(!canAdd)
            }
            .padding()
            Divider()
            PickerPane(model: model,
                       category: $category,
                       pickSelection: $pickSelection,
                       pidSelection: $pidSelection,
                       pidProcesses: $pidProcesses)
        }
    }

    private var canAdd: Bool {
        switch category {
        case .pids: return !pidSelection.isEmpty
        default:    return resolvedSelection() != nil
        }
    }

    private func addSelected() {
        switch category {
        case .pids:
            for pid in pidSelection {
                guard let p = pidProcesses.first(where: { $0.pid == pid }) else { continue }
                model.add(TraceTarget(
                    id: "pid:\(pid)",
                    kind: .pid(pid),
                    label: "PID \(pid) (\(p.name))",
                    detail: nil,
                    icon: nil
                ))
            }
        default:
            guard let target = resolvedSelection() else { return }
            model.add(target)
        }
        onClose()
    }

    /// Maps the current `pickSelection` ID to a TraceTarget by looking it up
    /// in whatever list the current category renders.
    private func resolvedSelection() -> TraceTarget? {
        guard let id = pickSelection else { return nil }
        switch category {
        case .recommended:
            return model.recommendedTargets().first { $0.id == id }
        case .applications:
            return model.runningApplications.first { $0.id == id }
        case .custom:
            return model.savedCustom.map { $0.asTarget() }.first { $0.id == id }
        case .pids:
            return nil
        }
    }
}

// MARK: - Active list

private struct ActiveListView: View {
    @ObservedObject var model: PickerModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Trace targets")
                    .font(.headline)
                Spacer()
                Text("\(model.active.count) selected")
                    .foregroundStyle(.secondary)
                    .font(.caption)
            }
            if model.active.isEmpty {
                Text("Add targets from the sections below, then press Start.")
                    .foregroundStyle(.secondary)
                    .font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 6)
            } else {
                ForEach(model.active) { target in
                    HStack {
                        Image(systemName: iconName(for: target.kind))
                            .frame(width: 18)
                            .foregroundStyle(.secondary)
                        Text(target.label)
                        if let detail = target.detail {
                            Text(detail)
                                .foregroundStyle(.secondary)
                                .font(.caption)
                        }
                        Spacer()
                        Button {
                            model.remove(target)
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.vertical, 2)
                }
            }
        }
    }

    private func iconName(for kind: TargetKind) -> String {
        switch kind {
        case .recommended, .recommendedByName: return "star.fill"
        case .application: return "app.fill"
        case .pid: return "number"
        case .custom: return "doc.fill"
        }
    }
}

// MARK: - Sections

private struct RecommendedSection: View {
    @ObservedObject var model: PickerModel
    @State private var expanded = true

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(spacing: 0) {
                ForEach(model.recommendedTargets()) { target in
                    let running: Bool = {
                        if case .recommended(let bid) = target.kind {
                            return model.isRunning(bundleID: bid)
                        }
                        return false
                    }()
                    PickerRow(
                        target: target,
                        statusDot: running ? .green : nil,
                        statusText: running ? "running" : "not running",
                        added: model.contains(target),
                        addDisabled: !running,
                        onAdd: { model.add(target) }
                    )
                }
            }
            .padding(.top, 4)
        } label: {
            Text("Recommended").font(.headline)
        }
        .padding(.vertical, 6)
    }
}

private struct ApplicationsSection: View {
    @ObservedObject var model: PickerModel
    @State private var expanded = false
    @State private var search = ""

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(spacing: 0) {
                TextField("Search…", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .padding(.bottom, 4)
                if model.runningApplications.isEmpty {
                    Text("No running applications detected yet.")
                        .foregroundStyle(.secondary)
                        .font(.callout)
                        .padding(.vertical, 6)
                } else {
                    ForEach(filtered) { target in
                        PickerRow(
                            target: target,
                            statusDot: .green,
                            statusText: nil,
                            added: model.contains(target),
                            onAdd: { model.add(target) }
                        )
                    }
                }
            }
            .padding(.top, 4)
        } label: {
            HStack {
                Text("Applications").font(.headline)
                Text("(\(model.runningApplications.count) running)")
                    .foregroundStyle(.secondary)
                    .font(.subheadline)
            }
        }
        .padding(.vertical, 6)
    }

    private var filtered: [TraceTarget] {
        let q = search.lowercased()
        guard !q.isEmpty else { return model.runningApplications }
        return model.runningApplications.filter { $0.label.lowercased().contains(q) }
    }
}

private struct PIDSection: View {
    @ObservedObject var model: PickerModel
    @State private var expanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    TextField("PID", text: $model.pidDraft)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 120)
                    if let name = resolvedName() {
                        Text("→ \(name)")
                            .foregroundStyle(.secondary)
                            .font(.callout)
                    } else if !model.pidDraft.isEmpty && parsedPID() != nil {
                        Text("→ (no such process)")
                            .foregroundStyle(.secondary)
                            .font(.callout)
                    }
                    Spacer()
                    Button("Add") { addPID() }
                        .disabled(parsedPID() == nil || resolvedName() == nil)
                }
            }
            .padding(.top, 4)
        } label: {
            Text("PID").font(.headline)
        }
        .padding(.vertical, 6)
    }

    private func parsedPID() -> pid_t? {
        let trimmed = model.pidDraft.trimmingCharacters(in: .whitespaces)
        guard let n = Int32(trimmed), n > 0 else { return nil }
        return pid_t(n)
    }

    private func resolvedName() -> String? {
        guard let pid = parsedPID() else { return nil }
        return model.resolveProcessName(pid: pid)
    }

    private func addPID() {
        guard let pid = parsedPID(), let name = resolvedName() else { return }
        let target = TraceTarget(
            id: "pid:\(pid)",
            kind: .pid(pid),
            label: "PID \(pid) (\(name))",
            detail: nil,
            icon: nil
        )
        model.add(target)
        model.pidDraft = ""
    }
}

private struct CustomSection: View {
    @ObservedObject var model: PickerModel
    @State private var expanded = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 6) {
                Grid(alignment: .leading, horizontalSpacing: 6, verticalSpacing: 4) {
                    GridRow {
                        Text("Name")
                        TextField("Display name", text: $model.customDraftName)
                            .textFieldStyle(.roundedBorder)
                    }
                    GridRow {
                        Text("Path")
                        HStack {
                            TextField("/path/to/binary", text: $model.customDraftPath)
                                .textFieldStyle(.roundedBorder)
                            Button("Browse…") { browse() }
                        }
                    }
                }
                HStack {
                    Spacer()
                    Button("Save") { save() }
                        .disabled(model.customDraftName.isEmpty || model.customDraftPath.isEmpty)
                }
                if !model.savedCustom.isEmpty {
                    Divider().padding(.vertical, 4)
                    Text("Saved")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    ForEach(model.savedCustom) { stored in
                        let target = stored.asTarget()
                        PickerRow(
                            target: target,
                            statusDot: nil,
                            statusText: nil,
                            added: model.contains(target),
                            onAdd: { model.add(target) },
                            onDelete: { model.deleteCustom(stored) }
                        )
                    }
                }
            }
            .padding(.top, 4)
        } label: {
            HStack {
                Text("Custom").font(.headline)
                Text("(\(model.savedCustom.count) saved)")
                    .foregroundStyle(.secondary)
                    .font(.subheadline)
            }
        }
        .padding(.vertical, 6)
    }

    private func browse() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url {
            model.customDraftPath = url.path
            if model.customDraftName.isEmpty {
                model.customDraftName = url.lastPathComponent
            }
        }
    }

    private func save() {
        model.addCustom(name: model.customDraftName, path: model.customDraftPath)
        model.customDraftName = ""
        model.customDraftPath = ""
    }
}

// MARK: - Row

private struct PickerRow: View {
    let target: TraceTarget
    let statusDot: Color?
    let statusText: String?
    let added: Bool
    var addDisabled: Bool = false
    var onAdd: () -> Void
    var onDelete: (() -> Void)? = nil

    var body: some View {
        HStack {
            if let statusDot = statusDot {
                Circle()
                    .fill(statusDot)
                    .frame(width: 8, height: 8)
            } else {
                Circle()
                    .stroke(Color.secondary.opacity(0.4), lineWidth: 1)
                    .frame(width: 8, height: 8)
            }
            if let icon = target.icon {
                Image(nsImage: icon)
                    .resizable()
                    .frame(width: 18, height: 18)
            }
            Text(target.label)
            if let detail = target.detail {
                Text(detail)
                    .foregroundStyle(.secondary)
                    .font(.caption)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer()
            if let statusText = statusText {
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if added {
                Label("Added", systemImage: "checkmark")
                    .labelStyle(.iconOnly)
                    .foregroundStyle(.green)
            } else {
                Button(action: onAdd) {
                    Label("Add", systemImage: "plus")
                        .labelStyle(.titleAndIcon)
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
                .disabled(addDisabled)
            }
            if let onDelete = onDelete {
                Button(action: onDelete) {
                    Image(systemName: "xmark.circle")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 3)
        .opacity(added ? 0.6 : 1.0)
    }
}
