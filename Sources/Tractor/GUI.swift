import AppKit
import SwiftUI

enum TractorGUIEntry {
    static func run() -> Never {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.mainMenu = buildMainMenu()
        let delegate = AppDelegate()
        app.delegate = delegate
        app.activate(ignoringOtherApps: true)
        app.run()
        exit(0)
    }

    private static func buildMainMenu() -> NSMenu {
        let mainMenu = NSMenu()
        let appName = ProcessInfo.processInfo.processName

        // App menu
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "About \(appName)",
                        action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
                        keyEquivalent: "")
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
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        // View menu
        let viewMenuItem = NSMenuItem()
        let viewMenu = NSMenu(title: "View")
        let hideExitedItem = NSMenuItem(title: "Hide Exited Processes",
                                        action: #selector(AppDelegate.toggleHideExited(_:)),
                                        keyEquivalent: "")
        viewMenu.addItem(hideExitedItem)
        viewMenuItem.submenu = viewMenu
        mainMenu.addItem(viewMenuItem)

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
    @objc func toggleHideExited(_ sender: NSMenuItem) {
        AppPrefs.shared.hideExited.toggle()
    }

    @MainActor
    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(toggleHideExited(_:)) {
            menuItem.state = AppPrefs.shared.hideExited ? .on : .off
            return true
        }
        return true
    }
}

// MARK: - Target model

enum TargetKind: Hashable {
    case recommended(bundleID: String)
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

@MainActor
final class TraceRunner: ObservableObject {
    @Published private(set) var isRunning = false
    /// Whether events are being persisted to the SQLite trace DB. Independent
    /// of tracing — tracing is always on once started; recording is the
    /// user-controlled "save to disk" switch, gated by SQLiteLog.isEnabled.
    @Published var isRecording = false {
        didSet {
            session?.setSQLiteRecordingEnabled(isRecording)
            if isRecording && !oldValue {
                session?.resetSQLiteRecordedCount()
            }
        }
    }

    /// Number of events written to the trace DB during the current recording.
    /// Polled by the GUI footer via a TimelineView tick.
    var recordedEventCount: Int { session?.sqliteRecordedCount ?? 0 }
    @Published private(set) var lastMessage: String?
    let live = LiveModel()

    private var session: TraceSession?
    private var sink: LiveSink?
    private var appliedPids: Set<pid_t> = []
    private var appliedPaths: Set<String> = []

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
        let groups = buildGroups(active: active, runningByBundleID: runningByBundleID)
        for target in active {
            switch target.kind {
            case .application(let bid), .recommended(let bid):
                if let pid = runningByBundleID[bid] { pids.append(pid) }
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
            let m = self?.live
            DispatchQueue.main.async {
                m?.handleBytesUpdate(pid: pid, host: host, port: port,
                                      bytesOut: bytesOut, bytesIn: bytesIn, flowID: flowID)
            }
        }
        session.onConnectionClosed = { [weak self] pid, host, port, flowID in
            let m = self?.live
            DispatchQueue.main.async {
                m?.handleConnectionClosed(pid: pid, host: host, port: port, flowID: flowID)
            }
        }

        let roots = TraceRoots(names: [], pids: pids, paths: paths)
        let options = TraceOptions(logToSQLite: true)

        do {
            try session.start(roots: roots, options: options)
            session.setSQLiteRecordingEnabled(isRecording)
            session.seedSinkFromTree()
            self.session = session
            self.sink = sink
            self.appliedPids = Set(pids)
            self.appliedPaths = Set(paths)
            self.isRunning = true
            self.lastMessage = nil
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
        for target in active {
            switch target.kind {
            case .application(let bid), .recommended(let bid):
                if let pid = runningByBundleID[bid] { pids.insert(pid) }
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
        if !newPids.isEmpty {
            session.attachExisting(roots: Array(newPids))
            appliedPids.formUnion(newPids)
        }
        if !newPaths.isEmpty {
            session.attachExisting(paths: Array(newPaths))
            appliedPaths.formUnion(newPaths)
        }
        session.setTrackerPatterns(names: [], paths: Array(appliedPaths))
    }

    private func buildGroups(active: [TraceTarget], runningByBundleID: [String: pid_t]) -> [TraceGroup] {
        active.map { target in
            let kind: TraceGroup.Kind
            switch target.kind {
            case .application(let bid), .recommended(let bid):
                if let pid = runningByBundleID[bid] { kind = .pid(pid) }
                else { kind = .name(target.label) }
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
    let bundleID: String
}

private let recommendedEntries: [RecommendedEntry] = [
    .init(name: "Cursor", bundleID: "com.todesktop.230313mzl4w4u92"),
    .init(name: "Claude", bundleID: "com.anthropic.claudefordesktop"),
    .init(name: "VS Code", bundleID: "com.microsoft.VSCode"),
    .init(name: "Zed", bundleID: "dev.zed.Zed"),
    .init(name: "Windsurf", bundleID: "com.exafunction.windsurf"),
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
            let icon = iconForBundleID(entry.bundleID)
            return TraceTarget(
                id: "rec:\(entry.bundleID)",
                kind: .recommended(bundleID: entry.bundleID),
                label: entry.name,
                detail: entry.bundleID,
                icon: icon
            )
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
    enum Tab: Hashable, CaseIterable { case trace, setup }
    @State private var selection: Tab = .trace
    @State private var filter: String = ""
    @ObservedObject private var prefs = AppPrefs.shared

    var body: some View {
        Group {
            switch selection {
            case .trace: RootView(filter: filter)
            case .setup: SetupView()
            }
        }
        .searchable(text: $filter, prompt: "Filter processes")
        .frame(minWidth: 720, minHeight: 580)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("View", selection: $selection) {
                    Text("Trace").tag(Tab.trace)
                    Text("Setup").tag(Tab.setup)
                }
                .pickerStyle(.segmented)
            }
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

private struct RootView: View {
    let filter: String
    @StateObject private var model = PickerModel()
    @StateObject private var runner = TraceRunner()
    @ObservedObject private var prefs = AppPrefs.shared
    @State private var pickerSheetShown = false
    @State private var selection: ProcessTableRow.ID? = nil
    @State private var detailTab: LiveView.DetailTab = .files

    var body: some View {
        VStack(spacing: 0) {
            LiveView(model: runner.live,
                     filter: filter,
                     selection: $selection,
                     onAddTarget: { pickerSheetShown = true },
                     onDeleteGroup: { groupID in
                        if let target = model.active.first(where: { $0.id == groupID }) {
                            model.remove(target)
                        }
                     })
            Divider()
            footer
        }
        .inspector(isPresented: $prefs.inspectorShown) {
            DetailPane(model: runner.live, selection: selectedPid(from: selection), tab: $detailTab)
                .inspectorColumnWidth(min: 320, ideal: 400, max: 700)
        }
        .frame(minWidth: 720, minHeight: 520)
        .sheet(isPresented: $pickerSheetShown) {
            PickerSheet(model: model) {
                pickerSheetShown = false
            }
            .frame(minWidth: 640, minHeight: 560)
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
        HStack {
            TimelineView(.periodic(from: .now, by: 1.0)) { _ in
                HStack(spacing: 6) {
                    if runner.isRecording {
                        Circle().fill(Color.red).frame(width: 8, height: 8)
                        Text("Recording — \(runner.recordedEventCount) events, \(runner.live.processes.count) processes, \(model.active.count) target\(model.active.count == 1 ? "" : "s")")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    } else if runner.isRunning {
                        Text("Tracing — \(runner.live.processes.count) processes, \(model.active.count) target\(model.active.count == 1 ? "" : "s")")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    } else if let msg = runner.lastMessage {
                        Text(msg).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            Spacer()
            RecordButton(isRecording: runner.isRecording) {
                runner.isRecording.toggle()
            }
            .keyboardShortcut(.return, modifiers: [.command])
        }
        .padding()
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
                case .pids:         PIDsCategoryView(model: model)
                case .custom:       CustomCategoryView(model: model, selection: $pickSelection)
                }
            }
            .frame(minWidth: 380, idealWidth: 520)
        }
        .onChange(of: category) { _, _ in pickSelection = nil }
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
        if case .recommended(let bid) = t.kind { running = model.isRunning(bundleID: bid) } else { running = false }
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
    @ObservedObject var model: PickerModel

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                TextField("PID", text: $model.pidDraft)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 120)
                if let name = resolvedName() {
                    Text("→ \(name)")
                        .foregroundStyle(.secondary).font(.callout)
                } else if !model.pidDraft.isEmpty && parsedPID() != nil {
                    Text("→ (no such process)")
                        .foregroundStyle(.secondary).font(.callout)
                }
                Spacer()
                Button("Add") { addPID() }
                    .disabled(parsedPID() == nil || resolvedName() == nil)
            }
            .padding(8)
            .background(.bar)
            Divider()
            let pidTargets = model.active.filter { if case .pid = $0.kind { return true } else { return false } }
            if pidTargets.isEmpty {
                ContentUnavailableView("No PID targets",
                                       systemImage: "number",
                                       description: Text("Enter a running PID above to trace it and all its descendants."))
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Table(pidTargets) {
                    TableColumn("Target") { Text($0.label) }
                    TableColumn("") { t in
                        Button(role: .destructive) { model.remove(t) } label: {
                            Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                    .width(40)
                }
            }
        }
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

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Add targets").font(.headline)
                Spacer()
                Button("Cancel", action: onClose)
                    .keyboardShortcut(.cancelAction)
                Button("Add", action: addSelected)
                    .keyboardShortcut(.return, modifiers: [.command])
                    .disabled(resolvedSelection() == nil)
            }
            .padding()
            Divider()
            PickerPane(model: model, category: $category, pickSelection: $pickSelection)
        }
    }

    private func addSelected() {
        guard let target = resolvedSelection() else { return }
        model.add(target)
        onClose()
    }

    /// Maps the current `pickSelection` ID to a TraceTarget by looking it up
    /// in whatever list the current category renders. Returns nil when the
    /// category has no row-based selection (PIDs) or when nothing is selected.
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
        case .recommended: return "star.fill"
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
