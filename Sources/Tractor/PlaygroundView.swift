import AppKit
import SwiftUI

// MARK: - View

struct PlaygroundView: View {
    // Persistent across tab switches: the underlying view model and
    // library are singletons so SwiftUI's view teardown when the user
    // switches tabs doesn't kill the running program or lose unsaved
    // edits. View-only state (sheets, alerts) stays @State below.
    @ObservedObject private var library = ScriptLibrary.shared
    @ObservedObject private var model = PlaygroundModel.shared

    @State private var saveAsName: String = ""
    @State private var showSaveAs: Bool = false
    @State private var pendingAction: PendingAction? = nil
    @State private var pendingError: String? = nil
    @State private var streamAutoScroll: Bool = true

    enum PendingAction { case run, switchTo(ScriptLibrary.Script) }
    enum OutputTab: Hashable { case output, logs }

    var body: some View {
        HSplitView {
            sidebar.frame(minWidth: 220, idealWidth: 260, maxWidth: 360)

            VSplitView {
                editorPane.frame(minHeight: 240, idealHeight: 360)
                outputPane.frame(minHeight: 180, idealHeight: 280)
            }
            .frame(minWidth: 480, maxWidth: .infinity, maxHeight: .infinity)
            .layoutPriority(1)
        }
        .onAppear {
            library.reload()
            if model.selectedID == nil { selectFirstAvailable() }
        }
        .onChange(of: model.selectedID) { _, _ in loadSelected() }
        .sheet(isPresented: $showSaveAs) { saveAsSheet }
        .alert("Couldn't save",
               isPresented: Binding(get: { pendingError != nil },
                                    set: { if !$0 { pendingError = nil } })) {
            Button("OK", role: .cancel) { pendingError = nil }
        } message: {
            Text(pendingError ?? "")
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(spacing: 0) {
            List(selection: $model.selectedID) {
                if !library.builtins.isEmpty {
                    Section("Built-in") {
                        ForEach(library.builtins) { s in scriptRow(s).tag(s.id) }
                    }
                }
                if !library.custom.isEmpty {
                    Section("My Scripts") {
                        ForEach(library.custom) { s in
                            scriptRow(s).tag(s.id)
                                .contextMenu {
                                    Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([s.url]) }
                                    Button(role: .destructive) { try? library.deleteUserScript(s) } label: { Text("Delete") }
                                }
                        }
                    }
                } else {
                    Section("My Scripts") {
                        Text("Create one with + below, or save a built-in as a copy.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .listStyle(.sidebar)

            Divider()

            HStack {
                Button { newScript() } label: { Image(systemName: "plus") }
                .buttonStyle(.borderless)
                .help("New script in My Scripts")

                Button {
                    NSWorkspace.shared.activateFileViewerSelecting([ScriptLibrary.customDir])
                } label: {
                    Image(systemName: "folder")
                }
                .help("Reveal user scripts folder")
                .buttonStyle(.borderless)

                Button { library.reload() } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless)
                .help("Reload script list from disk")

                Spacer()

                if model.otherProgramCount > 0 {
                    Text("\(model.otherProgramCount) loaded elsewhere")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
        }
    }

    private func scriptRow(_ s: ScriptLibrary.Script) -> some View {
        HStack(spacing: 6) {
            Image(systemName: s.isBuiltIn ? "doc.text" : "doc.text.fill")
                .foregroundStyle(.secondary)
            Text(s.name).lineLimit(1)
            if model.runningID == s.id {
                Spacer()
                Image(systemName: "circle.fill")
                    .font(.system(size: 6))
                    .foregroundStyle(.green)
            }
        }
    }

    // MARK: - Editor pane

    private var editorPane: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if let err = model.lastError {
                errorBanner(err)
                Divider()
            }
            CodeEditorView(text: $model.editorText, isEditable: true)
                .onChange(of: model.editorText) { _, new in
                    model.dirty = (currentScript.map { library.source(of: $0) } ?? "") != new
                }
        }
    }

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text(message)
                .font(.callout)
                .textSelection(.enabled)
                .lineLimit(4)
            Spacer()
            Button {
                model.lastError = nil
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
            .help("Dismiss")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(Color.red.opacity(0.08))
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            if let s = currentScript {
                HStack(spacing: 4) {
                    Image(systemName: s.isBuiltIn ? "lock.fill" : "pencil")
                        .foregroundStyle(.secondary)
                    Text(s.name).font(.headline)
                    if model.dirty {
                        Circle()
                            .fill(Color.orange)
                            .frame(width: 6, height: 6)
                            .help("Unsaved changes")
                    }
                }
            } else {
                Text("(no script selected)").foregroundStyle(.secondary)
            }

            if model.runningID != nil {
                HStack(spacing: 5) {
                    Circle().fill(Color.green).frame(width: 7, height: 7)
                    Text("running").font(.caption).foregroundStyle(.secondary)
                }
                .help("Program is loaded in the Endpoint Security extension")
            }

            Spacer()

            TextField("args (whitespace-separated; quote strings)",
                      text: $model.argsText)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
                .help(argsPreview)

            if model.runningID != nil {
                Button(role: .destructive) { model.stop() } label: {
                    Label("Stop", systemImage: "stop.fill")
                }
                .keyboardShortcut(".", modifiers: .command)
            } else {
                Button { onRun() } label: {
                    Label("Run", systemImage: "play.fill")
                }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(currentScript == nil)
            }

            Button { onSave() } label: {
                Label("Save", systemImage: "square.and.arrow.down")
            }
            .keyboardShortcut("s", modifiers: .command)
            .disabled(currentScript == nil || !model.dirty)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    private var argsPreview: String {
        let parsed = ShellArgs.parse(model.argsText)
        return parsed.isEmpty ? "args = []" : "args = " + parsed.map { "\"\($0)\"" }.joined(separator: ", ")
    }

    // MARK: - Output pane

    private var outputPane: some View {
        VStack(spacing: 0) {
            outputHeader
            Divider()
            switch model.outputTab {
            case .output:
                PanelsView(panels: model.panels)
            case .logs:
                EmitRecordsTable(records: model.emits, autoScroll: streamAutoScroll)
            }
        }
        .onChange(of: model.outputTab) { _, new in
            // Mark the stream as read when the user lands on it.
            if new == .logs { model.lastSeenLogsCount = model.emits.count }
        }
        .onChange(of: model.runningID) { _, _ in
            // Fresh run wipes the buffer; restart the unread counter so
            // the badge isn't immediately "0 of 0".
            model.lastSeenLogsCount = 0
        }
    }

    private var outputHeader: some View {
        let unseen = max(0, model.emits.count - model.lastSeenLogsCount)
        return HStack(spacing: 10) {
            Picker("", selection: $model.outputTab) {
                Text("Panels").tag(OutputTab.output)
                Text(unseen > 0 && model.outputTab != .logs ? "Stream (\(unseen))" : "Stream")
                    .tag(OutputTab.logs)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 220)

            Spacer()

            switch model.outputTab {
            case .output:
                if !model.panels.isEmpty {
                    Text("\(model.panels.count) panel\(model.panels.count == 1 ? "" : "s")")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            case .logs:
                Text("\(model.emits.count) record\(model.emits.count == 1 ? "" : "s")")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Toggle("Auto-scroll", isOn: $streamAutoScroll)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                Button("Clear") { model.clearEmits() }
                    .controlSize(.small)
                    .disabled(model.emits.isEmpty)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
    }

    // MARK: - Actions

    private var currentScript: ScriptLibrary.Script? {
        guard let id = model.selectedID else { return nil }
        return library.builtins.first(where: { $0.id == id })
            ?? library.custom.first(where: { $0.id == id })
    }

    private func selectFirstAvailable() {
        model.selectedID = library.builtins.first?.id ?? library.custom.first?.id
    }

    private func loadSelected() {
        guard let s = currentScript else { model.editorText = ""; model.dirty = false; return }
        model.editorText = library.source(of: s)
        model.dirty = false
    }

    private func onRun() {
        guard let s = currentScript else { return }
        // Built-in + model.dirty → prompt save-as before running.
        if s.isBuiltIn && model.dirty {
            pendingAction = .run
            saveAsName = s.name + "-copy"
            showSaveAs = true
            return
        }
        // User script with unsaved edits → save to its own file first.
        if !s.isBuiltIn && model.dirty {
            do { _ = try library.saveUserScript(name: s.name, source: model.editorText, overwriting: s.url) }
            catch { pendingError = error.localizedDescription; return }
            model.dirty = false
        }
        let args = ShellArgs.parse(model.argsText)
        model.run(name: s.name, source: model.editorText, args: args, scriptID: s.id)
    }

    private func newScript() {
        let template = """
        // New Tractor probe script.
        // probe(name, fn) subscribes to engine events; emit(channel, obj)
        // streams records to the Stream pane; render(panel, text) draws a
        // live panel. See the built-in scripts for working examples.

        probe("es:notify:exec", (ev) => {
          emit("exec", { process: ev.process, pid: ev.pid });
        });
        """
        // Pick the first free "untitled[-N]" name.
        var name = "untitled"
        var n = 2
        while library.custom.contains(where: { $0.name == name }) {
            name = "untitled-\(n)"
            n += 1
        }
        do {
            let saved = try library.saveUserScript(name: name, source: template)
            model.selectedID = saved.id
        } catch {
            pendingError = error.localizedDescription
        }
    }

    private func onSave() {
        guard let s = currentScript, model.dirty else { return }
        if s.isBuiltIn {
            // Built-in is read-only — prompt save-as.
            saveAsName = s.name + "-copy"
            showSaveAs = true
        } else {
            do { _ = try library.saveUserScript(name: s.name, source: model.editorText, overwriting: s.url) }
            catch { pendingError = error.localizedDescription; return }
            model.dirty = false
        }
    }

    // MARK: - Save-as sheet

    private var saveAsSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Save a copy in My Scripts").font(.headline)
            HStack {
                Text("Name")
                TextField("name", text: $saveAsName)
                    .textFieldStyle(.roundedBorder)
                Text(".js").foregroundStyle(.secondary)
            }
            HStack {
                Spacer()
                Button("Cancel") {
                    showSaveAs = false
                    pendingAction = nil
                }
                Button("Save") {
                    do {
                        let saved = try library.saveUserScript(name: saveAsName, source: model.editorText)
                        model.selectedID = saved.id
                        model.dirty = false
                        showSaveAs = false
                        if case .run = pendingAction {
                            let args = ShellArgs.parse(model.argsText)
                            model.run(name: saved.name, source: model.editorText, args: args, scriptID: saved.id)
                        }
                        pendingAction = nil
                    } catch {
                        pendingError = error.localizedDescription
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(saveAsName.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 360)
    }
}

// MARK: - Panels view

private struct PanelsView: View {
    let panels: [String: String]

    var body: some View {
        let names = panels.keys.sorted()
        if names.isEmpty {
            ContentUnavailableView {
                Label("No render() output yet", systemImage: "rectangle.dashed")
            } description: {
                Text("Scripts call render(panel, text) to draw a live panel here.")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            TabView {
                ForEach(names, id: \.self) { name in
                    ScrollView([.vertical, .horizontal]) {
                        // Hug the text's natural width so each row is
                        // left-aligned at column 0; horizontal scroll
                        // appears only when content exceeds the pane.
                        Text(panels[name] ?? "")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .multilineTextAlignment(.leading)
                            .fixedSize(horizontal: true, vertical: true)
                            .padding(8)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity,
                           alignment: .topLeading)
                    .tabItem { Text(name) }
                }
            }
        }
    }
}

// MARK: - Model

@MainActor
final class PlaygroundModel: ObservableObject {
    /// Process-wide singleton so view teardown on tab switch doesn't kill
    /// the running program or wipe in-progress edits.
    static let shared = PlaygroundModel()

    // Persistent UI state (was @State in the view; moved here so it
    // survives across tab switches).
    @Published var selectedID: String? = nil
    @Published var editorText: String = ""
    @Published var argsText: String = ""
    @Published var dirty: Bool = false
    @Published var outputTab: PlaygroundView.OutputTab = .output
    @Published var lastSeenLogsCount: Int = 0

    @Published private(set) var emits: [EmitRecord] = []
    @Published private(set) var panels: [String: String] = [:]
    @Published private(set) var runningID: String? = nil
    @Published private(set) var runningName: String? = nil
    /// Most recent run/load failure, shown as a banner in the editor pane.
    /// Cleared on the next run attempt or when dismissed.
    @Published var lastError: String? = nil
    @Published private(set) var otherProgramCount: Int = 0

    private var client: ESXPCClient?
    private var loadedProgramName: String?
    private var otherCountTimer: Timer?

    private let maxEmits = 1000

    private init() {
        otherCountTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshOtherCount() }
        }
        refreshOtherCount()
    }

    deinit {
        otherCountTimer?.invalidate()
    }

    func run(name: String, source: String, args: [String], scriptID: String) {
        // Replace any currently-running playground program first. Wait for the
        // teardown to finish so its unload can't race the new load when the
        // program name is reused.
        teardownClient { [weak self] in
            self?.beginRun(name: name, source: source, args: args, scriptID: scriptID)
        }
    }

    private func beginRun(name: String, source: String, args: [String], scriptID: String) {
        emits.removeAll(keepingCapacity: true)
        panels.removeAll()
        lastError = nil

        let c = ESXPCClient()
        c.onEmitRecord = { [weak self] record in
            Task { @MainActor in
                guard let self = self, record.program == name else { return }
                self.appendEmitRecord(record)
            }
        }
        c.onPanel = { [weak self] upd in
            Task { @MainActor in
                guard let self = self, upd.program == name else { return }
                self.panels[upd.panel] = upd.text
            }
        }
        c.onConnectionError = { [weak self] err in
            Task { @MainActor in
                self?.appendSyntheticError("XPC error: \(err.localizedDescription)")
                self?.lastError = "Lost the Endpoint Security connection: \(err.localizedDescription)"
                self?.runningID = nil
                self?.runningName = nil
                self?.loadedProgramName = nil
            }
        }
        client = c
        runningID = scriptID
        runningName = name

        // The availability probe and program compile both block on the sysext
        // (1s / 5s timeouts), so the connection is brought up off the main
        // thread. `client === c` guards against the user stopping mid-load;
        // connection invalidation then unloads anything this client loaded.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let error: String?
            if ESXPCClient.isAvailable() {
                c.start()
                error = c.loadProgram(name: name, source: source, args: args)
                    .map { "Load failed: \($0)" }
            } else {
                error = "Endpoint Security extension isn't active. Run `sudo tractor activate endpoint-security` first."
            }
            Task { @MainActor in
                guard let self = self, self.client === c else { return }
                if let error = error {
                    self.appendSyntheticError(error)
                    self.lastError = error
                    c.stopAsync()
                    self.client = nil
                    self.runningID = nil
                    self.runningName = nil
                    return
                }
                self.loadedProgramName = name
            }
        }
    }

    func stop() {
        teardownClient {}
    }

    /// Unloads the running program and tears down the client without blocking
    /// the main thread — unload and the final event drain each wait on the
    /// sysext for up to a couple of seconds.
    private func teardownClient(completion: @escaping () -> Void) {
        guard let c = client else {
            completion()
            return
        }
        let name = loadedProgramName
        client = nil
        loadedProgramName = nil
        runningID = nil
        runningName = nil
        DispatchQueue.global(qos: .userInitiated).async {
            if let name = name { c.unloadProgram(name: name) }
            DispatchQueue.main.async {
                c.stopAsync(completion: completion)
            }
        }
    }

    func clearEmits() {
        emits.removeAll(keepingCapacity: true)
    }

    private func appendEmitRecord(_ record: EmitRecord) {
        emits.append(record)
        if emits.count > maxEmits {
            emits.removeFirst(emits.count - maxEmits)
        }
    }

    private func appendSyntheticError(_ msg: String) {
        let json = (try? JSONSerialization.data(withJSONObject: ["line": msg]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        emits.append(EmitRecord(time: Date(), program: runningName ?? "-",
                                channel: "tractor:error",
                                payloadJSON: json))
    }

    private func refreshOtherCount() {
        let mineName = loadedProgramName
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let progs = ESXPCClient.fetchPrograms()
            let mine = mineName.map { Set([$0]) } ?? Set<String>()
            let others = progs.filter { !mine.contains($0.name) }.count
            Task { @MainActor in self?.otherProgramCount = others }
        }
    }
}
