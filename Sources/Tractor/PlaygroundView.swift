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
                        Text("Save a built-in as a copy to start collecting your own.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .listStyle(.sidebar)

            Divider()

            HStack {
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
            CodeEditorView(text: $model.editorText, isEditable: true)
                .onChange(of: model.editorText) { _, new in
                    model.dirty = (currentScript.map { library.source(of: $0) } ?? "") != new
                }
        }
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
        let unseen = max(0, model.emits.count - model.lastSeenLogsCount)
        return TabView(selection: $model.outputTab) {
            PanelsView(panels: model.panels)
                .tabItem { Label("Output", systemImage: "rectangle.split.2x1") }
                .tag(OutputTab.output)

            StreamView(records: model.emits, onClear: { model.clearEmits() })
                .tabItem { Label("Logs", systemImage: "list.bullet") }
                .badge(unseen)
                .tag(OutputTab.logs)
        }
        .padding(8)
        .onChange(of: model.outputTab) { _, new in
            // Mark logs as read when the user lands on the Logs tab.
            if new == .logs { model.lastSeenLogsCount = model.emits.count }
        }
        .onChange(of: model.runningID) { _, _ in
            // Fresh run wipes the buffer; restart the unread counter so
            // the badge isn't immediately "0 of 0".
            model.lastSeenLogsCount = 0
        }
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

// MARK: - Stream view (emits + log)

private struct StreamView: View {
    let records: [EmitRecord]
    let onClear: () -> Void

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss.SSS"; return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Emit stream").font(.caption).foregroundStyle(.secondary).textCase(.uppercase)
                Text("\(records.count)").font(.caption2).foregroundStyle(.secondary)
                Spacer()
                Button("Clear") { onClear() }.controlSize(.small)
            }
            .padding(.horizontal, 4).padding(.vertical, 4)

            Divider()

            ScrollViewReader { proxy in
                Table(records) {
                    TableColumn("Time") { r in
                        Text(Self.timeFormatter.string(from: r.time))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 90, ideal: 100, max: 110)

                    TableColumn("Channel") { r in
                        Text(r.channel).font(.system(.caption, design: .monospaced))
                    }
                    .width(min: 100, ideal: 140, max: 200)

                    TableColumn("Payload") { r in
                        Text(r.payloadJSON)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(r.payloadJSON)
                            .textSelection(.enabled)
                    }
                }
                .onChange(of: records.count) { _, _ in
                    if let last = records.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }
}

// MARK: - Panels view

private struct PanelsView: View {
    let panels: [String: String]

    var body: some View {
        let names = panels.keys.sorted()
        if names.isEmpty {
            VStack {
                Spacer()
                Text("No render() output yet.")
                    .foregroundStyle(.secondary)
                Text("Scripts use render(panelName, text) to update a fixed panel.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
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
        guard ESXPCClient.isAvailable() else {
            appendSyntheticError("Endpoint Security extension isn't active. Run `sudo tractor activate endpoint-security` first.")
            return
        }
        // Replace any currently-running playground program first.
        stop()
        emits.removeAll(keepingCapacity: true)
        panels.removeAll()

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
                self?.runningID = nil
                self?.runningName = nil
                self?.loadedProgramName = nil
            }
        }
        c.start()
        client = c

        if let err = c.loadProgram(name: name, source: source, args: args) {
            appendSyntheticError("Load failed: \(err)")
            c.stop()
            client = nil
            return
        }
        loadedProgramName = name
        runningID = scriptID
        runningName = name
    }

    func stop() {
        if let name = loadedProgramName {
            client?.unloadProgram(name: name)
        }
        client?.stop()
        client = nil
        loadedProgramName = nil
        runningID = nil
        runningName = nil
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
        emits.append(EmitRecord(time: Date(), program: runningName ?? "-",
                                channel: "tractor:error",
                                payloadJSON: "{\"line\":\"\(msg)\"}"))
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
