import SwiftUI

/// What gets persisted to the SQLite trace DB for a given trace group.
/// Per-event-type toggles. Persisted in UserDefaults via RecordOptionsStore.
struct RecordOptions: Codable, Hashable {
    var exec: Bool = true
    var exit: Bool = true
    var fileRead: Bool = false
    var fileWrite: Bool = true
    var fileCreate: Bool = true
    var fileDelete: Bool = true
    var fileRename: Bool = true
    var network: Bool = true
    var http: Bool = true
}

/// Persists default RecordOptions + per-group overrides in UserDefaults.
private final class RecordOptionsStore {
    private let defaults = UserDefaults.standard
    private let defaultKey = "tractor.gui.recordOptions.default.v1"
    private let perGroupKey = "tractor.gui.recordOptions.perGroup.v1"

    func loadDefault() -> RecordOptions {
        guard let data = defaults.data(forKey: defaultKey),
              let opts = try? JSONDecoder().decode(RecordOptions.self, from: data)
        else { return RecordOptions() }
        return opts
    }

    func saveDefault(_ opts: RecordOptions) {
        if let data = try? JSONEncoder().encode(opts) {
            defaults.set(data, forKey: defaultKey)
        }
    }

    func loadPerGroup() -> [String: RecordOptions] {
        guard let data = defaults.data(forKey: perGroupKey),
              let map = try? JSONDecoder().decode([String: RecordOptions].self, from: data)
        else { return [:] }
        return map
    }

    func savePerGroup(_ map: [String: RecordOptions]) {
        if let data = try? JSONEncoder().encode(map) {
            defaults.set(data, forKey: perGroupKey)
        }
    }
}

/// Process-list-wide UI preferences. Singleton so AppKit menu items and
/// SwiftUI views share the same source of truth.
@MainActor
final class AppPrefs: ObservableObject {
    static let shared = AppPrefs()
    static let hideExitedAfter: TimeInterval = 3.0

    @Published var hideExited: Bool = true
    @Published var inspectorShown: Bool = true

    /// Default record options applied when a new group is added or when
    /// the user has no per-group override for that group's ID.
    @Published var defaultRecordOptions: RecordOptions {
        didSet { recordOptionsStore.saveDefault(defaultRecordOptions) }
    }
    /// Per-group overrides keyed by TraceGroup.id.
    @Published var perGroupRecordOptions: [String: RecordOptions] {
        didSet { recordOptionsStore.savePerGroup(perGroupRecordOptions) }
    }

    private let recordOptionsStore = RecordOptionsStore()

    private init() {
        let store = RecordOptionsStore()
        self.defaultRecordOptions = store.loadDefault()
        self.perGroupRecordOptions = store.loadPerGroup()
    }

    /// Effective options for the given group id — per-group override if present,
    /// otherwise the current default.
    func effectiveRecordOptions(for groupID: String?) -> RecordOptions {
        if let id = groupID, let opts = perGroupRecordOptions[id] { return opts }
        return defaultRecordOptions
    }

    /// Returns a Binding that reads/writes a group's options (or the default
    /// when groupID is nil), automatically materialising a per-group entry on
    /// first write.
    func recordOptionsBinding(for groupID: String?) -> Binding<RecordOptions> {
        if let id = groupID {
            return Binding(
                get: { self.perGroupRecordOptions[id] ?? self.defaultRecordOptions },
                set: { self.perGroupRecordOptions[id] = $0 }
            )
        }
        return Binding(
            get: { self.defaultRecordOptions },
            set: { self.defaultRecordOptions = $0 }
        )
    }
}

struct LiveView: View {
    @ObservedObject var model: LiveModel
    @ObservedObject private var prefs = AppPrefs.shared
    let filter: String
    @Binding var selection: ProcessTableRow.ID?
    var onAddTarget: () -> Void
    var onDeleteGroup: (String) -> Void

    enum DetailTab: Hashable { case files, connections }

    var body: some View {
        // .periodic ticks once per second so exited processes disappear
        // after AppPrefs.hideExitedAfter even when no events are arriving.
        TimelineView(.periodic(from: .now, by: 1.0)) { context in
            VStack(spacing: 0) {
                ProcessTableView(model: model, now: context.date, hideExited: prefs.hideExited, filter: filter, selection: $selection)
                    .onDeleteCommand {
                        // Top-level group row ids look like "g:<group_id>" with
                        // no embedded "/" (process rows are paths with slashes).
                        if let id = selection, id.hasPrefix("g:"), !id.contains("/") {
                            let groupID = String(id.dropFirst(2))
                            onDeleteGroup(groupID)
                            selection = nil
                        }
                    }
                Divider()
                HStack {
                    Button(action: onAddTarget) {
                        Label("Add Target", systemImage: "plus")
                            .padding(.horizontal, 12)
                            .padding(.vertical, 2)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.regular)
                    Spacer()
                }
                .padding(.vertical, 8)
                .padding(.horizontal, 8)
                .background(.bar)
            }
        }
    }
}

/// Extracts a pid_t from a ProcessTableRow.ID. The id is a path like
/// "g:rec:foo/1234/5678" or "p/1234"; the last "/"-separated component is the
/// row's own pid (when it's a process row) or the group label (returns nil).
func selectedPid(from id: ProcessTableRow.ID?) -> pid_t? {
    guard let id = id, let last = id.split(separator: "/").last else { return nil }
    return pid_t(last)
}

// MARK: - Hierarchical row model

struct ProcessTableRow: Identifiable, Hashable {
    enum Kind: Hashable {
        case group(String)        // group id
        case process(pid_t)
    }
    let id: String                // "g:<group_id>" or "p:<pid>"
    let kind: Kind
    let name: String              // process name or group label
    let pidLabel: String          // "1234" for processes, "" for groups
    let fileOpCount: Int
    let connectionCount: Int
    let exited: Bool
    let exitStatus: Int32?
    let isGroup: Bool
    let placeholder: Bool         // empty-group "(waiting for matches…)" row
    let children: [ProcessTableRow]?

    /// Returns nil when this process should be hidden (exited > hideExitedAfter ago
    /// AND has no still-visible descendants).
    ///
    /// `parentID` participates in the row's id so the same pid appearing under
    /// two different groups (or under two different parents) produces two
    /// distinct rows. Otherwise SwiftUI Table treats them as the same row and
    /// selecting one highlights both.
    @MainActor
    static func process(_ pid: pid_t, model: LiveModel, now: Date, hideExited: Bool, filter: String, parentID: String) -> ProcessTableRow? {
        let id = "\(parentID)/\(pid)"
        let node = model.processes[pid]
        let kids = model.sortedChildren(pid).compactMap {
            process($0, model: model, now: now, hideExited: hideExited, filter: filter, parentID: id)
        }
        if hideExited, let exitedAt = node?.exitedAt,
           now.timeIntervalSince(exitedAt) > AppPrefs.hideExitedAfter,
           kids.isEmpty {
            return nil
        }
        if !filter.isEmpty {
            // Keep this row only if it matches OR has a (visible) matching descendant.
            let selfMatches = node.map {
                $0.name.localizedCaseInsensitiveContains(filter) ||
                $0.argv.localizedCaseInsensitiveContains(filter)
            } ?? false
            if !selfMatches && kids.isEmpty { return nil }
        }
        return ProcessTableRow(
            id: id,
            kind: .process(pid),
            name: node?.name ?? "pid \(pid)",
            pidLabel: "\(pid)",
            fileOpCount: node?.fileOpCount ?? 0,
            connectionCount: node?.connectionCount ?? 0,
            exited: node?.exitStatus != nil,
            exitStatus: node?.exitStatus,
            isGroup: false,
            placeholder: false,
            children: kids.isEmpty ? nil : kids
        )
    }

    static func emptyGroupPlaceholder(groupID: String) -> ProcessTableRow {
        ProcessTableRow(
            id: "g:\(groupID):empty",
            kind: .process(0),
            name: "(waiting for matches…)",
            pidLabel: "",
            fileOpCount: 0, connectionCount: 0,
            exited: false, exitStatus: nil,
            isGroup: false, placeholder: true,
            children: nil
        )
    }

    @MainActor
    static func group(_ group: TraceGroup, model: LiveModel, now: Date, hideExited: Bool, filter: String) -> ProcessTableRow {
        let groupRowID = "g:\(group.id)"
        let roots = model.rootsForGroup(group.id)
        let kidRows = roots.compactMap {
            process($0, model: model, now: now, hideExited: hideExited, filter: filter, parentID: groupRowID)
        }
        let kids = kidRows.isEmpty
            ? [emptyGroupPlaceholder(groupID: group.id)]
            : kidRows
        return ProcessTableRow(
            id: groupRowID,
            kind: .group(group.id),
            name: group.label,
            pidLabel: kidRows.isEmpty ? "" : "\(kidRows.count)",
            fileOpCount: 0, connectionCount: 0,
            exited: false, exitStatus: nil,
            isGroup: true, placeholder: false,
            children: kids
        )
    }
}

extension LiveModel {
    func buildRows(now: Date, hideExited: Bool, filter: String) -> [ProcessTableRow] {
        if groups.isEmpty {
            return sortedRoots().compactMap {
                ProcessTableRow.process($0, model: self, now: now, hideExited: hideExited, filter: filter, parentID: "p")
            }
        }
        return groups.map {
            ProcessTableRow.group($0, model: self, now: now, hideExited: hideExited, filter: filter)
        }
    }
}

/// A flattened tree row used to drive the non-hierarchical Table. Carries the
/// row's tree depth + whether it has children so we can render an indent and
/// a manual chevron. Going flat (instead of using SwiftUI Table's hierarchical
/// init) gives us "expanded by default" — new rows are visible immediately
/// without needing to seed Table's internal disclosure state.
struct FlatProcessRow: Identifiable, Hashable {
    let row: ProcessTableRow
    let depth: Int
    let hasChildren: Bool
    var id: ProcessTableRow.ID { row.id }
}

/// Recursively flatten the row tree, skipping any subtree whose root is in
/// `collapsed`. New rows that appear later are absent from `collapsed`, so
/// they're rendered fully expanded by default.
func flattenRows(_ rows: [ProcessTableRow], depth: Int = 0, collapsed: Set<ProcessTableRow.ID>) -> [FlatProcessRow] {
    var out: [FlatProcessRow] = []
    for r in rows {
        let kids = r.children ?? []
        out.append(FlatProcessRow(row: r, depth: depth, hasChildren: !kids.isEmpty))
        if !kids.isEmpty && !collapsed.contains(r.id) {
            out.append(contentsOf: flattenRows(kids, depth: depth + 1, collapsed: collapsed))
        }
    }
    return out
}

// MARK: - Table

private struct ProcessTableView: View {
    @ObservedObject var model: LiveModel
    let now: Date
    let hideExited: Bool
    let filter: String
    @Binding var selection: ProcessTableRow.ID?
    @State private var collapsed: Set<ProcessTableRow.ID> = []

    var body: some View {
        let flat = flattenRows(model.buildRows(now: now, hideExited: hideExited, filter: filter), collapsed: collapsed)
        Table(flat, selection: $selection) {
            TableColumn("Process") { entry in
                HStack(spacing: 4) {
                    Spacer().frame(width: CGFloat(entry.depth) * 14)
                    if entry.hasChildren {
                        Button {
                            if collapsed.contains(entry.id) {
                                collapsed.remove(entry.id)
                            } else {
                                collapsed.insert(entry.id)
                            }
                        } label: {
                            Image(systemName: collapsed.contains(entry.id) ? "chevron.right" : "chevron.down")
                                .font(.system(size: 9, weight: .semibold))
                                .foregroundStyle(.secondary)
                                .frame(width: 12)
                        }
                        .buttonStyle(.plain)
                    } else {
                        Spacer().frame(width: 12)
                    }
                    if entry.row.isGroup {
                        Image(systemName: "folder").foregroundStyle(.secondary)
                    } else if entry.row.placeholder {
                        EmptyView()
                    } else {
                        Image(systemName: entry.row.exited ? "circle" : "circle.fill")
                            .font(.system(size: 6))
                            .foregroundStyle(entry.row.exited ? Color.secondary : Color.green)
                    }
                    Text(entry.row.name)
                        .font(entry.row.isGroup ? .body.weight(.semibold) : .body)
                        .foregroundStyle(entry.row.placeholder ? .secondary : .primary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .width(min: 160)
            TableColumn("PID") { entry in
                Text(verbatim: entry.row.pidLabel).foregroundStyle(.secondary)
            }
            .width(min: 50, ideal: 60, max: 80)
            TableColumn("Disk") { entry in
                Text(verbatim: entry.row.isGroup || entry.row.placeholder ? "" : "\(entry.row.fileOpCount)")
                    .foregroundStyle(.secondary)
            }
            .width(min: 50, ideal: 60, max: 80)
            TableColumn("Network") { entry in
                Text(verbatim: entry.row.isGroup || entry.row.placeholder ? "" : "\(entry.row.connectionCount)")
                    .foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 80, max: 110)
            TableColumn("Status") { entry in
                if entry.row.isGroup || entry.row.placeholder {
                    Text("").foregroundStyle(.secondary)
                } else if let code = entry.row.exitStatus {
                    Text("exited \(code)").foregroundStyle(.secondary)
                } else {
                    Text("running").foregroundStyle(.secondary)
                }
            }
            .width(min: 70, ideal: 80, max: 110)
        }
    }
}

// MARK: - Detail pane

struct DetailPane: View {
    @ObservedObject var model: LiveModel
    /// Raw selection id from the process tree — either "p"-prefixed path for
    /// a process row, "g:<group_id>" for a group row, or nil for no selection.
    let selectionID: ProcessTableRow.ID?
    @Binding var tab: LiveView.DetailTab
    @State private var cwd: String = ""
    @State private var args: [String] = []
    @State private var env: [(key: String, value: String)] = []
    @State private var argsExpanded: Bool = true
    @State private var envExpanded: Bool = false

    private var selectedPid: pid_t? {
        guard let id = selectionID, !id.hasPrefix("g:"),
              let last = id.split(separator: "/").last else { return nil }
        return pid_t(last)
    }

    /// Group id when a group row is selected, "" when no selection.
    /// nil when a process row is selected.
    private var groupSelection: String? {
        guard let id = selectionID else { return "" }   // no selection → default
        guard id.hasPrefix("g:") else { return nil }    // process selection
        return String(id.dropFirst(2))
    }

    var body: some View {
        contentView
            .onAppear { fetchProcessDetails(for: selectedPid) }
            .onChange(of: selectionID) { _, _ in fetchProcessDetails(for: selectedPid) }
            .chromeStyle()
    }

    @ViewBuilder
    private var contentView: some View {
        if let pid = selectedPid, let node = model.processes[pid] {
            processDetailView(pid: pid, node: node)
        } else if let groupID = groupSelection {
            recordOptionsView(groupID: groupID)
        } else {
            ContentUnavailableView("Select a process", systemImage: "scope")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    @ViewBuilder
    private func processDetailView(pid: pid_t, node: ProcessNode) -> some View {
        VStack(spacing: 0) {
            DetailHeader(node: node)
            Divider()
            VSplitView {
                processInfoScroll
                    .frame(minHeight: 120, idealHeight: 220)
                processActivityPane(pid: pid)
                    .frame(minHeight: 140)
            }
        }
    }

    @ViewBuilder
    private var processInfoScroll: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                LabeledContent {
                    Text(verbatim: cwd.isEmpty ? "—" : cwd)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(cwd)
                        .frame(maxWidth: .infinity, alignment: .leading)
                } label: {
                    Text("Working Dir")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                DisclosureGroup(isExpanded: $argsExpanded) {
                    argsContent.padding(.top, 4)
                } label: {
                    sectionLabel("Arguments", count: args.count)
                }
                DisclosureGroup(isExpanded: $envExpanded) {
                    envContent.padding(.top, 4)
                } label: {
                    sectionLabel("Environment", count: env.count)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 12)
        }
    }

    @ViewBuilder
    private func processActivityPane(pid: pid_t) -> some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                Text("Files (\(model.fileStats[pid]?.count ?? 0))").tag(LiveView.DetailTab.files)
                Text("Connections (\(model.connections[pid]?.count ?? 0))").tag(LiveView.DetailTab.connections)
            }
            .pickerStyle(.segmented)
            .padding(8)
            Divider()
            switch tab {
            case .files:
                FilesTable(byPath: model.fileStats[pid] ?? [:])
            case .connections:
                ConnectionsTable(byFlow: model.connections[pid] ?? [:])
            }
        }
    }

    @ViewBuilder
    private func recordOptionsView(groupID: String) -> some View {
        let isDefault = groupID.isEmpty
        let group = isDefault ? nil : model.groups.first(where: { $0.id == groupID })
        let title = isDefault ? "Default Record Options" : (group?.label ?? "Default Record Options")
        let subtitle: String? = isDefault
            ? "Applied to new categories until you override them."
            : "Per-category record options."
        let hasOverride = !isDefault && AppPrefs.shared.perGroupRecordOptions[groupID] != nil
        RecordOptionsEditor(
            title: title,
            subtitle: subtitle,
            options: AppPrefs.shared.recordOptionsBinding(for: isDefault ? nil : groupID),
            canResetToDefault: hasOverride,
            onResetToDefault: isDefault ? nil : {
                AppPrefs.shared.perGroupRecordOptions[groupID] = nil
            }
        )
    }

    @ViewBuilder
    private func sectionLabel(_ title: String, count: Int) -> some View {
        HStack(spacing: 6) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            Text(verbatim: "\(count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(Color(NSColor.tertiaryLabelColor).opacity(0.25),
                            in: Capsule())
        }
    }

    @ViewBuilder
    private var argsContent: some View {
        if args.isEmpty {
            Text(verbatim: "—").foregroundStyle(.secondary).font(.callout)
        } else {
            VStack(alignment: .leading, spacing: 1) {
                ForEach(Array(args.enumerated()), id: \.offset) { idx, arg in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(verbatim: "\(idx)")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .frame(width: 22, alignment: .trailing)
                        Text(verbatim: arg)
                            .font(.system(.callout, design: .monospaced))
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .help(arg)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var envContent: some View {
        if env.isEmpty {
            Text(verbatim: "—").foregroundStyle(.secondary).font(.callout)
        } else {
            VStack(alignment: .leading, spacing: 1) {
                ForEach(Array(env.enumerated()), id: \.offset) { _, pair in
                    HStack(spacing: 0) {
                        Text(verbatim: pair.key)
                            .font(.system(.caption, design: .monospaced).weight(.semibold))
                        Text(verbatim: pair.key.isEmpty ? "" : "=")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.tertiary)
                        Text(verbatim: pair.value)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(pair.value)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    private func _placeholder_recordOptionsEditor() {}
    // (RecordOptionsEditor is defined below at file scope.)

    private func fetchProcessDetails(for pid: pid_t?) {
        guard let pid = pid else {
            cwd = ""; args = []; env = []
            return
        }
        cwd = getProcessCwd(pid) ?? ""
        args = getProcessArgs(pid)
        let envLines = getProcessEnv(pid)
        env = envLines.map { line in
            if let eq = line.firstIndex(of: "=") {
                return (String(line[..<eq]), String(line[line.index(after: eq)...]))
            }
            return (line, "")
        }
    }
}

/// Inspector outer chrome: inner rounded card with separator border, padded
/// from a window-tone background that has a square top-right corner so the
/// inspector meets the toolbar at a hard 90°.
private extension View {
    func chromeStyle() -> some View {
        self
            .background(Color(NSColor.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(Color(NSColor.separatorColor).opacity(0.6), lineWidth: 1)
            )
            .padding(8)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(
                UnevenRoundedRectangle(
                    topLeadingRadius: 0,
                    bottomLeadingRadius: 0,
                    bottomTrailingRadius: 10,
                    topTrailingRadius: 0,
                    style: .continuous
                )
                .fill(Color(NSColor.windowBackgroundColor))
            )
    }
}

/// Toggles for which event types this group (or the global default) records
/// to the SQLite trace DB. Shown in the inspector when a category row is
/// selected, or when nothing is selected (editing the defaults).
private struct RecordOptionsEditor: View {
    let title: String
    let subtitle: String?
    @Binding var options: RecordOptions
    let canResetToDefault: Bool
    let onResetToDefault: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                if let subtitle = subtitle {
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12)
            .padding(.top, 12)
            .padding(.bottom, 8)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    sectionHeader("Process")
                    Toggle("Exec", isOn: $options.exec)
                    Toggle("Exit", isOn: $options.exit)

                    sectionHeader("Files")
                    Toggle("Reads", isOn: $options.fileRead)
                    Toggle("Writes", isOn: $options.fileWrite)
                    Toggle("Creates", isOn: $options.fileCreate)
                    Toggle("Deletes", isOn: $options.fileDelete)
                    Toggle("Renames", isOn: $options.fileRename)

                    sectionHeader("Network")
                    Toggle("Connections", isOn: $options.network)
                    Toggle("HTTP traffic", isOn: $options.http)
                }
                .toggleStyle(.switch)
                .controlSize(.small)
                .padding(.horizontal, 12)
                .padding(.vertical, 12)
            }
            if canResetToDefault, let reset = onResetToDefault {
                Divider()
                HStack {
                    Spacer()
                    Button("Reset to Default", role: .destructive, action: reset)
                        .controlSize(.small)
                }
                .padding(8)
            }
            // NOTE: these toggles are not yet wired to actually gate SQLite
            // writes — that's a follow-up commit. They persist correctly and
            // the bindings are live.
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private func sectionHeader(_ title: String) -> some View {
        Text(title.uppercased())
            .font(.caption.bold())
            .foregroundStyle(.secondary)
            .tracking(0.4)
            .padding(.top, 4)
    }
}

private struct DetailHeader: View {
    let node: ProcessNode

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(node.name)
                    .font(.headline)
                Text(verbatim: "pid \(node.pid)")
                    .foregroundStyle(.secondary)
                if let status = node.exitStatus {
                    Text("exited \(status)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            Text(node.process)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            if !node.argv.isEmpty {
                Text(node.argv)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(8)
    }
}

// MARK: - Files

private struct FilesTable: View {
    struct Row: Identifiable {
        let path: String
        let stats: PathFileStats
        var id: String { path }
    }

    let byPath: [String: PathFileStats]

    var body: some View {
        let rows = byPath.map { Row(path: $0.key, stats: $0.value) }
            .sorted { $0.path < $1.path }
        Table(rows) {
            TableColumn("Path") { row in
                Text(row.path)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(row.path)
            }
            .width(min: 80)
            TableColumn("R") { Text(verbatim: "\($0.stats.reads)") }.width(min: 28, ideal: 32, max: 40)
            TableColumn("W") { Text(verbatim: "\($0.stats.writes)") }.width(min: 28, ideal: 32, max: 40)
            TableColumn("C") { Text(verbatim: "\($0.stats.creates)") }.width(min: 28, ideal: 32, max: 40)
            TableColumn("D") { Text(verbatim: "\($0.stats.deletes)") }.width(min: 28, ideal: 32, max: 40)
            TableColumn("Rn") { Text(verbatim: "\($0.stats.renames)") }.width(min: 28, ideal: 32, max: 40)
        }
    }
}

// MARK: - Connections

private struct ConnectionsTable: View {
    let byFlow: [UInt64: ConnectionRow]

    var body: some View {
        let rows = byFlow.values.sorted { $0.host < $1.host }
        Table(rows) {
            TableColumn("Host") { row in
                HStack {
                    if row.closed {
                        Image(systemName: "circle")
                            .font(.system(size: 6))
                            .foregroundStyle(.secondary)
                    } else {
                        Image(systemName: "circle.fill")
                            .font(.system(size: 6))
                            .foregroundStyle(.green)
                    }
                    Text(row.host)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
            .width(min: 80)
            TableColumn("Port") { Text(verbatim: "\($0.port)") }.width(min: 40, ideal: 50, max: 70)
            TableColumn("↑") { Text(formatBytes($0.bytesOut)).monospacedDigit() }.width(min: 60, ideal: 70, max: 90)
            TableColumn("↓") { Text(formatBytes($0.bytesIn)).monospacedDigit() }.width(min: 60, ideal: 70, max: 90)
        }
    }

    private func formatBytes(_ b: Int64) -> String {
        let bcf = ByteCountFormatter()
        bcf.countStyle = .binary
        return bcf.string(fromByteCount: b)
    }
}
