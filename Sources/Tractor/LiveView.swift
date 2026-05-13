import SwiftUI

/// Process-list-wide UI preferences. Singleton so AppKit menu items and
/// SwiftUI views share the same source of truth.
@MainActor
final class AppPrefs: ObservableObject {
    static let shared = AppPrefs()
    static let hideExitedAfter: TimeInterval = 3.0

    @Published var hideExited: Bool = true
    @Published var inspectorShown: Bool = true
}

struct LiveView: View {
    @ObservedObject var model: LiveModel
    @ObservedObject private var prefs = AppPrefs.shared
    @Binding var selection: ProcessTableRow.ID?
    var onAddTarget: () -> Void
    var onDeleteGroup: (String) -> Void

    enum DetailTab: Hashable { case files, connections }

    var body: some View {
        // .periodic ticks once per second so exited processes disappear
        // after AppPrefs.hideExitedAfter even when no events are arriving.
        TimelineView(.periodic(from: .now, by: 1.0)) { context in
            VStack(spacing: 0) {
                ProcessTableView(model: model, now: context.date, hideExited: prefs.hideExited, selection: $selection)
                    .onDeleteCommand {
                        if let id = selection, id.hasPrefix("g:") {
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

/// Resolves a ProcessTableRow.ID like "p:1234" to a pid_t.
func selectedPid(from id: ProcessTableRow.ID?) -> pid_t? {
    guard let id = id, id.hasPrefix("p:") else { return nil }
    return pid_t(id.dropFirst(2))
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
    @MainActor
    static func process(_ pid: pid_t, model: LiveModel, now: Date, hideExited: Bool) -> ProcessTableRow? {
        let node = model.processes[pid]
        let kids = model.sortedChildren(pid).compactMap {
            process($0, model: model, now: now, hideExited: hideExited)
        }
        if hideExited, let exitedAt = node?.exitedAt,
           now.timeIntervalSince(exitedAt) > AppPrefs.hideExitedAfter,
           kids.isEmpty {
            return nil
        }
        return ProcessTableRow(
            id: "p:\(pid)",
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
    static func group(_ group: TraceGroup, model: LiveModel, now: Date, hideExited: Bool) -> ProcessTableRow {
        let roots = model.rootsForGroup(group.id)
        let kidRows = roots.compactMap { process($0, model: model, now: now, hideExited: hideExited) }
        let kids = kidRows.isEmpty
            ? [emptyGroupPlaceholder(groupID: group.id)]
            : kidRows
        return ProcessTableRow(
            id: "g:\(group.id)",
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
    func buildRows(now: Date, hideExited: Bool) -> [ProcessTableRow] {
        if groups.isEmpty {
            return sortedRoots().compactMap {
                ProcessTableRow.process($0, model: self, now: now, hideExited: hideExited)
            }
        }
        return groups.map {
            ProcessTableRow.group($0, model: self, now: now, hideExited: hideExited)
        }
    }
}

// MARK: - Table

private struct ProcessTableView: View {
    @ObservedObject var model: LiveModel
    let now: Date
    let hideExited: Bool
    @Binding var selection: ProcessTableRow.ID?

    var body: some View {
        Table(model.buildRows(now: now, hideExited: hideExited), children: \.children, selection: $selection) {
            TableColumn("Process") { row in
                HStack(spacing: 6) {
                    if row.isGroup {
                        Image(systemName: "folder")
                            .foregroundStyle(.secondary)
                    } else if row.placeholder {
                        // no leading dot
                    } else {
                        Image(systemName: row.exited ? "circle" : "circle.fill")
                            .font(.system(size: 6))
                            .foregroundStyle(row.exited ? Color.secondary : Color.green)
                    }
                    Text(row.name)
                        .font(row.isGroup ? .body.weight(.semibold) : .body)
                        .foregroundStyle(row.placeholder ? .secondary : .primary)
                        .lineLimit(1)
                }
            }
            TableColumn("PID") { row in
                Text(row.pidLabel).foregroundStyle(.secondary)
            }
            .width(min: 50, ideal: 70)
            TableColumn("Files") { row in
                Text(row.isGroup || row.placeholder ? "" : "\(row.fileOpCount)")
                    .foregroundStyle(.secondary)
            }
            .width(min: 50, ideal: 70)
            TableColumn("Connections") { row in
                Text(row.isGroup || row.placeholder ? "" : "\(row.connectionCount)")
                    .foregroundStyle(.secondary)
            }
            .width(min: 60, ideal: 100)
            TableColumn("Status") { row in
                if row.isGroup || row.placeholder {
                    Text("").foregroundStyle(.secondary)
                } else if let code = row.exitStatus {
                    Text("exited \(code)").foregroundStyle(.secondary)
                } else {
                    Text("running").foregroundStyle(.secondary)
                }
            }
            .width(min: 70, ideal: 100)
        }
    }
}

// MARK: - Detail pane

struct DetailPane: View {
    @ObservedObject var model: LiveModel
    let selection: pid_t?
    @Binding var tab: LiveView.DetailTab

    var body: some View {
        VStack(spacing: 0) {
            if let pid = selection, let node = model.processes[pid] {
                DetailHeader(node: node)
                Divider()
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
            } else {
                ContentUnavailableView("Select a process", systemImage: "scope")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
}

private struct DetailHeader: View {
    let node: ProcessNode

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(node.name)
                    .font(.headline)
                Text("pid \(node.pid)")
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
            TableColumn("R") { Text("\($0.stats.reads)") }.width(36)
            TableColumn("W") { Text("\($0.stats.writes)") }.width(36)
            TableColumn("C") { Text("\($0.stats.creates)") }.width(36)
            TableColumn("D") { Text("\($0.stats.deletes)") }.width(36)
            TableColumn("Rn") { Text("\($0.stats.renames)") }.width(36)
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
            TableColumn("Port") { Text("\($0.port)") }.width(60)
            TableColumn("↑") { Text(formatBytes($0.bytesOut)) }.width(80)
            TableColumn("↓") { Text(formatBytes($0.bytesIn)) }.width(80)
        }
    }

    private func formatBytes(_ b: Int64) -> String {
        let bcf = ByteCountFormatter()
        bcf.countStyle = .binary
        return bcf.string(fromByteCount: b)
    }
}
