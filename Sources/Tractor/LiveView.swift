import SwiftUI

struct LiveView: View {
    @ObservedObject var model: LiveModel
    @State private var selection: pid_t? = nil
    @State private var detailTab: DetailTab = .files

    enum DetailTab: Hashable { case files, connections }

    var body: some View {
        HSplitView {
            ProcessTreeView(model: model, selection: $selection)
                .frame(minWidth: 280, idealWidth: 340)
            DetailPane(model: model, selection: selection, tab: $detailTab)
                .frame(minWidth: 360)
        }
    }
}

// MARK: - Tree

private struct ProcessTreeView: View {
    @ObservedObject var model: LiveModel
    @Binding var selection: pid_t?

    var body: some View {
        List(selection: $selection) {
            if model.groups.isEmpty {
                ForEach(model.sortedRoots(), id: \.self) { pid in
                    ProcessTreeRow(pid: pid, model: model)
                }
            } else {
                ForEach(model.groups) { group in
                    Section {
                        let roots = model.rootsForGroup(group.id)
                        if roots.isEmpty {
                            Text("(waiting for matches…)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(roots, id: \.self) { pid in
                                ProcessTreeRow(pid: pid, model: model)
                            }
                        }
                    } header: {
                        GroupHeader(group: group, rootCount: model.rootsForGroup(group.id).count)
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }
}

private struct GroupHeader: View {
    let group: TraceGroup
    let rootCount: Int

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: iconName)
                .foregroundStyle(.secondary)
            Text(group.label)
                .font(.headline)
            Spacer()
            Text("\(rootCount)")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var iconName: String {
        switch group.kind {
        case .pid: return "number"
        case .path: return "doc"
        case .name: return "magnifyingglass"
        }
    }
}

private struct ProcessTreeRow: View {
    let pid: pid_t
    @ObservedObject var model: LiveModel
    @State private var expanded: Bool = true

    var body: some View {
        let kids = model.sortedChildren(pid)
        if kids.isEmpty {
            ProcessRowLabel(pid: pid, model: model)
                .tag(pid)
        } else {
            DisclosureGroup(isExpanded: $expanded) {
                ForEach(kids, id: \.self) { child in
                    ProcessTreeRow(pid: child, model: model)
                }
            } label: {
                ProcessRowLabel(pid: pid, model: model)
                    .tag(pid)
            }
        }
    }
}

private struct ProcessRowLabel: View {
    let pid: pid_t
    @ObservedObject var model: LiveModel

    var body: some View {
        if let node = model.processes[pid] {
            HStack(spacing: 6) {
                Image(systemName: node.exitStatus == nil ? "circle.fill" : "circle")
                    .font(.system(size: 6))
                    .foregroundStyle(node.exitStatus == nil ? .green : .secondary)
                Text(node.name)
                    .lineLimit(1)
                Text("\(pid)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if node.fileOpCount > 0 || node.connectionCount > 0 {
                    HStack(spacing: 6) {
                        if node.fileOpCount > 0 {
                            Label("\(node.fileOpCount)", systemImage: "doc")
                                .labelStyle(.titleAndIcon)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        if node.connectionCount > 0 {
                            Label("\(node.connectionCount)", systemImage: "network")
                                .labelStyle(.titleAndIcon)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } else {
            Text("pid \(pid)")
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Detail pane

private struct DetailPane: View {
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
