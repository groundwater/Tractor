import AppKit
import Foundation
import SwiftUI

// MARK: - Domain types

struct TraceGroup: Identifiable, Hashable {
    enum Kind: Hashable {
        case pid(pid_t)
        case path(String)
        case name(String)
    }
    let id: String       // stable across re-applies (uses TraceTarget.id)
    let label: String
    let kind: Kind
}

struct ProcessNode: Identifiable, Hashable {
    let pid: pid_t
    var ppid: pid_t
    var process: String
    var argv: String
    var fileOpCount: Int = 0
    var connectionCount: Int = 0
    var bytesIn: Int64 = 0
    var bytesOut: Int64 = 0
    var exitStatus: Int32? = nil
    var firstSeen: Date = Date()

    var id: pid_t { pid }
    var name: String { (process as NSString).lastPathComponent }
}

struct PathFileStats: Hashable {
    var reads: Int = 0
    var writes: Int = 0
    var creates: Int = 0
    var deletes: Int = 0
    var renames: Int = 0
    var other: Int = 0
}

struct ConnectionRow: Identifiable, Hashable {
    let flowID: UInt64
    let host: String
    let port: UInt16
    var bytesOut: Int64 = 0
    var bytesIn: Int64 = 0
    var closed: Bool = false

    var id: UInt64 { flowID }
}

// MARK: - Live model

@MainActor
final class LiveModel: ObservableObject {
    @Published var processes: [pid_t: ProcessNode] = [:]
    @Published var children: [pid_t: [pid_t]] = [:]
    @Published var roots: [pid_t] = []

    @Published var fileStats: [pid_t: [String: PathFileStats]] = [:]
    @Published var connections: [pid_t: [UInt64: ConnectionRow]] = [:]

    @Published var groups: [TraceGroup] = []
    @Published var pidToGroups: [pid_t: Set<String>] = [:]

    // Stable ordering helpers
    func sortedRoots() -> [pid_t] {
        roots.sorted { (processes[$0]?.firstSeen ?? .distantPast) < (processes[$1]?.firstSeen ?? .distantPast) }
    }

    func sortedChildren(_ pid: pid_t) -> [pid_t] {
        (children[pid] ?? []).sorted { (processes[$0]?.firstSeen ?? .distantPast) < (processes[$1]?.firstSeen ?? .distantPast) }
    }

    func reset() {
        processes.removeAll()
        children.removeAll()
        roots.removeAll()
        fileStats.removeAll()
        connections.removeAll()
        groups.removeAll()
        pidToGroups.removeAll()
    }

    // MARK: - Trace groups

    func setGroups(_ newGroups: [TraceGroup]) {
        let newIDs = Set(newGroups.map { $0.id })
        let oldIDs = Set(groups.map { $0.id })
        let removed = oldIDs.subtracting(newIDs)
        if !removed.isEmpty {
            for (pid, gs) in pidToGroups {
                let remaining = gs.subtracting(removed)
                pidToGroups[pid] = remaining.isEmpty ? nil : remaining
            }
        }
        groups = newGroups
        // Re-match existing processes against any newly-added groups.
        let added = newGroups.filter { !oldIDs.contains($0.id) }
        if !added.isEmpty {
            for (pid, node) in processes {
                for g in added where groupMatches(g, pid: pid, process: node.process, name: node.name) {
                    pidToGroups[pid, default: []].insert(g.id)
                }
            }
        }
    }

    func rootsForGroup(_ groupID: String) -> [pid_t] {
        var out: [pid_t] = []
        for (pid, gs) in pidToGroups where gs.contains(groupID) {
            let ppid = processes[pid]?.ppid ?? 0
            let parentInGroup = pidToGroups[ppid]?.contains(groupID) ?? false
            if !parentInGroup { out.append(pid) }
        }
        return out.sorted { (processes[$0]?.firstSeen ?? .distantPast) < (processes[$1]?.firstSeen ?? .distantPast) }
    }

    private func groupMatches(_ group: TraceGroup, pid: pid_t, process: String, name: String) -> Bool {
        switch group.kind {
        case .pid(let p): return pid == p
        case .path(let s): return !s.isEmpty && process == s
        case .name(let s): return !s.isEmpty && name.range(of: s, options: .caseInsensitive) != nil
        }
    }

    private func assignGroups(pid: pid_t, ppid: pid_t, process: String, name: String) {
        var set = pidToGroups[pid] ?? []
        for g in groups where groupMatches(g, pid: pid, process: process, name: name) {
            set.insert(g.id)
        }
        if let parentGroups = pidToGroups[ppid] {
            set.formUnion(parentGroups)
        }
        if !set.isEmpty {
            pidToGroups[pid] = set
        }
    }

    // MARK: - Event handlers (call from main actor)

    func handleExec(pid: pid_t, ppid: pid_t, process: String, argv: String) {
        if processes[pid] == nil {
            processes[pid] = ProcessNode(pid: pid, ppid: ppid, process: process, argv: argv)
        } else {
            processes[pid]?.process = process
            processes[pid]?.argv = argv
            processes[pid]?.ppid = ppid
        }
        attach(pid: pid, ppid: ppid)
        let name = (process as NSString).lastPathComponent
        assignGroups(pid: pid, ppid: ppid, process: process, name: name)
    }

    func handleFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, details: [String: String]) {
        ensureProcess(pid: pid, ppid: ppid, process: process)
        let path = details["to"] ?? details["path"] ?? details["from"] ?? "?"
        var byPath = fileStats[pid] ?? [:]
        var stats = byPath[path] ?? PathFileStats()
        switch type {
        case "open", "read", "stat", "readlink": stats.reads += 1
        case "write", "truncate": stats.writes += 1
        case "create": stats.creates += 1
        case "unlink", "delete": stats.deletes += 1
        case "rename": stats.renames += 1
        default: stats.other += 1
        }
        byPath[path] = stats
        fileStats[pid] = byPath
        processes[pid]?.fileOpCount += 1
    }

    func handleExit(pid: pid_t, exitStatus: Int32) {
        processes[pid]?.exitStatus = exitStatus
    }

    func handleBytesUpdate(pid: pid_t, host: String, port: UInt16, bytesOut: Int64, bytesIn: Int64, flowID: UInt64) {
        ensureProcess(pid: pid, ppid: 0, process: "")
        var byFlow = connections[pid] ?? [:]
        if var row = byFlow[flowID] {
            row.bytesOut = bytesOut
            row.bytesIn = bytesIn
            byFlow[flowID] = row
        } else {
            byFlow[flowID] = ConnectionRow(flowID: flowID, host: host, port: port, bytesOut: bytesOut, bytesIn: bytesIn)
            processes[pid]?.connectionCount += 1
        }
        connections[pid] = byFlow
        if let row = byFlow[flowID] {
            processes[pid]?.bytesOut = row.bytesOut
            processes[pid]?.bytesIn = row.bytesIn
        }
    }

    func handleConnectionClosed(pid: pid_t, host: String, port: UInt16, flowID: UInt64) {
        connections[pid]?[flowID]?.closed = true
    }

    // MARK: - Helpers

    private func ensureProcess(pid: pid_t, ppid: pid_t, process: String) {
        if processes[pid] != nil { return }
        processes[pid] = ProcessNode(pid: pid, ppid: ppid, process: process, argv: "")
        if ppid > 0 { attach(pid: pid, ppid: ppid) } else { roots.append(pid) }
    }

    private func attach(pid: pid_t, ppid: pid_t) {
        if let parent = processes[ppid], parent.pid != 0 {
            var kids = children[ppid] ?? []
            if !kids.contains(pid) { kids.append(pid) }
            children[ppid] = kids
        } else {
            if !roots.contains(pid) { roots.append(pid) }
        }
    }
}

// MARK: - EventSink adapter

/// Receives events from any thread, dispatches to the @MainActor LiveModel.
final class LiveSink: EventSink {
    weak var model: LiveModel?

    init(model: LiveModel) {
        self.model = model
    }

    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t) {
        let m = model
        DispatchQueue.main.async { m?.handleExec(pid: pid, ppid: ppid, process: process, argv: argv) }
    }

    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String]) {
        let m = model
        DispatchQueue.main.async { m?.handleFileOp(type: type, pid: pid, ppid: ppid, process: process, details: details) }
    }

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16, flowID: UInt64) {
        // Bytes-based path is what we render; ignore the connect-only signal.
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t, exitStatus: Int32) {
        let m = model
        DispatchQueue.main.async { m?.handleExit(pid: pid, exitStatus: exitStatus) }
    }
}
