import AppKit
import Combine
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
    var exitedAt: Date? = nil
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
    // The storage dicts are NOT @Published — direct mutations don't trigger
    // a SwiftUI invalidation. Instead we coalesce invalidations to ~30Hz via
    // setNeedsPublish() so a burst of N events causes one redraw, not N.
    var processes: [pid_t: ProcessNode] = [:]
    var children: [pid_t: [pid_t]] = [:]
    var roots: [pid_t] = []

    var fileStats: [pid_t: [String: PathFileStats]] = [:]
    var connections: [pid_t: [UInt64: ConnectionRow]] = [:]

    var groups: [TraceGroup] = []
    var pidToGroups: [pid_t: Set<String>] = [:]

    /// Tickle to trigger a coalesced redraw at most every ~33ms.
    private var publishPending: Bool = false
    private static let publishInterval: TimeInterval = 1.0 / 30.0

    private func setNeedsPublish() {
        if publishPending { return }
        publishPending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.publishInterval) { [weak self] in
            guard let self = self else { return }
            self.publishPending = false
            self.objectWillChange.send()
        }
    }

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
        setNeedsPublish()
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
            let orphans = processes.keys.filter { pidToGroups[$0] == nil }
            for pid in orphans {
                processes.removeValue(forKey: pid)
                children.removeValue(forKey: pid)
                fileStats.removeValue(forKey: pid)
                connections.removeValue(forKey: pid)
            }
            roots.removeAll { processes[$0] == nil }
            for (parent, kids) in children {
                children[parent] = kids.filter { processes[$0] != nil }
            }
        }
        groups = newGroups
        let added = newGroups.filter { !oldIDs.contains($0.id) }
        if !added.isEmpty {
            for (pid, node) in processes {
                for g in added where groupMatches(g, pid: pid, process: node.process, name: node.name) {
                    pidToGroups[pid, default: []].insert(g.id)
                }
            }
        }
        setNeedsPublish()
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
        setNeedsPublish()
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
        setNeedsPublish()
    }

    func handleExit(pid: pid_t, exitStatus: Int32) {
        processes[pid]?.exitStatus = exitStatus
        processes[pid]?.exitedAt = Date()
        setNeedsPublish()
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
        setNeedsPublish()
    }

    func handleConnectionClosed(pid: pid_t, host: String, port: UInt16, flowID: UInt64) {
        connections[pid]?[flowID]?.closed = true
        setNeedsPublish()
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

/// Receives events from any thread and batches them into a single per-runloop
/// dispatch to the @MainActor LiveModel. With a busy sysext that's the
/// difference between one main-thread block per event (thousands/sec) and
/// one per drained batch.
final class LiveSink: EventSink {
    weak var model: LiveModel?

    private enum PendingEvent {
        case exec(pid_t, pid_t, String, String)
        case fileOp(String, pid_t, pid_t, String, [String: String])
        case exit(pid_t, Int32)
    }

    private let lock = NSLock()
    private var queue: [PendingEvent] = []
    private var scheduled = false

    init(model: LiveModel) {
        self.model = model
    }

    private func enqueue(_ event: PendingEvent) {
        lock.lock()
        queue.append(event)
        let needsSchedule = !scheduled
        if needsSchedule { scheduled = true }
        lock.unlock()
        if needsSchedule {
            DispatchQueue.main.async { [weak self] in self?.drain() }
        }
    }

    @MainActor
    private func drain() {
        lock.lock()
        let events = queue
        queue.removeAll(keepingCapacity: true)
        scheduled = false
        lock.unlock()
        guard let m = model else { return }
        for e in events {
            switch e {
            case .exec(let pid, let ppid, let process, let argv):
                m.handleExec(pid: pid, ppid: ppid, process: process, argv: argv)
            case .fileOp(let type, let pid, let ppid, let process, let details):
                m.handleFileOp(type: type, pid: pid, ppid: ppid, process: process, details: details)
            case .exit(let pid, let status):
                m.handleExit(pid: pid, exitStatus: status)
            }
        }
    }

    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t) {
        enqueue(.exec(pid, ppid, process, argv))
    }

    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String]) {
        enqueue(.fileOp(type, pid, ppid, process, details))
    }

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16, flowID: UInt64) {
        // Bytes-based path is what we render; ignore the connect-only signal.
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t, exitStatus: Int32) {
        enqueue(.exit(pid, exitStatus))
    }
}
