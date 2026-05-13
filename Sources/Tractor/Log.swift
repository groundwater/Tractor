import ArgumentParser
import Darwin
import Foundation

struct Log: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "log",
        abstract: "Summarize a Tractor trace database",
        subcommands: [LogOverview.self],
        defaultSubcommand: LogOverview.self
    )
}

struct LogOverview: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "overview",
        abstract: "Single-screen overview of agent activity"
    )

    @Argument(help: "Path to a trace .db file (default: shared app-group tractor.db)")
    var path: String?

    @Option(name: .long, help: "Render width in columns")
    var width: Int = 100

    func run() throws {
        let dbPath = try resolvePath()
        var dbHandle: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &dbHandle, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let db = dbHandle else {
            let msg = dbHandle.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            sqlite3_close(dbHandle)
            throw ValidationError("Cannot open \(dbPath): \(msg)")
        }
        defer { sqlite3_close(db) }

        let summary = Summary.collect(db: db)
        Renderer(width: max(60, width)).render(summary, dbPath: dbPath)
    }

    private func resolvePath() throws -> String {
        if let p = path {
            guard FileManager.default.fileExists(atPath: p) else {
                throw ValidationError("No such file: \(p)")
            }
            return p
        }
        let shared = try TractorPaths.sharedLogPath()
        guard FileManager.default.fileExists(atPath: shared) else {
            throw ValidationError("Shared trace DB not found at \(shared). Run `tractor trace` first, or pass a path.")
        }
        return shared
    }
}

// MARK: - Data model

private struct Summary {
    var firstTimestamp: String = ""
    var lastTimestamp: String = ""
    var totalEvents: Int = 0
    var distinctPids: Int = 0
    var typeCounts: [String: Int] = [:]

    var topExecs: [(name: String, count: Int)] = []
    var hosts: [HostRow] = []
    var fileGroups: [FileGroup] = []
    var findings: [Finding] = []

    struct HostRow {
        let label: String
        let connects: Int
        let httpRequests: Int
        let httpBytes: Int
        let flagged: Bool
    }

    struct FileGroup {
        let prefix: String
        let writes: Int
        let unlinks: Int
        let flagged: Bool
    }

    struct Finding {
        let message: String
    }

    static func collect(db: OpaquePointer) -> Summary {
        var s = Summary()

        // span + totals
        forEachRow(db, "SELECT MIN(timestamp), MAX(timestamp), COUNT(*), COUNT(DISTINCT pid) FROM events") { stmt in
            s.firstTimestamp = textColumn(stmt, 0) ?? ""
            s.lastTimestamp = textColumn(stmt, 1) ?? ""
            s.totalEvents = Int(sqlite3_column_int64(stmt, 2))
            s.distinctPids = Int(sqlite3_column_int64(stmt, 3))
        }

        // type histogram
        forEachRow(db, "SELECT type, COUNT(*) FROM events GROUP BY type") { stmt in
            let t = textColumn(stmt, 0) ?? "?"
            s.typeCounts[t] = Int(sqlite3_column_int64(stmt, 1))
        }

        // top execs by basename of `process`
        var execCounts: [String: Int] = [:]
        forEachRow(db, "SELECT process FROM events WHERE type = 'exec'") { stmt in
            if let p = textColumn(stmt, 0) {
                let name = (p as NSString).lastPathComponent
                execCounts[name, default: 0] += 1
            }
        }
        s.topExecs = execCounts.sorted { $0.value > $1.value }.prefix(8)
            .map { ($0.key, $0.value) }

        // network: connect addr:port counts (+ http_traffic if present)
        var connectCounts: [String: Int] = [:]
        var nonStandardPort = 0
        var plaintextHttp = 0
        forEachRow(db, "SELECT details FROM events WHERE type = 'connect'") { stmt in
            guard let details = textColumn(stmt, 0),
                  let parsed = parseDetails(details) else { return }
            let addr = parsed["addr"] ?? "?"
            let port = parsed["port"] ?? "?"
            connectCounts["\(addr):\(port)", default: 0] += 1
            if port == "80" { plaintextHttp += 1 }
            let p = Int(port) ?? 0
            if ![80, 443, 53, 22, 5353, 0].contains(p) { nonStandardPort += 1 }
        }

        // http_traffic — by host
        var httpByHost: [String: (req: Int, bytes: Int)] = [:]
        if tableExists(db, "http_traffic") {
            forEachRow(db, "SELECT host, direction, content FROM http_traffic") { stmt in
                let host = textColumn(stmt, 0) ?? "?"
                let dir = textColumn(stmt, 1) ?? ""
                let content = textColumn(stmt, 2) ?? ""
                var cur = httpByHost[host] ?? (0, 0)
                if dir == "request" || dir == "req" || dir == "send" { cur.req += 1 }
                cur.bytes += content.utf8.count
                httpByHost[host] = cur
            }
        }

        // merge: prefer hostnames; keep unresolved ip:port rows too
        var rows: [HostRow] = []
        for (host, v) in httpByHost {
            rows.append(HostRow(label: host, connects: 0, httpRequests: v.req, httpBytes: v.bytes, flagged: false))
        }
        // sort+limit IPs first, then resolve only the ones we'll show
        let topIPs = connectCounts.sorted { $0.value > $1.value }.prefix(12)
        let uniqueIPs = Set(topIPs.map { $0.key.split(separator: ":").first.map(String.init) ?? "" })
        let resolved = reverseResolve(Array(uniqueIPs), timeout: 0.4)
        for (addrPort, c) in topIPs {
            let parts = addrPort.split(separator: ":")
            let ip = parts.first.map(String.init) ?? ""
            let port = parts.last.map(String.init) ?? ""
            let flagged = port == "80" || ![80, 443, 53, 22, 5353].contains(Int(port) ?? 0)
            let label = (resolved[ip].map { "\($0):\(port)" }) ?? addrPort
            rows.append(HostRow(label: label, connects: c, httpRequests: 0, httpBytes: 0, flagged: flagged))
        }
        s.hosts = rows.sorted { ($0.httpRequests + $0.connects) > ($1.httpRequests + $1.connects) }
            .prefix(8).map { $0 }

        // file groups: roll up by directory under HOME (~depth 2) or root (depth 1)
        var writesByPrefix: [String: Int] = [:]
        var unlinksByPrefix: [String: Int] = [:]
        var sensitiveWrites: [String] = []
        forEachRow(db, "SELECT type, details FROM events WHERE type IN ('write','unlink','rename')") { stmt in
            let type = textColumn(stmt, 0) ?? ""
            guard let d = textColumn(stmt, 1), let parsed = parseDetails(d) else { return }
            let path: String = {
                if type == "rename" { return parsed["to"] ?? parsed["from"] ?? "" }
                return parsed["path"] ?? ""
            }()
            if path.isEmpty { return }
            let normalized = normalizePath(path)
            let prefix = rollupPrefix(normalized)
            if type == "unlink" {
                unlinksByPrefix[prefix, default: 0] += 1
            } else {
                writesByPrefix[prefix, default: 0] += 1
            }
            if isSensitiveWrite(normalized) {
                sensitiveWrites.append(normalized)
            }
        }
        let allPrefixes = Set(writesByPrefix.keys).union(unlinksByPrefix.keys)
        s.fileGroups = allPrefixes.map { p -> FileGroup in
            FileGroup(prefix: p,
                      writes: writesByPrefix[p] ?? 0,
                      unlinks: unlinksByPrefix[p] ?? 0,
                      flagged: prefixIsSensitive(p))
        }
        .sorted { ($0.writes + $0.unlinks) > ($1.writes + $1.unlinks) }
        .prefix(8).map { $0 }

        // findings
        var findings: [Finding] = []

        // privileged execs
        let privBins: Set<String> = ["sudo", "security", "osascript", "launchctl", "dscl", "defaults"]
        var privSeen: [String: Int] = [:]
        forEachRow(db, "SELECT process FROM events WHERE type = 'exec'") { stmt in
            if let p = textColumn(stmt, 0) {
                let name = (p as NSString).lastPathComponent
                if privBins.contains(name) { privSeen[name, default: 0] += 1 }
            }
        }
        for (bin, c) in privSeen.sorted(by: { $0.value > $1.value }) {
            findings.append(Finding(message: "privileged exec: \(bin) (\(c)×)"))
        }

        // curl|sh style
        var pipeToShell = 0
        forEachRow(db, "SELECT details FROM events WHERE type = 'exec'") { stmt in
            guard let d = textColumn(stmt, 0), let parsed = parseDetails(d),
                  let argv = parsed["argv"] else { return }
            if argv.contains("| sh") || argv.contains("|sh") || argv.contains("| bash") || argv.contains("|bash") {
                if argv.contains("curl ") || argv.contains("wget ") { pipeToShell += 1 }
            }
        }
        if pipeToShell > 0 {
            findings.append(Finding(message: "pipe-to-shell pattern in \(pipeToShell) exec(s) (curl|sh / wget|bash)"))
        }

        // sensitive writes
        if !sensitiveWrites.isEmpty {
            let sample = Set(sensitiveWrites).sorted().prefix(3).joined(separator: ", ")
            findings.append(Finding(message: "writes to sensitive paths (\(sensitiveWrites.count)): \(sample)"))
        }

        // plaintext http / non-standard ports
        if plaintextHttp > 0 {
            findings.append(Finding(message: "plaintext HTTP connects: \(plaintextHttp) on port 80"))
        }
        if nonStandardPort > 0 {
            findings.append(Finding(message: "connects to non-standard ports: \(nonStandardPort)"))
        }

        // http error clusters
        if tableExists(db, "http_traffic") {
            var errsByHost: [String: Int] = [:]
            forEachRow(db, "SELECT host, content FROM http_traffic WHERE direction = 'response' OR direction = 'resp'") { stmt in
                let host = textColumn(stmt, 0) ?? ""
                let content = textColumn(stmt, 1) ?? ""
                let firstLine = content.split(separator: "\n", maxSplits: 1).first.map(String.init) ?? ""
                if firstLine.contains(" 5") || firstLine.contains(" 4") {
                    // crude: HTTP/1.x 4xx or 5xx
                    let parts = firstLine.split(separator: " ")
                    if parts.count >= 2, let code = Int(parts[1]), code >= 400 {
                        errsByHost[host, default: 0] += 1
                    }
                }
            }
            for (host, c) in errsByHost where c >= 5 {
                findings.append(Finding(message: "HTTP 4xx/5xx cluster: \(c) responses from \(host)"))
            }
        }

        s.findings = findings
        return s
    }
}

// MARK: - Renderer

private struct Renderer {
    let width: Int

    func render(_ s: Summary, dbPath: String) {
        let halfWidth = (width - 4) / 2
        let leftCol = halfWidth
        let rightCol = width - leftCol - 4

        // Header
        let file = (dbPath as NSString).lastPathComponent
        let span = formatSpan(from: s.firstTimestamp, to: s.lastTimestamp)
        let totals = "\(s.totalEvents) events · \(s.distinctPids) pids"
        let header = "Tractor — \(file)"
        let right = "\(span) · \(totals)"
        print(padPair(header, right, total: width))
        print(String(repeating: "─", count: width))

        // Two-column body
        let leftBlocks: [[String]] = [
            block("ACTIVITY  (top exec'd binaries)",
                  rows: s.topExecs.map { "\(rpad($0.name, leftCol - 8))\(lpad("\($0.count)×", 5))" },
                  width: leftCol),
            block("FILES  (writes · unlinks)",
                  rows: s.fileGroups.map { row in
                      let counts = "\(lpad("\(row.writes)", 5))  ·\(lpad("\(row.unlinks)", 4))"
                      let mark = row.flagged ? " ⚠" : ""
                      let label = rpad(row.prefix + mark, leftCol - counts.count - 1)
                      return label + " " + counts
                  },
                  width: leftCol),
        ]
        let rightBlocks: [[String]] = [
            block("NETWORK  (hosts / endpoints)",
                  rows: s.hosts.map { row in
                      var detail = ""
                      if row.httpRequests > 0 { detail = "\(row.httpRequests) req · \(humanBytes(row.httpBytes))" }
                      else if row.connects > 0 { detail = "\(row.connects) conn" }
                      let mark = row.flagged ? " ⚠" : ""
                      return rpad(row.label + mark, rightCol - detail.count - 1) + " " + detail
                  },
                  width: rightCol),
            block("UNUSUAL",
                  rows: s.findings.isEmpty
                      ? ["(no rules fired)"]
                      : s.findings.map { "⚠ " + truncate($0.message, rightCol - 2) },
                  width: rightCol),
        ]

        let left = leftBlocks.flatMap { $0 + [""] }
        let rightLines = rightBlocks.flatMap { $0 + [""] }
        let rows = max(left.count, rightLines.count)
        for i in 0..<rows {
            let l = i < left.count ? left[i] : ""
            let r = i < rightLines.count ? rightLines[i] : ""
            print(rpad(l, leftCol) + "    " + r)
        }
    }

    private func block(_ title: String, rows: [String], width: Int) -> [String] {
        var out: [String] = []
        out.append(title)
        out.append(String(repeating: "·", count: min(title.count, width)))
        if rows.isEmpty {
            out.append("(none)")
        } else {
            out.append(contentsOf: rows)
        }
        return out
    }
}

// MARK: - Helpers

private func tableExists(_ db: OpaquePointer, _ name: String) -> Bool {
    var found = false
    forEachRow(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='\(name)'") { _ in
        found = true
    }
    return found
}

private func forEachRow(_ db: OpaquePointer, _ sql: String, _ body: (OpaquePointer) -> Void) {
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let s = stmt else { return }
    defer { sqlite3_finalize(s) }
    while sqlite3_step(s) == SQLITE_ROW {
        body(s)
    }
}

private func textColumn(_ stmt: OpaquePointer, _ idx: Int32) -> String? {
    guard let cstr = sqlite3_column_text(stmt, idx) else { return nil }
    return String(cString: cstr)
}

private func reverseResolve(_ ips: [String], timeout: TimeInterval) -> [String: String] {
    let lock = NSLock()
    var out: [String: String] = [:]
    let group = DispatchGroup()
    let queue = DispatchQueue.global(qos: .userInitiated)
    for ip in ips where !ip.isEmpty {
        group.enter()
        queue.async {
            defer { group.leave() }
            var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            var rc: Int32 = -1
            if ip.contains(":") {
                var sa6 = sockaddr_in6()
                sa6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                sa6.sin6_family = sa_family_t(AF_INET6)
                guard inet_pton(AF_INET6, ip, &sa6.sin6_addr) == 1 else { return }
                rc = withUnsafePointer(to: &sa6) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        getnameinfo(sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size),
                                    &hostBuf, socklen_t(hostBuf.count), nil, 0, NI_NAMEREQD)
                    }
                }
            } else {
                var sa = sockaddr_in()
                sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                sa.sin_family = sa_family_t(AF_INET)
                guard inet_pton(AF_INET, ip, &sa.sin_addr) == 1 else { return }
                rc = withUnsafePointer(to: &sa) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                        getnameinfo(sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size),
                                    &hostBuf, socklen_t(hostBuf.count), nil, 0, NI_NAMEREQD)
                    }
                }
            }
            guard rc == 0 else { return }
            let host = String(cString: hostBuf)
            if host != ip {
                lock.lock(); out[ip] = host; lock.unlock()
            }
        }
    }
    _ = group.wait(timeout: .now() + timeout)
    return out
}

private func parseDetails(_ json: String) -> [String: String]? {
    guard let data = json.data(using: .utf8) else { return nil }
    return (try? JSONDecoder().decode([String: String].self, from: data))
}

private func normalizePath(_ path: String) -> String {
    var p = path
    if p.hasPrefix("/private/var/folders/") { return p }
    if p.hasPrefix("/private/tmp/") { p = String(p.dropFirst("/private".count)) }
    let home = NSHomeDirectory()
    if p.hasPrefix(home + "/") { p = "~" + String(p.dropFirst(home.count)) }
    else if p == home { p = "~" }
    return p
}

private func rollupPrefix(_ path: String) -> String {
    // ~/foo/bar/baz.txt -> ~/foo/bar ; /etc/foo -> /etc ; /var/folders/.../T/x -> /var/folders/.../T
    if path.hasPrefix("~/") {
        let parts = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        // parts[0] == "~"
        if parts.count <= 2 { return parts.joined(separator: "/").replacingOccurrences(of: "~", with: "~", options: [], range: nil) }
        return "~/" + parts[1] + "/" + parts[2]
    }
    if path.hasPrefix("/var/folders/") || path.hasPrefix("/private/var/folders/") {
        let parts = path.split(separator: "/").map(String.init)
        if parts.count >= 5 { return "/" + parts.prefix(5).joined(separator: "/") }
    }
    let parts = path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    if parts.isEmpty { return path }
    return "/" + parts[0]
}

private func isSensitiveWrite(_ path: String) -> Bool {
    let sensitive = ["~/.ssh/", "~/.aws/", "~/.gnupg/", "~/.config/git/",
                     "/etc/", "/usr/", "/Library/", "/System/", "/bin/", "/sbin/"]
    return sensitive.contains { path.hasPrefix($0) }
}

private func prefixIsSensitive(_ prefix: String) -> Bool {
    let sensitive: Set<String> = ["~/.ssh", "~/.aws", "~/.gnupg", "/etc", "/usr", "/Library", "/System", "/bin", "/sbin"]
    return sensitive.contains(prefix)
}

private func formatSpan(from a: String, to b: String) -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    guard let s = f.date(from: a), let e = f.date(from: b) else { return "?" }
    let secs = e.timeIntervalSince(s)
    if secs < 60 { return String(format: "%.1fs", secs) }
    if secs < 3600 { return String(format: "%dm %ds", Int(secs) / 60, Int(secs) % 60) }
    return String(format: "%dh %dm", Int(secs) / 3600, (Int(secs) % 3600) / 60)
}

private func humanBytes(_ n: Int) -> String {
    let kb = 1024.0, mb = kb * 1024, gb = mb * 1024
    let d = Double(n)
    if d >= gb { return String(format: "%.1f GB", d / gb) }
    if d >= mb { return String(format: "%.1f MB", d / mb) }
    if d >= kb { return String(format: "%.1f KB", d / kb) }
    return "\(n) B"
}

private func rpad(_ s: String, _ w: Int) -> String {
    if s.count >= w { return String(s.prefix(w)) }
    return s + String(repeating: " ", count: w - s.count)
}

private func lpad(_ s: String, _ w: Int) -> String {
    if s.count >= w { return String(s.prefix(w)) }
    return String(repeating: " ", count: w - s.count) + s
}

private func truncate(_ s: String, _ w: Int) -> String {
    if s.count <= w { return s }
    if w <= 1 { return String(s.prefix(w)) }
    return String(s.prefix(w - 1)) + "…"
}

private func padPair(_ left: String, _ right: String, total: Int) -> String {
    let pad = max(1, total - left.count - right.count)
    return left + String(repeating: " ", count: pad) + right
}
