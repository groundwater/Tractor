import Foundation

/// EventSink that writes events to a SQLite database
final class SQLiteLog: EventSink {
    private var db: OpaquePointer?
    private var insertStmt: OpaquePointer?
    private var trafficStmt: OpaquePointer?
    private let lock = NSLock()
    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    let path: String

    init(path: String) throws {
        self.path = path
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            sqlite3_close(db)
            throw SQLiteLogError.open(msg)
        }
        self.db = db

        // Own the file as the invoking user, not root
        let ownerUid = ProcessInfo.processInfo.environment["SUDO_UID"].flatMap { uid_t($0) } ?? getuid()
        let ownerGid = ProcessInfo.processInfo.environment["SUDO_GID"].flatMap { gid_t($0) } ?? getgid()
        chown(path, ownerUid, ownerGid)

        sqlite3_exec(db, "PRAGMA journal_mode=WAL", nil, nil, nil)

        // WAL creates sidecar files — own them too
        chown(path + "-wal", ownerUid, ownerGid)
        chown(path + "-shm", ownerUid, ownerGid)

        let create = """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                pid INTEGER NOT NULL,
                ppid INTEGER NOT NULL,
                process TEXT NOT NULL,
                user INTEGER NOT NULL,
                details TEXT
            )
            """
        guard sqlite3_exec(db, create, nil, nil, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.schema(msg)
        }

        let createTraffic = """
            CREATE TABLE IF NOT EXISTS http_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                pid INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                direction TEXT NOT NULL,
                content TEXT NOT NULL
            )
            """
        guard sqlite3_exec(db, createTraffic, nil, nil, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.schema(msg)
        }

        var stmt: OpaquePointer?
        let insert = "INSERT INTO events (timestamp, type, pid, ppid, process, user, details) VALUES (?, ?, ?, ?, ?, ?, ?)"
        guard sqlite3_prepare_v2(db, insert, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.prepare(msg)
        }
        self.insertStmt = stmt

        var tstmt: OpaquePointer?
        let tinsert = "INSERT INTO http_traffic (timestamp, pid, host, port, direction, content) VALUES (?, ?, ?, ?, ?, ?)"
        guard sqlite3_prepare_v2(db, tinsert, -1, &tstmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.prepare(msg)
        }
        self.trafficStmt = tstmt
    }

    func close() {
        lock.lock()
        defer { lock.unlock() }
        if let stmt = insertStmt {
            sqlite3_finalize(stmt)
            insertStmt = nil
        }
        if let stmt = trafficStmt {
            sqlite3_finalize(stmt)
            trafficStmt = nil
        }
        if let d = db {
            sqlite3_wal_checkpoint_v2(d, nil, SQLITE_CHECKPOINT_TRUNCATE, nil, nil)
            sqlite3_close(d)
            db = nil
            // Force remove WAL sidecar files
            unlink(path + "-wal")
            unlink(path + "-shm")
        }
    }

    deinit {
        close()
    }

    private let dateFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    private func now() -> String {
        dateFormatter.string(from: Date())
    }

    private func insert(timestamp: String, type: String, pid: Int32, ppid: Int32, process: String, user: uid_t, details: [String: String]) {
        lock.lock()
        defer { lock.unlock() }
        guard let stmt = insertStmt else { return }

        sqlite3_reset(stmt)
        sqlite3_bind_text(stmt, 1, (timestamp as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (type as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 3, pid)
        sqlite3_bind_int(stmt, 4, ppid)
        sqlite3_bind_text(stmt, 5, (process as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 6, Int32(bitPattern: user))

        if let data = try? encoder.encode(details),
           let json = String(data: data, encoding: .utf8) {
            sqlite3_bind_text(stmt, 7, (json as NSString).utf8String, -1, nil)
        } else {
            sqlite3_bind_null(stmt, 7)
        }

        sqlite3_step(stmt)
    }

    /// Log captured HTTP traffic (called from MITM flow)
    func logTraffic(pid: pid_t, host: String, port: UInt16, direction: String, content: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let stmt = trafficStmt else { return }

        sqlite3_reset(stmt)
        sqlite3_bind_text(stmt, 1, (now() as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 2, pid)
        sqlite3_bind_text(stmt, 3, (host as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 4, Int32(port))
        sqlite3_bind_text(stmt, 5, (direction as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 6, (content as NSString).utf8String, -1, nil)

        sqlite3_step(stmt)
    }

    // MARK: - EventSink

    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t) {
        insert(timestamp: now(), type: "exec", pid: pid, ppid: ppid, process: process, user: user, details: ["argv": argv])
    }

    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String]) {
        insert(timestamp: now(), type: type, pid: pid, ppid: ppid, process: process, user: user, details: details)
    }

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16, flowID: UInt64) {
        insert(timestamp: now(), type: "connect", pid: pid, ppid: ppid, process: process, user: user, details: ["addr": remoteAddr, "port": "\(remotePort)", "flowID": "\(flowID)"])
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t, exitStatus: Int32 = 0) {
        insert(timestamp: now(), type: "exit", pid: pid, ppid: ppid, process: process, user: user, details: [:])
    }
}

/// Multiplexer that forwards events to multiple sinks
final class MultiSink: EventSink {
    private let sinks: [EventSink]

    init(_ sinks: [EventSink]) {
        self.sinks = sinks
    }

    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t) {
        for s in sinks { s.onExec(pid: pid, ppid: ppid, process: process, argv: argv, user: user) }
    }

    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String]) {
        for s in sinks { s.onFileOp(type: type, pid: pid, ppid: ppid, process: process, user: user, details: details) }
    }

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16, flowID: UInt64) {
        for s in sinks { s.onConnect(pid: pid, ppid: ppid, process: process, user: user, remoteAddr: remoteAddr, remotePort: remotePort, flowID: flowID) }
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t, exitStatus: Int32 = 0) {
        for s in sinks { s.onExit(pid: pid, ppid: ppid, process: process, user: user, exitStatus: exitStatus) }
    }
}

enum SQLiteLogError: Error, CustomStringConvertible {
    case open(String)
    case schema(String)
    case prepare(String)

    var description: String {
        switch self {
        case .open(let msg): return "Failed to open SQLite database: \(msg)"
        case .schema(let msg): return "Failed to create schema: \(msg)"
        case .prepare(let msg): return "Failed to prepare statement: \(msg)"
        }
    }
}
