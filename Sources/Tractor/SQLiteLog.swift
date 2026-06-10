import Darwin
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

    /// When false, every event handler short-circuits without writing.
    /// Lets the GUI's Record toggle gate SQLite writes without tearing down
    /// the trace session.
    var isEnabled: Bool = true

    /// Count of events actually written to the DB (i.e., handlers that ran
    /// while isEnabled was true). Read from the GUI footer to display
    /// "Recording — N events".
    private(set) var recordedCount: Int = 0

    let path: String
    let runID: Int64

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
        chmod(path, S_IRUSR | S_IWUSR)

        sqlite3_exec(db, "PRAGMA journal_mode=WAL", nil, nil, nil)

        // WAL creates sidecar files — own them too
        chown(path + "-wal", ownerUid, ownerGid)
        chown(path + "-shm", ownerUid, ownerGid)
        chmod(path + "-wal", S_IRUSR | S_IWUSR)
        chmod(path + "-shm", S_IRUSR | S_IWUSR)

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
        try Self.ensureColumn(db: db!, table: "events", column: "run_id", type: "INTEGER")

        let createTraffic = """
            CREATE TABLE IF NOT EXISTS http_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
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
        try Self.ensureColumn(db: db!, table: "http_traffic", column: "run_id", type: "INTEGER")

        let createRuns = """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                command TEXT
            )
            """
        guard sqlite3_exec(db, createRuns, nil, nil, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.schema(msg)
        }

        let startedAt = TraceTimestamp.now()
        var runStmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "INSERT INTO runs (started_at, command) VALUES (?, ?)", -1, &runStmt, nil) == SQLITE_OK,
              let runInsert = runStmt else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.prepare(msg)
        }
        sqlite3_bind_text(runInsert, 1, (startedAt as NSString).utf8String, -1, nil)
        let command = CommandLine.arguments.joined(separator: " ")
        sqlite3_bind_text(runInsert, 2, (command as NSString).utf8String, -1, nil)
        guard sqlite3_step(runInsert) == SQLITE_DONE else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_finalize(runInsert)
            sqlite3_close(db)
            throw SQLiteLogError.prepare(msg)
        }
        sqlite3_finalize(runInsert)
        self.runID = sqlite3_last_insert_rowid(db)

        var stmt: OpaquePointer?
        let insert = "INSERT INTO events (run_id, timestamp, type, pid, ppid, process, user, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        guard sqlite3_prepare_v2(db, insert, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.prepare(msg)
        }
        self.insertStmt = stmt

        var tstmt: OpaquePointer?
        let tinsert = "INSERT INTO http_traffic (run_id, timestamp, pid, host, port, direction, content) VALUES (?, ?, ?, ?, ?, ?, ?)"
        guard sqlite3_prepare_v2(db, tinsert, -1, &tstmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db!))
            sqlite3_close(db)
            throw SQLiteLogError.prepare(msg)
        }
        self.trafficStmt = tstmt
    }

    private static func ensureColumn(db: OpaquePointer, table: String, column: String, type: String) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(\(table))", -1, &stmt, nil) == SQLITE_OK,
              let info = stmt else {
            throw SQLiteLogError.schema(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(info) }
        while sqlite3_step(info) == SQLITE_ROW {
            if let c = sqlite3_column_text(info, 1), String(cString: c) == column {
                return
            }
        }
        let sql = "ALTER TABLE \(table) ADD COLUMN \(column) \(type)"
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw SQLiteLogError.schema(String(cString: sqlite3_errmsg(db)))
        }
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

    private func now() -> String {
        TraceTimestamp.now()
    }

    private func insert(timestamp: String, type: String, pid: Int32, ppid: Int32, process: String, user: uid_t, details: [String: String]) {
        lock.lock()
        defer { lock.unlock() }
        guard let stmt = insertStmt else { return }

        sqlite3_reset(stmt)
        sqlite3_bind_int64(stmt, 1, runID)
        sqlite3_bind_text(stmt, 2, (timestamp as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 3, (type as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 4, pid)
        sqlite3_bind_int(stmt, 5, ppid)
        sqlite3_bind_text(stmt, 6, (process as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 7, Int32(bitPattern: user))

        if let data = try? encoder.encode(details),
           let json = String(data: data, encoding: .utf8) {
            sqlite3_bind_text(stmt, 8, (json as NSString).utf8String, -1, nil)
        } else {
            sqlite3_bind_null(stmt, 8)
        }

        sqlite3_step(stmt)
    }

    /// Log captured HTTP traffic (called from MITM flow)
    func logTraffic(pid: pid_t, host: String, port: UInt16, direction: String, content: String) {
        guard isEnabled else { return }
        recordedCount &+= 1
        lock.lock()
        defer { lock.unlock() }
        guard let stmt = trafficStmt else { return }

        sqlite3_reset(stmt)
        sqlite3_bind_int64(stmt, 1, runID)
        sqlite3_bind_text(stmt, 2, (now() as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 3, pid)
        sqlite3_bind_text(stmt, 4, (host as NSString).utf8String, -1, nil)
        sqlite3_bind_int(stmt, 5, Int32(port))
        sqlite3_bind_text(stmt, 6, (direction as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 7, (content as NSString).utf8String, -1, nil)

        sqlite3_step(stmt)
    }

    // MARK: - EventSink

    func onExec(pid: pid_t, ppid: pid_t, process: String, argv: String, user: uid_t) {
        guard isEnabled else { return }
        recordedCount &+= 1
        insert(timestamp: now(), type: "exec", pid: pid, ppid: ppid, process: process, user: user, details: ["argv": argv])
    }

    func onFileOp(type: String, pid: pid_t, ppid: pid_t, process: String, user: uid_t, details: [String: String]) {
        guard isEnabled else { return }
        recordedCount &+= 1
        insert(timestamp: now(), type: type, pid: pid, ppid: ppid, process: process, user: user, details: details)
    }

    func onConnect(pid: pid_t, ppid: pid_t, process: String, user: uid_t, remoteAddr: String, remotePort: UInt16, flowID: UInt64) {
        guard isEnabled else { return }
        recordedCount &+= 1
        insert(timestamp: now(), type: "connect", pid: pid, ppid: ppid, process: process, user: user, details: ["addr": remoteAddr, "port": "\(remotePort)", "flowID": "\(flowID)"])
    }

    func onExit(pid: pid_t, ppid: pid_t, process: String, user: uid_t, exitStatus: Int32 = 0) {
        guard isEnabled else { return }
        recordedCount &+= 1
        insert(timestamp: now(), type: "exit", pid: pid, ppid: ppid, process: process, user: user, details: [:])
    }

    /// Reset the counter — called when the GUI's Record toggle flips from off to on.
    func resetRecordedCount() {
        recordedCount = 0
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
