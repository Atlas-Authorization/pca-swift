import Foundation
import AtlasPCAVerify
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite3 // Linux: the system SQLite (libsqlite3-dev)
#endif

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// A failure of the database. The stores surface it as a throw, and `authorize` / the executor then fail closed.
public struct SQLiteError: Error, CustomStringConvertible, Equatable {
    public let message: String
    public let code: Int32
    public var description: String { "sqlite: \(message) (code \(code))" }
}

/// A value bound to or read from a statement.
public enum SQLiteValue: Equatable {
    case int(Int64)
    case text(String)
    case null
}

/// One SQLite connection (the system SQLite3), serialized by a lock. Share it between the stores of one process (`SQLiteStateStore`,
/// `SQLiteOperationStore`, `SQLiteAtomicKV`: they then share the connection and its transactions), or open one per worker or process
/// on the same file: SQLite's write lock makes every claim atomic across connections and processes.
public final class SQLiteDatabase: @unchecked Sendable {
    private var handle: OpaquePointer?
    private let lock = NSRecursiveLock()

    /// Opens (creating it if needed) the database at `path` (`":memory:"` for a private in-memory one) with a busy timeout, so writers
    /// that meet a lock wait instead of failing. A file database is switched to WAL when the filesystem allows it.
    public init(path: String, busyTimeoutMs: Int32 = 30_000) throws {
        var h: OpaquePointer?
        let rc = sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let opened = h else {
            let msg = h.map { String(cString: sqlite3_errmsg($0)) } ?? "cannot open the database"
            if let hh = h { sqlite3_close_v2(hh) }
            throw SQLiteError(message: msg, code: rc)
        }
        handle = opened
        sqlite3_busy_timeout(opened, busyTimeoutMs)
        if path != ":memory:" && !path.isEmpty { _ = try? exec("PRAGMA journal_mode=WAL") }
    }

    deinit { close() }

    /// Closes the connection (later calls throw). Idempotent.
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        if let h = handle {
            sqlite3_close_v2(h)
            handle = nil
        }
    }

    private func makeError(_ rc: Int32) -> SQLiteError {
        SQLiteError(message: handle.map { String(cString: sqlite3_errmsg($0)) } ?? "the database is closed", code: rc)
    }

    private func prepare(_ sql: String, _ binds: [SQLiteValue]) throws -> OpaquePointer {
        guard let h = handle else { throw SQLiteError(message: "the database is closed", code: SQLITE_MISUSE) }
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(h, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let s = stmt else {
            if let st = stmt { sqlite3_finalize(st) }
            throw makeError(rc)
        }
        for (i, v) in binds.enumerated() {
            let idx = Int32(i + 1)
            let brc: Int32
            switch v {
            case let .int(x): brc = sqlite3_bind_int64(s, idx, x)
            case let .text(x): brc = sqlite3_bind_text(s, idx, x, -1, SQLITE_TRANSIENT)
            case .null: brc = sqlite3_bind_null(s, idx)
            }
            if brc != SQLITE_OK {
                sqlite3_finalize(s)
                throw makeError(brc)
            }
        }
        return s
    }

    /// Runs statements without parameters or results (DDL, pragmas, transaction control).
    public func exec(_ sql: String) throws {
        lock.lock()
        defer { lock.unlock() }
        guard let h = handle else { throw SQLiteError(message: "the database is closed", code: SQLITE_MISUSE) }
        let rc = sqlite3_exec(h, sql, nil, nil, nil)
        if rc != SQLITE_OK { throw makeError(rc) }
    }

    /// Runs ONE statement and returns the number of rows it changed (INSERT / UPDATE / DELETE).
    @discardableResult
    public func run(_ sql: String, _ binds: [SQLiteValue] = []) throws -> Int {
        lock.lock()
        defer { lock.unlock() }
        let s = try prepare(sql, binds)
        defer { sqlite3_finalize(s) }
        var rc = sqlite3_step(s)
        while rc == SQLITE_ROW { rc = sqlite3_step(s) }
        guard rc == SQLITE_DONE else { throw makeError(rc) }
        guard let h = handle else { throw SQLiteError(message: "the database is closed", code: SQLITE_MISUSE) }
        return Int(sqlite3_changes(h))
    }

    /// Runs a query and returns its rows.
    public func query(_ sql: String, _ binds: [SQLiteValue] = []) throws -> [[SQLiteValue]] {
        lock.lock()
        defer { lock.unlock() }
        let s = try prepare(sql, binds)
        defer { sqlite3_finalize(s) }
        var rows: [[SQLiteValue]] = []
        while true {
            let rc = sqlite3_step(s)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else { throw makeError(rc) }
            var row: [SQLiteValue] = []
            for c in 0..<sqlite3_column_count(s) {
                switch sqlite3_column_type(s, c) {
                case SQLITE_INTEGER: row.append(.int(sqlite3_column_int64(s, c)))
                case SQLITE_NULL: row.append(.null)
                default: row.append(sqlite3_column_text(s, c).map { .text(String(cString: $0)) } ?? .null)
                }
            }
            rows.append(row)
        }
        return rows
    }

    /// Runs `body` inside a write transaction (`BEGIN IMMEDIATE`: it takes SQLite's write lock up front, so a read-modify-write is atomic
    /// across connections and processes). A throw rolls back.
    public func transaction<T>(_ body: () throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        try exec("BEGIN IMMEDIATE")
        do {
            let out = try body()
            try exec("COMMIT")
            return out
        } catch {
            _ = try? exec("ROLLBACK")
            throw error
        }
    }

    /// A table name the stores may interpolate: letters, digits and `_`, not starting with a digit.
    static func validTable(_ t: String) -> Bool {
        guard !t.isEmpty, t.utf8.count <= 63, let f = t.utf8.first, !(f >= 0x30 && f <= 0x39) else { return false }
        return t.utf8.allSatisfy { ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5f }
    }

    static func checkedTable(_ t: String) throws -> String {
        guard validTable(t) else { throw SQLiteError(message: "invalid table name '\(t)'", code: SQLITE_MISUSE) }
        return t
    }
}
