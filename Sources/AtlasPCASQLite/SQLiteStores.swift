import Foundation
import AtlasPCAVerify
#if canImport(SQLite3)
import SQLite3
#else
import CSQLite3
#endif

/// A durable replay store on SQLite: one row per counter stream, `key` is the PRIMARY KEY.
///
/// The claim is ONE statement, `INSERT ... ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter WHERE
/// excluded.last_counter > last_counter`, which SQLite runs atomically under its write lock, so concurrent tasks, connections and
/// processes sharing the database file can never both consume the same counter: the claim succeeded iff exactly one row changed. A
/// database error is thrown (`authorize` then denies).
public final class SQLiteStateStore: PCALastStore, @unchecked Sendable {
    public static let DEFAULT_TABLE = "pca_replay"
    private let db: SQLiteDatabase
    private let claimSQL: String
    private let readSQL: String

    /// Creates the table if it does not exist.
    public init(database: SQLiteDatabase, table: String = SQLiteStateStore.DEFAULT_TABLE) throws {
        let t = try SQLiteDatabase.checkedTable(table)
        try database.exec("CREATE TABLE IF NOT EXISTS \(t) (key TEXT NOT NULL PRIMARY KEY, last_counter INTEGER NOT NULL)")
        self.db = database
        claimSQL = "INSERT INTO \(t) (key, last_counter) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter "
            + "WHERE excluded.last_counter > \(t).last_counter"
        readSQL = "SELECT last_counter FROM \(t) WHERE key = ?1"
    }

    /// Opens (or creates) the database file at `path` and the table in it.
    public convenience init(path: String, table: String = SQLiteStateStore.DEFAULT_TABLE) throws {
        try self.init(database: SQLiteDatabase(path: path), table: table)
    }

    public func claim(key: String, counter: Int64) throws -> ClaimResult {
        if try db.run(claimSQL, [.text(key), .int(counter)]) == 1 { return ClaimResult(ok: true) }
        // refused: report the stored counter when it can be read (the decision is already made)
        return ClaimResult(ok: false, lastCounter: try? last(key: key))
    }

    /// The highest admitted counter of a stream (nil: no row yet).
    public func last(key: String) throws -> Int64? {
        guard case let .int(n)? = try db.query(readSQL, [.text(key)]).first?.first else { return nil }
        return n
    }
}

/// A durable `OperationStore` (and `OperationLister`) on SQLite. `create` is one `INSERT ... ON CONFLICT DO NOTHING` and `transition` one
/// conditional `UPDATE ... WHERE state = ?`, so of N concurrent executions of one id (tasks, connections, processes) exactly one creates
/// the record and exactly one wins each transition.
public final class SQLiteOperationStore: OperationLister, @unchecked Sendable {
    public static let DEFAULT_TABLE = "pca_operations"
    private let db: SQLiteDatabase
    private let table: String

    /// Creates the table if it does not exist. Pass the database a `SQLiteStateStore` uses to keep both on the same connection.
    public init(database: SQLiteDatabase, table: String = SQLiteOperationStore.DEFAULT_TABLE) throws {
        let t = try SQLiteDatabase.checkedTable(table)
        try database.exec("CREATE TABLE IF NOT EXISTS \(t) (id TEXT NOT NULL PRIMARY KEY, state TEXT NOT NULL, record TEXT NOT NULL)")
        self.db = database
        self.table = t
    }

    public convenience init(path: String, table: String = SQLiteOperationStore.DEFAULT_TABLE) throws {
        try self.init(database: SQLiteDatabase(path: path), table: table)
    }

    private static func text(_ r: OperationRecord) -> String { r.json.canonicalText }

    private func decode(_ row: [SQLiteValue]?) throws -> OperationRecord? {
        guard case let .text(t)? = row?.first else { return nil }
        guard let v = JSONValue.parse(t), let r = OperationRecord(json: v) else {
            throw SQLiteError(message: "a stored operation record is unreadable", code: SQLITE_CORRUPT)
        }
        return r
    }

    public func create(_ record: OperationRecord) throws -> OperationCreate {
        let n = try db.run("INSERT INTO \(table) (id, state, record) VALUES (?1, ?2, ?3) ON CONFLICT(id) DO NOTHING",
                           [.text(record.id), .text(record.state.rawValue), .text(Self.text(record))])
        if n == 1 { return .created }
        guard let existing = try get(record.id) else {
            throw SQLiteError(message: "the operation record vanished during create", code: SQLITE_BUSY)
        }
        return .existing(existing)
    }

    public func get(_ id: String) throws -> OperationRecord? {
        try decode(try db.query("SELECT record FROM \(table) WHERE id = ?1", [.text(id)]).first)
    }

    public func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool {
        var n = next
        n.id = id
        return try db.run("UPDATE \(table) SET state = ?1, record = ?2 WHERE id = ?3 AND state = ?4",
                          [.text(n.state.rawValue), .text(Self.text(n)), .text(id), .text(from.rawValue)]) == 1
    }

    /// The records still `pending` or `executing`, ordered by id.
    public func listOpen() throws -> [OperationRecord] {
        try db.query("SELECT record FROM \(table) WHERE state IN ('pending', 'executing') ORDER BY id").compactMap { try decode($0) }
    }
}

/// A durable `AtomicKV` on SQLite (the plan registry and `KVOperationStore` run on it). Every `update` is one `BEGIN IMMEDIATE`
/// transaction: SQLite's write lock serializes read-modify-writes across connections and processes.
public final class SQLiteAtomicKV: AtomicKV, @unchecked Sendable {
    public static let DEFAULT_TABLE = "pca_kv"
    private let db: SQLiteDatabase
    private let table: String

    public init(database: SQLiteDatabase, table: String = SQLiteAtomicKV.DEFAULT_TABLE) throws {
        let t = try SQLiteDatabase.checkedTable(table)
        try database.exec("CREATE TABLE IF NOT EXISTS \(t) (k TEXT NOT NULL PRIMARY KEY, v TEXT NOT NULL)")
        self.db = database
        self.table = t
    }

    public convenience init(path: String, table: String = SQLiteAtomicKV.DEFAULT_TABLE) throws {
        try self.init(database: SQLiteDatabase(path: path), table: table)
    }

    private func read(_ key: String) throws -> JSONValue? {
        guard case let .text(t)? = try db.query("SELECT v FROM \(table) WHERE k = ?1", [.text(key)]).first?.first else { return nil }
        guard let v = JSONValue.parse(t) else { throw SQLiteError(message: "a stored value is unreadable", code: SQLITE_CORRUPT) }
        return v
    }

    public func get(_ key: String) throws -> JSONValue? { try read(key) }

    public func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws {
        try db.transaction {
            if let next = f(try read(key)) {
                try db.run("INSERT INTO \(table) (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", [.text(key), .text(next.canonicalText)])
            }
        }
    }
}
