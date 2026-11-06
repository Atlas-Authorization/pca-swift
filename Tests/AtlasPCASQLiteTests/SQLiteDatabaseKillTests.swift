import XCTest
import Foundation
@testable import AtlasPCASQLite

/// SQLiteDatabase at its edges: the default busy timeout, WAL only for a file database, text values with an embedded NUL, and every
/// character class boundary of the table-name rule (checked directly: an invalid name that reaches SQL fails there anyway).
final class SQLiteDatabaseKillTests: XCTestCase {
    var path = ""
    override func setUp() {
        super.setUp()
        path = FileManager.default.temporaryDirectory.appendingPathComponent("pca-kill-\(UUID().uuidString).sqlite").path
    }
    override func tearDown() {
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
        super.tearDown()
    }

    func testDefaultBusyTimeoutIs30Seconds() throws {
        XCTAssertEqual(try SQLiteDatabase(path: ":memory:").query("PRAGMA busy_timeout"), [[.int(30_000)]])
        XCTAssertEqual(try SQLiteDatabase(path: ":memory:", busyTimeoutMs: 5).query("PRAGMA busy_timeout"), [[.int(5)]])
    }

    func testWALOnlyForAFileDatabase() throws {
        XCTAssertEqual(try SQLiteDatabase(path: path).query("PRAGMA journal_mode"), [[.text("wal")]])
        XCTAssertEqual(try SQLiteDatabase(path: ":memory:").query("PRAGMA journal_mode"), [[.text("memory")]])
        XCTAssertNotEqual(try SQLiteDatabase(path: "").query("PRAGMA journal_mode"), [[.text("wal")]])
    }

    func testTextWithAnEmbeddedNULRoundTrips() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        try db.exec("CREATE TABLE t (k TEXT PRIMARY KEY)")
        XCTAssertEqual(try db.run("INSERT INTO t (k) VALUES (?)", [.text("a\u{0}b")]), 1)
        XCTAssertEqual(try db.run("INSERT INTO t (k) VALUES (?)", [.text("a\u{0}c")]), 1) // a distinct key, not a second "a"
        XCTAssertEqual(try db.query("SELECT k FROM t ORDER BY k"), [[.text("a\u{0}b")], [.text("a\u{0}c")]])
        XCTAssertEqual(try db.query("SELECT length(CAST(k AS BLOB)) FROM t WHERE k = ?", [.text("a\u{0}b")]), [[.int(3)]])
        XCTAssertEqual(try db.query("SELECT 'é'"), [[.text("é")]])
    }

    func testTableNameRule() {
        for ok in ["a", "A", "Z", "z", "_", "aZ", "az", "a0", "a9", "_9", "Az_09", String(repeating: "a", count: 63)] {
            XCTAssertTrue(SQLiteDatabase.validTable(ok), ok)
        }
        for bad in ["", "0a", "9a", "5", String(repeating: "a", count: 64), "a-", "a ", "a@", "a[", "a`", "a{", "a/", "a:", "a\u{7f}", "aé"] {
            XCTAssertFalse(SQLiteDatabase.validTable(bad), bad)
        }
    }
}
