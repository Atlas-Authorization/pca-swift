import XCTest
import Foundation
@testable import AtlasPCASQLite

/// Kills the SQLiteDatabase.swift survivors of group 5: close really closes (a clean WAL close removes the -wal / -shm files), a failed
/// bind leaves no statement behind, close is idempotent, and a throwing transaction is rolled back.
final class S2G5SQLiteDatabaseKillTests: XCTestCase {
    var path = ""
    override func setUp() {
        super.setUp()
        path = FileManager.default.temporaryDirectory.appendingPathComponent("pca-s2g5-\(UUID().uuidString).sqlite").path
    }
    override func tearDown() {
        for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) }
        super.tearDown()
    }

    private func exists(_ suffix: String) -> Bool { FileManager.default.fileExists(atPath: path + suffix) }

    func testCloseReleasesTheConnection() throws {
        #if !os(Linux)
        throw XCTSkip("the system SQLite on this OS keeps the -wal file after the last close")
        #endif
        let db = try SQLiteDatabase(path: path)
        try db.exec("CREATE TABLE t (k INTEGER)")
        try db.run("INSERT INTO t (k) VALUES (?)", [.int(1)])
        db.close()
        XCTAssertFalse(exists("-wal"), "line 56: the last connection to close removes the -wal file")
        XCTAssertFalse(exists("-shm"))
        db.close() // idempotent
    }

    func testCallsAfterCloseThrowTheClosedError() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        db.close()
        db.close()
        for call in [{ try db.exec("SELECT 1") }, { _ = try db.run("SELECT 1") }, { _ = try db.query("SELECT 1") }] as [() throws -> Void] {
            XCTAssertThrowsError(try call()) { e in
                XCTAssertEqual((e as? SQLiteError)?.message, "the database is closed", "line 55: the handle is forgotten")
            }
        }
    }

    func testAFailedBindLeavesNoStatementBehind() throws {
        #if !os(Linux)
        throw XCTSkip("the system SQLite on this OS keeps the -wal file after the last close")
        #endif
        let db = try SQLiteDatabase(path: path)
        try db.exec("CREATE TABLE t (k INTEGER)")
        try db.run("INSERT INTO t (k) VALUES (?)", [.int(1)])
        // two values for one parameter: the second bind is out of range and the prepared statement must be finalized (line 82)
        XCTAssertThrowsError(try db.run("INSERT INTO t (k) VALUES (?)", [.int(2), .int(3)]))
        XCTAssertEqual(try db.query("SELECT count(*) FROM t"), [[.int(1)]])
        db.close()
        XCTAssertFalse(exists("-wal"), "an unfinalized statement would keep the connection (and its WAL) alive after close")
    }

    func testAThrowingTransactionIsRolledBack() throws {
        struct Boom: Error {}
        let db = try SQLiteDatabase(path: ":memory:")
        try db.exec("CREATE TABLE t (k INTEGER)")
        XCTAssertThrowsError(try db.transaction { () -> Int in
            try db.run("INSERT INTO t (k) VALUES (?)", [.int(1)])
            throw Boom()
        }) { XCTAssertTrue($0 is Boom) }
        XCTAssertEqual(try db.query("SELECT count(*) FROM t"), [[.int(0)]], "line 148: the insert is rolled back")
        // and no transaction is left open
        XCTAssertEqual(try db.transaction { () -> Int in try db.run("INSERT INTO t (k) VALUES (?)", [.int(2)]) }, 1)
        XCTAssertEqual(try db.query("SELECT k FROM t"), [[.int(2)]])
    }

    /// A second transaction waits for the first instead of failing with "cannot start a transaction within a transaction" (lines 140, 91, 101, 114).
    func testConcurrentTransactionsAreSerialized() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        try db.exec("CREATE TABLE t (k INTEGER)")
        let failures = NSLock()
        var failed = 0
        DispatchQueue.concurrentPerform(iterations: 4) { i in
            do {
                try db.transaction { () -> Void in
                    try db.run("INSERT INTO t (k) VALUES (?)", [.int(Int64(i))])
                    Thread.sleep(forTimeInterval: 0.02)
                }
            } catch {
                failures.lock()
                failed += 1
                failures.unlock()
            }
        }
        XCTAssertEqual(failed, 0)
        XCTAssertEqual(try db.query("SELECT count(*) FROM t"), [[.int(4)]])
    }
}
