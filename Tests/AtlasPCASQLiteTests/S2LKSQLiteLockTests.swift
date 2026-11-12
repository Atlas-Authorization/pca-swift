import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCASQLite

/// SQLiteDatabase takes its (recursive) lock once per call and releases it; `transaction` nests `exec` twice (BEGIN, COMMIT).
final class S2LKSQLiteLockTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    private func check<T>(_ lock: PCALock, _ what: String, expect: Int = 1, _ body: () throws -> T) rethrows -> T {
        let a = lock.acquisitions
        let r = try body()
        XCTAssertEqual(lock.acquisitions, a + expect, "\(what): acquisitions")
        XCTAssertEqual(lock.depth, 0, "\(what): the lock is released")
        XCTAssertEqual(lock.imbalance, 0, "\(what): no unlock without a lock")
        return r
    }

    func testEveryCallTakesTheLock() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        try check(db.lock, "exec") { try db.exec("CREATE TABLE t (k INTEGER)") }
        _ = try check(db.lock, "run") { try db.run("INSERT INTO t (k) VALUES (?1)", [.int(1)]) }
        let rows = try check(db.lock, "query") { try db.query("SELECT k FROM t") }
        XCTAssertEqual(rows.count, 1)
        let v = try check(db.lock, "transaction", expect: 3) { try db.transaction { 7 } }
        XCTAssertEqual(v, 7)
        let w = try check(db.lock, "transaction with a statement", expect: 4) { try db.transaction { try db.run("INSERT INTO t (k) VALUES (2)") } }
        XCTAssertEqual(w, 1)
        XCTAssertThrowsError(try check(db.lock, "transaction that throws", expect: 3) { try db.transaction { () throws -> Int in throw SQLiteError(message: "x", code: 1) } })
        XCTAssertEqual(try db.query("SELECT k FROM t").count, 2, "the throwing transaction changed nothing")
        check(db.lock, "close") { db.close() }
        check(db.lock, "close again") { db.close() }
        XCTAssertThrowsError(try check(db.lock, "exec after close") { try db.exec("SELECT 1") })
    }
}
