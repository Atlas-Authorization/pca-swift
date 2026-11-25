import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCASQLite

/// SQLiteDatabase.swift 30 / 106 / 114: a non-recursive lock, a statement loop that never ends, a dropped lock. Each call runs under a deadline.
final class A0DeadlineSQLiteDatabaseTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private final class Box<T>: @unchecked Sendable {
        private let l = NSLock()
        private var v: T?
        func set(_ x: T) { l.lock(); v = x; l.unlock() }
        func get() -> T? { l.lock(); defer { l.unlock() }; return v }
    }

    private func within<T>(_ what: String, file: StaticString = #filePath, line: UInt = #line, _ body: @escaping @Sendable () -> T) -> T? {
        let box = Box<T>()
        let done = DispatchSemaphore(value: 0)
        let t = Thread { box.set(body()); done.signal() }
        t.stackSize = 8 << 20
        t.start()
        if done.wait(timeout: .now() + 10) == .timedOut {
            XCTFail("\(what): did not finish within 10 s", file: file, line: line)
            return nil
        }
        return box.get()
    }

    func testA1RunStepsAnInsertOnce() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        try db.exec("CREATE TABLE t (k INTEGER)")
        let changed: Int? = within("run insert") { (try? db.run("INSERT INTO t (k) VALUES (?1)", [.int(5)])) ?? -1 }
        XCTAssertEqual(changed, 1, "line 106")
        XCTAssertEqual(try db.query("SELECT COUNT(*) FROM t"), [[.int(1)]], "exactly one row")
    }

    func testA2TransactionNestsTheLock() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        let before = db.lock.acquisitions
        let n: Int? = within("transaction with a statement") {
            (try? db.transaction { () throws -> Int in
                try db.exec("CREATE TABLE t (k INTEGER)")
                return try db.run("INSERT INTO t (k) VALUES (1)")
            }) ?? -1
        }
        XCTAssertEqual(n, 1, "line 30")
        XCTAssertEqual(db.lock.depth, 0, "line 114: the transaction released the lock it took")
        XCTAssertEqual(db.lock.imbalance, 0, "line 114: no unlock without a lock")
        XCTAssertEqual(db.lock.acquisitions, before + 5, "line 114: the transaction, BEGIN, CREATE, INSERT, COMMIT each take the lock")
    }
}
