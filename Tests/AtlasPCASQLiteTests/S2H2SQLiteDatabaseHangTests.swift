import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCASQLite

/// Round 2, sheet hang2: SQLiteDatabase mutants that deadlock or never finish. The call runs on a thread and the test fails after 3 s.
final class S2H2SQLiteDatabaseHangTests: XCTestCase {
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
        if done.wait(timeout: .now() + 3) == .timedOut {
            XCTFail("\(what): did not finish within 3 s", file: file, line: line)
            return nil
        }
        return box.get()
    }

    /// SQLiteDatabase.swift 30: the lock is recursive, so a transaction (which takes it, then exec takes it again) does not deadlock.
    func testTransactionNestsTheLock() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        let got: Int? = within("transaction") { (try? db.transaction { 7 }) ?? -1 }
        XCTAssertEqual(got, 7, "line 30")
        let n: Int? = within("transaction with a statement") {
            (try? db.transaction { () throws -> Int in
                try db.exec("CREATE TABLE t (k INTEGER)")
                return try db.run("INSERT INTO t (k) VALUES (1)")
            }) ?? -1
        }
        XCTAssertEqual(n, 1, "line 30: statements inside the transaction")
    }

    /// SQLiteDatabase.swift 106: run steps an INSERT once (a mutated loop condition re-runs the finished statement for ever).
    func testRunStepsAnInsertOnce() throws {
        let db = try SQLiteDatabase(path: ":memory:")
        try db.exec("CREATE TABLE t (k INTEGER)")
        let changed: Int? = within("run insert") { (try? db.run("INSERT INTO t (k) VALUES (?1)", [.int(5)])) ?? -1 }
        XCTAssertEqual(changed, 1, "line 106")
        XCTAssertEqual(try db.query("SELECT COUNT(*) FROM t"), [[.int(1)]], "exactly one row")
    }
}
