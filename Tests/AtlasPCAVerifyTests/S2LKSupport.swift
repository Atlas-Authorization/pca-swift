import XCTest
@testable import AtlasPCAVerify

/// Deterministic lock checks: a method that takes the lock must take it exactly `expect` times and give it back (a dropped lock() shows
/// as a missing acquisition and an unbalanced unlock, a dropped unlock() as a held depth).
enum S2LK {
    static func check<T>(_ lock: PCALock, _ what: String, expect: Int = 1, file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> T) rethrows -> T {
        let a = lock.acquisitions
        let r = try body()
        XCTAssertEqual(lock.acquisitions, a + expect, "\(what): acquisitions", file: file, line: line)
        XCTAssertEqual(lock.depth, 0, "\(what): the lock is released", file: file, line: line)
        XCTAssertEqual(lock.imbalance, 0, "\(what): no unlock without a lock", file: file, line: line)
        return r
    }
}
