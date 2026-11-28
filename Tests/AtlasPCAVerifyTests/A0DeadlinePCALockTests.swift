import XCTest
import Foundation
@testable import AtlasPCAVerify

/// PCALock.swift 15-23: a lock that is not released (or an unlock that is miscounted) makes the next lock() wait for ever.
final class A0DeadlinePCALockTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testA1LockUnlockCyclesDoNotDeadlock() {
        let r: [Int]? = S2Deadline.within(10, "plain lock cycles") {
            let l = PCALock()
            l.lock(); l.unlock(); l.lock(); l.unlock()
            return [l.acquisitions, l.depth, l.imbalance]
        }
        XCTAssertEqual(r, [2, 0, 0], "lines 15, 20, 22, 23")
    }

    func testA2RecursiveLockNestsAndReleases() {
        let r: [Int]? = S2Deadline.within(10, "recursive lock") {
            let l = PCALock(recursive: true)
            l.lock(); l.lock(); l.unlock(); l.unlock(); l.lock(); l.unlock()
            return [l.acquisitions, l.depth, l.imbalance]
        }
        XCTAssertEqual(r, [3, 0, 0], "lines 15, 20, 22, 23")
    }

    func testA3UnlockWithoutLockIsCountedAndLockStillWorks() {
        let r: [Int]? = S2Deadline.within(10, "unbalanced unlock") {
            let l = PCALock()
            l.unlock(); l.lock(); l.unlock(); l.lock(); l.unlock()
            return [l.acquisitions, l.depth, l.imbalance]
        }
        XCTAssertEqual(r, [2, 0, 1], "line 20")
    }
}
