import XCTest
import Foundation
@testable import AtlasPCAVerify

final class S2R2PCALockKillTests: XCTestCase {
    func testDefaultLockIsNotRecursive() {
        let l = PCALock()
        let done = DispatchSemaphore(value: 0)
        let t = Thread { l.lock(); l.lock(); done.signal() }
        t.start()
        XCTAssertEqual(done.wait(timeout: .now() + 0.5), .timedOut, "line 11: the default lock excludes its own holder (a plain mutex)")
    }

    func testUnbalancedUnlocksAreCountedUnderContention() {
        let l = PCALock()
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            for _ in 0..<20000 { l.unlock() }
        }
        XCTAssertEqual(l.imbalance, 160000, "line 19: the imbalance counter is guarded by its own lock")
        XCTAssertEqual(l.depth, 0)
    }
}
