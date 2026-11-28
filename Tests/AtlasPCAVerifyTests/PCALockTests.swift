import XCTest
import Foundation
@testable import AtlasPCAVerify

final class PCALockTests: XCTestCase {
    func testCountsAcquisitionsAndDepth() {
        let l = PCALock()
        XCTAssertEqual(l.acquisitions, 0)
        XCTAssertEqual(l.depth, 0)
        l.lock()
        XCTAssertEqual(l.acquisitions, 1)
        XCTAssertEqual(l.depth, 1)
        l.unlock()
        XCTAssertEqual(l.depth, 0)
        XCTAssertEqual(l.imbalance, 0)
        l.lock(); l.unlock()
        XCTAssertEqual(l.acquisitions, 2)
    }

    func testAnUnlockWithoutALockIsCountedAndNeverReachesTheMutex() {
        let l = PCALock()
        l.unlock()
        XCTAssertEqual(l.imbalance, 1)
        XCTAssertEqual(l.depth, 0)
        l.lock() // the mutex is still usable and was not unlocked twice
        XCTAssertEqual(l.depth, 1)
        l.unlock()
        XCTAssertEqual(l.imbalance, 1)
    }

    func testRecursiveNestsAndPlainExcludes() {
        let r = PCALock(recursive: true)
        r.lock(); r.lock()
        XCTAssertEqual(r.depth, 2)
        r.unlock(); r.unlock()
        XCTAssertEqual(r.depth, 0)
        // the plain lock really excludes: a second thread cannot take it while it is held
        let p = PCALock()
        p.lock()
        let got = DispatchSemaphore(value: 0)
        DispatchQueue.global().async { p.lock(); got.signal(); p.unlock() }
        XCTAssertEqual(got.wait(timeout: .now() + 0.2), .timedOut)
        p.unlock()
        XCTAssertEqual(got.wait(timeout: .now() + 5), .success)
    }
}
