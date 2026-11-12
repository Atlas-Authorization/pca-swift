import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Ed25519Torsion.isPrimeOrder cache (mutation round 2, survivors sheet 3): the two critical sections take and release the counted
/// lock, a hit skips the second one, the result is stored, and the cache is emptied once it holds more than 8192 entries.
final class S2R3TorsionCacheKillTests: XCTestCase {
    typealias T = Ed25519Torsion

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    private func clear() {
        T.cacheLock.lock()
        T.cache.removeAll()
        T.cacheLock.unlock()
    }

    private func key(_ i: Int) -> [UInt8] { [UInt8(i & 0xff), UInt8((i >> 8) & 0xff)] } // not 32 bytes: decode refuses at once, the verdict (false) is cached

    func testMissLocksTwiceHitLocksOnceAndTheVerdictIsStored() {
        clear()
        let base: [UInt8] = [0x58] + [UInt8](repeating: 0x66, count: 31)
        let a = T.cacheLock.acquisitions
        XCTAssertTrue(T.isPrimeOrder(base))
        XCTAssertEqual(T.cacheLock.acquisitions, a + 2, "lines 163 and 178: a miss takes the lock to look up and again to store")
        XCTAssertEqual(T.cacheLock.depth, 0, "the lock is released")
        XCTAssertEqual(T.cacheLock.imbalance, 0, "no unlock without a lock (lines 163, 178)")
        XCTAssertEqual(T.cache[base], true, "line 180: the verdict is stored")
        XCTAssertTrue(T.isPrimeOrder(base))
        XCTAssertEqual(T.cacheLock.acquisitions, a + 3, "line 164: a hit returns after the first critical section")
        XCTAssertEqual(T.cacheLock.depth, 0)
        XCTAssertEqual(T.cacheLock.imbalance, 0)
        clear()
    }

    func testCacheIsEmptiedOnlyOncePastEightThousandOneHundredNinetyTwoEntries() {
        clear()
        for i in 0..<8192 { _ = T.isPrimeOrder(key(i)) }
        XCTAssertEqual(T.cache.count, 8192, "line 179: nothing is emptied while the count is 8192 or less (kills !(>) and a lower bound)")
        _ = T.isPrimeOrder(key(8192))
        XCTAssertEqual(T.cache.count, 8193, "line 179: a count of exactly 8192 is not emptied (kills >= and 8191)")
        _ = T.isPrimeOrder(key(8193))
        XCTAssertEqual(T.cache.count, 1, "line 179: a count of 8193 is emptied before the insert (kills 8193)")
        clear()
    }
}
