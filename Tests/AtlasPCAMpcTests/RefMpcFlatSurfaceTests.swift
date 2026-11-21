import XCTest
@testable import AtlasPCAMpc

/// The reference's flat names (field helpers and the byte-level Ed25519 group surface), beyond what the corpus replays reach.
final class RefMpcFlatSurfaceTests: XCTestCase {
    typealias M = PCAMpc
    static func le(_ y: [UInt8]) -> [UInt8] { y + [UInt8](repeating: 0, count: 32 - y.count) }

    func testFieldNamesReduceOperands() {
        let p = M.Field.prime
        XCTAssertEqual(M.fadd(p, 5), 5)
        XCTAssertEqual(M.fadd(p - 1, 1), 0)
        XCTAssertEqual(M.fsub(2, 5), p - 3)
        XCTAssertEqual(M.fmul(p + 3, p + 4), 12)
        XCTAssertEqual(M.fmul(UInt64.max, 1), UInt64.max % p)
        XCTAssertEqual(M.mod("-1"), p - 1)
        XCTAssertEqual(M.mod("18446744073709551616"), 8) // 2^64 mod (2^61 - 1)
        XCTAssertNil(M.mod("1.5"))
        XCTAssertNil(M.mod(""))
    }

    func testOrderConstant() {
        XCTAssertEqual(M.LDecimal, "7237005577332262213973186563042994240857116359379907606001950938285454250989")
        XCTAssertEqual(M.L.count, 32)
        XCTAssertEqual(M.L, M.Sodium.L)
    }

    func testGroupSurface() throws {
        let base = M.Ec.compressPoint(M.Ec.base)
        let identity = Self.le([1])
        let order2 = Self.le([0xec] + [UInt8](repeating: 0xff, count: 30) + [0x7f]).prefix(32).map { $0 } // (0, -1)
        XCTAssertTrue(M.isOnCurve(base))
        XCTAssertTrue(M.isInSubgroup(base))
        XCTAssertNoThrow(try M.assertInSubgroup(base))
        XCTAssertTrue(M.equal(base, base))
        XCTAssertFalse(M.equal(base, identity))
        // the identity and a small-order point are on the curve but not admissible
        XCTAssertTrue(M.isOnCurve(identity))
        XCTAssertFalse(M.isInSubgroup(identity))
        XCTAssertThrowsError(try M.assertInSubgroup(identity, "S")) { XCTAssertEqual(($0 as? M.PointValidationError)?.description, "S: identity element (forbidden here)") }
        XCTAssertEqual(order2.count, 32)
        XCTAssertTrue(M.isOnCurve(order2))
        XCTAssertFalse(M.isInSubgroup(order2))
        XCTAssertThrowsError(try M.assertInSubgroup(order2, "R")) { XCTAssertEqual(($0 as? M.PointValidationError)?.description, "R: not in the prime-order subgroup (small-order/cofactor)") }
        // not a point: wrong length, non-canonical y (y = p, which would reduce to the identity), a y with no x
        let nonCanonical = [UInt8](repeating: 0xff, count: 31) + [0x7f]
        XCTAssertFalse(M.isOnCurve([1, 2, 3]))
        XCTAssertFalse(M.isOnCurve(nonCanonical))
        XCTAssertFalse(M.isOnCurve(Self.le([2])))
        XCTAssertThrowsError(try M.assertInSubgroup(Self.le([2]), "P")) { XCTAssertEqual(($0 as? M.PointValidationError)?.description, "P: not on curve") }
        XCTAssertThrowsError(try M.decodePoint(nonCanonical)) { XCTAssertEqual(($0 as? M.PointValidationError)?.description, "decodePoint: point not on curve") }
        XCTAssertThrowsError(try M.encodePoint(Self.le([2]))) { XCTAssertEqual(($0 as? M.PointValidationError)?.description, "encodePoint: point not on curve") }
        XCTAssertFalse(M.equal(Self.le([2]), Self.le([2])), "an off-curve point equals nothing, not even itself")
    }
}
