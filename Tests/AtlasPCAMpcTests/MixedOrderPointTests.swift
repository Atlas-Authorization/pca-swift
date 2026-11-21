import XCTest
@testable import AtlasPCAMpc

/// The MPC curve's subgroup test is fail-closed whatever libsodium build answers its validity query: B + T (T of order 2) is mixed-order.
final class MixedOrderPointTests: XCTestCase {
    typealias Ec = PCAMpc.Ec

    func testMixedOrderAndDegeneratePointsAreNotInTheSubgroup() throws {
        let base: [UInt8] = [0x58] + [UInt8](repeating: 0x66, count: 31)
        let t: [UInt8] = [0xec] + [UInt8](repeating: 0xff, count: 30) + [0x7f]   // (0, -1), order 2
        let mixed = try Ec.add(try Ec.decompressPoint(base), try Ec.decompressPoint(t))
        XCTAssertTrue(Ec.isInSubgroup(try Ec.decompressPoint(base)))
        XCTAssertFalse(Ec.isInSubgroup(mixed), "a mixed-order point")
        XCTAssertFalse(Ec.isInSubgroup(try Ec.decompressPoint(t)), "the order-2 point")
        XCTAssertThrowsError(try Ec.assertInSubgroup(mixed))
        var neg = base; neg[31] |= 0x80
        XCTAssertTrue(Ec.isInSubgroup(try Ec.decompressPoint(neg)), "-B")
        XCTAssertThrowsError(try Ec.decompressPoint([0xee] + [UInt8](repeating: 0xff, count: 30) + [0x7f]), "a non-canonical encoding")
    }
}
