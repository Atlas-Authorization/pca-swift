import XCTest
@testable import AtlasPCAVerify

/// The P-224 arithmetic checked by its own definitions (a * a^-1 = 1, order comparisons, X.690 DER), for what a verify of a valid
/// signature cannot see: x^((p-3)/2) is +-1/x by Euler's criterion, and an ECDSA verify does not notice that sign.
final class AttestP224K05Tests: XCTestCase {
    func small(_ v: UInt32, _ k: Int = 7) -> [UInt32] {
        var a = [UInt32](repeating: 0, count: k)
        a[0] = v
        return a
    }

    func testGeqAtAndBelowTheModulus() {
        for f in [P224.F, P224.N] {
            XCTAssertTrue(f.geq(f.n))
            var below = f.n
            below[0] -= 1
            XCTAssertFalse(f.geq(below))
        }
    }

    /// Small values include non-residues of both primes, where the sign of a half-exponent result shows.
    func testInverseIsTheInverse() {
        for f in [P224.F, P224.N] {
            for a in UInt32(2)...31 {
                let m = f.toMont(small(a))
                XCTAssertEqual(f.fromMont(f.mul(f.inv(m), m)), small(1), "\(a)")
            }
        }
    }

    /// 2^64 + 13 is prime; its middle limb is zero, so computing n - 2 meets a limb that subtracts to exactly zero with no borrow.
    func testInverseWhenALimbSubtractsToZero() {
        let f = MontField([13, 0, 1])
        for a: UInt32 in [2, 3, 5] {
            let m = f.toMont(small(a, 3))
            XCTAssertEqual(f.fromMont(f.mul(f.inv(m), m)), small(1, 3), "\(a)")
        }
    }

    func testLimbsAreSevenAndIgnoreHigherBytes() {
        let low = [UInt8](repeating: 1, count: 28)
        XCTAssertEqual(P224.limbs(low).count, 7)
        XCTAssertEqual(P224.limbs([0xff] + low), P224.limbs(low))
        XCTAssertEqual(P224.limbs([0x01, 0x02]), small(0x0102))
    }

    func testLtComparesEveryLimb() {
        let zero = small(0)
        var m = zero
        m[1] = 1
        XCTAssertTrue(P224.lt(zero, m))
        XCTAssertFalse(P224.lt(m, zero))
        XCTAssertFalse(P224.lt(m, m))
    }

    /// A point with y = 0 has order 2: its double is the point at infinity.
    func testDoublingAPointOfOrderTwo() {
        let p: P224.JP = (P224.F.one, small(0), P224.F.one)
        let r = P224.dbl(p)
        XCTAssertTrue(P224.isInf(r))
        XCTAssertEqual(r.x, P224.F.one)
        XCTAssertEqual(r.y, P224.F.one)
    }

    func der(_ r: [UInt8], _ s: [UInt8]) -> [UInt8] {
        var out: [UInt8] = [0x30, UInt8(4 + r.count + s.count), 0x02, UInt8(r.count)]
        out += r
        out += [0x02, UInt8(s.count)]
        out += s
        return out
    }

    func testDerIntegersAreMinimal() {
        XCTAssertEqual(P224.parseSig(raw: nil, der: der([1], [2]))?.r, P224.limbs([1]))
        XCTAssertEqual(P224.parseSig(raw: nil, der: der([1], [2]))?.s, P224.limbs([2]))
        XCTAssertEqual(P224.parseSig(raw: nil, der: der([0, 0x80], [1]))?.r, P224.limbs([0x80]), "the sign byte is stripped")
        XCTAssertNil(P224.parseSig(raw: nil, der: der([0, 1], [1])), "a redundant leading zero")
        XCTAssertNil(P224.parseSig(raw: nil, der: der([1], [0, 1])), "a redundant leading zero in s")
        XCTAssertNil(P224.parseSig(raw: nil, der: der([0x80], [1])), "negative")
    }
}
