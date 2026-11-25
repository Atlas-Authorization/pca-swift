import XCTest
import AtlasPCAPairing
import CBlst

/// Directed tests of Sources/CBlst/pca_gt.c beyond the reference corpus: every exponent bit, every coordinate's canonical check (aliases
/// c + p of a valid coordinate), both operands, identity and infinity inputs, and on-curve points outside the prime-order subgroups.
/// They are the oracles of the hand mutants in c-mutants/pca_gt.mutants.json.
final class GtShimEdgeTests: XCTestCase {
    private static func hexBytes(_ h: String) -> [UInt8] {
        let c = Array(h.utf8).map { $0 > 57 ? $0 - 87 : $0 - 48 }
        return stride(from: 0, to: c.count, by: 2).map { c[$0] << 4 | c[$0 + 1] }
    }
    private static let p: [UInt8] = GtShimEdgeTests.hexBytes("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
    /// compressed points on E(Fp) and E'(Fp2) that are not in the prime-order subgroups (x = 4 on G1's curve, x = 2 on G2's)
    private static let g1Outside: [UInt8] = [0x80] + [UInt8](repeating: 0, count: 46) + [4]
    private static let g2Outside: [UInt8] = [0x80] + [UInt8](repeating: 0, count: 94) + [2]
    private static let g1Inf: [UInt8] = [0xc0] + [UInt8](repeating: 0, count: 47)
    private static let g2Inf: [UInt8] = [0xc0] + [UInt8](repeating: 0, count: 95)

    private static var one: [UInt8] { var o = [UInt8](repeating: 0, count: 576); o[47] = 1; return o }
    private let g1 = G1.generator.compressed, g2 = G2.generator.compressed

    private func e(_ n: UInt64 = 1) throws -> [UInt8] { try XCTUnwrap(Gt.pairing([(Fr(n) * G1.generator).compressed], [g2])) }
    private static func bit(_ k: [UInt8], _ j: Int) -> Bool { (k[31 - j / 8] >> UInt8(j % 8)) & 1 == 1 }
    private static func exponent(bit j: Int) -> [UInt8] { var k = [UInt8](repeating: 0, count: 32); k[31 - j / 8] = UInt8(1) << UInt8(j % 8); return k }
    /// coordinate i of the encoding replaced by its alias c + p (the same field element, not canonical)
    private static func alias(_ gt: [UInt8], _ i: Int) -> [UInt8] {
        var out = gt, carry = 0
        for b in stride(from: 47, through: 0, by: -1) {
            let s = Int(gt[48 * i + b]) + Int(p[b]) + carry
            out[48 * i + b] = UInt8(s & 0xff); carry = s >> 8
        }
        XCTAssertEqual(carry, 0)
        return out
    }

    func testPowEveryExponentBit() throws {
        let base = try e(1)
        var sq = [base]
        for _ in 1..<256 { sq.append(try XCTUnwrap(Gt.mul(sq.last!, sq.last!))) }
        for j in 0..<256 { XCTAssertEqual(Gt.pow(base, Self.exponent(bit: j)), sq[j], "e^(2^\(j))") }
        var ks: [[UInt8]] = [[UInt8](repeating: 0xff, count: 32), [UInt8](repeating: 0xa5, count: 32), [UInt8](repeating: 0x5a, count: 32), (0..<32).map { UInt8(($0 * 37 + 11) & 0xff) }]
        var x: UInt64 = 0x9e3779b97f4a7c15
        for _ in 0..<4 { ks.append((0..<32).map { _ in x = x &* 6364136223846793005 &+ 1442695040888963407; return UInt8(truncatingIfNeeded: x >> 33) }) }
        for k in ks {
            var want = Self.one
            for j in 0..<256 where Self.bit(k, j) { want = try XCTUnwrap(Gt.mul(want, sq[j])) }
            XCTAssertEqual(Gt.pow(base, k), want, "k = \(k)")
        }
        XCTAssertEqual(Gt.pow(base, [UInt8](repeating: 0, count: 32)), Self.one, "e^0 is the identity")
        // the group order r annihilates GT: the reference exponent is the one pca_gt_is_element uses
        let r = Self.hexBytes("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
        XCTAssertEqual(Gt.pow(base, r), Self.one, "e^r is the identity")
    }

    func testMulIsTheFieldProduct() throws {
        let e1 = try e(1), e2 = try e(2), e3 = try e(3)
        XCTAssertEqual(Gt.mul(e1, e2), e3)
        XCTAssertEqual(Gt.mul(e2, e1), e3)
        XCTAssertEqual(Gt.mul(e1, Self.one), e1)
        XCTAssertEqual(Gt.mul(Self.one, e2), e2)
    }

    func testNonCanonicalCoordinatesAreRefusedEverywhere() throws {
        let e1 = try e(1)
        var k = [UInt8](repeating: 0, count: 32); k[31] = 3
        XCTAssertTrue(Gt.isElement(e1))
        for i in 0..<12 {
            for bad in [Self.alias(e1, i), { var b = e1; for t in 0..<48 { b[48 * i + t] = 0xff }; return b }()] {
                XCTAssertNil(Gt.mul(bad, e1), "first operand, coordinate \(i)")
                XCTAssertNil(Gt.mul(e1, bad), "second operand, coordinate \(i)")
                XCTAssertNil(Gt.pow(bad, k), "pow base, coordinate \(i)")
                XCTAssertFalse(Gt.isElement(bad), "isElement, coordinate \(i)")
            }
        }
    }

    func testIdentityAndNonSubgroupElementsAreNotElements() throws {
        XCTAssertFalse(Gt.isElement(Self.one), "the identity is not an element")
        var two = Self.one; two[47] = 2
        XCTAssertFalse(Gt.isElement(two), "the Fp12 element 2 is not in the order-r subgroup")
        XCTAssertTrue(Gt.isElement(try e(5)))
        XCTAssertFalse(Gt.isElement([UInt8](repeating: 0, count: 575)))
    }

    func testPairingProductOfSeveralPairs() throws {
        let two = (Fr(2) * G1.generator).compressed
        let want = try XCTUnwrap(Gt.mul(try e(1), try e(2)))
        XCTAssertEqual(Gt.pairing([g1, two], [g2, g2]), want)
        XCTAssertEqual(Gt.pairing([two, g1], [g2, g2]), want)
        XCTAssertEqual(Gt.pairing([g1, two, g1], [g2, g2, g2]), try XCTUnwrap(Gt.mul(want, try e(1))))
        XCTAssertNil(Gt.pairing([], []))
        // the C entry point itself refuses an empty product
        var out = [UInt8](repeating: 0, count: 576)
        XCTAssertEqual(pca_gt_pairing(&out, nil, nil, 0), 0)
    }

    func testPairingRefusesInfinityAndPointsOutsideTheSubgroups() {
        XCTAssertNil(Gt.pairing([Self.g1Inf], [g2]), "G1 infinity")
        XCTAssertNil(Gt.pairing([g1], [Self.g2Inf]), "G2 infinity")
        XCTAssertNil(Gt.pairing([Self.g1Inf], [Self.g2Inf]), "both infinity")
        XCTAssertNil(Gt.pairing([g1, Self.g1Inf], [g2, g2]), "G1 infinity in a later pair")
        XCTAssertNil(Gt.pairing([g1, g1], [g2, Self.g2Inf]), "G2 infinity in a later pair")
        XCTAssertNil(Gt.pairing([Self.g1Outside], [g2]), "G1 point on the curve, outside the subgroup")
        XCTAssertNil(Gt.pairing([g1], [Self.g2Outside]), "G2 point on the curve, outside the subgroup")
        XCTAssertNil(Gt.pairing([Self.g1Outside], [Self.g2Outside]), "both outside")
        // a valid compressed encoding with the compression flag cleared is no point
        var u1 = g1; u1[0] &= 0x7f
        var u2 = g2; u2[0] &= 0x7f
        XCTAssertNil(Gt.pairing([u1], [g2]))
        XCTAssertNil(Gt.pairing([g1], [u2]))
    }
}
