import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCAMpc

/// The flat reference names of the MPC package (the arithmetic and authenticated-share replays run through them in RefMpcTests).
final class MpcSurfaceTests: XCTestCase {
    typealias M = PCAMpc

    func testGenTriplesAreIndependentTriples() throws {
        var g = M.Field.Rng(seed: 5)
        let ts = try M.genTriples(4, 3, &g)
        XCTAssertEqual(ts.count, 4)
        for t in ts {
            let a = try M.Sharing.reconstruct(t.a), b = try M.Sharing.reconstruct(t.b), c = try M.Sharing.reconstruct(t.c)
            XCTAssertEqual(M.Field.mul(a, b), c)
        }
        XCTAssertEqual(ts[0].a.count, 3)
        var g1 = M.Field.Rng(seed: 5), g2 = M.Field.Rng(seed: 5)
        XCTAssertEqual(try M.genTriples(1, 3, &g1)[0].a, try M.Beaver.genTriple(3, &g2).a)
        XCTAssertEqual(try M.genTriples(0, 3, &g1).count, 0)
    }

    func testFieldRandomIsSeededOrSecure() {
        var a = M.fieldRandom(testSeed: 9), b = M.fieldRandom(testSeed: 9)
        for _ in 0..<20 { XCTAssertEqual(a.next(), b.next()) }
        var s = M.SecureFieldRng()
        for _ in 0..<50 { XCTAssertLessThan(s.next(), M.Field.prime) }
        var x = M.fieldRandom(), y = M.fieldRandom()
        XCTAssertNotEqual((0..<8).map { _ in x.next() }, (0..<8).map { _ in y.next() })
    }

    func testModFqIsTheCanonicalRepresentative() {
        let q = "57896044618658097711785492504343953926634992332820282019728792003956564819949"
        XCTAssertEqual(M.modFq("0"), "0")
        XCTAssertEqual(M.modFq(q), "0")
        XCTAssertEqual(M.modFq("-1"), "57896044618658097711785492504343953926634992332820282019728792003956564819948")
        XCTAssertEqual(M.modFq("12345"), "12345")
        XCTAssertNil(M.modFq("12x"))
        XCTAssertNil(M.modFq(""))
    }

    func testReducedConstantsOnTheSharedValueOps() throws {
        let p = M.Field.prime
        XCTAssertEqual(M.fneg(0), 0)
        XCTAssertEqual(M.fneg(1), p - 1)
        XCTAssertEqual(M.addPublicSV([1, 2], p + 5), [6, 2])
        XCTAssertEqual(M.scaleSV([2, 3], p + 2), [4, 6])
        XCTAssertEqual(M.notBitSV([1, 0]), [0, 0])
        XCTAssertEqual(try M.subSV([5, 5], [2, 3]), [3, 2])
        XCTAssertThrowsError(try M.subSV([1], [1, 2]))
    }

    func testEvaluatePartyFailsClosedOnAnUndecidableInput() {
        let d = M.evaluateParty(M.PartyPolicy(id: "x", decideInput: .null), 50)
        XCTAssertEqual(d, M.DecisionVector(allow: 0, t: 3, rQuant: 50))
    }
}
