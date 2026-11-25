import XCTest
import AtlasPCAPairing

final class PairingSmokeTests: XCTestCase {
    func testGeneratorEncoding() {
        XCTAssertEqual(Ref.hex(G1.generator.compressed),
                       "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
        XCTAssertNotNil(G1(compressed: G1.generator.compressed))
        XCTAssertNotNil(G2(compressed: G2.generator.compressed))
        XCTAssertNil(G1(compressed: [UInt8](repeating: 0, count: 48)))
    }

    func testBilinearity() {
        let two = Fr(2)
        XCTAssertTrue(Bls12.pairingEq(two * G1.generator, G2.generator, G1.generator, two * G2.generator))
        XCTAssertFalse(Bls12.pairingEq(two * G1.generator, G2.generator, G1.generator, G2.generator))
    }

    func testGtShim() throws {
        let g1 = G1.generator.compressed, g2 = G2.generator.compressed
        let e = try XCTUnwrap(Gt.pairing([g1], [g2]))
        XCTAssertTrue(Gt.isElement(e))
        let sq = try XCTUnwrap(Gt.mul(e, e))
        var k = [UInt8](repeating: 0, count: 32); k[31] = 2
        XCTAssertEqual(try XCTUnwrap(Gt.pow(e, k)), sq)
        let e2 = try XCTUnwrap(Gt.pairing([(Fr(2) * G1.generator).compressed], [g2]))
        XCTAssertEqual(e2, sq)
    }

    func testScalarField() throws {
        let a = Fr(7), b = Fr(5)
        XCTAssertEqual(a * b, Fr(35))
        XCTAssertEqual(a - b, Fr(2))
        XCTAssertEqual(try a.inverse() * a, Fr(1))
        XCTAssertNil(Fr(canonical: blsOrderBE))
        XCTAssertTrue(Fr(reducing: blsOrderBE).isZero)
    }

    /// RFC 9380 K.1, expand_message_xmd(SHA-256), empty message.
    func testExpandMessageXmd() throws {
        let out = try Bls12.expandMessageXmd([], Array("QUUX-V01-CS02-with-expander-SHA256-128".utf8), 0x20)
        XCTAssertEqual(Ref.hex(out), "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235")
    }
}
