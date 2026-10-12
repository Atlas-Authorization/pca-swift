import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Each strict gate tested ON ITS OWN. Later layers (the platform Ed25519, the torsion check, the type check) refuse the
/// same inputs, so the end-to-end corpus alone cannot tell a broken gate from a working one.
final class GateKillTests: XCTestCase {
    /// Little-endian 32-byte encoding of 2^255 - 19 + delta (delta small), sign bit as given.
    private func encP(_ delta: Int, sign: Bool = false) -> [UInt8] {
        var b = [UInt8](repeating: 0xff, count: 32)
        b[0] = UInt8(0xed + delta) // p = ed ff .. ff 7f
        b[31] = sign ? 0xff : 0x7f
        return b
    }
    private static let L: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14]
        + [UInt8](repeating: 0, count: 15) + [0x10]

    func testCanonicalYGate() {
        XCTAssertTrue(Ed25519Strict.P == BigUInt(decimal: "57896044618658097711785492504343953926634992332820282019728792003956564819949"))
        for d in 0...0x12 { XCTAssertFalse(Ed25519Strict.isStrictPoint(encP(d)), "y = p + \(d)") }   // y in [p, 2^255-1]
        XCTAssertFalse(Ed25519Strict.isStrictPoint(encP(0, sign: true)))                               // y = p, sign bit set
        XCTAssertFalse(Ed25519Strict.isStrictPoint([UInt8](repeating: 0xff, count: 32)))              // y = 2^255 - 1
        XCTAssertFalse(Ed25519Strict.isStrictPoint([1, 2, 3]))
        XCTAssertFalse(Ed25519Strict.isStrictPoint([UInt8](repeating: 9, count: 33)))
        // a canonical, non-small-order encoding passes this gate (y = p - 2)
        XCTAssertTrue(Ed25519Strict.isStrictPoint(encP(-2)))
    }

    func testSmallOrderTable() {
        // every small-order y, with and without the sign bit
        let ys: [[UInt8]] = [[0x01] + [UInt8](repeating: 0, count: 31), [UInt8](repeating: 0, count: 32), encP(-1)] + Array(Ed25519Strict.smallOrderY[3...])
        XCTAssertEqual(Ed25519Strict.smallOrderY.count, 5)
        XCTAssertEqual(Ed25519Strict.smallOrderY[1], [UInt8](repeating: 0, count: 32))
        XCTAssertEqual(Ed25519Strict.smallOrderY[2], encP(-1))
        for y in ys {
            XCTAssertEqual(y.count, 32)
            XCTAssertFalse(Ed25519Strict.isStrictPoint(y))
            var s = y; s[31] |= 0x80
            XCTAssertFalse(Ed25519Strict.isStrictPoint(s))
        }
    }

    func testCanonicalSGate() {
        let r = [UInt8](repeating: 0, count: 32)
        var lMinus1 = Self.L; lMinus1[0] -= 1
        XCTAssertFalse(Ed25519Strict.isCanonicalS(r + Self.L))
        XCTAssertTrue(Ed25519Strict.isCanonicalS(r + lMinus1))
        XCTAssertFalse(Ed25519Strict.isCanonicalS(r + [UInt8](repeating: 0xff, count: 32)))
        XCTAssertTrue(Ed25519Strict.isCanonicalS(r + [UInt8](repeating: 0, count: 32)))
        XCTAssertFalse(Ed25519Strict.isCanonicalS(r + lMinus1 + [0]))
        XCTAssertFalse(Ed25519Strict.isCanonicalS(Array(r[0..<31]) + lMinus1))
    }

    func testVerifyLengthGate() {
        XCTAssertFalse(Ed25519Strict.verify(publicKey: [UInt8](repeating: 1, count: 31), message: [], signature: [UInt8](repeating: 0, count: 64)))
        XCTAssertFalse(Ed25519Strict.verify(publicKey: [UInt8](repeating: 1, count: 32), message: [], signature: [UInt8](repeating: 0, count: 63)))
    }

    func testSafeIntBoundaryAndIsNull() {
        XCTAssertEqual(JSONValue.double(9_007_199_254_740_991.0).safeInt, 9_007_199_254_740_991)
        XCTAssertEqual(JSONValue.double(-9_007_199_254_740_991.0).safeInt, -9_007_199_254_740_991)
        XCTAssertNil(JSONValue.double(9_007_199_254_740_992.0).safeInt)
        XCTAssertTrue(JSONValue.null.isNull)
        XCTAssertFalse(JSONValue.int(0).isNull)
        XCTAssertEqual(Merkle.paramsDigest(.null), Merkle.paramsDigest(nil))
        XCTAssertNotEqual(Merkle.paramsDigest(.object([JKey("a"): .int(1)])), Merkle.paramsDigest(nil))
        XCTAssertNil(Merkle.planLeaf(.null, [:], "x"))
        XCTAssertNil(Merkle.planLeaf(nil, [:], "x"))
        XCTAssertNotNil(Merkle.planLeaf(.string("n"), [:], "x"))
    }

    /// The chain type check refuses a non-object hop by its own reason, and a non-object hop counts 0 caveats.
    func testChainTypeAndCaveatCountOrder() {
        func hop(_ n: Int) -> JSONValue { .object([JKey("caveats"): .array(Array(repeating: .object([JKey("type"): .string("note")]), count: n))]) }
        XCTAssertEqual(Capability.verifyChain([.null], expectedRootIssuer: nil), "hop 0: malformed capability")
        XCTAssertEqual(Capability.verifyChain([.int(1)], expectedRootIssuer: nil), "hop 0: malformed capability")
        XCTAssertFalse(Capability.wellTyped(.null))
        XCTAssertFalse(Capability.wellTyped(.array([])))
        // 4 x 256 = 1024 caveats is AT the chain cap; a hop without caveats adds 0, so the type check (not the cap) refuses
        XCTAssertEqual(Capability.verifyChain([hop(256), hop(256), hop(256), hop(256), .null], expectedRootIssuer: nil), "hop 0: malformed capability")
        XCTAssertFalse(Capability.caveatLimitExceeded([hop(256), hop(256), hop(256), hop(256), .null, .object([:])]))
    }

    /// base64url gates: the round-trip check refuses every non-alphabet byte and non-zero trailing bits.
    func testBase64Gates() {
        XCTAssertNil(Base64URLStrict.decode("AA!A"))
        XCTAssertNil(Base64URLStrict.decode("AB"))   // trailing bits set
        XCTAssertEqual(Base64URLStrict.decode("AA"), [0])
        XCTAssertEqual(Base64URLStrict.decode("AAA"), [0, 0])
        XCTAssertEqual(Base64URLStrict.encode([0xff]), "_w")
        XCTAssertEqual(Base64URLStrict.encode([0xff, 0xff]), "__8")
        XCTAssertEqual(Base64URLStrict.encode([0xfb, 0xff, 0xbf]), "-_-_")
        XCTAssertEqual(Base64URLStrict.encodedLength(32), 43)
        XCTAssertEqual(Base64URLStrict.encodedLength(64), 86)
    }
}
