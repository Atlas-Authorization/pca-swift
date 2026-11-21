import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Hash sizes, hex, the MGF1 counter encoding and the ECDSA dispatch.
final class AttestCryptoK05PrimitivesTests: XCTestCase {
    static let MSG = Array("atlas pca ecdsa dispatch".utf8)

    func testHashLengthsMatchTheDigests() {
        let table: [(AHash, Int)] = [(.sha1, 20), (.sha256, 32), (.sha384, 48), (.sha512, 64)]
        for (hash, length) in table {
            XCTAssertEqual(hash.length, length)
            XCTAssertEqual(hash.digest([]).count, length)
        }
    }

    func testHexRoundTrip() {
        XCTAssertEqual(ACrypto.hex([0x00, 0x1f, 0xff]), "001fff")
        XCTAssertEqual(ACrypto.unhex("001fff"), [0x00, 0x1f, 0xff])
        XCTAssertEqual(ACrypto.unhex("AbCd"), [0xab, 0xcd])
        XCTAssertEqual(ACrypto.unhex(""), [])
    }

    func testUnhexRefusesOddLengthAndNonHex() {
        for bad in ["a", "abc", "abcde", "zz", "0g", "g0", "abz", "0 "] {
            XCTAssertNil(ACrypto.unhex(bad), bad)
        }
    }

    func testMgf1CounterIsBigEndian() {
        // zero first: a mutant that overflows UInt8 on the second value has already failed an assertion
        XCTAssertEqual(ACrypto.counterBytes(0), [0, 0, 0, 0])
        XCTAssertEqual(ACrypto.counterBytes(0x0102_0304), [1, 2, 3, 4])
        XCTAssertEqual(ACrypto.counterBytes(0xfeff_80c1), [0xfe, 0xff, 0x80, 0xc1])
    }

    func testMgf1IsTheCountedHashStream() {
        let seed: [UInt8] = [1, 2, 3]
        let block0 = AHash.sha256.digest(seed + [0, 0, 0, 0]), block1 = AHash.sha256.digest(seed + [0, 0, 0, 1])
        XCTAssertEqual(ACrypto.mgf1(seed: seed, length: 40, hash: .sha256), block0 + Array(block1.prefix(8)))
        XCTAssertEqual(ACrypto.mgf1(seed: seed, length: 32, hash: .sha256), block0)
        XCTAssertEqual(ACrypto.mgf1(seed: seed, length: 0, hash: .sha256), [])
    }

    func testP384RefusalsAreFalse() {
        let pt = AttestFailClosedTests.h(AttestFailClosedTests.P384_PT), raw = AttestFailClosedTests.h(AttestFailClosedTests.P384_RAW)
        let msg = AttestFailClosedTests.MSG
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-384", point: pt, hash: .sha384, message: msg, raw: raw))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-384", point: Array(pt.dropLast()), hash: .sha384, message: msg, raw: raw), "bad point")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-384", point: pt, hash: .sha384, message: msg, raw: Array(raw.dropLast())), "raw size")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-384", point: pt, hash: .sha384, message: msg), "no signature")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-384", point: pt, hash: .sha384, message: msg, der: [0x30, 0x00]), "bad DER")
    }

    func testP521RawSizeAndRefusals() throws {
        let key = P521.Signing.PrivateKey()
        let pt = [UInt8](key.publicKey.x963Representation)
        let sig = try key.signature(for: SHA512.hash(data: Data(Self.MSG)))
        let raw = [UInt8](sig.rawRepresentation)
        XCTAssertEqual(raw.count, 132)
        XCTAssertTrue(ACrypto.ecPointValid(curve: "P-521", point: pt))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-521", point: pt, hash: .sha512, message: Self.MSG, raw: raw))
        XCTAssertTrue(ACrypto.ecVerify(curve: "P-521", point: pt, hash: .sha512, message: Self.MSG, der: [UInt8](sig.derRepresentation)))
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-521", point: Array(pt.dropLast())))
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-521", point: Array(pt.dropLast()), hash: .sha512, message: Self.MSG, raw: raw), "bad point")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-521", point: pt, hash: .sha512, message: Self.MSG, raw: Array(raw.dropLast())), "131 bytes")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-521", point: pt, hash: .sha512, message: Self.MSG, raw: raw + [0]), "133 bytes")
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-521", point: pt, hash: .sha512, message: Self.MSG), "no signature")
    }

    func testUnknownCurveIsFalse() {
        let pt = AttestFailClosedTests.h(AttestFailClosedTests.P384_PT), raw = AttestFailClosedTests.h(AttestFailClosedTests.P384_RAW)
        XCTAssertFalse(ACrypto.ecVerify(curve: "P-999", point: pt, hash: .sha384, message: AttestFailClosedTests.MSG, raw: raw))
        XCTAssertFalse(ACrypto.ecPointValid(curve: "P-999", point: pt))
    }
}
