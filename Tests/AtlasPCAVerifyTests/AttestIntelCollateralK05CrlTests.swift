import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// The lenient DER reader and the CRL parser, exact reasons (attest-intel-collateral.ts:81-95, 123-184).
final class AttestIntelCollateralK05CrlTests: XCTestCase {
    private typealias C = IntelCollateral

    private func tlvError(_ b: [UInt8], _ limit: Int) -> String? { IntelForge.refusal { try C.tlvLenient(b, 0, limit) } }

    func testTlvHeaderNeedsTwoBytes() throws {
        let t = try C.tlvLenient([0x04, 0x00], 0, 2)
        XCTAssertEqual(t.tag, 0x04)
        XCTAssertEqual(t.start, 2)
        XCTAssertEqual(t.end, 2)
        XCTAssertEqual(tlvError([0x04, 0x00, 0x00, 0x00], 1), "DER truncated")
    }

    func testTlvLongFormLength() throws {
        let four = try C.tlvLenient([0x04, 0x84, 0, 0, 0, 1, 0xaa], 0, 7)
        XCTAssertEqual(four.start, 6)
        XCTAssertEqual(four.end, 7)
        let exact = try C.tlvLenient([0x04, 0x81, 0x00], 0, 3)
        XCTAssertEqual(exact.start, 3)
        XCTAssertEqual(exact.end, 3)
        XCTAssertEqual(tlvError([0x04, 0x80, 0x00], 3), "DER bad length")
        XCTAssertEqual(tlvError([0x04, 0x85, 0, 0, 0, 0, 0], 7), "DER bad length")
        XCTAssertEqual(tlvError([0x04, 0x82, 0, 0, 0, 0], 3), "DER bad length")
    }

    func testParseSignatureField() throws {
        let tbs = IntelForge.crlTbs(IntelForge.utc("350101000000Z"))
        XCTAssertEqual(try C.parseCRL(IntelForge.crlWrap(tbs, [0x03, 0x03, 0x00, 0xaa, 0xbb])).sigDer, [0xaa, 0xbb])
        XCTAssertEqual(try C.parseCRL(IntelForge.crlWrap(tbs, [0x03, 0x01, 0x00])).sigDer, [])
        XCTAssertEqual(try C.parseCRL(IntelForge.crlWrap(tbs, [0x03, 0x00])).sigDer, []) // der.slice(start + 1, end) is empty
        XCTAssertEqual(IntelForge.refusal { try C.parseCRL(IntelForge.crlWrap(tbs, [0x04, 0x02, 0x00, 0xaa])) }, "CRL: bad signature")
        XCTAssertEqual(IntelForge.refusal { try C.parseCRL(IntelForge.crlWrap(tbs, [0x03, 0x02, 0x00, 0xaa, 0x05, 0x00])) }, "CRL: bad signature")
    }

    private func parseTail(_ tail: [UInt8]) throws -> C.ParsedCRL { try C.parseCRL(IntelForge.crlWrap(IntelForge.crlTbs(tail), [0x03, 0x01, 0x00])) }

    func testTbsEndingAtEachOptionalField() throws {
        let missing = "CRL: missing nextUpdate"
        XCTAssertEqual(IntelForge.refusal { try self.parseTail([]) }, missing)
        let onlyNext = try parseTail(IntelForge.utc("350101000000Z"))
        XCTAssertEqual(onlyNext.thisUpdate, IntelForge.T2025)
        XCTAssertEqual(onlyNext.nextUpdate, IntelForge.T2035)
        XCTAssertTrue(onlyNext.revoked.isEmpty)
    }

    func testNextUpdateTags() throws {
        XCTAssertEqual(try parseTail(DERB.tlv(0x18, Array("20350101000000Z".utf8))).nextUpdate, IntelForge.T2035)
        // a revoked list straight after thisUpdate is read as the list, so nextUpdate is what is missing
        XCTAssertEqual(IntelForge.refusal { try self.parseTail(IntelForge.seq([])) }, "CRL: missing nextUpdate")
    }

    func testRevokedSerials() throws {
        let entry: [UInt8] = IntelForge.seq(DERB.tlv(0x02, [0x00, 0x8f]) + IntelForge.utc("250101000000Z"))
        let tail: [UInt8] = IntelForge.utc("350101000000Z") + IntelForge.seq(entry)
        XCTAssertEqual(try parseTail(tail).revoked, ["8f"])
    }

    func testAnUnknownIssuerKeyTypeNeverVerifies() {
        var k = CertKey()
        XCTAssertFalse(C.crlSigOK([1], [2], k))
        k.typ = "ed25519"
        XCTAssertFalse(C.crlSigOK([1], [2], k))
    }

    func testVerifyCrlValidityBoundaries() throws {
        var k = CertKey()
        k.typ = "ec"
        k.ecName = "P-256"
        k.point = Array(IntelForge.caKey.publicKey.x963Representation)
        let der = IntelForge.crl(IntelForge.caKey)
        XCTAssertEqual(C.verifyCRL(der, k, IntelForge.T2025 - 1).1, "CRL thisUpdate is in the future")
        XCTAssertEqual(C.verifyCRL(der, k, IntelForge.T2025).0, Set<String>())
        XCTAssertEqual(C.verifyCRL(der, k, IntelForge.T2035).0, Set<String>())
        XCTAssertEqual(C.verifyCRL(der, k, IntelForge.T2035 + 1).1, "CRL is stale (nextUpdate passed)")
    }
}
