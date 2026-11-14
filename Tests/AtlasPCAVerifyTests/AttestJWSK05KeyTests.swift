import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// The header fields, the DER builders and the JWK public keys of the MAA / Confidential Space verifiers (RFC 7517 / 7518; X.690;
/// createPublicKey in packages/pca/src/attest-gcp-confidential-space.ts:328,331). Leading zeros of a JWK coordinate carry no value.
final class AttestJWSK05KeyTests: XCTestCase {
    typealias C = AttestFailClosedTests

    func b(_ x: [UInt8]) -> String { Base64URLStrict.encode(x) }

    func thrown(_ f: () throws -> CertKey) -> String {
        do {
            _ = try f()
            return ""
        } catch { return (error as? AttestError)?.message ?? "?" }
    }

    func rsaErr(_ e: [UInt8]) -> String { thrown { try JWS.jwkRSAKey(b(C.h(C.N)), b(e)) } }

    // ---- parse ----

    func token(_ header: String) -> String { b(Array(header.utf8)) + "." + b(Array("{}".utf8)) + "." + b([0]) }

    func testAbsentHeaderFieldsAreAbsent() throws {
        let bare = try JWS.parse(token("{\"alg\":\"ES256\"}"), "t")
        XCTAssertFalse(bare.hasKid)
        XCTAssertFalse(bare.hasX5c)
        let full = try JWS.parse(token("{\"alg\":\"ES256\",\"kid\":\"k\",\"x5c\":[\"c\"]}"), "t")
        XCTAssertTrue(full.hasKid)
        XCTAssertEqual(full.kid, "k")
        XCTAssertTrue(full.hasX5c)
        XCTAssertEqual(full.x5c, ["c"])
    }

    // ---- DER ----

    func testDerLengths() {
        XCTAssertEqual(DERB.len(0x7f), [0x7f])
        XCTAssertEqual(DERB.len(0xffff), [0x82, 0xff, 0xff])
        XCTAssertEqual(DERB.len(0x012345), [0x83, 0x01, 0x23, 0x45])
        XCTAssertEqual(DERB.len(0x10000), [0x83, 0x01, 0x00, 0x00])
    }

    func testDerIntegerOfZero() {
        XCTAssertEqual(DERB.int([]), [0x02, 0x01, 0x00])
        XCTAssertEqual(DERB.int([0, 0]), [0x02, 0x01, 0x00])
    }

    // ---- RS256 ----

    /// OpenSSL verifies no PKCS#1 signature under an rsa-pss key (verify('RSA-SHA256', ...), attest-azure-maa.ts:453).
    func testRs256OnlyUnderAPlainRsaKey() {
        var k = CertKey()
        k.rsaN = C.h(C.N)
        k.rsaE = [1, 0, 1]
        k.typ = "rsa"
        XCTAssertTrue(JWS.rs256OK(C.h(C.PKCS1), C.MSG, k))
        k.typ = "rsa-pss"
        XCTAssertFalse(JWS.rs256OK(C.h(C.PKCS1), C.MSG, k))
        k.typ = "ec"
        XCTAssertFalse(JWS.rs256OK(C.h(C.PKCS1), C.MSG, k))
    }

    // ---- RSA JWK ----

    func testRsaModulusLeadingZerosAreDropped() throws {
        let n = C.h(C.N)
        XCTAssertEqual(try JWS.jwkRSAKey(b([0] + n), "AQAB").rsaN, n)
        XCTAssertEqual(try JWS.jwkRSAKey(b([1] + n), "AQAB").rsaN, [1] + n)
        XCTAssertEqual(thrown { try JWS.jwkRSAKey("", "AQAB") }, OSSL.unsupported)
        XCTAssertEqual(thrown { try JWS.jwkRSAKey(b([0]), "AQAB") }, OSSL.unsupported)
    }

    func testRsaExponentRange() {
        for e: [UInt8] in [[3], [1, 0, 1], [1, 0, 0, 1], [0x7f, 0xff, 0xff, 0xff], [0, 3]] { XCTAssertEqual(rsaErr(e), "", "\(e)") }
        for e: [UInt8] in [[], [0], [1], [2], [0x80, 0, 0, 0], [1, 0, 0, 0, 1]] { XCTAssertEqual(rsaErr(e), OSSL.unsupported, "\(e)") }
    }

    /// 11 bytes whose low 8 bytes read 0x010001: only the byte count refuses it (the shift would drop the high bytes).
    func testAnOversizedExponentCannotWrapIntoRange() {
        XCTAssertEqual(rsaErr([1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]), OSSL.unsupported)
    }

    // ---- EC JWK ----

    func testEcCoordinatesWithLeadingZeros() throws {
        let pt = C.h(C.P256_PT), x = Array(pt[1..<33]), y = Array(pt[33..<65])
        XCTAssertEqual(try JWS.jwkECKey("P-256", b(x), b(y)).point, pt)
        XCTAssertEqual(try JWS.jwkECKey("P-256", b([0] + x), b([0] + y)).point, pt)
        XCTAssertEqual(thrown { try JWS.jwkECKey("P-256", b([1] + x), b(y)) }, OSSL.unsupported)
        XCTAssertEqual(thrown { try JWS.jwkECKey("P-256", b(x), b([1] + y)) }, OSSL.unsupported)
    }

    /// The P-521 generator: x has a leading zero byte, y starts with 0x01, each is 66 bytes wide.
    func testP521GeneratorIsSixtySixBytesWide() throws {
        let x = C.h("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66")
        let y = C.h("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")
        let k = try JWS.jwkECKey("P-521", b(x), b(y))
        XCTAssertEqual(k.point, [0x04] + x + y)
        XCTAssertEqual(k.ecName, "P-521")
    }

    /// A short y is padded with zeros: the first P-256 key whose y starts with a zero byte (one in 256).
    func testAShortYCoordinateIsZeroPadded() throws {
        var found: [UInt8]?
        var s: UInt16 = 1
        while found == nil && s < 20000 {
            let raw: [UInt8] = [UInt8](repeating: 0, count: 30) + [UInt8(s >> 8), UInt8(s & 0xff)]
            let pt = Array(try P256.Signing.PrivateKey(rawRepresentation: Data(raw)).publicKey.x963Representation)
            if pt[33] == 0 { found = pt }
            s += 1
        }
        let pt = try XCTUnwrap(found)
        XCTAssertEqual(try JWS.jwkECKey("P-256", b(Array(pt[1..<33])), b(Array(pt[34..<65]))).point, pt)
    }
}
