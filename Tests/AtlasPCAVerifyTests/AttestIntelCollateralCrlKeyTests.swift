import XCTest
import Foundation
@testable import AtlasPCAVerify

/// node's verify('sha256', tbs, key, sig) is PKCS#1 v1.5 and OpenSSL refuses that under an rsa-pss key: a valid signature proves it.
final class AttestIntelCollateralCrlKeyTests: XCTestCase {
    func testAValidPkcs1SignatureCountsOnlyUnderAnRsaKey() throws {
        let doc = AttestCryptoDifferentialTests.doc
        let row = try XCTUnwrap(doc.get("rsa")?.asArray?.first {
            if case .bool(true)? = $0.get("ok"), $0.get("kind")?.asString == "pkcs1", $0.get("hash")?.asString == "sha256", $0.get("key")?.asString == "2048" { return true }
            return false
        })
        let key = try XCTUnwrap(doc.get("keys")?.get("2048"))
        func bytes(_ s: String?) throws -> [UInt8] {
            let t = s ?? "x"
            return try XCTUnwrap(ACrypto.unhex(t.count % 2 == 0 ? t : "0" + t))
        }
        var k = CertKey()
        k.rsaN = try bytes(key.get("n")?.asString)
        k.rsaE = try bytes(key.get("e")?.asString)
        k.typ = "rsa"
        let msg = try bytes(row.get("msg")?.asString), sig = try bytes(row.get("sig")?.asString)
        XCTAssertTrue(IntelCollateral.crlSigOK(msg, sig, k))
        k.typ = "rsa-pss"
        XCTAssertFalse(IntelCollateral.crlSigOK(msg, sig, k))
    }
}
