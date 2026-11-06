import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The pure-Swift P-224 verifier against OpenSSL on range and DER edges (test-data/attest-crypto-differential.json). A row marked
/// strict is one this verifier refuses on purpose although OpenSSL accepts it.
final class AttestP224DifferentialTests: XCTestCase {
    func testVerdictsMatchOpenSSL() throws {
        let rows = try XCTUnwrap(AttestCryptoDifferentialTests.doc.get("p224")?.asArray)
        XCTAssertGreaterThan(rows.count, 300)
        var seen = Set<Bool>()
        for r in rows {
            let hash: AHash
            switch r.get("hash")?.asString {
            case "sha1": hash = .sha1
            case "sha256": hash = .sha256
            case "sha384": hash = .sha384
            default: hash = .sha512
            }
            let point = try XCTUnwrap(ACrypto.unhex(r.get("point")?.asString ?? "x"))
            let msg = try XCTUnwrap(ACrypto.unhex(r.get("msg")?.asString ?? "x"))
            let sig = try XCTUnwrap(ACrypto.unhex(r.get("sig")?.asString ?? "x"))
            let got = ACrypto.ecVerify(curve: "P-224", point: point, hash: hash, message: msg, der: sig)
            var openssl = false, strict = false
            if case .bool(true)? = r.get("ok") { openssl = true }
            if case .bool(true)? = r.get("strict") { strict = true }
            seen.insert(openssl)
            let label = "\(r.get("hash")?.asString ?? "") \(r.get("why")?.asString ?? "")"
            if strict { XCTAssertFalse(got, label) } else { XCTAssertEqual(got, openssl, label) }
        }
        XCTAssertEqual(seen, [true, false])
    }
}
