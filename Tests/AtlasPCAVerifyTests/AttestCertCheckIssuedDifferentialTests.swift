import XCTest
import Foundation
@testable import AtlasPCAVerify

/// `Cert.checkIssued` and `Cert.parseDER` against Node's X509Certificate on the same bytes (test-data/attest-crypto-differential.json).
/// A row marked strict is one this verifier refuses on purpose although Node accepts it. Accepting anything Node refuses always fails.
final class AttestCertCheckIssuedDifferentialTests: XCTestCase {
    private func der(_ s: String?) throws -> [UInt8] { try XCTUnwrap(ACrypto.unhex(s ?? "x")) }
    private func yes(_ r: JSONValue, _ k: String) -> Bool {
        if case .bool(true)? = r.get(k) { return true }
        return false
    }

    func testIssuedVerdictsMatchNode() throws {
        let rows = try XCTUnwrap(AttestCryptoDifferentialTests.doc.get("issued")?.asArray)
        XCTAssertGreaterThan(rows.count, 30)
        XCTAssertTrue(rows.contains { yes($0, "node") })
        XCTAssertTrue(rows.contains { !yes($0, "node") })
        for r in rows {
            let label = r.get("why")?.asString ?? ""
            let got = Cert.checkIssued(try Cert.parseDER(try der(r.get("child")?.asString)), try Cert.parseDER(try der(r.get("issuer")?.asString)))
            if yes(r, "strict") { XCTAssertFalse(got, label) } else { XCTAssertEqual(got, yes(r, "node"), label) }
        }
    }

    func testParseVerdictsMatchNode() throws {
        let rows = try XCTUnwrap(AttestCryptoDifferentialTests.doc.get("parse")?.asArray)
        XCTAssertGreaterThanOrEqual(rows.count, 7)
        for r in rows {
            let label = r.get("why")?.asString ?? ""
            let got = (try? Cert.parseDER(try der(r.get("child")?.asString))) != nil
            if yes(r, "strict") {
                XCTAssertTrue(yes(r, "node"), label) // the row only excuses a refusal of what Node accepts
            } else {
                XCTAssertEqual(got, yes(r, "node"), label)
            }
        }
    }
}
