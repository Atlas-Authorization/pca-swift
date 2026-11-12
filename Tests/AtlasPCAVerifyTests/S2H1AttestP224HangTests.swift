import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Deadline/lock kills for AttestP224.swift mutants (see S2Deadline): inputs the original finishes in milliseconds.
final class A0H1AttestP224HangTests: XCTestCase {
    private func dl(_ what: String, _ body: @escaping @Sendable () -> String) -> String {
        S2Deadline.within(3, what) { body() } ?? "timeout"
    }

    func testP224LoopsTerminate() throws {
        XCTAssertEqual(dl("geq") { "\(P224.F.geq(P224.F.n))" }, "true", "AttestP224.swift:36")
        XCTAssertEqual(dl("lt equal") { "\(P224.lt(P224.F.n, P224.F.n))" }, "false", "AttestP224.swift:158")
        XCTAssertEqual(dl("inv") {
            let one = P224.F.toMont([1, 0, 0, 0, 0, 0, 0])
            return "\(P224.F.fromMont(P224.F.mul(P224.F.inv(one), one)) == [1, 0, 0, 0, 0, 0, 0])"
        }, "true", "AttestP224.swift:130")
        let rows = try XCTUnwrap(AttestCryptoDifferentialTests.doc.get("p224")?.asArray)
        let ok: JSONValue? = rows.first(where: { r in
            if case .bool(true)? = r.get("ok"), r.get("strict") == nil || r.get("strict") != .bool(true) { return true }
            return false
        })
        let row = try XCTUnwrap(ok)
        let hashName = row.get("hash")?.asString ?? "sha512"
        let pointHex = row.get("point")?.asString ?? "", msgHex = row.get("msg")?.asString ?? "", sigHex = row.get("sig")?.asString ?? ""
        XCTAssertEqual(dl("p224 verify") {
            let hash: AHash
            switch hashName {
            case "sha1": hash = .sha1
            case "sha256": hash = .sha256
            case "sha384": hash = .sha384
            default: hash = .sha512
            }
            guard let point = ACrypto.unhex(pointHex), let msg = ACrypto.unhex(msgHex), let sig = ACrypto.unhex(sigHex) else { return "badhex" }
            return "\(ACrypto.ecVerify(curve: "P-224", point: point, hash: hash, message: msg, der: sig))"
        }, "true", "AttestP224.swift:247 (and 130 through the inverse)")
    }
}
