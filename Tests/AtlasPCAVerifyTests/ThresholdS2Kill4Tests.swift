import XCTest
@testable import AtlasPCAVerify

/// The signer-set hash is over rows sorted bytewise by (role, publicKey): sha256(DOMAIN || canonical(rows)). Expected values are built
/// from the rows in their hand-sorted order, not from the code under test.
final class S2G4ThresholdKillTests: XCTestCase {
    typealias J = JSONValue

    func want(_ rows: [JObject]) -> [UInt8] {
        Canonical.sha256(Threshold.SIGNER_SET_DOMAIN + Canonical.utf8(Canonical.canonicalize(JSONValue.array(rows.map { JSONValue.object($0) }))))
    }
    func row(_ role: String, _ pk: String, pq: String? = nil) -> JObject {
        var r: JObject = ["publicKey": J.string(pk), "role": J.string(role)]
        if let q = pq { r["pq_pk"] = J.string(q) }
        return r
    }
    func raw(_ role: String, _ pk: String, pq: String? = nil) -> JSONValue { JSONValue.object(row(role, pk, pq: pq)) }

    func testRolesSortBeforeKeys() {
        let set = [Threshold.Signer(role: .principal, publicKey: "aaa"), Threshold.Signer(role: .agent, publicKey: "zzz"), Threshold.Signer(role: .guardian, publicKey: "mmm")]
        XCTAssertEqual(Threshold.signerSetHash(set), want([row("agent", "zzz"), row("guardian", "mmm"), row("principal", "aaa")]))
        XCTAssertEqual(Threshold.signerSetHashJSON([raw("principal", "aaa"), raw("agent", "zzz"), raw("guardian", "mmm")]),
                       want([row("agent", "zzz"), row("guardian", "mmm"), row("principal", "aaa")]))
    }

    func testKeysSortWithinARole() {
        let set = [Threshold.Signer(role: .agent, publicKey: "zzz"), Threshold.Signer(role: .agent, publicKey: "aaa")]
        XCTAssertEqual(Threshold.signerSetHash(set), want([row("agent", "aaa"), row("agent", "zzz")]))
        XCTAssertEqual(Threshold.signerSetHashJSON([raw("agent", "zzz"), raw("agent", "aaa")]), want([row("agent", "aaa"), row("agent", "zzz")]))
    }

    /// Equal (role, key) rows keep their input order (the comparator is strict).
    func testEqualRowsKeepTheirOrder() {
        let set = [Threshold.Signer(role: .agent, publicKey: "k", pqPk: "p1"), Threshold.Signer(role: .agent, publicKey: "k", pqPk: "p2")]
        XCTAssertEqual(Threshold.signerSetHash(set), want([row("agent", "k", pq: "p1"), row("agent", "k", pq: "p2")]))
        XCTAssertEqual(Threshold.signerSetHashJSON([raw("agent", "k", pq: "p1"), raw("agent", "k", pq: "p2")]),
                       want([row("agent", "k", pq: "p1"), row("agent", "k", pq: "p2")]))
    }

    /// Roles one byte apart ("agent" < "agenu"): the role decides even when the later key is smaller.
    func testRolesOneByteApartAreOrderedByRole() {
        XCTAssertEqual(Threshold.signerSetHashJSON([raw("agent", "z"), raw("agenu", "a")]), want([row("agent", "z"), row("agenu", "a")]))
        XCTAssertEqual(Threshold.signerSetHashJSON([raw("agenu", "a"), raw("agent", "z")]), want([row("agent", "z"), row("agenu", "a")]))
    }
}
