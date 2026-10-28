import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED lease vectors (packages/pca/conformance/lease-vectors.json). A missing file fails.
final class LeaseVectorTests: XCTestCase {
    private func strs(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    func testLeaseVectors() throws {
        let doc = try ConformanceTests.load("lease-vectors.json")
        let records = doc.get("records")?.asArray ?? []
        let revocations = doc.get("revocations")?.asArray ?? []
        let authority = doc.get("authority")?.asString ?? ""
        let scenarios = doc.get("scenarios")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(scenarios.count, 20)
        var f: [String] = []
        for s in scenarios {
            let name = s.get("name")?.asString ?? "?"
            let p = s.get("policy")
            let policy = Lease.Policy(authorities: [authority], minApprovals: p?.get("minApprovals")?.safeInt ?? 1,
                                      eligibleApprovers: p?.get("eligibleApprovers") == nil ? nil : strs(p?.get("eligibleApprovers")),
                                      freshJustification: p?.get("freshJustification") != .bool(false))
            let reg = Lease.Registry(policy: policy)
            for (i, st) in (s.get("steps")?.asArray ?? []).enumerated() {
                let at = "\(name) step \(i)"
                let e = st.get("expect")
                switch st.get("op")?.asString ?? "" {
                case "accept":
                    let got = reg.accept(records[Int(st.get("record")?.safeInt ?? 0)], chain: strs(st.get("chain")))
                    var ok = got.ok == (e?.get("ok") == .bool(true))
                    if ok && got.ok { ok = got.replaced == (e?.get("replaced") == .bool(true)) && got.seq == e?.get("seq")?.safeInt }
                    if ok && !got.ok { ok = got.code == e?.get("code")?.asString }
                    if !ok { f.append("\(at): accept \(got)") }
                case "revoke":
                    let got = reg.revoke(revocations[Int(st.get("revocation")?.safeInt ?? 0)])
                    var ok = got.ok == (e?.get("ok") == .bool(true))
                    if ok && got.ok { ok = Int64(got.revoked) == e?.get("revoked")?.safeInt }
                    if ok && !got.ok { ok = got.code == e?.get("code")?.asString }
                    if !ok { f.append("\(at): revoke \(got)") }
                case "check":
                    let got = Lease.checkLease(records[Int(st.get("record")?.safeInt ?? 0)], registry: reg, now: st.get("now"))
                    let ok = got.decision == e?.get("decision")?.asString && got.code == e?.get("code")?.asString
                        && got.leaseId == e?.get("lease_id")?.asString && got.expiresAt == e?.get("expires_at")?.safeInt
                    if !ok { f.append("\(at): check \(got)") }
                default:
                    f.append("\(at): unknown op")
                }
            }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }

    func testPathUnderAndSod() {
        XCTAssertTrue(Lease.pathUnder("db/prod/ro", "db/prod"))
        XCTAssertTrue(Lease.pathUnder("db/prod", "db/prod"))
        XCTAssertFalse(Lease.pathUnder("db/production", "db/prod"))
        XCTAssertNil(Lease.sodError(requester: "alice", holder: "agent", approvers: ["bob"]))
        XCTAssertEqual(Lease.sodError(requester: "alice", holder: "agent", approvers: ["alice"]), "the requester may not approve their own request")
    }
}
