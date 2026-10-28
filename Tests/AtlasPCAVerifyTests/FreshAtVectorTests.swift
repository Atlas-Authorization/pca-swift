import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED `fresh_at` member vectors (packages/pca/conformance/fresh-at-vectors.json) through `PCA.verify`: the member is
/// a closed signed PCActn member, the `fresh_at` check follows the intent checks, a stale verifier is an `escalate:` failure.
final class FreshAtVectorTests: XCTestCase {
    func testFreshAtMemberVectors() throws {
        let doc = try ConformanceTests.load("fresh-at-vectors.json")
        let cases = doc.get("vectors")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 28)
        var failures: [String] = []
        var escalations = 0
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            guard let now = c.get("context")?.get("now")?.safeInt, let aud = c.get("context")?.get("aud")?.asString,
                  let expect = c.get("expect"), let wantChecks = expect.get("checks")?.asObject, let wantFresh = expect.get("fresh_at")?.asString else {
                failures.append("\(name): malformed vector"); continue
            }
            // a policy exists iff the context carries `fresh_at`; `side_carried` present (even null) means a token travelled beside the PCActn
            let policy = c.get("context")?.get("fresh_at").map { FreshAtPolicy(json: $0) }
            let got = PCA.verify(pcactn: c.get("pcactn") ?? .null, grant: c.get("grant") ?? .null, now: now, audience: aud, freshAt: policy)

            if got.allow != (expect.get("allow") == .bool(true)) { failures.append("\(name): allow = \(got.allow) (\(got.reason))") }
            var core = got.checks
            let gotFresh = core.removeValue(forKey: "fresh_at").map { $0 ? "pass" : "fail" } ?? "absent"
            if gotFresh != wantFresh { failures.append("\(name): fresh_at = \(gotFresh), want \(wantFresh) (\(got.reason))") }
            if core.count != wantChecks.count { failures.append("\(name): checks \(core.keys.sorted()) want \(wantChecks.keys.map { $0.s }.sorted())") }
            for (k, w) in wantChecks where core[k.s].map({ JSONValue.bool($0) }) != w { failures.append("\(name): check \(k.s) = \(String(describing: core[k.s])) (\(got.reason))") }

            var status: [String: String] = [:]
            for (k, v) in got.checks { status[k] = v ? "pass" : "fail" }
            let decision = PCA.decisionOf(allow: got.allow, checks: status, reasons: got.reasons)
            if decision != expect.get("decision")?.asString { failures.append("\(name): decision \(decision), want \(expect.get("decision")?.asString ?? "?")") }
            if decision == "escalate" { escalations += 1 }

            if let want = expect.get("reason")?.asString {
                // the leaf-signature text differs between verifiers; its check name is the contract
                let ok = want.hasPrefix("leaf_signature: ") ? got.reason.hasPrefix("leaf_signature: ") : got.reason == want
                if !ok { failures.append("\(name): reason '\(got.reason)', want '\(want)'") }
            } else if !got.reason.isEmpty {
                failures.append("\(name): unexpected reason '\(got.reason)'")
            }
        }
        XCTAssertGreaterThan(escalations, 5)
        XCTAssertTrue(failures.isEmpty, "\(failures.count) fresh_at vectors failed:\n" + failures.joined(separator: "\n"))
    }

    /// A PCActn with neither the member nor a policy reports no `fresh_at` check (the pre-token verdict).
    func testNoMemberNoPolicyReportsNothing() {
        XCTAssertEqual(FreshAt.decide(nil, nil, now: 0), .absent)
        XCTAssertEqual(FreshAt.decide(nil, FreshAtPolicy(json: .object([:])), now: 0), .absent)
        XCTAssertEqual(FreshAt.decide(.object([:]), nil, now: 0), .fail("the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)"))
        XCTAssertEqual(FreshAt.decide(nil, FreshAtPolicy(json: .object(["require": .bool(true)])), now: 0),
                       .fail("escalate: a consistency token is required (refresh and retry with the token of your latest write)"))
        // a null side-carried token was presented and is refused, not ignored
        XCTAssertEqual(FreshAt.decide(nil, FreshAtPolicy(json: .object(["side_carried": .null])), now: 0), .fail("bad_token"))
    }

    func testWireShape() {
        XCTAssertEqual(FreshAt.validateWire(.null), "'fresh_at' must be an object")
        XCTAssertEqual(FreshAt.validateWire(.object(["extra": .int(1)])), "'fresh_at' has an unknown field 'extra'")
        XCTAssertEqual(FreshAt.validateWire(.object(["v": .int(2)])), "'fresh_at.v' must be 1")
    }
}
