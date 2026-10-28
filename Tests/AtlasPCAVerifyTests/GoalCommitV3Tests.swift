import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Goal binding v3: replays goal-commit-vectors.json (commit, invalid, binding). A missing file FAILS (it is loaded, never skipped).
final class GoalCommitV3Tests: XCTestCase {
    static func doc() throws -> JSONValue { try ConformanceTests.load("goal-commit-vectors.json") }

    static func rows(_ d: JSONValue, _ table: String, _ n: Int) -> [JSONValue] {
        let a = d.get(table)?.asArray ?? []
        XCTAssertEqual(a.count, n, "\(table): row count")
        return a
    }

    static func ref(_ v: JSONValue?) -> ApprovedGoalRef {
        ApprovedGoalRef(goalDigest: v?.get("goal_digest")?.asString ?? "", policyDigest: v?.get("policy_digest")?.asString ?? "")
    }

    func testCommitVectors() throws {
        let d = try Self.doc()
        XCTAssertEqual(d.get("goal_prefix")?.asString, Intent.GOAL_V3_PREFIX)
        XCTAssertEqual(d.get("domain")?.asString, Intent.GOAL_COMMIT_DOMAIN)
        for v in Self.rows(d, "commit", 7) {
            let name = v.get("name")?.asString ?? "?"
            XCTAssertEqual(PCA.intentGoalV3(Self.ref(v)), v.get("goal")?.asString, name)
            XCTAssertEqual(PCA.intentGoalCommitV3(Self.ref(v), goalSalt: v.get("salt")?.asString ?? ""), v.get("commit")?.asString, name)
        }
    }

    func testInvalidDigestsRefused() throws {
        for v in Self.rows(try Self.doc(), "invalid", 4) {
            let name = v.get("name")?.asString ?? "?"
            XCTAssertNil(PCA.intentGoalV3(Self.ref(v)), name)
            XCTAssertNil(PCA.intentGoalCommitV3(Self.ref(v), goalSalt: "s"), name)
        }
    }

    func testBindingVectors() throws {
        for v in Self.rows(try Self.doc(), "binding", 16) {
            let name = v.get("name")?.asString ?? "?"
            var grant: JSONValue = .object([:])
            if let gc = v.get("grant_commit") { grant = .object(["caveats": .array([.object(["type": .string("envelope"), "goal_commit": gc])])]) }
            let intent: JSONValue? = (v.get("intent")?.isNull ?? true) ? nil : v.get("intent")
            let pol = IntentPolicy.fromJSON(v.get("policy") ?? .null)
            let r = Intent.decide(intent, grant: grant, policy: pol, session: v.get("session")?.asString)
            let got = r == nil ? "absent" : (r!.ok ? "pass" : "fail")
            XCTAssertEqual(got, v.get("expect")?.asString, "\(name): \(r?.why ?? "")")
        }
    }

    /// Closed object: an extra member, a missing or non-string digest, a non-object are all fail-closed misconfigurations, and the
    /// misconfiguration alone activates the policy (an absent intent still fails, never "absent").
    func testMisconfiguredPolicyFailsClosed() {
        let g = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw"
        let cases: [String: JSONValue] = [
            "extra": .object(["goal_digest": .string(g), "policy_digest": .string(g), "x": .int(1)]),
            "missing": .object(["goal_digest": .string(g)]),
            "non-string": .object(["goal_digest": .string(g), "policy_digest": .int(5)]),
            "null": .null,
            "array": .array([]),
        ]
        for (name, ag) in cases {
            let p = IntentPolicy.fromJSON(.object(["approved_goal": ag]))
            let r = Intent.decide(nil, grant: .object([:]), policy: p)
            XCTAssertEqual(r?.ok, false, name)
            XCTAssertTrue(r?.why.contains("approved_goal digests") ?? false, "\(name): \(r?.why ?? "nil")")
        }
        let short = IntentPolicy(approvedGoal: ApprovedGoalRef(goalDigest: "AAAA", policyDigest: g))
        XCTAssertEqual(Intent.decide(nil, grant: .object([:]), policy: short)?.ok, false)
    }
}
