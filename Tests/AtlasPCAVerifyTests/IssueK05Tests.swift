import XCTest
@testable import AtlasPCAVerify

/// Pinned to packages/pca/src: PCACTN_DEFAULT_TTL_MS (pcactn.ts:150), the 16-byte goal salt and the grant's own goal_commit
/// (envelope.ts:188-191), and `holder_pq` kept only for an unchanged holder (capability.ts:399).
final class IssueK05Tests: XCTestCase {
    private func key(_ b: UInt8) throws -> PCASuiteKey { PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: b, count: 32))) }

    private func envelope() -> JObject {
        ["predicates": .array([.object(["verb": .string("*")])]), "caveats": .array([]),
         "risk_policy": .object(["weights": .object(["alpha": .double(0.25), "beta": .double(0), "gamma": .double(0), "delta": .double(0), "epsilon": .double(0), "zeta": .double(0)]), "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1)])]
    }

    func testDefaultTtlIsTwentyMinutes() {
        XCTAssertEqual(PCAIssue.DEFAULT_TTL_MS, 1_200_000)
    }

    func testGeneratedGoalSaltIsSixteenBytes() throws {
        let g = try PCAIssue.mintGrant(principal: try key(0), holder: try key(1).id!, envelope: envelope(), goal: "g")
        XCTAssertEqual(g.goalSalt.count, 22)
        XCTAssertNotNil(Base64URLStrict.decode(g.goalSalt, length: 16))
    }

    func testEnvelopeCannotOverrideItsTypeOrGoalCommit() throws {
        var e = envelope()
        e["type"] = .string("not-an-envelope")
        e["goal_commit"] = .string("forged")
        let g = try PCAIssue.mintGrant(principal: try key(0), holder: try key(1).id!, envelope: e, goal: "g", salt: "c2FsdA")
        let env = g.grant.get("caveats")?.asArray?.first
        XCTAssertEqual(env?.get("type")?.asString, "envelope")
        XCTAssertEqual(env?.get("goal_commit")?.asString, try PCAIssue.goalCommit(goal: "g", salt: "c2FsdA"))
        XCTAssertEqual(g.goalCommit, try PCAIssue.goalCommit(goal: "g", salt: "c2FsdA"))
    }

    func testHolderPqIsKeptOnlyForAnUnchangedHolder() throws {
        let me = try key(1), other = try key(2)
        let root = try PCAIssue.mintRoot(principal: try key(0), holder: me.id!, holderPqPk: "cHEtcGs", caveats: [])
        let committed = Capability.holderPqCommitment("cHEtcGs")
        XCTAssertEqual(root.get("holder_pq")?.asString, committed)
        XCTAssertEqual(try PCAIssue.delegate(parent: root, toHolder: me.id!, added: [], signer: me).get("holder_pq")?.asString, committed)
        XCTAssertNil(try PCAIssue.delegate(parent: root, toHolder: other.id!, added: [], signer: me).get("holder_pq"))
    }
}

/// mintGrant as the reference (envelope.ts): its named members only, each checked before anything is signed.
final class IssueK05MintGrantTests: XCTestCase {
    private func key(_ b: UInt8) throws -> PCASuiteKey { .ed25519(try PCAEdKey(seed: [UInt8](repeating: b, count: 32))) }
    private func envelope() -> JObject {
        ["predicates": .array([.object(["verb": .string("*")])]), "caveats": .array([]),
         "risk_policy": .object(["weights": .object(["alpha": .double(0.25), "beta": .double(0), "gamma": .double(0), "delta": .double(0), "epsilon": .double(0), "zeta": .double(0)]),
                                 "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1)])]
    }
    private func mint(_ e: JObject) throws -> JSONValue {
        try PCAIssue.mintGrant(principal: try key(0), holder: try key(1).id!, envelope: e, goal: "g", salt: "c2FsdA").grant
    }

    func testAnUnknownMemberNeverReachesTheGrant() throws {
        var e = envelope()
        e["budget"] = .int(5)
        e["progress"] = .int(1)
        let env = try mint(e).get("caveats")?.asArray?.first
        XCTAssertNil(env?.get("budget"))
        XCTAssertEqual(env?.get("progress"), .int(1))
        XCTAssertEqual(env?.get("agent_binding"), .object([:]))
    }

    func testBadMembersAreRefusedByName() throws {
        let cases: [(String, JSONValue)] = [("units", .int(1)), ("tighten", .int(1)), ("template_ref", .int(1)), ("actions", .int(1)), ("provenance", .int(1)), ("model_polarity", .string("other")), ("risk_policy", .int(1))]
        for (k, v) in cases {
            var e = envelope()
            e[JKey(k)] = v
            XCTAssertThrowsError(try mint(e), k) { XCTAssertTrue(String(describing: $0).contains("mintGrant: "), "\($0)") }
        }
        var legacy = envelope()
        legacy["model_polarity"] = .string("legacy")
        XCTAssertEqual(try mint(legacy).get("caveats")?.asArray?.first?.get("model_polarity"), .string("legacy"))
    }
}
