import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Forbid-wins clause decisions (veto polarity, signer precedence, permit signers), the capability hop type check, and the plan-root defaults of the
/// core PCActn verifier.
final class SwC1ForbidCapabilityPlanRootTests: XCTestCase {
    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }
    func ctx(_ verb: String = "x") -> JSONValue { .object(["action": .object(["verb": .string(verb), "resource": .string("/r")])]) }
    let X = #"{"verb":"x"}"#
    /// A trigger that cannot be decided: it reads a parameter the action does not carry.
    let UNKNOWN = #"{"verb":"x","where":[{"field":"action.params.ok","op":"eq","value":true}]}"#

    func values(_ d: ClauseDecision) -> [String] { d.values.compactMap { $0.get("value")?.asString } }

    func testPermitIsReadAffirmativelyAndForbidWithVetoPolarity() {
        let permit = ForbidClauses.decideClauses(J(#"[{"id":"p","kind":"permit","when":\#(UNKNOWN)}]"#), ctx())
        XCTAssertEqual(values(permit), ["false"])
        XCTAssertEqual(permit.decision, "deny")
        XCTAssertEqual(permit.winnerKind, "none")
        let forbid = ForbidClauses.decideClauses(J(#"[{"id":"f","kind":"forbid","when":\#(UNKNOWN)},{"id":"p","kind":"permit","when":\#(X)}]"#), ctx())
        XCTAssertEqual(values(forbid), ["unknown", "true"])
        XCTAssertEqual(forbid.decision, "deny")
        XCTAssertEqual(forbid.winnerKind, "forbid")
        XCTAssertEqual(forbid.winnerId, "f")
        XCTAssertEqual(forbid.shadowed, ["p"])
        let miss = ForbidClauses.decideClauses(J(#"[{"id":"f","kind":"forbid","when":{"verb":"y"}},{"id":"p","kind":"permit","when":\#(X)}]"#), ctx())
        XCTAssertEqual(values(miss), ["false", "true"])
        XCTAssertEqual(miss.decision, "allow")
    }

    func testMostAuthoritativeSignerWinsThenTheLowestId() {
        let two = J(#"[{"id":"f-a","kind":"forbid","signer":"s2","when":\#(X)},{"id":"f-b","kind":"forbid","signer":"s1","when":\#(X)}]"#)
        let d = ForbidClauses.decideClauses(two, ctx(), precedence: ["s1", "s2"])
        XCTAssertEqual(d.winnerId, "f-b")
        XCTAssertEqual(d.shadowed, ["f-a"])
        // an unlisted signer ranks last
        let unlisted = J(#"[{"id":"a","kind":"forbid","signer":"zz","when":\#(X)},{"id":"b","kind":"forbid","signer":"s2","when":\#(X)}]"#)
        XCTAssertEqual(ForbidClauses.decideClauses(unlisted, ctx(), precedence: ["s1", "s2"]).winnerId, "b")
        // equal rank: the lowest id (policy order does not matter)
        let tie = J(#"[{"id":"b","kind":"forbid","when":\#(X)},{"id":"a","kind":"forbid","when":\#(X)}]"#)
        let t = ForbidClauses.decideClauses(tie, ctx())
        XCTAssertEqual(t.winnerId, "a")
        XCTAssertEqual(t.shadowed, ["b"])
    }

    func testPermitSignersDropOnlyPermitsFromOtherSigners() {
        let permits = J(#"[{"id":"p1","kind":"permit","signer":"s1","when":\#(X)},{"id":"p2","kind":"permit","signer":"s2","when":\#(X)},{"id":"p3","kind":"permit","when":\#(X)}]"#)
        let d = ForbidClauses.decideClauses(permits, ctx(), permitSigners: ["s1"])
        XCTAssertEqual(values(d), ["true", "false", "false"])
        XCTAssertEqual(d.decision, "allow")
        XCTAssertEqual(d.winnerId, "p1")
        XCTAssertEqual(d.shadowed, [])
        XCTAssertEqual(values(ForbidClauses.decideClauses(permits, ctx())), ["true", "true", "true"])
        let none = ForbidClauses.decideClauses(permits, ctx(), permitSigners: [])
        XCTAssertEqual(values(none), ["false", "false", "false"])
        XCTAssertEqual(none.decision, "deny")
        // a forbid is never dropped, whoever signed it
        let withForbid = J(#"[{"id":"p1","kind":"permit","signer":"s1","when":\#(X)},{"id":"f","kind":"forbid","when":\#(X)},{"id":"f2","kind":"forbid","signer":"other","when":\#(X)}]"#)
        let w = ForbidClauses.decideClauses(withForbid, ctx(), permitSigners: ["s1"])
        XCTAssertEqual(values(w), ["true", "true", "true"])
        XCTAssertEqual(w.decision, "deny")
        XCTAssertEqual(w.winnerKind, "forbid")
    }

    func testAnEscalateOverridesAPermit() {
        let d = ForbidClauses.decideClauses(J(#"[{"id":"p","kind":"permit","when":\#(X)},{"id":"e","kind":"escalate","when":\#(X)}]"#), ctx())
        XCTAssertEqual(d.decision, "escalate")
        XCTAssertEqual(d.winnerKind, "escalate")
        XCTAssertEqual(d.winnerId, "e")
        XCTAssertEqual(d.shadowed, ["p"])
    }

    // ---- Capability ------------------------------------------------------------------------------------------------------------

    func testCapabilityWithoutCaveatsIsMalformed() {
        let hop: JObject = ["id": .string("a"), "issuer": .string("i"), "holder": .string("h"), "body_digest": .string("d"), "sig": .string("s")]
        XCTAssertFalse(Capability.wellTyped(.object(hop)))
        var withCaveats = hop
        withCaveats["caveats"] = .array([])
        XCTAssertTrue(Capability.wellTyped(.object(withCaveats)))
        withCaveats["caveats"] = .string("x")
        XCTAssertFalse(Capability.wellTyped(.object(withCaveats)))
    }

    // ---- PCActn ----------------------------------------------------------------------------------------------------------------

    func testEveryVerifyOverloadRefusesWithoutAConfiguredPlanRoot() throws {
        let doc = try ConformanceTests.load("plan-root-vectors.json")
        let core = try ConformanceTests.load("vectors.json")
        let c = try XCTUnwrap(doc.get("plan_root_authorized")?.asArray?.first)
        let vname = try XCTUnwrap(c.get("vector")?.asString)
        let v = try XCTUnwrap(core.get("vectors")?.asArray?.first { $0.get("name")?.asString == vname }, "vector \(vname)")
        let pcactn = try XCTUnwrap(v.get("pcactn"))
        let grant = v.get("grant") ?? .null
        let now = try XCTUnwrap(v.get("context")?.get("now")?.safeInt)
        let aud = try XCTUnwrap(v.get("context")?.get("aud")?.asString)
        let text = try Canonical.canonicalizeStrict(pcactn)
        let verdicts: [(String, PCA.Verdict)] = [
            ("pcactn/String", PCA.verify(pcactn: pcactn, grant: grant, now: now, audience: aud)),
            ("pcactn/Audience", PCA.verify(pcactn: pcactn, grant: grant, now: now, audience: PCA.Audience.id(aud))),
            ("json/String", PCA.verify(json: text, grant: grant, now: now, audience: aud)),
            ("json/Audience", PCA.verify(json: text, grant: grant, now: now, audience: PCA.Audience.id(aud))),
        ]
        for (name, verdict) in verdicts {
            XCTAssertEqual(verdict.checks["plan_root_authorized"], false, name)
            XCTAssertFalse(verdict.allow, name)
        }
    }
}
