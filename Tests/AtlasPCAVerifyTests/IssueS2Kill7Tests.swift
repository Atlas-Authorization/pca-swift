import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The producer side (Issue.swift): what goes into a signed body, the Merkle plan proofs, the escalation answer, the passport.
/// The pq_sig members of a hybrid suite can only be produced where ML-DSA signs (macOS/iOS 26); those tests skip elsewhere.
final class S2G7IssueKillTests: XCTestCase {
    typealias J = JSONValue

    func key(_ b: UInt8) throws -> PCASuiteKey { PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: b, count: 32))) }

    // ---- the holder_pq commitment is part of the signed body ----

    func testHolderPqIsSigned() throws {
        let me = try key(1)
        let root = try PCAIssue.mintRoot(principal: try key(0), holder: me.id!, holderPqPk: "cHEtcGs", caveats: [])
        let body: JObject = ["issuer": J.string(try key(0).id!), "holder": J.string(me.id!), "caveats": J.array([]), "parent": J.null,
                             "holder_pq": J.string(Capability.holderPqCommitment("cHEtcGs"))]
        XCTAssertEqual(root.get("id")?.asString, try PCAIssue.strictDigest(J.object(body)), "the capability id is the digest of the body WITH holder_pq")
        XCTAssertEqual(root.get("body_digest")?.asString, root.get("id")?.asString)
    }

    // ---- plan proofs ----

    func testEveryNodeOfASixNodePlanProvesInclusion() throws {
        let nodes: [JObject] = (0..<6).map { ["id": J.string("n\($0)"), "verb": J.string("v"), "resource": J.string("r\($0)")] }
        let plan = try PCAIssue.commitPlan(nodes)
        for (i, n) in nodes.enumerated() {
            let id = n["id"]?.asString ?? ""
            let proof = try plan.proofFor(id)
            let leaf = try XCTUnwrap(Merkle.planLeaf(J.string(id), n, try PCAIssue.conditionsDigest(n["pre"], n["post"])))
            XCTAssertTrue(Merkle.verifyInclusion(plan.root, proof.asObject, leaf), "node \(i)")
        }
    }

    // ---- buildPCActn ----

    func testParamsMustMatchThePlanNodeDigest() throws {
        let params: JSONValue = J.object(["a": J.int(1)])
        let good = try PCAIssue.strictDigest(params)
        let plan = try PCAIssue.commitPlan([["id": J.string("n1"), "verb": J.string("v"), "resource": J.string("r"), "params_digest": J.string(good)]])
        func spec(_ p: JSONValue) throws -> PCAIssue.ActSpec {
            PCAIssue.ActSpec(grant: J.object(["id": J.string("g")]), chain: [], plan: plan, nodeId: "n1", params: p, counter: 1, signer: try key(1), aud: "aud", iat: 1)
        }
        XCTAssertNoThrow(try PCAIssue.buildPCActn(try spec(params)))
        XCTAssertThrowsError(try PCAIssue.buildPCActn(try spec(J.object(["a": J.int(2)])))) { XCTAssertTrue(String(describing: $0).contains("params do not match plan node n1"), "\($0)") }
    }

    // ---- signed artifacts ----

    func testAnArtifactOutsideItsShapeIsRefused() throws {
        XCTAssertThrowsError(try PCAIssue.signDischarge(J.object([:]), issuer: try key(1))) { XCTAssertTrue(String(describing: $0).hasPrefix("signDischarge: "), "\($0)") }
        XCTAssertThrowsError(try PCAIssue.signNarrow(J.object([:]), holder: try key(1))) { XCTAssertTrue(String(describing: $0).hasPrefix("signNarrow: "), "\($0)") }
    }

    func testEscalationAnswerMembers() throws {
        let grant: JSONValue = J.object(["id": J.string("g1")])
        let act: JSONValue = J.object(["a": J.int(1)])
        let render = Base64URLStrict.encode([UInt8](repeating: 7, count: 32))
        let a = try PCAIssue.escalationAnswer(principal: try key(5), grant: grant, pcactn: act, lastCounter: 5, allow: true, iat: 1000, expiresAt: 2000, renderDigest: render)
        XCTAssertEqual(a.get("v"), J.int(1))
        XCTAssertEqual(a.get("kind")?.asString, "pca-escalation-answer")
        XCTAssertEqual(a.get("decision")?.asString, "allow")
        XCTAssertEqual(a.get("render_digest")?.asString, render)
        XCTAssertEqual(a.get("policy_digest")?.asString, PCA.escalationPolicyDigest(grant: grant))
        XCTAssertEqual(a.get("action_digest")?.asString, PCA.escalationActionDigest(pcactn: act))
        XCTAssertEqual(a.get("history_head")?.asString, PCA.escalationHistoryHead(lastCounter: 5))
        XCTAssertEqual(Base64URLStrict.decode(a.get("nonce")?.asString ?? "")?.count, 16, "a 16-byte nonce")
        let d = try PCAIssue.escalationAnswer(principal: try key(5), grant: grant, pcactn: act, lastCounter: nil, allow: false, iat: 1000, expiresAt: 2000)
        XCTAssertEqual(d.get("decision")?.asString, "deny")
        XCTAssertNil(d.get("render_digest"))
        XCTAssertEqual(d.get("history_head")?.asString, PCA.escalationHistoryHead(lastCounter: nil))
    }

    // ---- passports ----

    func passport(hardware: Bool) throws -> JObject {
        try PCAIssue.issuePassport(["model_id": J.string("m"), "weights_digest": J.string("w"), "system_prompt_digest": J.string("s"), "tool_manifest_digest": J.string("t"),
                                    "runtime_measurement": J.string("r"), "operator": J.string("o"), "hardware_rooted": J.bool(hardware)])
    }

    func testHardwareRootedNeedsEvidence() throws {
        let hw = try passport(hardware: true)
        XCTAssertThrowsError(try PCAIssue.signPassport(hw, issuer: try key(1), subject: "s", iat: 100, exp: 200), "no evidence")
        XCTAssertNoThrow(try PCAIssue.signPassport(hw, issuer: try key(1), subject: "s", iat: 100, exp: 200, evidence: ["quote": J.string("q")]))
        XCTAssertNoThrow(try PCAIssue.signPassport(try passport(hardware: false), issuer: try key(1), subject: "s", iat: 100, exp: 200))
    }

    func testPassportWindowAndEvidence() throws {
        let p = try passport(hardware: false)
        XCTAssertThrowsError(try PCAIssue.signPassport(p, issuer: try key(1), subject: "s", iat: 100, exp: 100), "exp == nbf")
        XCTAssertThrowsError(try PCAIssue.signPassport(p, issuer: try key(1), subject: "s", iat: 100, nbf: 150, exp: 150), "exp == explicit nbf")
        XCTAssertNoThrow(try PCAIssue.signPassport(p, issuer: try key(1), subject: "s", iat: 100, nbf: 150, exp: 151))
        // the evidence is carried, stamped with the issue time unless it brings its own
        let a = try PCAIssue.signPassport(p, issuer: try key(1), subject: "s", iat: 100, exp: 200, evidence: ["quote": J.string("q")])
        XCTAssertEqual(a.get("evidence")?.get("quote")?.asString, "q")
        XCTAssertEqual(a.get("evidence")?.get("at"), J.int(100))
        let b = try PCAIssue.signPassport(p, issuer: try key(1), subject: "s", iat: 100, exp: 200, evidence: ["quote": J.string("q"), "at": J.int(42)])
        XCTAssertEqual(b.get("evidence")?.get("at"), J.int(42))
        let c = try PCAIssue.signPassport(p, issuer: try key(1), subject: "s", iat: 100, exp: 200)
        XCTAssertNil(c.get("evidence"))
    }

    // ---- hybrid suites (ML-DSA signing: macOS/iOS 26 only) ----

    func hybridKey() throws -> PCASuiteKey {
        try XCTSkipUnless(PCAPQKey.signingAvailable, "ML-DSA signing is not available on this OS")
        let ed = try PCAEdKey(seed: [UInt8](repeating: 3, count: 32))
        let pq = try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 4, count: 32))
        return try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed, pq: pq)
    }

    func testHybridSignaturesCarryTheirPqHalf() throws {
        let k = try hybridKey()
        let root = try PCAIssue.mintRoot(principal: k, holder: try key(1).id!, caveats: [])
        XCTAssertNotNil(root.get("pq_sig")?.asString)
        let d = try PCAIssue.signArtifact(domain: "d\u{0}", body: J.object(["x": J.int(1)]), signer: k)
        XCTAssertNotNil(d["pq_sig"]?.asString)
        let p = try PCAIssue.signPassport(try passport(hardware: false), issuer: k, subject: "s", iat: 100, exp: 200)
        XCTAssertNotNil(p.get("pq_sig")?.asString)
        let plan = try PCAIssue.commitPlan([["id": J.string("n1"), "verb": J.string("v"), "resource": J.string("r")]])
        let act = try PCAIssue.buildPCActn(PCAIssue.ActSpec(grant: root, chain: [root], plan: plan, nodeId: "n1", counter: 1, signer: k, aud: "a", iat: 1))
        XCTAssertNotNil(act.get("pq_sig")?.asString)
    }
}
