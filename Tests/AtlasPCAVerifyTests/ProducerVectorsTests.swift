import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays producer-vectors.json: every producer must reproduce the TypeScript reference's output byte for byte (Ed25519 is deterministic),
/// and the TS-produced PCActns must pass this SDK's verifier. Apple's CryptoKit hedges Ed25519, so there the replay signs through
/// the RFC 8032 deterministic signer (`Ed25519Deterministic`); on Linux it replays the platform signer itself. Plus round trips of the native producer through the native verifier,
/// including the ML-DSA suites where CryptoKit provides them (macOS / iOS 26), which must otherwise refuse as `unsupported_suite`.
final class ProducerVectorsTests: XCTestCase {
    struct Fail: Error, CustomStringConvertible { let description: String }

    static func canon(_ v: JSONValue) -> String { Canonical.canonicalize(v) }

    func edKey(_ doc: JSONValue, _ name: String) throws -> PCAEdKey {
        guard let s = doc.get("keys")?.get(name)?.get("seed")?.asString, let b = Base64URLStrict.decode(s, length: 32) else { throw Fail(description: "no key \(name)") }
        return try Ed25519Deterministic.key(seed: b)
    }

    func run(_ doc: JSONValue, _ op: String, _ a: JSONValue) throws -> JSONValue {
        func str(_ k: String) throws -> String { guard let s = a.get(k)?.asString else { throw Fail(description: "missing \(k)") }; return s }
        func key(_ k: String) throws -> PCAEdKey { try edKey(doc, try str(k)) }
        func suite(_ k: String) throws -> PCASuiteKey { PCASuiteKey.ed25519(try key(k)) }
        func obj(_ k: String) throws -> JObject { guard let o = a.get(k)?.asObject else { throw Fail(description: "missing \(k)") }; return o }
        func int(_ k: String) throws -> Int64 { guard let i = a.get(k)?.safeInt else { throw Fail(description: "missing \(k)") }; return i }
        func nodes(_ k: String) throws -> [JObject] { (a.get(k)?.asArray ?? []).compactMap { $0.asObject } }
        switch op {
        case "ed25519_sign":
            let k = try Ed25519Deterministic.key(seed: Base64URLStrict.decode(try str("seed"), length: 32) ?? [])
            return .object(["public": .string(k.id), "sig": .string(Base64URLStrict.encode(try k.sign(Canonical.utf8(try str("message_utf8")))))])
        case "goal_commit": return .object(["commit": .string(try PCAIssue.goalCommit(goal: try str("goal"), salt: try str("salt")))])
        case "params_digest":
            let p = a.get("params")
            return .object(["digest": .string(Merkle.paramsDigest(p))])
        case "plan_commit":
            let ns = try nodes("nodes")
            let p = try PCAIssue.commitPlan(ns)
            var proofs: JObject = [:]
            for n in ns { let id = n["id"]!.asString!; proofs[JKey(id)] = try p.proofFor(id) }
            return .object(["root": .string(p.root), "proofs": .object(proofs)])
        case "mint_grant":
            let g = try PCAIssue.mintGrant(principal: try suite("principal"), holder: try key("holder").id, envelope: try obj("envelope"), goal: try str("goal"), salt: try str("salt"))
            return .object(["grant": g.grant, "goal_commit": .string(g.goalCommit), "goal_salt": .string(g.goalSalt)])
        case "delegate":
            guard let parent = a.get("parent") else { throw Fail(description: "parent") }
            var to = parent.get("holder")!.asString!
            if let n = a.get("to_holder")?.asString { to = try edKey(doc, n).id }
            return try PCAIssue.delegate(parent: parent, toHolder: to, added: a.get("added_caveats")?.asArray ?? [], signer: try suite("signer"))
        case "act":
            let plan = try PCAIssue.commitPlan(try nodes("plan"))
            var extras: JObject = [:]
            for k in ["nonce", "caution", "rationale_commitment", "tool_binding", "fresh_at"] { if let v = a.get(k) { extras[JKey(k)] = v } }
            let p = try PCAIssue.buildPCActn(.init(grant: a.get("grant")!, chain: a.get("chain")?.asArray ?? [], plan: plan, nodeId: try str("node_id"), params: a.get("params"),
                                                   counter: try int("counter"), signer: try suite("signer"), aud: try str("aud"), iat: try int("iat"), exp: try int("exp"), extras: extras))
            let tm = try PCA.thresholdMessage(p.asObject!)
            return .object(["pcactn": p, "threshold_message": .string(Base64URLStrict.encode(tm)), "header": .string(PCAIssue.header(p))])
        case "fresh_at": return try PCAIssue.signFreshAt(rs: try key("signer"), scope: try str("scope"), state: try obj("state"), issuedAt: try int("issued_at"))
        case "escalation_digests":
            let last = a.get("last_counter")?.safeInt
            return .object(["policy_digest": .string(PCA.escalationPolicyDigest(grant: a.get("grant")!)!), "action_digest": .string(PCA.escalationActionDigest(pcactn: a.get("pcactn")!)!),
                            "history_head": .string(PCA.escalationHistoryHead(lastCounter: last)!)])
        case "sign_escalation_answer": return try PCAIssue.signEscalationAnswer(a.get("body")!, principal: try suite("signer"))
        case "sign_discharge": return try PCAIssue.signDischarge(a.get("body")!, issuer: try suite("signer"))
        case "discharge_digest": return .object(["digest": .string(PCA.dischargeDigest(a.get("discharge")!)!)])
        case "sign_narrow": return try PCAIssue.signNarrow(a.get("body")!, holder: try suite("signer"))
        case "sign_passport":
            let pp = try PCAIssue.issuePassport(try obj("identity"))
            let signed = try PCAIssue.signPassport(pp, issuer: try suite("issuer"), subject: try key("subject").id, iat: a.get("identity")!.get("issued_at")!.safeInt!, exp: try int("exp"))
            return .object(["passport": .object(pp), "signed": signed])
        case "sign_workflow": return try PCAIssue.signWorkflow(principal: try key("signer"), body: a.get("body")!)
        case "sign_step_receipt":
            return try PCAIssue.signStepReceipt(rs: try key("signer"), workflow: a.get("workflow")!, step: try str("step"), outcome: try str("outcome"), paramsDigest: try str("params_digest"),
                                                outputs: a.get("outputs")!, issuedAt: try int("issued_at"), prev: a.get("prev"))
        case "sign_read_grant": return try PCAIssue.signReadGrant(principal: try key("signer"), body: a.get("body")!)
        case "sign_aggregate_grant": return try PCAIssue.signAggregateGrant(principal: try key("signer"), body: a.get("body")!)
        default: throw Fail(description: "unknown op \(op)")
        }
    }

    func testEveryCaseIsReproducedByteForByte() throws {
        let doc = try ConformanceTests.load("producer-vectors.json")
        let cases = doc.get("cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 30)
        var failures: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            do {
                let got = try run(doc, c.get("op")!.asString!, c.get("args")!)
                if Self.canon(got) != Self.canon(c.get("expect")!) { failures.append("\(name): output differs") }
            } catch { failures.append("\(name): \(error)") }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }

    /// Cross-verification: the TS-produced PCActns pass THIS SDK's verifier.
    func testReferenceActionsVerify() throws {
        let doc = try ConformanceTests.load("producer-vectors.json")
        var n = 0
        for c in doc.get("cases")?.asArray ?? [] where c.get("op")?.asString == "act" {
            let a = c.get("args")!
            if a.get("fresh_at") != nil { continue } // refused without a fresh_at policy (fail closed)
            let v = PCA.verify(pcactn: c.get("expect")!.get("pcactn")!, grant: a.get("grant")!, now: a.get("iat")!.safeInt! + 1000, audience: a.get("aud")!.asString!)
            XCTAssertTrue(v.allow, "\(c.get("name")?.asString ?? ""): \(v.reason)")
            n += 1
        }
        XCTAssertGreaterThanOrEqual(n, 4)
    }

    private let now: Int64 = 1_800_000_000_000
    private func envelope() -> JObject {
        ["predicates": .array([.object(["verb": .string("*")])]), "caveats": .array([]), "risk_policy": .object(["weights": .object(["alpha": .double(0.25)]), "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1)])]
    }

    func testNativeRoundTripEd25519AndDelegation() throws {
        let p = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 0, count: 32)))
        let me = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 1, count: 32)))
        let sub = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 2, count: 32)))
        let g = try PCAIssue.mintGrant(principal: p, holder: me.id!, envelope: envelope(), goal: "g")
        let agent = try PCAAgent(signer: me, aud: "ins_t", grant: g.grant)
        agent.clock = { self.now }
        let a1 = try agent.act(verb: "read", resource: "x")
        XCTAssertEqual(a1.get("counter")?.safeInt, 1)
        let v = PCA.verify(pcactn: a1, grant: g.grant, now: now + 1, audience: "ins_t")
        XCTAssertTrue(v.allow, v.reason)
        XCTAssertNotEqual(try agent.act(verb: "read", resource: "x").get("nonce"), a1.get("nonce"))
        let child = try agent.delegate(to: sub, addedCaveats: [.object(["type": .string("max_uses"), "id": .string("u1"), "n": .int(3), "until": .int(now + 3_600_000)])])
        XCTAssertEqual(child.chain.count, 2)
        let v2 = PCA.verify(pcactn: try child.act(verb: "read", resource: "x"), grant: g.grant, now: now + 1, audience: "ins_t")
        XCTAssertTrue(v2.allow, v2.reason)
        var tampered = a1.asObject!
        var action = tampered["action"]!.asObject!
        action["resource"] = .string("y")
        tampered["action"] = .object(action)
        XCTAssertFalse(PCA.verify(pcactn: .object(tampered), grant: g.grant, now: now + 1, audience: "ins_t").allow)
        XCTAssertEqual(PCAAgent.headerValue(a1), Base64URLStrict.encode(Canonical.utf8(PCAIssue.encode(a1))))
    }

    /// ML-DSA signs where CryptoKit has it; elsewhere the suite is refused with the same `unsupported_suite` reason as the verifier.
    func testMLDSAHybridRoundTripOrRefusal() throws {
        let ed = try PCAEdKey(seed: [UInt8](repeating: 6, count: 32))
        guard PCAPQKey.signingAvailable else {
            XCTAssertThrowsError(try PCAPQKey.generate(.mlDsa65)) { XCTAssertTrue("\($0)".contains("unsupported_suite")) }
            return
        }
        let pPq = try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 3, count: 32))
        XCTAssertEqual(pPq.pk, try PCAPQKey.fromSeed(.mlDsa65, seed: [UInt8](repeating: 3, count: 32)).pk) // seeded keys are reproducible
        XCTAssertEqual(pPq.pk.count, 1952)
        let principal = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: try PCAEdKey(seed: [UInt8](repeating: 0, count: 32)), pq: pPq)
        let aPq = try PCAPQKey.generate(.mlDsa65)
        let me = try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed, pq: aPq)
        let g = try PCAIssue.mintGrant(principal: principal, holder: ed.id, holderPqPk: aPq.pkB64u, envelope: envelope(), goal: "g")
        let agent = try PCAAgent(signer: me, aud: "ins_t", grant: g.grant)
        agent.clock = { self.now }
        let a = try agent.act(verb: "read", resource: "x")
        XCTAssertEqual(a.get("alg")?.asString, "hybrid-ed25519-ml-dsa-65")
        let v = PCA.verify(pcactn: a, grant: g.grant, now: now + 1, audience: "ins_t")
        XCTAssertTrue(v.allow, v.reason)
        // Set in CI (PCA_PRODUCER_OUT): the post-quantum PCActn for the reference implementation to verify (a randomised
        // signature cannot be a byte vector, so the reference checks it instead: packages/pca producer-native fixtures).
        if let out = ProcessInfo.processInfo.environment["PCA_PRODUCER_OUT"], !out.isEmpty {
            let doc: JSONValue = .object(["lang": .string("swift"), "aud": .string("ins_t"), "now": .int(now + 1),
                                          "cases": .array([.object(["alg": .string("hybrid-ed25519-ml-dsa-65 (root and leaf)"), "grant": g.grant, "pcactn": a])])])
            try Data(Canonical.canonicalize(doc).utf8).write(to: URL(fileURLWithPath: out))
        }
    }

    func testSuiteKeysFailClosed() throws {
        let ed = try PCAEdKey.generate()
        XCTAssertThrowsError(try PCASuiteKey(alg: "ml-dsa-65", ed: nil))
        XCTAssertThrowsError(try PCASuiteKey(alg: "hybrid-ed25519-ml-dsa-65", ed: ed))
        XCTAssertThrowsError(try PCASuiteKey(alg: "slh-dsa-sha2-128f", ed: ed))
        XCTAssertThrowsError(try PCASuiteKey(alg: "fn-dsa-512", ed: ed))
        XCTAssertThrowsError(try PCAEdKey(seed: [UInt8](repeating: 0, count: 31)))
    }
}
