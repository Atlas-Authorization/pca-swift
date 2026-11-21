import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kill tests (mutation sheet swift-k05 group 6) for AttestCert.swift, ReadVault.swift, PCActn.swift, StrictParser.swift, Agent.swift
/// and Escalation.swift.
final class S2G6AttestCertKillTests: XCTestCase {
    private func attError(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch let e as AttestError { return e.message } catch { return "other: \(error)" }
    }

    private static let edAlg: [UInt8] = Sigstore.enc(0x30, Sigstore.enc(0x06, [0x2b, 0x65, 0x70]))

    // ---------------------------------------------------------------- parseDER (lines 130, 166)

    func testSignatureBitStringUnusedBitsAreChecked() {
        let tbs = Sigstore.enc(0x30, [])
        let der = Sigstore.enc(0x30, tbs + Self.edAlg + Sigstore.enc(0x03, [0x08]))
        XCTAssertEqual(attError { _ = try Cert.parseDER(der) }, OSSL.bits, "line 130")
    }

    func testSubjectNameIsChecked() {
        let serial = Sigstore.enc(0x02, [0x01])
        let validity = Sigstore.enc(0x30, Sigstore.enc(0x17, [0x30]) + Sigstore.enc(0x17, [0x30]))
        let badSubject = Sigstore.enc(0x30, Sigstore.enc(0x30, []))   // an RDN must be a SET (0x31)
        let tbs = Sigstore.enc(0x30, serial + Self.edAlg + Sigstore.enc(0x30, []) + validity + badSubject)
        let der = Sigstore.enc(0x30, tbs + Self.edAlg + Sigstore.enc(0x03, [0x00]))
        XCTAssertEqual(attError { _ = try Cert.parseDER(der) }, OSSL.wrongTag, "line 166")
    }

    // ---------------------------------------------------------------- checkIssued (lines 420, 424)

    private func issued(serialContent: [UInt8]) -> Bool {
        var c = AttCert()
        c.exts = [LenientExt(oid: "2.5.29.35", critical: false, value: Sigstore.enc(0x30, Sigstore.enc(0x82, serialContent)))]
        var up = AttCert()
        up.serial = serialContent
        up.raw = [0x30, 0x02, 0x30, 0x00] // a certificate with no keyUsage: nothing further to refuse
        return Cert.checkIssued(c, up)
    }

    func testAuthorityKeyIdentifierSerialMustBeMinimal() {
        let ok: [[UInt8]] = [[1], [0, 0x80], [0xff, 0x7f], [1, 2], [0x7f, 1], [0x80, 0], [0, 0x80, 5]]
        for s in ok { XCTAssertTrue(issued(serialContent: s), "line 424 minimal serial \(s)") }
        let bad: [[UInt8]] = [[0, 1], [0xff, 0x80], [0, 0x7f], [0xff, 0x80, 5]]
        for s in bad { XCTAssertFalse(issued(serialContent: s), "line 424 non-minimal serial \(s)") }
    }

    func testUndecodableDirectoryNamesRefuse() {
        var c = AttCert()
        c.exts = [LenientExt(oid: "2.5.29.35", critical: false, value: Sigstore.enc(0x30, Sigstore.enc(0xa1, [0x30, 0x05])))]
        var up = AttCert()
        up.raw = [0x30, 0x02, 0x30, 0x00]
        XCTAssertFalse(Cert.checkIssued(c, up), "line 420")
    }
}

final class S2G6ReadVaultKillTests: XCTestCase {
    func testAggregateStateDefaults() {
        let s = AggregateState()
        XCTAssertEqual(s.spentMicro, 0, "line 54")
        XCTAssertEqual(s.queries, 0, "line 54")
        XCTAssertEqual(s.answered, [:])
        XCTAssertEqual(AggregateState.empty, s)
    }

    func testAggregateParse() {
        let v: JSONValue = .object(["spent_micro": .int(5), "queries": .int(2), "answered": .object(["a": .int(7), "b": .int(-3)])])
        let s = AggregateState.parse(v)
        XCTAssertEqual(s?.spentMicro, 5)
        XCTAssertEqual(s?.queries, 2)
        XCTAssertEqual(s?.answered, [JKey("a"): 7, JKey("b"): -3], "lines 66, 67 every answered entry is kept")
        XCTAssertNil(AggregateState.parse(.object(["spent_micro": .int(5), "queries": .int(2), "answered": .object(["a": .string("x")])])))
        XCTAssertEqual(AggregateState.parse(.object(["spent_micro": .int(5), "queries": .int(2), "answered": .object([:])])),
                       AggregateState(spentMicro: 5, queries: 2, answered: [:]))
    }

    func testAggregateValidityBounds() {
        let m = Canonical.MAX_SAFE
        XCTAssertTrue(AggregateState(spentMicro: m, queries: m, answered: ["a": m, "b": -m]).valid, "lines 72, 73 the bounds are inclusive")
        XCTAssertFalse(AggregateState(spentMicro: m + 1, queries: 0).valid)
        XCTAssertFalse(AggregateState(spentMicro: 0, queries: m + 1).valid)
        XCTAssertFalse(AggregateState(spentMicro: -1, queries: 0).valid)
        XCTAssertFalse(AggregateState(spentMicro: 0, queries: -1).valid)
        XCTAssertFalse(AggregateState(answered: ["a": m + 1]).valid, "line 73 above the range")
        XCTAssertFalse(AggregateState(answered: ["a": -m - 1]).valid, "line 73 below the range")
        XCTAssertTrue(AggregateState().valid)
    }

    func testMemoryVaultIsSafeUnderConcurrentUse() {
        let vault = MemoryVault()
        DispatchQueue.concurrentPerform(iterations: 8) { t in
            for i in 0..<250 {
                vault.put("t\(t)-\(i)", VaultEntry(cls: "c", value: .int(Int64(i)), grant: "g", exp: 1))
                _ = vault.get("t\(t)-\(i / 2)")
            }
        }
        for t in 0..<8 {
            for i in 0..<250 { XCTAssertEqual(vault.get("t\(t)-\(i)")?.value, .int(Int64(i))) }
        }
    }
}

final class S2G6PCActnKillTests: XCTestCase {
    private static func b32(_ n: UInt8) -> String { Base64URLStrict.encode([UInt8](repeating: n, count: 32)) }
    private static var sig64: String { Base64URLStrict.encode([UInt8](repeating: 7, count: 64)) }

    private static func hop() -> JObject {
        ["id": .string(b32(1)), "issuer": .string(b32(2)), "holder": .string(b32(3)), "body_digest": .string(b32(4)), "caveats": .array([]), "sig": .string(sig64)]
    }

    /// A wire-valid PCActn (nothing in it is signed correctly).
    private static func pcactn() -> JSONValue {
        .object([
            "ver": .int(2),
            "action": .object(["verb": .string("read"), "resource": .string("x"), "params_digest": .string(b32(5)), "reversibility_class": .string("r")]),
            "grant_ref": .string(b32(1)), "cap_chain": .array([.object(hop())]),
            "plan": .object(["root": .string(b32(6)), "node_id": .string("n"), "inclusion_proof": .object(["index": .int(0), "size": .int(1), "path": .array([])])]),
            "attestation": .object(["epoch": .int(0), "quote_digest": .string("q"), "model_id": .string("m"), "measurement": .string("x"), "operator": .string("o")]),
            "provenance": .object(["causal_hash": .string("c"), "taint_level": .int(0), "trusted_refs": .array([])]),
            "freshness": .object(["epoch": .int(0), "beacon_ref": .string("b"), "accumulator_witness": .string("w")]),
            "counter": .int(1), "risk_claim": .object(["r": .int(0), "inputs": .object([:])]),
            "aud": .string("a"), "iat": .int(1000), "exp": .int(2000), "sig": .string(sig64),
        ])
    }

    func testVerdictDefaults() {
        let v = PCA.Verdict(allow: true, checks: [:], reason: "")
        XCTAssertFalse(v.legacyModelPolarity, "line 27")
        XCTAssertEqual(v.reasons, [])
    }

    func testLeafSignatureReasonNamesTheSuitePolicy() {
        let v = PCA.verify(pcactn: Self.pcactn(), grant: .object(Self.hop()), now: 1500, audience: "a", allowedSuites: [], insecureSkipPlanRootCheck: true)
        XCTAssertEqual(v.checks["leaf_signature"], false)
        XCTAssertTrue(v.reasons.contains("leaf_signature: leaf: signature suite 'ed25519' is not allowed by this verifier's suite policy"), "line 164 \(v.reasons)")
        let open = PCA.verify(pcactn: Self.pcactn(), grant: .object(Self.hop()), now: 1500, audience: "a", insecureSkipPlanRootCheck: true)
        XCTAssertTrue(open.reasons.contains("leaf_signature: signature does not verify under the leaf holder key"), "\(open.reasons)")
    }
}

final class S2G6StrictParserKillTests: XCTestCase {
    func testWhitespaceInsideEmptyContainers() throws {
        XCTAssertEqual(try StrictJSON.parse("{ }"), .object([:]), "line 194")
        XCTAssertEqual(try StrictJSON.parse("[ ]"), .array([]), "line 217")
        XCTAssertEqual(try StrictJSON.parse("{\n}"), .object([:]))
        XCTAssertEqual(try StrictJSON.parse("[\t]"), .array([]))
        XCTAssertEqual(try StrictJSON.parseLenient("{ }"), .object([:]))
        XCTAssertEqual(try StrictJSON.parseLenient("[ ]"), .array([]))
    }

    func testLenientNumberStopsAtTheLexemeEnd() throws {
        // line 132 1->2: a point is consumed alone; the character after it is not part of the number
        XCTAssertThrowsError(try StrictJSON.parseLenient("[1.,2]"), "H7: a number needs digits after the point, as JSON.parse")
        XCTAssertEqual(try StrictJSON.parseLenient("[1.5,2]"), .array([.double(1.5), .int(2)]))
    }
}

final class S2G6AgentKillTests: XCTestCase {
    private func producerMessage(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch let e as PCAProducerError { return e.message } catch { return "other: \(error)" }
    }

    private func envelope() -> JObject {
        ["predicates": .array([.object(["verb": .string("*")])]), "caveats": .array([]),
         "risk_policy": .object(["weights": .object(["alpha": .double(0.25), "beta": .double(0), "gamma": .double(0), "delta": .double(0), "epsilon": .double(0), "zeta": .double(0)]), "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1)])]
    }

    func testActNodeNeedsACommittedPlan() throws {
        let principal = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 0, count: 32)))
        let me = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 1, count: 32)))
        let g = try PCAIssue.mintGrant(principal: principal, holder: me.id!, envelope: envelope(), goal: "g")
        let a = try PCAAgent(signer: me, aud: "ins_t", grant: g.grant)
        a.clock = { 1_800_000_000_000 }
        XCTAssertEqual(producerMessage { _ = try a.actNode("n1") }, "commitPlan() first", "line 51")
        try a.commitPlan([["id": .string("n1"), "verb": .string("read"), "resource": .string("x")]])
        let p = try a.actNode("n1")
        XCTAssertEqual(p.get("counter")?.safeInt, 1, "line 35: the committed plan is kept")
        XCTAssertEqual(p.get("action")?.get("verb")?.asString, "read")
    }
}

final class S2G6EscalationKillTests: XCTestCase {
    func testAnEmptyPinnedPqKeyFailsClosed() {
        func b32(_ n: UInt8) -> String { Base64URLStrict.encode([UInt8](repeating: n, count: 32)) }
        let principal = b32(1)
        let answer: JSONValue = .object([
            "v": .int(1), "kind": .string("pca-escalation-answer"), "principal": .string(principal), "policy_digest": .string(b32(2)),
            "action_digest": .string(b32(3)), "history_head": .string(b32(4)), "decision": .string("allow"), "iat": .int(1), "expires_at": .int(2),
            "nonce": .string(Base64URLStrict.encode([UInt8](repeating: 9, count: 16))), "sig": .string("x"),
        ])
        XCTAssertNil(PCA.escalationAnswerShapeError(answer), "the answer is well-formed")
        let bind = EscalationBinding(policyDigest: b32(2), actionDigest: b32(3), historyHead: b32(4))
        let v = PCA.verifyEscalationAnswer(answer, principals: [PinnedSigner(principal, pqPk: "")], bind: bind, now: 1)
        XCTAssertEqual(v.reason, "escalation answer error (fail closed): the pinned pq_pk is empty", "line 117")
        let w = PCA.verifyEscalationAnswer(answer, principals: [PinnedSigner(principal)], bind: bind, now: 1)
        XCTAssertEqual(w.reason, "escalation answer signature invalid")
    }
}

final class S2G6CapabilityKillTests: XCTestCase {
    func testPqBindingNeedsACommitmentWhereMlDsaRuns() throws {
        // Capability.pqBindingError (line 65) only has something to refuse for a suite that carries a PQ key and this platform can run.
        try XCTSkipUnless(MLDSA.available, "ML-DSA is not available on this platform")
        let e = Capability.pqBindingError(["alg": .string("hybrid-ed25519-ml-dsa-65"), "pq_pk": .string("x")], committed: nil, label: "leaf")
        XCTAssertNotNil(e)
        XCTAssertNil(Capability.pqBindingError(["alg": .string("ed25519")], committed: nil, label: "leaf"))
    }
}
