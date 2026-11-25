import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The gateway's verifier hooks (attestation, threshold, zk, revocation) and enforcement gates (taint, freshness, attestation) in the core
/// verification step, the K1 input merge and the provenance log of full-policy mode. The proofs are minted here over real keys derived from fixed
/// seeds; no corpus (the reference oracle covers signature-only mode with the revocation hook only).
final class RefGatewayHooksTests: XCTestCase {
    typealias G = PCAGateway
    static let now: Int64 = 1_800_000_000_000

    static func envelope() -> JObject {
        ["predicates": .array([.object(["verb": .string("*")])]), "caveats": .array([]),
         "risk_policy": .object(["weights": .object(["alpha": .double(0.25), "beta": .double(0), "gamma": .double(0), "delta": .double(0), "epsilon": .double(0), "zeta": .double(0)]), "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1)])]
    }

    /// One signature-only request with a real signed proof bound to it; `tweak` edits the gateway options, `slots` adds signed PCActn members.
    static func decide(slots: JObject = [:], _ tweak: (inout G.GatewayOptions) -> Void = { _ in }) throws -> G.Decision {
        let principal = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 11, count: 32)))
        let me = PCASuiteKey.ed25519(try PCAEdKey(seed: [UInt8](repeating: 12, count: 32)))
        let grant = try PCAIssue.mintGrant(principal: principal, holder: me.id!, envelope: envelope(), goal: "g").grant
        let agent = try PCAAgent(signer: me, aud: "gw", grant: grant)
        agent.clock = { now }
        var req = G.GatewayRequest(method: "POST", path: "/refunds")
        let pcactn = try agent.act(verb: "read", resource: "x", params: .object(try G.requestBinding(req)), slots: slots)
        req.headers = [(G.PCA_HEADER, .one(PCAAgent.headerValue(pcactn)))]
        var o = G.GatewayOptions(audience: "gw", routes: [G.RouteRule(path: "/refunds", capability: G.RequiredCapability(verb: "read"))],
                                 resolveGrant: { _, _ in grant }, policy: .signatureOnly)
        o.insecureSkipPlanRootCheck = true
        o.replayGuard = G.memoryReplayGuard()
        o.revocation = { _, _, _ in .enforced(ok: true, reason: nil) }
        o.now = { now }
        tweak(&o)
        return try G.authorize(req, o)
    }

    func testBaselineReportsEveryGateNotEnforced() throws {
        let d = try Self.decide()
        XCTAssertTrue(d.allow, d.reason)
        XCTAssertEqual(d.verdict?.status("taint_gate"), "not-enforced")
        XCTAssertEqual(d.verdict?.status("attestation"), "not-enforced")
        XCTAssertEqual(d.verdict?.status("threshold"), "not-enforced")
        XCTAssertEqual(d.verdict?.status("revocation"), "pass")
        XCTAssertNil(d.verdict?.status("freshness"))
        XCTAssertNil(d.verdict?.status("zk_compliance"))
    }

    func testAttestationHook() throws {
        let ok = try Self.decide { $0.attestation = { _, _, _ in G.HookOutcome(enforced: true, ok: true) } }
        XCTAssertTrue(ok.allow)
        XCTAssertEqual(ok.verdict?.status("attestation"), "pass")
        let bad = try Self.decide { $0.attestation = { _, _, _ in G.HookOutcome(enforced: true, ok: false, reason: "bad quote") } }
        XCTAssertFalse(bad.allow)
        XCTAssertEqual(bad.code, .verifyFailed)
        XCTAssertEqual(bad.status, 401)
        XCTAssertEqual(bad.reason, "attestation: bad quote")
        let noReason = try Self.decide { $0.threshold = { _, _, _ in G.HookOutcome(enforced: true, ok: false) } }
        XCTAssertEqual(noReason.reason, "threshold: rejected")
        XCTAssertEqual(noReason.verdict?.status("threshold"), "fail")
    }

    func testAttestationGateFailsClosedUnlessNotRequired() throws {
        let required = try Self.decide { $0.enforce.attestation = G.AttestationGate(verifier: { _, _, _ in .notEnforced }) }
        XCTAssertFalse(required.allow)
        XCTAssertEqual(required.reason, "attestation: attestation required but the verifier reported not-enforced / no document (fail closed)")
        let optional = try Self.decide { $0.enforce.attestation = G.AttestationGate(verifier: { _, _, _ in .notEnforced }, required: false) }
        XCTAssertTrue(optional.allow)
        XCTAssertEqual(optional.verdict?.status("attestation"), "not-enforced")
        // the gate's verifier takes the slot in place of the hook
        let slot = try Self.decide {
            $0.attestation = { _, _, _ in G.HookOutcome(enforced: true, ok: false, reason: "hook") }
            $0.enforce.attestation = G.AttestationGate(verifier: { _, _, _ in G.HookOutcome(enforced: true, ok: true) })
        }
        XCTAssertTrue(slot.allow)
    }

    func testThrowingHookMakesTheProofMalformed() throws {
        struct Boom: Error {}
        let d = try Self.decide { $0.threshold = { _, _, _ in throw Boom() } }
        XCTAssertFalse(d.allow)
        XCTAssertEqual(d.verdict?.status("malformed"), "fail")
        XCTAssertTrue(d.reason.hasPrefix("malformed PCActn: "))
        // the revocation check after it never ran
        XCTAssertNil(d.verdict?.status("revocation"))
    }

    func testEnforcementGates() throws {
        // the minted proof carries a stub freshness anchor and an empty provenance: both gates refuse it
        let fresh = try Self.decide { $0.enforce.freshness = PCA.FreshnessGate(maxAgeMs: 60_000) }
        XCTAssertFalse(fresh.allow)
        XCTAssertEqual(fresh.verdict?.status("freshness"), "fail")
        XCTAssertEqual(fresh.reason, "freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
        let misconfigured = try Self.decide { $0.enforce.freshness = PCA.FreshnessGate(maxAgeMs: -1) }
        XCTAssertEqual(misconfigured.reason, "freshness: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)")
        let taint = try Self.decide { $0.enforce.taint = PCA.TaintGate(registry: EmptyTrustedInputRegistry(), maxTaint: 0) }
        XCTAssertFalse(taint.allow)
        XCTAssertEqual(taint.verdict?.status("taint_gate"), "fail")
    }

    func testCarriedZkProofFailsClosedWithoutAVerifier() throws {
        let slots: JObject = ["zk_compliance": .object(["proof": .string("p")])]
        let none = try Self.decide(slots: slots)
        XCTAssertFalse(none.allow)
        XCTAssertEqual(none.reason, "zk_compliance: PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed): configure hooks.zk or do not present a proof")
        let ok = try Self.decide(slots: slots) { $0.zk = { _, _, _ in G.HookOutcome(enforced: true, ok: true) } }
        XCTAssertTrue(ok.allow, ok.reason)
        XCTAssertEqual(ok.verdict?.status("zk_compliance"), "pass")
        let refused = try Self.decide(slots: slots) { $0.zk = { _, _, _ in G.HookOutcome(enforced: true, ok: false, reason: "bad proof") } }
        XCTAssertEqual(refused.reason, "zk_compliance: bad proof")
        // a hook that did not enforce is the same as no hook
        let skipped = try Self.decide(slots: slots) { $0.zk = { _, _, _ in .notEnforced } }
        XCTAssertFalse(skipped.allow)
    }

    func testCarriedBondRefIsUnsupportedNeverAPass() throws {
        let d = try Self.decide(slots: ["bond_ref": .string("b")])
        XCTAssertEqual(d.verdict?.status("bond"), "unsupported")
    }

    // MARK: full-policy inputs

    func testK1MergeKeepsConfiguredMembers() {
        let presented: (discharges: [JSONValue]?, narrow: JSONValue?) = ([.string("d1")], .object(["n": .int(1)]))
        let fill = G.mergedK1(K1Input(spiffeId: "spiffe://x"), presented)
        XCTAssertEqual(fill.discharges, [.string("d1")])
        XCTAssertEqual(fill.narrow, .object(["n": .int(1)]))
        XCTAssertEqual(fill.spiffeId, "spiffe://x")
        let own = G.mergedK1(K1Input(discharges: [.string("own")], narrow: .string("own-narrow")), presented)
        XCTAssertEqual(own.discharges, [.string("own")])
        XCTAssertEqual(own.narrow, .string("own-narrow"))
        let none = G.mergedK1(K1Input(), (nil, nil))
        XCTAssertTrue(none.discharges.isEmpty)
        XCTAssertNil(none.narrow)
    }

    func testProvenanceLogKeyAndObservationsAreJoinedBySession() {
        let p: JSONValue = .object(["grant_ref": .string("g1"), "cap_chain": .array([.object(["holder": .string("h0")]), .object(["holder": .string("h1")])])])
        XCTAssertEqual(G.provenanceLogKey(p, session: "s"), "g1\nh1\ns")
        XCTAssertEqual(G.provenanceLogKey(p, session: nil), "g1\nh1\n-")
        XCTAssertEqual(G.provenanceLogKey(.object([:]), session: nil), "undefined\nundefined\n-")
        let log = G.MemoryProvenanceLog()
        log.add("k", G.ProvObservation(origin: .string("tool"), source: .string("read")))
        log.add("k", G.ProvObservation(origin: .string("tool"), source: .string("read")))
        XCTAssertEqual(try log.seen("k").map { $0.json }, [.object(["origin": .string("tool"), "source": .string("read")])])
        XCTAssertTrue(try log.seen("other").isEmpty)
    }
}
