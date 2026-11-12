import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The F3 gates: information-flow taint, liveness beacons, the freshness anchor, and the authorize options that enforce them
/// (`requirePassport`, `forbid`, `requireLinkedTemplate`, `contracts`, `enforceFreshness`, `enforceTaint`, `beacon`).
final class K05GGatesTests: XCTestCase {
    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }
    let key = try! PCAEdKey(seed: [UInt8](repeating: 4, count: 32))

    // ---- taint --------------------------------------------------------------------------------------------------------------------

    func testLatticeAndJoin() {
        XCTAssertEqual(Taint.LEVELS.map { Taint.value(TaintLabel(kind: $0)) }, [0, 0.25, 0.5, 0.75, 1])
        XCTAssertEqual(Taint.rank(TaintLabel(kind: "constructor")), 4) // an unknown kind is the worst
        XCTAssertEqual(Taint.rank(nil), 4)
        XCTAssertEqual(Taint.joinLabels([]), TaintLabel(kind: "agent"))
        XCTAssertEqual(Taint.join(TaintLabel(kind: "tool", id: "a"), TaintLabel(kind: "tool", id: "b")), TaintLabel(kind: "tool"))
        XCTAssertEqual(Taint.join(TaintLabel(kind: "tool", id: "a"), TaintLabel(kind: "tool", id: "a")), TaintLabel(kind: "tool", id: "a"))
        XCTAssertEqual(Taint.join(TaintLabel(kind: "trusted"), TaintLabel(kind: "web")), TaintLabel(kind: "web"))
        XCTAssertEqual(Taint.join(TaintLabel(kind: "agent"), TaintLabel(kind: "tool")), TaintLabel(kind: "agent"))
    }

    func testComputeTaintFailsClosed() {
        let reg = InMemoryTrustedInputRegistry().recordTrusted("d1").recordFirstParty("d2").recordWeb("d3").recordTool("d4", id: "t")
        XCTAssertEqual(reg.size, 4)
        func t(_ p: String?) -> TaintResult { Taint.computeTaint(p.map { J($0) }, registry: reg) }
        XCTAssertEqual(t(#"{"trusted_refs":["d1"]}"#).taint, 0)
        XCTAssertEqual(t(#"{"trusted_refs":["d1","d2"]}"#).taint, 0.25)
        XCTAssertEqual(t(#"{"trusted_refs":["d1","d3"]}"#).taint, 0.75)
        XCTAssertEqual(t(#"{"trusted_refs":["d4"]}"#).label, TaintLabel(kind: "tool", id: "t"))
        XCTAssertEqual(t(#"{"trusted_refs":["unknown"]}"#).taint, 1) // the agent merely asserted it
        XCTAssertEqual(t(#"{"trusted_refs":[]}"#).taint, 1) // an empty lineage is not trusted
        XCTAssertEqual(t(#"{}"#).taint, 1)
        XCTAssertEqual(t(nil).reason, "taint: provenance is absent or malformed")
        XCTAssertEqual(t(#"{"trusted_refs":"d1"}"#).reason, "taint: trusted_refs must be an array")
        XCTAssertEqual(t(#"{"trusted_refs":["d1",""]}"#).reason, "taint: trusted_refs must be non-empty strings")
        XCTAssertEqual(Taint.computeTaint(J("{}"), registry: nil).reason, "taint: no trusted-input registry")
        // the agent's own label is never read
        XCTAssertEqual(t(#"{"taint_level":0,"trusted_refs":["unknown"]}"#).taint, 1)
        // a resource-graph node is first-party
        XCTAssertEqual(Taint.computeTaint(J(#"{"trusted_refs":["node1"]}"#), registry: reg, resourceGraphNode: { $0 == "node1" }).taint, 0.25)
        struct Boom: Error {}
        struct Throwing: TrustedInputRegistry { func lookup(_ d: String) throws -> TaintLabel? { throw Boom() } }
        let r = Taint.computeTaint(J(#"{"trusted_refs":["x"]}"#), registry: Throwing())
        XCTAssertFalse(r.valid)
        XCTAssertEqual(r.taint, 1)
        XCTAssertTrue(r.reason?.hasPrefix("taint: evaluation error (fail closed): ") ?? false)
        // the gate reports the same reason for a throwing registry
        XCTAssertTrue(Taint.gate(J(#"{"trusted_refs":["x"]}"#), registry: Throwing(), maxTaint: 1).reason?.hasPrefix("taint: evaluation error (fail closed): ") ?? false)
    }

    func testTaintGate() {
        let reg = InMemoryTrustedInputRegistry().recordTrusted("d1").recordWeb("d3")
        func g(_ p: String, _ m: Double?) -> (ok: Bool, reason: String?) { Taint.gate(J(p), registry: reg, maxTaint: m) }
        XCTAssertTrue(g(#"{"trusted_refs":["d1"]}"#, 0).ok)
        XCTAssertEqual(g(#"{"trusted_refs":["d3"]}"#, 0.5).reason, "information-flow taint 0.75 exceeds policy max 0.5")
        XCTAssertTrue(g(#"{"trusted_refs":["d3"]}"#, 0.75).ok)
        XCTAssertTrue(g(#"{"trusted_refs":["unknown"]}"#, 1).ok)
        XCTAssertEqual(g(#"{"trusted_refs":["d1"]}"#, -1).reason, "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)")
        XCTAssertEqual(g(#"{"trusted_refs":["d1"]}"#, nil).reason, "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)")
        XCTAssertEqual(g(#"{"trusted_refs":["d1"]}"#, .nan).ok, false)
        XCTAssertEqual(g(#"{"trusted_refs":[]}"#, 0.9).reason, "information-flow taint 1 exceeds policy max 0.9")
    }

    // ---- beacons ------------------------------------------------------------------------------------------------------------------

    let T0: Int64 = 1_700_000_000_000

    func beacon(seq: Int64 = 1, scope: String = "*", validity: Int64? = nil) throws -> JSONValue {
        try Beacons.issueLivenessBeacon(issuer: PCASuiteKey.ed25519(key), instance: "inst", seq: seq, issuedAt: T0, scope: scope, validityMs: validity)
    }

    func testBeaconVerify() throws {
        let b = try beacon()
        let v = { (now: Int64, instance: String, issuers: [String], scope: String?) in
            Beacons.verifyLivenessBeacon(b, issuers: issuers, now: now, instance: instance, scope: scope)
        }
        XCTAssertEqual(v(T0 + 1000, "inst", [key.id], "grant-1"), .pass)
        XCTAssertEqual(v(T0 + 5 * 60_000, "inst", [key.id], nil), .pass)
        XCTAssertEqual(v(T0 + 5 * 60_000 + 1, "inst", [key.id], nil).reason, "expired")
        XCTAssertEqual(v(T0 - 30_001, "inst", [key.id], nil).reason, "not yet valid")
        XCTAssertEqual(v(T0 - 30_000, "inst", [key.id], nil), .pass)
        XCTAssertEqual(v(T0, "other", [key.id], nil).reason, "wrong instance")
        XCTAssertEqual(v(T0, "inst", ["someone"], nil).reason, "issuer not pinned")
        let narrow = try beacon(scope: "grant-1")
        XCTAssertEqual(Beacons.verifyLivenessBeacon(narrow, issuers: [key.id], now: T0, instance: "inst", scope: "grant-2").reason, "scope not covered")
        XCTAssertTrue(Beacons.verifyLivenessBeacon(narrow, issuers: [key.id], now: T0, instance: "inst", scope: "grant-1").ok)
        // tampering with any signed member breaks the signature
        guard case var .object(m) = b else { return XCTFail() }
        m["seq"] = .int(99)
        XCTAssertEqual(Beacons.verifyLivenessBeacon(.object(m), issuers: [key.id], now: T0, instance: "inst").reason, "bad signature")
        XCTAssertEqual(Beacons.verifyLivenessBeacon(.null, issuers: [key.id], now: T0, instance: "inst").reason, "malformed beacon")
        m["v"] = .int(1)
        XCTAssertEqual(Beacons.verifyLivenessBeacon(.object(m), issuers: [key.id], now: T0, instance: "inst").reason, "malformed beacon")
        XCTAssertThrowsError(try beacon(validity: 3_600_001))
        XCTAssertThrowsError(try beacon(seq: -1))
        XCTAssertTrue(Beacons.isFrozenLiveness([], issuers: [key.id], now: T0, instance: "inst"))
        XCTAssertFalse(Beacons.isFrozenLiveness([b], issuers: [key.id], now: T0, instance: "inst"))
    }

    func testBeaconRefIsStableAndBindsTheBeacon() throws {
        let a = try beacon(), b = try beacon(seq: 2)
        XCTAssertEqual(try Beacons.beaconRef(a), try Beacons.beaconRef(a))
        XCTAssertNotEqual(try Beacons.beaconRef(a), try Beacons.beaconRef(b))
        XCTAssertEqual(Beacons.beaconDecision(present: false, ok: false, replayed: false, refBinds: false), "not-enforced")
        XCTAssertEqual(Beacons.beaconDecision(present: true, ok: false, replayed: false, refBinds: true), "rejected")
        XCTAssertEqual(Beacons.beaconDecision(present: true, ok: true, replayed: true, refBinds: true), "replayed")
        XCTAssertEqual(Beacons.beaconDecision(present: true, ok: true, replayed: false, refBinds: false), "unbound")
        XCTAssertEqual(Beacons.beaconDecision(present: true, ok: true, replayed: false, refBinds: true), "pass")
    }

    func testAcceptBeaconAndTheDurableAcceptor() throws {
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: nil, next: try beacon(seq: 1)), .pass)
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: .int(1), next: try beacon(seq: 1)).reason, "replayed beacon: seq 1 <= 1")
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: .int(1), next: try beacon(seq: 2)), .pass)
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: nil, next: nil).reason, "malformed beacon")
        XCTAssertEqual(Beacons.acceptBeacon(prevSeq: nil, next: J(#"{"seq":-1}"#)).reason, "malformed beacon")
        let kv = MemoryAtomicKV()
        let acc = Beacons.Acceptor(kv: kv)
        func accept(_ seq: Int64) throws -> BeaconVerdict { acc.accept(try beacon(seq: seq), issuers: [key.id], now: T0, instance: "inst") }
        XCTAssertEqual(try accept(5), .pass)
        XCTAssertEqual(try accept(5).reason, "replayed beacon: seq 5 <= 5")
        XCTAssertEqual(try accept(4).reason, "replayed beacon: seq 4 <= 5")
        XCTAssertEqual(try accept(6), .pass)
        XCTAssertEqual(Beacons.Acceptor(kv: K05GContractsTests.FailingKV()).accept(try beacon(), issuers: [key.id], now: T0, instance: "inst").reason, "beacon state unavailable")
        XCTAssertEqual(acc.accept(try beacon(), issuers: ["x"], now: T0, instance: "inst").reason, "issuer not pinned")
    }

    // ---- authorize ----------------------------------------------------------------------------------------------------------------

    func fixture() throws -> (PCA.AuthorizeInput, JSONValue) {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first { $0.get("name")?.asString == "envelope-max-spend-within" })
        let s = try XCTUnwrap(c.get("steps")?.asArray?.first)
        let g = try XCTUnwrap(c.get("grant"))
        let op = try XCTUnwrap(AuthorizeTests.op(s.get("operation")))
        let input = PCA.AuthorizeInput(operation: op, audience: AuthorizeTests.AUD, resolveGrant: { _ in g }, stateStore: MemoryStateStore(),
                                       isRevoked: { _, _ in false }, now: AuthorizeTests.NOW, plan: PCA.SINGLE_STEP, riskSource: PCA.insecureCalmRisk).withProv()
        return (input, try XCTUnwrap(s.get("pcactn")))
    }

    func run(_ p: JSONValue, _ i: PCA.AuthorizeInput) -> PCA.AuthorizeResult { PCA.authorize(pcactn: p, i.withProv()) }

    func testBaselineAllows() throws {
        let (i, p) = try fixture()
        let r = run(p, i)
        XCTAssertTrue(r.allow, r.reasons.joined(separator: "; "))
        XCTAssertNil(r.forbidCertificate)
        XCTAssertNil(r.template)
    }

    func testForbidGate() throws {
        var (i, p) = try fixture()
        let both = J(#"[{"id":"f1","kind":"forbid","when":{"verb":"*"}},{"id":"p","kind":"permit","when":{"verb":"*"}}]"#)
        i.forbid = PCA.ForbidGate(clauses: { _, _ in both })
        var r = run(p, i)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.reason, "forbid: deny by forbid f1")
        XCTAssertEqual(r.checks["forbid"], .fail)
        // permit only: allowed, and the recomputed certificate is on the result
        let permit = J(#"[{"id":"p","kind":"permit","when":{"verb":"*"}}]"#)
        i.forbid = PCA.ForbidGate(clauses: { _, _ in permit })
        r = run(p, i)
        XCTAssertTrue(r.allow, r.reasons.joined(separator: "; "))
        XCTAssertEqual(r.forbidCertificate?.get("decision")?.asString, "allow")
        // no permit: default deny naming nothing
        i.forbid = PCA.ForbidGate(clauses: { _, _ in .array([]) })
        XCTAssertEqual(run(p, i).reason, "forbid: deny by none")
        // a certificate is required and recomputed
        i.forbid = PCA.ForbidGate(clauses: { _, _ in permit }, requireCertificate: true)
        XCTAssertEqual(run(p, i).reason, "forbid: the call carries no certificate (fail closed)")
        let op = try XCTUnwrap(i.operation)
        let ctx: JSONValue = .object(["action": .object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params])])
        i.forbidCertificate = try ForbidClauses.certify(permit, ctx)
        i.stateStore = MemoryStateStore() // the earlier allowed run consumed this PCActn's counter
        let withCert = run(p, i)
        XCTAssertTrue(withCert.allow, "\(withCert.reasons); cert \(String(describing: i.forbidCertificate))")
        i.forbidCertificate = J(#"{"v":1,"kind":"forbid-wins"}"#)
        XCTAssertEqual(run(p, i).reason, "forbid: certificate refused (certificate table does not entail its decision)")
        // an unreadable clause source is an error, which denies
        struct Boom: Error {}
        i.forbid = PCA.ForbidGate(clauses: { _, _ in throw Boom() })
        XCTAssertTrue(run(p, i).reason?.hasPrefix("authorize error (fail closed)") ?? false)
    }

    /// Diagnostic: the enforcer's commit on a fresh store, with its own reasons in the message.
    func testContractEnforcerCommitsOnAFreshStore() throws {
        let (i, _) = try fixture()
        let op = try XCTUnwrap(i.operation)
        let good = try Contracts.signContract(J(#"{"version":1,"principal":"\#(key.id)","clauses":[{"id":"no-del","kind":"never","p":{"verb":"delete"}}]}"#), principal: key)
        let e = try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: good, principal: key.id)
        let action: JSONValue = .object(["action": .object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params])])
        let peeked = e.peek(action)
        XCTAssertTrue(peeked.allow, "peek: \(peeked.reason) \(peeked.reasons)")
        let r = e.check(action)
        XCTAssertTrue(r.allow, "check: \(r.reason) \(r.violated) \(r.reasons)")
        XCTAssertEqual(r.seq, 1)
    }

    func testContractsGate() throws {
        var (i, p) = try fixture()
        let op = try XCTUnwrap(i.operation)
        let kv = MemoryAtomicKV()
        let bad = try Contracts.signContract(J(#"{"version":1,"principal":"\#(key.id)","clauses":[{"id":"no-pay","kind":"never","p":{"verb":"\#(op.verb)"}}]}"#), principal: key)
        let e1 = try ContractEnforcer.open(kv: kv, contract: bad, principal: key.id)
        i.contracts = e1
        let r = run(p, i)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.reason, "contract: violated (no-pay)")
        XCTAssertEqual(r.checks["contract"], .fail)
        XCTAssertNil(try e1.state()) // the refusal came from the read-only peek: nothing was written
        // a satisfied contract commits once the action is admitted
        let good = try Contracts.signContract(J(#"{"version":1,"principal":"\#(key.id)","clauses":[{"id":"no-del","kind":"never","p":{"verb":"delete"}}]}"#), principal: key)
        let kv2 = MemoryAtomicKV()
        let e2 = try ContractEnforcer.open(kv: kv2, contract: good, principal: key.id)
        i.contracts = e2
        let admitted = run(p, i)
        XCTAssertTrue(admitted.allow, "\(admitted.reasons)")
        XCTAssertEqual(try e2.state()?.state.get("seq"), .int(1))
        // a failing store denies
        i.contracts = try ContractEnforcer.open(kv: K05GContractsTests.FailingKV(), contract: good, principal: key.id)
        XCTAssertEqual(run(p, i).reason, "contract: store-error")
    }

    func testEnforceTaintAndFreshnessGates() throws {
        var (i, p) = try fixture()
        i.enforceTaint = PCA.TaintGate(registry: EmptyTrustedInputRegistry(), maxTaint: 0)
        var r = run(p, i)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["taint_gate"], .fail)
        XCTAssertTrue(r.reasons.contains { $0.hasPrefix("taint_gate: ") })
        i.enforceTaint = nil
        i.enforceFreshness = PCA.FreshnessGate(maxAgeMs: 1000)
        r = run(p, i)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["freshness_anchor"], .fail) // its own name: the revocation `freshness` check is a different gate
        i.enforceFreshness = PCA.FreshnessGate(maxAgeMs: -1)
        XCTAssertTrue(run(p, i).reasons.contains("freshness_anchor: freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)"))
    }

    func testFreshnessAnchorTexts() {
        let g = PCA.FreshnessGate(maxAgeMs: 120_000)
        let now: Int64 = 10 * 60_000
        func e(_ fr: String?, _ gate: PCA.FreshnessGate = g) -> String? {
            var p: JObject = [:]
            if let f = fr { p["freshness"] = J(f) }
            return PCA.freshnessAnchorError(p, gate, now)
        }
        XCTAssertNil(e(#"{"beacon_ref":"r","epoch":9}"#))
        XCTAssertEqual(e(nil), "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
        XCTAssertEqual(e(#"{"beacon_ref":"","epoch":9}"#), "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
        XCTAssertEqual(e(#"{"beacon_ref":"r","epoch":0}"#), "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
        XCTAssertEqual(e(#"{"beacon_ref":"r","epoch":9.5}"#), "freshness anchor is missing (empty beacon_ref or non-positive epoch stub)")
        XCTAssertEqual(e(#"{"beacon_ref":"r","epoch":11}"#), "freshness anchor is in the future")
        XCTAssertNil(e(#"{"beacon_ref":"r","epoch":11}"#, PCA.FreshnessGate(maxAgeMs: 120_000, clockSkewMs: 60_000)))
        XCTAssertEqual(e(#"{"beacon_ref":"r","epoch":7}"#), "freshness anchor is stale (older than 120000 ms)")
        XCTAssertNil(e(#"{"beacon_ref":"r","epoch":8}"#))
        XCTAssertEqual(e(#"{"beacon_ref":"r","epoch":8}"#, PCA.FreshnessGate(maxAgeMs: 1, epochMs: 0)), "freshness gate misconfigured: epochMs must be > 0 and maxAgeMs >= 0 (fail closed)")
    }

    func testBeaconGateIsRequired() throws {
        var (i, p) = try fixture()
        i.beacon = { _, _ in nil }
        let r = run(p, i)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["beacon"], .fail)
        XCTAssertTrue(r.reasons.contains("beacon: required check is not-enforced (default-deny: not enforced by this resource server)"))
        // a beacon that does not verify names its reason
        let kid = key.id
        i.beacon = { _, _ in PCA.BeaconInput(beacon: .object([:]), issuers: [kid], instance: "inst") }
        XCTAssertTrue(run(p, i).reasons.contains("beacon: malformed beacon"))
        // a verifying beacon that the PCActn does not bind
        let signedBeacon = try beacon()
        i.beacon = { _, _ in PCA.BeaconInput(beacon: signedBeacon, issuers: [kid], instance: "inst") }
        i.now = T0
        let unbound = run(p, i)
        XCTAssertFalse(unbound.allow)
        XCTAssertTrue(unbound.reasons.contains { $0.hasPrefix("beacon: ") })
        // a state store without pins cannot protect against replay: refused up front
        struct NoPins: PCAStateStore { func claim(key: String, counter: Int64) throws -> ClaimResult { ClaimResult(ok: true) } }
        i.stateStore = NoPins()
        XCTAssertEqual(run(p, i).missing?.first, "stateStore (beacon needs a state store that implements pins (replay protection))")
    }

    func testPassportAndTemplateGates() throws {
        var (i, p) = try fixture()
        i.requirePassport = PCA.RequirePassport(trustedIssuers: [key.id])
        var r = run(p, i)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.checks["passport"], .fail)
        XCTAssertTrue(r.reason?.hasPrefix("passport: ") ?? false)
        i.requirePassport = nil
        i.requireLinkedTemplate = PCA.LinkedTemplateGate(registry: J(#"{"templates":{},"trusted":[]}"#))
        r = run(p, i)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["template"], .fail)
        XCTAssertEqual(r.reason, "template: the grant carries no template_ref")
    }

    func testVerifiedPassportAddsItsAssuranceEntry() throws {
        var (i, p) = try fixture()
        let leaf = try XCTUnwrap(PCA.presentedLeaf(p))
        let now = AuthorizeTests.NOW
        let ident: JObject = ["model_id": .string("m1"), "weights_digest": .string("w1"), "operator": .string("acme"), "hardware_rooted": .bool(false),
                              "weights_measured": .bool(false), "issued_at": .int(now - 1000)]
        let pp = try PCAIssue.issuePassport(ident)
        let signed = try PCAIssue.signPassport(pp, issuer: PCASuiteKey.ed25519(key), subject: leaf, iat: now - 1000, exp: now + 100_000)
        i.requirePassport = PCA.RequirePassport(trustedIssuers: [key.id], revoked: { _, _, _ in false }, now: { now })
        i.passport = signed
        let r = run(p, i)
        XCTAssertTrue(r.allow, r.reasons.joined(separator: "; "))
        XCTAssertEqual(r.passport?.ok, true)
        // same key and shape as the reference: {outcome: pass, level: software}, appended after the checks
        XCTAssertEqual(r.assurance.json.get("passport"), .object(["outcome": .string("pass"), "level": .string("software")]))
        XCTAssertEqual(r.assurance.names.last, "passport")
        // hardware-required but the passport is software: refused
        i.requirePassport?.hardware = true
        XCTAssertEqual(run(p, i).reason, "passport: hardware_evidence_missing")
    }

    func testVerifyLinkedPolicy() {
        // no template_ref: nothing to verify; an unresolvable one names the registry's reason
        let env = J(#"{"predicates":[],"caveats":[]}"#)
        XCTAssertTrue(PCA.verifyLinkedPolicy(env, registry: J(#"{"templates":{},"trusted":[]}"#)).ok)
        let withRef = J(#"{"predicates":[],"caveats":[],"template_ref":{"template_id":"t","version_digest":"d","slots":{}}}"#)
        let v = PCA.verifyLinkedPolicy(withRef, registry: J(#"{"templates":{},"trusted":[]}"#))
        XCTAssertFalse(v.ok)
        XCTAssertEqual(v.reason, "template version is not in the registry")
    }
}
