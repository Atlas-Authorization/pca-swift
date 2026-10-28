import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Revocation staleness (T9): replays staleness-vectors.json (constants, max_age, effective_reversibility, age, epoch, gate), then
/// the `authorize` wiring. A missing vector file FAILS (it is loaded, never skipped).
final class RevocationStalenessTests: XCTestCase {
    static func doc() throws -> JSONValue { try ConformanceTests.load("staleness-vectors.json") }

    /// A vector number; the string "NaN" stands for NaN.
    static func ms(_ v: JSONValue?) -> Double {
        if case .string("NaN")? = v { return .nan }
        return IV.num(v) ?? .nan
    }
    static func opt(_ v: JSONValue?) -> Double? {
        guard let v = v, !v.isNull else { return nil }
        return ms(v)
    }

    static func rows(_ d: JSONValue, _ table: String, _ n: Int) -> [JSONValue] {
        let a = d.get(table)?.asArray ?? []
        XCTAssertEqual(a.count, n, "\(table): row count")
        return a
    }

    func want(_ got: RevocationAgeResult, _ v: JSONValue, _ label: String) {
        let exp = v.get("result")
        let ok = exp?.get("ok") == .bool(true)
        XCTAssertEqual(got.ok, ok, "\(label): ok (reason \(got.reason ?? "-"))")
        if v.get("ok_only") != nil || got.ok { return }
        XCTAssertEqual(got.reason, exp?.get("reason")?.asString, label)
    }

    func testConstants() throws {
        let c = try Self.doc().get("constants")
        XCTAssertEqual(PCA.REVOCATION_EPOCH_REFRESH_MS, Self.ms(c?.get("refresh_ms")))
        XCTAssertEqual(PCA.REVOCATION_EPOCH_VALIDITY_MS, Self.ms(c?.get("validity_ms")))
        XCTAssertEqual(PCA.REVOCATION_IRREVERSIBLE_MAX_AGE_MS, Self.ms(c?.get("irreversible_max_age_ms")))
        XCTAssertEqual(PCA.REVOCATION_SKEW_MS, Self.ms(c?.get("skew_ms")))
    }

    func testMaxAgeVectors() throws {
        for v in Self.rows(try Self.doc(), "max_age", 15) {
            let p = RevocationStalenessPolicy.fromJSON(v.get("policy")) ?? RevocationStalenessPolicy()
            XCTAssertEqual(PCA.revocationMaxAgeMs(p, class: v.get("class")?.asString ?? ""), Self.ms(v.get("max_age_ms")), Canonical.canonicalize(v))
        }
    }

    func testEffectiveReversibilityVectors() throws {
        for v in Self.rows(try Self.doc(), "effective_reversibility", 14) {
            let signed = v.get("signed_class").flatMap { $0.isNull ? nil : $0 }
            XCTAssertEqual(PCA.effectiveReversibility(serverClass: v.get("server_class")?.asString, signedClass: signed),
                           v.get("effective")?.asString, Canonical.canonicalize(v))
        }
    }

    func testAgeVectors() throws {
        for (i, v) in Self.rows(try Self.doc(), "age", 13).enumerated() {
            var issued: Double?
            switch v.get("issued_at") { // null, "NaN" and "x" are all an unknown age
            case .int(let x)?: issued = Double(x)
            case .double(let x)?: issued = x
            default: issued = nil
            }
            let got = PCA.checkRevocationAge(issuedAt: issued, now: Self.ms(v.get("now")), maxAgeMs: Self.ms(v.get("max_age_ms")),
                                             what: v.get("what")?.asString ?? "revocation state")
            want(got, v, "age#\(i)")
        }
    }

    func testEpochVectors() throws {
        let d = try Self.doc()
        for v in Self.rows(d, "epoch", 25) {
            var o = EpochCheckOptions(guardianPublic: v.get("guardian_public")?.asString ?? "", now: Self.ms(v.get("now")))
            o.grantRef = v.get("grant_ref")?.asString
            o.lastAcceptedEpoch = Self.opt(v.get("last_accepted_epoch"))
            o.pcactnEpoch = Self.opt(v.get("pcactn_epoch"))
            o.maxAgeMs = Self.opt(v.get("max_age_ms"))
            want(PCA.checkRevocationEpoch(v.get("epoch"), o), v, "epoch/\(v.get("name")?.asString ?? "?")")
        }
    }

    func testGateVectors() throws {
        let d = try Self.doc()
        let guardian = d.get("guardian_public")?.asString
        for v in Self.rows(d, "gate", 28) {
            var policy = RevocationStalenessPolicy.fromJSON(v.get("policy")) ?? RevocationStalenessPolicy()
            policy.allowUnsignedRootForIrreversible = v.get("allow_unsigned_root_for_irreversible") == .bool(true)
            var g = RevocationGateInput(policy: policy, guardianPublic: guardian, grantRef: "g1", pcactnEpoch: 0, now: Self.ms(v.get("now")),
                                        serverClass: v.get("server_class")?.asString, signedClass: v.get("signed_class"))
            switch v.get("mode")?.asString {
            case "epoch"?:
                g.epochSource = true
                g.epoch = v.get("epoch")
                g.root = v.get("bare_root")?.asString
            case "root"?:
                g.root = d.get("revocation_root")?.asString
                g.rootIssuedAt = Self.opt(v.get("root_issued_at"))
            case "none"?:
                g.epochSource = true
            default:
                XCTFail("mode \(String(describing: v.get("mode")))")
            }
            let r = PCA.revocationGate(g)
            want(RevocationAgeResult(ok: r.ok, reason: r.reason), v, "gate/\(v.get("name")?.asString ?? "?")")
        }
    }

    func testMembershipVectors() throws {
        let d = try Self.doc()
        let set = d.get("revocation_set")
        let rows = Self.rows(d, "membership", 27)
        for v in rows {
            let got = PCA.verifyNonMembership(root: v.get("root")?.asString ?? "", proof: v.get("proof") ?? .null, id: v.get("id")?.asString ?? "")
            XCTAssertEqual(got, v.get("ok") == .bool(true), v.get("name")?.asString ?? "?")
        }
        // the named sets are the roots the cases use
        XCTAssertTrue(rows.contains { $0.get("set")?.asString == "main" && $0.get("root") == set?.get("root") })
        XCTAssertTrue(rows.contains { $0.get("set")?.asString == "empty" && $0.get("root") == set?.get("empty_root") })
        XCTAssertTrue(rows.contains { $0.get("set")?.asString == "one" && $0.get("root") == set?.get("single")?.get("root") })
    }

    func testGateIdsVectors() throws {
        let d = try Self.doc()
        let guardian = try XCTUnwrap(d.get("guardian_public")?.asString)
        let set = try XCTUnwrap(d.get("revocation_set"))
        let policy = RevocationStalenessPolicy(maxRevocationAgeMs: PCA.REVOCATION_EPOCH_VALIDITY_MS)
        let seed = [UInt8](repeating: 11, count: 32) // the vectors' guardian key
        for v in Self.rows(d, "gate_ids", 10) {
            let name = v.get("name")?.asString ?? "?"
            let issued = try XCTUnwrap(IV.num(v.get("epoch_issued_at")))
            let ep = try XCTUnwrap(PCA.signRevocationEpoch(guardianSeed: seed, RevocationEpochBody(
                instanceId: "i", grantRef: "g1", epoch: 0, setSize: Int64(try XCTUnwrap(IV.num(set.get("size")))),
                root: try XCTUnwrap(set.get("root")?.asString), issuedAt: Int64(issued), notAfter: Int64(issued) + 600_000)))
            XCTAssertEqual(ep.get("guardian")?.asString, guardian, "\(name): the test key must be the vectors' guardian")
            var g = RevocationGateInput(policy: policy, guardianPublic: guardian, grantRef: "g1", pcactnEpoch: 0, now: Self.ms(v.get("now")),
                                        signedClass: .string("costly"), epochSource: true, epoch: ep)
            g.ids = (v.get("ids")?.asArray ?? []).compactMap { $0.asString }
            let proofs = v.get("proofs")
            g.proofFor = { id in proofs?.get(id) }
            let r = PCA.revocationGate(g)
            want(RevocationAgeResult(ok: r.ok, reason: r.reason), v, "gate_ids/\(name)")
        }
    }

    func testInvalidPolicyRefused() {
        let bad: [String: RevocationStalenessPolicy] = [
            "zero": RevocationStalenessPolicy(maxRevocationAgeMs: 0),
            "negative": RevocationStalenessPolicy(staleness: StalenessWindows(irreversible: -1)),
            "nan": RevocationStalenessPolicy(staleness: StalenessWindows(costly: .nan)),
            "infinite": RevocationStalenessPolicy(maxRevocationAgeMs: .infinity),
            "not-number": RevocationStalenessPolicy.fromJSON(.object(["maxRevocationAgeMs": .string("300000")]))!,
        ]
        for (name, p) in bad {
            XCTAssertNotNil(p.validate(), name)
            let r = PCA.revocationGate(RevocationGateInput(policy: p, grantRef: "g", now: 1, signedClass: .string("reversible"), root: "r", rootIssuedAt: 1))
            XCTAssertFalse(r.ok, "\(name): the gate opened under an invalid policy")
        }
        XCTAssertFalse(RevocationStalenessPolicy().isOn, "the empty policy must be off")
    }

    // A post-quantum epoch needs a pin for the guardian; an unregistered suite is refused as not signed by the pinned guardian.
    func testEpochSuitesUnderPins() throws {
        let seed = [UInt8](repeating: 11, count: 32)
        let ep = try XCTUnwrap(PCA.signRevocationEpoch(guardianSeed: seed, RevocationEpochBody(instanceId: "i", grantRef: "g1", root: "r", issuedAt: 1000, notAfter: 2000)))
        let guardian = try XCTUnwrap(ep.get("guardian")?.asString)
        let o = EpochCheckOptions(guardianPublic: guardian, now: 1500)
        XCTAssertTrue(PCA.checkRevocationEpoch(ep, o).ok)
        func mut(_ k: String, _ v: JSONValue) -> JSONValue {
            var m = ep.asObject ?? [:]
            m[JKey(k)] = v
            return .object(m)
        }
        let tampered = PCA.checkRevocationEpoch(mut("root", .string("other")), o)
        XCTAssertEqual(tampered.reason, "revocation epoch signature invalid")
        XCTAssertFalse(PCA.checkRevocationEpoch(mut("alg", .string("ml-dsa-65")), o).ok, "a PQ suite without a pin must be refused")
        var pinned = o
        pinned.pins = [guardian: "AAAA"]
        XCTAssertFalse(PCA.checkRevocationEpoch(mut("alg", .string("ml-dsa-65")), pinned).ok, "a PQ suite whose pq_pk is not the pinned key must be refused")
        XCTAssertEqual(PCA.checkRevocationEpoch(mut("alg", .string("no-such-suite")), o).reason, "revocation epoch not signed by the pinned guardian")
        XCTAssertEqual(PCA.checkRevocationEpoch(mut("alg", .int(1)), o).reason, "revocation epoch not signed by the pinned guardian")
        XCTAssertNil(PCA.signRevocationEpoch(guardianSeed: [1], RevocationEpochBody(instanceId: "i", grantRef: "g", root: "r", issuedAt: 1, notAfter: 2)))
    }

    // ---- authorize wiring ----

    /// Case 0 of the authorize fixtures (signed class irreversible, freshness.epoch 0), authorized with the given staleness setup.
    func authorize(policy: RevocationStalenessPolicy?, ageMs: Int64, epochRoot: String = "root", proof: ((JSONValue, String) -> JSONValue?)? = nil,
                   ids: ((JSONValue) -> [String])? = { _ in [] }, state: ((_ grantRef: String, _ epoch: JSONValue) -> RevocationState?)?) throws -> PCA.AuthorizeResult {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let s = try XCTUnwrap(c.get("steps")?.asArray?.first)
        let g = try XCTUnwrap(c.get("grant"))
        let pcactn = try XCTUnwrap(s.get("pcactn"))
        let grantRef = try XCTUnwrap(pcactn.get("grant_ref")?.asString)
        let now = AuthorizeTests.NOW
        let seed = [UInt8](repeating: 11, count: 32)
        let probe = try XCTUnwrap(PCA.signRevocationEpoch(guardianSeed: seed, RevocationEpochBody(instanceId: "i", grantRef: "x", root: "r", issuedAt: 0, notAfter: 1)))
        var input = PCA.AuthorizeInput(operation: AuthorizeTests.op(s.get("operation")), audience: AuthorizeTests.AUD, resolveGrant: { _ in g },
                                       stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: now, plan: PCA.SINGLE_STEP)
        input.revocationStaleness = policy
        input.revocationIds = ids // freshness-only tests pass explicit empty ids; the proofs have their own test below
        input.revocationProof = proof
        input.guardianPublic = probe.get("guardian")?.asString
        if let state = state {
            input.revocationState = { _, _ in
                let ep = PCA.signRevocationEpoch(guardianSeed: seed, RevocationEpochBody(instanceId: "i", grantRef: grantRef, root: epochRoot, issuedAt: now - ageMs, notAfter: now + 600_000))
                return state(grantRef, ep ?? .null)
            }
        }
        return PCA.authorize(pcactn: pcactn, input)
    }

    func testAuthorizeIrreversible() throws {
        let on = RevocationStalenessPolicy(maxRevocationAgeMs: 300_000)
        let epoch: (String, JSONValue) -> RevocationState? = { _, e in RevocationState(epoch: e) }
        let fresh = try authorize(policy: on, ageMs: 30_000, state: epoch)
        XCTAssertTrue(fresh.allow, "\(fresh.reasons)")
        XCTAssertEqual(fresh.checks["freshness"], .pass)
        let stale = try authorize(policy: on, ageMs: 180_000, state: epoch)
        XCTAssertFalse(stale.allow)
        XCTAssertEqual(stale.checks["freshness"], .fail)
        XCTAssertTrue(stale.reason?.contains("revocation epoch is 180000 ms old, over the verifier's maximum of 120000 ms") ?? false, stale.reason ?? "nil")
        let root = try authorize(policy: on, ageMs: 0, state: { _, _ in RevocationState(root: "root", rootIssuedAt: 1) })
        XCTAssertFalse(root.allow)
        XCTAssertTrue(root.reason?.contains("unsigned revocation root refused for an irreversible action") ?? false, root.reason ?? "nil")
        let none = try authorize(policy: on, ageMs: 0, state: { _, _ in nil })
        XCTAssertFalse(none.allow)
        XCTAssertTrue(none.reason?.contains("no verifiable (guardian-signed) revocation state") ?? false, none.reason ?? "nil")
        // off (nil or empty policy): unchanged behaviour, no freshness check
        let off = try authorize(policy: nil, ageMs: 0, state: nil)
        XCTAssertTrue(off.allow)
        XCTAssertNil(off.checks["freshness"])
        XCTAssertTrue(try authorize(policy: RevocationStalenessPolicy(), ageMs: 0, state: nil).allow)
    }

    func testAuthorizeMisconfigured() throws {
        let r = try authorize(policy: RevocationStalenessPolicy(maxRevocationAgeMs: 300_000), ageMs: 0, state: nil)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.missing?.count, 1)
        XCTAssertTrue(r.missing?.first?.hasPrefix("revocationState") ?? false)
        let bad = try authorize(policy: RevocationStalenessPolicy(maxRevocationAgeMs: -1), ageMs: 0, state: { _, _ in nil })
        XCTAssertFalse(bad.allow)
        XCTAssertEqual(bad.missing?.count, 1)
        XCTAssertTrue(bad.missing?.first?.hasPrefix("revocationStaleness") ?? false)
    }

    // Default ids = the PCActn's cap_chain: with no proof source a request that has a chain is denied, fail closed.
    func testEveryChainCapabilityNeedsAProof() throws {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let pcactn = try XCTUnwrap(c.get("steps")?.asArray?.first?.get("pcactn"))
        let first = try XCTUnwrap(pcactn.get("cap_chain")?.asArray?.first?.get("id")?.asString, "the fixture must carry a capability chain")
        let on = RevocationStalenessPolicy(maxRevocationAgeMs: 300_000)
        let empty = try XCTUnwrap(IntentRevocation.revsetRoot([]))
        let epoch: (String, JSONValue) -> RevocationState? = { _, e in RevocationState(epoch: e) }
        let denied = try authorize(policy: on, ageMs: 1_000, epochRoot: empty, ids: nil, state: epoch)
        XCTAssertFalse(denied.allow)
        XCTAssertEqual(denied.checks["freshness"], .fail)
        XCTAssertTrue(denied.reason?.contains("no non-membership proof for \(first)") ?? false, denied.reason ?? "nil")
        let ok = try authorize(policy: on, ageMs: 1_000, epochRoot: empty, proof: { _, _ in .object(["size": .int(0)]) }, ids: nil, state: epoch)
        XCTAssertTrue(ok.allow, "\(ok.reasons)")
        XCTAssertEqual(ok.checks["freshness"], .pass)
        // a proof for the wrong set denies, naming the capability
        let wrong = try authorize(policy: on, ageMs: 1_000, epochRoot: "root", proof: { _, _ in .object(["size": .int(0)]) }, ids: nil, state: epoch)
        XCTAssertFalse(wrong.allow)
        XCTAssertTrue(wrong.reason?.contains("capability \(first) is revoked or proof invalid") ?? false, wrong.reason ?? "nil")
    }
}
