import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mutation-kill tests for the smaller Intent Layer v2 files: IntentV2.swift (session / accumulator steps, the clock),
/// IntentSession.swift (root shape, caveat), IntentRevocation.swift, PQ.swift / MLDSA.swift (suite table, availability),
/// Intent.swift (missing fidelity) and Caveats.swift (the `intent_session` caveat). Each assertion pins the ORIGINAL result,
/// usually the exact refusal reason, so a flipped operator or boundary changes it.
final class IntentMiscKillTests: XCTestCase {
    typealias F = V2F
    typealias K = IntentV2KillTests
    static let CLOCK = "the verifier clock is not a safe integer (fail closed)"

    func rep(_ n: Int, _ c: String = "a") -> String { String(repeating: c, count: n) }
    func norm(_ v: JSONValue) -> JSONValue { IntentV2Context.fromJSON(v)!.value }

    // ---- IntentV2: schema docs that cannot be hashed are never "the" schema ----

    func testUnhashableSchemaDocIsSkipped() {
        let garbage: JSONValue = .object(["x": .int(9_007_199_254_740_992)])
        XCTAssertNil(ActionSchema.digest(norm(garbage)), "no strict canonical form")
        let v = F.verify(F.P0, F.G0, F.ctx(["schema": .object(["docs": .array([garbage, F.SCHEMA]), "keys": F.KEYS])]))
        XCTAssertTrue(v.allow, v.reason)
        XCTAssertEqual(v.checks["schema"], true)
        XCTAssertEqual(v.checks["accumulators"], true)
    }

    // ---- IntentV2: the admitting root and the held chain (sessionStep) ----

    func sessionCtx(_ grants: [JSONValue]) -> JSONValue {
        norm(F.ctx(["session": .object(["root": F.BASE.S, "grants": .array(grants)]), "acc": K.acc(38_900)]))
    }
    func step(_ p: JSONValue, _ grant: JSONValue, _ grants: [JSONValue]) -> String? {
        IntentV2.sessionStep(p.asObject!, grant, sessionCtx(grants), Double(F.NOW))
    }

    func testAdmittingRootBindingEachMemberAlone() {
        let bound = "the admitting root is bound to another session, root or seq"
        XCTAssertNil(step(F.P0, F.G0, []))
        // only the root differs
        let rootOnly = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: F.digest("other-root"))
        XCTAssertEqual(step(F.P0, rootOnly, []), bound)
        // only the session differs
        let sessionOnly = F.mint(seq: 0, map: F.MAP0, salt: "salt0", session: F.digest("s2"))
        XCTAssertEqual(step(F.P0, sessionOnly, []), bound)
        // only the seq differs
        let seqOnly = F.mint(seq: 3, prev: F.digest("p"), map: F.MAP0, salt: "salt0")
        XCTAssertEqual(step(F.P0, seqOnly, []), bound)
        // a grant with no issuer is not signed by a session principal
        XCTAssertEqual(step(F.P0, F.without(F.G0, ["issuer"]), []), "the admitting root is not signed by a session principal")
    }

    func testHeldGrantBindingEachMemberAlone() {
        func run(_ prior: JSONValue) -> String? {
            let d1 = F.mint(seq: 1, prev: prior.get("id")!.asString!, map: F.MAP1, salt: "salt1")
            let p = F.build(d1, map: F.MAP1, salt: "salt1", is: F.is0(["seq": .int(1)]))
            return step(p, d1, [prior])
        }
        let bad = "session grant 0 does not belong to this session at seq 0"
        XCTAssertNil(run(F.G0))
        XCTAssertEqual(run(F.mint(seq: 5, prev: F.digest("p"), map: F.MAP0, salt: "salt0")), bad, "seq only")
        XCTAssertEqual(run(F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: F.digest("other-root"))), bad, "root only")
        XCTAssertEqual(run(F.mint(seq: 0, map: F.MAP0, salt: "salt0", session: F.digest("s2"))), bad, "session only")
        // a caveat that is well bound but malformed (an extra member): the shape check alone refuses it
        let env: JSONValue = .object(["type": .string("envelope"), "goal_commit": .string(F.goalCommitV2(map: F.MAP0, salt: "salt0"))])
        let extra: JSONValue = .object(["type": .string("intent_session"), "session": .string(F.SESSION), "seq": .int(0), "root": .string(F.BASE.R), "x": .int(1)])
        let malformed = F.cap(issuer: F.principal, holder: F.agent, caveats: [env, extra])
        XCTAssertNotNil(IntentSession.caveatError(IntentSession.grantCaveat(malformed)))
        XCTAssertEqual(run(malformed), bad, "shape only")
    }

    func testHeldChainLinksEveryGrantToItsPredecessor() {
        let d2 = F.mint(seq: 2, prev: F.D1.get("id")!.asString!, map: F.MAP1, salt: "salt1")
        let p2 = F.build(d2, map: F.MAP1, salt: "salt1", is: F.is0(["seq": .int(2)]))
        XCTAssertNil(step(p2, d2, [F.G0, F.D1]), "a correct two-link chain is admitted")
        // the broken link is between grant 1 and grant 0 (the admitting root chains correctly to grant 1)
        let d1b = F.mint(seq: 1, prev: F.digest("nope"), map: F.MAP1, salt: "salt1")
        let d2b = F.mint(seq: 2, prev: d1b.get("id")!.asString!, map: F.MAP1, salt: "salt1")
        let p2b = F.build(d2b, map: F.MAP1, salt: "salt1", is: F.is0(["seq": .int(2)]))
        XCTAssertEqual(step(p2b, d2b, [F.G0, d1b]), "session grant 1 does not chain to grant 0")
        // the admitting root must chain to the LAST held grant
        let d2c = F.mint(seq: 2, prev: F.digest("zzz"), map: F.MAP1, salt: "salt1")
        let p2c = F.build(d2c, map: F.MAP1, salt: "salt1", is: F.is0(["seq": .int(2)]))
        XCTAssertEqual(step(p2c, d2c, [F.G0, F.D1]), "the admitting root does not chain to grant 1")
    }

    // ---- IntentV2: accumulators ----

    func testAccumulatesIntoNeedsTheSessionSchema() {
        let ctx = norm(F.ctx(["schema": .object(["docs": .array([]), "keys": F.KEYS])]))
        let r = IntentV2.accStep(F.P0.asObject!, ctx, Double(F.NOW))
        XCTAssertEqual(r.0, "accumulator 'trip_spend' selects by accumulates_into but the session schema is not available")
        // with the schema the same claim is fine
        XCTAssertNil(IntentV2.accStep(F.P0.asObject!, norm(F.ctx()), Double(F.NOW)).0)
    }

    func sequencedFixture() -> (RS: (S: JSONValue, R: String), gs: JSONValue, rsv: String) {
        let RS = F.root(["accumulators": .array([K.SEQ])])
        let gs = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: RS.R)
        return (RS, gs, IntentAcc.reservationDigest(F.body(gs, map: F.MAP0, salt: "salt0"))!)
    }

    func testUnhashableReceiptIsNotThePresentedOne() {
        let (RS, gs, rsv) = sequencedFixture()
        let rc = F.receipt(["pcactn_digest": .string(rsv)])
        let p = F.build(gs, is: F.is0(["root": .string(RS.R), "acc": .array([.object(["id": .string("trip_spend"), "post": .int(48_900),
                                                                                    "receipt": .string(IntentAcc.receiptDigest(rc)!)])])]))
        let garbage: JSONValue = .object(["x": .int(9_007_199_254_740_992)])
        func run(_ receipts: [JSONValue]) -> PCA.Verdict {
            F.verify(p, gs, F.ctx(["session": .object(["root": RS.S, "grants": .array([])]),
                                   "acc": .object(["receipts": .array(receipts), "monitors": .object([:]), "sequencer_keys": .array([F.keySet(keys: [F.keyEntry()])])])]))
        }
        XCTAssertTrue(run([rc]).allow, run([rc]).reason)
        let v = run([garbage, rc])
        XCTAssertTrue(v.allow, v.reason)
        XCTAssertEqual(v.checks["accumulators"], true)
    }

    func testPolicyKeySetAgeIsSecondsTimesOneThousand() {
        let (RS, gs, rsv) = sequencedFixture()
        let rc = F.receipt(["pcactn_digest": .string(rsv), "issued_at": .int(F.NOW - 1_000), "expires_at": .int(F.NOW + 59_000)])
        let p = F.build(gs, is: F.is0(["root": .string(RS.R), "acc": .array([.object(["id": .string("trip_spend"), "post": .int(48_900),
                                                                                    "receipt": .string(IntentAcc.receiptDigest(rc)!)])])]))
        func run(setAge: Int64, maxS: Int64) -> PCA.Verdict {
            F.verify(p, gs, F.ctx(["session": .object(["root": RS.S, "grants": .array([])]),
                                   "acc": .object(["receipts": .array([rc]), "monitors": .object([:]),
                                                   "sequencer_keys": .array([F.keySet(keys: [F.keyEntry()], issued: F.NOW - setAge)])]),
                                   "policy": .object(["acc": .object(["max_keyset_age_s": .int(maxS)])])]))
        }
        let edge = run(setAge: 5_000, maxS: 5)
        XCTAssertTrue(edge.allow, edge.reason)
        let over = run(setAge: 5_001, maxS: 5)
        XCTAssertFalse(over.allow); XCTAssertEqual(over.checks["accumulators"], false)
    }

    // ---- IntentV2: the verifier clock ----

    func testClockRangeIsExactlyTheSafeIntegers() {
        let ctx = IntentV2Context(F.ctx())
        func reasons(_ now: Int64) -> [IntentV2.Check] { IntentV2.decide(F.P0.asObject!, grant: F.G0, ctx: ctx, now: now).checks }
        let MAXS = Canonical.MAX_SAFE
        for now in [MAXS + 1, -MAXS - 1] {
            let cs = reasons(now)
            XCTAssertEqual(cs.map { $0.name }, ["schema", "intent_session", "accumulators"], "\(now)")
            for c in cs { XCTAssertFalse(c.ok, "\(now) \(c.name)"); XCTAssertEqual(c.reason, Self.CLOCK, "\(now) \(c.name)") }
        }
        for now in [MAXS, -MAXS, 0] {
            for c in reasons(now) { XCTAssertFalse(c.reason.contains("verifier clock"), "\(now) \(c.name): \(c.reason)") }
        }
        XCTAssertTrue(reasons(F.NOW).allSatisfy { $0.ok })
    }

    // ---- IntentSession ----

    func shape(_ over: JObject) -> String? { IntentSession.shapeError(F.signRoot(F.rootBody(over))) }

    func testCaveatShapeBoundaries() {
        func cv(_ over: JObject) -> JSONValue? {
            var o: JObject = ["type": .string("intent_session"), "session": .string(F.SESSION), "root": .string(F.BASE.R), "seq": .int(0)]
            for (k, v) in over { o[k] = v }
            return .object(o)
        }
        XCTAssertNil(IntentSession.caveatError(cv([:])))
        let both = "intent_session caveat: session and root must be canonical base64url (32 bytes)"
        XCTAssertEqual(IntentSession.caveatError(cv(["session": .string("x")])), both)
        XCTAssertEqual(IntentSession.caveatError(cv(["root": .string("x")])), both)
        XCTAssertNil(IntentSession.caveatError(cv(["seq": .int(2_147_483_647), "prev": .string(F.digest("p"))])))
        XCTAssertEqual(IntentSession.caveatError(cv(["seq": .int(2_147_483_648), "prev": .string(F.digest("p"))])),
                       "intent_session caveat: seq must be a safe integer in [0, 2147483647]")
    }

    func testRootShapeHeaderAndLayerBoundaries() {
        let S = F.BASE.S
        XCTAssertNil(IntentSession.shapeError(S))
        XCTAssertEqual(IntentSession.shapeError(F.with(S, ["v": .int(2)])), "not a pca-intent-session v1")
        XCTAssertEqual(IntentSession.shapeError(F.with(S, ["kind": .string("pca-intent-sessions")])), "not a pca-intent-session v1")
        let both = "session and intent_ref must be canonical base64url (32 bytes)"
        XCTAssertEqual(IntentSession.shapeError(F.with(S, ["session": .string("x")])), both)
        XCTAssertEqual(IntentSession.shapeError(F.with(S, ["intent_ref": .string("x")])), both)
        // a principal's pq_pk is a canonical base64url string
        func principals(_ pq: JSONValue) -> JObject { ["principals": .array([.object(["key": .string(F.pub(F.principal)), "pq_pk": pq])])] }
        XCTAssertNil(shape(principals(.string("AAAA"))))
        XCTAssertEqual(shape(principals(.int(1))), "principal pq_pk is not canonical base64url")
        XCTAssertEqual(shape(principals(.null)), "principal pq_pk is not canonical base64url")
        // std.profile is at most 128 UTF-8 bytes
        func std(_ profile: String) -> JObject {
            ["layers": .object(["task": .object(["map_digest": .string(F.MAP0)]),
                                "std": .object(["profile": .string(profile), "version": .int(1), "digest": .string(F.MAP1)])])]
        }
        XCTAssertNil(shape(std(rep(128))))
        XCTAssertEqual(shape(std(rep(129))), "layers.std must be {profile, version >= 1, digest}")
        // monitors: at most 16
        func mons(_ n: Int) -> JObject {
            ["monitors": .array((0..<n).map { i in JSONValue.object(["id": .string("m\(i)"), "kind": .string("never"), "p": .object(["verb": .string("v")])]) })]
        }
        XCTAssertNil(shape(mons(16)))
        XCTAssertEqual(shape(mons(17)), "monitors must be an array of at most 16")
        // flows is an object when present
        XCTAssertNil(shape(["flows": .object([:])]))
        XCTAssertEqual(shape(["flows": .string("x")]), "flows must be an object")
        XCTAssertEqual(shape(["flows": .array([])]), "flows must be an object")
    }

    // ---- IntentRevocation ----

    func testRevokedListMustBeSortedAndDistinct() {
        let ep = F.epoch(["a", "b"], issued: F.NOW - 1_000).asObject!
        XCTAssertNil(IntentRevocation.revokedListError(ep, .array([.string("a"), .string("b")])))
        let msg = "revoked must be sorted by UTF-8 bytes and distinct"
        XCTAssertEqual(IntentRevocation.revokedListError(ep, .array([.string("a"), .string("a")])), msg)
        XCTAssertEqual(IntentRevocation.revokedListError(ep, .array([.string("b"), .string("a")])), msg)
    }

    func revInput(issued: Int64, now: JSONValue, drop: String? = nil) -> JSONValue {
        let ev = F.evidence([], issued: issued).asObject!
        var i: JObject = ["epoch": ev["epoch"]!, "revoked": ev["revoked"]!, "session": .string(F.SESSION), "authority": .string(F.pub(F.revAuthority)),
                          "ids": .array([]), "now": now, "max_age_ms": .int(60_000)]
        if let d = drop { i[JKey(d)] = nil }
        return .object(i)
    }

    func testRevocationClockAndRequiredInputs() {
        XCTAssertTrue(PCA.intentRevocationPrimitive(revInput(issued: F.NOW - 10_000, now: .int(F.NOW))))
        // negative zero is not a usable clock, zero is
        XCTAssertTrue(PCA.intentRevocationPrimitive(revInput(issued: 1_000, now: .int(0))))
        XCTAssertFalse(PCA.intentRevocationPrimitive(revInput(issued: 1_000, now: .double(-0.0))))
        // every parameter is required
        for k in ["ids", "session", "authority", "now"] {
            XCTAssertFalse(PCA.intentRevocationPrimitive(revInput(issued: F.NOW - 10_000, now: .int(F.NOW), drop: k)), k)
        }
    }

    // ---- PQ / MLDSA ----

    func testMLDSAAvailabilityMatchesThePlatform() {
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            XCTAssertTrue(MLDSA.available)
        } else {
            XCTAssertFalse(MLDSA.available)
        }
    }

    func testSuiteResolutionFollowsAvailability() {
        XCTAssertNotNil(PQ.resolve(nil))
        XCTAssertEqual(PQ.resolve("ed25519")?.alg, .ed25519)
        for a in ["ml-dsa-65", "ml-dsa-87", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "hybrid-ed25519-ml-dsa-87"] {
            XCTAssertEqual(PQ.resolve(a) != nil, MLDSA.available, a)
        }
        XCTAssertNil(PQ.resolve("slh-dsa-sha2-128f"))
        XCTAssertNil(PQ.resolve("no-such-suite"))
    }

    func testSuiteWireMembersPerSuite() throws {
        func b64(_ n: Int) -> String { Base64URLStrict.encode([UInt8](repeating: 1, count: n)) }
        // classical: a 64-byte sig and neither pq member
        XCTAssertNil(PQ.validateSignatureWire(["sig": .string(b64(64))]))
        XCTAssertNil(PQ.validateSignatureWire(["alg": .string("ed25519"), "sig": .string(b64(64))]))
        XCTAssertEqual(PQ.validateSignatureWire(["sig": .string(b64(64)), "pq_pk": .string(b64(8))]), "'pq_pk' must be absent for alg 'ed25519'")
        XCTAssertEqual(PQ.validateSignatureWire(["sig": .string(b64(64)), "pq_sig": .string(b64(8))]), "'pq_sig' must be absent for alg 'ed25519'")
        // pure PQ suites: sig is the PQ signature, pq_pk required, pq_sig forbidden
        try XCTSkipUnless(MLDSA.available)
        for (alg, level) in [("ml-dsa-65", MLDSA.Level.mlDsa65), ("ml-dsa-87", .mlDsa87)] {
            let l = MLDSA.lens(level)
            let ok: JObject = ["alg": .string(alg), "sig": .string(b64(l.sig)), "pq_pk": .string(b64(l.pk))]
            XCTAssertNil(PQ.validateSignatureWire(ok), alg)
            var withPqSig = ok
            withPqSig["pq_sig"] = .string(b64(l.sig))
            XCTAssertEqual(PQ.validateSignatureWire(withPqSig), "'pq_sig' must be absent for alg '\(alg)'", alg)
            var noPk = ok
            noPk["pq_pk"] = nil
            XCTAssertEqual(PQ.validateSignatureWire(noPk), "'pq_pk' is not canonical base64url (\(l.pk) bytes)", alg)
        }
    }

    // ---- Intent: a missing fidelity reads as -1 ----

    func testMissingFidelityIsMinusOne() {
        let g = IntentTests.rootGrant([IntentTests.envelope(.string(IntentTests.commit()))])
        let noFid = IntentTests.theIntent(["fidelity_ppm": .some(.string("x"))])
        let r = Intent.decide(noFid, grant: g, policy: IntentPolicy(minFidelityPpm: 0))
        XCTAssertEqual(r?.ok, false)
        XCTAssertEqual(r?.why, "intent fidelity -1 ppm is below the policy minimum 0")
        let ok = Intent.decide(IntentTests.theIntent(["fidelity_ppm": .int(0)]), grant: g, policy: IntentPolicy(minFidelityPpm: 0))
        XCTAssertEqual(ok?.ok, true)
    }

    // ---- Caveats: the intent_session caveat is satisfied iff well formed ----

    func testIntentSessionCaveatSatisfiedIffWellFormed() {
        let ctx: JSONValue = .object(["now": .int(F.NOW)])
        let good: JSONValue = .object(["type": .string("intent_session"), "session": .string(F.SESSION), "seq": .int(0), "root": .string(F.BASE.R)])
        let r = PCA.evaluateCaveats(.array([good]), context: ctx)
        XCTAssertTrue(r.ok); XCTAssertEqual(r.failed, [])
        let bad: JSONValue = .object(["type": .string("intent_session"), "session": .string(F.SESSION), "seq": .int(1), "root": .string(F.BASE.R)])
        let b = PCA.evaluateCaveats(.array([bad]), context: ctx)
        XCTAssertFalse(b.ok); XCTAssertEqual(b.failed, ["intent_session"])
    }
}
