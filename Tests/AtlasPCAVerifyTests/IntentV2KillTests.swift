import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mutation-kill tests for the Intent Layer v2 pipeline (IntentV2.swift, IntentSession.swift, ActionSchema.swift,
/// IntentAcc.swift, IntentRevocation.swift, the `layers` predicate evaluator and the hooks in Wire / PCActn / Intent):
/// every boundary pinned on both sides, the reporting conditions, the check order and the independence of checks 1-4.
final class IntentV2KillTests: XCTestCase {
    typealias F = V2F
    static let CORE = ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter"]
    static let V2 = ["schema", "intent_session", "accumulators"]

    func failing(_ v: PCA.Verdict) -> Set<String> { Set(v.checks.filter { !$0.value }.map { $0.key }) }
    func mustAllow(_ n: String, _ v: PCA.Verdict, reported: [String] = V2, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(v.allow, "\(n): \(v.reason)", file: file, line: line)
        XCTAssertEqual(Set(v.checks.keys), Set(Self.CORE + ["intent"] + reported), n, file: file, line: line)
    }
    func mustFail(_ n: String, _ v: PCA.Verdict, _ fails: [String], reported: [String] = V2, why: String? = nil,
                  file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(v.allow, n, file: file, line: line)
        XCTAssertEqual(failing(v), Set(fails), "\(n): \(v.reason)", file: file, line: line)
        XCTAssertEqual(Set(v.checks.keys), Set(Self.CORE + ["intent"] + reported), n, file: file, line: line)
        if let w = why { XCTAssertTrue(v.reason.contains(w), "\(n): \(v.reason)", file: file, line: line) }
    }
    func mustWire(_ n: String, _ p: JSONValue, file: StaticString = #filePath, line: UInt = #line) {
        let v = F.verify(p, F.G0, F.ctx())
        XCTAssertEqual(v.checks, ["wire": false], "\(n): \(v.reason)", file: file, line: line)
    }
    func notWire(_ n: String, _ p: JSONValue, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(Wire.validate(p), n, file: file, line: line)
    }

    static func acc(_ sum: Int64, monitors: JObject = [:]) -> JSONValue {
        .object(["state": .object(["trip_spend": .object(["sum": .int(sum)])]), "monitors": .object(monitors)])
    }
    static func claim(_ post: Int64, id: String = "trip_spend") -> JObject { ["acc": .array([.object(["id": .string(id), "post": .int(post)])])] }
    static var g0id: String { F.G0.get("id")!.asString! }

    // ---- reporting and order ----------------------------------------------------------------------------------------

    func testG0AndDeltaAccepted() {
        mustAllow("g0", F.verify(F.P0, F.G0, F.ctx()))
        let p1 = F.build(F.D1, map: F.MAP1, salt: "salt1", is: F.is0(["seq": .int(1)].merging(Self.claim(77_800)) { $1 }))
        let held = F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([F.G0])]), "acc": Self.acc(38_900)])
        mustAllow("d1", F.verify(p1, F.D1, held))
        mustFail("d1-unheld", F.verify(p1, F.D1, F.ctx(["acc": Self.acc(38_900)])), ["intent_session"], why: "earlier grants")
        // the verifier holds MORE grants than needed: still fine
        let more = F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([F.G0, F.D1])]), "acc": Self.acc(38_900)])
        mustAllow("d1-extra-held", F.verify(p1, F.D1, more))
    }

    func testBackCompatAndPolicyActivation() {
        let plain = F.build(F.G0, is: nil)
        // no member, no v2 policy: no v2 check is reported (the v1 goal does not open the v2 grant: intent fails)
        for c in [nil, F.ctx(), F.ctx(["policy": .object(["session": .object(["require": .bool(false)]), "schema": .object(["closed_world": .bool(false)])])])] {
            mustFail("backcompat", F.verify(plain, F.G0, c), ["intent"], reported: [])
        }
        mustFail("require", F.verify(plain, F.G0, F.ctx(["policy": .object(["session": .object(["require": .bool(true)])])])), ["intent", "intent_session"],
                 reported: ["intent_session"], why: "intent: ")
        let req = F.verify(plain, F.G0, F.ctx(["policy": .object(["session": .object(["require": .bool(true)])])]))
        XCTAssertEqual(req.checks["intent_session"], false)
        // only `require: true` activates the session check
        // the policy is closed and typed: a non-boolean flag is a malformed context (schema and intent_session fail)
        mustFail("require-1", F.verify(plain, F.G0, F.ctx(["policy": .object(["session": .object(["require": .int(1)])])])), ["intent", "schema", "intent_session"],
                 reported: ["schema", "intent_session"])
        mustFail("closed-world", F.verify(plain, F.G0, F.ctx(["policy": .object(["schema": .object(["closed_world": .bool(true)])])])), ["intent"], reported: ["schema"])
        // closed world against the FIRST accepted schema (a second, foreign one is never consulted)
        let two = F.ctx(["policy": .object(["schema": .object(["closed_world": .bool(true)])]),
                         "schema": .object(["docs": .array([F.signSchema(F.UNSIGNED, by: F.stranger), F.SCHEMA]), "keys": F.KEYS])])
        mustFail("closed-world-first", F.verify(plain, F.G0, two), ["intent", "schema"], reported: ["schema"])
        // the v2 goal: with a member the v1 goal no longer opens anything, and the session goal does
        XCTAssertEqual(Intent.goalCommit(ref: "x", mapDigest: F.MAP0, goalSalt: "salt0", session: F.SESSION),
                       Intent.goalCommit(ref: "y", mapDigest: F.MAP0, goalSalt: "salt0", session: F.SESSION))
        XCTAssertNotEqual(Intent.goalCommit(ref: F.REF, mapDigest: F.MAP0, goalSalt: "salt0"),
                          Intent.goalCommit(ref: F.REF, mapDigest: F.MAP0, goalSalt: "salt0", session: F.SESSION))
    }

    func testChecksOneToFourAreIndependent() {
        var bad = F.PARAMS.asObject!
        bad["total"] = .int(1)
        mustFail("params-not-digest", F.verify(F.P0, F.G0, F.ctx(["params": .object(bad)])), ["schema", "accumulators"])
        let other = F.signSchema(F.UNSIGNED.merging(["version": .string("v2")]) { $1 })
        mustFail("unknown-digest", F.verify(F.P0, F.G0, F.ctx(["schema": .object(["docs": .array([other]), "keys": F.KEYS])])), ["schema", "accumulators"])
        let forged: JSONValue = .array([.object(["kid": .string("skyair-2026"), "alg": .string("ed25519"), "pk": .string(F.pub(F.stranger))])])
        mustFail("forged", F.verify(F.P0, F.G0, F.ctx(["schema": .object(["docs": .array([F.SCHEMA]), "keys": forged])])), ["schema"])
        mustFail("no-root", F.verify(F.P0, F.G0, F.ctx(["session": .object(["grants": .array([])])])), ["intent_session", "accumulators"])
        mustFail("no-docs", F.verify(F.P0, F.G0, F.ctx(["schema": .object(["docs": .array([]), "keys": F.KEYS])])), ["schema", "accumulators"])
        mustFail("no-params", F.verify(F.P0, F.G0, F.ctx(["params": .null])), ["schema", "intent_session", "accumulators"], why: "malformed v2 context")
        // tampering without re-signing: leaf_signature and the claim both fail, every v2 check still reported
        var t = F.P0.asObject!
        t["intent_session"] = F.is0(Self.claim(1))
        mustFail("unsigned-tamper", F.verify(.object(t), F.G0, F.ctx()), ["leaf_signature", "accumulators"])
    }

    // ---- wire ------------------------------------------------------------------------------------------------------

    func testWireBoundaries() {
        func p(_ s: JSONValue) -> JSONValue { F.build(F.G0, is: s) }
        let d = { (i: Int) in F.digest("d\(i)") }
        notWire("seq-max", p(F.is0(["seq": .int(2_147_483_647)])))
        mustWire("seq-over", p(F.is0(["seq": .int(2_147_483_648)])))
        mustWire("seq-neg", p(F.is0(["seq": .int(-1)])))
        mustWire("seq-frac", p(F.is0(["seq": .double(0.5)])))
        mustWire("seq-string", p(F.is0(["seq": .string("0")])))
        notWire("acc-16", p(F.is0(["acc": .array((0..<16).map { .object(["id": .string("a\($0)"), "post": .int(0)]) })])))
        mustWire("acc-17", p(F.is0(["acc": .array((0..<17).map { .object(["id": .string("a\($0)"), "post": .int(0)]) })])))
        notWire("acc-id-64", p(F.is0(["acc": .array([.object(["id": .string(String(repeating: "a", count: 64)), "post": .int(0)])])])))
        mustWire("acc-id-65", p(F.is0(["acc": .array([.object(["id": .string(String(repeating: "a", count: 65)), "post": .int(0)])])])))
        mustWire("acc-id-dash", p(F.is0(["acc": .array([.object(["id": .string("a-b"), "post": .int(0)])])])))
        mustWire("acc-id-empty", p(F.is0(["acc": .array([.object(["id": .string(""), "post": .int(0)])])])))
        mustWire("acc-dup", p(F.is0(["acc": .array([.object(["id": .string("a"), "post": .int(1)]), .object(["id": .string("a"), "post": .int(2)])])])))
        mustWire("acc-post-neg", p(F.is0(["acc": .array([.object(["id": .string("a"), "post": .int(-1)])])])))
        mustWire("acc-post-frac", p(F.is0(["acc": .array([.object(["id": .string("a"), "post": .double(1.5)])])])))
        notWire("acc-post-max", p(F.is0(["acc": .array([.object(["id": .string("a"), "post": .int(9_007_199_254_740_991)])])])))
        mustWire("acc-unknown", p(F.is0(["acc": .array([.object(["id": .string("a"), "post": .int(0), "x": .int(1)])])])))
        mustWire("acc-receipt-31", p(F.is0(["acc": .array([.object(["id": .string("a"), "post": .int(0), "receipt": .string(Base64URLStrict.encode([UInt8](repeating: 1, count: 31)))])])])))
        notWire("acc-receipt", p(F.is0(["acc": .array([.object(["id": .string("a"), "post": .int(0), "receipt": .string(d(1))])])])))
        mustWire("acc-not-array", p(F.is0(["acc": .object([:])])))
        for (name, max) in [("facts", 16), ("labels", 16), ("classes", 8)] {
            notWire("\(name)-\(max)", p(F.is0([JKey(name): .array((0..<max).map { .string(d($0)) })])))
            mustWire("\(name)-\(max + 1)", p(F.is0([JKey(name): .array((0...max).map { .string(d($0)) })])))
            mustWire("\(name)-dup", p(F.is0([JKey(name): .array([.string(d(1)), .string(d(1))])])))
            mustWire("\(name)-bad", p(F.is0([JKey(name): .array([.string("x")])])))
            notWire("\(name)-empty", p(F.is0([JKey(name): .array([])])))
        }
        notWire("offer-set", p(F.is0(["offer_set": .string(d(1))])))
        mustWire("offer-set-null", p(F.is0(["offer_set": .null])))
        func prov(_ o: JObject) -> JSONValue { p(F.is0(["prov": .object(o)])) }
        notWire("prov-32", prov(Dictionary(uniqueKeysWithValues: (0..<32).map { (JKey("action.params.p\($0)"), JSONValue.array([.string("r")])) })))
        mustWire("prov-33", prov(Dictionary(uniqueKeysWithValues: (0..<33).map { (JKey("action.params.p\($0)"), JSONValue.array([.string("r")])) })))
        notWire("prov-8-refs", prov(["action.params.total": .array((0..<8).map { .string("r\($0)") })]))
        mustWire("prov-9-refs", prov(["action.params.total": .array((0..<9).map { .string("r\($0)") })]))
        mustWire("prov-0-refs", prov(["action.params.total": .array([])]))
        mustWire("prov-empty-ref", prov(["action.params.total": .array([.string("")])]))
        notWire("prov-ref-256", prov(["action.params.total": .array([.string(String(repeating: "\u{e9}", count: 128))])]))
        mustWire("prov-ref-257", prov(["action.params.total": .array([.string(String(repeating: "\u{e9}", count: 128) + "a")])]))
        mustWire("prov-ref-number", prov(["action.params.total": .array([.int(1)])]))
        mustWire("prov-path-env", prov(["env.x": .array([.string("r")])]))
        mustWire("prov-path-nested", prov(["action.params.a.b": .array([.string("r")])]))
        notWire("prov-path-64", prov([JKey("action.params." + String(repeating: "a", count: 64)): .array([.string("r")])]))
        mustWire("prov-path-65", prov([JKey("action.params." + String(repeating: "a", count: 65)): .array([.string("r")])]))
        mustWire("unknown-member", p(F.is0(["note": .string("x")])))
        mustWire("missing-schema", p(F.without(F.is0(), ["schema"])))
        mustWire("missing-seq", p(F.without(F.is0(), ["seq"])))
        mustWire("root-31", p(F.is0(["root": .string(Base64URLStrict.encode([UInt8](repeating: 1, count: 31)))])))
        mustWire("array", p(.array([F.is0()])))
        mustWire("null", p(.null))
        XCTAssertEqual(IntentSession.validateWire(F.is0(["zz": .int(1)])), "unknown field 'intent_session.zz'")
        XCTAssertNil(IntentSession.validateWire(F.is0()))
    }

    // ---- rule 13 ---------------------------------------------------------------------------------------------------

    func testSessionFailures() {
        let held = F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([F.G0])]), "acc": Self.acc(38_900)])
        let is1 = F.is0(["seq": .int(1)].merging(Self.claim(77_800)) { $1 })
        let forged = F.mint(seq: 1, prev: Self.g0id, map: F.MAP1, salt: "salt1", signer: F.agent)
        mustFail("agent-signed-delta", F.verify(F.build(forged, map: F.MAP1, salt: "salt1", is: is1), forged, held), ["intent_session"], why: "principal")
        let loose = F.mint(seq: 1, prev: F.digest("nope"), map: F.MAP1, salt: "salt1")
        mustFail("broken-prev", F.verify(F.build(loose, map: F.MAP1, salt: "salt1", is: is1), loose, held), ["intent_session"], why: "chain")
        mustFail("seq-mismatch", F.verify(F.build(F.G0, is: F.is0(["seq": .int(1)])), F.G0, F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([F.G0])])])),
                 ["intent_session"], why: "another session, root or seq")
        mustFail("ref-not-statement", F.verify(F.build(F.G0, is: F.is0(), ref: F.digest("x")), F.G0, F.ctx()), ["intent_session"], why: "statement")
        // a prior grant that a stranger signed, or that is bound to another seq
        let g0s = F.mint(seq: 0, map: F.MAP0, salt: "salt0", signer: F.stranger)
        let d1s = F.mint(seq: 1, prev: g0s.get("id")!.asString!, map: F.MAP1, salt: "salt1")
        mustFail("prior-not-principal", F.verify(F.build(d1s, map: F.MAP1, salt: "salt1", is: is1), d1s,
                                                  F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([g0s])]), "acc": Self.acc(38_900)])), ["intent_session"],
                 why: "grant 0 is not signed")
        mustFail("prior-other-seq", F.verify(F.build(F.D1, map: F.MAP1, salt: "salt1", is: is1), F.D1,
                                              F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([F.D1])]), "acc": Self.acc(38_900)])), ["intent_session"],
                 why: "seq 0")
        // the admitting root: prev at seq 0 (malformed caveat), a stranger issuer, another root
        let prev0 = F.mint(seq: 0, prev: F.digest("p"), map: F.MAP0, salt: "salt0")
        XCTAssertEqual(IntentSession.caveatError(IntentSession.grantCaveat(prev0)), "intent_session caveat: prev is present exactly when seq > 0")
        mustFail("caveat-prev-at-0", F.verify(F.build(prev0, is: F.is0()), prev0, F.ctx()), ["intent_session"], why: "admitting root")
        let byStranger = F.mint(seq: 0, map: F.MAP0, salt: "salt0", signer: F.stranger)
        mustFail("stranger-root", F.verify(F.build(byStranger, is: F.is0()), byStranger, F.ctx()), ["intent_session"], why: "session principal")
        // the session root itself
        mustFail("root-missing", F.verify(F.P0, F.G0, F.ctx(["session": .object(["grants": .array([])])])), ["intent_session", "accumulators"])
        for (over, why) in [(["schema": JSONValue.object(["aud": .string(F.AUD), "digest": .string(F.digest("s"))])], "session schema"),
                            (["schema": .object(["aud": .string("other.example"), "digest": .string(F.SD)])], "another audience"),
                            (["layers": .object(["task": .object(["map_digest": .string(F.MAP1)])])], "task map")] as [(JObject, String)] {
            let r = F.root(over)
            let g = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: r.R)
            mustFail(why, F.verify(F.build(g, is: F.is0(["root": .string(r.R)])), g, F.ctx(["session": .object(["root": r.S, "grants": .array([])])])), ["intent_session"],
                     why: why)
        }
        // expiry: now < expires_at (strict)
        for (exp, ok) in [(F.NOW, false), (F.NOW + 1, true)] {
            let r = F.root(["expires_at": .int(exp)])
            let g = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: r.R)
            let v = F.verify(F.build(g, is: F.is0(["root": .string(r.R)])), g, F.ctx(["session": .object(["root": r.S, "grants": .array([])])]))
            if ok { mustAllow("expires+1", v) } else { mustFail("expires==now", v, ["intent_session", "accumulators"], why: "expired") }
        }
        // the session member without the intent binding
        var noIntent = F.body(F.G0, map: F.MAP0, salt: "salt0")
        noIntent["intent"] = nil
        noIntent["intent_session"] = F.is0()
        let v = F.verify(F.signP(noIntent), F.G0, F.ctx())
        XCTAssertNil(v.checks["intent"])
        XCTAssertEqual(v.checks["intent_session"], false, v.reason)
        XCTAssertTrue(v.reason.contains("envelope.intent"), v.reason)
        // a root signed by a key that is not a principal, and a tampered root
        let foreignRoot = F.signRoot(F.rootBody(), by: F.stranger)
        XCTAssertEqual(IntentSession.verifyRoot(foreignRoot).reason, "signer is not one of the session principals")
        XCTAssertFalse(IntentSession.verifyRoot(F.with(F.BASE.S, ["question_uri": .string("https://x")])).ok)
        XCTAssertTrue(IntentSession.verifyRoot(F.BASE.S).ok)
    }

    func testSessionRootShapeBoundaries() {
        func shape(_ over: JObject) -> String? { IntentSession.shapeError(F.signRoot(F.rootBody(over))) }
        XCTAssertNil(shape([:]))
        let p = { (i: Int) in JSONValue.object(["key": .string(F.pub(F.key("p\(i)")))]) }
        // the signer must stay a principal: put the real principal first
        let principal: JSONValue = .object(["key": .string(F.pub(F.principal))])
        XCTAssertNil(shape(["principals": .array([principal] + (1..<16).map(p))]))
        XCTAssertNotNil(shape(["principals": .array([principal] + (1..<17).map(p))]))
        XCTAssertNotNil(shape(["principals": .array([principal, principal])]))
        XCTAssertNotNil(shape(["principals": .array([])]))
        XCTAssertNil(shape(["layers": .object(["task": .object(["map_digest": .string(F.MAP0)]), "std": .object(["profile": .string("p"), "version": .int(1), "digest": .string(F.MAP1)])])]))
        XCTAssertNotNil(shape(["layers": .object(["task": .object(["map_digest": .string(F.MAP0)]), "std": .object(["profile": .string("p"), "version": .int(0), "digest": .string(F.MAP1)])])]))
        XCTAssertNotNil(shape(["layers": .object(["task": .object(["map_digest": .string(F.MAP0)]), "std": .null])]), "null std is malformed")
        XCTAssertNotNil(shape(["layers": .object(["task": .object(["map_digest": .string(F.MAP0)]), "org": .null])]), "null org is malformed")
        XCTAssertNil(shape(["layers": .object(["task": .object(["map_digest": .string(F.MAP0)]), "org": .object(["digest": .string(F.MAP1)])])]))
        XCTAssertNil(shape(["revocation": .object(["epoch_uri": .string("u"), "max_age_s": .int(60), "key": .string(F.pub(F.stranger)), "pq_pk": .string("AAAA")])]))
        XCTAssertNotNil(shape(["revocation": .object(["epoch_uri": .string("u"), "max_age_s": .int(60), "pq_pk": .string("AAAA")])]), "the authority key is required")
        XCTAssertNotNil(shape(["revocation": .object(["epoch_uri": .string("u"), "max_age_s": .int(60)])]), "the authority key is required")
        XCTAssertNotNil(shape(["revocation": .object(["epoch_uri": .string("u"), "max_age_s": .int(60), "key": .string(F.pub(F.principal))])]), "a principal is never the authority")
        XCTAssertNotNil(shape(["revocation": .object(["epoch_uri": .string("u"), "max_age_s": .int(60), "key": .string(F.pub(F.stranger)), "pq_pk": .null])]))
        for r in ["__proto__", "constructor", "prototype"] {
            XCTAssertNotNil(shape(["accumulators": .array([F.with(F.TRIP, ["id": .string(r)])])]), r)
            XCTAssertNotNil(shape(["monitors": .array([.object(["id": .string(r), "kind": .string("never"), "p": .object(["verb": .string("v")])])])]), r)
        }
        XCTAssertNotNil(shape(["principals": .array([.object(["key": .string(F.pub(F.principal)), "alg": .string("no-such-suite")])])]))
        XCTAssertNotNil(shape(["layers": .object(["task": .object(["map_digest": .string(F.MAP0), "x": .int(1)])])]))
        XCTAssertNil(shape(["accumulators": .array((0..<16).map { F.with(F.TRIP, ["id": .string("t\($0)")]) })]))
        XCTAssertNotNil(shape(["accumulators": .array((0..<17).map { F.with(F.TRIP, ["id": .string("t\($0)")]) })]))
        XCTAssertNotNil(shape(["accumulators": .array([F.TRIP, F.TRIP])]))
        XCTAssertNotNil(shape(["accumulators": .array([F.without(F.TRIP, ["key"])])]), "key is required (null or a path)")
        XCTAssertNotNil(shape(["question_uri": .string(String(repeating: "a", count: 2049))]))
        XCTAssertNil(shape(["question_uri": .string(String(repeating: "a", count: 2048))]))
        XCTAssertNotNil(shape(["revocation": .object(["epoch_uri": .string("u"), "max_age_s": .int(-1), "key": .string(F.pub(F.stranger))])]))
        XCTAssertNil(shape(["revocation": .object(["epoch_uri": .string("u"), "max_age_s": .int(0), "key": .string(F.pub(F.stranger))])]))
        XCTAssertNotNil(shape(["expires_at": .double(1.5)]))
        // an ed25519 root must not carry pq fields
        XCTAssertNotNil(IntentSession.shapeError(F.with(F.BASE.S, ["pq_pk": .string("AA")])))
    }

    func testSessionRevocation() {
        let R4 = F.root(["revocation": F.revocationSource()])
        let g = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: R4.R)
        let p = F.build(g, is: F.is0(["root": .string(R4.R)]))
        let ids = [IntentRevocation.sessionId(F.SESSION), IntentRevocation.mapId(F.MAP0), IntentRevocation.deltaId(g.get("id")!.asString!)]
        func c(_ rev: JSONValue?, _ policy: JSONValue? = nil, root: JSONValue = R4.S, last: JSONValue? = nil) -> JSONValue {
            var s: JObject = ["root": root, "grants": .array([])]
            if let r = rev { s["revocation"] = r }
            if let l = last { s["revocation_last"] = l }
            var o: JObject = ["session": .object(s)]
            if let pol = policy { o["policy"] = pol }
            return F.ctx(o)
        }
        let fresh = F.evidence(["pca-intent:session:zz"], issued: F.NOW - 30_000)
        mustAllow("fresh", F.verify(p, g, c(fresh)))
        mustAllow("empty-set", F.verify(p, g, c(F.evidence([], issued: F.NOW - 1_000))))
        mustAllow("other-ids-revoked", F.verify(p, g, c(F.evidence([IntentRevocation.mapId(F.MAP1), "pca-intent:delta:x", "zzz"], issued: F.NOW - 1_000))))
        mustFail("absent", F.verify(p, g, c(nil)), ["intent_session"], why: "revocation")
        mustAllow("age==max", F.verify(p, g, c(F.evidence([], issued: F.NOW - 60_000))))
        mustFail("age==max+1", F.verify(p, g, c(F.evidence([], issued: F.NOW - 60_001))), ["intent_session"])
        mustAllow("future==skew", F.verify(p, g, c(F.evidence([], issued: F.NOW + 60_000))))
        mustFail("future>skew", F.verify(p, g, c(F.evidence([], issued: F.NOW + 60_001))), ["intent_session"])
        mustAllow("not_after==now", F.verify(p, g, c(F.evidence([], issued: F.NOW - 1_000, notAfter: F.NOW))))
        mustFail("not_after<now", F.verify(p, g, c(F.evidence([], issued: F.NOW - 1_000, notAfter: F.NOW - 1))), ["intent_session"])
        for (i, id) in ids.enumerated() { mustFail("revoked-\(i)", F.verify(p, g, c(F.evidence([id], issued: F.NOW - 1_000))), ["intent_session"], why: "is revoked") }
        // ONLY the dedicated authority signs: a principal's or a stranger's epoch is refused
        mustFail("principal-signed", F.verify(p, g, c(F.evidence([], issued: F.NOW - 1_000, by: F.principal))), ["intent_session"], why: "revocation authority")
        mustFail("stranger-signed", F.verify(p, g, c(F.evidence([], issued: F.NOW - 1_000, by: F.stranger))), ["intent_session"], why: "revocation authority")
        mustFail("other-scope", F.verify(p, g, c(F.evidence([], issued: F.NOW - 1_000, scope: IntentRevocation.sessionScope(F.digest("s2"))))), ["intent_session"])
        // the evidence is exactly {epoch, revoked}; the list is the signed set
        let ep = F.epoch(["a", "b"], issued: F.NOW - 1_000)
        for (n, ev) in [("extra-member", JSONValue.object(["epoch": ep, "revoked": .array([.string("a"), .string("b")]), "proofs": .object([:])])),
                        ("no-revoked", .object(["epoch": ep])),
                        ("unsorted", .object(["epoch": ep, "revoked": .array([.string("b"), .string("a")])])),
                        ("duplicate", .object(["epoch": F.epoch(["a", "a"], issued: F.NOW - 1_000, number: 2), "revoked": .array([.string("a"), .string("a")])])),
                        ("short-list", .object(["epoch": ep, "revoked": .array([.string("a")])])),
                        ("other-list", .object(["epoch": ep, "revoked": .array([.string("a"), .string("c")])])),
                        ("non-string", .object(["epoch": ep, "revoked": .array([.string("a"), .int(1)])])),
                        ("epoch-not-size", .object(["epoch": F.epoch(["a", "b"], issued: F.NOW - 1_000, number: 3), "revoked": .array([.string("a"), .string("b")])]))] {
            mustFail(n, F.verify(p, g, c(ev)), ["intent_session"])
        }
        mustAllow("signed-list", F.verify(p, g, c(.object(["epoch": ep, "revoked": .array([.string("a"), .string("b")])]))))
        // APPEND-ONLY against the tracked last epoch: no rollback, no drop, no equivocation
        let last = F.evidence(["a", "b"], issued: F.NOW - 5_000)
        mustAllow("extends-last", F.verify(p, g, c(F.evidence(["a", "b", "c"], issued: F.NOW - 1_000), last: last)))
        mustAllow("same-as-last", F.verify(p, g, c(F.evidence(["a", "b"], issued: F.NOW - 1_000), last: last)))
        mustFail("rollback", F.verify(p, g, c(F.evidence(["a"], issued: F.NOW - 1_000), last: last)), ["intent_session"], why: "rollback")
        mustFail("drop", F.verify(p, g, c(F.evidence(["a", "c", "d"], issued: F.NOW - 1_000), last: last)), ["intent_session"], why: "drops")
        mustFail("equivocation", F.verify(p, g, c(F.evidence(["a", "c"], issued: F.NOW - 1_000), last: last)), ["intent_session"])
        mustFail("last-extra-member", F.verify(p, g, c(F.evidence(["a", "b"], issued: F.NOW - 1_000),
                                                      last: F.with(last, ["note": .string("x")]))), ["intent_session"], why: "tracked last epoch")
        mustFail("missing-revoked", F.verify(p, g, c(.object(["epoch": ep]))), ["intent_session"], why: "revoked must be an array")
        mustFail("last-malformed", F.verify(p, g, c(F.evidence(["a"], issued: F.NOW - 1_000), last: .object(["epoch": ep]))), ["intent_session"], why: "tracked last epoch")
        mustFail("last-null", F.verify(p, g, c(F.evidence(["a"], issued: F.NOW - 1_000), last: .null)), ["intent_session"], why: "tracked last revocation epoch")
        // the stricter of S and the policy; a policy age with no authority in S fails
        let pol = { (x: JSONValue) in JSONValue.object(["session": .object(["max_revocation_age_s": x])]) }
        mustFail("policy-stricter", F.verify(p, g, c(F.evidence([], issued: F.NOW - 20_000), pol(.int(10)))), ["intent_session"])
        mustAllow("policy-stricter-edge", F.verify(p, g, c(F.evidence([], issued: F.NOW - 10_000), pol(.int(10)))))
        mustAllow("policy-looser", F.verify(p, g, c(F.evidence([], issued: F.NOW - 60_000), pol(.int(600)))))
        for x: JSONValue in [.int(-1), .double(1.5), .double(-0.0), .string("10"), .null] {
            mustFail("policy-misconfigured-\(x)", F.verify(p, g, c(fresh, pol(x))), ["schema", "intent_session", "accumulators"], why: "malformed v2 context")
        }
        mustFail("policy-no-authority", F.verify(F.P0, F.G0, F.ctx(["policy": pol(.int(60))])), ["intent_session"], why: "names no revocation authority")
        // M * 1000 beyond 2^53-1: misconfigured at step a
        let Rbig = F.root(["revocation": F.revocationSource(maxAgeS: 9_007_199_254_740_991)])
        let gbig = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: Rbig.R)
        let pbig = F.build(gbig, is: F.is0(["root": .string(Rbig.R)]))
        mustFail("max-age-overflow", F.verify(pbig, gbig, c(fresh, root: Rbig.S)), ["intent_session"], why: "max age misconfigured")
        let Rok = F.root(["revocation": F.revocationSource(maxAgeS: 9_007_199_254_740)])
        let gok = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: Rok.R)
        mustAllow("max-age-largest-safe", F.verify(F.build(gok, is: F.is0(["root": .string(Rok.R)])), gok, c(fresh, root: Rok.S)))
        // the held chain's deltas and the standing profile are checked too
        let R1 = F.root(["revocation": F.revocationSource()])
        let g0 = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: R1.R)
        let d1 = F.mint(seq: 1, prev: g0.get("id")!.asString!, map: F.MAP1, salt: "salt1", root: R1.R)
        let p1 = F.build(d1, map: F.MAP1, salt: "salt1", is: F.is0(["root": .string(R1.R), "seq": .int(1)].merging(Self.claim(77_800)) { $1 }))
        for (revoked, ok) in [([String](), true), ([IntentRevocation.deltaId(g0.get("id")!.asString!)], false)] {
            let v = F.verify(p1, d1, F.ctx(["session": .object(["root": R1.S, "grants": .array([g0]), "revocation": F.evidence(revoked, issued: F.NOW - 1_000)]),
                                            "acc": Self.acc(38_900)]))
            if ok { mustAllow("d1-chain", v) } else { mustFail("d1-g0-revoked", v, ["intent_session"]) }
        }
        let Rs = F.root(["layers": .object(["task": .object(["map_digest": .string(F.MAP0)]), "std": .object(["profile": .string("prof"), "version": .int(2), "digest": .string(F.MAP1)])]),
                         "revocation": F.revocationSource()])
        let gs = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: Rs.R)
        XCTAssertEqual(IntentRevocation.profileId("prof", 2), "pca-intent:profile:prof@2")
        for (revoked, ok) in [(["pca-intent:profile:prof@1"], true), (["pca-intent:profile:prof@2"], false)] {
            let v = F.verify(F.build(gs, is: F.is0(["root": .string(Rs.R)])), gs, c(F.evidence(revoked, issued: F.NOW - 1_000), root: Rs.S))
            if ok { mustAllow("profile-other-version", v) } else { mustFail("profile-revoked", v, ["intent_session"]) }
        }
    }

    func testRevocationPrimitiveBoundaries() {
        let id = IntentRevocation.sessionId(F.SESSION)
        func run(_ revoked: [String], issued: Int64 = F.NOW - 10_000, maxAge: Int64 = 60_000, last: JSONValue? = nil, patch: JObject = [:]) -> Bool {
            let ev = F.evidence(revoked, issued: issued).asObject!
            var i: JObject = ["epoch": ev["epoch"]!, "revoked": ev["revoked"]!, "session": .string(F.SESSION), "authority": .string(F.pub(F.revAuthority)),
                              "ids": .array([.string(id)]), "now": .int(F.NOW), "max_age_ms": .int(maxAge)]
            if let l = last { i["last"] = l }
            for (k, v) in patch { i[k] = v }
            return PCA.intentRevocationPrimitive(.object(i))
        }
        XCTAssertTrue(run(["pca-intent:map:a", "pca-intent:session:zzzz"]))
        XCTAssertTrue(run([]))
        XCTAssertFalse(run([id]))
        XCTAssertFalse(run([], maxAge: -1))
        XCTAssertTrue(run([], issued: F.NOW, maxAge: 0))
        XCTAssertFalse(run([], issued: F.NOW - 1, maxAge: 0))
        XCTAssertFalse(run([], patch: ["authority": .string(F.pub(F.principal))]))
        XCTAssertFalse(run([], patch: ["ids": .array([.int(1)])]))
        XCTAssertFalse(run([], patch: ["now": .double(1.5)]))
        XCTAssertFalse(run([], patch: ["revoked": .null]))
        XCTAssertFalse(run([], patch: ["proofs": .object([:])]), "the evidence is the input without the parameters: closed")
        XCTAssertTrue(run([], patch: ["scope": .string(IntentRevocation.sessionScope(F.SESSION))]), "scope is a parameter, not evidence")
        XCTAssertTrue(run(["a", "b"], last: F.evidence(["a"], issued: F.NOW - 20_000)))
        XCTAssertFalse(run(["b"], last: F.evidence(["a"], issued: F.NOW - 20_000)))
        // revset_root: the RFC-6962 tree over the sorted ids, size-bound; the empty list binds sha256("")
        XCTAssertEqual(IntentRevocation.revsetRoot([]), IntentRevocation.bindRoot(.int(0), IntentRevocation.EMPTY_TREE))
        XCTAssertNotEqual(IntentRevocation.revsetRoot(["a", "b"]), IntentRevocation.revsetRoot(["b", "a"]))
    }

    // ---- rule 14 ---------------------------------------------------------------------------------------------------

    func testConformanceOrderAndDomains() {
        func conf(_ patch: JObject, verb: String = "air.book", base: JSONValue = F.PARAMS) -> (Bool, String, String?) {
            guard case var .object(p) = base else { return (false, "", nil) }
            for (k, v) in patch { p[k] = v }
            let r = ActionSchema.conform(F.SCHEMA, verb: verb, params: .object(p))
            return (r.ok, r.code, r.path)
        }
        XCTAssertTrue(conf([:]).0)
        XCTAssertEqual(ActionSchema.conform(F.SCHEMA, verb: "air.book", params: .array([])).code, "params_not_object")
        XCTAssertEqual(conf([:], verb: "air.cancel").1, "unknown_verb")
        XCTAssertEqual(conf(["zz": .int(1), "aa": .int(1)]).2, "action.params.aa")
        XCTAssertEqual(ActionSchema.conform(F.SCHEMA, verb: "air.book", params: .object(["offer_id": .string("x"), "extra": .int(1)])).code, "undeclared_param")
        let missing = ActionSchema.conform(F.SCHEMA, verb: "air.book", params: .object([:]))
        XCTAssertEqual(missing.code, "missing_param"); XCTAssertEqual(missing.path, "action.params.add_ons")
        for (v, code) in [(JSONValue.string("38900"), "bad_type"), (.double(1.5), "bad_type"), (.double(-0.0), "bad_type"), (.int(-1), "out_of_domain"),
                          (.int(5_000_001), "out_of_domain"), (.bool(true), "bad_type")] {
            XCTAssertEqual(conf(["total": v]).1, code, "\(v)")
        }
        for v: JSONValue in [.int(0), .int(5_000_000), .double(5_000_000)] { XCTAssertTrue(conf(["total": v]).0, "\(v)") }
        XCTAssertEqual(conf(["refundable": .string("false")]).1, "bad_type")
        XCTAssertEqual(conf(["add_ons": .array([.string("none"), .string("none")])]).1, "out_of_domain")
        XCTAssertEqual(conf(["add_ons": .array([.string("bag")])]).1, "out_of_domain")
        XCTAssertEqual(conf(["add_ons": .array([.int(1)])]).1, "bad_type")
        XCTAssertTrue(conf(["add_ons": .array([])]).0)
        XCTAssertTrue(conf(["add_ons": .array([.string("none"), .string("tripshield"), .string("seat_plus")])]).0, "max_items defaults to |values|")
        XCTAssertTrue(conf(["passengers": .array((0..<9).map { .string("p\($0)") })]).0)
        XCTAssertEqual(conf(["passengers": .array((0..<10).map { .string("p\($0)") })]).1, "out_of_domain")
        XCTAssertTrue(conf(["passengers": .array([.string(String(repeating: "x", count: 64))])]).0)
        XCTAssertEqual(conf(["passengers": .array([.string(String(repeating: "x", count: 65))])]).1, "bad_type")
        XCTAssertTrue(conf(["note": .string(String(repeating: "\u{e9}", count: 8))]).0)
        XCTAssertEqual(conf(["note": .string(String(repeating: "\u{e9}", count: 8) + "a")]).1, "out_of_domain")
        let search: JSONValue = .object(["from": .string("SFO"), "date": .string("2026-11-20"), "pax": .int(2)])
        XCTAssertTrue(conf([:], verb: "air.search", base: search).0)
        XCTAssertEqual(conf(["from": .string("LAX")], verb: "air.search", base: search).1, "out_of_domain")
        for (d, ok) in [("2028-02-29", true), ("2026-02-29", false), ("1900-02-29", false), ("2000-02-29", true), ("2026-1-05", false), ("0000-01-01", false),
                        ("0001-01-01", true), ("9999-12-31", true), ("2026-04-31", false), ("2026-04-30", true), ("2026-13-01", false), ("2026-12-00", false)] {
            XCTAssertEqual(ActionSchema.isCalendarDate(d), ok, d)
        }
        XCTAssertEqual(conf(["pax": .int(0)], verb: "air.search", base: search).1, "out_of_domain")
        XCTAssertTrue(conf(["pax": .int(9)], verb: "air.search", base: search).0)
        XCTAssertEqual(conf(["pax": .int(10)], verb: "air.search", base: search).1, "out_of_domain")
        // a canon projection: present booleans, sets (sorted), arrays (as sent)
        let canon = ActionSchema.canonProjection(F.SCHEMA, verb: "air.book", params: F.with(F.PARAMS, ["add_ons": .array([.string("tripshield"), .string("none")]),
                                                                                                 "passengers": .array([.string("b"), .string("a")])]).asObject!)
        XCTAssertEqual(canon["add_ons"], .string("[\"none\",\"tripshield\"]"))
        XCTAssertEqual(canon["passengers"], .string("[\"b\",\"a\"]"))
        XCTAssertEqual(canon["refundable"], .string("false"))
        XCTAssertNil(canon["total"]); XCTAssertNil(canon["note"])
    }

    func testSchemaSignature() {
        XCTAssertTrue(ActionSchema.verify(F.SCHEMA, keys: F.KEYS).ok)
        XCTAssertFalse(ActionSchema.verify(F.SCHEMA, keys: .array([F.with(F.KEYS.asArray![0], ["kid": .string("other")])])).ok)
        XCTAssertFalse(ActionSchema.verify(F.SCHEMA, keys: .array([F.with(F.KEYS.asArray![0], ["alg": .string("ml-dsa-65")])])).ok)
        XCTAssertTrue(ActionSchema.verify(F.SCHEMA, keys: .array([F.without(F.KEYS.asArray![0], ["alg"])])).ok, "an absent key alg is ed25519")
        XCTAssertTrue(ActionSchema.verify(F.with(F.SCHEMA, ["sig": F.without(F.SCHEMA.get("sig")!, ["alg"])]), keys: F.KEYS).ok, "an absent sig.alg is ed25519")
        XCTAssertFalse(ActionSchema.verify(F.with(F.SCHEMA, ["sig": F.with(F.SCHEMA.get("sig")!, ["alg": .string("ml-dsa-65")])]), keys: F.KEYS).ok)
        XCTAssertFalse(ActionSchema.verify(F.with(F.SCHEMA, ["version": .string("x")]), keys: F.KEYS).ok)
        XCTAssertFalse(ActionSchema.verify(F.with(F.SCHEMA, ["extra": .int(1)]), keys: F.KEYS).ok)
        XCTAssertFalse(ActionSchema.verify(F.SCHEMA, keys: .array([F.with(F.KEYS.asArray![0], ["pk": .string(F.digest("x") + "A")])])).ok)
        XCTAssertFalse(ActionSchema.verify(F.SCHEMA, keys: .object([:])).ok)
        XCTAssertNotNil(ActionSchema.shapeError(F.signSchema(F.UNSIGNED.merging(["verbs": .array([])]) { $1 })))
        XCTAssertNotNil(ActionSchema.shapeError(F.signSchema(F.UNSIGNED.merging(["verbs": .array([F.UNSIGNED["verbs"]!.asArray![0], F.UNSIGNED["verbs"]!.asArray![0]])]) { $1 })))
        XCTAssertNotNil(ActionSchema.shapeError(F.signSchema(F.UNSIGNED.merging(["v": .int(2)]) { $1 })))
        XCTAssertNil(ActionSchema.shapeError(F.signSchema(F.UNSIGNED.merging(["v": .double(1)]) { $1 })))
        XCTAssertEqual(ActionSchema.digest(F.SCHEMA), F.SD)
        XCTAssertNotEqual(ActionSchema.digest(F.signSchema(F.UNSIGNED, kid: "k2")), F.SD)
    }

    // ---- rule 15 ---------------------------------------------------------------------------------------------------

    func testSiteLocalAccumulators() {
        func run(_ isOver: JObject, _ c: JSONValue, grant: JSONValue = F.G0) -> PCA.Verdict { F.verify(F.build(grant, is: F.is0(isOver)), grant, c) }
        for post in [38_899, 38_901] as [Int64] { mustFail("claim-\(post)", run(Self.claim(post), F.ctx()), ["accumulators"], why: "differs") }
        mustFail("claim-missing", run(["acc": .array([])], F.ctx()), ["accumulators"], why: "no claim")
        mustFail("claim-unknown", run(["acc": .array([.object(["id": .string("trip_spend"), "post": .int(38_900)]), .object(["id": .string("nope"), "post": .int(0)])])], F.ctx()),
                 ["accumulators"], why: "names no accumulator")
        mustFail("claim-wallet", run(["acc": .array([.object(["id": .string("trip_spend"), "post": .int(38_900)]), .object(["id": .string("questions"), "post": .int(1)])])], F.ctx()),
                 ["accumulators"], why: "wallet-held")
        mustFail("no-state", run([:], F.ctx(["acc": .object(["state": .object([:]), "monitors": .object([:])])])), ["accumulators"], why: "no state")
        for (name, st) in [("count-shape", JSONValue.object(["count": .int(0)])), ("extra", .object(["sum": .int(0), "x": .int(1)])), ("neg", .object(["sum": .int(-1)])),
                           ("frac", .object(["sum": .double(0.5)])), ("neg-zero", .object(["sum": .double(-0.0)])), ("not-object", .array([]))] {
            mustFail("bad-state-\(name)", run([:], F.ctx(["acc": .object(["state": .object(["trip_spend": st]), "monitors": .object([:])])])), ["accumulators"])
        }
        mustAllow("domain==max", run(Self.claim(500_000), F.ctx(["acc": Self.acc(461_100)])))
        mustFail("domain>max", run(Self.claim(500_001), F.ctx(["acc": Self.acc(461_101)])), ["accumulators"], why: "outside its domain")
        // a site-local claim must not carry a receipt
        mustFail("site-local-receipt", run(["acc": .array([.object(["id": .string("trip_spend"), "post": .int(38_900), "receipt": .string(F.digest("r"))])])], F.ctx()),
                 ["accumulators"], why: "site-local")
        // 2^53-1 overflow (no domain bound)
        let open = F.root(["accumulators": .array([F.without(F.TRIP, ["domain_max"])])])
        let go = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: open.R)
        let max: Int64 = 9_007_199_254_740_991
        mustAllow("post==2^53-1", F.verify(F.build(go, is: F.is0(["root": .string(open.R)].merging(Self.claim(max)) { $1 })), go,
                                            F.ctx(["session": .object(["root": open.S, "grants": .array([])]), "acc": Self.acc(max - 38_900)])))
        mustFail("post>2^53-1", F.verify(F.build(go, is: F.is0(["root": .string(open.R)].merging(Self.claim(max)) { $1 })), go,
                                          F.ctx(["session": .object(["root": open.S, "grants": .array([])]), "acc": Self.acc(max - 38_899)])), ["accumulators"], why: "overflows")
    }

    func testNotSelectedAndAggregates() {
        // an action the accumulator does not feed: no claim allowed, the pre-state still lands in env
        let search: JSONValue = .object(["from": .string("SFO"), "date": .string("2026-11-20"), "pax": .int(2)])
        let ps = F.build(F.G0, is: F.is0(["acc": .array([])]), params: search, verb: "air.search")
        mustAllow("not-selected", F.verify(ps, F.G0, F.ctx(["params": search])))
        let env = PCA.intentV2Env(pcactn: ps, grant: F.G0, now: F.NOW, context: IntentV2Context(F.ctx(["params": search, "acc": Self.acc(1_234)])))
        XCTAssertEqual(env?.acc?["trip_spend"], .object(["post": .int(1_234)]))
        mustFail("not-selected-claim", F.verify(F.build(F.G0, is: F.is0(), params: search, verb: "air.search"), F.G0, F.ctx(["params": search])), ["accumulators"],
                 why: "does not feed")
        // distinct / max / keyed count
        let DIST: JSONValue = .object(["id": .string("payees"), "agg": .string("distinct"), "val": .string("action.params.offer_id"), "sel": .object(["verbs": .array([.string("air.book")])]),
                                       "win": .object(["kind": .string("task")]), "key": .null, "domain_max": .int(3), "holder": .object(["kind": .string("site_local")])])
        let MAX: JSONValue = .object(["id": .string("largest"), "agg": .string("max"), "val": .string("action.params.total"), "sel": .object(["verbs": .array([.string("air.book")])]),
                                      "win": .object(["kind": .string("task")]), "key": .null, "holder": .object(["kind": .string("site_local")])])
        let CNT: JSONValue = .object(["id": .string("per_offer"), "agg": .string("count"), "sel": .object(["verbs": .array([.string("air.book")])]),
                                      "win": .object(["kind": .string("sliding"), "ms": .int(60_000)]), "key": .string("action.params.offer_id"), "domain_max": .int(1),
                                      "holder": .object(["kind": .string("site_local")])])
        let RX = F.root(["accumulators": .array([DIST, MAX, CNT])])
        let gx = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: RX.R)
        func claims(_ d: Int64, _ m: Int64, _ c: Int64) -> JSONValue {
            .array([.object(["id": .string("payees"), "post": .int(d)]), .object(["id": .string("largest"), "post": .int(m)]), .object(["id": .string("per_offer"), "post": .int(c)])])
        }
        func run(_ cl: JSONValue, _ st: JObject) -> PCA.Verdict {
            F.verify(F.build(gx, is: F.is0(["root": .string(RX.R), "acc": cl])), gx,
                     F.ctx(["session": .object(["root": RX.S, "grants": .array([])]), "acc": .object(["state": .object(st), "monitors": .object([:])])]))
        }
        let st: JObject = ["payees": .object(["values": .array([.string("\"OF-1\""), .string("\"OF-9\"")])]), "largest": .object(["max": .int(40_000)]),
                           "per_offer": .object(["count": .int(0)])]
        mustAllow("distinct-max-count", run(claims(2, 40_000, 1), st))
        mustFail("distinct-new", run(claims(2, 40_000, 1), st.merging(["payees": .object(["values": .array([.string("\"OF-7\""), .string("\"OF-9\"")])])]) { $1 }), ["accumulators"])
        mustAllow("distinct-new-3", run(claims(3, 40_000, 1), st.merging(["payees": .object(["values": .array([.string("\"OF-7\""), .string("\"OF-9\"")])])]) { $1 }))
        mustFail("distinct-dup-pre", run(claims(2, 40_000, 1), st.merging(["payees": .object(["values": .array([.string("x"), .string("x")])])]) { $1 }), ["accumulators"])
        mustAllow("max-new", run(claims(2, 38_900, 1), st.merging(["largest": .object(["max": .int(38_899)])]) { $1 }))
        mustFail("max-wrong", run(claims(2, 38_899, 1), st.merging(["largest": .object(["max": .int(38_899)])]) { $1 }), ["accumulators"])
        mustFail("count-over-domain", run(claims(2, 40_000, 2), st.merging(["per_offer": .object(["count": .int(1)])]) { $1 }), ["accumulators"], why: "outside its domain")
        XCTAssertEqual(IntentAcc.distinctKey(.int(7)), "7")
        XCTAssertEqual(IntentAcc.distinctKey(.double(7)), "7")
        XCTAssertNil(IntentAcc.distinctKey(.double(-0.0)))
        XCTAssertNil(IntentAcc.distinctKey(.double(7.5)))
        XCTAssertEqual(IntentAcc.distinctKey(.string("OF")), "\"OF\"")
        // a key on free text is refused; a missing key parameter is refused
        let TXT = F.with(CNT, ["key": .string("action.params.note"), "id": .string("per_note")])
        let RT = F.root(["accumulators": .array([TXT])])
        let gt = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: RT.R)
        var withNote = F.PARAMS.asObject!
        withNote["note"] = .string("hi")
        func runT(_ params: JSONValue) -> PCA.Verdict {
            F.verify(F.build(gt, is: F.is0(["root": .string(RT.R), "acc": .array([.object(["id": .string("per_note"), "post": .int(1)])])]), params: params), gt,
                     F.ctx(["params": params, "session": .object(["root": RT.S, "grants": .array([])]),
                            "acc": .object(["state": .object(["per_note": .object(["count": .int(0)])]), "monitors": .object([:])])]))
        }
        mustFail("key-free-text", runT(.object(withNote)), ["accumulators"], why: "free text")
        mustFail("key-missing", runT(F.PARAMS), ["accumulators"], why: "missing")
    }

    func testMonitors() {
        func run(_ mon: JSONValue, _ state: JSONValue?) -> PCA.Verdict {
            let RM = F.root(["monitors": .array([mon])])
            let gm = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: RM.R)
            var ms: JObject = [:]
            if let s = state { ms[JKey(mon.get("id")!.asString!)] = s }
            return F.verify(F.build(gm, is: F.is0(["root": .string(RM.R)])), gm, F.ctx(["session": .object(["root": RM.S, "grants": .array([])]), "acc": Self.acc(0, monitors: ms)]))
        }
        let prior: JSONValue = .object(["id": .string("m"), "kind": .string("requires_prior"), "p": .object(["verb": .string("air.book")]), "q": .object(["verb": .string("hotel.book")]),
                                        "status": .string("committed")])
        mustAllow("unmet", run(prior, .string("unmet")))
        mustAllow("met", run(prior, .string("met")))
        mustFail("missing", run(prior, nil), ["accumulators"], why: "monitor")
        mustFail("maybe", run(prior, .string("maybe")), ["accumulators"])
        mustFail("not-string", run(prior, .int(1)), ["accumulators"])
        let rw: JSONValue = .object(["id": .string("r"), "kind": .string("responds_within"), "p": .object(["verb": .string("a")]), "q": .object(["verb": .array([.string("b")])]), "within": .int(2)])
        for (s, ok) in [("idle", true), ("pending:1", true), ("pending:2", true), ("pending:3", false), ("pending:0", false), ("missed", true)] {
            let v = run(rw, .string(s))
            if ok { mustAllow(s, v) } else { mustFail(s, v, ["accumulators"]) }
        }
        XCTAssertEqual(IntentAcc.monitorStates(.object(["kind": .string("never")])), ["clean", "seen"])
        XCTAssertEqual(IntentAcc.monitorStates(.object(["kind": .string("always")])), ["ok", "broken"])
        XCTAssertNil(IntentAcc.monitorDeclError(F.with(rw, ["within": .int(64)])))
        XCTAssertNotNil(IntentAcc.monitorDeclError(F.with(rw, ["within": .int(65)])))
        XCTAssertNotNil(IntentAcc.monitorDeclError(F.with(rw, ["within": .int(0)])))
        XCTAssertNotNil(IntentAcc.monitorDeclError(F.without(rw, ["q"])))
        XCTAssertNotNil(IntentAcc.monitorDeclError(F.with(prior, ["within": .int(1)])))
        XCTAssertNotNil(IntentAcc.monitorDeclError(F.with(prior, ["p": .object(["verb": .array([])])])))
    }

    // the sequenced holder: receipts resolved through the sequencer's root-signed key set
    static let SEQ = F.with(F.TRIP, ["holder": .object(["kind": .string("sequenced"), "uri": .string("https://atlas.example/seq"), "root": .string(F.pub(F.seqRoot))])])

    func testSequencedReceipts() {
        func setup(_ decl: JSONValue = Self.SEQ) -> (JSONValue, JSONValue, String, String) {
            let RS = F.root(["accumulators": .array([decl])])
            let gs = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: RS.R)
            let rsv = IntentAcc.reservationDigest(F.body(gs, map: F.MAP0, salt: "salt0"))!
            return (RS.S, gs, RS.R, rsv)
        }
        let (S, gs, R, rsv) = setup()
        func ps(_ rc: JSONValue, post: Int64 = 48_900, id: String = "trip_spend", root: String = R, grant: JSONValue = gs) -> JSONValue {
            F.build(grant, is: F.is0(["root": .string(root), "acc": .array([.object(["id": .string(id), "post": .int(post), "receipt": .string(IntentAcc.receiptDigest(rc)!)])])]))
        }
        func cs(_ receipts: [JSONValue], keys: JSONValue? = .array([F.keySet(keys: [F.keyEntry()])]), last: JSONValue? = nil, root: JSONValue = S) -> JSONValue {
            var a: JObject = ["receipts": .array(receipts), "monitors": .object([:])]
            if let k = keys { a["sequencer_keys"] = k }
            if let l = last { a["last_seq"] = l }
            return F.ctx(["session": .object(["root": root, "grants": .array([])]), "acc": .object(a)])
        }
        let rc = F.receipt(["pcactn_digest": .string(rsv)])
        mustAllow("receipt", F.verify(ps(rc), gs, cs([rc])))
        mustFail("not-presented", F.verify(ps(rc), gs, cs([])), ["accumulators"], why: "not presented")
        mustFail("missing-set", F.verify(ps(rc), gs, cs([rc], keys: nil)), ["accumulators"], why: "key set")
        mustFail("empty-sets", F.verify(ps(rc), gs, cs([rc], keys: .array([]))), ["accumulators"])
        mustFail("foreign-set", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry()], by: F.stranger)]))), ["accumulators"])
        mustAllow("some-set", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry()], by: F.stranger), F.keySet(keys: [F.keyEntry()])]))))
        mustFail("tampered-set", F.verify(ps(rc), gs, cs([rc], keys: .array([F.with(F.keySet(keys: [F.keyEntry()]), ["issued_at": .int(1)])]))), ["accumulators"])
        mustFail("kid-mismatch", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(kid: "k2")])]))), ["accumulators"])
        mustFail("pk-mismatch", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(key: F.stranger)])]))), ["accumulators"])
        let issued = F.NOW - 1_000
        mustAllow("not_before==issued", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(notBefore: issued)])]))))
        mustFail("not_before>issued", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(notBefore: issued + 1)])]))), ["accumulators"])
        mustAllow("not_after==issued", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(notAfter: issued)])]))))
        mustFail("retired", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(notAfter: issued - 1)])]))), ["accumulators"])
        // rotation: the retired key's receipt from inside its window still verifies
        mustAllow("rotated-in-window", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(notAfter: issued + 5), F.keyEntry(kid: "k2", key: F.stranger, notBefore: issued + 6)])]))))
        for (at, ok) in [(F.NOW + 60_000, true), (F.NOW + 60_001, false)] {
            let r = F.receipt(["pcactn_digest": .string(rsv), "issued_at": .int(at), "expires_at": .int(F.NOW + 120_000)])
            let v = F.verify(ps(r), gs, cs([r]))
            if ok { mustAllow("issued==now+skew", v) } else { mustFail("issued>now+skew", v, ["accumulators"]) }
        }
        mustAllow("entry-alg-ed25519", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(alg: "ed25519")])]))))
        mustFail("entry-alg-mismatch", F.verify(ps(rc), gs, cs([rc], keys: .array([F.keySet(keys: [F.keyEntry(alg: "ml-dsa-65")])]))), ["accumulators"])
        for (exp, ok) in [(F.NOW, true), (F.NOW - 1, false)] {
            let r = F.receipt(["pcactn_digest": .string(rsv), "expires_at": .int(exp)])
            let v = F.verify(ps(r), gs, cs([r]))
            if ok { mustAllow("expires==now", v) } else { mustFail("expired", v, ["accumulators"], why: "expired") }
        }
        mustFail("replay", F.verify(ps(rc), gs, cs([rc], last: .object(["trip_spend": .int(3)]))), ["accumulators"], why: "replays")
        mustAllow("seq>last", F.verify(ps(rc), gs, cs([rc], last: .object(["trip_spend": .int(2)]))))
        mustAllow("last-other-id", F.verify(ps(rc), gs, cs([rc], last: .object(["other": .int(9)]))))
        let bent = F.receipt(["pcactn_digest": .string(rsv), "post": .int(48_901)])
        mustFail("arithmetic", F.verify(ps(bent, post: 48_901), gs, cs([bent])), ["accumulators"], why: "add up")
        for (over, why) in [(["aud": JSONValue.string("hotel.example")], "another session"), (["session": .string(F.digest("s2"))], "another session"),
                            (["pcactn_digest": .string(F.digest("other"))], "another action")] as [(JObject, String)] {
            var o = over
            if o["pcactn_digest"] == nil { o["pcactn_digest"] = .string(rsv) }
            let r = F.receipt(o)
            mustFail(why, F.verify(ps(r), gs, cs([r])), ["accumulators"], why: why)
        }
        let noReceipt = F.build(gs, is: F.is0(["root": .string(R), "acc": .array([.object(["id": .string("trip_spend"), "post": .int(48_900)])])]))
        mustFail("claim-without-receipt", F.verify(noReceipt, gs, cs([rc])), ["accumulators"], why: "needs a reservation receipt")
        XCTAssertTrue(IntentAcc.receiptArithmeticOk("count", .object(["pre": .int(4), "delta": .int(1), "post": .int(5)]), 1))
        XCTAssertFalse(IntentAcc.receiptArithmeticOk("count", .object(["pre": .int(4), "delta": .int(2), "post": .int(6)]), 1))
        XCTAssertTrue(IntentAcc.receiptArithmeticOk("max", .object(["pre": .int(9), "delta": .int(4), "post": .int(9)]), 4))
        XCTAssertFalse(IntentAcc.receiptArithmeticOk("max", .object(["pre": .int(9), "delta": .int(4), "post": .int(4)]), 4))
        XCTAssertTrue(IntentAcc.receiptArithmeticOk("distinct", .object(["pre": .int(2), "delta": .int(0), "post": .int(2)]), 1))
        XCTAssertFalse(IntentAcc.receiptArithmeticOk("distinct", .object(["pre": .int(2), "delta": .int(2), "post": .int(4)]), 1))
        // last_seq: own members only; every value must be a non-negative safe integer
        mustAllow("last-own-only", F.verify(ps(rc), gs, cs([rc], last: .object(["constructor": .int(1)]))))
        for bad: JSONValue in [.null, .string("2"), .double(2.5), .bool(false)] {
            mustFail("last-not-int-\(bad)", F.verify(ps(rc), gs, cs([rc], last: .object(["trip_spend": bad]))), ["accumulators"])
        }
        mustFail("keys-not-list", F.verify(ps(rc), gs, cs([rc], keys: .object([:]))), ["accumulators"])
        mustFail("receipts-not-list", F.verify(ps(rc), gs, F.ctx(["session": .object(["root": S, "grants": .array([])]),
                                                                  "acc": .object(["receipts": .object([:]), "sequencer_keys": .array([F.keySet(keys: [F.keyEntry()])])])])),
                 ["accumulators"])
        // a suite the dispatch does not implement fails closed with unsupported_suite
        let unk = F.keySet(keys: [F.keyEntry()])
        let unkSet = F.with(unk, ["alg": .string("no-such-suite"), "pq_pk": .string("AA")])
        let vu = F.verify(ps(rc), gs, cs([rc], keys: .array([unkSet])))
        mustFail("unsupported-key-set", vu, ["accumulators"], why: "unsupported_suite")
    }

    func testReceiptAndKeySetFreshness() {
        let RS = F.root(["accumulators": .array([Self.SEQ])])
        let gs = F.mint(seq: 0, map: F.MAP0, salt: "salt0", root: RS.R)
        let rsv = IntentAcc.reservationDigest(F.body(gs, map: F.MAP0, salt: "salt0"))!
        func ps(_ rc: JSONValue) -> JSONValue {
            F.build(gs, is: F.is0(["root": .string(RS.R), "acc": .array([.object(["id": .string("trip_spend"), "post": .int(48_900), "receipt": .string(IntentAcc.receiptDigest(rc)!)])])]))
        }
        func run(_ rc: JSONValue, keys: [JSONValue] = [F.keySet(keys: [F.keyEntry()])], versions: JObject? = nil, policyAcc: JObject? = nil) -> PCA.Verdict {
            var a: JObject = ["receipts": .array([rc]), "monitors": .object([:]), "sequencer_keys": .array(keys)]
            if let v = versions { a["keyset_versions"] = .object(v) }
            var o: JObject = ["session": .object(["root": RS.S, "grants": .array([])]), "acc": .object(a)]
            if let pa = policyAcc { o["policy"] = .object(["acc": .object(pa)]) }
            return F.verify(ps(rc), gs, F.ctx(o))
        }
        func rc(issued: Int64 = F.NOW - 1_000, expires: Int64? = nil) -> JSONValue {
            F.receipt(["pcactn_digest": .string(rsv), "issued_at": .int(issued), "expires_at": .int(expires ?? max(issued + 60_000, F.NOW))])
        }
        mustAllow("baseline", run(rc()))
        // lifetime: expires_at - issued_at <= 15 min, expires_at >= issued_at
        XCTAssertNil(IntentAcc.receiptShapeError(rc(issued: F.NOW - 1_000, expires: F.NOW - 1_000 + 900_000)))
        XCTAssertNotNil(IntentAcc.receiptShapeError(rc(issued: F.NOW - 1_000, expires: F.NOW - 1_000 + 900_001)))
        XCTAssertNotNil(IntentAcc.receiptShapeError(rc(issued: F.NOW, expires: F.NOW - 1)))
        // receipt age: default 900 s, policy max_receipt_age_s
        mustAllow("age==900s", run(rc(issued: F.NOW - 900_000, expires: F.NOW), keys: [F.keySet(keys: [F.keyEntry()], issued: F.NOW - 1_000)]))
        mustFail("age>900s", run(rc(issued: F.NOW - 900_001, expires: F.NOW + 1 - 1)), ["accumulators"])
        mustAllow("policy-age-edge", run(rc(issued: F.NOW - 10_000), policyAcc: ["max_receipt_age_s": .int(10)]))
        mustFail("policy-age-over", run(rc(issued: F.NOW - 10_001), policyAcc: ["max_receipt_age_s": .int(10)]), ["accumulators"])
        // key-set age: default 1 h, policy max_keyset_age_s; at most 60 s in the future
        mustAllow("set-age==1h", run(rc(), keys: [F.keySet(keys: [F.keyEntry()], issued: F.NOW - 3_600_000)]))
        mustFail("set-age>1h", run(rc(), keys: [F.keySet(keys: [F.keyEntry()], issued: F.NOW - 3_600_001)]), ["accumulators"])
        mustAllow("set-future==skew", run(rc(), keys: [F.keySet(keys: [F.keyEntry()], issued: F.NOW + 60_000)]))
        mustFail("set-future>skew", run(rc(), keys: [F.keySet(keys: [F.keyEntry()], issued: F.NOW + 60_001)]), ["accumulators"])
        mustFail("policy-set-age", run(rc(), keys: [F.keySet(keys: [F.keyEntry()], issued: F.NOW - 5_000)], policyAcc: ["max_keyset_age_s": .int(4)]), ["accumulators"])
        // key-set version: required >= 1, and >= the tracked version for the root
        XCTAssertNotNil(IntentAcc.keySetShapeError(F.keySet(keys: [F.keyEntry()], version: 0)))
        XCTAssertNotNil(IntentAcc.keySetShapeError(F.without(F.keySet(keys: [F.keyEntry()]), ["version"])))
        // the tracked key set {version, digest}: rollback and equivocation SKIP a set (another set can still verify)
        let root = F.pub(F.seqRoot)
        let ks2 = F.keySet(keys: [F.keyEntry()], version: 2)
        let ks2other = F.keySet(keys: [F.keyEntry()], issued: F.NOW - 2_000, version: 2)
        let ks3 = F.keySet(keys: [F.keyEntry()], version: 3)
        func tracked(_ v: Int64, _ ks: JSONValue) -> JObject { [JKey(root): .object(["version": .int(v), "digest": .string(IntentAcc.keySetDigest(ks)!)])] }
        mustAllow("same-version-same-digest", run(rc(), keys: [ks2], versions: tracked(2, ks2)))
        mustFail("equivocation", run(rc(), keys: [ks2other], versions: tracked(2, ks2)), ["accumulators"])
        mustFail("rollback", run(rc(), keys: [ks2], versions: tracked(3, ks3)), ["accumulators"])
        mustAllow("newer-version", run(rc(), keys: [ks3], versions: tracked(2, ks2)))
        mustAllow("skip-then-verify", run(rc(), keys: [ks2other, ks2], versions: tracked(2, ks2)))
        mustAllow("rollback-skipped-newer-kept", run(rc(), keys: [ks2, ks3], versions: tracked(3, ks3)))
        mustAllow("tracked-other-root", run(rc(), versions: [JKey(F.pub(F.stranger)): .object(["version": .int(9), "digest": .string(F.digest("x"))])]))
        let d2 = IntentAcc.keySetDigest(ks2)!
        for (n, bad) in [("bare-number", JSONValue.int(2)), ("null", .null), ("no-digest", .object(["version": .int(2)])),
                         ("version-0", .object(["version": .int(0), "digest": .string(d2)])), ("version-string", .object(["version": .string("2"), "digest": .string(d2)])),
                         ("bad-digest", .object(["version": .int(2), "digest": .string("x")])), ("extra", .object(["version": .int(2), "digest": .string(d2), "x": .int(1)]))] {
            mustFail("tracked-\(n)", run(rc(), keys: [ks2], versions: [JKey(root): bad]), ["accumulators"], why: "keyset_versions")
        }
        XCTAssertNotEqual(IntentAcc.keySetDigest(ks2), IntentAcc.keySetDigest(ks2other))
        // a retired key stops verifying once retired: not_after >= now - 60 s
        let old = rc(issued: F.NOW - 70_000, expires: F.NOW + 60_000)
        mustAllow("retired-at-skew", run(old, keys: [F.keySet(keys: [F.keyEntry(notAfter: F.NOW - 60_000)])]))
        mustFail("retired-before-skew", run(old, keys: [F.keySet(keys: [F.keyEntry(notAfter: F.NOW - 60_001)])]), ["accumulators"])
        // the policy acc member is closed and typed
        for bad: JObject in [["max_receipt_age_s": .null], ["max_keyset_age_s": .double(1.5)], ["other": .int(1)]] {
            mustFail("policy-acc-\(bad)", run(rc(), policyAcc: bad), ["schema", "intent_session", "accumulators"], why: "malformed v2 context")
        }
    }

    // ---- rule 19: committed map ---------------------------------------------------------------------------------------

    func testCommittedMap() {
        let cm = F.committedMap()
        let R = F.root(["layers": .object(["task": .object(["map_digest": .string(cm.commit)])])])
        let g = F.mint(seq: 0, map: cm.commit, salt: "salt0", root: R.R, mapForm: "commit")
        let p = F.build(g, map: cm.commit, is: F.is0(["root": .string(R.R), "map_form": .string("commit")]))
        func ctx(_ over: JObject = [:], disclosure: JSONValue? = cm.disclosure(flat: 0)) -> JSONValue {
            var o: JObject = ["session": .object(["root": R.S, "grants": .array([])])]
            if let d = disclosure { o["map"] = .object(["disclosure": d]) }
            for (k, v) in over { o[k] = v }
            return F.ctx(o)
        }
        let r = Self.V2 + ["map"]
        mustAllow("committed", F.verify(p, g, ctx()), reported: r)
        // the v2c goal: a grant minted over the plain-digest goal never opens under the commit form (and vice versa)
        let gPlain = F.mint(seq: 0, map: cm.commit, salt: "salt0", root: R.R)
        mustFail("v2-goal-under-commit", F.verify(F.build(gPlain, map: cm.commit, is: F.is0(["root": .string(R.R), "map_form": .string("commit")])), gPlain, ctx()),
                 ["intent"], reported: r)
        mustFail("v2c-goal-without-commit", F.verify(F.build(g, map: cm.commit, is: F.is0(["root": .string(R.R)])), g, ctx()), ["intent"])
        XCTAssertNotEqual(Intent.goalCommit(ref: "", mapDigest: F.MAP0, goalSalt: "s", session: F.SESSION),
                          Intent.goalCommit(ref: "", mapDigest: F.MAP0, goalSalt: "s", session: F.SESSION, mapForm: "commit"))
        // the check: a disclosure is required; ε inclusive; the cell must be the action's and in the grant
        mustFail("no-disclosure", F.verify(p, g, ctx(disclosure: nil)), ["map"], reported: r, why: "no disclosure")
        // map is independent of the earlier checks: an accumulator failure does not suppress it, and its reason follows
        let pBad = F.build(g, map: cm.commit, is: F.is0(["root": .string(R.R), "map_form": .string("commit"), "acc": .array([.object(["id": .string("trip_spend"), "post": .int(1)])])]))
        let vb = F.verify(pBad, g, ctx(disclosure: nil))
        mustFail("acc-and-map", vb, ["accumulators", "map"], reported: r, why: "accumulators: ")
        mustAllow("eps==rr", F.verify(p, g, ctx(["policy": .object(["map": .object(["max_residual_risk_ppm": .int(5_000)])])])), reported: r)
        mustFail("eps<rr", F.verify(p, g, ctx(["policy": .object(["map": .object(["max_residual_risk_ppm": .int(4_999)])])])), ["map"], reported: r, why: "exceeds")
        mustFail("other-cell", F.verify(p, g, ctx(disclosure: cm.disclosure(flat: 3))), ["map"], reported: r, why: "not the action's cell")
        let denied = F.committedMap(granted: [3])
        let Rd = F.root(["layers": .object(["task": .object(["map_digest": .string(denied.commit)])])])
        let gd = F.mint(seq: 0, map: denied.commit, salt: "salt0", root: Rd.R, mapForm: "commit")
        let pd = F.build(gd, map: denied.commit, is: F.is0(["root": .string(Rd.R), "map_form": .string("commit")]))
        mustFail("outside-grant", F.verify(pd, gd, F.ctx(["session": .object(["root": Rd.S, "grants": .array([])]), "map": .object(["disclosure": denied.disclosure(flat: 0)])])),
                 ["map"], reported: r, why: "outside the committed grant")
        mustFail("foreign-commit", F.verify(p, g, ctx(disclosure: denied.disclosure(flat: 0))), ["map"], reported: r, why: "does not open")
        // the policy requires a committed map: reported even without the member, and failing
        mustFail("require-no-member", F.verify(F.build(F.G0, is: nil), F.G0, F.ctx(["policy": .object(["map": .object(["require": .bool(true)])])])), ["intent", "map"],
                 reported: ["map"], why: "intent: ")
        mustFail("require-plain-form", F.verify(F.P0, F.G0, F.ctx(["policy": .object(["map": .object(["require": .bool(true)])])])), ["map"], reported: r,
                 why: "requires a committed map")
        mustAllow("require-false", F.verify(F.P0, F.G0, F.ctx(["policy": .object(["map": .object(["require": .bool(false)])])])))
        // the map member and policy are closed and typed; a malformed context fails map too when the PCActn commits
        for bad: JObject in [["map": .null], ["map": .object(["other": .int(1)])], ["policy": .object(["map": .object(["require": .null])])],
                             ["policy": .object(["map": .object(["max_residual_risk_ppm": .int(-1)])])], ["policy": .object(["map": .object(["x": .bool(true)])])]] {
            mustFail("ctx-\(bad)", F.verify(p, g, ctx(bad)), ["schema", "intent_session", "accumulators", "map"], reported: r, why: "malformed v2 context")
        }
        // wire: the only map form is "commit"
        for v: JSONValue in [.string("plain"), .null, .bool(true)] { mustWire("map_form-\(v)", F.build(F.G0, is: F.is0(["map_form": v]))) }
        notWire("map_form-commit", F.build(F.G0, is: F.is0(["map_form": .string("commit")])))
    }

    func testMapDecisionAndShapes() {
        let cm = F.committedMap()
        let action: JSONValue = .object(["verb": .string("air.book"), "resource": .string("skyair.example/bookings"), "params_digest": .string(F.hash(.object(["total": .int(38_900)])))])
        func run(_ over: JObject = [:], params: JSONValue? = .object(["total": .int(38_900)]), disclosure: JSONValue? = nil, flat: Int = 0) -> (Bool, [Int64]) {
            var i: JObject = ["map_commit": .string(cm.commit), "action": action, "disclosure": disclosure ?? cm.disclosure(flat: flat)]
            if let p = params { i["params"] = p }
            for (k, v) in over { i[k] = v }
            let r = PCA.intentMapPrimitive(.object(i))
            return (r.ok, r.cell)
        }
        XCTAssertTrue(run() == (true, [0, 0]))
        XCTAssertEqual(PCA.intentMapCommitPrimitive(.object(["leaves": .array(cm.leaves.enumerated().map { JSONValue.object(["kind": .string($0.element.0),
            "salt": .string(Base64URLStrict.encode(cm.salt($0.offset))), "leaf": $0.element.1]) })])), cm.commit)
        // the cell of ω: numeric cut cells (the cut itself is a cell), exact beats prefix beats other
        func cellFor(_ total: Int64, _ resource: String) -> [Int64]? {
            IntentMap.cellOf(cm.header.asObject!, resource: .string(resource), params: .object(["total": .int(total)]))?.cell
        }
        XCTAssertEqual(cellFor(39_999, "skyair.example/bookings"), [0, 0])
        XCTAssertEqual(cellFor(40_000, "skyair.example/x"), [1, 1])
        XCTAssertEqual(cellFor(40_001, "other.example"), [2, 2])
        XCTAssertEqual(cellFor(0, "skyair.example/"), [0, 1])
        XCTAssertEqual(cellFor(100_000, "skyair.example/bookings"), [2, 0])
        XCTAssertNil(cellFor(100_001, "skyair.example/bookings"))
        XCTAssertNil(cellFor(-1, "skyair.example/bookings"))
        XCTAssertNil(IntentMap.cellOf(cm.header.asObject!, resource: .string("r"), params: .object(["total": .string("1")])))
        XCTAssertNil(IntentMap.cellOf(cm.header.asObject!, resource: .string("r"), params: .object(["total": .double(1.5)])))
        XCTAssertNil(IntentMap.cellOf(cm.header.asObject!, resource: .int(1), params: .object(["total": .int(1)])))
        XCTAssertNil(IntentMap.cellOf(cm.header.asObject!, resource: .string("r"), params: .object([:])))
        // the decision: params digest, layout, openings, metrics position
        XCTAssertFalse(run(params: .object(["total": .int(1)])).0)
        XCTAssertFalse(run(params: .null).0)
        XCTAssertFalse(run(["map_commit": .string(F.digest("x"))]).0)
        var d = cm.disclosure(flat: 0).asObject!
        var cellE = d["cell"]!.asObject!
        cellE["salt"] = .string(F.digest("wrong-salt"))
        d["cell"] = .object(cellE)
        XCTAssertFalse(run(disclosure: .object(d)).0, "an altered salt does not open")
        d = cm.disclosure(flat: 0).asObject!
        d["metrics"] = cm.entry(Int(cm.size) - 1)
        XCTAssertFalse(run(disclosure: .object(d)).0, "kind confusion: the learner leaf is not metrics")
        d = cm.disclosure(flat: 0).asObject!
        d["size"] = .int(cm.size + 1)
        XCTAssertFalse(run(disclosure: .object(d)).0)
        XCTAssertTrue(run(["x": .int(1)]).0, "unknown primitive input members are not part of the decision")
        // closed and typed disclosure / leaves
        XCTAssertNotNil(IntentMap.disclosureError(F.with(cm.disclosure(flat: 0), ["extra": .int(1)])))
        XCTAssertNotNil(IntentMap.disclosureError(F.with(cm.disclosure(flat: 0), ["size": .int(3)])))
        XCTAssertNotNil(IntentMap.headerError(F.with(cm.header, ["cells": .int(8)])), "cells must be the product of the dimensions' cell counts")
        XCTAssertNotNil(IntentMap.headerError(F.with(cm.header, ["dims": .array([.object(["kind": .string("num"), "path": .string("action.params.t"), "lo": .int(0), "hi": .int(9),
                                                                                         "cuts": .array([.int(5), .int(5)])])])])), "cuts strictly increasing")
        XCTAssertNotNil(IntentMap.headerError(F.with(cm.header, ["dims": .array([.object(["kind": .string("cat"), "path": .string("action.resource"),
                                                                                         "values": .array([.object(["kind": .string("exact"), "value": .string("a")])])])])])), "other is required and last")
        XCTAssertNotNil(IntentMap.cellError(F.with(cm.cells[0], ["in_grant": .int(1)])))
        XCTAssertNotNil(IntentMap.cellError(F.with(cm.cells[0], ["p_ppm": .int(1_000_001)])))
        XCTAssertNotNil(IntentMap.metricsError(F.with(cm.metrics, ["log2_vs_mbits": .null])))
        XCTAssertNil(IntentMap.metricsError(F.with(cm.metrics, ["log2_vs_mbits": .int(3)])))
        // RFC 9162 root from a path: the path length must match (index, size)
        let hs = cm.hashes
        let path = cm.path(5).compactMap { $0.asString.flatMap { Base64URLStrict.decode($0, length: 32) } }
        XCTAssertEqual(IntentMap.rootFromPath(5, cm.size, hs[5], path), IntentMap.treeRoot(hs[...]))
        XCTAssertNil(IntentMap.rootFromPath(5, cm.size, hs[5], path + [hs[0]]))
        XCTAssertNil(IntentMap.rootFromPath(5, cm.size, hs[5], Array(path.dropLast())))
        XCTAssertNil(IntentMap.rootFromPath(cm.size, cm.size, hs[5], path))
        XCTAssertEqual(IntentMap.u64be(258), [0, 0, 0, 0, 0, 0, 1, 2])
    }

    // ---- layers ----------------------------------------------------------------------------------------------------

    func testLayers() {
        func lay(_ o: JObject) -> JSONValue { F.ctx(["layers": .object(o)]) }
        func pred(_ where_: [JSONValue], resource: JSONValue? = nil) -> JSONValue {
            var p: JObject = ["verb": .string("air.book"), "where": .array(where_)]
            if let r = resource { p["resource"] = r }
            return .object(["predicates": .array([.object(p)])])
        }
        let canonEq = pred([.object(["field": .string("env.canon.add_ons"), "op": .string("eq"), "value": .string("[\"none\"]")])])
        let r = Self.V2 + ["layers"]
        mustAllow("site-canon", F.verify(F.P0, F.G0, lay(["site": canonEq])), reported: r)
        // a malformed layers context (null, a null / non-object ceiling, a ceiling without a predicate list) fails every
        // reportable v2 check; layers itself is then not reported
        for (n, c) in [("null-layers", F.ctx(["layers": .null])), ("null-ceiling", lay(["org": .null])), ("no-predicates", lay(["site": .object([:])])),
                       ("number-layer", lay(["site": .int(5)])), ("unknown-ceiling", lay(["task": canonEq]))] {
            mustFail(n, F.verify(F.P0, F.G0, c), ["schema", "intent_session", "accumulators"], why: "malformed v2 context")
        }
        let lte = { (n: Int64) in pred([.object(["field": .string("action.params.total"), "op": .string("lte"), "value": .int(n)])]) }
        mustAllow("lte-edge", F.verify(F.P0, F.G0, lay(["org": lte(38_900)])), reported: r)
        mustFail("org", F.verify(F.P0, F.G0, lay(["org": lte(38_899)])), ["layers"], reported: r, why: "org ceiling")
        mustFail("org-first", F.verify(F.P0, F.G0, lay(["org": lte(1), "site": lte(1), "std": lte(1)])), ["layers"], reported: r, why: "org ceiling")
        mustFail("site", F.verify(F.P0, F.G0, lay(["org": lte(38_900), "site": lte(1)])), ["layers"], reported: r, why: "site ceiling")
        mustFail("std", F.verify(F.P0, F.G0, lay(["org": lte(38_900), "std": lte(1)])), ["layers"], reported: r, why: "std ceiling")
        mustFail("empty-predicates", F.verify(F.P0, F.G0, lay(["site": .object(["predicates": .array([])])])), ["layers"], reported: r)
        // not reported without the member
        mustFail("no-member", F.verify(F.build(F.G0, is: nil), F.G0, lay(["org": lte(1)])), ["intent"], reported: [])
        // canon only from a passing schema: a failing schema leaves env.canon empty
        var bad = F.PARAMS.asObject!
        bad["total"] = .int(1)
        mustFail("canon-needs-schema", F.verify(F.P0, F.G0, F.ctx(["params": .object(bad), "layers": .object(["site": canonEq])])), ["schema", "layers", "accumulators"], reported: r)
        // resource / verb matchers and the regex subset
        mustAllow("re", F.verify(F.P0, F.G0, lay(["site": pred([], resource: .string("re:skyair\\.example/book.*"))])), reported: r)
        mustFail("re-nested-refused", F.verify(F.P0, F.G0, lay(["site": pred([], resource: .string("re:(s+)+.*"))])), ["layers"], reported: r)
        mustAllow("prefix-star", F.verify(F.P0, F.G0, lay(["site": pred([], resource: .string("skyair.example/*"))])), reported: r)
        mustFail("prefix-star-miss", F.verify(F.P0, F.G0, lay(["site": pred([], resource: .string("skyair.example/x*"))])), ["layers"], reported: r)
        let other: JSONValue = .object(["predicates": .array([.object(["verb": .string("air.search")])])])
        mustFail("verb-miss", F.verify(F.P0, F.G0, lay(["site": other])), ["layers"], reported: r)
        mustAllow("verb-star", F.verify(F.P0, F.G0, lay(["site": .object(["predicates": .array([.object(["verb": .array([.string("x"), .string("*")])])])])])), reported: r)
    }

    func testPredicateEvaluator() {
        let ctx: JSONValue = .object(["action": .object(["verb": .string("v"), "resource": .string("r/1"),
                                                         "params": .object(["n": .int(5), "s": .string("abc"), "arr": .array([.int(1), .int(2)]),
                                                                            "who": .string("u1"), "tagged": .object(["type": .string("doc::pdf")])])]),
                                      "env": .object(["g": .object(["u1": .string("team"), "team": .array([.string("org")])])])])
        func leaf(_ o: JObject) -> Predicates.Tri { Predicates.conditionTri(.object(o), ctx, SafeRegex.Budget()) }
        XCTAssertEqual(leaf(["field": .string("action.params.n"), "op": .string("gte"), "value": .int(5)]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.n"), "op": .string("gt"), "value": .double(5)]), .f)
        XCTAssertEqual(leaf(["field": .string("action.params.n"), "op": .string("lt"), "value": .string("6")]), .u)
        XCTAssertEqual(leaf(["field": .string("action.params.s"), "op": .string("lt"), "value": .string("abd")]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.x"), "op": .string("exists"), "value": .bool(false)]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.x"), "op": .string("eq"), "value": .int(1)]), .u)
        XCTAssertEqual(leaf(["field": .string("action.params.arr.1"), "op": .string("eq"), "value": .double(2)]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.arr.01"), "op": .string("exists")]), .f)
        XCTAssertEqual(leaf(["field": .string("action.params.n"), "op": .string("in"), "value": .array([.int(4), .int(5)])]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.n"), "op": .string("nin"), "value": .int(5)]), .u)
        XCTAssertEqual(leaf(["field": .string("action.params.s"), "op": .string("like"), "value": .string("a*c")]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.s"), "op": .string("like"), "value": .string("a?")]), .f)
        XCTAssertEqual(leaf(["field": .string("action.params.s"), "op": .string("like"), "value": .string("abc\\")]), .u)
        XCTAssertEqual(leaf(["field": .string("action.params.s"), "op": .string("matches"), "value": .string("a[b-c]+")]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.s"), "op": .string("matches"), "value": .string("(a|b)+")]), .u)
        XCTAssertEqual(leaf(["field": .string("action.params.s"), "op": .string("prefix"), "value": .string("ab")]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.tagged"), "op": .string("is_a"), "value": .string("doc")]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.who"), "op": .string("member_of"), "value": .string("org"), "collection": .string("env.g")]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.who"), "op": .string("member_of"), "value": .string("x"), "collection": .string("env.g")]), .f)
        XCTAssertEqual(leaf(["field": .string("action.params.n"), "op": .string("eq"), "ref": .int(1)]), .u)
        XCTAssertEqual(leaf(["field": .string("action.params.n"), "op": .string("eq"), "ref": .string("action.params.n")]), .t)
        XCTAssertEqual(leaf(["field": .string("action.params.constructor"), "op": .string("exists")]), .f)
        let notU: JSONValue = .object(["not": .object(["field": .string("action.params.x"), "op": .string("eq"), "value": .int(1)])])
        XCTAssertEqual(Predicates.conditionTri(notU, ctx, SafeRegex.Budget()), .u)
        XCTAssertEqual(Predicates.conditionTri(.object(["any_of": .array([])]), ctx, SafeRegex.Budget()), .u)
        XCTAssertEqual(Predicates.conditionTri(.object(["all_of": .array([.object(["field": .string("action.params.n"), "op": .string("eq"), "value": .int(5)])]), "not": .null]), ctx,
                                               SafeRegex.Budget()), .t)
        // the per-document regex budget: 64 evaluations, the 65th is refused
        let budget = SafeRegex.Budget()
        for _ in 0..<64 { XCTAssertEqual(SafeRegex.fullMatchTri("a", "a", budget), true) }
        XCTAssertNil(SafeRegex.fullMatchTri("a", "a", budget))
        XCTAssertNil(SafeRegex.fullMatchTri("a", "a", budget), "the scope stays poisoned")
        // the safe-source guard
        for (src, ok) in [("a{64}", true), ("a{65}", false), ("a{2,64}", true), ("(ab)+", true), ("(a+)+", false), ("(a|b)+", false), ("\\1", false), ("(?=a)", false),
                          ("a*b*", true), ("a*b*c*", false), ("a?", true), ("[^]", true), ("[]a", true), ("{1}", false), ("a{1", false), ("\\b", false)] {
            XCTAssertEqual(SafeRegex.isSafeSource(Array(src.utf16)), ok, src)
        }
        XCTAssertEqual(SafeRegex.run(SafeRegex.compile(Array("a.c".utf16))!, Array("a\nc".utf16)), false)
        XCTAssertEqual(SafeRegex.run(SafeRegex.compile(Array("\\d\\w\\s".utf16))!, Array("1_ ".utf16)), true)
    }

    // ---- suites -----------------------------------------------------------------------------------------------------

    func testUnsupportedSuiteFailsClosed() {
        // every v2 signature routes through the suite dispatch: an alg it does not resolve is `unsupported_suite`
        var rb = F.rootBody()
        rb["alg"] = .string("no-such-suite")
        rb["pq_pk"] = .string("AA")
        let root = F.signRoot(rb)
        XCTAssertTrue(IntentSession.verifyRoot(root).reason.contains(IV.UNSUPPORTED_SUITE), IntentSession.verifyRoot(root).reason)
        let keys: JSONValue = .array([.object(["kid": .string("skyair-2026"), "alg": .string("no-such-suite"), "pk": .string(F.pub(F.site)), "pq_pk": .string("AA")])])
        let schema = F.with(F.SCHEMA, ["sig": F.with(F.SCHEMA.get("sig")!, ["alg": .string("no-such-suite")])])
        XCTAssertTrue(ActionSchema.verify(schema, keys: keys).reason.contains(IV.UNSUPPORTED_SUITE))
        let ep = F.with(F.epoch([], issued: F.NOW - 1_000), ["alg": .string("no-such-suite"), "pq_pk": .string("AA")])
        let r = IntentRevocation.check(.object(["epoch": ep, "revoked": .array([])]), session: F.SESSION, authority: F.pub(F.revAuthority), ids: [],
                                       now: Double(F.NOW), maxAgeMs: 60_000)
        XCTAssertTrue(r.1.contains(IV.UNSUPPORTED_SUITE), r.1)
        // a non-string alg is malformed, never unsupported
        XCTAssertFalse(ActionSchema.verify(F.with(F.SCHEMA, ["sig": F.with(F.SCHEMA.get("sig")!, ["alg": .int(1)])]), keys: F.KEYS).reason.contains(IV.UNSUPPORTED_SUITE))
        // the ed25519 path is the dispatch's too
        XCTAssertEqual(IV.verifyPinned(alg: nil, identity: F.pub(F.site), artifactPqPk: nil, msg: [1], sig: .string("x"), pqSig: nil, pin: nil), .invalid)
    }

    // ---- absent vs JSON null: an absent optional member is empty / default, a null one is malformed -----------------

    func testNullIsMalformedAbsentIsDefault() {
        let plain = F.build(F.G0, is: nil)
        let all = ["schema", "intent_session", "accumulators"]
        // a malformed TOP-LEVEL context member fails every reportable v2 check (schema, intent_session, and accumulators
        // with the member), even with no policy active; the layers and W-B checks are then not reported
        for (n, c) in [("policy-null", ["policy": JSONValue.null]), ("policy.session-null", ["policy": .object(["session": .null])]),
                       ("policy.schema-null", ["policy": .object(["schema": .null])]), ("params-null", ["params": .null]), ("schema-null", ["schema": .null]),
                       ("session-null", ["session": .null]), ("acc-null", ["acc": .null]), ("layers-null", ["layers": .null]),
                       ("layers.org-null", ["layers": .object(["org": .null])]), ("wb-null", ["wb": .null]), ("wb.artifacts-null", ["wb": .object(["artifacts": .null])]),
                       ("wb.policy-null", ["wb": .object(["policy": .null])]), ("wb.artifacts.facts-null", ["wb": .object(["artifacts": .object(["facts": .null])])]),
                       ("wb.artifacts.offer_set-null", ["wb": .object(["artifacts": .object(["offer_set": .null])])]),
                       ("wb.policy.world-null", ["wb": .object(["policy": .object(["world": .null])])]),
                       ("wb.policy.provenance-null", ["wb": .object(["policy": .object(["provenance": .null])])]),
                       ("wb.policy.classifiers-null", ["wb": .object(["policy": .object(["classifiers": .null])])])] as [(String, JObject)] {
            mustFail(n, F.verify(F.P0, F.G0, F.ctx(c)), all, why: "malformed v2 context")
            mustFail(n + "-no-member", F.verify(plain, F.G0, F.ctx(c)), ["intent", "schema", "intent_session"], reported: ["schema", "intent_session"])
        }
        mustFail("policy-absent", F.verify(plain, F.G0, F.ctx()), ["intent"], reported: [])
        mustAllow("wb-empty", F.verify(F.P0, F.G0, F.ctx(["wb": .object([:])])))
        mustAllow("layers-empty", F.verify(F.P0, F.G0, F.ctx(["layers": .object([:])])), reported: Self.V2 + ["layers"])
        // only `true` activates; a null flag leaves the check inactive
        // the v2 policy is closed and typed; explicit false stays inactive
        for (n, pol) in [("require-null", JSONValue.object(["session": .object(["require": .null])])), ("require-string", .object(["session": .object(["require": .string("true")])])),
                         ("closed_world-null", .object(["schema": .object(["closed_world": .null])])), ("closed_world-1", .object(["schema": .object(["closed_world": .int(1)])])),
                         ("max_age-null", .object(["session": .object(["max_revocation_age_s": .null])])), ("max_age-neg", .object(["session": .object(["max_revocation_age_s": .int(-1)])])),
                         ("max_age-frac", .object(["session": .object(["max_revocation_age_s": .double(1.5)])])),
                         ("session-unknown", .object(["session": .object(["other": .bool(true)])])), ("schema-unknown", .object(["schema": .object(["x": .bool(false)])])),
                         ("policy-unknown", .object(["extra": .object([:])]))] {
            mustFail(n, F.verify(plain, F.G0, F.ctx(["policy": pol])), ["intent", "schema", "intent_session"], reported: ["schema", "intent_session"])
            mustFail(n + "-member", F.verify(F.P0, F.G0, F.ctx(["policy": pol])), all, why: "malformed v2 context")
        }
        mustFail("flags-false", F.verify(plain, F.G0, F.ctx(["policy": .object(["session": .object(["require": .bool(false)]), "schema": .object(["closed_world": .bool(false)])])])),
                 ["intent"], reported: [])
        // a layer is exactly {predicates}: an extra member passes the context check and fails `layers` as that ceiling
        mustFail("layer-extra", F.verify(F.P0, F.G0, F.ctx(["layers": .object(["site": .object(["predicates": .array([]), "note": .string("x")])])])), ["layers"],
                 reported: Self.V2 + ["layers"], why: "site ceiling is malformed")
        mustFail("layers-unknown", F.verify(F.P0, F.G0, F.ctx(["layers": .object(["task": .object(["predicates": .array([])])])])), all, why: "malformed v2 context")
        // the W-B artifacts / policy are closed: an unknown member fails `facts`
        for (n, c) in [("artifacts-unknown", ["wb": JSONValue.object(["artifacts": .object(["x": .array([])])])]),
                       ("wb-policy-unknown", ["wb": .object(["policy": .object(["x": .object([:])])])])] as [(String, JObject)] {
            mustFail(n, F.verify(F.P0, F.G0, F.ctx(c)), ["facts"], reported: Self.V2 + ["facts"], why: "W-B context is malformed")
        }
        // members inside an object: their own check fails
        mustAllow("grants-absent", F.verify(F.P0, F.G0, F.ctx(["session": .object(["root": F.BASE.S])])))
        mustFail("grants-null", F.verify(F.P0, F.G0, F.ctx(["session": .object(["root": F.BASE.S, "grants": .null])])), ["intent_session"])
        mustFail("revocation-null", F.verify(F.P0, F.G0, F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([]), "revocation": .null])])), ["intent_session"])
        mustFail("root-null", F.verify(F.P0, F.G0, F.ctx(["session": .object(["root": .null, "grants": .array([])])])), ["intent_session", "accumulators"])
        mustFail("docs-null", F.verify(F.P0, F.G0, F.ctx(["schema": .object(["docs": .null, "keys": F.KEYS])])), ["schema", "accumulators"])
        mustFail("keys-null", F.verify(F.P0, F.G0, F.ctx(["schema": .object(["docs": .array([F.SCHEMA]), "keys": .null])])), ["schema", "accumulators"])
        mustFail("keys-absent", F.verify(F.P0, F.G0, F.ctx(["schema": .object(["docs": .array([F.SCHEMA])])])), ["schema", "accumulators"])
        let st: JObject = ["trip_spend": .object(["sum": .int(0)])]
        mustFail("acc.state-null", F.verify(F.P0, F.G0, F.ctx(["acc": .object(["state": .null])])), ["accumulators"])
        mustAllow("acc.monitors-absent", F.verify(F.P0, F.G0, F.ctx(["acc": .object(["state": .object(st)])])))
        for k in ["monitors", "last_seq", "receipts", "sequencer_keys"] {
            mustFail("acc.\(k)-null", F.verify(F.P0, F.G0, F.ctx(["acc": .object(["state": .object(st), JKey(k): .null])])), ["accumulators"])
        }
        mustFail("last_seq-entry-null", F.verify(F.P0, F.G0, F.ctx(["acc": .object(["state": .object(st), "last_seq": .object(["x": .null])])])), ["accumulators"])
        mustFail("last_seq-entry-string", F.verify(F.P0, F.G0, F.ctx(["acc": .object(["state": .object(st), "last_seq": .object(["x": .string("1")])])])), ["accumulators"])
        mustAllow("last_seq-entry-int", F.verify(F.P0, F.G0, F.ctx(["acc": .object(["state": .object(st), "last_seq": .object(["x": .int(1)])])])))
        // held grants: capability objects with string id / issuer and an implemented suite
        let p1 = F.build(F.D1, map: F.MAP1, salt: "salt1", is: F.is0(["seq": .int(1)].merging(Self.claim(77_800)) { $1 }))
        for (n, g) in [("grant-null", JSONValue.null), ("grant-no-id", F.without(F.G0, ["id"])), ("grant-unsupported", F.with(F.G0, ["alg": .string("no-such-suite")]))] {
            let v = F.verify(p1, F.D1, F.ctx(["session": .object(["root": F.BASE.S, "grants": .array([g])]), "acc": Self.acc(38_900)]))
            mustFail(n, v, ["intent_session"])
            if n == "grant-unsupported" { XCTAssertTrue(v.reason.contains("unsupported_suite"), v.reason) }
        }
    }

    func testClockAndStrictRevocationShapes() {
        // the clock must be a safe integer, else every v2 check fails (the core validity check is independent)
        let big = F.verify(F.P0, F.G0, F.ctx(), now: Canonical.MAX_SAFE + 1)
        for c in Self.V2 { XCTAssertEqual(big.checks[c], false, c) }
        // a strictly typed epoch
        let id = IntentRevocation.sessionId(F.SESSION)
        func run(_ patch: JObject) -> Bool {
            let ep = F.with(F.epoch([], issued: F.NOW - 1_000), patch)
            return IntentRevocation.check(.object(["epoch": ep, "revoked": .array([])]), session: F.SESSION, authority: F.pub(F.revAuthority), ids: [id],
                                          now: Double(F.NOW), maxAgeMs: 60_000).0
        }
        XCTAssertTrue(run([:]))
        for (k, v) in [("alg", JSONValue.null), ("pq_pk", .null), ("pq_sig", .null), ("guardian_epoch", .null), ("guardian_epoch", .string("1")),
                       ("epoch", .string("0")), ("set_size", .null), ("issued_at", .double(1.5)), ("not_after", .string("x")), ("instance_id", .int(1))] {
            XCTAssertFalse(run([JKey(k): v]), "\(k)=\(v)")
        }
        XCTAssertTrue(IntentRevocation.epochShapeError(F.with(F.epoch([], issued: 1), ["guardian_epoch": .int(3)])) == nil)
        // a PQ epoch needs the PQ key the session root pins for the authority
        let pq = F.with(F.epoch([], issued: F.NOW - 1_000), ["alg": .string("ml-dsa-65"), "pq_pk": .string("AAAA")])
        XCTAssertFalse(IntentRevocation.check(.object(["epoch": pq, "revoked": .array([])]), session: F.SESSION, authority: F.pub(F.revAuthority), ids: [id],
                                              now: Double(F.NOW), maxAgeMs: 60_000).0)
        // reserved schema parameter names and a null default
        XCTAssertNotNil(ActionSchema.paramDeclError("action.params.constructor", .object(["type": .string("string"), "semantic": .string("s"), "sensitivity": .string("free")]), nil))
        XCTAssertNotNil(ActionSchema.paramDeclError("action.params.x", .object(["type": .string("string"), "semantic": .string("s"), "sensitivity": .string("free"),
                                                                                "default": .null]), nil))
        XCTAssertNil(ActionSchema.paramDeclError("action.params.x", .object(["type": .string("string"), "semantic": .string("s"), "sensitivity": .string("free"),
                                                                             "default": .string("d")]), nil))
        // a schema key pq_pk must be a string when present; keys must be an array
        XCTAssertFalse(ActionSchema.verify(F.SCHEMA, keys: .array([F.with(F.KEYS.asArray![0], ["pq_pk": .null])])).ok)
        XCTAssertFalse(ActionSchema.verify(F.SCHEMA, keys: .null).ok)
    }
}
