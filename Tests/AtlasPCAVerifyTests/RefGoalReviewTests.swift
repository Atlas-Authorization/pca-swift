import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the goal review flow (policy card, semantic diff, signed approval, loader) against the TypeScript reference
/// (@atlasauth/pca-goal review.ts) over the stub compiler kernel of the oracle, plus the end-to-end behaviours the corpus does not reach:
/// a real signature round trip, tampering with every signed field, domain separation, time and pin refusals, caps.
/// A reference throw requires a native refusal (with the same code where the reference carries one).
final class RefGoalReviewTests: XCTestCase {
    static let file = "ref-goal-review.json.gz"
    typealias R = PCAGoalReview

    // ---- the stub kernel of the oracle ----

    struct StubKernel: PCAGoalReviewKernel {
        let mode: String

        func compile(_ goal: JSONValue, _ ont: JSONValue) throws -> JSONValue {
            if mode == "throwcompile" { throw JSError("boom") }
            guard let grants = goal.get("grants")?.asArray else { throw JSError("no grants") }
            if grants.isEmpty { return .object(["ok": .bool(false), "reasons": .array([.string("empty")])]) }
            var gids: [JSONValue] = []
            for g in grants { gids.append(g.get("gid") ?? .null) }
            let pol: JSONValue = .object(["gids": .array(gids), "n": .int(Int64(grants.count))])
            return .object(["ok": .bool(true), "policy": pol])
        }

        func policyDigest(_ policy: JSONValue) throws -> String {
            if mode == "throwdigest" { throw JSError("boom") }
            return Canonical.hashCanonical(.object(["d": .string("stub-policy"), "p": policy]))
        }

        func analyze(_ policy: JSONValue) throws -> [String] {
            let n = IV.int(policy.get("n")) ?? 0
            return n >= 5 ? ["too many"] : []
        }

        func canDecide() -> Bool { mode != "nodecide" }

        func decide(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> String {
            for g in goal.get("grants")?.asArray ?? [] where IV.strictEq(g.get("verb"), act.get("verb")) { return "allow" }
            return "deny"
        }

        func canListNewlyAllowed() -> Bool { mode != "nonewly" }

        func newlyAllowed(_ prev: JSONValue, _ next: JSONValue, _ ont: JSONValue, _ limit: Int64) throws -> JSONValue {
            var w: [JSONValue] = []
            for x in next.get("grants")?.asArray ?? [] {
                var known = false
                for y in prev.get("grants")?.asArray ?? [] where IV.strictEq(y.get("gid"), x.get("gid")) { known = true }
                if known { continue }
                w.append(.object([
                    "verb": x.get("verb") ?? .null, "res": .string("r"), "params": .object([:]), "t": .int(0), "sess": .string("s"),
                    "prin": .string("p"), "org": .string("o"), "agent": .string("a"), "depth": .int(0),
                ]))
            }
            return .object(["witnesses": .array(w), "complete": .bool(true)])
        }
    }

    // ---- decoding of the oracle arguments (the Kotlin replay's m / l / lng) ----

    static func obj(_ v: JSONValue?) -> JSONValue? { v?.isObject == true ? v : nil }
    static func arr(_ v: JSONValue?) -> [JSONValue]? { v?.asArray }

    static func must(_ v: JSONValue?) throws -> JSONValue {
        guard let x = v, x.isObject else { throw JSError("object expected") }
        return x
    }

    /// A number of the case as Int64; a value that is not an exact Int64 becomes Int64.max (so the native refuses it).
    static func lng(_ v: JSONValue?) -> Int64? {
        guard let v = v, v != .null else { return nil }
        guard let d = IV.num(v), d.isFinite, d.rounded(.towardZero) == d, abs(d) < 9.2e18 else { return Int64.max }
        return Int64(d)
    }

    static func code(_ e: Error) -> String? {
        if let r = e as? R.ReviewError { return r.code }
        if let j = e as? JSError { return j.code }
        return nil
    }

    func replay(_ fn: String, expected: Int, _ body: @escaping ([JSONValue]) throws -> JSONValue) throws {
        let d = Base.Diffs()
        let n = try Base.each(Self.file, [fn], seeds: true) { c in
            d.add(c, Base.diff(c, Base.run(Self.code) { try body(c.args) }))
        }
        XCTAssertEqual(n, expected, "\(fn): cases in the corpus")
        d.finish(max(1, n - d.skipped.values.reduce(0, +)))
        print("goal review \(fn): \(n) cases, skipped \(d.skipped.values.reduce(0, +))")
    }

    func testEffectiveLimits() throws {
        try replay("effectiveLimits", expected: 9) { a in R.effectiveLimits(a.first) }
    }

    func testRenderPolicyCard() throws {
        try replay("renderPolicyCard", expected: 121) { a in
            let opts = Self.obj(a.count > 2 ? a[2] : nil)
            return try R.renderPolicyCard(Self.obj(a.first), Self.arr(a.count > 1 ? a[1] : nil), Self.obj(opts?.get("limits")), opts?.get("allowHoles") == JSONValue.bool(true))
        }
    }

    func testCardDigest() throws {
        try replay("cardDigest", expected: 6) { a in .string(try R.cardDigest(try Self.must(a.first))) }
    }

    func testCardToText() throws {
        try replay("cardToText", expected: 6) { a in .string(try R.cardToText(try Self.must(a.first))) }
    }

    func testDiffGoals() throws {
        try replay("diffGoals", expected: 115) { a in
            let op = try Self.must(a[2])
            let km = op.get("kmode")?.asString ?? ""
            let kernel: PCAGoalReviewKernel? = km == "none" ? nil : StubKernel(mode: km)
            return try R.diffGoals(try Self.must(a[0]), try Self.must(a[1]), kernel, Self.obj(op.get("limits")), Self.obj(op.get("ontology")))
        }
    }

    func testDiffToText() throws {
        try replay("diffToText", expected: 20) { a in .string(try R.diffToText(try Self.must(a.first))) }
    }

    func testApproveGoalSeed() throws {
        try replay("approveGoalSeed", expected: 96) { a in
            let op = try Self.must(a[2])
            let o = R.ApproveOptions()
            o.kernel = StubKernel(mode: op.get("kmode")?.asString ?? "")
            o.now = Self.lng(op.get("now"))
            o.ttlMs = Self.lng(op.get("ttlMs"))
            o.limits = Self.obj(op.get("limits"))
            o.base = Self.obj(op.get("base"))
            guard let seed = a[1].asString.flatMap({ Base64URLStrict.decode($0) }) else { throw JSError("seed expected") }
            return try R.approveGoal(try Self.must(a[0]), seed, o)
        }
    }

    func testLoadApprovedGoal() throws {
        try replay("loadApprovedGoal", expected: 77) { a in
            let op = try Self.must(a[2])
            let o = R.LoadOptions()
            o.kernel = StubKernel(mode: op.get("kmode")?.asString ?? "")
            o.reviewers = Self.arr(op.get("reviewers"))
            o.ontologyDigest = op.get("ontology_digest")?.asString
            o.now = Self.lng(op.get("now"))
            o.limits = Self.obj(op.get("limits"))
            // a submission that is not an object is the reference's `malformed_submission`, not a refusal to call
            return R.loadApprovedGoal(a[0], Self.obj(a[1]), o)
        }
    }

    // ---- behaviours beyond the corpus: a real signature, end to end ----

    static let instruction = "do the thing"

    static let goalText = """
    {"v":1,"principal":"user:alice","ontDigest":"pOU65ytGx5JIiNI3oyikvRwXzxPtGgM6qIOVIS0YFRg","nlDigest":"NL","sources":[],
     "grants":[{"gid":"refund-one","verb":"refund","res":{"k":"exact","id":"ch_1"},
       "cond":{"k":"cmp","op":"lte","l":{"k":"param","path":"amount","ty":{"k":"q","u":{"k":"money","ccy":"USD"}}},
               "r":{"k":"lit","v":{"k":"q","q":{"u":{"k":"money","ccy":"USD"},"n":4000}}}}}],
     "prohibits":[{"pid":"no-transfer","target":{"k":"verb","verb":"transfer"},"res":{"k":"any","reason":"blanket"},"cond":{"k":"true"}}],
     "bounds":[],"validity":{"notBefore":0,"notAfter":9007199254740991,"maxIdle":0},
     "deleg":{"maxDepth":0,"narrowOnly":true,"mayTouch":[]},"escalateOn":[],"wildcardAck":[],"holes":[]}
    """

    static let ontologyText = """
    {"verbs":[{"verb":"refund","cls":"irreversible","params":[{"path":"amount","ty":{"k":"q","u":{"k":"money","ccy":"USD"}}}]},
              {"verb":"transfer","cls":"irreversible","params":[]}],"rels":[]}
    """

    static let testsText = """
    [{"id":"t1","act":{"verb":"refund","res":"ch_1","params":{},"t":0,"sess":"s","prin":"user:alice","org":"o","agent":"a","depth":0},
      "hist":{"adms":[],"last":-1,"aggs":{}},"answer":"allow"}]
    """

    func goal(_ edit: (inout JObject) -> Void = { _ in }) throws -> JSONValue {
        var g = K042.parse(Self.goalText).asObject!
        g[JKey("nlDigest")] = .string(try PCAGoalDigests.nlDigest(Self.instruction))
        edit(&g)
        return .object(g)
    }

    func submission(goal g: JSONValue? = nil, tests: Bool = true) throws -> JSONValue {
        var s: JObject = [
            "goal": try g ?? goal(), "ontology": K042.parse(Self.ontologyText), "instruction": .string(Self.instruction),
            "model_set": .array([.string("m-a"), .string("m-b")]),
        ]
        if tests { s["tests"] = K042.parse(Self.testsText) }
        return .object(s)
    }

    static let T0: Int64 = 1_700_000_000_000

    func seed(_ label: String) -> [UInt8] { Canonical.sha256(Array(("atlas-pca-conformance/" + label).utf8)) }

    func approve(_ s: JSONValue, _ sd: [UInt8], mode: String = "full") throws -> JSONValue {
        let o = R.ApproveOptions()
        o.kernel = StubKernel(mode: mode)
        o.now = Self.T0
        return try R.approveGoal(s, sd, o)
    }

    func load(_ s: JSONValue, _ a: JSONValue, _ pins: [JSONValue], now: Int64 = RefGoalReviewTests.T0 + 1000, mode: String = "full") -> JSONValue {
        let o = R.LoadOptions()
        o.kernel = StubKernel(mode: mode)
        o.reviewers = pins
        o.now = now
        return R.loadApprovedGoal(s, a, o)
    }

    func reason(_ r: JSONValue) -> String { r.get("ok") == JSONValue.bool(true) ? "ok" : (r.get("reason")?.asString ?? "?") }

    func testRoundTripLoadsReDerived() throws {
        let sd = seed("goal-review-reviewer")
        let pk = try PCAGoalSign.signerId(sd)
        let s = try submission()
        let a = try approve(s, sd)
        XCTAssertEqual(a.get("reviewer"), .string(pk))
        let r = load(s, a, [.string(pk)])
        XCTAssertEqual(reason(r), "ok")
        let approved = r.get("approved")
        XCTAssertEqual(approved?.get("reviewer"), .string(pk))
        XCTAssertEqual(approved?.get("expires_at"), a.get("expires_at"))
        let ref = approved?.get("ref")
        XCTAssertEqual(ref?.get("goal_digest"), a.get("goal_digest"))
        XCTAssertEqual(ref?.get("policy_digest"), a.get("policy_digest"))
        let gd: String = a.get("goal_digest")?.asString ?? ""
        let pd: String = a.get("policy_digest")?.asString ?? ""
        let want: String = "pca-intent:v3:" + gd + ":" + pd
        XCTAssertEqual(approved?.get("goal_string")?.asString, want)
        // a pin given as {pk} loads too
        XCTAssertEqual(reason(load(s, a, [.object(["pk": .string(pk)])])), "ok")
    }

    func testEverySignedFieldIsTamperEvident() throws {
        let sd = seed("goal-review-reviewer")
        let pk = try PCAGoalSign.signerId(sd)
        let s = try submission()
        let a = try approve(s, sd)
        XCTAssertEqual(Set(R.GOAL_APPROVAL_SIGNED_FIELDS), Set(a.asObject!.keys.map { $0.s }.filter { $0 != "sig" && $0 != "alg" }))
        for f in R.GOAL_APPROVAL_SIGNED_FIELDS {
            var t = a.asObject!
            switch t[JKey(f)] {
            case .string(let x)?: t[JKey(f)] = .string(x + "x")
            case .int(let x)?: t[JKey(f)] = .int(x + 1)
            default: XCTFail("unexpected member kind: \(f)")
            }
            XCTAssertNotEqual(reason(load(s, .object(t), [.string(pk)])), "ok", "tampered \(f) must not load")
        }
        var noSig = a.asObject!
        noSig[JKey("sig")] = .string("AAAA")
        XCTAssertEqual(reason(load(s, .object(noSig), [.string(pk)])), "bad_signature")
    }

    func testSubmissionIsBoundToTheApproval() throws {
        let sd = seed("goal-review-reviewer")
        let pk = try PCAGoalSign.signerId(sd)
        let a = try approve(try submission(), sd)
        // another goal, another instruction, another model set, other tests: each digest is re-derived
        let other = try submission(goal: try goal({ $0[JKey("principal")] = .string("user:bob") }))
        XCTAssertEqual(reason(load(other, a, [.string(pk)])), "goal_digest_mismatch")
        XCTAssertEqual(reason(load(try submission(tests: false), a, [.string(pk)])), "tests_digest_mismatch")
        var ms = try submission().asObject!
        ms[JKey("model_set")] = .array([.string("m-a")])
        XCTAssertEqual(reason(load(.object(ms), a, [.string(pk)])), "model_set_digest_mismatch")
        var ins = try submission().asObject!
        ins[JKey("instruction")] = .string("do another thing")
        XCTAssertEqual(reason(load(.object(ins), a, [.string(pk)])), "instruction_mismatch")
        // a pinned ontology that differs from the goal ontology
        let o = R.LoadOptions()
        o.kernel = StubKernel(mode: "full")
        o.reviewers = [.string(pk)]
        o.now = Self.T0 + 1000
        o.ontologyDigest = "something-else"
        XCTAssertEqual(reason(R.loadApprovedGoal(try submission(), a, o)), "ontology_mismatch")
    }

    func testPinsAndTime() throws {
        let sd = seed("goal-review-reviewer")
        let pk = try PCAGoalSign.signerId(sd)
        let otherPk = try PCAGoalSign.signerId(seed("goal-review-other"))
        let s = try submission()
        let a = try approve(s, sd)
        XCTAssertEqual(reason(load(s, a, [])), "no_reviewers_pinned")
        XCTAssertEqual(reason(load(s, a, [.string(otherPk)])), "reviewer_not_pinned")
        XCTAssertEqual(reason(load(s, a, [.string(pk)], now: Self.T0 - 1)), "not_yet_valid")
        XCTAssertEqual(reason(load(s, a, [.string(pk)], now: Self.T0 + 3_600_000)), "expired")
        XCTAssertEqual(reason(load(s, a, [.string(pk)], now: Self.T0 + 3_599_999)), "ok")
        // an approval signed by an unpinned key never loads, even when it names a pinned reviewer
        let forged = try approve(s, seed("goal-review-other"))
        var named = forged.asObject!
        named[JKey("reviewer")] = .string(pk)
        XCTAssertNotEqual(reason(load(s, .object(named), [.string(pk)])), "ok")
        // the ttl beyond the maximum is refused when signing
        let o = R.ApproveOptions()
        o.kernel = StubKernel(mode: "full")
        o.now = Self.T0
        o.ttlMs = R.MAX_GOAL_APPROVAL_TTL_MS + 1
        XCTAssertThrowsError(try R.approveGoal(s, sd, o))
        o.ttlMs = 0
        XCTAssertThrowsError(try R.approveGoal(s, sd, o))
        // no kernel given: the proved kernel is the default, so review works without injection
        let proved = PCAGoalKernel.provedKernel()
        XCTAssertTrue(proved.canDecide())
        XCTAssertFalse(proved.canListNewlyAllowed())
    }

    func testDomainSeparation() throws {
        let sd = seed("goal-review-reviewer")
        let pk = try PCAGoalSign.signerId(sd)
        let s = try submission()
        let a = try approve(s, sd)
        var body = a.asObject!
        body[JKey("sig")] = nil
        let wrongKind = try PCAGoalSign.signGoalArtifact("goal-test-set", .object(body), sd)
        XCTAssertEqual(reason(load(s, wrongKind, [.string(pk)])), "bad_signature")
    }

    func testRefusalsOfTheFlow() throws {
        let sd = seed("goal-review-reviewer")
        // holes: a draft is not signable
        let withHole = try goal({ $0[JKey("holes")] = .array([K042.parse(#"{"q":"which account?","affects":[]}"#)]) })
        XCTAssertThrowsError(try approve(try submission(goal: withHole), sd))
        // an `any` resource needs an acknowledgement
        let wild = try goal({ $0[JKey("grants")] = K042.parse(#"[{"gid":"w","verb":"refund","res":{"k":"any","reason":"x"},"cond":{"k":"true"}}]"#) })
        XCTAssertThrowsError(try R.renderPolicyCard(wild, nil, nil, false)) { e in XCTAssertEqual((e as? R.ReviewError)?.code, "wildcard_unacknowledged") }
        // a draft renders with its holes when asked to
        XCTAssertNoThrow(try R.renderPolicyCard(withHole, nil, nil, true))
        // examples the compiled policy contradicts, a kernel that cannot decide, a kernel that fails
        let contradicted = K042.parse(Self.testsText.replacingOccurrences(of: "\"allow\"", with: "\"deny\""))
        var sub = try submission().asObject!
        sub[JKey("tests")] = contradicted
        XCTAssertThrowsError(try approve(.object(sub), sd))
        XCTAssertThrowsError(try approve(try submission(), sd, mode: "nodecide"))
        XCTAssertThrowsError(try approve(try submission(), sd, mode: "throwcompile"))
        XCTAssertThrowsError(try approve(try submission(), sd, mode: "throwdigest"))
        // garbage never throws from the loader
        let pk = try PCAGoalSign.signerId(sd)
        for junk: JSONValue in [.null, .string("x"), .array([]), .object([:]), .int(1)] {
            XCTAssertNotEqual(reason(load(junk, junk, [.string(pk)])), "ok")
            XCTAssertNotEqual(reason(load(try submission(), junk, [.string(pk)])), "ok")
        }
        // limits only tighten
        let eff = R.effectiveLimits(K042.parse(#"{"max_grants":1,"max_prohibits":9999,"max_bounds":-1}"#))
        XCTAssertEqual(eff.get("max_grants"), .int(1))
        XCTAssertEqual(eff.get("max_prohibits"), .int(64))
        XCTAssertEqual(eff.get("max_bounds"), .int(32))
        let g2 = try goal({ $0[JKey("grants")] = .array((0..<2).map { i in K042.parse("{\"gid\":\"g\(i)\",\"verb\":\"refund\",\"res\":{\"k\":\"exact\",\"id\":\"c\"},\"cond\":{\"k\":\"true\"}}") }) })
        XCTAssertThrowsError(try R.renderPolicyCard(g2, nil, K042.parse(#"{"max_grants":1}"#), false)) { e in XCTAssertEqual((e as? R.ReviewError)?.code, "card_too_large") }
    }

    func testCardAndDiff() throws {
        let g = try goal()
        let card = try R.renderPolicyCard(g, K042.parse(Self.testsText).asArray, nil, false)
        XCTAssertEqual(card.get("goal_digest")?.asString, try PCAGoalDigests.goalDigest(g))
        // deterministic, and sensitive to every clause
        XCTAssertEqual(try R.cardDigest(card), try R.cardDigest(try R.renderPolicyCard(g, K042.parse(Self.testsText).asArray, nil, false)))
        let changed = try goal({ $0[JKey("principal")] = .string("user:bob") })
        XCTAssertNotEqual(try R.cardDigest(card), try R.cardDigest(try R.renderPolicyCard(changed, K042.parse(Self.testsText).asArray, nil, false)))
        // a wildcard prohibition is red
        let text = try R.cardToText(card)
        XCTAssertTrue(text.contains("!! "))
        // no change, no diff
        let same = try R.diffGoals(g, g, nil, nil, nil)
        XCTAssertEqual(same.get("changes"), .array([]))
        XCTAssertEqual(same.get("widenings"), .int(0))
        XCTAssertEqual(same.get("newly_allowed_complete"), .bool(false))
        // a changed principal is a widening ("unknown"), listed first; diffToText flags it
        let d = try R.diffGoals(g, changed, nil, nil, nil)
        XCTAssertEqual(d.get("widenings"), .int(1))
        XCTAssertEqual(d.get("changes")?.asArray?.first?.get("direction"), .string("unknown"))
        XCTAssertTrue(try R.diffToText(d).hasPrefix("!! "))
        // a removed grant narrows, an added one widens; the kernel lists the newly allowed witnesses first
        let none = try goal({ $0[JKey("grants")] = .array([]) })
        XCTAssertEqual(try R.diffGoals(g, none, nil, nil, nil).get("changes")?.asArray?.first?.get("direction"), .string("narrow"))
        let ont = K042.parse(Self.ontologyText)
        let added = try R.diffGoals(none, g, StubKernel(mode: "full"), nil, ont)
        XCTAssertEqual(added.get("changes")?.asArray?.first?.get("direction"), .string("widen"))
        XCTAssertEqual(added.get("newly_allowed")?.asArray?.count, 1)
        XCTAssertEqual(added.get("newly_allowed_complete"), .bool(true))
        XCTAssertTrue(try R.diffToText(added).hasPrefix("!! NEWLY ALLOWED:"))
        // a cap on the number of changes refuses, never truncates
        XCTAssertThrowsError(try R.diffGoals(g, changed, nil, K042.parse(#"{"max_diff_widenings":0}"#), nil)) { e in
            XCTAssertEqual((e as? R.ReviewError)?.code, "too_many_widenings")
        }
    }
}
