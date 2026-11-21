import Foundation

/// The compiler and decision entry points the review flow needs. The default is the proved compiler (`PCAGoalKernel.provedKernel()`); a host may inject another. Every method may throw; a throw is a refusal of the goal (never a pass).
public protocol PCAGoalReviewKernel {
    /// Goal, IR ontology -> {ok: true, policy} | {ok: false, reasons}. Pure and total.
    func compile(_ goal: JSONValue, _ ont: JSONValue) throws -> JSONValue
    /// Content digest of the compiled policy.
    func policyDigest(_ policy: JSONValue) throws -> String
    /// Error-level analyzer findings over the compiled policy; any finding refuses. The default has no analyzer.
    func analyze(_ policy: JSONValue) throws -> [String]
    /// Whether `decide` is available (needed to re-run the confirmed examples).
    func canDecide() -> Bool
    /// The decision ("allow" | "deny" | "escalate") for an action.
    func decide(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> String
    /// Whether `newlyAllowed` is available.
    func canListNewlyAllowed() -> Bool
    /// Actions allowed by `next` and not by `prev`: {witnesses, complete}.
    func newlyAllowed(_ prev: JSONValue, _ next: JSONValue, _ ont: JSONValue, _ limit: Int64) throws -> JSONValue
}

extension PCAGoalReviewKernel {
    public func analyze(_ policy: JSONValue) throws -> [String] { [] }
    public func canDecide() -> Bool { false }
    public func decide(_ goal: JSONValue, _ ont: JSONValue, _ act: JSONValue, _ hist: JSONValue) throws -> String { throw IrError("no decide") }
    public func canListNewlyAllowed() -> Bool { false }
    public func newlyAllowed(_ prev: JSONValue, _ next: JSONValue, _ ont: JSONValue, _ limit: Int64) throws -> JSONValue { throw IrError("no newlyAllowed") }
}

/// Principal review and signing for a Goal IR. The PolicyCard is a deterministic, template-only (no model) rendering of the WHOLE goal:
/// every grant, prohibition, bound, validity window, delegation limit, escalation trigger, hole, wildcard and confirmed boundary example,
/// with exact numbers. Lossless-or-refuse: a card is never truncated; reviewer-fatigue limits REFUSE a goal or diff that is too large to
/// read. The semantic diff counts anything not PROVEN narrower as a widening. A GoalApproval is a pinned reviewer's signature over
/// {goal, policy, card, ontology, tests, instruction, model-set digests}; `loadApprovedGoal` trusts nothing the submission claims
/// about itself: it recomputes every digest, recompiles, re-renders, re-runs the confirmed examples, then checks the signature.
///
/// The compiler is injected (`ReviewKernel`). A submission is {goal, ontology, instruction, model_set, tests?}.
public enum PCAGoalReview {
    public typealias ReviewKernel = PCAGoalReviewKernel

    // ---- limits (reviewer fatigue) ----

    private static let LIMIT_KEYS: [String] = [
        "max_grants", "max_prohibits", "max_bounds", "max_escalate_on", "max_examples", "max_card_lines", "max_card_bytes",
        "max_diff_changes", "max_diff_widenings", "max_witnesses",
    ]
    private static let LIMIT_VALUES: [Int64] = [32, 64, 32, 32, 40, 200, 24576, 60, 12, 20]

    private static func limitMap() -> [String: Int64] {
        var m: [String: Int64] = [:]
        for i in 0..<LIMIT_KEYS.count { m[LIMIT_KEYS[i]] = LIMIT_VALUES[i] }
        return m
    }

    private static func limitJSON(_ m: [String: Int64]) -> JSONValue {
        var o = JObject()
        for k in LIMIT_KEYS { o[JKey(k)] = .int(m[k] ?? 0) }
        return .object(o)
    }

    /// The hard caps on what a human is asked to read.
    public static func REVIEW_LIMITS() -> JSONValue { limitJSON(limitMap()) }

    /// Caller overrides may only TIGHTEN a limit (a larger number is ignored). `o` may be nil.
    public static func effectiveLimits(_ o: JSONValue?) -> JSONValue { limitJSON(limits(o)) }

    private static func limits(_ o: JSONValue?) -> [String: Int64] {
        var out = limitMap()
        if let obj = o?.asObject {
            for k in LIMIT_KEYS {
                // Number.isSafeInteger accepts -0 (the limit then becomes 0)
                if let d = IV.safe(obj[JKey(k)]), d >= 0, Int64(d) < out[k]! { out[k] = Int64(d) }
            }
        }
        return out
    }

    /// A review refusal with a stable code: card_too_large, unrenderable, holes, wildcard_unacknowledged, diff_too_large, too_many_widenings.
    public struct ReviewError: Error, CustomStringConvertible {
        public let code: String
        public let message: String
        public init(_ code: String, _ detail: String) {
            self.code = code
            self.message = "goal review: \(code): \(detail)"
        }
        public var description: String { message }
    }

    private static let D_CARD = "atlas-pca/policy-card/v1"
    private static let D_CLAUSE = "atlas-pca/goal-clause/v1"
    public static let GOAL_APPROVAL_KIND = "goal-approval"

    /// An approval may not be valid for longer than this.
    public static let MAX_GOAL_APPROVAL_TTL_MS: Int64 = 24 * 3_600_000
    private static let DEFAULT_TTL_MS: Int64 = 3_600_000

    /// The fields covered by the signature.
    public static let GOAL_APPROVAL_SIGNED_FIELDS: [String] = [
        "v", "goal_digest", "policy_digest", "card_digest", "ontology_digest", "tests_digest", "nl_digest", "model_set_digest", "reviewer", "approved_at", "expires_at",
    ]

    // ---- small helpers ----

    private static func mx(_ v: JSONValue?) throws -> JObject {
        guard let o = v?.asObject else { throw IrError("object expected") }
        return o
    }

    private static func objV(_ v: JSONValue?) throws -> JSONValue { .object(try mx(v)) }

    private static func at(_ o: JObject, _ k: String) -> JSONValue? { o[JKey(k)] }

    private static func isObj(_ v: JSONValue?) -> Bool { v?.asObject != nil }

    /// The strict canonical text of a clause; a value with no canonical form (float, undefined, cycle) refuses the card.
    private static func jsonOf(_ v: JSONValue?) throws -> String {
        guard let x = v else { throw ReviewError("unrenderable", "a clause has no canonical form (float, undefined or cycle)") }
        do { return try Canonical.canonicalizeStrict(x) } catch { throw ReviewError("unrenderable", "a clause has no canonical form (float, undefined or cycle)") }
    }

    private static func hashStrict(_ v: JSONValue) throws -> String {
        Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v)))
    }

    private static func line(_ id: String, _ kind: String, _ text: String, _ clause: JSONValue?, _ severity: String) throws -> JSONValue {
        guard let c = clause else { throw IrError("canonicalize: unsupported type undefined") }
        let cd = try hashStrict(GV.obj([("d", .string(D_CLAUSE)), ("kind", .string(kind)), ("clause", c)]))
        return GV.obj([("id", .string(id)), ("kind", .string(kind)), ("severity", .string(severity)), ("text", .string(text)), ("clause_digest", .string(cd))])
    }

    /// JS `includes` over code units (Swift's String.contains is canonical-equivalence based).
    private static func jsIncludes(_ hay: String, _ needle: String) -> Bool {
        let h = Array(hay.utf16)
        let n = Array(needle.utf16)
        if n.isEmpty { return true }
        if h.count < n.count { return false }
        for i in 0...(h.count - n.count) where Array(h[i..<(i + n.count)]) == n { return true }
        return false
    }

    /// Clause text through the shared phrase table; an unknown clause shape is shown as its canonical JSON, never dropped.
    private static func safeText(_ f: () throws -> String, _ clause: JSONValue?) throws -> String {
        do {
            let t = try f()
            if jsIncludes(t, "undefined") { throw IrError("unknown clause shape") }
            return t
        } catch {
            return try jsonOf(clause)
        }
    }

    private static func big(_ what: String, _ n: Int64, _ max: Int64) throws {
        if n > max { throw ReviewError("card_too_large", "\(n) \(what) exceed the cap of \(max): split the goal into smaller goals") }
    }

    private static func goalDigestOf(_ goal: JSONValue) throws -> String {
        do { return try PCAGoalDigests.goalDigest(goal) } catch { throw ReviewError("unrenderable", "the Goal has no canonical form (float, undefined or cycle)") }
    }

    private static func sev(_ red: Bool) -> String { red ? "red" : "info" }

    /// SameValueZero membership (Set.has / includes) of a JSON value.
    private static func jsContains(_ xs: [JSONValue], _ x: JSONValue?) -> Bool {
        guard let v = x else { return false }
        for y in xs {
            if IV.strictEq(y, v) { return true }
        }
        return false
    }

    // ---- the card ----

    /// Render the card: {v, goal_digest, ontology_digest, nl_digest, principal, lines}. Deterministic, no model, no locale. Throws
    /// ReviewError `holes` (unless `allowHoles`), `wildcard_unacknowledged`, `card_too_large`, `unrenderable`. `tests` and `limits` may be nil.
    public static func renderPolicyCard(_ goalV: JSONValue?, _ tests: [JSONValue]?, _ limitsV: JSONValue?, _ allowHoles: Bool) throws -> JSONValue {
        let lim = limits(limitsV)
        let ts: [JSONValue] = tests ?? []
        guard let goalVal = goalV, let goal = goalVal.asObject,
              let grants = at(goal, "grants")?.asArray, let prohibits = at(goal, "prohibits")?.asArray, let bounds = at(goal, "bounds")?.asArray,
              let escalateOn = at(goal, "escalateOn")?.asArray, let holes = at(goal, "holes")?.asArray,
              isObj(at(goal, "validity")), isObj(at(goal, "deleg"))
        else { throw ReviewError("unrenderable", "not a Goal IR") }
        try big("grants", Int64(grants.count), lim["max_grants"]!)
        try big("prohibitions", Int64(prohibits.count), lim["max_prohibits"]!)
        try big("bounds", Int64(bounds.count), lim["max_bounds"]!)
        try big("escalation triggers", Int64(escalateOn.count), lim["max_escalate_on"]!)
        try big("boundary examples", Int64(ts.count), lim["max_examples"]!)
        try big("card lines", Int64(4 + grants.count + prohibits.count + bounds.count + escalateOn.count + holes.count + ts.count), lim["max_card_lines"]!)
        if !holes.isEmpty && !allowHoles { throw ReviewError("holes", "\(holes.count) unresolved question(s): a goal with holes is a draft and cannot be signed") }
        let ack: [JSONValue] = at(goal, "wildcardAck")?.asArray ?? []
        var lines: [JSONValue] = []
        let principalText = try jsonOf(at(goal, "principal"))
        lines.append(try line("principal", "meta", "Acting for principal \(principalText). Nothing outside this card is allowed (default deny).", at(goal, "principal"), "info"))
        for go in grants {
            let g = try mx(go)
            let wild = GV.kind(at(g, "res")) == "any"
            if wild && !jsContains(ack, at(g, "gid")) {
                let gidText = try jsonOf(at(g, "gid"))
                throw ReviewError("wildcard_unacknowledged", "grant \(gidText) allows ANY resource without a wildcard acknowledgement")
            }
            let gv: JSONValue = .object(g)
            let text = try safeText({ try PCAGoalCard.grantLine(gv) + "." + (wild ? " WILDCARD acknowledged by the principal." : "") }, gv)
            lines.append(try line(GV.jsStr(at(g, "gid")), "grant", text, gv, sev(wild)))
        }
        for po in prohibits {
            let p = try mx(po)
            let pv: JSONValue = .object(p)
            let text = try safeText({ try PCAGoalCard.prohibitLine(pv) + "." }, pv)
            lines.append(try line(GV.jsStr(at(p, "pid")), "prohibit", text, pv, sev(GV.kind(at(p, "res")) == "any")))
        }
        for bo in bounds {
            let b = try mx(bo)
            let bv: JSONValue = .object(b)
            let text = try safeText({ try PCAGoalCard.boundLine(bv) + "." }, bv)
            lines.append(try line(GV.jsStr(at(b, "bid")), "bound", text, bv, "info"))
        }
        let validity = try mx(at(goal, "validity"))
        let deleg = try mx(at(goal, "deleg"))
        let validityV: JSONValue = .object(validity)
        let delegV: JSONValue = .object(deleg)
        lines.append(try line("validity", "validity", try safeText({ try PCAGoalCard.validityLine(validityV) + "." }, validityV), validityV, "info"))
        lines.append(try line("delegation", "delegation", try safeText({ try PCAGoalCard.delegationLine(delegV) + "." }, delegV), delegV, sev(!JS.truthy(at(deleg, "narrowOnly")))))
        for i in 0..<escalateOn.count {
            let c = try objV(escalateOn[i])
            lines.append(try line("escalate_on[\(i)]", "escalate", try safeText({ try PCAGoalCard.escalateLine(c) + "." }, c), c, "info"))
        }
        for i in 0..<holes.count {
            let h = try objV(holes[i])
            lines.append(try line("hole[\(i)]", "hole", try safeText({ try PCAGoalCard.holeLine(h) + ". Everything depending on it is dropped." }, h), h, "red"))
        }
        for to in ts {
            let t = try mx(to)
            let act = try mx(at(t, "act"))
            let verbText = try jsonOf(at(act, "verb"))
            let resText = try jsonOf(at(act, "res"))
            let paramsText = try jsonOf(at(act, "params"))
            let adms = try GV.arr(try mx(at(t, "hist"))[JKey("adms")]).count
            let answer = at(t, "answer")
            let ans = answer == JSONValue.string("ask") ? "ASKED about" : (answer == JSONValue.string("allow") ? "ALLOWED" : "DENIED")
            var text = "EXAMPLE you confirmed: \(verbText) on \(resText) with \(paramsText)"
            if adms > 0 { text += " after \(adms) earlier admitted action(s)" }
            text += " must be \(ans)."
            lines.append(try line("example:" + GV.jsStr(at(t, "id")), "example", text, .object(t), "info"))
        }
        try big("card lines", Int64(lines.count), lim["max_card_lines"]!)
        let gd = try goalDigestOf(goalVal)
        // a card member that is undefined has no canonical form: the reference's byte count of the card throws
        guard let ontD = at(goal, "ontDigest"), let nlD = at(goal, "nlDigest"), let prin = at(goal, "principal") else { throw IrError("canonicalize: unsupported type undefined") }
        let card = GV.obj([
            ("v", .int(1)), ("goal_digest", .string(gd)), ("ontology_digest", ontD), ("nl_digest", nlD), ("principal", prin), ("lines", .array(lines)),
        ])
        try big("bytes of card", Int64(try Canonical.canonicalBytes(card).count), lim["max_card_bytes"]!)
        return card
    }

    public static func cardDigest(_ card: JSONValue) throws -> String {
        try hashStrict(GV.obj([("d", .string(D_CARD)), ("card", card)]))
    }

    /// Plain-text form of a card for any console or terminal. Red lines are prefixed `!!`.
    public static func cardToText(_ card: JSONValue) throws -> String {
        var out: [String] = []
        for lo in try GV.arr(GV.get(card, "lines")) {
            out.append((GV.get(lo, "severity") == JSONValue.string("red") ? "!! " : "   ") + GV.jsStr(GV.get(lo, "text")))
        }
        return out.joined(separator: "\n")
    }

    // ---- semantic diff ----

    private static func same(_ a: JSONValue?, _ b: JSONValue?) throws -> Bool {
        let x = try jsonOf(a)
        let y = try jsonOf(b)
        return x.unicodeScalars.elementsEqual(y.unicodeScalars)
    }

    private static func conjuncts(_ c: JSONValue?) throws -> [JSONValue] {
        guard let v = c, v != .null else { throw IrError("cannot read a clause of undefined") }
        let k = GV.kind(v)
        if k == "and" {
            var out = try conjuncts(GV.get(v, "a"))
            out.append(contentsOf: try conjuncts(GV.get(v, "b")))
            return out
        }
        return k == "true" ? [] : [v]
    }

    /// new.cond is old.cond AND more (or equal): provably no wider.
    private static func whereNoWider(_ oldW: JSONValue?, _ newW: JSONValue?) throws -> Bool {
        var have = Set<JKey>()
        for c in try conjuncts(newW) { have.insert(JKey(try jsonOf(c))) }
        for c in try conjuncts(oldW) {
            if !have.contains(JKey(try jsonOf(c))) { return false }
        }
        return true
    }

    private static func grantDir(_ ov: JSONValue?, _ nv: JSONValue?) throws -> String {
        if try same(ov, nv) { return "neutral" }
        let o = try mx(ov)
        let n = try mx(nv)
        if IV.strictEq(at(o, "verb"), at(n, "verb")), try same(at(o, "res"), at(n, "res")), try whereNoWider(at(o, "cond"), at(n, "cond")) { return "narrow" }
        return "unknown"
    }

    private static func prohibitDir(_ ov: JSONValue?, _ nv: JSONValue?) throws -> String {
        if try same(ov, nv) { return "neutral" }
        let o = try mx(ov)
        let n = try mx(nv)
        if try same(at(o, "target"), at(n, "target")), try same(at(o, "res"), at(n, "res")), try whereNoWider(at(n, "cond"), at(o, "cond")) { return "narrow" }
        return "unknown"
    }

    private static func capOf(_ o: JObject) throws -> JSONValue {
        guard let c = at(o, "cap"), c != .null else { throw IrError("cannot read cap of undefined") }
        return c
    }

    private static func boundDir(_ ov: JSONValue?, _ nv: JSONValue?) throws -> String {
        if try same(ov, nv) { return "neutral" }
        var ro = try mx(ov)
        var rn = try mx(nv)
        let oCap = try capOf(ro)
        let nCap = try capOf(rn)
        ro[JKey("cap")] = .null
        rn[JKey("cap")] = .null
        let restSame = try same(.object(ro), .object(rn))
        let unitSame = try same(GV.get(oCap, "u"), GV.get(nCap, "u"))
        if !restSame || !unitSame { return "unknown" }
        let a = JS.toNumber(GV.get(nCap, "n"))
        let b = JS.toNumber(GV.get(oCap, "n"))
        return a < b ? "narrow" : (a > b ? "widen" : (a == b ? "neutral" : "unknown"))
    }

    /// maxIdle 0 means "no idle limit": the widest.
    private static func idle(_ x: JSONValue?) -> Double {
        if let d = IV.num(x), d == 0 { return Double.infinity }
        return JS.toNumber(x)
    }

    private static func validityDir(_ ov: JSONValue?, _ nv: JSONValue?) throws -> String {
        if try same(ov, nv) { return "neutral" }
        let o = try mx(ov)
        let n = try mx(nv)
        let nb = JS.toNumber(at(n, "notBefore"))
        let ob = JS.toNumber(at(o, "notBefore"))
        let na = JS.toNumber(at(n, "notAfter"))
        let oa = JS.toNumber(at(o, "notAfter"))
        let nar = nb >= ob && na <= oa && idle(at(n, "maxIdle")) <= idle(at(o, "maxIdle"))
        let wid = nb <= ob && na >= oa && idle(at(n, "maxIdle")) >= idle(at(o, "maxIdle"))
        return nar ? "narrow" : (wid ? "widen" : "unknown")
    }

    /// `new Set(x)`: absent or null is the empty set; an array its members.
    private static func setOf(_ v: JSONValue?) throws -> [JSONValue] {
        if v == nil || v == .null { return [] }
        return try GV.arr(v)
    }

    private static func delegationDir(_ ov: JSONValue?, _ nv: JSONValue?) throws -> String {
        if try same(ov, nv) { return "neutral" }
        let o = try mx(ov)
        let n = try mx(nv)
        let touchO = try setOf(at(o, "mayTouch"))
        let touchN = try setOf(at(n, "mayTouch"))
        var sub = true
        for x in touchN where !jsContains(touchO, x) { sub = false }
        var sup = true
        for x in touchO where !jsContains(touchN, x) { sup = false }
        let nd = JS.toNumber(at(n, "maxDepth"))
        let od = JS.toNumber(at(o, "maxDepth"))
        let nar = nd <= od && sub && (JS.truthy(at(n, "narrowOnly")) || !JS.truthy(at(o, "narrowOnly")))
        let wid = nd >= od && sup && (JS.truthy(at(o, "narrowOnly")) || !JS.truthy(at(n, "narrowOnly")))
        return nar ? "narrow" : (wid ? "widen" : "unknown")
    }

    private static func keyed(_ xs: [JSONValue], _ field: String) -> [(String, JSONValue)] {
        var r: [(String, JSONValue)] = []
        for x in xs { r.append((GV.jsStr(GV.get(x, field)), x)) }
        return r
    }

    private static func change(_ ch: String, _ kind: String, _ id: String, _ direction: String, _ text: String) -> JSONValue {
        GV.obj([("change", .string(ch)), ("kind", .string(kind)), ("id", .string(id)), ("direction", .string(direction)), ("text", .string(text))])
    }

    private static func pairs(
        _ out: inout [JSONValue], _ prev: [(String, JSONValue)], _ next: [(String, JSONValue)], _ kind: String, _ added: String, _ removed: String,
        _ changed: (JSONValue?, JSONValue?) throws -> String, _ text: (String, JSONValue) throws -> String
    ) throws {
        var pm: [JKey: JSONValue] = [:]
        var nm = Set<JKey>()
        for e in prev { pm[JKey(e.0)] = e.1 }
        for e in next { nm.insert(JKey(e.0)) }
        for e in next {
            let id = e.0
            let v = try objV(e.1)
            let o = pm[JKey(id)]
            if o == nil {
                let t = try text(id, v)
                out.append(change("added", kind, id, added, "ADDED \(t)"))
            } else if !(try same(o, v)) {
                let dir = try changed(o, v)
                let now = try text(id, v)
                let was = try text(id, try objV(o))
                out.append(change("changed", kind, id, dir, "CHANGED \(now) (was: \(was))"))
            }
        }
        for e in prev where !nm.contains(JKey(e.0)) {
            let t = try text(e.0, try objV(e.1))
            out.append(change("removed", kind, e.0, removed, "REMOVED \(t)"))
        }
    }

    private static func isWide(_ c: JSONValue?) -> Bool {
        let d = GV.get(c, "direction")
        return d == JSONValue.string("widen") || d == JSONValue.string("unknown")
    }

    /// Clause-level semantic diff between the goal a principal approved before and the one now proposed. Widenings first. Throws ReviewError
    /// `diff_too_large` / `too_many_widenings` past the fatigue caps. `kernel` (newlyAllowed), `limits` and `ontology` may be nil.
    public static func diffGoals(_ prev: JSONValue, _ next: JSONValue, _ kernel: PCAGoalReviewKernel?, _ limitsV: JSONValue?, _ ontology: JSONValue?) throws -> JSONValue {
        let lim = limits(limitsV)
        let gl: (String, JSONValue) throws -> String = { id, g in
            let idText = try jsonOf(.string(id))
            let verbText = try jsonOf(GV.get(g, "verb"))
            let resText = try PCAGoalCard.res(try objV(GV.get(g, "res")))
            let condText = try PCAGoalCard.cond(try objV(GV.get(g, "cond")))
            return "grant \(idText): \(verbText) on \(resText) when \(condText)"
        }
        let pl: (String, JSONValue) throws -> String = { id, p in
            let t = GV.get(p, "target")
            let targetText: String
            if GV.kind(t) == "verb" {
                targetText = try jsonOf(GV.get(t, "verb"))
            } else {
                guard let tv = t, tv != .null else { throw IrError("cannot read cls of undefined") }
                let clsText = try jsonOf(GV.get(tv, "cls"))
                targetText = "effect class \(clsText)"
            }
            let idText = try jsonOf(.string(id))
            let resText = try PCAGoalCard.res(try objV(GV.get(p, "res")))
            let condText = try PCAGoalCard.cond(try objV(GV.get(p, "cond")))
            return "prohibition \(idText): \(targetText) on \(resText) when \(condText)"
        }
        let bl: (String, JSONValue) throws -> String = { id, b in
            let idText = try jsonOf(.string(id))
            let lineText = try PCAGoalCard.boundLine(b)
            let qText = try PCAGoalCard.quantity(try objV(GV.get(b, "cap")))
            return "bound \(idText): \(lineText) (\(qText))"
        }
        var changes: [JSONValue] = []
        try pairs(&changes, keyed(try GV.arr(GV.get(prev, "grants")), "gid"), keyed(try GV.arr(GV.get(next, "grants")), "gid"), "grant", "widen", "narrow", { o, n in try grantDir(o, n) }, gl)
        try pairs(&changes, keyed(try GV.arr(GV.get(prev, "prohibits")), "pid"), keyed(try GV.arr(GV.get(next, "prohibits")), "pid"), "prohibit", "narrow", "widen", { o, n in try prohibitDir(o, n) }, pl)
        try pairs(&changes, keyed(try GV.arr(GV.get(prev, "bounds")), "bid"), keyed(try GV.arr(GV.get(next, "bounds")), "bid"), "bound", "narrow", "widen", { o, n in try boundDir(o, n) }, bl)
        var ep: [(String, JSONValue)] = []
        var en: [(String, JSONValue)] = []
        for c in try GV.arr(GV.get(prev, "escalateOn")) { ep.append((try jsonOf(c), c)) }
        for c in try GV.arr(GV.get(next, "escalateOn")) { en.append((try jsonOf(c), c)) }
        try pairs(&changes, ep, en, "escalate", "narrow", "widen", { _, _ in "unknown" }, { _, c in "escalation when " + (try PCAGoalCard.cond(c)) })
        let pValidity = GV.get(prev, "validity")
        let nValidity = GV.get(next, "validity")
        if !(try same(pValidity, nValidity)) {
            let dir = try validityDir(pValidity, nValidity)
            let nowText = try jsonOf(nValidity)
            let wasText = try jsonOf(pValidity)
            changes.append(change("changed", "validity", "validity", dir, "CHANGED validity: \(nowText) (was: \(wasText))"))
        }
        let pDeleg = GV.get(prev, "deleg")
        let nDeleg = GV.get(next, "deleg")
        if !(try same(pDeleg, nDeleg)) {
            let dir = try delegationDir(pDeleg, nDeleg)
            let nowText = try jsonOf(nDeleg)
            let wasText = try jsonOf(pDeleg)
            changes.append(change("changed", "delegation", "delegation", dir, "CHANGED delegation: \(nowText) (was: \(wasText))"))
        }
        // Identity of the actor, the vocabulary and the wildcard acknowledgements are never "neutral": a swap can widen.
        if !IV.strictEq(GV.get(prev, "principal"), GV.get(next, "principal")) {
            let nowText = try jsonOf(GV.get(next, "principal"))
            let wasText = try jsonOf(GV.get(prev, "principal"))
            changes.append(change("changed", "meta", "principal", "unknown", "CHANGED principal: \(nowText) (was: \(wasText))"))
        }
        if !IV.strictEq(GV.get(prev, "ontDigest"), GV.get(next, "ontDigest")) {
            let wasText = try jsonOf(GV.get(prev, "ontDigest"))
            let nowText = try jsonOf(GV.get(next, "ontDigest"))
            changes.append(change("changed", "meta", "ontology", "unknown", "CHANGED ontology: every term now means what the new vocabulary says (was \(wasText), now \(nowText))"))
        }
        let pAck = GV.get(prev, "wildcardAck")
        let nAck = GV.get(next, "wildcardAck")
        if !(try same(pAck, nAck)) {
            let nowText = try jsonOf(nAck)
            let wasText = try jsonOf(pAck)
            changes.append(change("changed", "meta", "wildcard_ack", "unknown", "CHANGED wildcard acknowledgements: \(nowText) (was: \(wasText))"))
        }
        if !IV.strictEq(GV.get(prev, "nlDigest"), GV.get(next, "nlDigest")) {
            changes.append(change("changed", "meta", "instruction", "neutral", "CHANGED the instruction text the goal was interpreted from"))
        }
        var widenings = 0
        for c in changes where isWide(c) { widenings += 1 }
        let maxChanges = lim["max_diff_changes"]!
        let maxWid = lim["max_diff_widenings"]!
        let maxWit = lim["max_witnesses"]!
        if Int64(changes.count) > maxChanges { throw ReviewError("diff_too_large", "\(changes.count) changes exceed the cap of \(maxChanges): review the new goal as a whole instead") }
        if Int64(widenings) > maxWid { throw ReviewError("too_many_widenings", "\(widenings) widenings exceed the cap of \(maxWid) per review") }
        var witnesses: [JSONValue] = []
        var complete = false
        if let ont = ontology, let k = kernel, k.canListNewlyAllowed() {
            let na = try k.newlyAllowed(prev, next, ont, maxWit)
            let w = try GV.arr(GV.get(na, "witnesses"))
            var i = 0
            while i < w.count && Int64(i) < maxWit {
                witnesses.append(w[i])
                i += 1
            }
            complete = JS.truthy(GV.get(na, "complete")) && Int64(w.count) <= maxWit
        }
        var ordered: [JSONValue] = []
        for c in changes where isWide(c) { ordered.append(c) }
        for c in changes where !isWide(c) { ordered.append(c) }
        return GV.obj([
            ("v", .int(1)), ("from_goal_digest", .string(try goalDigestOf(prev))), ("to_goal_digest", .string(try goalDigestOf(next))), ("newly_allowed", .array(witnesses)),
            ("newly_allowed_complete", .bool(complete)), ("changes", .array(ordered)), ("widenings", .int(Int64(widenings))),
        ])
    }

    public static func diffToText(_ d: JSONValue) throws -> String {
        var out: [String] = []
        for w in try GV.arr(GV.get(d, "newly_allowed")) {
            let verbText = try jsonOf(GV.get(w, "verb"))
            let resText = try jsonOf(GV.get(w, "res"))
            let paramsText = try jsonOf(GV.get(w, "params"))
            out.append("!! NEWLY ALLOWED: \(verbText) on \(resText) with \(paramsText)")
        }
        if GV.get(d, "newly_allowed_complete") != JSONValue.bool(true) {
            out.append("!! The list of newly allowed actions is incomplete or unavailable: read every widening below.")
        }
        for c in try GV.arr(GV.get(d, "changes")) { out.append((isWide(c) ? "!! " : "   ") + GV.jsStr(GV.get(c, "text"))) }
        return out.joined(separator: "\n")
    }

    // ---- GoalApproval ----

    /// Options of `approveGoal`; every field may be nil.
    public final class ApproveOptions {
        public var kernel: PCAGoalReviewKernel?
        public var now: Int64?
        public var ttlMs: Int64?
        public var limits: JSONValue?
        /// The previously approved goal: when given, the diff must be reviewable (fatigue caps) or signing is refused.
        public var base: JSONValue?
        public init() {}
    }

    /// Options of `loadApprovedGoal`. `reviewers`: pinned b64u keys or {pk, ...} objects.
    public final class LoadOptions {
        public var kernel: PCAGoalReviewKernel?
        public var reviewers: [JSONValue]?
        public var ontologyDigest: String?
        public var now: Int64?
        public var limits: JSONValue?
        public init() {}
    }

    private static func bad(_ reason: String) -> JSONValue { GV.obj([("ok", .bool(false)), ("reason", .string(reason))]) }

    private static let FIELD_REASON: [(String, String)] = [
        ("goal_digest", "goal_digest_mismatch"), ("policy_digest", "policy_digest_mismatch"), ("ontology_digest", "ontology_mismatch"),
        ("tests_digest", "tests_digest_mismatch"), ("nl_digest", "nl_digest_mismatch"), ("model_set_digest", "model_set_digest_mismatch"),
        ("card_digest", "card_digest_mismatch"),
    ]

    private enum Derived {
        case ok(digests: JObject, policy: JSONValue)
        case fail(String)
    }

    private static func nowMillis() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded(.down)) }

    /// The digests a submission derives to, or the reason it is refused.
    private static func derive(_ subO: JSONValue?, _ kernel: PCAGoalReviewKernel, _ limitsV: JSONValue?) throws -> Derived {
        guard let sub = subO?.asObject else { return .fail("malformed_submission") }
        guard let goal = at(sub, "goal"), goal.isObject, let ontology = at(sub, "ontology"), ontology.isObject,
              let instruction = at(sub, "instruction")?.asString, let modelSet = at(sub, "model_set")?.asArray
        else { return .fail("malformed_submission") }
        if at(sub, "tests") != nil && at(sub, "tests")?.asArray == nil { return .fail("malformed_submission") }
        var models: [String] = []
        for m in modelSet {
            guard let s = m.asString else { return .fail("malformed_submission") }
            models.append(s)
        }
        let tests: [JSONValue] = at(sub, "tests")?.asArray ?? []
        let card: JSONValue
        do {
            card = try renderPolicyCard(goal, tests, limitsV, false)
        } catch let e as ReviewError {
            return .fail(e.code)
        } catch {
            return .fail("malformed_goal")
        }
        let gd: String
        let nl: String
        let ts: String
        let ms: String
        do {
            gd = try PCAGoalDigests.goalDigest(goal)
            nl = try PCAGoalDigests.nlDigest(instruction)
            ts = try PCAGoalExamples.testsDigest(tests)
            ms = try PCAGoalDigests.modelSetDigest(models)
        } catch {
            return .fail("malformed_goal")
        }
        guard let goalNl = GV.get(goal, "nlDigest")?.asString, IV.same(nl, goalNl) else { return .fail("instruction_mismatch") }
        let compiled: JSONValue
        do {
            compiled = try kernel.compile(goal, ontology)
        } catch {
            return .fail("compile_error")
        }
        if GV.get(compiled, "ok") != JSONValue.bool(true) { return .fail("compile_error") }
        let policy: JSONValue
        let pd: String
        do {
            guard let p = GV.get(compiled, "policy") else { throw IrError("no policy") }
            policy = p
            let findings = try kernel.analyze(p)
            if !findings.isEmpty { return .fail("analyzer_error") }
            pd = try kernel.policyDigest(p)
        } catch {
            return .fail("analyzer_error")
        }
        if !tests.isEmpty {
            if !kernel.canDecide() { return .fail("tests_unverifiable") }
            // Regression pin: the principal's confirmed examples must be reproduced by the policy we just compiled.
            for to in tests {
                let t = try mx(to)
                let got: String
                do {
                    var ont: JSONValue = ontology
                    if JS.truthy(at(t, "rels")), var oo = ontology.asObject {
                        oo[JKey("rels")] = at(t, "rels")
                        ont = .object(oo)
                    }
                    got = try kernel.decide(goal, ont, try objV(at(t, "act")), try objV(at(t, "hist")))
                } catch {
                    return .fail("tests_unverifiable")
                }
                // an answer that is not a string expects "escalate", as the reference's fall-through
                if !IV.same(got, PCAGoalExamples.expectedDecision(at(t, "answer")?.asString)) { return .fail("tests_contradicted") }
            }
        }
        guard let ontD = GV.get(goal, "ontDigest") else { throw IrError("canonicalize: unsupported type undefined") }
        var digests = JObject()
        digests[JKey("goal_digest")] = .string(gd)
        digests[JKey("policy_digest")] = .string(pd)
        digests[JKey("card_digest")] = .string(try cardDigest(card))
        digests[JKey("ontology_digest")] = ontD
        digests[JKey("tests_digest")] = .string(ts)
        digests[JKey("nl_digest")] = .string(nl)
        digests[JKey("model_set_digest")] = .string(ms)
        return .ok(digests: digests, policy: policy)
    }

    private static func approveWith(_ sub: JSONValue, _ reviewerId: String, _ signer: (JSONValue) throws -> JSONValue, _ opts: ApproveOptions?) throws -> JSONValue {
        let o = opts ?? ApproveOptions()
        let now: Int64 = o.now ?? nowMillis()
        let ttl: Int64 = o.ttlMs ?? DEFAULT_TTL_MS
        if ttl <= 0 || ttl > MAX_GOAL_APPROVAL_TTL_MS || now > GV.MAX_SAFE || now < -GV.MAX_SAFE { throw IrError("approveGoal: invalid time or ttl") }
        let kernel: PCAGoalReviewKernel = o.kernel ?? PCAGoalKernel.provedKernel()
        let d = try derive(sub, kernel, o.limits)
        guard case let .ok(digests, _) = d else {
            if case let .fail(r) = d { throw IrError("approveGoal: " + r) }
            throw IrError("approveGoal")
        }
        if let base = o.base { _ = try diffGoals(base, try objV(GV.get(sub, "goal")), nil, o.limits, nil) }
        var body = digests
        body[JKey("v")] = .int(1)
        body[JKey("reviewer")] = .string(reviewerId)
        body[JKey("approved_at")] = .int(now)
        body[JKey("expires_at")] = .int(now + ttl)
        return try signer(.object(body))
    }

    /// The human step: sign the exact goal with an Ed25519 seed. Re-derives everything the loader will; throws when the goal is not signable
    /// (holes, wildcard without ack, card or diff over the fatigue caps, compile or analyzer failure, a contradicted test, an instruction that
    /// does not match `nlDigest`). The kernel defaults to the proved one.
    public static func approveGoal(_ sub: JSONValue, _ reviewerSeed: [UInt8], _ opts: ApproveOptions?) throws -> JSONValue {
        try approveWith(sub, try PCAGoalSign.signerId(reviewerSeed), { body in try PCAGoalSign.signGoalArtifact(GOAL_APPROVAL_KIND, body, reviewerSeed) }, opts)
    }

    /// `approveGoal` with a suite-agile (hybrid or post-quantum) signer.
    public static func approveGoal(_ sub: JSONValue, _ reviewer: PCASuiteKey, _ opts: ApproveOptions?) throws -> JSONValue {
        guard let id = reviewer.id else { throw IrError("approveGoal: the reviewer has no pinned identity") }
        return try approveWith(sub, id, { body in try PCAGoalSign.signGoalArtifact(GOAL_APPROVAL_KIND, body, reviewer) }, opts)
    }

    /// The only door from a submitted goal to an enforceable one: recomputes every digest, recompiles, re-renders the card, re-runs the
    /// confirmed examples, then checks the signature. Never throws: {ok: true, approved} | {ok: false, reason}.
    public static func loadApprovedGoal(_ sub: JSONValue, _ approval: JSONValue?, _ opts: LoadOptions) -> JSONValue {
        do {
            let now: Int64 = opts.now ?? nowMillis()
            guard let reviewers = opts.reviewers, !reviewers.isEmpty else { return bad("no_reviewers_pinned") }
            guard let a = approval?.asObject, IV.strictEq(at(a, "v"), .int(1)), at(a, "sig")?.asString != nil, at(a, "reviewer")?.asString != nil,
                  IV.int(at(a, "approved_at")) != nil, IV.int(at(a, "expires_at")) != nil
            else { return bad("malformed_approval") }
            for f in FIELD_REASON where at(a, f.0)?.asString == nil { return bad("malformed_approval") }
            let kernel: PCAGoalReviewKernel = opts.kernel ?? PCAGoalKernel.provedKernel()
            let d = try derive(sub, kernel, opts.limits)
            guard case let .ok(digests, policy) = d else {
                if case let .fail(r) = d { return bad(r) }
                return bad("malformed_approval")
            }
            let goal = try objV(GV.get(sub, "goal"))
            if let od = opts.ontologyDigest, !IV.strictEq(.string(od), GV.get(goal, "ontDigest")) { return bad("ontology_mismatch") }
            for f in FIELD_REASON where !IV.strictEq(at(a, f.0), digests[JKey(f.0)]) { return bad(f.1) }
            var pinned = false
            for p in reviewers {
                let pk: JSONValue?
                if p.asString != nil { pk = p } else {
                    if p == .null { throw IrError("cannot read pk of null") }
                    pk = GV.get(p, "pk")
                }
                if IV.strictEq(pk, at(a, "reviewer")) { pinned = true; break }
            }
            if !pinned { return bad("reviewer_not_pinned") }
            let approvedAt = IV.int(at(a, "approved_at"))!
            let expiresAt = IV.int(at(a, "expires_at"))!
            if expiresAt - approvedAt <= 0 || expiresAt - approvedAt > MAX_GOAL_APPROVAL_TTL_MS { return bad("ttl_too_long") }
            if approvedAt > now { return bad("not_yet_valid") }
            if now >= expiresAt { return bad("expired") }
            if !(try PCAGoalSign.verifyGoalArtifact(GOAL_APPROVAL_KIND, .object(a), "reviewer", reviewers)) { return bad("bad_signature") }
            guard let gdig = digests[JKey("goal_digest")], let pdig = digests[JKey("policy_digest")], let gds = gdig.asString, let pds = pdig.asString else { return bad("malformed_approval") }
            let ref = GV.obj([("goal_digest", gdig), ("policy_digest", pdig)])
            guard let goalString = PCA.intentGoalV3(ApprovedGoalRef(goalDigest: gds, policyDigest: pds)) else { throw IrError("intentGoalV3: malformed digest") }
            let approved = GV.obj([
                ("goal", goal), ("ontology", GV.get(sub, "ontology") ?? .null), ("policy", policy), ("ref", ref), ("goal_string", .string(goalString)),
                ("intent_policy", GV.obj([("approved_goal", ref)])), ("instruction", GV.get(sub, "instruction") ?? .null), ("reviewer", at(a, "reviewer") ?? .null),
                ("expires_at", at(a, "expires_at") ?? .null),
            ])
            return GV.obj([("ok", .bool(true)), ("approved", approved)])
        } catch {
            return bad("malformed_approval")
        }
    }
}
