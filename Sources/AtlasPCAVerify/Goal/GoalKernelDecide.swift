import Foundation

/// The decision function D_P of the lowered policy, the witness of an Allow and the separate witness checker.
/// Decisions: 0 Deny, 1 Escalate, 2 Allow; Kleene truth 0 false, 1 unknown, 2 true (meet / join are min / max).
enum KDecide {
    private static let DENY: Int = 0
    private static let ESCALATE: Int = 1
    private static let ALLOW: Int = 2
    private static let KF: Int = 0
    private static let KU: Int = 1
    private static let KT: Int = 2

    private static func b2t(_ b: Bool) -> Int { return b ? KT : KF }

    private static func eqT(_ x: KVal, _ y: KVal) -> Int {
        switch x {
        case let .vq(a):
            if case let .vq(b) = y, a.u == b.u { return b2t(a.n == b.n) }
            return KU
        case let .vs(a):
            if case let .vs(b) = y { return b2t(a == b) }
            return KU
        case .vset: return KU
        }
    }

    private static func ltT(_ x: KVal, _ y: KVal) -> Int {
        if case let .vq(a) = x, case let .vq(b) = y, a.u == b.u { return b2t(a.n < b.n) }
        return KU
    }

    private static func inT(_ x: KVal, _ items: [KAtom]) -> Int {
        var r = KF
        for a in items { r = max(r, eqT(x, KTypes.atomV(a))) }
        return r
    }

    private static func inOf(_ y: KVal) -> (KVal) -> Int {
        return { (x: KVal) -> Int in
            if case let .vset(items) = y { return inT(x, items) }
            return KU
        }
    }

    private static func cmpT(_ op: KOp, _ x: KVal?, _ y: KVal?) -> Int {
        guard let x = x, let y = y else { return KU }
        switch op {
        case .eq: return eqT(x, y)
        case .ne: return 2 - eqT(x, y)
        case .lt: return ltT(x, y)
        case .gte: return 2 - ltT(x, y)
        case .gt: return ltT(y, x)
        case .lte: return 2 - ltT(y, x)
        case .inn: return inOf(y)(x)
        case .nin: return 2 - inOf(y)(x)
        }
    }

    private static func evalT(_ t: KTerm, _ a: KAct, _ h: KHist) -> KVal? {
        switch t {
        case let .param(p, _): return a.params[p]
        case let .lit(v): return v
        case let .histAgg(b, _):
            if let q = h.aggs[b] { return .vq(q) }
            return nil
        }
    }

    private static func evalN(_ c: KNC, _ a: KAct, _ h: KHist) -> Int {
        switch c {
        case .ntrue: return KT
        case .nfalse: return KF
        case let .atom(op, l, r): return cmpT(op, evalT(l, a, h), evalT(r, a, h))
        case let .and(x, y): return min(evalN(x, a, h), evalN(y, a, h))
        case let .or(x, y): return max(evalN(x, a, h), evalN(y, a, h))
        }
    }

    private static func resOk(_ p: KResPat, _ r: KS) -> Bool {
        switch p {
        case .star: return true
        case let .set(ids): return ids.contains(r)
        }
    }

    private static func appliesL(_ s: KLSel, _ gid: KS, _ verb: KS) -> Bool { return s.gids.contains(gid) || s.verbs.contains(verb) }

    private static func inScope(_ sc: KScope, _ a: KAct, _ x: KAct) -> Bool {
        switch sc {
        case .session: return a.sess == x.sess
        case .principal: return a.prin == x.prin
        case .org: return a.org == x.org
        case let .fleet(agents): return agents.contains(a.agent) && agents.contains(x.agent)
        }
    }

    /// Floor division for a positive divisor.
    private static func floorDiv(_ a: Int64, _ b: Int64) -> Int64 {
        let q = a / b
        return (a % b != 0 && a < 0) ? q - 1 : q
    }

    private static func inWindow(_ w: KWindow, _ a: KAct, _ x: KAct) -> Bool {
        switch w {
        case .task, .lifetime: return true
        case let .sliding(ms): return x.t > a.t - ms && x.t <= a.t
        case let .period(ms, t0): return ms > 0 && floorDiv(a.t - t0, ms) == floorDiv(x.t - t0, ms)
        }
    }

    /// The admitted actions this bound counts, followed by the candidate itself.
    private static func selItems(_ core: KBCore, _ s: KLSel, _ adms: [KAdm], _ a: KAct) -> [KAct] {
        var out: [KAct] = []
        for m in adms {
            if appliesL(s, m.gid, m.act.verb) && inScope(core.scope, a, m.act) && inWindow(core.window, a, m.act) { out.append(m.act) }
        }
        out.append(a)
        return out
    }

    /// Numeric values of the value term over the items; nil as soon as one is unreadable or of another unit.
    private static func itemVals(_ core: KBCore, _ items: [KAct], _ h: KHist) -> [Int64]? {
        var out: [Int64] = []
        for x in items {
            guard let v = evalT(core.value, x, h), case let .vq(q) = v, q.u == core.cap.u else { return nil }
            out.append(q.n)
        }
        return out
    }

    /// Exact sum > cap (cap >= 0) without overflow: the sum is kept as high * 2^32 + low.
    private static func sumExceeds(_ xs: [Int64], _ cap: Int64) -> Bool {
        var hi: Int64 = 0
        var lo: Int64 = 0
        for x in xs { hi += x >> 32; lo += x & 0xFFFF_FFFF }
        hi += lo >> 32
        lo = lo & 0xFFFF_FFFF
        let chi = cap >> 32
        let clo = cap & 0xFFFF_FFFF
        return hi > chi || (hi == chi && lo > clo)
    }

    private static func exceeded(_ core: KBCore, _ items: [KAct], _ h: KHist) -> Int {
        let cap = core.cap.n
        switch core.agg {
        case .count: return b2t(Int64(items.count) > cap)
        case .sum:
            guard let xs = itemVals(core, items, h) else { return KU }
            return b2t(sumExceeds(xs, cap))
        case .max:
            guard let xs = itemVals(core, items, h) else { return KU }
            var m: Int64? = nil
            for x in xs { if m == nil || x > m! { m = x } }
            guard let mx = m else { return KU }
            return b2t(mx > cap)
        case .distinct:
            var vs = Set<KVal>()
            for x in items {
                guard let v = x.params[core.key] else { return KU }
                vs.insert(v)
            }
            return b2t(Int64(vs.count) > cap)
        }
    }

    /// The decision a bound imposes on a candidate admitted by a grant it applies to.
    private static func boundStat(_ core: KBCore, _ s: KLSel, _ a: KAct, _ h: KHist) -> Int {
        let e = exceeded(core, selItems(core, s, h.adms, a), h)
        if e == KT { return core.onExceed == .deny ? DENY : ESCALATE }
        return e == KU ? ESCALATE : ALLOW
    }

    private static func validityDec(_ v: KValidity, _ dg: KDeleg, _ a: KAct, _ h: KHist) -> Int {
        if a.t < v.notBefore || a.t > v.notAfter { return DENY }
        if v.maxIdle > 0 && h.last >= 0 && a.t - h.last > v.maxIdle { return DENY }
        if a.depth < 0 || a.depth > dg.maxDepth { return DENY }
        return ALLOW
    }

    private static func delegOk(_ dg: KDeleg, _ gid: KS, _ a: KAct) -> Bool { return a.depth == 0 || dg.mayTouch.contains(gid) }

    private static func prohOne(_ p: KLProh, _ a: KAct, _ h: KHist) -> Int {
        let m = min(b2t(p.verbs.contains(a.verb)), min(b2t(resOk(p.res, a.res)), evalN(p.cond, a, h)))
        if m == KT { return DENY }
        return m == KU ? ESCALATE : ALLOW
    }

    private static func prohDec(_ ps: [KLProh], _ a: KAct, _ h: KHist) -> Int {
        var d = ALLOW
        for p in ps { d = min(d, prohOne(p, a, h)) }
        return d
    }

    private static func escDec(_ cs: [KNC], _ a: KAct, _ h: KHist) -> Int {
        var d = ALLOW
        for c in cs { d = min(d, evalN(c, a, h) == KF ? ALLOW : ESCALATE) }
        return d
    }

    private static func ceilsDec(_ cs: [KLCeil], _ gid: KS, _ a: KAct, _ h: KHist) -> Int {
        var d = ALLOW
        for c in cs { d = min(d, appliesL(c.sel, gid, a.verb) ? boundStat(c.core, c.sel, a, h) : ALLOW) }
        return d
    }

    private static func predMatch(_ p: KLPred, _ dg: KDeleg, _ a: KAct, _ h: KHist) -> Int {
        return min(b2t(a.verb == p.verb && delegOk(dg, p.gid, a)), min(b2t(resOk(p.res, a.res)), evalN(p.cond, a, h)))
    }

    private static func predDec(_ p: KLPred, _ ceils: [KLCeil], _ dg: KDeleg, _ a: KAct, _ h: KHist) -> Int {
        return min(predMatch(p, dg, a, h), ceilsDec(ceils, p.gid, a, h))
    }

    private static func predsDec(_ ps: [KLPred], _ ceils: [KLCeil], _ dg: KDeleg, _ a: KAct, _ h: KHist) -> Int {
        var d = DENY
        for p in ps { d = max(d, predDec(p, ceils, dg, a, h)) }
        return d
    }

    /// D_P: Deny < Escalate < Allow; unknown never yields Allow.
    static func dp(_ p: KPol, _ a: KAct, _ h: KHist) -> Int {
        return min(validityDec(p.validity, p.deleg, a, h),
                   min(prohDec(p.prohs, a, h), min(escDec(p.escs, a, h), predsDec(p.preds, p.ceils, p.deleg, a, h))))
    }

    /// The reference semantics D_G; the compiled policy of the goal itself is proved to decide identically (lowering preserves every decision).
    static func dg(_ ont: KOntology, _ g: KGoal, _ a: KAct, _ h: KHist) -> Int { return dp(KCompile.lower(ont, g), a, h) }

    private static func applicable(_ cs: [KLCeil], _ gid: KS, _ verb: KS) -> [KS] {
        var out: [KS] = []
        for c in cs { if appliesL(c.sel, gid, verb) { out.append(c.bid) } }
        return out
    }

    /// The decision with the witness (grant id, applicable bound ids) of an Allow.
    struct Dw { let decision: Int; let gid: KS; let bids: [KS] }

    static func decideW(_ p: KPol, _ a: KAct, _ h: KHist) -> Dw {
        let d = dp(p, a, h)
        if d != ALLOW { return Dw(decision: d, gid: KS(""), bids: []) }
        for pr in p.preds {
            if predDec(pr, p.ceils, p.deleg, a, h) == ALLOW { return Dw(decision: ALLOW, gid: pr.gid, bids: applicable(p.ceils, pr.gid, a.verb)) }
        }
        return Dw(decision: DENY, gid: KS(""), bids: [])
    }

    /// The checker re-evaluates ONE grant and the gates, never the whole policy.
    static func verifyWitness(_ p: KPol, _ a: KAct, _ h: KHist, _ w: Dw) -> Bool {
        if validityDec(p.validity, p.deleg, a, h) != ALLOW || prohDec(p.prohs, a, h) != ALLOW || escDec(p.escs, a, h) != ALLOW { return false }
        var any = false
        for x in p.preds { if x.gid == w.gid && predDec(x, p.ceils, p.deleg, a, h) == ALLOW { any = true; break } }
        return any && w.bids == applicable(p.ceils, w.gid, a.verb)
    }
}
