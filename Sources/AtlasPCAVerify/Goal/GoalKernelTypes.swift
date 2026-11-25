import Foundation

/// The typing judgement of the proved compiler (units, currency, closed world, canonical order, wildcards, holes) and its reasons.
enum KTypes {
    static func atomV(_ a: KAtom) -> KVal {
        switch a {
        case let .aq(q): return .vq(q)
        case let .aS(s): return .vs(s)
        }
    }

    static func tyOfV(_ v: KVal) -> KTy? {
        switch v {
        case let .vq(q): return .tyQ(q.u)
        case .vs: return .tyS
        case .vset: return nil
        }
    }

    static func tyOfTerm(_ t: KTerm) -> KTy? {
        switch t {
        case let .param(_, ty): return ty
        case let .lit(v): return tyOfV(v)
        case let .histAgg(_, u): return .tyQ(u)
        }
    }

    private static func unitOk(_ u: KUnit) -> Bool {
        if case let .money(c) = u { return !c.isEmpty }
        return true
    }

    private static func tyOk(_ t: KTy) -> Bool {
        if case let .tyQ(u) = t { return unitOk(u) }
        return true
    }

    private static func vOk(_ v: KVal) -> Bool {
        switch v {
        case let .vq(q): return unitOk(q.u)
        case .vs: return true
        case let .vset(items):
            for a in items { if case let .aq(q) = a, !unitOk(q.u) { return false } }
            return true
        }
    }

    private static func termOk(_ t: KTerm) -> Bool {
        switch t {
        case let .param(p, ty): return !p.isEmpty && tyOk(ty)
        case let .lit(v): return vOk(v)
        case let .histAgg(b, u): return !b.isEmpty && unitOk(u)
        }
    }

    private static func isTyQ(_ t: KTy) -> Bool {
        if case .tyQ = t { return true }
        return false
    }

    private static func cmpTyped(_ op: KOp, _ l: KTerm, _ r: KTerm) -> Bool {
        if !termOk(l) || !termOk(r) { return false }
        guard let tl = tyOfTerm(l) else { return false }
        switch op {
        case .eq, .ne: return tyOfTerm(r) == tl
        case .lt, .lte, .gt, .gte: return tyOfTerm(r) == tl && isTyQ(tl)
        case .inn, .nin:
            guard case let .lit(v) = r, case let .vset(items) = v else { return false }
            for a in items { if tyOfV(atomV(a)) != tl { return false } }
            return true
        }
    }

    private static func condTyped(_ c: KCond, _ ok: (KS, KTy) -> Bool) -> Bool {
        switch c {
        case .ctrue: return true
        case let .cmp(op, l, r): return cmpTyped(op, l, r) && paramsOk(l, ok) && paramsOk(r, ok)
        case let .and(a, b): return condTyped(a, ok) && condTyped(b, ok)
        case let .or(a, b): return condTyped(a, ok) && condTyped(b, ok)
        case let .not(x): return condTyped(x, ok)
        }
    }

    private static func paramsOk(_ t: KTerm, _ ok: (KS, KTy) -> Bool) -> Bool {
        if case let .param(p, ty) = t { return ok(p, ty) }
        return true
    }

    private static func findDecl(_ vs: [KVerbDecl], _ verb: KS) -> KVerbDecl? {
        for v in vs { if v.verb == verb { return v } }
        return nil
    }

    private static func declaredFor(_ ont: KOntology, _ verbs: [KS], _ p: KS, _ ty: KTy) -> Bool {
        let want = KParamDecl(path: p, ty: ty)
        for v in verbs {
            guard let d = findDecl(ont.verbs, v) else { return false }
            if !d.params.contains(want) { return false }
        }
        return true
    }

    private static func noConflict(_ vs: [KVerbDecl], _ p: KS, _ ty: KTy) -> Bool {
        for v in vs { for x in v.params { if x.path == p && x.ty != ty { return false } } }
        return true
    }

    private static func hasRel(_ ont: KOntology, _ rel: KS, _ anchor: KS) -> Bool {
        for r in ont.rels { if r.rel == rel && r.anchor == anchor { return true } }
        return false
    }

    private static func partOk(_ ont: KOntology, _ p: KResPart) -> Bool {
        switch p {
        case let .exact(id): return !id.isEmpty
        case let .oneOf(ids): return !ids.isEmpty
        case let .related(rel, an): return hasRel(ont, rel, an)
        }
    }

    private static func resSelOk(_ ont: KOntology, _ s: KResSel) -> Bool {
        switch s {
        case let .exact(id): return !id.isEmpty
        case let .oneOf(ids): return !ids.isEmpty
        case let .related(rel, an): return hasRel(ont, rel, an)
        case .anyRes: return true
        case let .allOf(parts):
            if parts.count < 2 { return false }
            for p in parts { if !partOk(ont, p) { return false } }
            return true
        }
    }

    static func verbsOfClass(_ vs: [KVerbDecl], _ cls: KS) -> [KS] {
        var out: [KS] = []
        for v in vs { if v.cls == cls { out.append(v.verb) } }
        return out
    }

    static func prohVerbs(_ ont: KOntology, _ t: KProhTarget) -> [KS] {
        switch t {
        case let .verb(v): return [v]
        case let .effect(c): return verbsOfClass(ont.verbs, c)
        }
    }

    private static func isAnyRes(_ s: KResSel) -> Bool {
        if case .anyRes = s { return true }
        return false
    }

    private static func grantOk(_ ont: KOntology, _ g: KGoal, _ gr: KGrant) -> Bool {
        if gr.gid.isEmpty || findDecl(ont.verbs, gr.verb) == nil || !resSelOk(ont, gr.res) { return false }
        if isAnyRes(gr.res) && !g.wildcardAck.contains(gr.gid) { return false }
        return condTyped(gr.cond) { (p: KS, ty: KTy) -> Bool in declaredFor(ont, [gr.verb], p, ty) }
    }

    private static func prohibitOk(_ ont: KOntology, _ p: KProhibit) -> Bool {
        let tOk: Bool
        switch p.target {
        case let .verb(v): tOk = findDecl(ont.verbs, v) != nil
        case let .effect(c): tOk = !c.isEmpty && !verbsOfClass(ont.verbs, c).isEmpty
        }
        if p.pid.isEmpty || !resSelOk(ont, p.res) || !tOk { return false }
        let vs = prohVerbs(ont, p.target)
        return condTyped(p.cond) { (q: KS, ty: KTy) -> Bool in declaredFor(ont, vs, q, ty) }
    }

    private static func windowOk(_ w: KWindow) -> Bool {
        switch w {
        case let .sliding(ms): return ms > 0
        case let .period(ms, _): return ms > 0
        default: return true
        }
    }

    private static func scopeOk(_ s: KScope) -> Bool {
        if case let .fleet(a) = s { return !a.isEmpty }
        return true
    }

    private static func hasGid(_ g: KGoal, _ gid: KS) -> Bool {
        for x in g.grants { if x.gid == gid { return true } }
        return false
    }

    private static func boundOk(_ g: KGoal, _ b: KBound) -> Bool {
        let c = b.core
        if !(!b.bid.isEmpty && termOk(c.value) && unitOk(c.cap.u) && c.cap.n >= 0 && windowOk(c.window) && scopeOk(c.scope)) { return false }
        var selOk: Bool
        switch b.sel {
        case let .gids(gs):
            selOk = !gs.isEmpty
            if selOk { for x in gs { if !hasGid(g, x) { selOk = false; break } } }
        case let .effect(c): selOk = !c.isEmpty
        }
        if !selOk { return false }
        switch c.agg {
        case .count: return c.cap.u == .count
        case .sum, .max: return tyOfTerm(c.value) == KTy.tyQ(c.cap.u)
        case .distinct: return c.cap.u == .count && !c.key.isEmpty
        }
    }

    private static func validityOk(_ g: KGoal) -> Bool {
        if !(g.validity.notBefore <= g.validity.notAfter && g.validity.maxIdle >= 0 && g.deleg.maxDepth >= 0 && g.deleg.maxDepth <= 16 && g.deleg.narrowOnly) { return false }
        for x in g.deleg.mayTouch { if !hasGid(g, x) { return false } }
        return true
    }

    private static func holeOk(_ g: KGoal, _ h: KHole) -> Bool {
        if h.hid.isEmpty { return false }
        for x in h.affects { if !hasGid(g, x) { return false } }
        return true
    }

    private static func escsTyped(_ ont: KOntology, _ g: KGoal) -> Bool {
        for c in g.escalateOn {
            if !condTyped(c, { (p: KS, ty: KTy) -> Bool in noConflict(ont.verbs, p, ty) }) { return false }
        }
        return true
    }

    private static func strictlySorted(_ xs: [KS]) -> Bool {
        if xs.count < 2 { return true }
        for i in 0..<(xs.count - 1) { if !xs[i].lt(xs[i + 1]) { return false } }
        return true
    }

    private static func sorted4(_ g: KGoal) -> Bool {
        return strictlySorted(g.grants.map { $0.gid }) && strictlySorted(g.prohibits.map { $0.pid }) &&
            strictlySorted(g.bounds.map { $0.bid }) && strictlySorted(g.holes.map { $0.hid })
    }

    /// The type reasons of a goal against an ontology, in the proved order; empty = well typed.
    static func reasons(_ ont: KOntology, _ g: KGoal) -> [String] {
        var r: [String] = []
        if !sorted4(g) { r.append("not_canonical_order") }
        if !g.grants.allSatisfy({ grantOk(ont, g, $0) }) { r.append("ill_typed_grant") }
        if !g.prohibits.allSatisfy({ prohibitOk(ont, $0) }) { r.append("ill_typed_prohibit") }
        if !g.bounds.allSatisfy({ boundOk(g, $0) }) { r.append("ill_typed_bound") }
        if !escsTyped(ont, g) { r.append("ill_typed_escalation") }
        if !validityOk(g) { r.append("bad_validity_or_delegation") }
        if !g.holes.allSatisfy({ holeOk(g, $0) }) { r.append("bad_hole") }
        return r
    }
}
