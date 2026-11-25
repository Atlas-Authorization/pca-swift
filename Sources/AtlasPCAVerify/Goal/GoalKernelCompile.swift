import Foundation

// Negation-normal conditions and the lowered policy (GoalCompile): the compiler is a pure total function of (ontology, goal).

indirect enum KNC {
    case ntrue
    case nfalse
    case atom(KOp, KTerm, KTerm)
    case and(KNC, KNC)
    case or(KNC, KNC)
}

enum KResPat {
    case star
    case set([KS])
}

struct KLSel { let gids: [KS]; let verbs: [KS] }
struct KLPred { let gid: KS; let verb: KS; let res: KResPat; let cond: KNC }
struct KLProh { let pid: KS; let verbs: [KS]; let res: KResPat; let cond: KNC }
struct KLCeil { let bid: KS; let sel: KLSel; let core: KBCore }
struct KPol {
    let preds: [KLPred]
    let prohs: [KLProh]
    let ceils: [KLCeil]
    let escs: [KNC]
    let validity: KValidity
    let deleg: KDeleg
}

/// The result of Compile: a policy or the type reasons.
struct KCResult { let policy: KPol?; let reasons: [String] }

enum KCompile {
    private static func negOp(_ op: KOp) -> KOp {
        switch op {
        case .eq: return .ne
        case .ne: return .eq
        case .lt: return .gte
        case .gte: return .lt
        case .gt: return .lte
        case .lte: return .gt
        case .inn: return .nin
        case .nin: return .inn
        }
    }

    /// `pos` = the polarity: nnf(c, false) is the normal form of `not c`.
    static func nnf(_ c: KCond, _ pos: Bool) -> KNC {
        switch c {
        case .ctrue: return pos ? .ntrue : .nfalse
        case let .cmp(op, l, r): return .atom(pos ? op : negOp(op), l, r)
        case let .and(a, b): return pos ? .and(nnf(a, true), nnf(b, true)) : .or(nnf(a, false), nnf(b, false))
        case let .or(a, b): return pos ? .or(nnf(a, true), nnf(b, true)) : .and(nnf(a, false), nnf(b, false))
        case let .not(x): return nnf(x, !pos)
        }
    }

    private static func relMembers(_ rels: [KRelDecl], _ rel: KS, _ anchor: KS) -> [KS] {
        for r in rels { if r.rel == rel && r.anchor == anchor { return r.members } }
        return []
    }

    private static func interPat(_ x: KResPat, _ y: KResPat) -> KResPat {
        switch x {
        case .star: return y
        case let .set(xs):
            if case let .set(ys) = y { return .set(xs.filter { ys.contains($0) }) }
            return x
        }
    }

    private static func resolvePart(_ ont: KOntology, _ p: KResPart) -> KResPat {
        switch p {
        case let .exact(id): return .set([id])
        case let .oneOf(ids): return .set(ids)
        case let .related(rel, an): return .set(relMembers(ont.rels, rel, an))
        }
    }

    static func resolveSel(_ ont: KOntology, _ s: KResSel) -> KResPat {
        switch s {
        case let .exact(id): return .set([id])
        case let .oneOf(ids): return .set(ids)
        case let .related(rel, an): return .set(relMembers(ont.rels, rel, an))
        case .anyRes: return .star
        case let .allOf(parts):
            var acc: KResPat = .star
            var i = parts.count - 1
            while i >= 0 { acc = interPat(resolvePart(ont, parts[i]), acc); i -= 1 }
            return acc
        }
    }

    private static func resolveBSel(_ ont: KOntology, _ s: KSel) -> KLSel {
        switch s {
        case let .gids(g): return KLSel(gids: g, verbs: [])
        case let .effect(c): return KLSel(gids: [], verbs: KTypes.verbsOfClass(ont.verbs, c))
        }
    }

    private static func dependsOn(_ hs: [KHole], _ gid: KS) -> Bool {
        for h in hs { if h.global || h.affects.contains(gid) { return true } }
        return false
    }

    /// Drop every grant that depends on a hole (the most restrictive completion); the other clauses stay.
    static func strip(_ g: KGoal) -> KGoal {
        return KGoal(v: g.v, principal: g.principal, ontDigest: g.ontDigest, nlDigest: g.nlDigest, sources: g.sources,
                     grants: g.grants.filter { !dependsOn(g.holes, $0.gid) }, prohibits: g.prohibits, bounds: g.bounds,
                     validity: g.validity, deleg: g.deleg, escalateOn: g.escalateOn, wildcardAck: g.wildcardAck, holes: [])
    }

    static func lower(_ ont: KOntology, _ g: KGoal) -> KPol {
        var preds: [KLPred] = []
        for x in g.grants { preds.append(KLPred(gid: x.gid, verb: x.verb, res: resolveSel(ont, x.res), cond: nnf(x.cond, true))) }
        var prohs: [KLProh] = []
        for x in g.prohibits { prohs.append(KLProh(pid: x.pid, verbs: KTypes.prohVerbs(ont, x.target), res: resolveSel(ont, x.res), cond: nnf(x.cond, true))) }
        var ceils: [KLCeil] = []
        for x in g.bounds { ceils.append(KLCeil(bid: x.bid, sel: resolveBSel(ont, x.sel), core: x.core)) }
        var escs: [KNC] = []
        for x in g.escalateOn { escs.append(nnf(x, true)) }
        return KPol(preds: preds, prohs: prohs, ceils: ceils, escs: escs, validity: g.validity, deleg: g.deleg)
    }

    /// C: ill-typed goals are rejected with reasons (no coercion); a goal with holes compiles to its most restrictive completion.
    static func compile(_ ont: KOntology, _ g: KGoal) -> KCResult {
        let rs = KTypes.reasons(ont, g)
        if !rs.isEmpty { return KCResult(policy: nil, reasons: rs) }
        return KCResult(policy: lower(ont, strip(g)), reasons: rs)
    }

    // ---- encoders of the compiled policy ----

    private static func resPat(_ o: inout [KTok], _ p: KResPat) {
        switch p {
        case .star: KEnc.kw(&o, 630)
        case let .set(ids): KEnc.kw(&o, 631); KEnc.strs(&o, ids)
        }
    }

    private static func nc(_ o: inout [KTok], _ c: KNC) {
        switch c {
        case .ntrue: KEnc.kw(&o, 600)
        case .nfalse: KEnc.kw(&o, 601)
        case let .atom(op, l, r): KEnc.kw(&o, 602); KEnc.op(&o, op); KEnc.term(&o, l); KEnc.term(&o, r)
        case let .and(a, b): KEnc.kw(&o, 603); nc(&o, a); nc(&o, b)
        case let .or(a, b): KEnc.kw(&o, 604); nc(&o, a); nc(&o, b)
        }
    }

    static func encPol(_ p: KPol) -> [KTok] {
        var o: [KTok] = []
        KEnc.kw(&o, 650)
        KEnc.int(&o, Int64(p.preds.count))
        for x in p.preds { KEnc.kw(&o, 620); KEnc.str(&o, x.gid); KEnc.str(&o, x.verb); resPat(&o, x.res); nc(&o, x.cond) }
        KEnc.int(&o, Int64(p.prohs.count))
        for x in p.prohs { KEnc.kw(&o, 640); KEnc.str(&o, x.pid); KEnc.strs(&o, x.verbs); resPat(&o, x.res); nc(&o, x.cond) }
        KEnc.int(&o, Int64(p.ceils.count))
        for x in p.ceils { KEnc.kw(&o, 610); KEnc.str(&o, x.bid); KEnc.strs(&o, x.sel.gids); KEnc.strs(&o, x.sel.verbs); KEnc.bcore(&o, x.core) }
        KEnc.int(&o, Int64(p.escs.count))
        for x in p.escs { nc(&o, x) }
        KEnc.validity(&o, p.validity)
        KEnc.deleg(&o, p.deleg)
        return o
    }
}
