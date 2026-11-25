import Foundation

/// Partial evaluation, residual policies and "what may I do?" discovery. Everything here is advisory: the verifier stays authoritative.
/// `residual` specialises a policy to what is known about a request and leaves the unknown parameters symbolic; only constants are
/// folded, with the evaluator's own three-valued rules, so no condition is ever rewritten. A veto that reads an unknown field stays
/// unknown and keeps firing.
///
/// Policies, residuals and envelopes are plain JSON trees (`JSONValue`); a missing member is `nil` (JavaScript `undefined`).
fileprivate enum RsH {
    typealias V = JSONValue
    typealias A = PCAAnalyzer

    static let UNKNOWN_VERB = "\u{0}unknown-verb\u{0}"
    static let UNKNOWN_RESOURCE = "\u{0}unknown-resource\u{0}"

    /// A path is symbolic when it is an unknown path, below one, or an ancestor of one.
    static func isUnknownPath(_ path: V?, _ unk: [V]) throws -> Bool {
        guard case let .string(p)? = path else { return false }
        for u in unk {
            if let us = u.asString {
                if IV.same(p, us) || IV.startsWith(p, us + ".") || IV.startsWith(us, p + ".") { return true }
            } else {
                // `path.startsWith(u + '.')` coerces, `u.startsWith(..)` on a non-string is a TypeError
                if IV.startsWith(p, JS.toString(u) + ".") { return true }
                throw JSError("u.startsWith is not a function")
            }
        }
        return false
    }

    enum PE {
        case const(String, V?)
        case cond(V)
        var isCond: Bool { if case .cond = self { return true } else { return false } }
        func isConst(_ v: String) -> Bool { if case let .const(x, _) = self { return x == v } else { return false } }
        var out: V { switch self { case let .const(_, s): return s ?? .null; case let .cond(c): return c } }
    }

    static func triName(_ t: Predicates.Tri) -> String {
        switch t { case .t: return "true"; case .f: return "false"; case .u: return "unknown" }
    }

    static func peGroup(_ list: V?, _ ctx: V, _ unk: [V], _ c: V, _ key: String, _ absorbing: String, _ neutral: String) throws -> PE {
        guard case let .array(a)? = list, !a.isEmpty else { return .const("unknown", c) }
        let rs = try a.map { try pe($0, ctx, unk) }
        if rs.contains(where: { $0.isConst(absorbing) }) { return .const(absorbing, c) }
        let kept = rs.filter { !$0.isConst(neutral) }
        if kept.isEmpty { return .const(neutral, c) }
        if kept.allSatisfy({ !$0.isCond }) { return .const("unknown", c) }
        let cs = kept.map { $0.out }
        return .cond(cs.count == 1 ? cs[0] : .object([JKey(key): .array(cs)]))
    }

    static func pe(_ c: V?, _ ctx: V, _ unk: [V]) throws -> PE {
        guard let cv = c, cv.isObject else { return .const("unknown", c) }
        if A.isGroup(cv) {
            // same precedence as the evaluator (all_of, any_of, not): an empty or malformed group is unknown and never falls through
            if A.inObj(cv, "all_of") { return try peGroup(A.mem(cv, "all_of"), ctx, unk, cv, "all_of", "false", "true") }
            if A.inObj(cv, "any_of") { return try peGroup(A.mem(cv, "any_of"), ctx, unk, cv, "any_of", "true", "false") }
            let r = try pe(A.mem(cv, "not"), ctx, unk)
            switch r {
            case let .cond(x): return .cond(.object(["not": x]))
            case let .const(v, _): return .const(v == "true" ? "false" : v == "false" ? "true" : "unknown", cv)
            }
        }
        if A.isLeaf(cv) {
            for k in ["field", "ref", "collection"] {
                if try isUnknownPath(A.mem(cv, k), unk) { return .cond(cv) }
            }
        }
        return .const(triName(Predicates.conditionTri(cv, ctx, SafeRegex.Budget())), cv)
    }

    enum PA { case v(String), cs([V]) }

    /// AND of a `where` list (implicit all_of): a const, or the symbolic remainder.
    static func peAll(_ where_: V?, _ ctx: V, _ unk: [V]) throws -> PA {
        guard let w = where_ else { return .v("true") }
        guard case let .array(list) = w else { return .v("unknown") }
        let rs = try list.map { try pe($0, ctx, unk) }
        if rs.contains(where: { $0.isConst("false") }) { return .v("false") }
        let kept = rs.filter { !$0.isConst("true") }
        if kept.isEmpty { return .v("true") }
        if kept.allSatisfy({ !$0.isCond }) { return .v("unknown") }
        return .cs(kept.map { $0.out })
    }

    static func contextOf(_ k: V?) -> V {
        var action: JObject = [
            "verb": JS.present(A.mem(k, "verb")) ?? .string(UNKNOWN_VERB),
            "resource": JS.present(A.mem(k, "resource")) ?? .string(UNKNOWN_RESOURCE),
            "params": .object(JSLoose.spread(A.mem(k, "params"))),
        ]
        if let rc = A.mem(k, "reversibilityClass") { action["reversibility_class"] = rc }
        return .object(["action": .object(action), "subject": .object(JSLoose.spread(A.mem(k, "subject"))), "env": .object(JSLoose.spread(A.mem(k, "env")))])
    }

    static func flatten(_ m: A.Model) -> [A.Model] { [m] + m.meets.flatMap(flatten) }

    /// `predicateMatches({verb, resource}, ctx)` over a pattern whose undefined members are left out.
    static func pm(_ verb: V?, _ resource: V?, _ ctx: V) -> Bool {
        Predicates.predicateMatches(A.obj([("verb", verb), ("resource", resource)]), ctx, SafeRegex.Budget())
    }

    static func emptyPart() -> JObject { ["predicates": .array([]), "caveats": .array([]), "vetoes": .array([]), "tighten": .array([])] }

    static func residualPart(_ part: A.Model, _ ctx: V, _ unk: [V], _ verbKnown: Bool, _ resKnown: Bool) throws -> JObject {
        var predicates: [V] = []
        for p in part.predicates {
            guard p.isObject || p.isArray else { continue }
            let pv = A.mem(p, "verb"), pr = A.mem(p, "resource")
            if verbKnown && !pm(pv, .string("*"), ctx) { continue }
            if resKnown && !pm(.string("*"), pr, ctx) { continue }
            let w = try peAll(A.mem(p, "where"), ctx, unk)
            var cs: [V]?
            switch w {
            case let .v(x): if x != "true" { continue } // false and unknown both fail closed for a permit
            case let .cs(c): cs = c
            }
            predicates.append(A.obj([("verb", verbKnown ? JSONValue.string("*") : pv), ("resource", !resKnown ? pr : nil), ("where", cs.map { JSONValue.array($0) })]))
        }
        var vetoes: [V] = []
        for v in part.vetoes { if let r = try peVeto(v, ctx, unk, verbKnown, resKnown) { vetoes.append(r) } }
        var tighten: [V] = []
        for t in part.tighten {
            let tw = try A.rd(t, "when")
            let r = try pe(tw, ctx, unk) // a veto-polarity rule that cleanly cannot hold is dropped
            if r.isConst("false") { continue }
            var nt = JSLoose.spread(t)
            if case let .cond(c) = r { nt[JKey("when")] = c } else { nt[JKey("when")] = tw }
            tighten.append(.object(nt))
        }
        return ["predicates": .array(predicates), "caveats": .array(part.caveats), "vetoes": .array(vetoes), "tighten": .array(tighten)]
    }

    static func peVeto(_ v: V, _ ctx: V, _ unk: [V], _ verbKnown: Bool, _ resKnown: Bool) throws -> V? {
        let when = try A.rd(v, "when")
        let wv = try A.rd(when, "verb")
        if verbKnown && !pm(wv, .string("*"), ctx) { return nil }
        let wr = try A.rd(when, "resource")
        if resKnown && wr != nil && !pm(.string("*"), wr, ctx) { return nil }
        let w = try peAll(try A.rd(when, "where"), ctx, unk)
        var keep: [V]?
        switch w {
        case let .v(x): if x == "false" { return nil } // veto polarity: a clean false removes the veto; true and unknown mean it applies
        case let .cs(c): keep = c
        }
        var out: JObject = [:]
        if let id = try A.rd(v, "id") { out["id"] = id }
        if let k = try A.rd(v, "kind") { out["kind"] = k }
        out["when"] = A.obj([("verb", verbKnown ? JSONValue.string("*") : wv), ("resource", !resKnown ? wr : nil), ("where", keep.map { JSONValue.array($0) })])
        if let over = try A.rd(v, "over"), JS.truthy(over) {
            let opath = A.mem(over, "path")
            if try isUnknownPath(opath, unk) { out["over"] = over }
            else {
                let found = opath?.asString.flatMap { Predicates.resolve(ctx, $0) }
                var isOver = true
                if let x = found, let d = IV.num(x), d.isFinite, d >= 0 { isOver = JSLoose.gt(x, A.mem(over, "threshold")) }
                if !isOver { return nil }
            }
        }
        let unless = try A.rd(v, "unless")
        if let u = unless, JS.truthy(u), IV.same(try A.rd(v, "kind")?.asString, "approval") { out["unless"] = u } // evidence of approval: carried, never drops the veto
        else if let u = unless, JS.truthy(u) {
            switch try peAll(u, ctx, unk) {
            case let .cs(c): out["unless"] = .array(c)
            case let .v(x): if x == "true" { return nil } // the exception certainly holds: the veto never applies
            }
        }
        return .object(out)
    }

    // ---- what may I do ----

    struct NumRange {
        var lo: V?, hi: V?
        var loInc = false, hiInc = false
        var json: V { A.obj([("lo", lo), ("hi", hi), ("loInclusive", loInc ? .bool(true) : nil), ("hiInclusive", hiInc ? .bool(true) : nil)]) }
        var loN: Double { lo.map { JS.toNumber($0) } ?? -.infinity }
        var hiN: Double { hi.map { JS.toNumber($0) } ?? .infinity }
    }

    static func mergeRanges(_ rs: [NumRange]) -> [NumRange] {
        func cmp(_ a: NumRange, _ b: NumRange) -> Double {
            JSLoose.or(a.loN - b.loN) { (b.loInc ? 1 : 0) - (a.loInc ? 1 : 0) }
        }
        let idx = rs.indices.sorted { i, j in
            let c = cmp(rs[i], rs[j])
            return c != 0 ? c < 0 : i < j
        }
        var out: [NumRange] = []
        for i in idx {
            let r = rs[i]
            if var last = out.last, last.hiN >= r.loN, !(last.hiN == r.loN && !last.hiInc && !r.loInc) {
                if r.hiN > last.hiN || (r.hiN == last.hiN && r.hiInc) {
                    last.hi = r.hi
                    last.hiInc = r.hiInc
                    out[out.count - 1] = last
                }
            } else { out.append(r) }
        }
        return out
    }

    static func cellRange(_ value: V, _ T: [Double]) -> NumRange {
        let x = JS.toNumber(value)
        if T.contains(where: { $0 == x }) { return NumRange(lo: value, hi: value, loInc: true, hiInc: true) }
        var r = NumRange()
        if let b = T.reversed().first(where: { $0 < x }) { r.lo = A.num(b) }
        if let a = T.first(where: { $0 > x }) { r.hi = A.num(a) }
        return r
    }

    final class SeenVal {
        let value: V?
        var allow = false, escalate = false
        init(_ v: V?) { value = v }
    }
    final class SeenSet {
        var order: [SeenVal] = []
        var idx: [JKey: SeenVal] = [:]
    }

    static func sortedUnits(_ xs: [String]) -> V { .array(xs.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.map { .string($0) }) }
}

extension PCAAnalyzer {
    /// hashCanonical (strict canonical form) of the original policy, so a PCActn can cite the policy a residual was planned against.
    static func policyDigestOf(_ model: Model) throws -> String {
        let meet = try model.meets.map { V.string(try policyDigestOf($0)) }
        let v: V = .object(["predicates": .array(model.predicates), "caveats": .array(model.caveats), "vetoes": .array(model.vetoes),
                            "tighten": .array(model.tighten), "meet": .array(meet)])
        guard let h = IV.strictHash(v) else { throw JSError(IV.strictCanonError(v) ?? "canonicalize: outside the strict profile") }
        return h
    }

    /// Specialise `policy` to `known`; everything under `opts.unknown` stays symbolic. Returns {decision: never | always | conditional,
    /// reason?, policy, policyDigest}.
    static func residual(_ policy: V?, _ known: V?, _ opts: V? = nil) throws -> V {
        let model = try toModel(policy)
        let digest = try policyDigestOf(model)
        let o: V = opts ?? .object([:])
        let verbKnown = try rd(known, "verb") != nil
        let resKnown = mem(known, "resource") != nil && mem(o, "resourceUnknown") != .bool(true)
        // a verb / resource that is not known is symbolic too, or a condition on it would be folded against a placeholder
        var unk: [V] = try JS.spread(JS.present(try rd(o, "unknown")) ?? .array([.string("action.params")]))
        if !verbKnown { unk.append(.string("action.verb")) }
        if !resKnown { unk.append(.string("action.resource")) }
        let ctx = RsH.contextOf(known)
        func never(_ reason: String) -> V {
            .object(["decision": .string("never"), "reason": .string(reason), "policy": .object(RsH.emptyPart()), "policyDigest": .string(digest)])
        }
        if !model.caveatSat { return never("caveats unsatisfiable: \(reasonOf(model))") }
        if let rc = mem(known, "reversibilityClass"), let cap = model.revCap {
            let idx = revIndex(rc)
            if idx < 0 || idx > cap { return never("reversibility class exceeds the caveat cap") }
        }
        let parts = try RsH.flatten(model).map { try RsH.residualPart($0, ctx, unk, verbKnown, resKnown) }
        var pol = parts[0]
        if parts.count > 1 { pol["meet"] = .array(parts.dropFirst().map { .object($0) }) }
        var decision = "conditional"
        func list(_ p: JObject, _ k: String) -> [V] { p[JKey(k)]?.asArray ?? [] }
        if parts.contains(where: { list($0, "predicates").isEmpty }) { return never("no permit survives the known facts") }
        for p in parts {
            let certain = list(p, "vetoes").first { v in
                let w = mem(v, "when")
                return IV.same(mem(v, "kind")?.asString, "deny") && (mem(w, "resource") == nil || IV.same(mem(w, "resource")?.asString, "*"))
                    && (mem(w, "where") == nil || (mem(w, "where")?.asArray?.isEmpty ?? false)) && mem(v, "unless") == nil && mem(v, "over") == nil
            }
            if let c = certain { return never("veto \(JS.toString(mem(c, "id"))) applies to every completion") }
        }
        if parts.allSatisfy({ p in list(p, "predicates").contains { mem($0, "where") == nil } && list(p, "vetoes").isEmpty && list(p, "tighten").isEmpty }) {
            decision = "always"
        }
        return .object(["decision": .string(decision), "policy": .object(pol), "policyDigest": .string(digest)])
    }

    /// The residual as a policy the analyzer and the real evaluator both understand.
    public static func residualPolicy(_ r: JSONValue?) throws -> JSONValue {
        var own = try JSLoose.rest(try rd(r, "policy"), without: "meet")
        let meet = mem(try rd(r, "policy"), "meet")
        if let m = meet, JS.truthy(m) {
            guard case let .array(ms) = m else { throw JSError("meet.map is not a function") }
            own[JKey("meet")] = .array(ms.map { .object(JSLoose.spread($0)) })
        }
        return .object(own)
    }

    /// Ternary decision of a residual once the unknown fields are bound (allow | escalate | deny).
    public static func evaluateResidual(_ r: JSONValue?, _ ctx: JSONValue?) throws -> String {
        if IV.same(try rd(r, "decision")?.asString, "never") { return "deny" }
        let a = try rd(ctx, "action")
        var o: [(String, V?)] = [("verb", try rd(a, "verb")), ("resource", try rd(a, "resource"))]
        if let p = try rd(a, "params"), JS.truthy(p) { o.append(("params", p)) }
        if let s = try rd(ctx, "subject"), JS.truthy(s) { o.append(("subject", s)) }
        if let e = try rd(ctx, "env"), JS.truthy(e) { o.append(("env", e)) }
        if let rc = try rd(a, "reversibility_class"), JS.truthy(rc) { o.append(("reversibilityClass", rc)) }
        return try decideAction(try toModel(try residualPolicy(r)), obj(o))
    }

    /// Per verb shape ({verb, params}): is it autonomous, approval-only or denied for the known principal, and which parameter values and
    /// resources are still allowed. Advisory; exact on the decided fragment, otherwise `approximate`.
    public static func whatMayIDo(_ policy: JSONValue?, _ verbs: JSONValue?, _ known: JSONValue? = nil, _ o: JSONValue? = nil) throws -> JSONValue {
        let kn: V = known ?? .object([:])
        let oo: V = o ?? .object([:])
        var out: [V] = []
        let mcv = try rd(oo, "maxCombinations")
        let mx: Double = (mcv?.isNumber ?? false) ? JS.toNumber(mcv) : DEFAULT_MAX_COMBINATIONS
        for shape in try JS.spread(verbs) {
            let sverb = try rd(shape, "verb")
            var k2 = JSLoose.spread(kn)
            k2[JKey("verb")] = sverb
            let res = try residual(policy, .object(k2), nil)
            var env: JObject = ["status": .string("denied"), "params": .object([:]),
                                "resources": .object(["autonomous": .array([]), "withApproval": .array([]), "other": .bool(false)]),
                                "policyDigest": mem(res, "policyDigest") ?? .null, "advisory": .bool(true)]
            if let v = sverb { env["verb"] = v }
            if let rem = try rd(oo, "remaining"), JS.truthy(rem) { env["remaining"] = .object(JSLoose.spread(rem)) }
            if let md = try rd(oo, "missingDischarges"), JS.truthy(md) { env["missingDischarges"] = .array(try JS.spread(md)) }
            if IV.same(mem(res, "decision")?.asString, "never") {
                if let r = mem(res, "reason") { env["reason"] = r }
                out.append(.object(env))
                continue
            }
            let rp = try toModel(try residualPolicy(res))
            let sparams = try rd(shape, "params")
            guard let sp = sparams, sp != .null else { throw JSError("Cannot convert undefined or null to object") }
            let names = JSLoose.keys(sp)
            var extra: [(path: String, cond: V)] = []
            for name in names {
                let d = JSLoose.get(sp, name)
                if let vals = try rd(d, "values") {
                    let p = "action.params.\(name)"
                    extra.append((p, .object(["field": .string(p), "op": .string("in"), "value": vals])))
                }
            }
            for name in names {
                let d = JSLoose.get(sp, name)
                let p = "action.params.\(name)"
                if let mn = try rd(d, "min") { extra.append((p, .object(["field": .string(p), "op": .string("gte"), "value": mn]))) }
                if let mxv = try rd(d, "max") { extra.append((p, .object(["field": .string(p), "op": .string("lte"), "value": mxv]))) }
            }
            var pr = try collectProbes(ProbeInputs(predicateSets: [try probeSet(rp)], extraFieldConditions: extra, varyReversibility: rp.revCap != nil))
            pr.verbs = [sverb]
            if productSize(pr) > mx {
                env["status"] = .string("needs-approval")
                env["approximate"] = .bool(true)
                env["reason"] = .string("representative grid exceeded the bound; no domain is claimed")
                out.append(.object(env))
                continue
            }
            if let kr = mem(kn, "resource") { pr.resources = [kr] }
            var seen: [JKey: RsH.SeenSet] = [:]
            var resSeen: [JKey: (allow: Bool, escalate: Bool)] = [:]
            var anyAllow = false, anyEscalate = false, freshRes = false
            try eachRep(pr) { rep in
                let d = try decide(rp, rep)
                if d == "deny" { return false }
                if d == "allow" { anyAllow = true } else { anyEscalate = true }
                let act = repToAction(rep)
                let params = mem(act, "params")
                for name in names {
                    let v = mem(params, name)
                    let set = seen[JKey(name)] ?? RsH.SeenSet()
                    seen[JKey(name)] = set
                    let k = JKey(v == nil ? "\u{0}absent" : JS.stringify(v!))
                    let cur: RsH.SeenVal
                    if let c = set.idx[k] { cur = c } else { cur = RsH.SeenVal(v); set.idx[k] = cur; set.order.append(cur) }
                    if d == "allow" { cur.allow = true } else { cur.escalate = true }
                }
                guard let rname = mem(act, "resource")?.asString else { throw JSError("act.resource.startsWith is not a function") }
                var rr = resSeen[JKey(rname)] ?? (false, false)
                if d == "allow" { rr.allow = true } else { rr.escalate = true }
                resSeen[JKey(rname)] = rr
                if IV.startsWith(rname, "\u{0}") { freshRes = true }
                return false
            }
            env["status"] = .string(anyAllow ? "autonomous" : anyEscalate ? "needs-approval" : "denied")
            var envParams: JObject = [:]
            for name in names {
                let decl = JSLoose.get(sp, name)
                let T = try thresholdsOf(rp, "action.params.\(name)")
                let vals = seen[JKey(name)]?.order ?? []
                let dmin = try rd(decl, "min"), dmax = try rd(decl, "max")
                let nums = vals.filter { x in
                    guard let v = x.value, v.isNumber else { return false }
                    return (dmin == nil || JS.toNumber(v) >= JS.toNumber(dmin)) && (dmax == nil || JS.toNumber(v) <= JS.toNumber(dmax))
                }
                let strs = vals.filter { $0.value?.asString != nil }
                let dvalues = try rd(decl, "values")
                if IV.same(try rd(decl, "type")?.asString, "integer") || !nums.isEmpty {
                    func clip(_ r: RsH.NumRange) -> RsH.NumRange {
                        var n = r
                        if let lo = dmin, r.lo == nil || JSLoose.lt(r.lo, lo) { n.lo = lo; n.loInc = true }
                        if let hi = dmax, r.hi == nil || JSLoose.gt(r.hi, hi) { n.hi = hi; n.hiInc = true }
                        return n
                    }
                    func ranges(_ pick: (RsH.SeenVal) -> Bool) -> V {
                        .array(RsH.mergeRanges(nums.filter(pick).map { clip(RsH.cellRange($0.value!, T)) }).map { $0.json })
                    }
                    envParams[JKey(name)] = .object(["kind": .string("numeric"), "autonomous": ranges { $0.allow }, "withApproval": ranges { $0.escalate && !$0.allow }])
                } else if dvalues != nil || !strs.isEmpty {
                    func pickList(_ f: (RsH.SeenVal) -> Bool) -> V {
                        RsH.sortedUnits(strs.filter { f($0) && !IV.startsWith($0.value!.asString!, "\u{0}") }.map { $0.value!.asString! })
                    }
                    let fresh = strs.first { IV.startsWith($0.value!.asString!, "\u{0}") }
                    envParams[JKey(name)] = .object([
                        "kind": .string("enum"), "autonomous": pickList { $0.allow }, "withApproval": pickList { $0.escalate && !$0.allow },
                        "otherAutonomous": .bool(dvalues == nil && fresh?.allow == true),
                        "otherWithApproval": .bool(dvalues == nil && fresh != nil && fresh!.escalate && !fresh!.allow),
                    ])
                } else { envParams[JKey(name)] = .object(["kind": .string("unconstrained")]) }
            }
            env["params"] = .object(envParams)
            let named = resSeen.filter { !IV.startsWith($0.key.s, "\u{0}") }
            env["resources"] = .object(["autonomous": RsH.sortedUnits(named.filter { $0.value.allow }.map { $0.key.s }),
                                        "withApproval": RsH.sortedUnits(named.filter { $0.value.escalate && !$0.value.allow }.map { $0.key.s }),
                                        "other": .bool(freshRes)])
            if !rp.undecidable.isEmpty {
                env["approximate"] = .bool(true)
                env["reason"] = .string("over-approximated (\(rp.undecidable.joined(separator: "; ")))")
            }
            out.append(.object(env))
        }
        return .array(out)
    }
}
