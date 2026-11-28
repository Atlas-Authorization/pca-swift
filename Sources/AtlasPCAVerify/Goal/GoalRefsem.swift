import Foundation

/// An independent reading of the goal semantics D_G for the grammar the tests generate (conditions, grants, prohibitions, count /
/// sum / max / distinct bounds, validity, delegation). Three-valued: 0 false/deny, 1 unknown/escalate, 2 true/allow. Numbers are
/// JavaScript doubles, as in the reference. Unit and parameter values that are compared as JSON text use the sorted-key form
/// (a parsed object keeps no member order).
public enum PCAGoalRefsem {
    private static func and(_ a: Int, _ b: Int) -> Int { min(a, b) }
    private static func or(_ a: Int, _ b: Int) -> Int { max(a, b) }
    private static func not(_ a: Int) -> Int { 2 - a }
    private static func b2t(_ b: Bool) -> Int { b ? 2 : 0 }
    /// `JSON.stringify(a) === JSON.stringify(b)`: an absent value (undefined) is not the text of a null.
    private static func sameUnit(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if a == nil || b == nil { return a == nil && b == nil }
        return IV.same(GV.stable(a), GV.stable(b))
    }
    private static func nv(_ v: JSONValue?) -> JSONValue { v ?? .null }

    /// The value when it is an object (Kotlin's `G.m`).
    private static func mo(_ v: JSONValue?) -> JSONValue? {
        if let v = v, v.isObject { return v }
        return nil
    }

    private static func req(_ v: JSONValue?, _ what: String) throws -> JSONValue {
        guard let o = mo(v) else { throw IrError("\(what) expected") }
        return o
    }

    private static func has(_ m: JSONValue, _ k: JSONValue?) -> Bool {
        guard let s = k?.asString else { return false }
        return m.asObject?[JKey(s)] != nil
    }

    /// Number(x) with an absent or null member as 0.
    private static func n(_ o: JSONValue?) -> Double { JS.toNumber(nv(o)) }

    /// JavaScript `===` on two parsed JSON scalars.
    private static func seq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        let x = IV.num(a)
        let y = IV.num(b)
        if x != nil || y != nil { return x != nil && y != nil && x! == y! }
        return nv(a) == nv(b)
    }

    private static func value(_ t: JSONValue?, _ a: JSONValue, _ h: JSONValue) throws -> JSONValue? {
        let k = GV.kind(t)
        if k == "param" {
            let ps = mo(GV.get(a, "params"))
            if GV.get(a, "params") == nil || GV.get(a, "params") == .null { throw IrError("params expected") }
            if let ps = ps, has(ps, GV.get(t, "path")), let p = GV.get(t, "path")?.asString { return mo(GV.get(ps, p)) }
            return nil
        }
        guard let tt = t else { throw IrError("value expected") }
        if k == "lit" { return mo(GV.get(tt, "v")) }
        let aggs = mo(GV.get(h, "aggs"))
        if let aggs = aggs, has(aggs, GV.get(tt, "bid")), let b = GV.get(tt, "bid")?.asString {
            return GV.obj([("k", .string("q")), ("q", nv(GV.get(aggs, b)))])
        }
        return nil
    }

    /// `v.q[k]`: a TypeError when `q` is null or absent; a member read off a number, string, boolean or array is absent (undefined), not a refusal.
    private static func qm(_ v: JSONValue, _ k: String) throws -> JSONValue? {
        guard let q = GV.get(v, "q"), q != .null else { throw IrError("q expected") }
        return GV.get(q, k)
    }
    private static func qn(_ v: JSONValue) throws -> JSONValue? { try qm(v, "n") }
    private static func qu(_ v: JSONValue) throws -> JSONValue? { try qm(v, "u") }

    private static func eq(_ x: JSONValue, _ y: JSONValue) throws -> Int {
        let kx = GV.kind(x)
        let ky = GV.kind(y)
        if kx == "q" && ky == "q" { return try sameUnit(qu(x), qu(y)) ? b2t(seq(qn(x), qn(y))) : 1 }
        if kx == "s" && ky == "s" { return b2t(seq(GV.get(x, "s"), GV.get(y, "s"))) }
        return 1
    }

    private static func lt(_ x: JSONValue, _ y: JSONValue) throws -> Int {
        if GV.kind(x) == "q" && GV.kind(y) == "q", try sameUnit(qu(x), qu(y)) { return try b2t(n(qn(x)) < n(qn(y))) }
        return 1
    }

    private static func inSet(_ x: JSONValue, _ y: JSONValue) throws -> Int {
        if GV.kind(y) != "set" { return 1 }
        var acc = 0
        for it in try GV.arr(GV.get(y, "items"), "items") { acc = or(acc, try eq(x, try req(it, "item"))) }
        return acc
    }

    private static func cmp(_ op: String, _ x: JSONValue?, _ y: JSONValue?) throws -> Int {
        guard let x = x, let y = y else { return 1 }
        switch op {
        case "eq": return try eq(x, y)
        case "ne": return not(try eq(x, y))
        case "lt": return try lt(x, y)
        case "gte": return not(try lt(x, y))
        case "gt": return try lt(y, x)
        case "lte": return not(try lt(y, x))
        case "in": return try inSet(x, y)
        default: return not(try inSet(x, y))
        }
    }

    private static func evalC(_ c: JSONValue?, _ a: JSONValue, _ h: JSONValue) throws -> Int {
        switch GV.kind(c) {
        case "true": return 2
        case "cmp":
            let op = GV.jsStr(GV.get(c, "op"))
            let l = try value(mo(GV.get(c, "l")), a, h)
            let r = try value(mo(GV.get(c, "r")), a, h)
            return try cmp(op, l, r)
        case "and":
            let x = try evalC(mo(GV.get(c, "a")), a, h)
            let y = try evalC(mo(GV.get(c, "b")), a, h)
            return and(x, y)
        case "or":
            let x = try evalC(mo(GV.get(c, "a")), a, h)
            let y = try evalC(mo(GV.get(c, "b")), a, h)
            return or(x, y)
        case "not": return not(try evalC(mo(GV.get(c, "c")), a, h))
        default: throw IrError("unknown condition")
        }
    }

    private static func includes(_ list: JSONValue?, _ x: JSONValue?) -> Bool {
        guard let l = list?.asArray else { return false }
        let target = nv(x)
        for o in l where o != .null && o == target { return true }
        return false
    }

    private static func includesList(_ l: [JSONValue], _ x: JSONValue?) -> Bool { includes(.array(l), x) }

    private static func resOk(_ s: JSONValue?, _ ont: JSONValue, _ r: JSONValue?) throws -> Bool {
        switch GV.kind(s) {
        case "any": return true
        case "exact": return seq(r, GV.get(s, "id"))
        case "oneof": return includes(GV.get(s, "ids"), r)
        case "related":
            for x in try GV.arr(GV.get(ont, "rels"), "rels") {
                let rel = GV.get(s, "rel")
                let anchor = GV.get(s, "anchor")
                if nv(rel) != .null && nv(rel) == nv(GV.get(x, "rel")) && nv(anchor) != .null && nv(anchor) == nv(GV.get(x, "anchor")) {
                    return includes(GV.get(x, "members"), r)
                }
            }
            return false
        case "all_of":
            for p in try GV.arr(GV.get(s, "parts"), "parts") { if !(try resOk(mo(p), ont, r)) { return false } }
            return true
        default: throw IrError("unknown selector")
        }
    }

    private static func verbsOf(_ ont: JSONValue, _ cls: JSONValue?) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for v in try GV.arr(GV.get(ont, "verbs"), "verbs") {
            if nv(cls) != .null && nv(cls) == nv(GV.get(v, "cls")) { out.append(nv(GV.get(v, "verb"))) }
        }
        return out
    }

    private static func inScope(_ sc: JSONValue?, _ a: JSONValue, _ x: JSONValue) -> Bool {
        switch GV.kind(sc) {
        case "session": return nv(GV.get(a, "sess")) == nv(GV.get(x, "sess"))
        case "principal": return nv(GV.get(a, "prin")) == nv(GV.get(x, "prin"))
        case "org": return nv(GV.get(a, "org")) == nv(GV.get(x, "org"))
        case "fleet": return includes(GV.get(sc, "agents"), GV.get(a, "agent")) && includes(GV.get(sc, "agents"), GV.get(x, "agent"))
        default: return false
        }
    }

    private static func inWin(_ w: JSONValue?, _ a: JSONValue, _ x: JSONValue) -> Bool {
        switch GV.kind(w) {
        case "task", "lifetime": return true
        case "sliding": return n(GV.get(x, "t")) > n(GV.get(a, "t")) - n(GV.get(w, "ms")) && n(GV.get(x, "t")) <= n(GV.get(a, "t"))
        case "period":
            let ms = n(GV.get(w, "ms"))
            return ms > 0 && ((n(GV.get(a, "t")) - n(GV.get(w, "t0"))) / ms).rounded(.down) == ((n(GV.get(x, "t")) - n(GV.get(w, "t0"))) / ms).rounded(.down)
        default: return false
        }
    }

    /// The decision (0 deny, 1 escalate, 2 allow); see `refExplain`.
    public static func refDecide(_ g: JSONValue, _ ont: JSONValue, _ a: JSONValue, _ h: JSONValue) throws -> Int {
        let r = try explain(g, ont, a, h)
        return r.d
    }

    /// {d, witness, prohibit}: witness is the first grant whose own decision is allow (only when d = 2); prohibit is the meet over the prohibitions.
    public static func refExplain(_ g: JSONValue, _ ont: JSONValue, _ a: JSONValue, _ h: JSONValue) throws -> JSONValue {
        let r = try explain(g, ont, a, h)
        return GV.obj([("d", .int(Int64(r.d))), ("witness", r.d == 2 ? r.witness : .null), ("prohibit", .int(Int64(r.prohibit)))])
    }

    private struct Explained {
        var d: Int
        var witness: JSONValue
        var prohibit: Int
    }

    private static func explain(_ g: JSONValue, _ ont: JSONValue, _ a: JSONValue, _ h: JSONValue) throws -> Explained {
        var d = 2
        var prohibit = 2
        var witness: JSONValue? = nil
        let validity = try req(GV.get(g, "validity"), "validity")
        let deleg = try req(GV.get(g, "deleg"), "deleg")
        let t = n(GV.get(a, "t"))
        let depth = n(GV.get(a, "depth"))
        if t < n(GV.get(validity, "notBefore")) || t > n(GV.get(validity, "notAfter")) { d = min(d, 0) }
        else if n(GV.get(validity, "maxIdle")) > 0 && n(GV.get(h, "last")) >= 0 && t - n(GV.get(h, "last")) > n(GV.get(validity, "maxIdle")) { d = min(d, 0) }
        else if depth < 0 || depth > n(GV.get(deleg, "maxDepth")) { d = min(d, 0) }
        for po in try GV.arr(GV.get(g, "prohibits"), "prohibits") {
            let p = try req(po, "prohibit")
            let tg = try req(GV.get(p, "target"), "target")
            var verbs: [JSONValue] = [nv(GV.get(tg, "verb"))]
            if GV.kind(tg) != "verb" { verbs = try verbsOf(ont, GV.get(tg, "cls")) }
            let v1 = b2t(includesList(verbs, GV.get(a, "verb")))
            let v2 = b2t(try resOk(mo(GV.get(p, "res")), ont, GV.get(a, "res")))
            let v3 = try evalC(mo(GV.get(p, "cond")), a, h)
            let m = and(v1, and(v2, v3))
            let pd = m == 2 ? 0 : (m == 1 ? 1 : 2)
            d = min(d, pd)
            prohibit = min(prohibit, pd)
        }
        for c in try GV.arr(GV.get(g, "escalateOn"), "escalateOn") { d = min(d, try evalC(mo(c), a, h) == 0 ? 2 : 1) }
        var best = 0
        for gro in try GV.arr(GV.get(g, "grants"), "grants") {
            let gr = try req(gro, "grant")
            let c0 = b2t(nv(GV.get(a, "verb")) == nv(GV.get(gr, "verb")) && (seq(GV.get(a, "depth"), .int(0)) || includes(GV.get(deleg, "mayTouch"), GV.get(gr, "gid"))))
            let c1 = b2t(try resOk(mo(GV.get(gr, "res")), ont, GV.get(a, "res")))
            let c2 = try evalC(mo(GV.get(gr, "cond")), a, h)
            let m = and(c0, and(c1, c2))
            var gd = m
            for bo in try GV.arr(GV.get(g, "bounds"), "bounds") {
                let b = try req(bo, "bound")
                let sel = mo(GV.get(b, "sel"))
                var gids: [JSONValue] = []
                if GV.kind(sel) == "gids" { gids = try GV.arr(GV.get(sel, "gids"), "gids") }
                var verbs: [JSONValue] = []
                if GV.kind(sel) == "effect" { verbs = try verbsOf(ont, GV.get(sel, "cls")) }
                if !(includesList(gids, GV.get(gr, "gid")) || includesList(verbs, GV.get(a, "verb"))) { continue }
                var items: [JSONValue] = []
                for ao in try GV.arr(GV.get(h, "adms"), "adms") {
                    let aoo = try req(ao, "adm")
                    let x = try req(GV.get(aoo, "act"), "act")
                    if (includesList(gids, GV.get(aoo, "gid")) || includesList(verbs, GV.get(x, "verb"))) && inScope(mo(GV.get(b, "scope")), a, x) && inWin(mo(GV.get(b, "window")), a, x) {
                        items.append(x)
                    }
                }
                items.append(a)
                let cap = try req(GV.get(b, "cap"), "cap")
                let agg = GV.jsStr(GV.get(b, "agg"))
                let ex: Int
                if agg == "count" {
                    ex = b2t(Double(items.count) > n(GV.get(cap, "n")))
                } else if agg == "sum" || agg == "max" {
                    var xs: [Double] = []
                    var ok = true
                    for it in items {
                        let v = try value(mo(GV.get(b, "value")), it, h)
                        var usable = false
                        if let vv = v, GV.kind(vv) == "q" { usable = try sameUnit(qu(vv), GV.get(cap, "u")) }
                        if !usable {
                            ok = false
                            break
                        }
                        xs.append(n(try qn(v!)))
                    }
                    if !ok {
                        ex = 1
                    } else if agg == "sum" {
                        var s = 0.0
                        for x in xs { s += x }
                        ex = b2t(s > n(GV.get(cap, "n")))
                    } else if xs.isEmpty {
                        ex = 1
                    } else {
                        var mx = -Double.infinity
                        for x in xs {
                            if x.isNaN {
                                mx = Double.nan
                                break
                            }
                            if x > mx { mx = x }
                        }
                        ex = b2t(mx > n(GV.get(cap, "n")))
                    }
                } else {
                    var ks: [String] = []
                    var seen = Set<JKey>()
                    var ok = true
                    for it in items {
                        let ps = mo(GV.get(it, "params"))
                        guard let pso = ps, has(pso, GV.get(b, "key")), let keyName = GV.get(b, "key")?.asString else {
                            ok = false
                            break
                        }
                        let text = GV.stable(GV.get(pso, keyName))
                        if seen.insert(JKey(text)).inserted { ks.append(text) }
                    }
                    ex = ok ? b2t(Double(ks.count) > n(GV.get(cap, "n"))) : 1
                }
                let onExceedDeny = nv(GV.get(b, "onExceed")) == .string("deny")
                gd = min(gd, ex == 2 ? (onExceedDeny ? 0 : 1) : (ex == 1 ? 1 : 2))
            }
            if gd == 2 && witness == nil {
                let gid = nv(GV.get(gr, "gid"))
                if gid != .null && gid.asString == nil { throw IrError("gid is not a string") }
                if gid != .null { witness = gid }
            }
            best = max(best, gd)
        }
        d = min(d, best)
        return Explained(d: d, witness: witness ?? .null, prohibit: prohibit)
    }
}
