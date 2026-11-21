import Foundation

/// Boundary examples and signed goal tests over the IR and its reference semantics. An action is classified per coordinate
/// (verb, resource, relation bits, each parameter) against the literals of the policies; `cells` enumerates one representative
/// per decision cell. Goals, acts and histories are parsed-JSON objects (`JSONValue`).
public enum PCAGoalExamples {
    /// A relation declared by the policies: `rel` over `anchor`.
    public struct Rel {
        public var rel: String
        public var anchor: String
    }

    /// The quantity literals of one unit key (sorted distinct values).
    public struct QGroup {
        var key: String
        var vals: [Int64]
    }

    public struct QParam {
        var p: String
        var groups: [QGroup]
    }

    /// The discrete literals of one parameter ("s:" + text, sorted distinct).
    public struct DParam {
        var p: String
        var vals: [String]
    }

    /// The classification space of one or more goals. Groups keep their insertion order (it fixes the order of the cases).
    public struct Space {
        public var verbs: [String] = []
        public var resources: [String] = []
        public var rels: [Rel] = []
        var q: [QParam] = []
        var d: [DParam] = []

        public init() {}

        func qGroups(_ p: String) -> [QGroup]? {
            for x in q where IV.same(x.p, p) { return x.groups }
            return nil
        }

        func dVals(_ p: String) -> [String]? {
            for x in d where IV.same(x.p, p) { return x.vals }
            return nil
        }

        mutating func addQ(_ p: String, _ key: String, _ v: Int64) {
            var pi: Int? = nil
            for i in 0..<q.count where IV.same(q[i].p, p) { pi = i; break }
            if pi == nil {
                q.append(QParam(p: p, groups: []))
                pi = q.count - 1
            }
            let a: Int = pi!
            var gi: Int? = nil
            for i in 0..<q[a].groups.count where IV.same(q[a].groups[i].key, key) { gi = i; break }
            if gi == nil {
                q[a].groups.append(QGroup(key: key, vals: []))
                gi = q[a].groups.count - 1
            }
            let b: Int = gi!
            if !q[a].groups[b].vals.contains(v) { q[a].groups[b].vals.append(v) }
        }

        mutating func addD(_ p: String, _ k: String) {
            var pi: Int? = nil
            for i in 0..<d.count where IV.same(d[i].p, p) { pi = i; break }
            if pi == nil {
                d.append(DParam(p: p, vals: []))
                pi = d.count - 1
            }
            let a: Int = pi!
            for x in d[a].vals where IV.same(x, k) { return }
            d[a].vals.append(k)
        }

        public func toJson() -> JSONValue {
            var rs: [JSONValue] = []
            for r in rels { rs.append(GV.obj([("rel", .string(r.rel)), ("anchor", .string(r.anchor))])) }
            var qj = JObject()
            for pr in q {
                var inner = JObject()
                for g in pr.groups { inner[JKey(g.key)] = .array(g.vals.map { JSONValue.int($0) }) }
                qj[JKey(pr.p)] = .object(inner)
            }
            var dj = JObject()
            for pr in d { dj[JKey(pr.p)] = .array(pr.vals.map { JSONValue.string($0) }) }
            return GV.obj([
                ("verbs", .array(verbs.map { JSONValue.string($0) })), ("resources", .array(resources.map { JSONValue.string($0) })),
                ("rels", .array(rs)), ("q", .object(qj)), ("d", .object(dj)),
            ])
        }
    }

    // ---- small helpers ----

    /// An insertion-ordered set of strings compared by code points.
    fileprivate struct OSet {
        var items: [String] = []
        var seen: Set<JKey> = []
        mutating func add(_ s: String) {
            if seen.insert(JKey(s)).inserted { items.append(s) }
        }
        func has(_ s: String) -> Bool { seen.contains(JKey(s)) }
    }

    private static func mm(_ v: JSONValue?) -> JSONValue? {
        if let x = v, x.isObject { return x }
        return nil
    }

    private static func req(_ v: JSONValue?, _ what: String) throws -> JSONValue {
        guard let x = mm(v) else { throw IrError("\(what) expected an object") }
        return x
    }

    private static func sv(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw IrError("string expected") }
        return s
    }

    /// A JSON null is as absent as a missing member.
    private static func nn(_ v: JSONValue?) -> JSONValue? {
        if let x = v, x != .null { return x }
        return nil
    }

    private static func sortStrings(_ xs: [String]) -> [String] {
        var idx: [Int] = Array(0..<xs.count)
        idx.sort { (a: Int, b: Int) -> Bool in
            if IV.same(xs[a], xs[b]) { return a < b }
            return GV.less(xs[a], xs[b])
        }
        return idx.map { xs[$0] }
    }

    private static func hasPre(_ s: String, _ p: String) -> Bool { s.unicodeScalars.starts(with: p.unicodeScalars) }

    private static func dropScalars(_ s: String, _ n: Int) -> String {
        IV.text(s.unicodeScalars.dropFirst(n))
    }

    /// base64url(sha256(strict canonical form)).
    private static func hashCanonical(_ v: JSONValue) throws -> String {
        Base64URLStrict.encode(Canonical.sha256(Array(try Canonical.canonicalizeStrict(v).utf8)))
    }

    private static func emptyHist() -> JSONValue {
        GV.obj([("adms", .array([])), ("last", GV.num(-1)), ("aggs", .object(JObject()))])
    }

    public static func decisionOf(_ d: Int) -> String { d == 2 ? "allow" : (d == 1 ? "escalate" : "deny") }

    public static func rankOf(_ d: String?) -> Int { d == "allow" ? 0 : (d == "escalate" ? 1 : 2) }

    /// An action with the fixed envelope the examples use (one session, one principal, no delegation, time 0).
    public static func mkAct(_ verb: String?, _ res: String?, _ params: JSONValue?) -> JSONValue {
        GV.obj([
            ("verb", verb.map { JSONValue.string($0) } ?? .null), ("res", res.map { JSONValue.string($0) } ?? .null),
            ("params", params ?? .null), ("t", GV.num(0)), ("sess", .string("s")), ("prin", .string("p")), ("org", .string("o")),
            ("agent", .string("a")), ("depth", GV.num(0)),
        ])
    }

    /// The reference decision of a goal for an action, its history and its relation facts: {decision, witness, prohibited}.
    public static func decideCase(_ g: JSONValue, _ ont: JSONValue, _ c: JSONValue) throws -> JSONValue {
        let rels: JSONValue? = nn(GV.get(c, "rels"))
        var o: JSONValue = ont
        if let r = rels {
            guard var oo = ont.asObject else { throw IrError("ontology expected an object") }
            oo[JKey("rels")] = r
            o = .object(oo)
        }
        let hist: JSONValue? = nn(GV.get(c, "hist"))
        var h: JSONValue = emptyHist()
        if hist != nil { h = try req(hist, "hist") }
        let act: JSONValue = try req(GV.get(c, "act"), "act")
        let x: JSONValue = try PCAGoalRefsem.refExplain(g, o, act, h)
        guard let d = GV.safeInt(GV.get(x, "d")), let p = GV.safeInt(GV.get(x, "prohibit")) else { throw IrError("refExplain result malformed") }
        return GV.obj([("decision", .string(decisionOf(Int(d)))), ("witness", GV.get(x, "witness") ?? .null), ("prohibited", .bool(p < 2))])
    }

    /// The history of the admitted prefix of `acts`: an action the goal refuses is not recorded.
    public static func replay(_ g: JSONValue, _ ont: JSONValue, _ acts: [JSONValue], _ rels: [JSONValue]?) throws -> JSONValue {
        var adms: [JSONValue] = []
        var last: JSONValue = GV.num(-1)
        let relsV: JSONValue = rels.map { JSONValue.array($0) } ?? .null
        for a in acts {
            let h: JSONValue = GV.obj([("adms", .array(adms)), ("last", last), ("aggs", .object(JObject()))])
            let c: JSONValue = GV.obj([("act", a), ("hist", h), ("rels", relsV)])
            let v: JSONValue = try decideCase(g, ont, c)
            let w: JSONValue? = GV.get(v, "witness")
            if GV.get(v, "decision")?.asString == "allow" && w != nil && w! != .null {
                adms.append(GV.obj([("gid", w!), ("act", a)]))
                last = GV.get(a, "t") ?? .null
            }
        }
        return GV.obj([("adms", .array(adms)), ("last", last), ("aggs", .object(JObject()))])
    }

    // ---- space ----

    private static func qval(_ q: JSONValue?) throws -> Int64 {
        guard let n = GV.safeInt(GV.get(q, "n")) else { throw IrError("quantity is not a safe integer") }
        return n
    }

    private static func qkey(_ q: JSONValue) -> String {
        let u: JSONValue? = mm(GV.get(q, "u"))
        return GV.kind(u) == "money" ? "money:" + GV.jsStr(GV.get(u, "ccy")) : GV.kind(u)
    }

    private static func unitOfKey(_ key: String) -> JSONValue {
        hasPre(key, "money:") ? GV.obj([("k", .string("money")), ("ccy", .string(dropScalars(key, 6)))]) : GV.obj([("k", .string(key))])
    }

    private static func dkey(_ v: JSONValue?) throws -> String? {
        GV.kind(v) == "s" ? "s:" + GV.jsStr(GV.get(v, "s")) : nil
    }

    private static func walkCond(_ c: JSONValue?, _ f: (String, JSONValue?) throws -> Void) throws {
        switch GV.kind(c) {
        case "cmp":
            let l: JSONValue? = mm(GV.get(c, "l"))
            let r: JSONValue? = mm(GV.get(c, "r"))
            var p: String? = nil
            if GV.kind(l) == "param" { p = try sv(GV.get(l, "path")) } else if GV.kind(r) == "param" { p = try sv(GV.get(r, "path")) }
            let other: JSONValue? = GV.kind(l) == "param" ? r : l
            guard let path = p, GV.kind(other) == "lit" else { return }
            let v: JSONValue? = mm(GV.get(other, "v"))
            if GV.kind(v) == "set" {
                for i in try GV.arr(GV.get(v, "items"), "items") { try f(path, mm(i)) }
            } else {
                try f(path, v)
            }
        case "and", "or":
            try walkCond(mm(GV.get(c, "a")), f)
            try walkCond(mm(GV.get(c, "b")), f)
        case "not":
            try walkCond(mm(GV.get(c, "c")), f)
        default:
            break
        }
    }

    private static func parts(_ s: JSONValue?) throws -> [JSONValue?] {
        var out: [JSONValue?] = []
        let k = GV.kind(s)
        if k == "all_of" {
            for p in try GV.arr(GV.get(s, "parts"), "parts") { out.append(mm(p)) }
        } else if k != "any" {
            out.append(s)
        }
        return out
    }

    /// The space of the goals plus extra verbs.
    public static func buildSpace(_ goals: [JSONValue], _ extraVerbs: [String]) throws -> Space {
        var verbs = OSet()
        for v in extraVerbs { verbs.add(v) }
        var resources = OSet()
        var relKeys: [String] = []
        var relVals: [Rel] = []
        var sp = Space()

        func lit(_ p: String, _ v: JSONValue?) throws {
            if GV.kind(v) == "q" {
                let qq: JSONValue = try req(GV.get(v, "q"), "q")
                sp.addQ(p, qkey(qq), try qval(qq))
            } else if let k = try dkey(v) {
                sp.addD(p, k)
            }
        }
        func res(_ s: JSONValue?) throws {
            for xo in try parts(s) {
                guard let x = xo else { throw IrError("resource selector expected an object") }
                switch GV.kind(x) {
                case "exact": resources.add(try sv(GV.get(x, "id")))
                case "oneof": for i in try GV.arr(GV.get(x, "ids"), "ids") { resources.add(try sv(i)) }
                default:
                    let key = GV.jsStr(GV.get(x, "rel")) + "\u{0}" + GV.jsStr(GV.get(x, "anchor"))
                    let r = Rel(rel: try sv(GV.get(x, "rel")), anchor: try sv(GV.get(x, "anchor")))
                    var at: Int? = nil
                    for i in 0..<relKeys.count where IV.same(relKeys[i], key) { at = i; break }
                    if let i = at { relVals[i] = r } else { relKeys.append(key); relVals.append(r) }
                }
            }
        }
        for g in goals {
            for gro in try GV.arr(GV.get(g, "grants"), "grants") {
                let gr: JSONValue = try req(gro, "grant")
                verbs.add(try sv(GV.get(gr, "verb")))
                try res(mm(GV.get(gr, "res")))
                try walkCond(mm(GV.get(gr, "cond")), lit)
            }
            for po in try GV.arr(GV.get(g, "prohibits"), "prohibits") {
                let p: JSONValue = try req(po, "prohibit")
                let t: JSONValue? = mm(GV.get(p, "target"))
                if GV.kind(t) == "verb" { verbs.add(try sv(GV.get(t, "verb"))) }
                try res(mm(GV.get(p, "res")))
                try walkCond(mm(GV.get(p, "cond")), lit)
            }
            for c in try GV.arr(GV.get(g, "escalateOn"), "escalateOn") { try walkCond(mm(c), lit) }
            for bo in try GV.arr(GV.get(g, "bounds"), "bounds") {
                let b: JSONValue = try req(bo, "bound")
                let v: JSONValue? = mm(GV.get(b, "value"))
                if GV.get(b, "agg")?.asString == "sum" && GV.kind(v) == "param" {
                    try lit(try sv(GV.get(v, "path")), GV.obj([("k", .string("q")), ("q", GV.get(b, "cap") ?? .null)]))
                }
            }
        }
        sp.verbs = sortStrings(verbs.items)
        sp.resources = sortStrings(resources.items)
        // sorted by rel + anchor, ties keep insertion order
        var ridx: [Int] = Array(0..<relVals.count)
        ridx.sort { (a: Int, b: Int) -> Bool in
            let ka = relVals[a].rel + relVals[a].anchor
            let kb = relVals[b].rel + relVals[b].anchor
            if IV.same(ka, kb) { return a < b }
            return GV.less(ka, kb)
        }
        sp.rels = ridx.map { relVals[$0] }
        for i in 0..<sp.q.count {
            for j in 0..<sp.q[i].groups.count { sp.q[i].groups[j].vals.sort() }
        }
        for i in 0..<sp.d.count { sp.d[i].vals = sortStrings(sp.d[i].vals) }
        return sp
    }

    private static func classifyLit(_ sp: Space, _ p: String, _ l: JSONValue?) throws -> String {
        if l == nil || GV.kind(l) == "set" { return "missing" }
        let groups: [QGroup]? = sp.qGroups(p)
        let ds: [String]? = sp.dVals(p)
        if GV.kind(l) == "q" {
            let qq: JSONValue = try req(GV.get(l, "q"), "q")
            let key = qkey(qq)
            var g: [Int64]? = nil
            if let gs = groups { for x in gs where IV.same(x.key, key) { g = x.vals; break } }
            guard let vals = g else { return (groups != nil || ds != nil) ? "unit" : "any" }
            let v: Int64 = try qval(qq)
            if let i = vals.firstIndex(of: v) { return key + "=" + String(i) }
            var pos = 0
            while pos < vals.count && vals[pos] < v { pos += 1 }
            return key + "@" + String(pos)
        }
        let k: String? = try dkey(l)
        guard let dv = ds else { return groups != nil ? "unit" : "any" }
        if let kk = k {
            for x in dv where IV.same(x, kk) { return kk }
        }
        return "other"
    }

    private static func relBit(_ c: JSONValue, _ rel: String, _ anchor: String) throws -> Int {
        for xo in try GV.arr(GV.get(c, "rels"), "rels") {
            let x: JSONValue = try req(xo, "rel")
            if IV.same(GV.get(x, "rel")?.asString, rel) && IV.same(GV.get(x, "anchor")?.asString, anchor) {
                let act: JSONValue = try req(GV.get(c, "act"), "act")
                let members: [JSONValue] = try GV.arr(GV.get(x, "members"), "members")
                if let r = GV.get(act, "res"), members.contains(r) { return 1 }
                return 0
            }
        }
        return 0
    }

    private static func paramNames(_ sp: Space) -> [String] {
        var ps = OSet()
        for x in sp.q { ps.add(x.p) }
        for x in sp.d { ps.add(x.p) }
        return sortStrings(ps.items)
    }

    /// The decision cell of a case under a space (canonical string; the unit of precedents).
    public static func cellKey(_ sp: Space, _ c: JSONValue) throws -> String {
        let params: [String] = paramNames(sp)
        let act: JSONValue = try req(GV.get(c, "act"), "act")
        var l: [JSONValue] = []
        for r in sp.rels { l.append(GV.num(try relBit(c, r.rel, r.anchor))) }
        var pm = JObject()
        let actParams: JSONValue? = mm(GV.get(act, "params"))
        for p in params { pm[JKey(p)] = .string(try classifyLit(sp, p, actParams == nil ? nil : mm(GV.get(actParams, p)))) }
        var verb: JSONValue = .string("*")
        if let s = GV.get(act, "verb")?.asString, sp.verbs.contains(where: { IV.same($0, s) }) { verb = .string(s) }
        var res: JSONValue = .string("*")
        if let s = GV.get(act, "res")?.asString, sp.resources.contains(where: { IV.same($0, s) }) { res = .string(s) }
        return GV.stable(GV.obj([("v", verb), ("r", res), ("l", .array(l)), ("p", .object(pm))]))
    }

    private static let OTHER = "\u{0}other"
    public static let MAX_CELLS = 40000

    private static func paramOptions(_ sp: Space, _ p: String) -> [JSONValue?] {
        var out: [JSONValue?] = [nil] // the parameter absent
        var seen: Set<JKey> = []
        func add(_ v: JSONValue) {
            if seen.insert(JKey(GV.stable(v))).inserted { out.append(v) }
        }
        if let groups = sp.qGroups(p) {
            for g in groups {
                let isInstant = IV.same(g.key, "instant")
                for v in g.vals {
                    for x in [v - 1, v, v + 1] where x >= 0 || isInstant {
                        add(GV.obj([("k", .string("q")), ("q", GV.obj([("u", unitOfKey(g.key)), ("n", GV.num(x))]))]))
                    }
                }
                if hasPre(g.key, "money:") {
                    add(GV.obj([("k", .string("q")), ("q", GV.obj([("u", GV.obj([("k", .string("money")), ("ccy", .string("ZZZ"))])), ("n", GV.num(0))]))]))
                }
            }
        }
        if let ds = sp.dVals(p) {
            for k in ds { add(GV.obj([("k", .string("s")), ("s", .string(dropScalars(k, 2)))])) }
            add(GV.obj([("k", .string("s")), ("s", .string(OTHER))]))
        }
        return out
    }

    private static func build(_ sp: Space, _ params: [String], _ verb: String, _ resource: String, _ bits: Int, _ choice: [JSONValue?]) -> JSONValue {
        var pr = JObject()
        for i in 0..<params.count {
            if let c = choice[i] { pr[JKey(params[i])] = c }
        }
        var rels: [JSONValue] = []
        for i in 0..<sp.rels.count {
            var members: [JSONValue] = []
            if i < 62 && (bits & (1 << i)) != 0 { members.append(.string(resource)) }
            rels.append(GV.obj([("rel", .string(sp.rels[i].rel)), ("anchor", .string(sp.rels[i].anchor)), ("members", .array(members))]))
        }
        return GV.obj([("act", mkAct(verb, resource, .object(pr))), ("rels", .array(rels))])
    }

    /// One representative per decision cell: {cases, complete} (complete false when the grid exceeded MAX_CELLS: then a subset).
    public static func cells(_ sp: Space, _ verbsOpt: [String]?) throws -> JSONValue {
        var verbs: [String] = verbsOpt ?? sp.verbs
        if verbsOpt == nil { verbs.append("\u{0}other-verb") }
        var resources: [String] = sp.resources
        resources.append("\u{0}other-resource")
        let params: [String] = paramNames(sp)
        var pOpts: [[JSONValue?]] = []
        for p in params { pOpts.append(paramOptions(sp, p)) }
        let relBits = sp.rels.count
        var total = Double(verbs.count) * Double(resources.count) * pow(2.0, Double(relBits))
        for o in pOpts { total *= Double(o.count) }
        let complete = total <= Double(MAX_CELLS)
        var out: [JSONValue] = []
        var seen: Set<JKey> = []
        func push(_ c: JSONValue) throws {
            if seen.insert(JKey(try cellKey(sp, c))).inserted { out.append(c) }
        }
        let nbits: Int = relBits >= 31 ? Int.max : (1 << relBits)
        if complete {
            var idx: [Int] = Array(repeating: 0, count: params.count)
            for verb in verbs {
                for res in resources {
                    for bits in 0..<nbits {
                        for i in 0..<idx.count { idx[i] = 0 }
                        while true {
                            var choice: [JSONValue?] = []
                            for i in 0..<idx.count { choice.append(pOpts[i][idx[i]]) }
                            try push(build(sp, params, verb, res, bits, choice))
                            var k = 0
                            while k < idx.count {
                                idx[k] += 1
                                if idx[k] == pOpts[k].count {
                                    idx[k] = 0
                                    k += 1
                                } else { break }
                            }
                            if k == idx.count { break }
                        }
                    }
                }
            }
        } else {
            // subset: the all-defaults base plus every single-coordinate perturbation of it
            var base: [JSONValue?] = []
            for o in pOpts { base.append(o[min(2, o.count - 1)]) }
            for verb in verbs {
                try push(build(sp, params, verb, resources[0], 0, base))
                for res in resources {
                    for bits in 0..<nbits { try push(build(sp, params, verb, res, bits, base)) }
                }
                for i in 0..<pOpts.count {
                    for l in pOpts[i] {
                        var ch: [JSONValue?] = base
                        ch[i] = l
                        try push(build(sp, params, verb, resources[0], 0, ch))
                    }
                }
            }
        }
        return GV.obj([("cases", .array(out)), ("complete", .bool(complete))])
    }

    private static func magnitude(_ a: JSONValue) throws -> Int64 {
        var s: Int64 = 0
        if let ps = mm(GV.get(a, "params"))?.asObject {
            for (_, v) in ps where GV.kind(v) == "q" {
                let n: Int64 = try qval(mm(GV.get(v, "q")))
                s = s &+ (n < 0 ? 0 &- n : n)
            }
        }
        return s
    }

    /// The smallest-magnitude case the grant admits (a minimal Allow witness), or nil if its Allow set is empty.
    public static func allowWitness(_ g: JSONValue, _ gr: JSONValue, _ ont: JSONValue) throws -> JSONValue? {
        let sp: Space = try buildSpace([g], [])
        var best: JSONValue? = nil
        let cs: JSONValue = try cells(sp, [try sv(GV.get(gr, "verb"))])
        for co in try GV.arr(GV.get(cs, "cases"), "cases") {
            let c: JSONValue = try req(co, "case")
            let v: JSONValue = try decideCase(g, ont, c)
            let w: JSONValue? = GV.get(v, "witness")
            if GV.get(v, "decision")?.asString == "allow", let ww = w, ww != .null, ww == GV.get(gr, "gid") {
                if best == nil { best = c } else if try magnitude(req(GV.get(c, "act"), "act")) < magnitude(req(GV.get(best, "act"), "act")) { best = c }
            }
        }
        return best
    }

    private static func example(_ kind: String, _ why: String, _ cs: JSONValue, _ hist: JSONValue, _ g: JSONValue, _ ont: JSONValue) throws -> JSONValue {
        let act: JSONValue = GV.get(cs, "act") ?? .null
        let rels: JSONValue = GV.get(cs, "rels") ?? .null
        let digest: String = try hashCanonical(GV.obj([("act", act), ("hist", hist), ("rels", rels)]))
        let id: String = kind + ":" + String(digest.prefix(12))
        let dc: JSONValue = try decideCase(g, ont, GV.obj([("act", act), ("hist", hist), ("rels", rels)]))
        return GV.obj([("id", .string(id)), ("kind", .string(kind)), ("why", .string(why)), ("act", act), ("hist", hist), ("rels", rels), ("decision", GV.get(dc, "decision") ?? .null)])
    }

    /// `${n}` of a floored count.
    private static func countText(_ n: Double) -> String {
        if n.isNaN { return "NaN" }
        if n.isInfinite { return n < 0 ? "-Infinity" : "Infinity" }
        return String(Int64(n))
    }

    /// The full example set (cell representatives, cap sequences, unmentioned-dimension probes): {examples, complete}.
    public static func boundaryExamples(_ g: JSONValue, _ ont: JSONValue, _ extra: [JSONValue]?, _ verbsOpt: [String]?) throws -> JSONValue {
        var goals: [JSONValue] = [g]
        if let e = extra { goals.append(contentsOf: e) }
        let sp: Space = try buildSpace(goals, verbsOpt ?? [])
        let c: JSONValue = try cells(sp, nil)
        var out: [JSONValue] = []
        for cso in try GV.arr(GV.get(c, "cases"), "cases") {
            let cs: JSONValue = try req(cso, "case")
            let v: JSONValue = try decideCase(g, ont, cs)
            let prohibited = GV.get(v, "prohibited") == .bool(true)
            let decision: String = GV.get(v, "decision")?.asString ?? ""
            let kind: String = (prohibited && decision == "deny") ? "prohibit_trigger" : (decision == "allow" ? "member" : "boundary")
            out.append(try example(kind, "cell " + decision, cs, emptyHist(), g, ont))
        }
        let grants: [JSONValue] = try GV.arr(GV.get(g, "grants"), "grants")
        for gro in grants {
            if let w = try allowWitness(g, gro, ont) {
                out.append(try example("allow_witness", "minimal Allow witness of grant " + GV.jsStr(GV.get(gro, "gid")), w, emptyHist(), g, ont))
            }
        }
        for bo in try GV.arr(GV.get(g, "bounds"), "bounds") {
            let b: JSONValue = try req(bo, "bound")
            let sel: JSONValue? = mm(GV.get(b, "sel"))
            var gids: [JSONValue] = []
            if GV.kind(sel) == "gids" { gids = try GV.arr(GV.get(sel, "gids"), "gids") }
            var gr: JSONValue? = nil
            for x in grants {
                if let id = GV.get(x, "gid"), gids.contains(id) { gr = mm(x); break }
            }
            guard let grant = gr, let w = try allowWitness(g, grant, ont) else { continue }
            let per: Double
            if GV.get(b, "agg")?.asString == "count" {
                per = 1.0
            } else {
                let v: JSONValue? = mm(GV.get(b, "value"))
                var pv: JSONValue? = nil
                if GV.kind(v) == "param" { pv = mm(GV.get(mm(GV.get(mm(GV.get(w, "act")), "params")), try sv(GV.get(v, "path")))) }
                if pv != nil && GV.kind(pv) == "q" { per = Double(try qval(try req(GV.get(pv, "q"), "q"))) } else { per = 0.0 }
            }
            let isSum = GV.get(b, "agg")?.asString == "sum"
            if isSum && per <= 0 { continue }
            let n: Double = (Double(try qval(try req(GV.get(b, "cap"), "cap"))) / per).rounded(.down)
            if n > 60 { continue } // sequence too long to review
            let cnt: Int = (n.isNaN || n < 0) ? 0 : Int(n)
            var acts: [JSONValue] = []
            for _ in 0..<cnt { acts.append(GV.get(w, "act") ?? .null) }
            let rels: [JSONValue] = try GV.arr(GV.get(w, "rels"), "rels")
            let hist: JSONValue = try replay(g, ont, acts, rels)
            out.append(try example("cap_sequence", "reach the " + GV.jsStr(GV.get(b, "bid")) + " cap with " + countText(n) + " action(s), then one more", w, hist, g, ont))
        }
        for gro in grants {
            guard let w = try allowWitness(g, gro, ont) else { continue }
            let wact: JSONValue = try req(GV.get(w, "act"), "act")
            let wparams: JSONValue = try req(GV.get(wact, "params"), "params")
            for pk in JSLoose.keys(wparams) {
                let l: JSONValue? = mm(GV.get(wparams, pk))
                if GV.kind(l) == "q" && GV.kind(mm(GV.get(mm(GV.get(l, "q")), "u"))) == "money" {
                    guard var q2 = mm(GV.get(l, "q"))?.asObject, var ps2 = wparams.asObject, var act2 = wact.asObject else { throw IrError("object expected") }
                    q2[JKey("n")] = GV.num(1000000000 as Int64)
                    ps2[JKey(pk)] = GV.obj([("k", .string("q")), ("q", .object(q2))])
                    act2[JKey("params")] = .object(ps2)
                    out.append(try example("probe", "extreme " + pk, GV.obj([("act", .object(act2)), ("rels", GV.get(w, "rels") ?? .null)]), emptyHist(), g, ont))
                }
            }
            var nothing: [JSONValue] = []
            for ro in try GV.arr(GV.get(w, "rels"), "rels") {
                guard var r2 = mm(ro)?.asObject else { throw IrError("object expected") }
                r2[JKey("members")] = .array([])
                nothing.append(.object(r2))
            }
            guard var act3 = wact.asObject else { throw IrError("object expected") }
            act3[JKey("res")] = .string("\u{0}other-resource")
            out.append(try example("probe", "other resource", GV.obj([("act", .object(act3)), ("rels", .array(nothing))]), emptyHist(), g, ont))
            out.append(try example("probe", "other customer/anchor", GV.obj([("act", GV.get(w, "act") ?? .null), ("rels", .array(nothing))]), emptyHist(), g, ont))
        }
        var seen: Set<JKey> = []
        var uniq: [JSONValue] = []
        for e in out {
            if seen.insert(JKey(try sv(GV.get(e, "id")))).inserted { uniq.append(e) }
        }
        return GV.obj([("examples", .array(uniq)), ("complete", GV.get(c, "complete") ?? .null)])
    }

    private static func kindRank(_ k: String) throws -> Int {
        switch k {
        case "probe": return 0
        case "cap_sequence": return 1
        case "allow_witness": return 2
        case "prohibit_trigger": return 3
        case "member": return 4
        case "boundary": return 5
        default: throw IrError("unknown example kind")
        }
    }

    private static func decisionText(_ v: JSONValue?) throws -> String? {
        guard let x = nn(v) else { return nil }
        return try sv(x)
    }

    /// Review subset: at most `cap` examples, riskiest-looking first (probe, cap_sequence, allow_witness, prohibit_trigger, member,
    /// boundary), stable.
    public static func reviewSet(_ examples: [JSONValue], _ cap: Int) throws -> [JSONValue] {
        var keys: [(Int, Int, String)] = []
        for e in examples {
            keys.append((rankOf(try decisionText(GV.get(e, "decision"))), try kindRank(try sv(GV.get(e, "kind"))), try sv(GV.get(e, "id"))))
        }
        var idx: [Int] = Array(0..<examples.count)
        idx.sort { (a: Int, b: Int) -> Bool in
            let x = keys[a]
            let y = keys[b]
            if x.0 != y.0 { return x.0 < y.0 }
            if x.1 != y.1 { return x.1 < y.1 }
            if !IV.same(x.2, y.2) { return GV.less(x.2, y.2) }
            return a < b
        }
        let n: Int = max(0, min(cap, examples.count))
        return idx.prefix(n).map { examples[$0] }
    }

    // ---- GoalTest and the pin ----

    public static func expectedDecision(_ answer: String?) -> String { answer == "allow" ? "allow" : (answer == "deny" ? "deny" : "escalate") }

    /// Order-independent digest of a test list.
    public static func testsDigest(_ tests: [JSONValue]) throws -> String {
        var ids: [String] = []
        for t in tests { ids.append(try sv(GV.get(t, "id"))) }
        var idx: [Int] = Array(0..<tests.count)
        idx.sort { (a: Int, b: Int) -> Bool in
            if IV.same(ids[a], ids[b]) { return a < b }
            return GV.less(ids[a], ids[b])
        }
        let s: [JSONValue] = idx.map { tests[$0] }
        return try hashCanonical(GV.obj([("d", .string("atlas-pca/goal-tests/v1")), ("tests", .array(s))]))
    }

    /// confirmed: list of {example, answer}.
    public static func makeGoalTests(_ g: JSONValue, _ confirmed: [JSONValue]) throws -> JSONValue {
        var tests: [JSONValue] = []
        for co in confirmed {
            let ex: JSONValue = try req(GV.get(co, "example"), "example")
            tests.append(GV.obj([
                ("id", GV.get(ex, "id") ?? .null), ("act", GV.get(ex, "act") ?? .null), ("hist", GV.get(ex, "hist") ?? .null),
                ("rels", GV.get(ex, "rels") ?? .null), ("answer", GV.get(co, "answer") ?? .null),
            ]))
        }
        return GV.obj([
            ("goal_digest", .string(try PCAGoalDigests.goalDigest(g))), ("ontology_digest", GV.get(g, "ontDigest") ?? .null),
            ("tests", .array(tests)), ("tests_digest", .string(try testsDigest(tests))),
        ])
    }

    public static func signGoalTests(_ s: JSONValue, _ seed: [UInt8]) throws -> JSONValue { try PCAGoalSign.signPayload("goal-tests", s, seed) }

    /// Recompile check: every confirmed test must be reproduced by `decideFn` (test -> decision). {ok, reason?, failures}.
    public static func checkGoalTests(_ s: JSONValue, _ pins: [JSONValue], _ decideFn: (JSONValue) throws -> String) throws -> JSONValue {
        if !(try PCAGoalSign.verifyPayload(s, "goal-tests", pins)) {
            return GV.obj([("ok", .bool(false)), ("reason", .string("signature")), ("failures", .array([]))])
        }
        let payload: JSONValue = try req(GV.get(s, "payload"), "payload")
        let tests: [JSONValue] = try GV.arr(GV.get(payload, "tests"), "tests")
        let digest: String = try testsDigest(tests)
        if GV.get(payload, "tests_digest") != .string(digest) {
            return GV.obj([("ok", .bool(false)), ("reason", .string("tests_digest")), ("failures", .array([]))])
        }
        var failures: [JSONValue] = []
        for to in tests {
            let t: JSONValue = try req(to, "test")
            let got: String = try decideFn(t)
            let want: String = expectedDecision(try decisionText(GV.get(t, "answer")))
            if !IV.same(want, got) {
                failures.append(GV.obj([("id", GV.get(t, "id") ?? .null), ("expected", .string(want)), ("got", .string(got))]))
            }
        }
        if failures.isEmpty { return GV.obj([("ok", .bool(true)), ("failures", .array(failures))]) }
        return GV.obj([("ok", .bool(false)), ("reason", .string("test_regression")), ("failures", .array(failures))])
    }

    public static func signPin(_ p: JSONValue, _ seed: [UInt8]) throws -> JSONValue { try PCAGoalSign.signPayload("policy-pin", p, seed) }

    /// cur: {goal, policy_digest, tests}. {ok, reason?}.
    public static func checkPin(_ pin: JSONValue, _ pins: [JSONValue], _ cur: JSONValue) throws -> JSONValue {
        func fail(_ r: String) -> JSONValue { GV.obj([("ok", .bool(false)), ("reason", .string(r))]) }
        if !(try PCAGoalSign.verifyPayload(pin, "policy-pin", pins)) { return fail("signature") }
        let p: JSONValue = try req(GV.get(pin, "payload"), "payload")
        let goal: JSONValue = try req(GV.get(cur, "goal"), "goal")
        let tests: JSONValue = try req(GV.get(cur, "tests"), "tests")
        let gd: String = try PCAGoalDigests.goalDigest(goal)
        if GV.get(p, "goal_digest") != .string(gd) { return fail("goal changed under the pin") }
        if GV.get(p, "policy_digest") != GV.get(cur, "policy_digest") { return fail("policy changed under the pin") }
        let td: JSONValue? = GV.get(p, "tests_digest")
        let tdc: String = try testsDigest(try GV.arr(GV.get(tests, "tests"), "tests"))
        if td != GV.get(tests, "tests_digest") || td != .string(tdc) { return fail("tests changed under the pin") }
        if GV.get(p, "ontology_digest") != GV.get(goal, "ontDigest") { return fail("ontology changed under the pin") }
        return GV.obj([("ok", .bool(true))])
    }
}
