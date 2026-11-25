import Foundation

/// N-version interpretation: the enforced policy is the semantic meet of the readings. Allow(meet gs) a implies Allow(g) a for
/// every g in gs. Grants are the cross product of the readings' grants on equal verbs (a merged grant is named `x&y&z`),
/// resources intersect through `all_of`, conditions conjoin; a bound counts the admitted actions of the merged grants
/// derived from the grants it selected, so the merged goal never admits more than any reading.
public enum PCAGoalNVersion {
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

    private static func sortedStrings(_ xs: [String]) -> [String] {
        var idx: [Int] = Array(0..<xs.count)
        idx.sort { (a: Int, b: Int) -> Bool in
            if IV.same(xs[a], xs[b]) { return a < b }
            return GV.less(xs[a], xs[b])
        }
        return idx.map { xs[$0] }
    }

    /// An insertion-ordered set of strings compared by code points.
    private struct OSet {
        var items: [String] = []
        var seen: Set<JKey> = []
        mutating func add(_ s: String) {
            if seen.insert(JKey(s)).inserted { items.append(s) }
        }
        func has(_ s: String) -> Bool { seen.contains(JKey(s)) }
    }

    /// An insertion-ordered map: a repeated key replaces the value and keeps its first position (Map.set).
    private struct OMap<V> {
        var keys: [String] = []
        var vals: [JKey: V] = [:]
        mutating func put(_ k: String, _ v: V) {
            if vals[JKey(k)] == nil { keys.append(k) }
            vals[JKey(k)] = v
        }
        func get(_ k: String) -> V? { vals[JKey(k)] }
        var values: [V] { keys.map { vals[JKey($0)]! } }
    }

    private static func partsOf(_ s: JSONValue?) throws -> [JSONValue?] {
        var out: [JSONValue?] = []
        let k = GV.kind(s)
        if k == "all_of" {
            for p in try GV.arr(GV.get(s, "parts"), "parts") { out.append(mm(p)) }
        } else if k != "any" {
            out.append(s)
        }
        return out
    }

    private static func intersect(_ a: JSONValue?, _ b: JSONValue?) throws -> JSONValue? {
        if GV.kind(a) == "any" { return b }
        if GV.kind(b) == "any" { return a }
        var uniq = OMap<JSONValue?>()
        for p in try partsOf(a) { uniq.put(GV.stable(p), p) }
        for p in try partsOf(b) { uniq.put(GV.stable(p), p) }
        let vs: [JSONValue?] = uniq.values
        if vs.count == 1 { return vs[0] }
        return GV.obj([("k", .string("all_of")), ("parts", .array(vs.map { $0 ?? .null }))])
    }

    private static func conj(_ a: JSONValue?, _ b: JSONValue?) -> JSONValue? {
        if GV.kind(a) == "true" { return b }
        if GV.kind(b) == "true" { return a }
        return GV.obj([("k", .string("and")), ("a", a ?? .null), ("b", b ?? .null)])
    }

    /// A merged grant and, per reading, the gid of the grant it was derived from.
    private struct Tracked {
        let g: JSONValue
        let from: [String]
    }

    private static func cross(_ a: [Tracked], _ b: [Tracked]) throws -> [Tracked] {
        var out: [Tracked] = []
        for x in a {
            for y in b {
                if GV.get(x.g, "verb") != GV.get(y.g, "verb") { continue }
                let gid: String = GV.jsStr(GV.get(x.g, "gid")) + "&" + GV.jsStr(GV.get(y.g, "gid"))
                let res: JSONValue? = try intersect(mm(GV.get(x.g, "res")), mm(GV.get(y.g, "res")))
                let cond: JSONValue? = conj(mm(GV.get(x.g, "cond")), mm(GV.get(y.g, "cond")))
                let g: JSONValue = GV.obj([("gid", .string(gid)), ("verb", GV.get(x.g, "verb") ?? .null), ("res", res ?? .null), ("cond", cond ?? .null)])
                out.append(Tracked(g: g, from: x.from + y.from))
            }
        }
        return out
    }

    private static func track(_ grants: [JSONValue]) throws -> [Tracked] {
        var out: [Tracked] = []
        for g in grants { out.append(Tracked(g: try req(g, "grant"), from: [try sv(GV.get(g, "gid"))])) }
        return out
    }

    /// Meet of grants: cross product on equal verbs, resource intersection, conjoined conditions.
    public static func meetGrants(_ a: [JSONValue], _ b: [JSONValue]) throws -> [JSONValue] {
        let ta: [Tracked] = try track(a)
        let tb: [Tracked] = try track(b)
        return try cross(ta, tb).map { $0.g }
    }

    private static func derived(_ tracked: [Tracked], _ i: Int, _ gids: [JSONValue]) -> [JSONValue] {
        var out: [JSONValue] = []
        for t in tracked where gids.contains(.string(t.from[i])) { out.append(GV.get(t.g, "gid") ?? .null) }
        return out
    }

    private static func num(_ v: JSONValue?) -> Double { GV.toNum(v) }

    private static func jsMax(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? Double.nan : Swift.max(a, b) }
    private static func jsMin(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? Double.nan : Swift.min(a, b) }

    private static func numOut(_ d: Double) throws -> JSONValue {
        if d == d.rounded(.toNearestOrEven) && abs(d) <= Double(GV.MAX_SAFE) { return GV.num(Int64(d)) }
        throw IrError("non-integer result")
    }

    private static func objCopy(_ v: JSONValue?, _ what: String) throws -> JObject {
        guard let o = v?.asObject else { throw IrError("\(what) expected an object") }
        return o
    }

    public static func meet(_ goals: [JSONValue]) throws -> JSONValue {
        if goals.isEmpty { throw IrError("meet: no goals") }
        let first: JSONValue = goals[0]
        for g in goals {
            if GV.get(g, "principal") != GV.get(first, "principal") || GV.get(g, "ontDigest") != GV.get(first, "ontDigest") || GV.get(g, "nlDigest") != GV.get(first, "nlDigest") {
                throw IrError("meet: readings must share principal, ontology and text")
            }
        }
        if goals.count == 1 { return first }
        var tracked: [Tracked] = try track(try GV.arr(GV.get(first, "grants"), "grants"))
        for g in goals[1...] { tracked = try cross(tracked, try track(try GV.arr(GV.get(g, "grants"), "grants"))) }
        let grants: [JSONValue] = tracked.map { $0.g }

        var prohibits: [JSONValue] = []
        var pseen: [(body: String, pid: JSONValue?)] = []
        for i in 0..<goals.count {
            for po in try GV.arr(GV.get(goals[i], "prohibits"), "prohibits") {
                let p: JSONValue = try req(po, "prohibit")
                var bodyMap: JObject = try objCopy(p, "prohibit")
                bodyMap[JKey("pid")] = .string("")
                let body: String = GV.stable(.object(bodyMap))
                if pseen.contains(where: { IV.same($0.body, body) }) { continue }
                let pid: JSONValue? = GV.get(p, "pid")
                let taken: Bool = pseen.contains(where: { $0.pid == pid })
                pseen.append((body: body, pid: pid))
                if taken {
                    var np: JObject = try objCopy(p, "prohibit")
                    np[JKey("pid")] = .string(GV.jsStr(pid) + "#" + String(i))
                    prohibits.append(.object(np))
                } else {
                    prohibits.append(p)
                }
            }
        }

        var bounds: [JObject] = []
        var bseen: [JKey: Int] = [:]
        for i in 0..<goals.count {
            for bo in try GV.arr(GV.get(goals[i], "bounds"), "bounds") {
                let b: JSONValue = try req(bo, "bound")
                let bsel: JSONValue? = mm(GV.get(b, "sel"))
                var sel: JSONValue? = bsel
                if GV.kind(bsel) == "gids" {
                    let ds: [JSONValue] = derived(tracked, i, try GV.arr(GV.get(bsel, "gids"), "gids"))
                    var names: [String] = []
                    for d in ds { names.append(try sv(d)) }
                    sel = GV.obj([("k", .string("gids")), ("gids", .array(sortedStrings(names).map { JSONValue.string($0) }))])
                }
                if GV.kind(sel) == "gids" {
                    let selGids: [JSONValue] = try GV.arr(GV.get(sel, "gids"), "gids")
                    if selGids.isEmpty { continue }
                }
                let cap: JSONValue = try req(GV.get(b, "cap"), "cap")
                var kv: [(String, JSONValue)] = []
                if let s = sel { kv.append(("sel", s)) }
                for k in ["agg", "value", "key", "window", "scope"] { if let v = GV.get(b, k) { kv.append((k, v)) } }
                if let u = GV.get(cap, "u") { kv.append(("unit", u)) }
                let key: JKey = JKey(GV.stable(GV.obj(kv)))
                if let at = bseen[key] {
                    let prevCap: JSONValue = try req(GV.get(JSONValue.object(bounds[at]), "cap"), "cap")
                    if num(GV.get(cap, "n")) < num(GV.get(prevCap, "n")) { bounds[at][JKey("cap")] = cap }
                    if GV.get(b, "onExceed") == .string("deny") { bounds[at][JKey("onExceed")] = .string("deny") }
                    continue
                }
                var nb: JObject = try objCopy(b, "bound")
                nb[JKey("sel")] = sel ?? .null
                var dup = false
                for x in bounds where GV.get(JSONValue.object(x), "bid") == GV.get(b, "bid") { dup = true }
                if dup { nb[JKey("bid")] = .string(GV.jsStr(GV.get(b, "bid")) + "#" + String(i)) }
                bounds.append(nb)
                bseen[key] = bounds.count - 1
            }
        }

        var escSeen = OMap<JSONValue>()
        for g in goals {
            for c in try GV.arr(GV.get(g, "escalateOn"), "escalateOn") { escSeen.put(GV.stable(c), c) }
        }

        var idle: [Double] = []
        for g in goals {
            let x: Double = num(GV.get(try req(GV.get(g, "validity"), "validity"), "maxIdle"))
            if x > 0 { idle.append(x) }
        }
        var touch: [JSONValue] = []
        for t in tracked {
            var all = true
            for i in 0..<goals.count {
                let mt: [JSONValue] = try GV.arr(GV.get(try req(GV.get(goals[i], "deleg"), "deleg"), "mayTouch"), "mayTouch")
                if !mt.contains(.string(t.from[i])) { all = false; break }
            }
            if all { touch.append(GV.get(t.g, "gid") ?? .null) }
        }
        var ack: [JSONValue] = []
        for t in tracked {
            if GV.kind(GV.get(t.g, "res")) != "any" { continue }
            var all = true
            for i in 0..<goals.count {
                var src: JSONValue? = nil
                for x in try GV.arr(GV.get(goals[i], "grants"), "grants") where GV.get(x, "gid") == .string(t.from[i]) {
                    src = mm(x)
                    break
                }
                let notAny: Bool = src == nil || GV.kind(GV.get(src, "res")) != "any"
                let acked: Bool = try GV.arr(GV.get(goals[i], "wildcardAck"), "wildcardAck").contains(.string(t.from[i]))
                if !(notAny || acked) { all = false; break }
            }
            if all { ack.append(GV.get(t.g, "gid") ?? .null) }
        }
        var holes = OMap<JSONValue>()
        for i in 0..<goals.count {
            for ho in try GV.arr(GV.get(goals[i], "holes"), "holes") {
                let h: JSONValue = try req(ho, "hole")
                let hid: String = try sv(GV.get(h, "hid"))
                let prev: JSONValue? = holes.get(hid)
                var aff = OSet()
                if let p = prev { for a in try GV.arr(GV.get(p, "affects"), "affects") { aff.add(try sv(a)) } }
                for a in derived(tracked, i, try GV.arr(GV.get(h, "affects"), "affects")) { aff.add(try sv(a)) }
                var nh: JObject = try objCopy(h, "hole")
                nh[JKey("affects")] = .array(sortedStrings(aff.items).map { JSONValue.string($0) })
                if JS.truthy(GV.get(h, "global")) {
                    nh[JKey("global")] = GV.get(h, "global") ?? .null
                } else if let pg = JS.present(GV.get(prev, "global")) {
                    nh[JKey("global")] = pg
                } else {
                    nh[JKey("global")] = .bool(false)
                }
                holes.put(hid, .object(nh))
            }
        }
        var sources = OSet()
        for g in goals {
            for s in try GV.arr(GV.get(g, "sources"), "sources") { sources.add(try sv(s)) }
        }
        var nb: Double = -Double.infinity
        var na: Double = Double.infinity
        var md: Double = Double.infinity
        for g in goals {
            let v: JSONValue = try req(GV.get(g, "validity"), "validity")
            nb = jsMax(nb, num(GV.get(v, "notBefore")))
            na = jsMin(na, num(GV.get(v, "notAfter")))
            md = jsMin(md, num(GV.get(try req(GV.get(g, "deleg"), "deleg"), "maxDepth")))
        }
        var mi: Double = 0.0
        if !idle.isEmpty {
            mi = Double.infinity
            for x in idle { mi = jsMin(mi, x) }
        }
        var out: JObject = try objCopy(first, "goal")
        out[JKey("grants")] = .array(grants)
        out[JKey("prohibits")] = .array(prohibits)
        out[JKey("bounds")] = .array(bounds.map { JSONValue.object($0) })
        out[JKey("escalateOn")] = .array(escSeen.values)
        out[JKey("sources")] = .array(sources.items.map { JSONValue.string($0) })
        out[JKey("validity")] = GV.obj([("notBefore", try numOut(nb)), ("notAfter", try numOut(na)), ("maxIdle", try numOut(mi))])
        out[JKey("deleg")] = GV.obj([("maxDepth", try numOut(md)), ("narrowOnly", .bool(true)), ("mayTouch", .array(touch))])
        out[JKey("holes")] = .array(holes.values)
        out[JKey("wildcardAck")] = .array(ack)
        return try PCAGoalNormalize.canonicalizeGoal(.object(out))
    }

    /// Panel requirements: at least 3 interpreters, one deterministic non-LLM interpreter, two distinct model families. Issues {code, msg}.
    public static func checkPanel(_ readings: [JSONValue]) -> [JSONValue] {
        var out: [JSONValue] = []
        if readings.count < 3 { out.append(GV.obj([("code", .string("too_few")), ("msg", .string("need at least 3 interpreters"))])) }
        var det = false
        var fams: Set<JKey> = []
        for r in readings {
            if JS.truthy(GV.get(r, "deterministic")) {
                det = true
            } else {
                // an absent family is its own member, distinct from a JSON null
                let f: JSONValue = GV.get(r, "family") ?? .string("\u{0}undefined")
                fams.insert(JKey(GV.stable(f)))
            }
        }
        if !det { out.append(GV.obj([("code", .string("no_deterministic")), ("msg", .string("need at least one deterministic template interpreter"))])) }
        if fams.count < 2 { out.append(GV.obj([("code", .string("no_family_diversity")), ("msg", .string("need at least two distinct model families"))])) }
        return out
    }

    /// {merged, panelIssues, disagreementHoles, mass, signable}.
    public static func nVersion(_ readings: [JSONValue], _ opts: PCAGoalDisambiguate.Opts, _ massThreshold: Double?) throws -> JSONValue {
        var goals: [JSONValue] = []
        for r in readings { goals.append(try req(GV.get(r, "goal"), "goal")) }
        let merged: JSONValue = try meet(goals)
        let panelIssues: [JSONValue] = checkPanel(readings)
        var verbSets: [OSet] = []
        var allVerbs = OSet()
        for g in goals {
            var s = OSet()
            for gr in try GV.arr(GV.get(g, "grants"), "grants") {
                let v: String = try sv(GV.get(gr, "verb"))
                s.add(v)
                allVerbs.add(v)
            }
            verbSets.append(s)
        }
        var holes: [JSONValue] = []
        for v in sortedStrings(allVerbs.items) {
            var some = false
            for s in verbSets where !s.has(v) { some = true }
            if some {
                holes.append(GV.obj([
                    ("hid", .string("nv:verb:" + v)), ("q", .string("Only some readings allow \"" + v + "\". Should it be allowed at all?")),
                    ("domain", .array([])), ("affects", .array([])), ("global", .bool(false)),
                ]))
            }
        }
        let mass: Double = try PCAGoalDisambiguate.disagreementMass(readings, opts.ont)
        if mass > (massThreshold ?? 0.0) {
            let qs: [JSONValue] = try PCAGoalDisambiguate.questions(readings, opts)
            let text: JSONValue = qs.isEmpty ? .string("The readings disagree.") : (GV.get(qs[0], "text") ?? .null)
            holes.append(GV.obj([("hid", .string("nv:split")), ("q", text), ("domain", .array([])), ("affects", .array([])), ("global", .bool(true))]))
        }
        var all: [JSONValue] = try GV.arr(GV.get(merged, "holes"), "holes")
        all.append(contentsOf: holes)
        var byHid = OMap<JSONValue>()
        for h in all { byHid.put(try sv(GV.get(h, "hid")), h) }
        var m2: JObject = try objCopy(merged, "goal")
        m2[JKey("holes")] = .array(byHid.values)
        let canon: JSONValue = try PCAGoalNormalize.canonicalizeGoal(.object(m2))
        return GV.obj([
            ("merged", canon), ("panelIssues", .array(panelIssues)), ("disagreementHoles", .array(holes)), ("mass", .double(mass)),
            ("signable", .bool(panelIssues.isEmpty && all.isEmpty)),
        ])
    }
}
