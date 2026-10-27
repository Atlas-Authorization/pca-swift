import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The pca-goal conformance corpus (packages/pca-conformance/vectors/goal; vendored as conformance/goal in the mirrors): the goal
/// digest of every vector, the decision (and its witness) of every probe, and the helper vectors (canon, units, polarity, meet,
/// pep, commit, claim). `GoalRef` is an independent port of the reference semantics, like the Go / Rust / Python runners.
enum GoalRef {
    typealias M = JObject

    static func o(_ v: JSONValue?) -> M { v?.asObject ?? [:] }
    static func a(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }
    static func s(_ v: JSONValue?) -> String { v?.asString ?? "" }
    static func iv(_ v: JSONValue?) -> Int64 {
        switch v {
        case let .int(i)?: return i
        default: return 0
        }
    }
    static func nn(_ v: JSONValue?) -> Bool { v != nil && v != .null }
    static func obj(_ kv: [(String, JSONValue)]) -> JSONValue {
        var m: M = [:]
        for (k, v) in kv { m[JKey(k)] = v }
        return .object(m)
    }

    // ---- canonical form and digests (the corpus's own: \b \t \n \f \r short escapes, other controls as \u00xx, keys by UTF-8 bytes) ----

    static func canon(_ v: JSONValue?) -> String {
        switch v {
        case nil, .null?: return "null"
        case let .bool(b)?: return b ? "true" : "false"
        case let .int(i)?: return String(i)
        case let .double(d)?: return Canonical.numberString(d)
        case let .string(t)?:
            var out = "\""
            for u in t.unicodeScalars {
                switch u.value {
                case 0x22: out += "\\\""
                case 0x5C: out += "\\\\"
                case 8: out += "\\b"
                case 9: out += "\\t"
                case 10: out += "\\n"
                case 12: out += "\\f"
                case 13: out += "\\r"
                default:
                    if u.value < 0x20 { out += "\\u" + String(format: "%04x", u.value) } else { out.unicodeScalars.append(u) }
                }
            }
            return out + "\""
        case let .array(xs)?: return "[" + xs.map { canon($0) }.joined(separator: ",") + "]"
        case let .object(m)?:
            let ks = m.keys.sorted()
            return "{" + ks.map { canon(.string($0.s)) + ":" + canon(m[$0]) }.joined(separator: ",") + "}"
        }
    }

    static func b64(_ text: String) -> String { Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(text))) }
    static func hashCanon(_ v: JSONValue?) -> String { b64(canon(v)) }
    static func goalDigest(_ g: JSONValue?) -> String { hashCanon(obj([("d", .string("atlas-pca/goal-ir/v1")), ("goal", g ?? .null)])) }

    // ---- Kleene truth 0/1/2 (false/unknown/true); decisions 0/1/2 (deny/escalate/allow) ----

    static func b2k(_ b: Bool) -> Int { b ? 2 : 0 }

    static func eqV(_ x: M, _ y: M) -> Int {
        if s(x["k"]) == "q" {
            guard s(y["k"]) == "q", o(x["q"])["u"] == o(y["q"])["u"] else { return 1 }
            return b2k(iv(o(x["q"])["n"]) == iv(o(y["q"])["n"]))
        }
        if s(x["k"]) == "s" { return s(y["k"]) == "s" ? b2k(x["s"] == y["s"]) : 1 }
        return 1
    }

    static func ltV(_ x: M, _ y: M) -> Int {
        guard s(x["k"]) == "q", s(y["k"]) == "q", o(x["q"])["u"] == o(y["q"])["u"] else { return 1 }
        return b2k(iv(o(x["q"])["n"]) < iv(o(y["q"])["n"]))
    }

    static func cmp(_ op: String, _ x: M?, _ y: M?) -> Int {
        guard let x = x, let y = y else { return 1 }
        switch op {
        case "eq": return eqV(x, y)
        case "ne": return 2 - eqV(x, y)
        case "lt": return ltV(x, y)
        case "gte": return 2 - ltV(x, y)
        case "gt": return ltV(y, x)
        case "lte": return 2 - ltV(y, x)
        default: break
        }
        var t = 1
        if s(y["k"]) == "set" {
            t = 0
            for it in a(y["items"]) { t = max(t, eqV(x, o(it))) }
        }
        return op == "in" ? t : 2 - t
    }

    static func term(_ t: M, _ act: M, _ h: M) -> M? {
        switch s(t["k"]) {
        case "param": return o(act["params"])[JKey(s(t["path"]))]?.asObject
        case "lit": return o(t["v"])
        default:
            guard let q = o(h["aggs"])[JKey(s(t["bid"]))], q != .null else { return nil }
            return ["k": .string("q"), "q": q]
        }
    }

    static func cond(_ c: M, _ act: M, _ h: M) -> Int {
        switch s(c["k"]) {
        case "true": return 2
        case "cmp": return cmp(s(c["op"]), term(o(c["l"]), act, h), term(o(c["r"]), act, h))
        case "and": return min(cond(o(c["a"]), act, h), cond(o(c["b"]), act, h))
        case "or": return max(cond(o(c["a"]), act, h), cond(o(c["b"]), act, h))
        default: return 2 - cond(o(c["c"]), act, h)
        }
    }

    // ---- resource selectors, verbs, bounds ----

    static func partIds(_ ont: M, _ p: M) -> [JSONValue] {
        switch s(p["k"]) {
        case "exact": return [p["id"] ?? .null]
        case "oneof": return a(p["ids"])
        default:
            for r in a(ont["rels"]) {
                let rr = o(r)
                if rr["rel"] == p["rel"] && rr["anchor"] == p["anchor"] { return a(rr["members"]) }
            }
            return []
        }
    }

    /// nil means "any resource".
    static func resolve(_ ont: M, _ sel: M) -> [JSONValue]? {
        if s(sel["k"]) == "any" { return nil }
        if s(sel["k"]) != "all_of" { return partIds(ont, sel) }
        var acc: [JSONValue]?
        for p in a(sel["parts"]).reversed() {
            let ids = partIds(ont, o(p))
            if let cur = acc { acc = ids.filter { cur.contains($0) } } else { acc = ids }
        }
        return acc
    }

    static func resOk(_ p: [JSONValue]?, _ r: JSONValue?) -> Bool { p == nil || p!.contains(r ?? .null) }

    static func verbsOfClass(_ ont: M, _ cls: JSONValue?) -> [JSONValue] {
        a(ont["verbs"]).compactMap { (x: JSONValue) -> JSONValue? in let v = o(x); return v["cls"] == cls ? (v["verb"] ?? .null) : nil }
    }

    static func prohVerbs(_ ont: M, _ p: M) -> [JSONValue] {
        let t = o(p["target"])
        return s(t["k"]) == "verb" ? [t["verb"] ?? .null] : verbsOfClass(ont, t["cls"])
    }

    typealias Sel = (gids: [JSONValue], verbs: [JSONValue])
    static func lsel(_ ont: M, _ b: M) -> Sel {
        let sl = o(b["sel"])
        if s(sl["k"]) == "gids" { return (gids: a(sl["gids"]), verbs: [JSONValue]()) }
        return (gids: [JSONValue](), verbs: verbsOfClass(ont, sl["cls"]))
    }
    static func applies(_ sl: Sel, _ gid: JSONValue?, _ verb: JSONValue?) -> Bool {
        sl.gids.contains(gid ?? .null) || sl.verbs.contains(verb ?? .null)
    }

    static func floorDiv(_ a: Int64, _ b: Int64) -> Int64 {
        let q = a / b
        return (a % b != 0) && ((a < 0) != (b < 0)) ? q - 1 : q
    }

    static func inScope(_ b: M, _ act: M, _ x: M) -> Bool {
        let sc = o(b["scope"])
        switch s(sc["k"]) {
        case "session": return act["sess"] == x["sess"]
        case "principal": return act["prin"] == x["prin"]
        case "org": return act["org"] == x["org"]
        default:
            let ag = a(sc["agents"])
            return ag.contains(act["agent"] ?? .null) && ag.contains(x["agent"] ?? .null)
        }
    }

    static func inWindow(_ w: M, _ act: M, _ x: M) -> Bool {
        let at = iv(act["t"]), xt = iv(x["t"]), ms = iv(w["ms"])
        switch s(w["k"]) {
        case "sliding": return xt > at &- ms && xt <= at
        case "period": return ms > 0 && floorDiv(at &- iv(w["t0"]), ms) == floorDiv(xt &- iv(w["t0"]), ms)
        default: return true
        }
    }

    /// Kleene: is the bound exceeded (2 yes, 0 no, 1 unknown)?
    static func exceeded(_ b: M, _ sl: Sel, _ act: M, _ h: M) -> Int {
        var items: [M] = []
        for m in a(h["adms"]) {
            let mm = o(m), x = o(mm["act"])
            if applies(sl, mm["gid"], x["verb"]) && inScope(b, act, x) && inWindow(o(b["window"]), act, x) { items.append(x) }
        }
        items.append(act)
        let cap = iv(o(b["cap"])["n"])
        switch s(b["agg"]) {
        case "count": return b2k(Int64(items.count) > cap)
        case "distinct":
            var vs = Set<JKey>()
            for x in items {
                guard let v = o(x["params"])[JKey(s(b["key"]))] else { return 1 }
                vs.insert(JKey(canon(v)))
            }
            return b2k(Int64(vs.count) > cap)
        default: break
        }
        var ns: [Int64] = []
        for x in items {
            guard let v = term(o(b["value"]), x, h), s(v["k"]) == "q", o(v["q"])["u"] == o(b["cap"])["u"] else { return 1 }
            ns.append(iv(o(v["q"])["n"]))
        }
        let r = s(b["agg"]) == "sum" ? ns.reduce(Int64(0), &+) : (ns.max() ?? 0)
        return b2k(r > cap)
    }

    static func boundDec(_ b: M, _ sl: Sel, _ act: M, _ h: M) -> Int {
        let e = exceeded(b, sl, act, h)
        return e == 2 ? (s(b["onExceed"]) == "deny" ? 0 : 1) : (e == 1 ? 1 : 2)
    }

    /// Holes drop the grants they affect (or all of them when global) and are then cleared.
    static func strip(_ g: M) -> M {
        let holes = a(g["holes"]).map { o($0) }
        var out = g
        out["holes"] = .array([])
        out["grants"] = .array(a(g["grants"]).filter { gr in
            !holes.contains { $0["global"] == .bool(true) || a($0["affects"]).contains(o(gr)["gid"] ?? .null) }
        })
        return out
    }

    static func grantDec(_ g: M, _ ont: M, _ gr: M, _ act: M, _ h: M) -> Int {
        let delegOk = iv(act["depth"]) == 0 || a(o(g["deleg"])["mayTouch"]).contains(gr["gid"] ?? .null)
        var m = min(b2k(act["verb"] == gr["verb"] && delegOk), b2k(resOk(resolve(ont, o(gr["res"])), act["res"])), cond(o(gr["cond"]), act, h))
        for b in a(g["bounds"]) {
            let bb = o(b), sl = lsel(ont, bb)
            if applies(sl, gr["gid"], act["verb"]) { m = min(m, boundDec(bb, sl, act, h)) }
        }
        return m
    }

    static func decide(_ goal: M, _ ont: M, _ act: M, _ h: M) -> JSONValue {
        let g = strip(goal)
        let v = o(g["validity"])
        let at = iv(act["t"]), depth = iv(act["depth"])
        var d = 2
        if at < iv(v["notBefore"]) || at > iv(v["notAfter"]) { d = 0 }
        else if iv(v["maxIdle"]) > 0 && iv(h["last"]) >= 0 && at &- iv(h["last"]) > iv(v["maxIdle"]) { d = 0 }
        else if depth < 0 || depth > iv(o(g["deleg"])["maxDepth"]) { d = 0 }
        for p in a(g["prohibits"]) {
            let pp = o(p)
            let m = min(b2k(prohVerbs(ont, pp).contains(act["verb"] ?? .null)), b2k(resOk(resolve(ont, o(pp["res"])), act["res"])), cond(o(pp["cond"]), act, h))
            d = min(d, m == 2 ? 0 : (m == 1 ? 1 : 2))
        }
        for c in a(g["escalateOn"]) { d = min(d, cond(o(c), act, h) == 0 ? 2 : 1) }
        let grants = a(g["grants"]).map { o($0) }
        let per = grants.map { grantDec(g, ont, $0, act, h) }
        d = min(d, per.max() ?? 0)
        if d != 2 { return obj([("decision", .string(d == 1 ? "escalate" : "deny")), ("witness", .null)]) }
        let gr = grants[per.firstIndex(of: 2)!]
        let bids: [JSONValue] = a(g["bounds"]).compactMap { (x: JSONValue) -> JSONValue? in
            let b = o(x)
            return applies(lsel(ont, b), gr["gid"], act["verb"]) ? (b["bid"] ?? .null) : nil
        }
        return obj([("decision", .string("allow")), ("witness", obj([("gid", gr["gid"] ?? .null), ("bids", .array(bids))]))])
    }

    // ---- lowering (the policy digest) ----

    static let NEG: [String: String] = ["eq": "ne", "ne": "eq", "lt": "gte", "gte": "lt", "gt": "lte", "lte": "gt", "in": "nin", "nin": "in"]
    static func nnf(_ c: M, _ pos: Bool) -> JSONValue {
        switch s(c["k"]) {
        case "true": return obj([("k", .string(pos ? "true" : "false"))])
        case "cmp":
            let op = s(c["op"])
            return obj([("k", .string("atom")), ("op", .string(pos ? op : (NEG[op] ?? op))), ("l", c["l"] ?? .null), ("r", c["r"] ?? .null)])
        case "and": return obj([("k", .string(pos ? "and" : "or")), ("a", nnf(o(c["a"]), pos)), ("b", nnf(o(c["b"]), pos))])
        case "or": return obj([("k", .string(pos ? "or" : "and")), ("a", nnf(o(c["a"]), pos)), ("b", nnf(o(c["b"]), pos))])
        default: return nnf(o(c["c"]), !pos)
        }
    }
    static func pat(_ p: [JSONValue]?) -> JSONValue {
        if let ids = p { return obj([("k", .string("set")), ("ids", .array(ids))]) }
        return obj([("k", .string("star"))])
    }
    static func lower(_ ont: M, _ goal: M) -> JSONValue {
        let g = strip(goal)
        let ceils: [JSONValue] = a(g["bounds"]).map { (x: JSONValue) -> JSONValue in
            let b = o(x), sl = lsel(ont, b)
            return obj([("bid", b["bid"] ?? .null), ("selGids", .array(sl.gids)), ("selVerbs", .array(sl.verbs)), ("agg", b["agg"] ?? .null),
                        ("value", b["value"] ?? .null), ("key", b["key"] ?? .null), ("window", b["window"] ?? .null), ("scope", b["scope"] ?? .null),
                        ("cap", b["cap"] ?? .null), ("onExceed", b["onExceed"] ?? .null)])
        }
        let preds: [JSONValue] = a(g["grants"]).map { (y: JSONValue) -> JSONValue in
            let x = o(y)
            return obj([("gid", x["gid"] ?? .null), ("verb", x["verb"] ?? .null), ("res", pat(resolve(ont, o(x["res"])))), ("cond", nnf(o(x["cond"]), true))])
        }
        let prohs: [JSONValue] = a(g["prohibits"]).map { (y: JSONValue) -> JSONValue in
            let p = o(y)
            return obj([("pid", p["pid"] ?? .null), ("verbs", .array(prohVerbs(ont, p))), ("res", pat(resolve(ont, o(p["res"])))), ("cond", nnf(o(p["cond"]), true))])
        }
        return obj([("preds", .array(preds)), ("prohs", .array(prohs)), ("ceils", .array(ceils)), ("escs", .array(a(g["escalateOn"]).map { nnf(o($0), true) })),
                    ("validity", g["validity"] ?? .null), ("deleg", g["deleg"] ?? .null)])
    }

    // ---- helper functions ----

    static let RANK: [String: Int] = ["deny": 0, "escalate": 1, "allow": 2]
    static func meet(_ d: String, _ sig: String) -> String {
        if let r = RANK[sig], r < (RANK[d] ?? 0) { return sig }
        return d
    }

    static func polarity(_ ws: [JSONValue]) -> [JSONValue] {
        var set = Set<JKey>()
        func walk(_ c: M) {
            switch s(c["k"]) {
            case "and", "or": walk(o(c["a"])); walk(o(c["b"]))
            case "not": walk(o(c["c"]))
            case "cmp":
                for k in ["l", "r"] {
                    let t = o(c[JKey(k)])
                    if s(t["k"]) == "param" {
                        for p in ["env.class.", "env.prov.", "env.judge.", "env.world."] where IV.startsWith(s(t["path"]), p) { set.insert(JKey(s(t["path"]))) }
                    }
                }
            default: break
            }
        }
        for w in ws { walk(o(w)) }
        return set.sorted().map { .string($0.s) }
    }

    static func units(_ schema: M, _ terms: M) -> [JSONValue] {
        terms.keys.filter { schema[$0] == nil || schema[$0] != terms[$0] }.sorted().map { .string($0.s) }
    }

    static func runFn(_ v: M) -> JSONValue {
        let i = o(v["input"])
        switch s(v["fn"]) {
        case "canon": return obj([("canon", .string(canon(v["input"]))), ("digest", .string(goalDigest(v["input"])))])
        case "units": return .array(units(o(i["schema"]), o(i["terms"])))
        case "polarity": return .array(polarity(a(v["input"])))
        case "meet": return .string(meet(s(i["decision"]), s(i["signal"])))
        case "pep":
            let d = s(i["decision"])
            if d == "allow" { return .bool(true) }
            if d == "deny" { return .bool(false) }
            let ans = o(i["answer"]), ctx = o(i["ctx"])
            if ans["valid"] != .bool(true) { return .bool(false) }
            for k in ["policy_digest", "action_digest", "history_head"] where ans[JKey(k)] != ctx[JKey(k)] { return .bool(false) }
            return .bool(true)
        case "commit":
            let c = b64("pca-goal:v3:commit:" + s(i["goal_digest"]) + ":" + s(i["policy_digest"]) + ":" + s(i["salt"]))
            return obj([("commit", .string(c)), ("opens_other_goal", .bool(false))])
        case "claim":
            if nn(i["replayed_ppm"]) && iv(i["replayed_ppm"]) < iv(i["min_ppm"]) { return .string(meet(s(i["base"]), "escalate")) }
            return .string(s(i["base"]))
        default: return .string("unknown fn " + s(v["fn"]))
        }
    }
}

final class GoalVectorTests: XCTestCase {
    /// The mirrors vendor the corpus at <conformance>/goal; the monorepo keeps it at packages/pca-conformance/vectors/goal.
    static let goalDir: URL = {
        let vendored = ConformanceTests.conformanceDir.appendingPathComponent("goal", isDirectory: true)
        if FileManager.default.fileExists(atPath: vendored.appendingPathComponent("index.json").path) { return vendored }
        return ConformanceTests.conformanceDir.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("packages/pca-conformance/vectors/goal", isDirectory: true)
    }()

    static func files() throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: goalDir.path).filter { $0.hasSuffix(".json") && $0 != "index.json" }.sorted()
    }

    static func load(_ name: String) throws -> JSONValue {
        try StrictJSON.parseLenient(ConformanceTests.readText(goalDir.appendingPathComponent(name)))
    }

    func testIndexMatchesTheFiles() throws {
        let idx = try Self.load("index.json")
        XCTAssertEqual(idx.get("format")?.asString, "pca-goal-vectors/2")
        let names = try Self.files()
        let counts = idx.get("counts")?.asObject ?? [:]
        let total = counts.values.reduce(Int64(0)) { $0 + ($1.safeInt ?? 0) }
        XCTAssertEqual(Int64(names.count), total, "index.json counts do not match the vector files")
        XCTAssertEqual(idx.get("cases")?.asArray?.count, names.count)
    }

    func testGoalDigestsDecisionsAndHelperVectors() throws {
        let names = try Self.files()
        XCTAssertGreaterThanOrEqual(names.count, 240)
        var bad: [String] = []
        var probes = 0
        for n in names {
            let v = try Self.load(n)
            guard case let .object(vo) = v else { bad.append("\(n): not an object"); continue }
            let id = GoalRef.s(vo["id"])
            if GoalRef.s(vo["kind"]) == "fn" {
                if GoalRef.canon(GoalRef.runFn(vo)) != GoalRef.canon(vo["expect"]) { bad.append(id) }
                continue
            }
            if GoalRef.goalDigest(vo["goal"]) != GoalRef.s(vo["goal_digest"]) { bad.append("\(id):goal_digest") }
            guard GoalRef.o(vo["compile"])["ok"] == .bool(true) else { continue }
            if GoalRef.hashCanon(GoalRef.lower(GoalRef.o(vo["ontology"]), GoalRef.o(vo["goal"]))) != GoalRef.s(vo["policy_digest"]) { bad.append("\(id):policy_digest") }
            for (i, p) in GoalRef.a(vo["probes"]).enumerated() {
                probes += 1
                let pp = GoalRef.o(p)
                let got = GoalRef.decide(GoalRef.o(vo["goal"]), GoalRef.o(vo["ontology"]), GoalRef.o(pp["action"]), GoalRef.o(pp["history"]))
                if GoalRef.canon(got) != GoalRef.canon(pp["expect"]) { bad.append("\(id)#\(i)") }
            }
        }
        XCTAssertGreaterThan(probes, 6000)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) disagreements:\n" + bad.prefix(30).joined(separator: "\n"))
    }

    // ---- exact outcomes beyond the corpus ----

    func testMeetAndClaimNeverRaiseADecision() {
        XCTAssertEqual(GoalRef.meet("allow", "escalate"), "escalate")
        XCTAssertEqual(GoalRef.meet("escalate", "allow"), "escalate")
        XCTAssertEqual(GoalRef.meet("deny", "escalate"), "deny")
        XCTAssertEqual(GoalRef.meet("allow", "ok"), "allow")
        // the canonical form writes control characters as \u00xx and sorts keys by UTF-8 bytes
        XCTAssertEqual(GoalRef.canon(.object(["b": .int(1), "a": .string("x\n\"y")])), "{\"a\":\"x\\n\\\"y\",\"b\":1}")
    }
}
