import Foundation

/// The token-tape form of the Goal IR. A tape is an array of tokens; a token is a two-element array `["k", n]` (keyword),
/// `["i", n]` (integer) or `["s", text]`. Encoding is strict: anything that is not exactly an IR value throws `IrError`.
/// Goals, ontologies, acts and histories are parsed-JSON objects shaped like the TypeScript IR.
public enum PCAGoalCodec {
    public static let OPS: [String] = ["eq", "ne", "lt", "lte", "gt", "gte", "in", "nin"]
    public static let AGGS: [String] = ["count", "sum", "max", "distinct"]

    /// The tape being written.
    final class Tp {
        var t: [JSONValue] = []
        func add(_ v: JSONValue) { t.append(v) }
    }

    private static func tok(_ t: String, _ v: JSONValue) -> JSONValue { return JSONValue.array([JSONValue.string(t), v]) }
    private static func kw(_ n: Int64) -> JSONValue { return tok("k", JSONValue.int(n)) }
    private static func iv(_ v: JSONValue?) throws -> JSONValue {
        guard let n = GV.safeInt(v) else { throw IrError(GV.jsStr(v) + " is not a safe integer") }
        return tok("i", JSONValue.int(n))
    }
    private static func iv(_ n: Int64) -> JSONValue { return tok("i", JSONValue.int(n)) }
    private static func sv(_ s: JSONValue?) throws -> JSONValue {
        guard let x = s, let str = x.asString else { throw IrError("string expected") }
        return tok("s", JSONValue.string(str))
    }
    private static func bad(_ what: String, _ v: JSONValue?) -> IrError {
        let s: String = v == nil ? "undefined" : GV.stringify(v)
        return IrError("unknown " + what + ": " + s)
    }

    private static func list(_ out: Tp, _ xs: JSONValue?, _ f: (JSONValue) throws -> Void) throws {
        guard let a = GV.l(xs) else { throw IrError("array expected") }
        out.add(iv(Int64(a.count)))
        for x in a { try f(x) }
    }

    private static func strs(_ out: Tp, _ xs: JSONValue?) throws {
        try list(out, xs) { (s: JSONValue) throws -> Void in out.add(try sv(s)) }
    }

    private static func unit(_ out: Tp, _ u: JSONValue?) throws {
        switch GV.kind(u) {
        case "money":
            out.add(kw(300))
            out.add(try sv(GV.get(u, "ccy")))
        case "count": out.add(kw(301))
        case "duration": out.add(kw(302))
        case "instant": out.add(kw(303))
        case "bytes": out.add(kw(304))
        case "ratio": out.add(kw(305))
        default: throw bad("unit", u)
        }
    }

    private static func quantity(_ out: Tp, _ q: JSONValue?) throws {
        try unit(out, GV.get(q, "u"))
        out.add(try iv(GV.get(q, "n")))
    }

    private static func ty(_ out: Tp, _ t: JSONValue?) throws {
        let k = GV.kind(t)
        if k == "q" {
            out.add(kw(310))
            try unit(out, GV.get(t, "u"))
        } else if k == "s" {
            out.add(kw(311))
        } else { throw bad("type", t) }
    }

    private static func atom(_ out: Tp, _ a: JSONValue?) throws {
        let k = GV.kind(a)
        if k == "q" {
            out.add(kw(320))
            try quantity(out, GV.get(a, "q"))
        } else if k == "s" {
            out.add(kw(321))
            out.add(try sv(GV.get(a, "s")))
        } else { throw bad("set member (sets hold quantities and strings only)", a) }
    }

    private static func value(_ out: Tp, _ v: JSONValue?) throws {
        switch GV.kind(v) {
        case "q":
            out.add(kw(330))
            try quantity(out, GV.get(v, "q"))
        case "s":
            out.add(kw(331))
            out.add(try sv(GV.get(v, "s")))
        case "set":
            out.add(kw(332))
            try list(out, GV.get(v, "items")) { (x: JSONValue) throws -> Void in try atom(out, x) }
        default: throw bad("value", v)
        }
    }

    private static func term(_ out: Tp, _ t: JSONValue?) throws {
        switch GV.kind(t) {
        case "param":
            out.add(kw(340))
            out.add(try sv(GV.get(t, "path")))
            try ty(out, GV.get(t, "ty"))
        case "lit":
            out.add(kw(341))
            try value(out, GV.get(t, "v"))
        case "hist":
            out.add(kw(342))
            out.add(try sv(GV.get(t, "bid")))
            try unit(out, GV.get(t, "u"))
        default: throw bad("term", t)
        }
    }

    private static func op(_ out: Tp, _ o: JSONValue?) throws {
        var i = -1
        if let s = o?.asString { i = OPS.firstIndex(where: { IV.same($0, s) }) ?? -1 }
        if i < 0 { throw bad("operator", o) }
        out.add(kw(Int64(350 + i)))
    }

    private static func cond(_ out: Tp, _ c: JSONValue?) throws {
        switch GV.kind(c) {
        case "true": out.add(kw(360))
        case "cmp":
            out.add(kw(361))
            try op(out, GV.get(c, "op"))
            try term(out, GV.get(c, "l"))
            try term(out, GV.get(c, "r"))
        case "and":
            out.add(kw(362))
            try cond(out, GV.get(c, "a"))
            try cond(out, GV.get(c, "b"))
        case "or":
            out.add(kw(363))
            try cond(out, GV.get(c, "a"))
            try cond(out, GV.get(c, "b"))
        case "not":
            out.add(kw(364))
            try cond(out, GV.get(c, "c"))
        default: throw bad("condition", c)
        }
    }

    private static func part(_ out: Tp, _ s: JSONValue?) throws {
        switch GV.kind(s) {
        case "exact":
            out.add(kw(375))
            out.add(try sv(GV.get(s, "id")))
        case "oneof":
            out.add(kw(376))
            try strs(out, GV.get(s, "ids"))
        case "related":
            out.add(kw(377))
            out.add(try sv(GV.get(s, "rel")))
            out.add(try sv(GV.get(s, "anchor")))
        default: throw bad("resource part", s)
        }
    }

    private static func res(_ out: Tp, _ s: JSONValue?) throws {
        switch GV.kind(s) {
        case "exact":
            out.add(kw(370))
            out.add(try sv(GV.get(s, "id")))
        case "oneof":
            out.add(kw(371))
            try strs(out, GV.get(s, "ids"))
        case "related":
            out.add(kw(372))
            out.add(try sv(GV.get(s, "rel")))
            out.add(try sv(GV.get(s, "anchor")))
        case "any":
            out.add(kw(373))
            out.add(try sv(GV.get(s, "reason")))
        case "all_of":
            out.add(kw(374))
            try list(out, GV.get(s, "parts")) { (x: JSONValue) throws -> Void in try part(out, x) }
        default: throw bad("resource selector", s)
        }
    }

    private static func grant(_ out: Tp, _ g: JSONValue?) throws {
        out.add(kw(380))
        out.add(try sv(GV.get(g, "gid")))
        out.add(try sv(GV.get(g, "verb")))
        try res(out, GV.get(g, "res"))
        try cond(out, GV.get(g, "cond"))
    }

    private static func target(_ out: Tp, _ t: JSONValue?) throws {
        let k = GV.kind(t)
        if k == "verb" {
            out.add(kw(390))
            out.add(try sv(GV.get(t, "verb")))
        } else if k == "effect" {
            out.add(kw(391))
            out.add(try sv(GV.get(t, "cls")))
        } else { throw bad("prohibit target", t) }
    }

    private static func prohibit(_ out: Tp, _ p: JSONValue?) throws {
        out.add(kw(392))
        out.add(try sv(GV.get(p, "pid")))
        try target(out, GV.get(p, "target"))
        try res(out, GV.get(p, "res"))
        try cond(out, GV.get(p, "cond"))
    }

    private static func sel(_ out: Tp, _ s: JSONValue?) throws {
        let k = GV.kind(s)
        if k == "gids" {
            out.add(kw(410))
            try strs(out, GV.get(s, "gids"))
        } else if k == "effect" {
            out.add(kw(411))
            out.add(try sv(GV.get(s, "cls")))
        } else { throw bad("selection", s) }
    }

    private static func window(_ out: Tp, _ w: JSONValue?) throws {
        switch GV.kind(w) {
        case "task": out.add(kw(420))
        case "sliding":
            out.add(kw(421))
            out.add(try iv(GV.get(w, "ms")))
        case "period":
            out.add(kw(422))
            out.add(try iv(GV.get(w, "ms")))
            out.add(try iv(GV.get(w, "t0")))
        case "lifetime": out.add(kw(423))
        default: throw bad("window", w)
        }
    }

    private static func scope(_ out: Tp, _ s: JSONValue?) throws {
        switch GV.kind(s) {
        case "session": out.add(kw(430))
        case "principal": out.add(kw(431))
        case "org": out.add(kw(432))
        case "fleet":
            out.add(kw(433))
            try strs(out, GV.get(s, "agents"))
        default: throw bad("scope", s)
        }
    }

    private static func onExceed(_ out: Tp, _ o: JSONValue?) throws {
        if let s = o?.asString, IV.same(s, "deny") { out.add(kw(440)) }
        else if let s = o?.asString, IV.same(s, "escalate") { out.add(kw(441)) }
        else { throw bad("on_exceed", o) }
    }

    private static func bcore(_ out: Tp, _ b: JSONValue?) throws {
        let agg = GV.get(b, "agg")
        var a = -1
        if let s = agg?.asString { a = AGGS.firstIndex(where: { IV.same($0, s) }) ?? -1 }
        if a < 0 { throw bad("aggregate", agg) }
        out.add(kw(450))
        out.add(kw(Int64(400 + a)))
        try term(out, GV.get(b, "value"))
        out.add(try sv(GV.get(b, "key")))
        try window(out, GV.get(b, "window"))
        try scope(out, GV.get(b, "scope"))
        try quantity(out, GV.get(b, "cap"))
        try onExceed(out, GV.get(b, "onExceed"))
    }

    private static func bound(_ out: Tp, _ b: JSONValue?) throws {
        out.add(kw(451))
        out.add(try sv(GV.get(b, "bid")))
        try sel(out, GV.get(b, "sel"))
        try bcore(out, b)
    }

    private static func validity(_ out: Tp, _ v: JSONValue?) throws {
        out.add(kw(460))
        out.add(try iv(GV.get(v, "notBefore")))
        out.add(try iv(GV.get(v, "notAfter")))
        out.add(try iv(GV.get(v, "maxIdle")))
    }

    private static func deleg(_ out: Tp, _ d: JSONValue?) throws {
        out.add(kw(461))
        out.add(try iv(GV.get(d, "maxDepth")))
        out.add(iv(GV.truthy(GV.get(d, "narrowOnly")) ? 1 : 0))
        try strs(out, GV.get(d, "mayTouch"))
    }

    private static func hole(_ out: Tp, _ h: JSONValue?) throws {
        out.add(kw(470))
        out.add(try sv(GV.get(h, "hid")))
        out.add(try sv(GV.get(h, "q")))
        try strs(out, GV.get(h, "domain"))
        try strs(out, GV.get(h, "affects"))
        out.add(iv(GV.truthy(GV.get(h, "global")) ? 1 : 0))
    }

    // ---- the public encoders of single IR parts (encUnit, encQ, encV, encTerm, encCond of the reference) ----

    public static func encUnit(_ u: JSONValue?) throws -> [JSONValue] { let o = Tp(); try unit(o, u); return o.t }
    public static func encQ(_ q: JSONValue?) throws -> [JSONValue] { let o = Tp(); try quantity(o, q); return o.t }
    public static func encV(_ v: JSONValue?) throws -> [JSONValue] { let o = Tp(); try value(o, v); return o.t }
    public static func encTerm(_ t: JSONValue?) throws -> [JSONValue] { let o = Tp(); try term(o, t); return o.t }
    public static func encCond(_ c: JSONValue?) throws -> [JSONValue] { let o = Tp(); try cond(o, c); return o.t }

    /// The goal as a token tape.
    public static func encodeGoal(_ g: JSONValue) throws -> JSONValue {
        let out = Tp()
        out.add(kw(480))
        out.add(try iv(GV.get(g, "v")))
        out.add(try sv(GV.get(g, "principal")))
        out.add(try sv(GV.get(g, "ontDigest")))
        out.add(try sv(GV.get(g, "nlDigest")))
        try strs(out, GV.get(g, "sources"))
        try list(out, GV.get(g, "grants")) { (x: JSONValue) throws -> Void in try grant(out, x) }
        try list(out, GV.get(g, "prohibits")) { (x: JSONValue) throws -> Void in try prohibit(out, x) }
        try list(out, GV.get(g, "bounds")) { (x: JSONValue) throws -> Void in try bound(out, x) }
        try validity(out, GV.get(g, "validity"))
        try deleg(out, GV.get(g, "deleg"))
        try list(out, GV.get(g, "escalateOn")) { (x: JSONValue) throws -> Void in try cond(out, x) }
        try strs(out, GV.get(g, "wildcardAck"))
        try list(out, GV.get(g, "holes")) { (x: JSONValue) throws -> Void in try hole(out, x) }
        return JSONValue.array(out.t)
    }

    public static func encodeOntology(_ o: JSONValue) throws -> JSONValue {
        let out = Tp()
        out.add(kw(510))
        try list(out, GV.get(o, "verbs")) { (v: JSONValue) throws -> Void in
            out.add(kw(501))
            out.add(try sv(GV.get(v, "verb")))
            out.add(try sv(GV.get(v, "cls")))
            try list(out, GV.get(v, "params")) { (p: JSONValue) throws -> Void in
                out.add(kw(500))
                out.add(try sv(GV.get(p, "path")))
                try ty(out, GV.get(p, "ty"))
            }
        }
        try list(out, GV.get(o, "rels")) { (r: JSONValue) throws -> Void in
            out.add(kw(502))
            out.add(try sv(GV.get(r, "rel")))
            out.add(try sv(GV.get(r, "anchor")))
            try strs(out, GV.get(r, "members"))
        }
        return JSONValue.array(out.t)
    }

    /// `Object.keys(o).sort()`: null / undefined throw (TypeError), arrays and strings expose their indices, other scalars have none.
    private static func sortedKeys(_ o: JSONValue?) throws -> [String] {
        guard let v = o else { throw IrError("object expected") }
        var ks: [String] = []
        switch v {
        case .null: throw IrError("object expected")
        case .object(let m): for k in m.keys { ks.append(k.s) }
        case .array(let a): for i in 0..<a.count { ks.append(String(i)) }
        case .string(let s): for i in 0..<s.utf16.count { ks.append(String(i)) }
        default: break
        }
        ks.sort(by: { GV.less($0, $1) })
        return ks
    }

    private static func member(_ o: JSONValue?, _ k: String) -> JSONValue? {
        guard let v = o else { return nil }
        switch v {
        case .array(let a): if let i = Int(k), i >= 0, i < a.count { return a[i] } else { return nil }
        case .string(let s):
            // an indexed character of a string: a one-code-unit string value (never a valid IR value)
            let u = Array(s.utf16)
            if let i = Int(k), i >= 0, i < u.count { return JSONValue.string(String(decoding: [u[i]], as: UTF16.self)) } else { return nil }
        default: return GV.get(v, k)
        }
    }

    private static func act(_ out: Tp, _ a: JSONValue?) throws {
        let params = GV.get(a, "params")
        let keys = try sortedKeys(params)
        out.add(kw(530))
        out.add(try sv(GV.get(a, "verb")))
        out.add(try sv(GV.get(a, "res")))
        out.add(iv(Int64(keys.count)))
        for k in keys {
            out.add(kw(520))
            out.add(try sv(JSONValue.string(k)))
            try value(out, member(params, k))
        }
        out.add(try iv(GV.get(a, "t")))
        out.add(try sv(GV.get(a, "sess")))
        out.add(try sv(GV.get(a, "prin")))
        out.add(try sv(GV.get(a, "org")))
        out.add(try sv(GV.get(a, "agent")))
        out.add(try iv(GV.get(a, "depth")))
    }

    public static func encodeAct(_ a: JSONValue) throws -> JSONValue {
        let out = Tp()
        try act(out, a)
        return JSONValue.array(out.t)
    }

    public static func encodeHist(_ h: JSONValue) throws -> JSONValue {
        let out = Tp()
        let aggs = GV.get(h, "aggs")
        let keys = try sortedKeys(aggs)
        out.add(kw(541))
        try list(out, GV.get(h, "adms")) { (a: JSONValue) throws -> Void in
            out.add(kw(531))
            out.add(try sv(GV.get(a, "gid")))
            try act(out, GV.get(a, "act"))
        }
        out.add(try iv(GV.get(h, "last")))
        out.add(iv(Int64(keys.count)))
        for k in keys {
            out.add(kw(540))
            out.add(try sv(JSONValue.string(k)))
            try quantity(out, member(aggs, k))
        }
        return JSONValue.array(out.t)
    }

    // ---- decoding ----

    /// A cursor over a tape (the reference's `TapeReader`).
    public final class Rd {
        private let t: [JSONValue]
        private var i = 0

        public init(_ tape: JSONValue) throws {
            guard let a = tape.asArray else { throw IrError("tape expected") }
            self.t = a
        }

        init(tokens: [JSONValue]) { self.t = tokens }

        private func next() throws -> [JSONValue] {
            if i >= t.count { throw IrError("truncated tape") }
            let x = t[i]
            i += 1
            guard let a = x.asArray, a.count == 2 else { throw IrError("malformed token") }
            return a
        }

        private func tag(_ x: [JSONValue], _ want: String) -> Bool {
            guard let s = x[0].asString else { return false }
            return IV.same(s, want)
        }

        private func tokInt(_ v: JSONValue) throws -> Int64 {
            guard let n = GV.safeInt(v) else { throw IrError("integer expected") }
            return n
        }

        public func k() throws -> Int64 {
            let x = try next()
            if !tag(x, "k") { throw IrError("keyword expected") }
            return try tokInt(x[1])
        }

        public func integer() throws -> Int64 {
            let x = try next()
            if !tag(x, "i") { throw IrError("integer expected") }
            return try tokInt(x[1])
        }

        public func str() throws -> String {
            let x = try next()
            guard tag(x, "s"), let s = x[1].asString else { throw IrError("string expected") }
            return s
        }

        public func done() -> Bool { return i >= t.count }

        public func list(_ f: () throws -> JSONValue) throws -> JSONValue {
            let n = try integer()
            if n < 0 { throw IrError("negative length") }
            var out: [JSONValue] = []
            var j: Int64 = 0
            while j < n {
                out.append(try f())
                j += 1
            }
            return JSONValue.array(out)
        }

        public func strs() throws -> JSONValue { return try list { () throws -> JSONValue in JSONValue.string(try self.str()) } }
    }

    private static func s(_ x: String) -> JSONValue { return JSONValue.string(x) }
    private static func n(_ x: Int64) -> JSONValue { return JSONValue.int(x) }

    private static func dUnit(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 300 { return GV.obj([("k", s("money")), ("ccy", s(try r.str()))]) }
        let u: String
        switch k {
        case 301: u = "count"
        case 302: u = "duration"
        case 303: u = "instant"
        case 304: u = "bytes"
        case 305: u = "ratio"
        default: throw IrError("bad unit tag \(k)")
        }
        return GV.obj([("k", s(u))])
    }

    private static func dQ(_ r: Rd) throws -> JSONValue {
        let u = try dUnit(r)
        return GV.obj([("u", u), ("n", n(try r.integer()))])
    }

    private static func dTy(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 310 { return GV.obj([("k", s("q")), ("u", try dUnit(r))]) }
        if k == 311 { return GV.obj([("k", s("s"))]) }
        throw IrError("bad type tag \(k)")
    }

    private static func dAtom(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 320 { return GV.obj([("k", s("q")), ("q", try dQ(r))]) }
        if k == 321 { return GV.obj([("k", s("s")), ("s", s(try r.str()))]) }
        throw IrError("bad atom tag \(k)")
    }

    private static func dV(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 330 { return GV.obj([("k", s("q")), ("q", try dQ(r))]) }
        if k == 331 { return GV.obj([("k", s("s")), ("s", s(try r.str()))]) }
        if k == 332 { return GV.obj([("k", s("set")), ("items", try r.list { () throws -> JSONValue in try dAtom(r) })]) }
        throw IrError("bad value tag \(k)")
    }

    private static func dTerm(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 340 {
            let p = try r.str()
            return GV.obj([("k", s("param")), ("path", s(p)), ("ty", try dTy(r))])
        }
        if k == 341 { return GV.obj([("k", s("lit")), ("v", try dV(r))]) }
        if k == 342 {
            let b = try r.str()
            return GV.obj([("k", s("hist")), ("bid", s(b)), ("u", try dUnit(r))])
        }
        throw IrError("bad term tag \(k)")
    }

    private static func dOp(_ r: Rd) throws -> String {
        let k = try r.k() - 350
        if k < 0 || k >= Int64(OPS.count) { throw IrError("bad operator") }
        return OPS[Int(k)]
    }

    private static func dN(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 600 { return GV.obj([("k", s("true"))]) }
        if k == 601 { return GV.obj([("k", s("false"))]) }
        if k == 602 {
            let op = try dOp(r)
            let l = try dTerm(r)
            return GV.obj([("k", s("atom")), ("op", s(op)), ("l", l), ("r", try dTerm(r))])
        }
        if k == 603 {
            let a = try dN(r)
            return GV.obj([("k", s("and")), ("a", a), ("b", try dN(r))])
        }
        if k == 604 {
            let a = try dN(r)
            return GV.obj([("k", s("or")), ("a", a), ("b", try dN(r))])
        }
        throw IrError("bad condition tag \(k)")
    }

    private static func dResPat(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 630 { return GV.obj([("k", s("star"))]) }
        if k == 631 { return GV.obj([("k", s("set")), ("ids", try r.strs())]) }
        throw IrError("bad resource pattern tag \(k)")
    }

    private static func dWindow(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 420 { return GV.obj([("k", s("task"))]) }
        if k == 421 { return GV.obj([("k", s("sliding")), ("ms", n(try r.integer()))]) }
        if k == 422 {
            let ms = try r.integer()
            return GV.obj([("k", s("period")), ("ms", n(ms)), ("t0", n(try r.integer()))])
        }
        if k == 423 { return GV.obj([("k", s("lifetime"))]) }
        throw IrError("bad window tag \(k)")
    }

    private static func dScope(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 430 { return GV.obj([("k", s("session"))]) }
        if k == 431 { return GV.obj([("k", s("principal"))]) }
        if k == 432 { return GV.obj([("k", s("org"))]) }
        if k == 433 { return GV.obj([("k", s("fleet")), ("agents", try r.strs())]) }
        throw IrError("bad scope tag \(k)")
    }

    /// Remaining fields of a bound core after the 450 tag: agg, value, key, window, scope, cap, onExceed.
    private static func dBoundCore(_ r: Rd, _ into: inout JObject) throws {
        let ak = try r.k() - 400
        if ak < 0 || ak >= Int64(AGGS.count) { throw IrError("bad aggregate") }
        into[JKey("agg")] = s(AGGS[Int(ak)])
        into[JKey("value")] = try dTerm(r)
        into[JKey("key")] = s(try r.str())
        into[JKey("window")] = try dWindow(r)
        into[JKey("scope")] = try dScope(r)
        into[JKey("cap")] = try dQ(r)
        let oe = try r.k()
        if oe != 440 && oe != 441 { throw IrError("bad on_exceed") }
        into[JKey("onExceed")] = s(oe == 440 ? "deny" : "escalate")
    }

    private static func dCeil(_ r: Rd) throws -> JSONValue {
        if try r.k() != 610 { throw IrError("ceiling expected") }
        var m = JObject()
        m[JKey("bid")] = s(try r.str())
        m[JKey("selGids")] = try r.strs()
        m[JKey("selVerbs")] = try r.strs()
        if try r.k() != 450 { throw IrError("bound core expected") }
        try dBoundCore(r, &m)
        return JSONValue.object(m)
    }

    /// Decode the compiler's policy tape (the leading status token already consumed).
    public static func decodePolicy(_ t: JSONValue) throws -> JSONValue {
        let r = try Rd(t)
        if try r.k() != 650 { throw IrError("policy expected") }
        let preds = try r.list { () throws -> JSONValue in
            if try r.k() != 620 { throw IrError("pred") }
            let gid = try r.str()
            let verb = try r.str()
            let rp = try dResPat(r)
            return GV.obj([("gid", s(gid)), ("verb", s(verb)), ("res", rp), ("cond", try dN(r))])
        }
        let prohs = try r.list { () throws -> JSONValue in
            if try r.k() != 640 { throw IrError("prohibition") }
            let pid = try r.str()
            let vs = try r.strs()
            let rp = try dResPat(r)
            return GV.obj([("pid", s(pid)), ("verbs", vs), ("res", rp), ("cond", try dN(r))])
        }
        let ceils = try r.list { () throws -> JSONValue in try dCeil(r) }
        let escs = try r.list { () throws -> JSONValue in try dN(r) }
        if try r.k() != 460 { throw IrError("validity") }
        let nb = try r.integer()
        let na = try r.integer()
        let mi = try r.integer()
        let validity = GV.obj([("notBefore", n(nb)), ("notAfter", n(na)), ("maxIdle", n(mi))])
        if try r.k() != 461 { throw IrError("delegation") }
        let md = try r.integer()
        let no = try r.integer() == 1
        let mt = try r.strs()
        let deleg = GV.obj([("maxDepth", n(md)), ("narrowOnly", JSONValue.bool(no)), ("mayTouch", mt)])
        if !r.done() { throw IrError("trailing tokens after policy") }
        return GV.obj([("preds", preds), ("prohs", prohs), ("ceils", ceils), ("escs", escs), ("validity", validity), ("deleg", deleg)])
    }

    private static func dCond(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 360 { return GV.obj([("k", s("true"))]) }
        if k == 361 {
            let op = try dOp(r)
            let l = try dTerm(r)
            return GV.obj([("k", s("cmp")), ("op", s(op)), ("l", l), ("r", try dTerm(r))])
        }
        if k == 362 {
            let a = try dCond(r)
            return GV.obj([("k", s("and")), ("a", a), ("b", try dCond(r))])
        }
        if k == 363 {
            let a = try dCond(r)
            return GV.obj([("k", s("or")), ("a", a), ("b", try dCond(r))])
        }
        if k == 364 { return GV.obj([("k", s("not")), ("c", try dCond(r))]) }
        throw IrError("bad condition tag \(k)")
    }

    private static func dPart(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 375 { return GV.obj([("k", s("exact")), ("id", s(try r.str()))]) }
        if k == 376 { return GV.obj([("k", s("oneof")), ("ids", try r.strs())]) }
        if k == 377 {
            let rel = try r.str()
            return GV.obj([("k", s("related")), ("rel", s(rel)), ("anchor", s(try r.str()))])
        }
        throw IrError("bad resource part tag \(k)")
    }

    private static func dRes(_ r: Rd) throws -> JSONValue {
        let k = try r.k()
        if k == 370 { return GV.obj([("k", s("exact")), ("id", s(try r.str()))]) }
        if k == 371 { return GV.obj([("k", s("oneof")), ("ids", try r.strs())]) }
        if k == 372 {
            let rel = try r.str()
            return GV.obj([("k", s("related")), ("rel", s(rel)), ("anchor", s(try r.str()))])
        }
        if k == 373 { return GV.obj([("k", s("any")), ("reason", s(try r.str()))]) }
        if k == 374 { return GV.obj([("k", s("all_of")), ("parts", try r.list { () throws -> JSONValue in try dPart(r) })]) }
        throw IrError("bad resource selector tag \(k)")
    }

    private static func expect(_ r: Rd, _ k: Int64, _ what: String) throws {
        if try r.k() != k { throw IrError(what + " expected") }
    }

    /// Parse a goal tape; throws IrError unless the whole tape is exactly one goal.
    public static func decodeGoal(_ t: JSONValue) throws -> JSONValue {
        let r = try Rd(t)
        try expect(r, 480, "goal")
        let v = try r.integer()
        let principal = try r.str()
        let ontDigest = try r.str()
        let nlDigest = try r.str()
        let sources = try r.strs()
        let grants = try r.list { () throws -> JSONValue in
            try expect(r, 380, "grant")
            let gid = try r.str()
            let verb = try r.str()
            let rs = try dRes(r)
            return GV.obj([("gid", s(gid)), ("verb", s(verb)), ("res", rs), ("cond", try dCond(r))])
        }
        let prohibits = try r.list { () throws -> JSONValue in
            try expect(r, 392, "prohibit")
            let pid = try r.str()
            let tk = try r.k()
            let target: JSONValue
            if tk == 390 { target = GV.obj([("k", s("verb")), ("verb", s(try r.str()))]) }
            else if tk == 391 { target = GV.obj([("k", s("effect")), ("cls", s(try r.str()))]) }
            else { throw IrError("bad prohibit target") }
            let rs = try dRes(r)
            return GV.obj([("pid", s(pid)), ("target", target), ("res", rs), ("cond", try dCond(r))])
        }
        let bounds = try r.list { () throws -> JSONValue in
            try expect(r, 451, "bound")
            var m = JObject()
            m[JKey("bid")] = s(try r.str())
            let sk = try r.k()
            if sk == 410 { m[JKey("sel")] = GV.obj([("k", s("gids")), ("gids", try r.strs())]) }
            else if sk == 411 { m[JKey("sel")] = GV.obj([("k", s("effect")), ("cls", s(try r.str()))]) }
            else { throw IrError("bad selection") }
            try expect(r, 450, "bound core")
            try dBoundCore(r, &m)
            return JSONValue.object(m)
        }
        try expect(r, 460, "validity")
        let nb = try r.integer()
        let na = try r.integer()
        let mi = try r.integer()
        let validity = GV.obj([("notBefore", n(nb)), ("notAfter", n(na)), ("maxIdle", n(mi))])
        try expect(r, 461, "delegation")
        let md = try r.integer()
        let no = try r.integer() == 1
        let mt = try r.strs()
        let deleg = GV.obj([("maxDepth", n(md)), ("narrowOnly", JSONValue.bool(no)), ("mayTouch", mt)])
        let escalateOn = try r.list { () throws -> JSONValue in try dCond(r) }
        let wildcardAck = try r.strs()
        let holes = try r.list { () throws -> JSONValue in
            try expect(r, 470, "hole")
            let hid = try r.str()
            let q = try r.str()
            let dom = try r.strs()
            let aff = try r.strs()
            let gl = try r.integer() == 1
            return GV.obj([("hid", s(hid)), ("q", s(q)), ("domain", dom), ("affects", aff), ("global", JSONValue.bool(gl))])
        }
        if !r.done() { throw IrError("trailing tokens after goal") }
        return GV.obj([
            ("v", n(v)), ("principal", s(principal)), ("ontDigest", s(ontDigest)), ("nlDigest", s(nlDigest)), ("sources", sources),
            ("grants", grants), ("prohibits", prohibits), ("bounds", bounds), ("validity", validity), ("deleg", deleg),
            ("escalateOn", escalateOn), ("wildcardAck", wildcardAck), ("holes", holes),
        ])
    }
}
