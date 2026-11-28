import Foundation

/// The history checker of pca-store-conformance (model.ts, search.ts, check.ts): a recorded history of `consumeOnce` / `advance` operations is checked for
/// linearizability against ONE register model, per key (P-compositionality), with sound verdict-preserving reductions, an exact decision when no outcome is
/// unknown, a BUDGETED Wing-Gong search otherwise (a key over budget is UNRESOLVED, never a pass) and a 1-minimal counterexample per violating key.
///
/// The register `s` starts at -infinity. A TRUE answer is legal iff `s < lo` and then `s := max(s, w)`; a FALSE answer is legal iff `s >= lo` and leaves `s`
/// unchanged; an UNKNOWN outcome from `s < lo` may leave `s` or move it to `max(s, w)`. The register never decreases.
public enum PCAStoreConformance {
    public static let DEFAULT_SEARCH_BUDGET = 200_000

    public struct Op: Equatable {
        public var client: String
        /// `consume` or `advance`.
        public var kind: String
        public var key: String
        public var lo: Double
        public var w: Double
        public var call: Double
        /// +infinity when the outcome is unknown.
        public var ret: Double
        /// `true`, `false` or `unknown`.
        public var res: String
        public init(client: String, kind: String, key: String, lo: Double, w: Double, call: Double, ret: Double, res: String) {
            self.client = client; self.kind = kind; self.key = key; self.lo = lo; self.w = w; self.call = call; self.ret = ret; self.res = res
        }
    }

    public struct KeyResult: Equatable {
        public var key: String
        public var kind: String
        public var ops: Int
        public var searched: Int
        public var verdict: String
        public var method: String
        public var counterexample: [Op]?
        public var minimized: Bool?
    }

    public struct HistoryCheck: Equatable {
        public var ops: Int
        public var keys: Int
        public var ok: Bool
        public var outcomes: [String: Int]
        public var violations: [KeyResult]
        public var unresolved: [KeyResult]
    }

    /// JavaScript's stable sort by a numeric key.
    private static func stable(_ ops: [Op], by key: (Op) -> Double) -> [Op] {
        ops.enumerated().sorted { a, b in
            let x = key(a.element), y = key(b.element)
            return x == y ? a.offset < b.offset : x < y
        }.map { $0.element }
    }

    /// The register's successor states after `op` from `s` (empty: the answer is impossible from `s`).
    public static func step(_ s: Double, _ op: Op) -> [Double] {
        let fresh = s < op.lo
        if op.res == "true" { return fresh ? [Swift.max(s, op.w)] : [] }
        if op.res == "false" { return fresh ? [] : [s] }
        return fresh ? [s, Swift.max(s, op.w)] : [s]
    }

    /// Two definite TRUE answers whose [lo, w] intervals overlap can never both linearize; returns such a pair (the minimal counterexample), or nil.
    public static func overlappingTrues(_ ops: [Op]) -> (Op, Op)? {
        let ts = stable(ops.filter { $0.res == "true" }, by: { $0.lo })
        if ts.count < 2 { return nil }
        for i in 1..<ts.count where ts[i - 1].w >= ts[i].lo { return (ts[i - 1], ts[i]) }
        return nil
    }

    /// Drop every definite FALSE that a definite TRUE explains (a TRUE with `w >= lo` that returned before the FALSE was invoked).
    public static func prune(_ ops: [Op]) -> [Op] {
        let ts = stable(ops.filter { $0.res == "true" }, by: { $0.ret })
        var pm: [Double] = []
        for t in ts { pm.append(Swift.max(t.w, pm.last ?? -Double.infinity)) }
        return ops.filter { o in
            if o.res != "false" { return true }
            var n = 0
            while n < ts.count && ts[n].ret < o.call { n += 1 }
            return !(n > 0 && pm[n - 1] >= o.lo)
        }
    }

    /// EXACT decision for a history with no unknown operation, in O(n log n) (nil when one is unknown).
    public static func fastCheck(_ ops: [Op]) -> Bool? {
        if ops.contains(where: { $0.res == "unknown" }) { return nil }
        let ts = stable(ops.filter { $0.res == "true" }, by: { $0.lo })
        var t: [Double] = []
        var prev = -Double.infinity
        for i in 0..<ts.count {
            let o = ts[i]
            if i > 0 && ts[i - 1].w >= o.lo { return false }
            let ti = Swift.max(o.call, prev)
            if ti > o.ret { return false }
            t.append(ti)
            prev = ti
        }
        for f in ops where f.res == "false" {
            guard let j = ts.firstIndex(where: { $0.w >= f.lo }), t[j] <= f.ret else { return false }
        }
        return true
    }

    /// Linearizability search for ONE key's history: `ok`, `violation` or `unresolved` (over `budget` distinct states).
    public static func searchLinearizable(_ ops: [Op], _ budget: Int = DEFAULT_SEARCH_BUDGET) -> String {
        let order = stable(ops, by: { $0.call })
        let n = order.count
        let words = (n + 63) / 64
        func full(_ d: [UInt64]) -> Bool {
            for i in 0..<n where d[i / 64] & (UInt64(1) << UInt64(i % 64)) == 0 { return false }
            return true
        }
        var seen = Set<String>()
        var stack: [(done: [UInt64], s: Double)] = [([UInt64](repeating: 0, count: words), -Double.infinity)]
        while let cur = stack.popLast() {
            if full(cur.done) { return "ok" }
            let id = cur.done.map { String($0, radix: 36) }.joined(separator: ".") + "|" + String(cur.s.bitPattern, radix: 16)
            if seen.contains(id) { continue }
            if seen.count >= budget { return "unresolved" }
            seen.insert(id)
            var minRet = Double.infinity
            for i in 0..<n where cur.done[i / 64] & (UInt64(1) << UInt64(i % 64)) == 0 { minRet = Swift.min(minRet, order[i].ret) }
            var i = 0
            while i < n && order[i].call <= minRet {
                if cur.done[i / 64] & (UInt64(1) << UInt64(i % 64)) == 0 {
                    for s2 in step(cur.s, order[i]) {
                        var d = cur.done
                        d[i / 64] |= UInt64(1) << UInt64(i % 64)
                        stack.append((d, s2))
                    }
                }
                i += 1
            }
        }
        return "violation"
    }

    /// Decide one key's history (all operations share `kind` and `key`).
    public static func decideKey(_ ops: [Op], _ budget: Int = DEFAULT_SEARCH_BUDGET) -> (verdict: String, method: String, kept: [Op]) {
        if overlappingTrues(ops) != nil { return ("violation", "overlap", ops) }
        let kept = prune(ops)
        if let exact = fastCheck(kept) { return (exact ? "ok" : "violation", "exact", kept) }
        return (searchLinearizable(kept, budget), "search", kept)
    }

    /// The SOUND deletion step for the operation at `index`: a deletion under which a linearizable history stays linearizable.
    public static func deletion(_ ops: [Op], _ index: Int) -> [Op] {
        let op = ops[index]
        if op.res == "false" { return ops.enumerated().filter { $0.offset != index }.map { $0.element } }
        return ops.enumerated().filter { $0.offset != index && !($0.element.res == "false" && $0.element.lo <= op.w) }.map { $0.element }
    }

    /// Greedy sound deletion to a 1-minimal violating history.
    public static func minimize(_ ops: [Op], _ budget: Int = DEFAULT_SEARCH_BUDGET) -> [Op] {
        var cur = ops
        var changed = true
        while changed {
            changed = false
            for i in 0..<cur.count {
                let next = deletion(cur, i)
                if decideKey(next, budget).verdict == "violation" { cur = next; changed = true; break }
            }
        }
        return cur
    }

    public static func checkKey(_ ops: [Op], budget: Int = DEFAULT_SEARCH_BUDGET, minimize shrink: Bool = true, minimizeLimit: Int = 200) -> KeyResult {
        let first = ops[0]
        let d = decideKey(ops, budget)
        var r = KeyResult(key: first.key, kind: first.kind, ops: ops.count, searched: d.kept.count, verdict: d.verdict, method: d.method)
        if d.verdict != "violation" { return r }
        if let pair = overlappingTrues(ops) {
            r.counterexample = stable([pair.0, pair.1], by: { $0.call })
            r.minimized = true
        } else if shrink && d.kept.count <= minimizeLimit {
            r.counterexample = minimize(d.kept, budget)
            r.minimized = true
        } else {
            r.counterexample = d.kept
            r.minimized = false
        }
        return r
    }

    /// Split a history by (kind, key) and check every key.
    public static func checkHistory(_ ops: [Op], budget: Int = DEFAULT_SEARCH_BUDGET, minimize shrink: Bool = true, minimizeLimit: Int = 200) -> HistoryCheck {
        var order: [String] = []
        var byKey: [String: [Op]] = [:]
        var outcomes = ["true": 0, "false": 0, "unknown": 0]
        for o in ops {
            outcomes[o.res, default: 0] += 1
            let id = o.kind + "\u{0}" + o.key
            if byKey[id] == nil { order.append(id) }
            byKey[id, default: []].append(o)
        }
        var violations: [KeyResult] = [], unresolved: [KeyResult] = []
        for id in order {
            let r = checkKey(byKey[id]!, budget: budget, minimize: shrink, minimizeLimit: minimizeLimit)
            if r.verdict == "violation" { violations.append(r) } else if r.verdict == "unresolved" { unresolved.append(r) }
        }
        return HistoryCheck(ops: ops.count, keys: order.count, ok: violations.isEmpty && unresolved.isEmpty, outcomes: outcomes, violations: violations, unresolved: unresolved)
    }

    private static func fmtT(_ t: Double, _ base: Double) -> String { t == Double.infinity ? "open" : "+" + toFixed3(t - base) + "ms" }

    /// `Number.prototype.toFixed(3)` (ECMA-262 21.1.3.3): n is the integer for which n / 1000 - x is closest to zero on the EXACT value of x, the larger n on a tie;
    /// a magnitude from 1e21 on is Number::toString; the sign of a negative x is kept (-0.0001 is "-0.000", -0 is "0.000").
    static func toFixed3(_ x: Double) -> String {
        if x.isNaN { return "NaN" }
        if x.isInfinite { return x < 0 ? "-Infinity" : "Infinity" }
        let neg = x < 0
        let a = abs(x)
        if a >= 1e21 { return (neg ? "-" : "") + JS.number(a) }
        let sign = neg ? "-" : ""
        if a == 0 { return sign + "0.000" }
        // a = m * 2^e exactly
        let bits = a.bitPattern
        let expBits = Int((bits >> 52) & 0x7FF)
        let frac = bits & 0xF_FFFF_FFFF_FFFF
        let m: UInt64 = expBits == 0 ? frac : (frac | (1 << 52))
        let e = (expBits == 0 ? 1 : expBits) - 1075
        let digits: String
        if e >= 0 {
            // an integer (a >= 2^52): its digits are exact and the fraction is zero
            digits = String(format: "%.0f", a) + "000"
        } else {
            // n = floor(a * 1000 + 1/2) = floor((2 * m * 1000 + 2^k) / 2^(k + 1)), k = -e; m * 1000 < 2^63, so 2 * m * 1000 fits 64 bits
            let k = -e
            let twice = (m * 1000) << 1
            let n: UInt64
            if k >= 64 {
                n = 0 // the sum is below 2^(k+1) / 2 + 2^k * (1/2), i.e. under one
            } else {
                let (sum, carry) = twice.addingReportingOverflow(UInt64(1) << UInt64(k))
                let sh = k + 1
                n = sh == 64 ? (carry ? 1 : 0) : ((sum >> UInt64(sh)) | (carry ? (UInt64(1) << UInt64(64 - sh)) : 0))
            }
            digits = String(n)
        }
        let padded = String(repeating: "0", count: Swift.max(0, 4 - digits.count)) + digits
        return sign + String(padded.dropLast(3)) + "." + String(padded.suffix(3))
    }

    private static func num(_ d: Double) -> String {
        if d == Double.infinity { return "Infinity" }
        if d == -Double.infinity { return "-Infinity" }
        return Canonical.numberString(d)
    }

    /// One line per operation, times relative to the first invocation.
    public static func formatOps(_ ops: [Op]) -> [String] {
        guard let base = ops.map({ $0.call }).min() else { return [] }
        return stable(ops, by: { $0.call }).map { o in
            let what = o.kind == "consume" ? "consumeOnce(now=\(num(o.lo)), retainUntil=\(num(o.w)))" : "advance(\(num(o.lo)))"
            let res = o.res == "true" ? "TRUE" : o.res == "false" ? "false" : "unknown"
            return "\(o.client): \(what) [\(fmtT(o.call, base)) .. \(fmtT(o.ret, base))] -> \(res)"
        }
    }

    // ---- JSON forms (Infinity travels as {"$num": "Infinity"}) ----

    static func numValue(_ d: Double) -> JSONValue {
        if d == Double.infinity { return .object(["$num": .string("Infinity")]) }
        if d == -Double.infinity { return .object(["$num": .string("-Infinity")]) }
        return d == d.rounded() && abs(d) < 9e15 ? .int(Int64(d)) : .double(d)
    }

    static func numOf(_ v: JSONValue?) -> Double? {
        if let s = v?.asObject?["$num"]?.asString { return s == "Infinity" ? Double.infinity : s == "-Infinity" ? -Double.infinity : nil }
        return IV.num(v)
    }

    public static func op(from v: JSONValue?) throws -> Op {
        guard let o = v?.asObject, let client = o["client"]?.asString, let kind = o["kind"]?.asString, let key = o["key"]?.asString,
              let lo = numOf(o["lo"]), let w = numOf(o["w"]), let call = numOf(o["call"]), let ret = numOf(o["ret"]), let res = o["res"]?.asString else { throw JSError("bad op") }
        return Op(client: client, kind: kind, key: key, lo: lo, w: w, call: call, ret: ret, res: res)
    }

    public static func json(_ o: Op) -> JSONValue {
        .object(["client": .string(o.client), "kind": .string(o.kind), "key": .string(o.key), "lo": numValue(o.lo), "w": numValue(o.w), "call": numValue(o.call),
                 "ret": numValue(o.ret), "res": .string(o.res)])
    }

    public static func json(_ r: KeyResult) -> JSONValue {
        var o: JObject = ["key": .string(r.key), "kind": .string(r.kind), "ops": .int(Int64(r.ops)), "searched": .int(Int64(r.searched)), "verdict": .string(r.verdict), "method": .string(r.method)]
        if let c = r.counterexample { o["counterexample"] = .array(c.map { json($0) }) }
        if let m = r.minimized { o["minimized"] = .bool(m) }
        return .object(o)
    }

    public static func json(_ h: HistoryCheck) -> JSONValue {
        .object(["ops": .int(Int64(h.ops)), "keys": .int(Int64(h.keys)), "ok": .bool(h.ok),
                 "outcomes": .object(["true": .int(Int64(h.outcomes["true"] ?? 0)), "false": .int(Int64(h.outcomes["false"] ?? 0)), "unknown": .int(Int64(h.outcomes["unknown"] ?? 0))]),
                 "violations": .array(h.violations.map { json($0) }), "unresolved": .array(h.unresolved.map { json($0) })])
    }
}
