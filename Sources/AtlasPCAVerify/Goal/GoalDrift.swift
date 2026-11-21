import Foundation
import CryptoKit

/// Runtime drift monitoring, tighten-only. A monitor compares the action stream to the goal's expected profile (verbs, resources,
/// magnitude, rate, novelty). Anomalies convert allow to escalate; the strike counter is a ratchet; at `lockdown` strikes every
/// allow becomes escalate. `applyDrift` can never relax a decision.
///
/// A parsed object keeps no member order: the parameters of an action are visited in JavaScript key order (index keys, then code-unit
/// order), and the sealed state text is written with the monitor's own insertion order of the observed parameters (`seenOrder`).
public enum PCAGoalDrift {
    static func nv(_ v: JSONValue?) -> JSONValue { v ?? .null }

    /// Defaults: windowMs 60000, maxPerWindow 20, maxNovel 3, magnitudeFactor 3, warmup 5, lockdown 5.
    public static func defaults() -> JObject {
        [JKey("windowMs"): .int(60000), JKey("maxPerWindow"): .int(20), JKey("maxNovel"): .int(3), JKey("magnitudeFactor"): .int(3),
         JKey("warmup"): .int(5), JKey("lockdown"): .int(5)]
    }

    /// The verbs of the goal's grants (first-seen order, no duplicates).
    public static func expectedVerbs(_ g: JSONValue) throws -> [String] {
        var out: [String] = []
        for gr in try GV.arr(GV.get(g, "grants"), "grants") {
            guard let v = GV.get(gr, "verb")?.asString else { throw IrError("verb is not a string") }
            if !out.contains(where: { IV.same($0, v) }) { out.append(v) }
        }
        return out
    }

    private static func resIds(_ s: JSONValue?, _ out: inout [String]) throws {
        func add(_ v: JSONValue?) throws {
            guard let x = v?.asString else { throw IrError("id is not a string") }
            if !out.contains(where: { IV.same($0, x) }) { out.append(x) }
        }
        switch GV.kind(s) {
        case "exact": try add(GV.get(s, "id"))
        case "oneof": for i in try GV.arr(GV.get(s, "ids"), "ids") { try add(i) }
        case "all_of": for p in try GV.arr(GV.get(s, "parts"), "parts") { try resIds(p.isObject ? p : nil, &out) }
        default: break
        }
    }

    private static func knownResources(_ g: JSONValue) throws -> [String] {
        var out: [String] = []
        for gr in try GV.arr(GV.get(g, "grants"), "grants") {
            let r = GV.get(gr, "res")
            try resIds(r != nil && r!.isObject ? r : nil, &out)
        }
        return out
    }

    private static func numStr(_ o: JSONValue?) -> String {
        guard let d = GV.dbl(o) else { return GV.jsStr(o) }
        if d == d.rounded(.toNearestOrEven) && abs(d) < 1e21 { return d == 0 ? "0" : String(format: "%.0f", d) }
        return GV.jsStr(o)
    }

    private static func freshState() -> JObject {
        [JKey("strikes"): .int(0), JKey("times"): .array([]), JKey("novel"): .array([]), JKey("seen"): .object([:])]
    }

    private static func hmac(_ key: [UInt8], _ text: String) -> [UInt8] {
        let k = SymmetricKey(data: Data(key.isEmpty ? [0] : key))
        return Array(HMAC<SHA256>.authenticationCode(for: Data(text.utf8), using: k))
    }

    private static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    /// Node's Buffer.from(s, 'hex'): decoding stops at the first non-hex pair.
    private static func hexLenient(_ s: String) -> [UInt8] {
        let u = Array(s.utf16)
        func digit(_ c: UInt16) -> UInt8? {
            switch c {
            case 48...57: return UInt8(c - 48)
            case 97...102: return UInt8(c - 87)
            case 65...70: return UInt8(c - 55)
            default: return nil
            }
        }
        var out: [UInt8] = []
        var i = 0
        while i + 1 < u.count {
            guard let hi = digit(u[i]), let lo = digit(u[i + 1]) else { break }
            out.append(hi * 16 + lo)
            i += 2
        }
        return out
    }

    private static func ctEq(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return false }
        var d: UInt8 = 0
        for i in a.indices { d |= a[i] ^ b[i] }
        return d == 0
    }

    private static func toLong(_ d: Double) -> Int64 {
        if d.isNaN { return 0 }
        if d >= 9.2233720368547758e18 { return Int64.max }
        if d <= -9.2233720368547758e18 { return Int64.min }
        return Int64(d.rounded(.towardZero))
    }

    /// JSON.stringify of a state: strikes, times, novel, seen in the reference's order, `seen` members in `seenOrder` (index keys first).
    static func stateText(_ st: JSONValue?, _ seenOrder: [String]) -> String {
        guard let o = st?.asObject else { return GV.stringify(st) }
        var parts: [String] = []
        var used = Set<JKey>()
        for k in ["strikes", "times", "novel", "seen"] {
            guard let v = o[JKey(k)] else { continue }
            used.insert(JKey(k))
            parts.append(GV.q(k) + ":" + (k == "seen" ? JS.stringify(v, order: seenOrder) : JS.stringify(v)))
        }
        for k in o.keys.filter({ !used.contains($0) }).sorted(by: { GV.less($0.s, $1.s) }) { parts.append(GV.q(k.s) + ":" + JS.stringify(o[k]!)) }
        return "{" + parts.joined(separator: ",") + "}"
    }

    /// One drift monitor over a goal.
    public final class Monitor {
        private let goal: JSONValue
        private var o: JObject
        private var st: JObject = PCAGoalDrift.freshState()
        /// The insertion order of the observed parameter names in `state().seen`.
        public private(set) var seenOrder: [String] = []

        public init(_ goal: JSONValue, _ opts: JSONValue?) {
            self.goal = goal
            self.o = PCAGoalDrift.defaults()
            if let extra = opts?.asObject { for (k, v) in extra { o[k] = v } }
        }

        private func opt(_ k: String) -> Double { JS.toNumber(PCAGoalDrift.nv(o[JKey(k)])) }

        /// Observe an action at time `t`: {anomalous, strikes, lockdown, reasons}.
        public func observe(_ a: JSONValue, _ t: JSONValue?) throws -> JSONValue {
            var reasons: [JSONValue] = []
            let verb = GV.get(a, "verb")
            let verbs = try PCAGoalDrift.expectedVerbs(goal)
            var verbKnown = false
            if let vs = verb?.asString { verbKnown = verbs.contains(where: { IV.same($0, vs) }) }
            if !verbKnown { reasons.append(.string("verb " + GV.jsStr(verb) + " outside the goal profile")) }
            let known = try PCAGoalDrift.knownResources(goal)
            guard var novel = st[JKey("novel")]?.asArray else { throw IrError("state.novel expected an array") }
            let res = PCAGoalDrift.nv(GV.get(a, "res"))
            var resKnown = false
            if let rs = res.asString { resKnown = known.contains(where: { IV.same($0, rs) }) }
            if !known.isEmpty && !resKnown && !novel.contains(res) { novel.append(res) }
            st[JKey("novel")] = .array(novel)
            if Double(novel.count) > opt("maxNovel") { reasons.append(.string("novel resources beyond the allowance")) }
            var times: [JSONValue] = []
            let tNum = JS.toNumber(PCAGoalDrift.nv(t))
            for x in try GV.arr(st[JKey("times")], "times") where JS.toNumber(x) > tNum - opt("windowMs") { times.append(x) }
            times.append(PCAGoalDrift.nv(t))
            st[JKey("times")] = .array(times)
            if Double(times.count) > opt("maxPerWindow") { reasons.append(.string("rate above the profile")) }
            guard let params = GV.get(a, "params")?.asObject else { throw IrError("params expected") }
            guard var seen = st[JKey("seen")]?.asObject else { throw IrError("state.seen expected an object") }
            for p in JS.keyOrder(params).map({ $0.s }) {
                let l = params[JKey(p)]!
                if GV.kind(l) != "q" { continue }
                var hist: [JSONValue] = []
                if let prior = seen[JKey(p)], prior != .null {
                    guard let h = prior.asArray else { throw IrError("state.seen member expected an array") }
                    hist = h
                }
                guard let qo = GV.get(l, "q"), qo.isObject else { throw IrError("q expected an object") }
                let v = PCAGoalDrift.nv(GV.get(qo, "n"))
                if Double(hist.count) >= opt("warmup") {
                    var sum = 0.0
                    for x in hist { sum += JS.toNumber(x) }
                    let mean = sum / Double(hist.count)
                    if mean > 0 && JS.toNumber(v) > mean * opt("magnitudeFactor") {
                        reasons.append(.string(p + " magnitude " + PCAGoalDrift.numStr(o[JKey("magnitudeFactor")]) + "x above the running mean"))
                    }
                }
                var next = hist
                next.append(v)
                seen[JKey(p)] = .array(Array(next[max(0, next.count - 50)..<next.count]))
                if !seenOrder.contains(where: { IV.same($0, p) }) { seenOrder.append(p) }
                st[JKey("seen")] = .object(seen)
            }
            if !reasons.isEmpty {
                guard let s0 = IV.int(st[JKey("strikes")]) else { throw IrError("state.strikes expected an integer") }
                st[JKey("strikes")] = .int(s0 + 1)
            }
            guard let strikes = IV.int(st[JKey("strikes")]) else { throw IrError("state.strikes expected an integer") }
            return GV.obj([("anomalous", .bool(!reasons.isEmpty)), ("strikes", .int(strikes)), ("lockdown", .bool(Double(strikes) >= opt("lockdown"))), ("reasons", .array(reasons))])
        }

        public func state() -> JSONValue { .object(st) }

        /// Sealed state: {state, mac} (HMAC-SHA256 over the state's JSON text, hex).
        public func seal(_ key: [UInt8]) -> JSONValue {
            GV.obj([("state", .object(st)), ("mac", .string(PCAGoalDrift.hex(PCAGoalDrift.hmac(key, PCAGoalDrift.stateText(.object(st), seenOrder)))))])
        }

        /// Restore; a state that fails its MAC locks down (fail closed). `stateOrder` is the insertion order of the sealed state's
        /// `seen` members (`seenOrder` of the monitor that sealed it); the sorted order is accepted as well.
        public static func restore(_ goal: JSONValue, _ sealed: JSONValue, _ key: [UInt8], _ opts: JSONValue?, _ stateOrder: [String] = []) throws -> Monitor {
            let m = Monitor(goal, opts)
            let state = GV.get(sealed, "state")
            let got = PCAGoalDrift.hexLenient(GV.jsStr(GV.get(sealed, "mac")))
            var ok = false
            for order in [stateOrder, []] {
                let want = PCAGoalDrift.hmac(key, PCAGoalDrift.stateText(state, order))
                if PCAGoalDrift.ctEq(got, want) { ok = true; break }
            }
            if ok {
                guard let s = state?.asObject else { throw IrError("state expected an object") }
                m.st = s
                m.seenOrder = stateOrder
            } else {
                m.st = PCAGoalDrift.freshState()
                m.st[JKey("strikes")] = .int(PCAGoalDrift.toLong(m.opt("lockdown")))
            }
            return m
        }
    }

    /// Tighten-only: allow becomes escalate on an anomaly or lockdown; nothing else changes.
    public static func applyDrift(_ d: String, _ signal: JSONValue) -> String {
        if d == "allow" && (JS.truthy(GV.get(signal, "anomalous")) || JS.truthy(GV.get(signal, "lockdown"))) { return "escalate" }
        return d
    }

    /// Decide, observe, tighten: {decision, signal}. `c` = {act, rels, hist?}.
    public static func guardedDecide(_ goal: JSONValue, _ ont: JSONValue, _ mon: Monitor, _ c: JSONValue, _ t: JSONValue?) throws -> JSONValue {
        let decided = try PCAGoalExamples.decideCase(goal, ont, c)
        guard let base = GV.get(decided, "decision")?.asString else { throw IrError("decision is not a string") }
        guard let act = GV.get(c, "act"), act.isObject else { throw IrError("act expected an object") }
        let signal = try mon.observe(act, t)
        return GV.obj([("decision", .string(applyDrift(base, signal))), ("signal", signal)])
    }
}
