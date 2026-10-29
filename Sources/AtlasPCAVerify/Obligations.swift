import Foundation

/// DECISION OBLIGATIONS: an `allow` may carry obligations the policy enforcement point must perform; a PEP that cannot perform every
/// one turns the allow into a `deny` (`pepObligationGate`). Port of packages/pca/src/obligations.ts; replays
/// packages/pca/conformance/obligations-vectors.json. Everything is total. A nil or JSON null list means absent (the empty list).
public enum Obligations {
    /// `undo_window` {id, window_end}: the action runs under a veto window (undo record `id`, open until `window_end`). An enforcement
    /// point that does not run undo windows must not list it as supported (the gate then turns the allow into a deny).
    public static let KINDS = ["log", "notify", "redact", "watermark", "require_receipt", "undo_window"]
    public static let MAX_OBLIGATIONS = 16
    static let MAX_REDACT_FIELDS = 32
    static let ALLOWED: [String: [String]] = ["log": ["sink"], "notify": ["to"], "redact": ["fields"], "watermark": ["id"], "require_receipt": [],
                                                  "undo_window": ["id", "window_end"]]

    /// `^[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}$`, checked by hand (ASCII only).
    static func fieldOk(_ s: String) -> Bool {
        let segs = s.utf8.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
        if segs.count < 1 || segs.count > 8 { return false }
        for seg in segs {
            if seg.count < 1 || seg.count > 64 { return false }
            var first = true
            for b in seg {
                let alpha = (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b == 95
                let digit = b >= 48 && b <= 57
                if !(alpha || (digit && !first)) { return false }
                first = false
            }
        }
        return true
    }

    static func paramsError(_ kind: String, _ p: JObject) -> String? {
        let allowed = ALLOWED[kind] ?? []
        for k in p.keys where !allowed.contains(k.s) { return "unknown parameter '\(k.s)' for '\(kind)'" }
        if kind == "log", let s = p[JKey("sink")], K3Sig.str(s, 128) == nil { return "log.sink must be a non-empty string of at most 128 characters" }
        if kind == "notify", K3Sig.str(p[JKey("to")], 256) == nil { return "notify.to is required (a non-empty string of at most 256 characters)" }
        if kind == "watermark", K3Sig.str(p[JKey("id")], 128) == nil { return "watermark.id is required (a non-empty string of at most 128 characters)" }
        if kind == "undo_window", K3Sig.str(p[JKey("id")], 128) == nil || K3Sig.safeInt(p[JKey("window_end")]) == nil {
            return "undo_window needs id (a non-empty string of at most 128 characters) and window_end (a non-negative safe integer)"
        }
        if kind == "redact" {
            guard let f = p[JKey("fields")]?.asArray, !f.isEmpty, f.count <= MAX_REDACT_FIELDS,
                  f.allSatisfy({ v in v.asString.map(fieldOk) ?? false }) else { return "redact.fields must be 1..32 dotted field paths" }
            if Set(f.compactMap { $0.asString }.map { JKey($0) }).count != f.count { return "redact.fields has a duplicate" }
        }
        return nil
    }

    /// nil = well formed.
    public static func obligationError(_ o: JSONValue?) -> String? {
        guard let m = o?.asObject else { return "an obligation must be an object" }
        for k in m.keys where k.s != "kind" && k.s != "params" && k.s != "due" { return "unknown member '\(k.s)'" }
        guard let kind = m[JKey("kind")]?.asString, KINDS.contains(kind) else { return "unknown obligation kind" }
        if let d = m[JKey("due")], K3Sig.safeInt(d) == nil { return "due must be a non-negative safe integer" }
        var params: JObject = [:]
        if let p = m[JKey("params")] {
            guard let po = p.asObject else { return "params must be an object" }
            params = po
        }
        return paramsError(kind, params)
    }

    /// nil = a well-formed, duplicate-free list of at most `MAX_OBLIGATIONS`. nil or JSON null (absent) is the empty list.
    public static func obligationsError(_ list: JSONValue?) -> String? {
        guard let value = list, !value.isNull else { return nil }
        guard let items = value.asArray else { return "obligations must be an array" }
        if items.count > MAX_OBLIGATIONS { return "more than \(MAX_OBLIGATIONS) obligations" }
        var seen = Set<JKey>()
        for (i, item) in items.enumerated() {
            if let e = obligationError(item) { return "obligations[\(i)]: \(e)" }
            guard let key = obligationKey(item) else { return "obligations[\(i)]: not canonicalizable" }
            if !seen.insert(JKey(key)).inserted { return "obligations[\(i)] duplicates an earlier obligation" }
        }
        return nil
    }

    /// The canonical identity of an obligation (kind, parameters, due): equal keys are the same obligation. nil where the reference throws.
    public static func obligationKey(_ o: JSONValue) -> String? {
        guard let m = o.asObject else { return nil }
        var k: JObject = [JKey("kind"): m[JKey("kind")] ?? .null, JKey("params"): m[JKey("params")] ?? .object([:])]
        if let d = m[JKey("due")] { k[JKey("due")] = d }
        return try? Canonical.canonicalizeStrict(.object(k))
    }

    public struct Merge: Equatable {
        public var ok: Bool
        public var obligations: [JSONValue] = []
        public var reason: String? = nil
    }

    /// The union of obligation lists, deduplicated by `obligationKey` and sorted by key in UTF-8 byte order. Any malformed input is a refusal.
    public static func mergeObligations(_ lists: [JSONValue?]) -> Merge {
        var by: [JKey: JSONValue] = [:]
        for list in lists {
            if let e = obligationsError(list) { return Merge(ok: false, reason: e) }
            for item in list?.asArray ?? [] {
                guard let key = obligationKey(item) else { return Merge(ok: false, reason: "evaluation error (fail closed)") }
                by[JKey(key)] = item
            }
        }
        if by.count > MAX_OBLIGATIONS { return Merge(ok: false, reason: "more than \(MAX_OBLIGATIONS) obligations after merging") }
        let keys = by.keys.sorted { Canonical.compareUtf8($0.s, $1.s) < 0 }
        return Merge(ok: true, obligations: keys.compactMap { by[$0] })
    }

    public struct Gate: Equatable {
        public var decision: String
        public var perform: [JSONValue] = []
        public var unsupported: [String] = []
        public var reason: String? = nil
    }

    /// The PEP rule. `supported` is the set of kinds this PEP performs. An `allow` (or an answered `escalate`) with any obligation outside it
    /// is a `deny`, as is a malformed list or `supported` set. A `deny` and an unanswered `escalate` pass through with nothing to perform.
    public static func pepObligationGate(decision: String, answered: Bool, obligations: JSONValue?, supported: JSONValue?) -> Gate {
        let eff = PCA.pepDecision(decision, answered: answered)
        if eff != "allow" { return Gate(decision: eff == "escalate" ? "escalate" : "deny") }
        if let e = obligationsError(obligations) { return Gate(decision: "deny", reason: "malformed obligations: \(e)") }
        guard let sup = supported?.asArray, sup.allSatisfy({ $0.asString != nil }) else {
            return Gate(decision: "deny", reason: "the supported obligation kinds are malformed")
        }
        let supportedKinds = sup.compactMap { $0.asString }
        let list = obligations?.asArray ?? []
        var missing: [String] = []
        for item in list {
            guard let kind = item.get("kind")?.asString else { continue }
            if !supportedKinds.contains(where: { IV.same($0, kind) }) && !missing.contains(where: { IV.same($0, kind) }) { missing.append(kind) }
        }
        missing.sort { Canonical.compareUtf8($0, $1) < 0 }
        if !missing.isEmpty {
            return Gate(decision: "deny", unsupported: missing, reason: "the enforcement point does not support obligation(s) \(missing.joined(separator: ", "))")
        }
        return Gate(decision: "allow", perform: list)
    }

    /// `outcome` is ok or escalate; `overdue` indexes the overdue obligations; `status` is `obligation_unmet` on escalate.
    public struct Outcome: Equatable {
        public var outcome: String
        public var overdue: [Int] = []
        public var status: String? = nil
    }

    /// After the action: which obligations are overdue (`due <= now`, not in `fulfilled`)? A malformed input is overdue-everything.
    public static func obligationOutcome(obligations: JSONValue?, fulfilled: JSONValue?, now: JSONValue?) -> Outcome {
        let list = obligations?.asArray ?? []
        guard obligationsError(obligations) == nil, let f = fulfilled?.asArray, let n = K3Sig.safeInt(now) else {
            return Outcome(outcome: "escalate", overdue: Array(0..<list.count), status: "obligation_unmet")
        }
        var done = Set<Int64>()
        for item in f {
            guard let i = K3Sig.safeInt(item) else { return Outcome(outcome: "escalate", overdue: Array(0..<list.count), status: "obligation_unmet") }
            done.insert(i)
        }
        var overdue: [Int] = []
        for (i, item) in list.enumerated() {
            if let due = K3Sig.safeInt(item.get("due")), due <= n, !done.contains(Int64(i)) { overdue.append(i) }
        }
        return overdue.isEmpty ? Outcome(outcome: "ok") : Outcome(outcome: "escalate", overdue: overdue, status: "obligation_unmet")
    }
}
