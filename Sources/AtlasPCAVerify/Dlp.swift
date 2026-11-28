import Foundation

/// Data-flow governance, DLP for agents: declare data classes (a resource matcher and the maximum taint that may reach them without a human)
/// and evaluate an action's provenance taint against them. ADVISORY: taint levels are labels something upstream attached; this checks them
/// against ceilings and never tracks data through a program, so it is never the only control over an exfiltration path. Taint 0 is clean;
/// higher is more untrusted or sensitive. The policy is JSON: `{classes: [{name, resource, verbs?, maxTaintForAuto, hardDenyAbove?}],
/// defaultMaxTaintForAuto?}`.
public enum PCADlp {
    public struct Result: Equatable {
        /// "allow", "step_up" or "deny".
        public var outcome: String
        /// The matched data class's `name` as written (a JavaScript value: any JSON type), if the class has one.
        public var name: JSONValue?
        /// The matched data class's name when it is a string.
        public var cls: String? { name?.asString }
        public var reason: String?
        public init(outcome: String, cls: String?, reason: String?) { self.outcome = outcome; self.name = cls.map { .string($0) }; self.reason = reason }
        init(outcome: String, name: JSONValue?, reason: String?) { self.outcome = outcome; self.name = name; self.reason = reason }
        public var json: JSONValue {
            var o: JObject = ["outcome": .string(outcome)]
            if let c = name { o["class"] = c }
            if let r = reason { o["reason"] = .string(r) }
            return .object(o)
        }
    }

    /// Exact, `*` for any, or a trailing-`*` prefix.
    static func matches(_ pattern: String, _ resource: String) -> Bool {
        if pattern == "*" { return true }
        if IV.endsWith(pattern, "*") { return IV.startsWith(resource, String(pattern.unicodeScalars.dropLast())) }
        return IV.same(pattern, resource)
    }

    static func specificity(_ pattern: String) -> Double {
        if pattern == "*" { return 0 }
        if IV.endsWith(pattern, "*") { return Double(IV.u16(pattern) - 1) }
        return Double(IV.u16(pattern) + 1000) // exact beats any prefix
    }

    /// A malformed ceiling sorts first, so the policy then denies instead of picking a lenient sibling; an absent ceiling is the most lenient.
    static func strictness(_ c: JObject) -> Double {
        guard let v = c["maxTaintForAuto"] else { return .infinity }
        if let n = IV.num(v), !n.isNaN { return n }
        return -.infinity
    }

    /// The most specific matching class (longest non-wildcard prefix wins, exact beats prefix); of equally specific ones the strictest wins,
    /// then the first listed. Throws where the reference throws (a class that is not an object, a resource that is not a string).
    static func classFor(_ classes: [JSONValue], verb: String, resource: String) throws -> JObject? {
        var best: JObject?
        for cv in classes {
            guard case let .object(c) = cv else { throw JSError("Cannot read properties of a non-object class") }
            guard let pat = c["resource"]?.asString else { throw JSError("pattern.endsWith is not a function") }
            guard matches(pat, resource) else { continue }
            if let vs = c["verbs"], JS.truthy(vs) {
                // `c.verbs.includes(verb)`: an array's element test, or a string's substring test; anything else has no includes
                if case let .array(list) = vs { if !list.contains(where: { IV.same($0.asString, verb) }) { continue } }
                else if case let .string(text) = vs { if !utf16Contains(text, verb) { continue } }
                else { throw JSError("c.verbs.includes is not a function") }
            }
            guard let b = best else { best = c; continue }
            // the comparator `specificity(b) - specificity(a) || strictness(a) - strictness(b)`, a NaN reading as equal
            let sp = specificity(b["resource"]!.asString!) - specificity(pat)
            var order = sp
            if order == 0 || order.isNaN { order = strictness(c) - strictness(b) }
            if order < 0 { best = c }
        }
        return best
    }

    /// `text.includes(part)` over UTF-16 code units.
    private static func utf16Contains(_ text: String, _ part: String) -> Bool {
        let h = Array(text.utf16), n = Array(part.utf16)
        if n.isEmpty { return true }
        if n.count > h.count { return false }
        for i in 0...(h.count - n.count) where Array(h[i..<(i + n.count)]) == n { return true }
        return false
    }

    private static func js(_ d: Double) -> String { JS.toString(.double(d)) }
    private static func isNum(_ v: JSONValue?) -> Bool { IV.num(v).map { !$0.isNaN } ?? false }

    /// A ceiling that is present but not a number (or NaN) would make every `>` false and allow everything.
    static func malformed(_ policy: JObject, _ cls: JObject?) -> Bool {
        if let c = cls { return (c["maxTaintForAuto"] != nil && !isNum(c["maxTaintForAuto"])) || (c["hardDenyAbove"] != nil && !isNum(c["hardDenyAbove"])) }
        return policy["defaultMaxTaintForAuto"] != nil && !isNum(policy["defaultMaxTaintForAuto"])
    }

    /// Evaluate an action's data flow against the DLP policy. A non-finite taint is treated as maximally tainted (fail closed).
    public static func evaluate(_ policy: JSONValue?, verb: String, resource: String, taint: Double) throws -> Result {
        guard case let .object(p)? = policy, case let .array(classes)? = p["classes"] else { return Result(outcome: "deny", cls: nil, reason: "malformed DLP policy") }
        let cls = try classFor(classes, verb: verb, resource: resource)
        let name = cls?["name"]
        if malformed(p, cls) { return Result(outcome: "deny", name: name, reason: "malformed DLP policy: ceilings must be numbers") }
        let maxV = cls != nil ? cls!["maxTaintForAuto"] : p["defaultMaxTaintForAuto"]
        let bad = !taint.isFinite
        let t = bad ? Double.infinity : taint
        // no ceiling at all: nothing to compare against, so even an unknown taint is unconstrained here
        guard let max = IV.num(maxV) else { return Result(outcome: "allow", name: name, reason: nil) }
        let label = (name == .null ? nil : name).map { JS.toString($0) } ?? "<default>"
        if let c = cls, let hard = IV.num(c["hardDenyAbove"]), bad || t > hard {
            return Result(outcome: "deny", name: name, reason: "taint \(js(t)) exceeds hard ceiling \(js(hard)) for '\(label)'")
        }
        if bad || t > max { return Result(outcome: "step_up", name: name, reason: "taint \(js(t)) > \(js(max)) for '\(label)' \u{2014} needs human review") }
        return Result(outcome: "allow", name: name, reason: nil)
    }
}
