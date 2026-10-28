import Foundation

/// POLICY CLASSES (access is granted only if every consulted policy class allows it): the decision is the meet of the class answers,
/// and the record names who said no. Port of packages/pca/src/policy-classes.ts; replays packages/pca/conformance/policy-classes-vectors.json.
/// Total; never throws.
public enum PolicyClasses {
    public static let CLASSES = ["constitution", "regulatory", "org", "blueprint", "user"]
    static let DECISIONS = ["allow", "escalate", "deny"]

    public struct Verdict: Equatable {
        public var cls: String
        public var revision: Int64
        public var digest: String
        public var decision: String
    }

    public struct Result: Equatable {
        public var decision: String
        public var classes: [Verdict] = []
        public var deniedBy: [String] = []
        public var escalatedBy: [String] = []
        public var reason: String? = nil
    }

    /// nil = a well-formed list: closed members, known classes, each at most once.
    public static func classVerdictsError(_ list: JSONValue?) -> String? {
        guard let l = list?.asArray else { return "policy classes must be an array" }
        if l.count > CLASSES.count { return "more than \(CLASSES.count) policy classes" }
        var seen = Set<JKey>()
        for (i, x) in l.enumerated() {
            guard let v = x.asObject else { return "policy_classes[\(i)] must be an object" }
            for k in v.keys.sorted() where !["class", "revision", "digest", "decision"].contains(k.s) { return "policy_classes[\(i)] has unknown member '\(k.s)'" }
            guard let c = v[JKey("class")]?.asString, CLASSES.contains(where: { IV.same($0, c) }) else { return "policy_classes[\(i)].class is not a known class" }
            if !seen.insert(JKey(c)).inserted { return "policy class '\(c)' appears twice" }
            if K3Sig.safeInt(v[JKey("revision")]) == nil { return "policy_classes[\(i)].revision must be a non-negative safe integer" }
            if K3Sig.str(v[JKey("digest")], 128) == nil { return "policy_classes[\(i)].digest invalid" }
            guard let d = v[JKey("decision")]?.asString, DECISIONS.contains(d) else { return "policy_classes[\(i)].decision must be allow, escalate or deny" }
        }
        return nil
    }

    public static func decideClasses(_ list: JSONValue?) -> Result {
        if let l = list?.asArray, l.isEmpty { return Result(decision: "deny", reason: "no_policy_class") }
        if let e = classVerdictsError(list) { return Result(decision: "deny", reason: "malformed policy classes: \(e)") }
        var classes: [Verdict] = []
        for x in list?.asArray ?? [] {
            guard let v = x.asObject, let c = v[JKey("class")]?.asString, let d = v[JKey("decision")]?.asString,
                  let digest = v[JKey("digest")]?.asString, let rev = K3Sig.safeInt(v[JKey("revision")]) else { return Result(decision: "deny", reason: "evaluation error (fail closed)") }
            classes.append(Verdict(cls: c, revision: rev, digest: digest, decision: d))
        }
        classes.sort { (CLASSES.firstIndex(of: $0.cls) ?? 0) < (CLASSES.firstIndex(of: $1.cls) ?? 0) }
        var decision = "allow"
        for c in classes { decision = PCA.meet(decision, c.decision) }
        return Result(decision: decision, classes: classes, deniedBy: classes.filter { $0.decision == "deny" }.map { $0.cls },
                      escalatedBy: classes.filter { $0.decision == "escalate" }.map { $0.cls })
    }
}
