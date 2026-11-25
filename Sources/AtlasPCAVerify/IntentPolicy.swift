import Foundation

/// Policy plumbing: an outcome as the analyzer's concrete action, and the real evaluator as an admission oracle over the outcome space
/// (`PCAIntentOmega`). The evaluator itself is `PCAIntentAdmitter`.
public enum PCAIntentPolicy {
    /// Default resource string when the space has no resource dimension for a verb.
    public static let ANY_RESOURCE = "resource:any"

    /// {predicates, caveats} of a policy: a non-array member counts as empty.
    public static func normalizePolicy(_ p: JSONValue?) -> JSONValue {
        let preds: [JSONValue] = p?.get("predicates")?.asArray ?? []
        let cavs: [JSONValue] = p?.get("caveats")?.asArray ?? []
        return JSONValue.object([JKey("predicates"): JSONValue.array(preds), JKey("caveats"): JSONValue.array(cavs)])
    }

    /// The verb space as the evaluator's verb record (only the verb name and reversibility class are read).
    static func walletVerb(_ vs: PCAIntentOmega.VerbSpace) -> WalletVerb {
        return WalletVerb(verb: vs.verb, reversibility: vs.reversibility, weight: vs.weight, dims: [])
    }

    /// The outcome as the analyzer's concrete action (params / env / subject trees, reversibility from the space).
    public static func outcomeToAction(_ vs: WalletVerb, _ o: JSONValue) -> JObject {
        return PCAIntentRuntime.outcomeToAction(vs, o)
    }

    /// The same for a typed outcome of the typed outcome space.
    public static func outcomeToAction(_ vs: PCAIntentOmega.VerbSpace, _ o: PCAIntentOmega.Outcome) -> JObject {
        return PCAIntentRuntime.outcomeToAction(walletVerb(vs), PCAIntentOmega.outcomeToJson(o))
    }

    /// A compiled admission oracle for one policy over the typed outcome space (compile once, query many times).
    public struct TypedAdmitter {
        let fn: (PCAIntentOmega.VerbSpace, PCAIntentOmega.Outcome) -> Bool
        public init(_ fn: @escaping (PCAIntentOmega.VerbSpace, PCAIntentOmega.Outcome) -> Bool) { self.fn = fn }
        public func admits(_ vs: PCAIntentOmega.VerbSpace, _ o: PCAIntentOmega.Outcome) -> Bool { return fn(vs, o) }
    }

    /// A compiled admission oracle for one policy (compile once, query many times).
    public static func admitter(_ policy: JSONValue?) throws -> PCAIntentAdmitter {
        return try PCAIntentAdmitter(policy)
    }

    public static func typedAdmitter(_ policy: JSONValue?) throws -> TypedAdmitter {
        let a: PCAIntentAdmitter = try PCAIntentAdmitter(policy)
        return TypedAdmitter { (vs: PCAIntentOmega.VerbSpace, o: PCAIntentOmega.Outcome) -> Bool in
            return a.admits(walletVerb(vs), PCAIntentOmega.outcomeToJson(o))
        }
    }

    public static func vsOf(_ omega: WalletOmega, _ o: JSONValue) -> WalletVerb? {
        guard let v = o.get("verb")?.asString else { return nil }
        return omega.verb(v)
    }

    public static func vsOf(_ omega: PCAIntentOmega.Omega, _ o: PCAIntentOmega.Outcome) -> PCAIntentOmega.VerbSpace? {
        return omega.verbs.first { IV.same($0.verb, o.verb) }
    }
}
