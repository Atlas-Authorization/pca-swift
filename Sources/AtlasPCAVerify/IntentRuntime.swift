import Foundation

/// The pure parts of runtime intent conformance: the judge input and the PCActn action shape for an outcome, the content addresses
/// of the conformance attestation, the calibration set and the just-in-time consent request, the consent prompt, and the monotone
/// risk fold. The route decision lives in `PCAIntentRouting`. Outcomes are `{verb, values}` values; the verb space is the learner's
/// own (`WalletVerb`).
public enum PCAIntentRuntime {
    public static let IC_ATT_DOMAIN = "atlas-pca/intent-ic-att/v1"
    static let ANY_RESOURCE = "resource:any"

    /// Deep copy with every number spelled as the JSON number JavaScript would print (hashed trees carry plain numbers).
    static func jsonNums(_ v: JSONValue?) -> JSONValue {
        guard let v = v else { return .null }
        switch v {
        case .double: return WJ.plain(v)
        case let .object(o): return .object(o.mapValues { jsonNums($0) })
        case let .array(a): return .array(a.map { jsonNums($0) })
        default: return v
        }
    }

    private static func setPath(_ root: inout JObject, _ segs: [String], _ i: Int, _ value: JSONValue) {
        let k = JKey(segs[i])
        if i == segs.count - 1 { root[k] = value; return }
        var child: JObject = [:]
        if case let .object(c)? = root[k] { child = c }
        setPath(&child, segs, i + 1, value)
        root[k] = .object(child)
    }

    /// The outcome as the analyzer's concrete action: `{verb, resource, params, reversibilityClass, env?, subject?}`. The values are
    /// visited in the engine's own member order (array-index keys first, then UTF-16 order).
    static func outcomeToAction(_ vs: WalletVerb, _ o: JSONValue) -> JObject {
        var params: JObject = [:]
        var env: JObject = [:]
        var subject: JObject = [:]
        var resource = ANY_RESOURCE
        let values: JSONValue? = o.get("values")
        for path in JSLoose.keys(values) {
            guard let value = JSLoose.get(values, path) else { continue }
            let segs: [String] = IV.split(path, ".")
            if IV.same(path, "action.resource") {
                resource = IntentV2.jsString(value)
            } else if segs.count > 2 && IV.same(segs[0], "action") && IV.same(segs[1], "params") {
                setPath(&params, segs, 2, value)
            } else if segs.count > 1 && IV.same(segs[0], "env") {
                setPath(&env, segs, 1, value)
            } else if segs.count > 1 && IV.same(segs[0], "subject") {
                setPath(&subject, segs, 1, value)
            }
        }
        var a: JObject = [:]
        a["verb"] = o.get("verb") ?? .null
        a["resource"] = .string(resource)
        a["params"] = .object(params)
        a["reversibilityClass"] = .string(vs.reversibility)
        if !env.isEmpty { a["env"] = .object(env) }
        if !subject.isEmpty { a["subject"] = .object(subject) }
        return a
    }

    /// The PCActn action shape for an outcome (params digest by the canonical rule).
    public static func pcactnActionOf(_ vs: WalletVerb, _ o: JSONValue) -> JSONValue {
        let a: JObject = outcomeToAction(vs, o)
        let params: JSONValue = jsonNums(a["params"])
        var out: JObject = [:]
        out["verb"] = a["verb"] ?? .null
        out["resource"] = a["resource"] ?? .null
        out["params_digest"] = .string(Merkle.paramsDigest(params))
        out["reversibility_class"] = .string(vs.reversibility)
        return .object(out)
    }

    /// The digest every verdict must bind to.
    public static func actionDigest(_ action: JSONValue?) -> String { Canonical.hashCanonical(action ?? .null) }

    /// Digest of a verdict (canonical over the full verdict).
    public static func verdictDigest(_ verdict: JSONValue?) -> String { Canonical.hashCanonical(verdict ?? .null) }

    /// What every judge sees; `p` is the map's acceptance of the outcome; `ctx`: intentRef, mapDigest, statementText, slots, goalCommitment.
    public static func judgeInputOf(_ vs: WalletVerb, _ o: JSONValue, _ p: Double, _ ctx: JSONValue) throws -> JSONValue {
        var out: JObject = ctx.asObject ?? [:]
        let values: JSONValue = .object(o.get("values")?.asObject ?? [:])
        out["renderedAction"] = .string(try PCAIntentRender.renderAction(vs, values))
        out["p"] = .double(p)
        out["reversibility"] = .string(vs.reversibility)
        out["actionDigest"] = .string(actionDigest(pcactnActionOf(vs, o)))
        return .object(out)
    }

    /// Digest of a calibration set (`{alpha, samples: [{score, faithful}]}`).
    public static func calibrationDigest(_ c: JSONValue) throws -> String {
        guard let samples = c.get("samples")?.asArray else { throw JSError("calibrationDigest: samples must be a list") }
        var list: [JSONValue] = []
        for s in samples {
            guard let so = s.asObject else { throw JSError("calibrationDigest: a sample must be an object") }
            list.append(.object(["score": so["score"] ?? .null, "faithful": so["faithful"] ?? .null]))
        }
        return Canonical.hashCanonical(.object(["d": .string("atlas-pca/intent-calibration/v1"), "alpha": c.get("alpha") ?? .null, "samples": .array(list)]))
    }

    /// Content address of an IC-Att (the value a PCActn carries as `ic_att_digest`).
    public static func icAttDigest(_ att: JSONValue?) -> String {
        Canonical.hashCanonical(.object(["d": .string(IC_ATT_DOMAIN), "a": att ?? .null]))
    }

    /// The risk contribution of an aggregate judge score: 1 - score clamped to [0, 1] (1 when not finite).
    public static func semanticRiskContribution(_ aggregateScore: Double) -> Double {
        if aggregateScore.isNaN || aggregateScore.isInfinite { return 1.0 }
        let r = 1 - aggregateScore
        return r < 0 ? 0.0 : (r > 1 ? 1.0 : r)
    }

    /// The monotone risk fold: r := max(r, 1 - aggregateScore). Never lowers r.
    public static func foldSemanticRisk(_ r: Double, _ att: JSONValue) -> Double {
        let ppm: Double = IV.num(att.get("aggregate_score_ppm")) ?? Double.nan
        let c = semanticRiskContribution(ppm / 1_000_000)
        if r.isNaN { return r }
        return r > c ? r : c
    }

    /// The consent prompt for an action; `p` is the map's acceptance of the outcome.
    public static func jitConsentRequest(_ vs: WalletVerb, _ o: JSONValue, _ p: Double, _ intentRef: String?, _ mapDigest: String?) throws -> JSONValue {
        let values: JSONValue = .object(o.get("values")?.asObject ?? [:])
        var out: JObject = [:]
        out["v"] = .int(1)
        out["kind"] = .string("pca-intent-jit")
        out["intent_ref"] = intentRef.map { JSONValue.string($0) } ?? .null
        out["map_digest"] = mapDigest.map { JSONValue.string($0) } ?? .null
        out["verb"] = o.get("verb") ?? .null
        out["values"] = jsonNums(values)
        out["reversibility"] = .string(vs.reversibility)
        out["p_ppm"] = .int(PCAIntentMap.ppm(p))
        out["text"] = .string(try PCAIntentRender.renderAction(vs, values) + " This cannot be undone. Approve?")
        return .object(out)
    }

    public static func jitConsentDigest(_ request: JSONValue?) -> String {
        Canonical.hashCanonical(.object(["d": .string("atlas-pca/intent-jit/v1"), "r": request ?? .null]))
    }
}
