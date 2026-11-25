import Foundation

/// The pure, scheme-independent parts of the homomorphic risk gate: risk-input transformation and fixed-point quantization, the public gate
/// policy, the risk claim binding read from a signed action, and the plaintext reference verdict. Values are parsed JSON (`JSONValue`); a
/// JavaScript number that is not finite is the fail-closed worst case, as in the reference. The BFV evaluation is the separate AtlasPCAFhe
/// product (Microsoft SEAL); the signed-claim layer is `PCAFheOrigin`.
public enum PCAFheRisk {
    public static let POLY_MODULUS_DEGREE = 8192
    public static let PLAIN_MODULUS_BITS = 30
    public static let PLAIN_MODULUS: Int64 = 1_073_692_673
    public static let SIGNED_BOUND: Int64 = PLAIN_MODULUS / 2
    public static let DEFAULT_SCALE: Double = 1000
    public static let RISK_DIM = 6

    private static let inputFields = ["semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"]

    /// The JavaScript number value of a parsed JSON number; NaN for anything that is not a number.
    static func num(_ v: JSONValue?) -> Double { IV.num(v) ?? .nan }

    private static func clamp01(_ x: Double) -> Double { x < 0 ? 0 : (x > 1 ? 1 : x) }
    private static func unit(_ x: Double, _ worst: Double) -> Double { x.isFinite ? clamp01(x) : worst }
    private static func wt(_ x: Double) -> Double { x.isFinite && x > 0 ? x : 0 }

    private static func field(_ m: JSONValue?, _ k: String) throws -> Double {
        guard let m = m, !m.isNull else { throw PCAProducerError("Cannot read properties of null (reading '\(k)')") }
        return num(m.get(k))
    }

    private static func object(_ v: JSONValue?, _ what: String) throws -> JSONValue {
        guard let v = v, v.isObject else { throw PCAProducerError("\(what) is not an object") }
        return v
    }

    /// [d, 1 - rev, bl, taint, 1 - conf, age], each through `unit` with the worst case of the risk score.
    public static func transformedInputs(_ i: JSONValue) throws -> [Double] {
        [unit(try field(i, "semanticDistance"), 1),
         1 - unit(try field(i, "reversibility"), 0),
         unit(try field(i, "blastRadius"), 1),
         unit(try field(i, "taint"), 1),
         1 - unit(try field(i, "confidence"), 0),
         unit(try field(i, "age"), 1)]
    }

    /// The weight vector of the risk score in canonical order with its clamp applied.
    public static func weightVector(_ w: JSONValue) throws -> [Double] {
        try ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"].map { wt(try field(w, $0)) }
    }

    /// JavaScript Math.round (ties toward +infinity), exact.
    static func jsRound(_ x: Double) -> Double {
        guard x.isFinite else { return x }
        let f = x.rounded(.down)
        return x - f >= 0.5 ? f + 1 : f
    }

    private static func requireScale(_ s: Double) throws {
        if !s.isFinite || s != s.rounded() || s <= 0 { throw PCAProducerError("scale must be a positive integer") }
    }

    /// round(x_i * scale) for each transformed input: the integer vector the agent encrypts.
    public static func quantizeRiskInputs(_ i: JSONValue, scale: JSONValue = .int(1000)) throws -> [Double] {
        let s = num(scale)
        try requireScale(s)
        return try transformedInputs(i).map { jsRound($0 * s) }
    }

    /// A JSON number for a binary64 value: an integer when it is a safe integer, else the double.
    static func numVal(_ d: Double) -> JSONValue { PCAFacade.jsNum(d) }

    /// The public gate policy from a risk policy {weights, kappa} and the trust budget B, at fixed-point scale S: weights round(w_i S),
    /// kappa-weighted weights round(kappa w_i S), budget round(B S^2). Refuses a policy whose scaled values could overflow the signed
    /// plain-modulus range (a wrap would silently corrupt the verdict).
    public static func fheRiskPolicy(_ core: JSONValue, budget: JSONValue, scale scaleArg: JSONValue = .int(1000)) throws -> JSONValue {
        let scale = num(scaleArg)
        try requireScale(scale)
        let b = num(budget)
        if !(b.isFinite && b >= 0) { throw PCAProducerError("budget must be finite and >= 0") }
        let kappa = try field(core, "kappa")
        if !(kappa.isFinite && kappa > 0) { throw PCAProducerError("policy.kappa must be finite and > 0") }
        let w = try weightVector(try object(core.get("weights"), "policy.weights"))
        let ws = w.map { jsRound($0 * scale) }
        let kws = w.map { jsRound(kappa * $0 * scale) }
        let budgetScaled = jsRound(b * scale * scale)
        let maxAbs = max(ws.reduce(0, +) * scale, kws.reduce(0, +) * scale, budgetScaled)
        if maxAbs >= Double(SIGNED_BOUND) {
            throw PCAProducerError("policy/scale overflow the plain modulus: max |value| \(PCAFacade.jsNumberText(maxAbs)) must be < SIGNED_BOUND \(SIGNED_BOUND). Lower the scale or the weights/budget.")
        }
        return .object([
            "scale": numVal(scale), "dim": .int(Int64(RISK_DIM)),
            "weightsScaled": .array(ws.map(numVal)), "kappaWeightsScaled": .array(kws.map(numVal)),
            "budgetScaled": numVal(budgetScaled), "kappa": numVal(kappa),
        ])
    }

    /// The six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field is NaN (fail-closed).
    public static func riskInputsFromPCActn(_ p: JSONValue) throws -> JSONValue {
        let src = try object(try object(p.get("risk_claim"), "risk_claim").get("inputs"), "risk_claim.inputs")
        var out = JObject()
        for k in inputFields {
            let v = src.get(k)
            out[JKey(k)] = (v?.isNumber ?? false) ? v! : .double(.nan)
        }
        return .object(out)
    }

    /// The replay binding of a signed action: audience, action digest, counter and the optional nonce.
    public static func bindingFromPCActn(_ p: JSONValue) throws -> JSONValue {
        var m: JObject = [
            "aud": p.get("aud") ?? .null,
            "actionRef": try object(p.get("action"), "action").get("params_digest") ?? .null,
            "counter": p.get("counter") ?? .null,
        ]
        if let n = p.asObject?[JKey("nonce")] { m["nonce"] = n }
        return .object(m)
    }

    /// The plaintext reference verdict: r = risk score, admit iff kappa-cost(r) <= budget. Returns {r, admit}.
    public static func plaintextVerdict(_ inputs: JSONValue, _ core: JSONValue, budget: JSONValue) throws -> JSONValue {
        let w = try object(core.get("weights"), "policy.weights")
        let r = clamp01(wt(try field(w, "alpha")) * unit(try field(inputs, "semanticDistance"), 1)
            + wt(try field(w, "beta")) * (1 - unit(try field(inputs, "reversibility"), 0))
            + wt(try field(w, "gamma")) * unit(try field(inputs, "blastRadius"), 1)
            + wt(try field(w, "delta")) * unit(try field(inputs, "taint"), 1)
            + wt(try field(w, "epsilon")) * (1 - unit(try field(inputs, "confidence"), 0))
            + wt(try field(w, "zeta")) * unit(try field(inputs, "age"), 1))
        let kappa = try field(core, "kappa")
        let cost = (kappa.isFinite && kappa > 0 ? kappa : 0) * clamp01(r.isFinite ? r : 1)
        return .object(["r": numVal(r), "admit": .bool(num(budget).isFinite && cost <= num(budget))])
    }
}
