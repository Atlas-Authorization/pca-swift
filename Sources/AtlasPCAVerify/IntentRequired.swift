import Foundation

/// The signed "ask the principal" question and its RFC 9457 problem: the constants, the digest of the action a question is about, the shape check of an unsigned
/// or signed body, the clock-checked verifier and the 403 problem response. Signing lives in `PCASigners.signIntentRequired`, the verifier in
/// `PCAWalletDelivery.verifyIntentRequired`; this adds the facade the reference exports.
public enum PCAIntentRequired {
    public static let PROBLEM_BASE = "https://atlasauth.net/pca/problems/"
    public static let INTENT_PROBLEM_KINDS = ["intent-required", "intent-denied", "schema-violation", "ceiling"]
    public static let INTENT_REQUIRED_DOMAIN = PCASigners.INTENT_REQUIRED_DOMAIN
    public static let INTENT_ACTION_DOMAIN = "atlas-pca/intent-action/v1"
    public static let FRICTIONS = ["tap", "hold", "typed", "device"]

    private static let TITLES: [String: String] = [
        "intent-required": "Principal confirmation required for this action",
        "intent-denied": "The principal does not intend this action",
        "schema-violation": "The action does not conform to the site action schema",
        "ceiling": "The action is outside a ceiling the principal cannot widen",
    ]
    private static let ERRORS: [String: String] = ["intent-required": "intent_required", "intent-denied": "intent_denied", "schema-violation": "schema_violation", "ceiling": "ceiling"]

    /// base64url(sha256(strict canonical `{d: INTENT_ACTION_DOMAIN, action: {verb, resource, params_digest, reversibility_class}}`)); other members are ignored.
    public static func intentActionDigest(_ action: JSONValue?) throws -> String {
        func m(_ k: String) -> JSONValue? { action?.get(k) }
        var a: JObject = [:]
        for k in ["verb", "resource", "params_digest", "reversibility_class"] { if let v = m(k) { a[JKey(k)] = v } }
        return Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(.object(["d": .string(INTENT_ACTION_DOMAIN), "action": .object(a)]))))
    }

    public static func cellCoordsError(_ c: JSONValue?) -> String? { PCASigners.cellCoordsError(c) }

    /// The shape of a `pca-intent-required` v1 body: signed (default) or unsigned.
    public static func intentRequiredShapeError(_ b: JSONValue?, signed: Bool = true) -> String? {
        signed ? PCAWalletDelivery.intentRequiredShapeError(b) : (b.map { PCASigners.intentRequiredShapeError($0) } ?? "not an object")
    }

    /// `{ok: true}` or `{ok: false, reason}`; a clock that is not a safe integer is refused.
    public static func verifyIntentRequiredAt(_ b: JSONValue?, _ keys: JSONValue?, _ now: JSONValue?) -> JSONValue { PCAWalletDelivery.verifyIntentRequired(b, keys, now) }

    /// The 403 problem response of a refusal kind; `intent-required` needs the signed body (its session and question id go in the challenge). An unknown kind
    /// still answers, with no title and `error="undefined"`, as the reference does.
    public static func intentProblem(_ kind: JSONValue?, detail: JSONValue? = nil, body: JSONValue? = nil) throws -> JSONValue {
        let k = kind?.asString
        let known = k.flatMap { ks in INTENT_PROBLEM_KINDS.first { IV.same($0, ks) } }
        var params = ["error=\"\(known.flatMap { ERRORS[$0] } ?? "undefined")\""]
        let hasBody = body.map { JS.truthy($0) } ?? false
        if let kn = known, IV.same(kn, "intent-required") {
            guard hasBody, let b = body else { throw JSError("intentProblem: intent-required needs the signed body") }
            params.append("session=\"\(JS.toString(b.get("session")))\"")
            params.append("question=\"\(JS.toString(b.get("question_id")))\"")
        }
        var out: JObject = ["type": .string(PROBLEM_BASE + JS.toString(kind))]
        if let kn = known, let t = TITLES[kn] { out["title"] = .string(t) }
        out["status"] = .int(403)
        if let d = detail { out["detail"] = d }
        if hasBody, let b = body { out["pca"] = b }
        return .object(["status": .int(403),
                        "headers": .object(["WWW-Authenticate": .string("PCA " + params.joined(separator: ", ")), "Content-Type": .string("application/problem+json")]),
                        "body": .object(out)])
    }
}
