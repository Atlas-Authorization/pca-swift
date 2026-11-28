import Foundation

/// The approval-render helpers over action defs. The canonical render itself is `Approval.render`; these bind it to an executed PCActn, to the
/// approver client's check, and to the pinned definitions a step-up renderer is derived from.
public enum ActionApprovals {
    /// The canonical approval render of a def for params (`confirmed`: the def carries a valid signed confirmation).
    public static func renderApproval(_ def: JObject, _ params: JSONValue?, _ confirmed: Bool) throws -> JSONValue {
        try Approval.render(def: def, params: params ?? .null, confirmed: confirmed)
    }

    private static func digestOf(_ r: JSONValue) throws -> String {
        guard let d = Approval.renderDigest(r) else { throw AK.fail("render_digest", "the render is outside the strict JSON profile") }
        return d
    }

    /// H(R) for an executed action: refuses unless the params are the ones the PCActn signed and the verb is the PCActn's verb.
    public static func renderDigestForAction(_ def: JObject, _ params: JObject, _ pcactn: JObject, _ confirmed: Bool) throws -> String {
        let action = pcactn["action"]
        if def["verb"] != action?.get("verb") {
            throw AK.fail("render_verb_mismatch", "the PCActn is for '\(JS.toString(action?.get("verb")))', the definition for '\(JS.toString(def["verb"]))'")
        }
        guard let pd = action?.get("params_digest")?.asString, pd == Merkle.paramsDigest(.object(params)) else {
            throw AK.fail("render_params_mismatch", "the supplied params are not the params the PCActn signed")
        }
        return try digestOf(try renderApproval(def, .object(params), confirmed))
    }

    /// The approver client's check before it signs: re-render from the pinned def and the displayed params, and require the digest the request carries.
    public static func approverRenderCheck(_ def: JObject, _ params: JObject, _ requestedRenderDigest: String?, _ confirmed: Bool) throws -> String {
        let d = try digestOf(try renderApproval(def, .object(params), confirmed))
        if d != requestedRenderDigest { throw AK.fail("render_mismatch", "the approval request commits to a render this definition and these params do not produce") }
        return d
    }

    /// Single-tap (one-gesture) approval is allowed only for a confirmed definition.
    public static func singleTapAllowed(_ render: JObject) -> Bool { !JS.truthy(render["unreviewed"]) }

    /// The step-up renderer derived from the PINNED definitions: the def is found by verb (or alias, first definition wins); a verb with no pinned
    /// definition throws, which makes the review a deny.
    public static func renderFromDefs(_ defs: [JSONValue], _ verb: String, _ params: JObject?, _ confirmed: Bool) throws -> JSONValue {
        var byVerb: [JKey: JObject] = [:]
        for d in defs {
            guard let v = d.get("verb")?.asString else { throw AK.fail("bad_def", "verb") }
            byVerb[JKey(v)] = AK.o(d)
            for a in AK.arr(d.get("aliases")) {
                guard let s = a.asString else { throw AK.fail("bad_def", "alias") }
                if byVerb[JKey(s)] == nil { byVerb[JKey(s)] = AK.o(d) }
            }
        }
        guard let d = byVerb[JKey(verb)] else { throw AK.fail("render_unknown_verb", "no pinned action definition for '\(verb)'") }
        return try renderApproval(d, .object(params ?? [:]), confirmed)
    }
}

/// The facts the default provenance gate reads, derived from signed action defs. "Unconfirmed means maximally dangerous": a def without a
/// valid signed confirmation reports no effects and the top trait set, and its `provenance_min` relaxations are ignored.
public enum ActionProvenance {
    /// The gate facts of one def under a trait registry: `{effects, traits, params?}`.
    public static func provenanceInfoOf(_ d: JObject, _ reg: TraitRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> JSONValue {
        let traits = try ActionEffective.traitsOf(d, reg, attestationVerified)
        if !ActionEffective.isConfirmed(d, attestationVerified) { return AK.obj(["effects": .array([]), "traits": AK.strs(traits)]) }
        let n = try Actions.normalize(d)
        var params: JObject = [:]
        let np = AK.o(n["params"])
        for k in JS.keyOrder(np) { if let pm = JS.present(np[k]?.get("provenance_min")) { params[k] = pm } }
        var out: JObject = ["effects": n["effects"] ?? .array([]), "traits": AK.strs(traits)]
        if !params.isEmpty { out["params"] = .object(params) }
        return .object(out)
    }

    /// The `provenance.actions` resolver: the facts of the def whose verb (or alias) is the operation's verb; nil for an unknown verb (the gate then treats
    /// the action as sensitive). Two defs claiming one name throw at build time.
    public static func provenanceActions(_ defs: [JSONValue], _ reg: TraitRegistry, _ attestationVerified: ((JObject) -> Bool)? = nil) throws -> (String) -> JSONValue? {
        var byVerb: [JKey: JSONValue] = [:]
        for dO in defs {
            let d = AK.o(dO)
            let n = try Actions.normalize(d)
            let info = try provenanceInfoOf(d, reg, attestationVerified)
            var names: [JSONValue] = [n["verb"] ?? .null]
            names += AK.arr(n["aliases"])
            for v in names {
                guard let s = v.asString else { throw AK.fail("bad_def", "verb") }
                if byVerb[JKey(s)] != nil { throw AK.fail("duplicate_verb", "provenanceActions: two definitions claim the verb '\(s)'") }
                byVerb[JKey(s)] = info
            }
        }
        let table = byVerb
        return { v in table[JKey(v)] }
    }
}

/// The regulatory and platform views of the canonical approval render: PSD2 RTS Art. 5 dynamic linking (amount and payee, batches), the Secure Payment
/// Confirmation expectation and the CIBA / RFC 9396 authorization details. The linking, the minor-unit text and the batch are `Approval`'s; this is the
/// package's own surface for them.
public enum ActionApprovalProfiles {
    public static let APPROVAL_BATCH_DOMAIN = Approval.BATCH_DOMAIN

    /// The amount and the payee of a payment render, as Art. 5(1) needs them: `{amount_minor, currency, exp, payee}`.
    public static func psd2Linking(_ r: JSONValue) throws -> JSONValue { try Approval.psd2Linking(r) }

    /// Minor units to the decimal string of the major unit ("1250", exp 2 -> "12.50").
    public static func minorToDecimal(_ minor: Int64, _ exp: Int64) throws -> String { try Approval.minorToDecimal(minor, exp) }

    /// One approval over N payments (items `{action_digest, render}`): `{batch, action_digest, render_digest, challenge, words}`.
    public static func approvalBatch(_ items: [JSONValue]) throws -> JSONValue { try Approval.batch(items) }

    /// What a WebAuthn assertion verifier must find in the signed `clientData.payment`. The payee value is the name or the origin the browser shows.
    public static func spcExpectation(_ r: JSONValue, _ topOrigin: String, _ payeeAs: String = "name") throws -> JSONValue {
        let l = try Approval.psd2Linking(r)
        guard let amt = IV.int(l.get("amount_minor")), let exp = IV.int(l.get("exp")) else { throw AK.fail("psd2_unlinkable", "the money unit has no integer exponent") }
        var out = AK.o(AK.obj(["topOrigin": .string(topOrigin), "total": AK.obj(["currency": l.get("currency") ?? .null, "value": .string(try Approval.minorToDecimal(amt, exp))])]))
        out[JKey(payeeAs == "name" ? "payeeName" : "payeeOrigin")] = l.get("payee") ?? .null
        return .object(out)
    }

    /// RFC 9396 authorization_details entry carrying the canonical render, plus the speakable match code.
    public static func cibaApprovalDetails(_ r: JSONValue) throws -> JSONValue {
        guard let rd = Approval.renderDigest(r), let words = Approval.bindingWords(rd) else { throw AK.fail("render_digest", "the render is outside the strict JSON profile") }
        return AK.obj(["authorization_details": .array([AK.obj(["type": .string("pca_approval"), "render": r, "render_digest": .string(rd)])]), "match_code": .string(words)])
    }
}
