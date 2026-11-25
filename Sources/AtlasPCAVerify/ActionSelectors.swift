import Foundation

/// Trait selectors and the registry-growth semantics. A selector is a positive predicate over the trait closure of an action.
/// Prohibit selectors float (they cover every present and future action that matches); allow selectors are pinned to a set of
/// verbs and may not use negation (the absence of a trait is never a safety claim). A selector is `{k: 'trait', id}`,
/// `{k: 'all_of'|'any_of', ids}`, `{k: 'not', s}` or `{k: 'and', a, b}`.
public enum ActionSelectors {
    /// Does the selector match an action whose trait closure is `closure`?
    public static func selectorMatches(_ s: JSONValue?, _ closure: [JSONValue]) throws -> Bool {
        let k = s?.get("k")
        if k == .string("trait") { return closure.contains(s?.get("id") ?? .null) }
        if k == .string("all_of") { return AK.arr(s?.get("ids")).allSatisfy { closure.contains($0) } }
        if k == .string("any_of") { return AK.arr(s?.get("ids")).contains { closure.contains($0) } }
        if k == .string("not") { return !(try selectorMatches(s?.get("s"), closure)) }
        if k == .string("and") { return try selectorMatches(s?.get("a"), closure) && selectorMatches(s?.get("b"), closure) }
        throw AK.fail("unknown_selector", "unknown selector kind")
    }

    /// Does a selector of the given mode (`allow` or `prohibit`) match an action? An UNCONFIRMED action is maximally dangerous: every
    /// prohibit selector matches it whatever it says, and no allow selector ever does.
    public static func selectorMatchesFor(_ s: JSONValue?, _ mode: String, _ closure: [JSONValue], _ confirmed: Bool) throws -> Bool {
        if !confirmed { return mode == "prohibit" }
        return try selectorMatches(s, closure)
    }

    public static func selectorHasNot(_ s: JSONValue?) -> Bool {
        let k = s?.get("k")
        return k == .string("not") || (k == .string("and") && (selectorHasNot(s?.get("a")) || selectorHasNot(s?.get("b"))))
    }

    private static func anyOf(_ s: JSONValue?) -> Bool {
        let k = s?.get("k")
        return k == .string("any_of") || (k == .string("and") && (anyOf(s?.get("a")) || anyOf(s?.get("b"))))
    }

    /// The typing rule for an ALLOW selector: no negation anywhere, and any_of only inside a pinned allow. Nil = allowed.
    public static func allowSelectorError(_ s: JSONValue?, _ pinned: Bool) -> String? {
        if selectorHasNot(s) { return "an allow selector must not use negation: the absence of a trait is never a safety claim" }
        if !pinned && anyOf(s) { return "any_of in an allow selector requires the grant to be pinned to a pack digest" }
        return nil
    }

    /// The policy component of the decision for one action: a matching prohibit denies; otherwise a pinned verb with a matching allow is
    /// allowed; an unpinned verb is deny/escalate; a pinned verb with no allow is deny. `p` is `{pinned, allow, prohibit, on_new_action?}`.
    public static func policyDecision(_ p: JObject, _ verb: String, _ closure: [JSONValue], _ confirmed: Bool) throws -> String {
        for s in AK.arr(p["prohibit"]) { if try selectorMatchesFor(s, "prohibit", closure, confirmed) { return "deny" } }
        if !AK.arr(p["pinned"]).contains(.string(verb)) { return p["on_new_action"] == .string("escalate") ? "escalate" : "deny" }
        for s in AK.arr(p["allow"]) { if try selectorMatchesFor(s, "allow", closure, confirmed) { return "allow" } }
        return "deny"
    }
}

/// The signed human confirmation of an action: the only thing that can set an action's effective trait set below the top of the
/// registry ("unconfirmed means maximally dangerous"). Signing, and the verifier's view of a confirmation on a schema verb.
public enum ActionConfirmation {
    public static let REVIEW_DOMAIN = "atlas-pca/action-review/v2"
    public static let VERB_FACTS_DOMAIN = "atlas-pca/action-verb-facts/v1"
    public static let KEY_ROLES = ["reviewer", "importer", "model", "publisher"]

    /// A dismissal reason with no content: only white space (which includes U+001C..U+001F, as in the reference).
    public static func blankReason(_ s: String) -> Bool {
        s.utf16.allSatisfy { u in (9...13).contains(u) || u == 32 || u == 0xa0 || u == 0x1680 || (0x2000...0x200a).contains(u) || u == 0x2028 || u == 0x2029 || u == 0x202f || u == 0x205f || u == 0x3000 || u == 0xfeff || (0x1c...0x1f).contains(u) }
    }

    public static func factsDigest(_ verb: JObject) -> String { Actions.factsDigest(verb) }
    public static func reviewerPinsError(_ pins: JSONValue?) -> String? { Actions.reviewerPinsError(pins) }

    /// The bytes a reviewer signs: `REVIEW_DOMAIN \0` then the strict canonical body.
    public static func reviewMessage(_ b: JObject) throws -> [UInt8] {
        guard let m = Actions.reviewMessage(b) else { throw AK.fail("bad_review", "the review body is malformed") }
        return m
    }

    /// Sign a review body (`def_digest, traits_digest, facts_digest, final_traits, dismissed, reviewer_kid, ts`) with an Ed25519 key.
    public static func signReview(_ b: JObject, _ key: PCAEdKey) throws -> JSONValue {
        var norm = b
        norm["final_traits"] = AK.strs(Actions.sortUniq(AK.arr(b["final_traits"]).compactMap { $0.asString }))
        let dis = AK.arr(b["dismissed"]).sorted { x, y in (x.get("trait")?.asString ?? "").utf16.lexicographicallyPrecedes((y.get("trait")?.asString ?? "").utf16) }
        norm["dismissed"] = .array(dis)
        var out = norm
        out["sig"] = .string(Base64URLStrict.encode(try key.sign(try reviewMessage(norm))))
        return .object(out)
    }

    /// Nil iff the verb carries a VALID human confirmation (an attestation over exactly the def digest the verb names, against an accepted
    /// trait registry digest, whose final traits are carried by the verb, signed by a key pinned with the reviewer role inside its validity
    /// window); anything else is a reason string and the verb is UNCONFIRMED. Never throws.
    public static func verbConfirmationError(_ v: JObject, _ reg: TraitRegistry, _ pins: JSONValue?) -> String? {
        guard let pins = pins else { return "no reviewer keys are pinned" } // only an absent value: a null is a malformed pin set
        if let pe = reviewerPinsError(pins) { return "bad pins: \(pe)" }
        guard let av = v["confirmation"] else { return "no confirmation" }
        // an array is a JavaScript object with none of the members read below
        let am: JObject
        switch av { case let .object(o): am = o; case .array: am = [:]; default: return "confirmation is not an object" }
        guard let sig = am["sig"]?.asString else { return "the confirmation is unsigned" }
        guard let def = v["def"]?.asString, am["def_digest"] == .string(def) else { return "the confirmation covers a different def digest" }
        var accepted: [JSONValue] = [.string(Actions.traitsDigest(reg))]
        if case let .array(extra)? = pins.get("traits_digests") { accepted += extra }
        if !accepted.contains(am["traits_digest"] ?? .null) { return "the confirmation was made against a different trait registry" }
        guard let fd = am["facts_digest"]?.asString, fd == factsDigest(v) else { return "the verb facts differ from the facts the reviewer confirmed" }
        guard case let .array(fin)? = am["final_traits"], case let .array(dis)? = am["dismissed"], let tsv = IV.int(am["ts"]), let kid = am["reviewer_kid"]?.asString else { return "malformed confirmation" }
        let carried = AK.arr(v["traits"])
        for t in fin { if t.asString == nil || !carried.contains(t) { return "the verb does not carry every trait the reviewer signed" } }
        for d in dis {
            guard let tt = d.get("trait")?.asString, let rr = d.get("reason")?.asString, !fin.contains(.string(tt)), !blankReason(rr) else { return "a dismissed trait is also final, or has no reason" }
        }
        var key: JSONValue?
        for k in AK.arr(pins.get("keys")) where k.get("kid") == .string(kid) { key = k; break }
        guard let kv = key else { return "no pinned key '\(kid)'" }
        if !AK.arr(kv.get("roles")).contains(.string("reviewer")) { return "key '\(JS.toString(kv.get("kid")))' does not hold the reviewer role" }
        let ts = Double(tsv)
        if let nb = IV.num(kv.get("not_before")), ts < nb { return "the confirmation time is outside the key validity" }
        if let na = IV.num(kv.get("not_after")), ts > na { return "the confirmation time is outside the key validity" }
        var body = am
        body[JKey("sig")] = nil
        guard let pk = kv.get("pk")?.asString, Base64URLStrict.isValid(pk, length: 32), Base64URLStrict.isValid(sig, length: 64),
              let msg = Actions.reviewMessage(body), Ed25519Strict.verifyB64u(pk, msg, sig) else { return "the confirmation signature is invalid" }
        return nil
    }
}
