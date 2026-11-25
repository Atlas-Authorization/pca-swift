import Foundation

/// Portable, revocable intent profiles (`pca-intent-profile` v1): the principal's signed, versioned, append-only record of standing
/// rules (deny wins; permit is explicit, scoped and expiring) and prior answers (negative answers become vetoes, positive ones never
/// feed the learner). Profiles, scopes, rules and uses are JSON values. Verification honours every suite the SDK implements.
public enum PCAIntentProfile {
    public static let INTENT_PROFILE_KIND = "pca-intent-profile"
    public static let INTENT_PROFILE_SIG_DOMAIN = "atlas-pca/intent-profile/v1\u{0}"
    public static let INTENT_PROFILE_REF_DOMAIN = "atlas-pca/intent-profile-ref/v1"
    public static let MAX_PROFILE_RULES = 256
    public static let MAX_PROFILE_OBSERVATIONS = 2000

    static let KEYS = ["v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev", "alg", "pq_pk", "sig", "pq_sig"]
    static let BODY_KEYS = ["v", "kind", "profile_id", "version", "owner", "scope", "standing", "prior", "expires_at", "revocation", "prev"]

    private static func get(_ o: JSONValue?, _ k: String) -> JSONValue? { JSLoose.get(o, k) }

    private static func has(_ o: JSONValue?, _ k: String) -> Bool {
        if case let .object(d)? = o { return d[JKey(k)] != nil }
        return false
    }

    /// A member that is present and not null (Kotlin's null).
    private static func nn(_ v: JSONValue?) -> JSONValue? {
        guard let v = v, !v.isNull else { return nil }
        return v
    }

    private static func dbl(_ v: JSONValue?) -> Double { IV.num(v) ?? Double.nan }

    private static func b32(_ v: JSONValue?) -> Bool { IV.digest(v) != nil }

    private static func isId(_ s: String) -> Bool {
        let u = Array(s.unicodeScalars)
        return (1...128).contains(u.count) && u.allSatisfy { c in
            (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A) || c == "_" || c == "." || c == "-"
        }
    }

    private static func strList(_ v: JSONValue?) -> Bool {
        guard let a = v?.asArray, a.count <= 256 else { return false }
        return a.allSatisfy { ($0.asString.map { !$0.isEmpty }) ?? false }
    }

    private static func predOk(_ p: JSONValue?) -> Bool {
        guard case .object? = p else { return false }
        let verb = get(p, "verb")
        if verb?.asString != nil { return true }
        if let a = verb?.asArray { return a.allSatisfy { $0.asString != nil } }
        return false
    }

    /// The member names of an object are exactly `names`.
    private static func exactKeys(_ v: JSONValue?, _ names: [String]) -> Bool {
        guard let o = v?.asObject, o.count == names.count else { return false }
        return names.allSatisfy { o[JKey($0)] != nil }
    }

    /// The first reason a profile is malformed, or nil. `signed = false` skips the suite / signature members.
    public static func intentProfileShapeError(_ pv: JSONValue?, _ signed: Bool = true) -> String? {
        guard case let .object(p)? = pv else { return "profile is not an object" }
        for k in JSLoose.keys(pv) where !IV.contains(KEYS, k) { return "profile: unknown member '\(k)'" }
        if IV.num(p["v"]) != 1 || !IV.same(p["kind"]?.asString, INTENT_PROFILE_KIND) { return "not a pca-intent-profile v1" }
        guard let pid = p["profile_id"]?.asString, isId(pid) else { return "profile_id must match [A-Za-z0-9_.-]{1,128}" }
        guard let version = IV.int(p["version"]), version >= 1 else { return "version must be a safe integer >= 1" }
        if !b32(p["owner"]) { return "owner must be canonical base64url (32 bytes)" }
        guard let scope = p["scope"]?.asObject else { return "scope must be {sites?, verbs?, semantic_types?}" }
        for k in JS.keyOrder(scope) where !IV.contains(["sites", "verbs", "semantic_types"], k.s) { return "scope must be {sites?, verbs?, semantic_types?}" }
        for k in ["sites", "verbs", "semantic_types"] {
            if let x = scope[JKey(k)], !strList(x) { return "scope.\(k) must be a list of strings" }
        }
        guard exactKeys(p["standing"], ["deny", "permit"]) else { return "standing must be {deny, permit}" }
        for k in ["deny", "permit"] {
            guard let r = get(p["standing"], k)?.asArray, r.count <= MAX_PROFILE_RULES, r.allSatisfy({ predOk($0) }) else {
                return "standing.\(k) must be at most \(MAX_PROFILE_RULES) predicates"
            }
        }
        guard exactKeys(p["prior"], ["maps", "observations"]) else { return "prior must be {observations, maps}" }
        guard let obs = get(p["prior"], "observations")?.asArray, obs.count <= MAX_PROFILE_OBSERVATIONS else { return "prior.observations must be at most \(MAX_PROFILE_OBSERVATIONS)" }
        for o in obs {
            let yv: Double? = IV.num(get(o, "y"))
            let yOk = yv == 0.0 || yv == 1.0
            let atOk: Bool = IV.int(get(o, "at")).map { $0 >= 0 } ?? false
            if !exactKeys(o, ["at", "values", "verb", "y"]) || get(o, "verb")?.asString == nil || get(o, "values")?.asObject == nil || !yOk || !atOk {
                return "prior.observations entries are {verb, values, y, at}"
            }
        }
        guard let maps = get(p["prior"], "maps")?.asArray, maps.allSatisfy({ b32($0) }) else { return "prior.maps must be 32-byte digests" }
        _ = maps
        guard let exp = IV.int(p["expires_at"]), exp >= 0 else { return "expires_at must be a non-negative safe integer" }
        _ = exp
        guard let rev = p["revocation"]?.asObject else { return "revocation must be {epoch_uri, key?}" }
        for k in JS.keyOrder(rev) where k.s != "epoch_uri" && k.s != "key" { return "revocation must be {epoch_uri, key?}" }
        guard let eu = rev["epoch_uri"]?.asString, !eu.isEmpty else { return "revocation must be {epoch_uri, key?}" }
        if let k = rev["key"], !b32(k) { return "revocation.key (the revocation authority; absent = the owner) must be canonical base64url (32 bytes)" }
        if (version == 1) != (p["prev"] == nil) { return "prev is required exactly when version > 1" }
        if let pv = p["prev"], !b32(pv) { return "prev must be canonical base64url (32 bytes)" }
        if signed {
            if let a = p["alg"], a.asString == nil { return "alg must be a string" }
            let alg: String? = IV.sigAlg(p["alg"])
            guard let name = alg, PQ.resolve(name) != nil else { return "alg: unsupported_suite: '\(p["alg"].map { IntentV2.jsString($0) } ?? "undefined")'" }
            if IV.same(name, "ed25519") && (p["pq_pk"] != nil || p["pq_sig"] != nil) { return "an ed25519 profile must not carry pq_pk / pq_sig" }
            if p["sig"]?.asString == nil { return "sig must be a string" }
        }
        if let e = IV.strictCanonError(.object(profileBody(p))) { return "malformed profile: " + e }
        return nil
    }

    private static func profileBody(_ p: JObject) -> JObject {
        var b: JObject = [:]
        for k in BODY_KEYS { if let x = p[JKey(k)] { b[JKey(k)] = x } }
        return b
    }

    private static func message(_ body: JObject) -> [UInt8]? { IV.message(INTENT_PROFILE_SIG_DOMAIN, .object(body)) }

    /// Sign a profile version as its owner with the owner's Ed25519 seed (the owner identity must be the signer's key).
    public static func signIntentProfile(_ body: JSONValue, ownerSeed: [UInt8]) throws -> JSONValue {
        try signIntentProfile(body, key: PCASuiteKey.ed25519(try PCAEdKey(seed: ownerSeed)))
    }

    /// Sign under any registry suite (ML-DSA, hybrid, ...): `alg` and `pq_pk` are signed into the profile.
    public static func signIntentProfile(_ body: JSONValue, key: PCASuiteKey) throws -> JSONValue {
        guard let ed = key.ed else { throw JSError("signIntentProfile: signer needs an Ed25519 identity key") }
        let owner = ed.id
        guard var withOwner = body.asObject else { throw JSError("signIntentProfile: the profile body must be an object") }
        if let o = withOwner["owner"], !IV.same(o.asString, owner) { throw JSError("signIntentProfile: owner does not match the signing key") }
        withOwner["owner"] = .string(owner)
        let b: JObject = profileBody(withOwner)
        if let bad = intentProfileShapeError(.object(b), false) { throw JSError("signIntentProfile: \(bad)") }
        do {
            return .object(try PCAIssue.signArtifact(domain: INTENT_PROFILE_SIG_DOMAIN, body: .object(b), signer: key))
        } catch let e as PCAProducerError {
            throw JSError("signIntentProfile: \(e.message)")
        }
    }

    private static func result(_ reason: String?) -> JSONValue {
        var r: JObject = ["ok": .bool(reason == nil)]
        if let x = reason { r["reason"] = .string(x) }
        return .object(r)
    }

    /// `{ok: true}` or `{ok: false, reason}`; `pin` maps an identity to the PQ key the verifier pins for it. Never throws.
    public static func verifyIntentProfile(_ p: JSONValue?, _ pin: JSONValue? = nil) -> JSONValue {
        if let bad = intentProfileShapeError(p) { return result(bad) }
        guard let r = p?.asObject, let owner = r["owner"]?.asString else { return result("malformed profile: not an object") }
        guard let body = IV.bindSuite(profileBody(r), alg: r["alg"], pqPk: r["pq_pk"]) else { return result("malformed profile: missing pq_pk") }
        guard let msg = message(body) else { return result("malformed profile: canonicalize: value is outside the strict JSON profile") }
        let verdict = IV.verifyPinned(alg: r["alg"], identity: owner, artifactPqPk: r["pq_pk"], msg: msg, sig: r["sig"], pqSig: r["pq_sig"], pin: pin?.get(owner)?.asString)
        return verdict == .valid ? result(nil) : result("profile signature invalid")
    }

    /// The content address of a signed profile version.
    public static func intentProfileDigest(_ p: JSONValue?) -> String {
        Canonical.hashCanonical(.object(["d": .string(INTENT_PROFILE_REF_DOMAIN), "p": p ?? .null]))
    }

    /// Append-only succession: same id and owner, version + 1, `prev` = digest(previous).
    public static func verifyProfileSuccession(_ prev: JSONValue?, _ next: JSONValue?) -> JSONValue {
        let both: [JSONValue?] = [prev, next]
        let names = ["previous", "next"]
        for i in 0..<2 {
            let v = verifyIntentProfile(both[i])
            if v.get("ok") != .bool(true) { return result(names[i] + " version: " + (v.get("reason").map { IntentV2.jsString($0) } ?? "undefined")) }
        }
        if get(next, "profile_id") != get(prev, "profile_id") || get(next, "owner") != get(prev, "owner") { return result("a profile version cannot change its id or owner") }
        if !(dbl(get(next, "version")) == dbl(get(prev, "version")) + 1) { return result("versions are append-only: next.version must be previous + 1") }
        if get(next, "prev") != .string(intentProfileDigest(prev)) { return result("next.prev is not the digest of the previous version") }
        return result(nil)
    }

    private static func includes(_ list: JSONValue?, _ x: JSONValue?) -> Bool {
        guard let a = list?.asArray, let x = x else { return false }
        return a.contains { e in
            if e.isNull { return false }
            if let s = e.asString, let t = x.asString { return IV.same(s, t) }
            return e == x
        }
    }

    /// Is the profile in scope (and unexpired) for this use (`{aud, verb, now, semantics?}`)?
    public static func profileApplies(_ p: JSONValue, _ u: JSONValue) -> Bool {
        if !(dbl(u.get("now")).isFinite && dbl(p.get("expires_at")).isFinite && dbl(u.get("now")) < dbl(p.get("expires_at"))) { return false }
        let scope: JSONValue? = p.get("scope")
        if let sites = nn(get(scope, "sites")), !includes(sites, u.get("aud")) { return false }
        if let verbs = nn(get(scope, "verbs")), !includes(verbs, u.get("verb")) { return false }
        if let types = nn(get(scope, "semantic_types")) {
            var anyType = false
            if let sem = nn(u.get("semantics")) {
                guard let items = sem.asArray else { return false }
                for s in items where includes(types, s) { anyType = true }
            }
            if !anyType { return false }
        }
        return true
    }

    private static func anyRuleMatches(_ rules: JSONValue?, _ action: JSONValue) -> Bool {
        (rules?.asArray ?? []).contains { Predicates.predicateMatches($0, action, SafeRegex.Budget()) }
    }

    /// G^std membership: an in-scope action is OUTSIDE the standing layer iff a deny rule matches it (deny wins).
    public static func standingAdmits(_ p: JSONValue, _ u: JSONValue, _ action: JSONValue) -> Bool {
        if !profileApplies(p, u) { return true }
        return !anyRuleMatches(get(p.get("standing"), "deny"), action)
    }

    /// The explicit standing-permission layer: true iff an in-scope permit rule matches.
    public static func standingPermits(_ p: JSONValue, _ u: JSONValue, _ action: JSONValue) -> Bool {
        profileApplies(p, u) && anyRuleMatches(get(p.get("standing"), "permit"), action)
    }

    /// The cells that the profile's negative observations veto: `[{verb, cell}]`, de-duplicated in order.
    public static func profileVetoCells(_ p: JSONValue, _ omega: WalletOmega) -> [JSONValue] {
        var out: [JSONValue] = []
        var seen = Set<JKey>()
        for o in get(p.get("prior"), "observations")?.asArray ?? [] {
            if dbl(get(o, "y")) != 0.0 { continue }
            guard let verb = get(o, "verb")?.asString, let vs = omega.verb(verb), let cell = WalletOmegaMath.cellOf(vs, values: get(o, "values")) else { continue }
            if seen.insert(JKey(verb + "|" + cell.map { String($0) }.joined(separator: ","))).inserted {
                out.append(.object(["verb": .string(verb), "cell": .array(cell.map { JSONValue.int(Int64($0)) })]))
            }
        }
        return out
    }

    /// A ceiling function (for a visit decision) from the profile's standing deny rules over outcomes.
    public static func profileCeiling(_ p: JSONValue, _ u: JSONValue) -> (WalletVerb, JSONValue) -> Bool {
        return { vs, o in
            let a: JObject = PCAIntentRuntime.outcomeToAction(vs, o)
            var action: JObject = [:]
            for k in ["verb", "resource", "params"] { action[JKey(k)] = a[JKey(k)] ?? .null }
            var ctx: JObject = ["action": .object(action)]
            if let env = a["env"] { ctx["env"] = env }
            if let subject = a["subject"] { ctx["subject"] = subject }
            var use: JObject = u.asObject ?? [:]
            use["verb"] = o.get("verb") ?? .null
            return standingAdmits(p, .object(use), .object(ctx))
        }
    }

    /// Is this profile version usable now: signed, unexpired and not revoked per a fresh epoch of its revocation authority?
    /// `c` members: now, maxAgeMs, revocation?, last?, pin?.
    public static func profileUsable(_ p: JSONValue, _ c: JSONValue) -> JSONValue {
        let pin: JSONValue? = c.get("pin")?.asObject != nil ? c.get("pin") : nil
        let v = verifyIntentProfile(p, pin)
        if v.get("ok") != .bool(true) { return v }
        if !(dbl(c.get("now")).isFinite && dbl(p.get("expires_at")).isFinite && dbl(c.get("now")) < dbl(p.get("expires_at"))) { return result("the profile has expired") }
        guard let id = p.get("profile_id")?.asString, let version = IV.int(p.get("version")) else { return result("malformed profile: profile_id / version") }
        let authority: String? = nn(get(p.get("revocation"), "key"))?.asString ?? p.get("owner")?.asString
        guard let auth = authority else { return result("malformed profile: no revocation authority") }
        var pins: [String: String] = [:]
        for (k, x) in pin?.asObject ?? [:] { if let s = x.asString { pins[k.s] = s } }
        let r = IntentRevocation.check(c.get("revocation"), session: id, authority: auth, ids: [IntentRevocation.profileId(id, version)], now: dbl(c.get("now")),
                                       maxAgeMs: dbl(c.get("maxAgeMs")), scope: "pca-intent-profile:" + id, pqPins: pins, last: nn(c.get("last")))
        return r.0 ? result(nil) : result("profile revocation: \(r.1)")
    }
}
