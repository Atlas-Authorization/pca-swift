import Foundation

// The small public helpers of core pca that a resource server calls around the verifier: the cheap pre-authentication checks (claims window, chain
// shape), the PQ key of a holder, share assembly, the decision meet over a list.
extension PCA {
    /// The `kind` of a canonical approval render.
    public static let APPROVAL_RENDER_KIND = Approval.RENDER_KIND

    /// The default PCActn lifetime (20 minutes) a minted action carries when the caller names none.
    public static let PCACTN_DEFAULT_TTL_MS: Int64 = 20 * 60_000
    /// The longest lifetime (`exp - iat`) the verifier accepts.
    public static let PCACTN_MAX_LIFETIME_MS: Int64 = MAX_LIFETIME_MS

    private static func cheap(_ check: String, _ reason: String) -> JSONValue { .object(["check": .string(check), "reason": .string(reason)]) }

    /// The PCActn's `aud`, `iat` and `exp`, checked BEFORE any signature work or metering. These fields are unauthenticated at this point, so a pass
    /// proves nothing; a FAIL is final (the full verifier makes the same two decisions on the same fields), so a server refuses without touching a shared
    /// rate-limit bucket or doing any crypto. O(1). nil when both checks pass, else `{check: audience|validity, reason}`.
    public static func pcactnCheapClaims(_ p: JSONValue?, audience: String, now: Double) -> JSONValue? {
        guard let aud = p?.get("aud")?.asString, !aud.isEmpty, IV.same(aud, audience) else { return cheap("audience", "aud does not match this resource server / instance") }
        guard let iat = p?.get("iat")?.safeInt, let exp = p?.get("exp")?.safeInt else { return cheap("validity", "iat and exp must be safe-integer epoch ms") }
        guard now.isFinite, now.rounded() == now, abs(now) <= 9_007_199_254_740_991 else { return cheap("validity", "the verifier clock is not a safe integer epoch-ms") }
        if !(exp > iat) { return cheap("validity", "exp must be greater than iat") }
        if exp - iat > MAX_LIFETIME_MS { return cheap("validity", "lifetime exceeds \(MAX_LIFETIME_MS) ms") }
        if Double(iat) > now + Double(MAX_SKEW_MS) { return cheap("validity", "iat is in the future (clock skew)") }
        if now > Double(exp) { return cheap("validity", "the PCActn has expired") }
        return nil
    }

    /// What `verifyChainCheap` reports: `ok` with `pqHops`, or a `reason`.
    public struct CheapChain: Equatable, Sendable {
        public let ok: Bool
        /// The hops that still need post-quantum verification.
        public let pqHops: Int
        public let reason: String?
    }

    private static func cheapNo(_ r: String) -> CheapChain { CheapChain(ok: false, pqHops: 0, reason: r) }

    /// The CHEAP chain check for a gate that runs BEFORE authentication: only work that is cheap and a NECESSARY condition of the full chain verifier
    /// (shape, caveat caps, depth, suite allowlist, body digest, parent links, issuer == parent holder, the root-issuer check, and the Ed25519 half of
    /// every hop that has one). No post-quantum verification and no PQ key resolution; a pure-PQ hop passes on structure alone. `ok` is NEVER an
    /// authentication: run the full verifier (after matching the root to a stored grant) before treating the chain as authentic.
    public static func verifyChainCheap(_ chain: [JSONValue], expectedRootIssuer: String? = nil, allowedSuites: [String]? = nil) -> CheapChain {
        if chain.isEmpty { return cheapNo("empty chain") }
        if chain.count > Capability.MAX_CHAIN_DEPTH { return cheapNo("chain too long (max \(Capability.MAX_CHAIN_DEPTH) hops)") }
        if Capability.caveatLimitExceeded(chain) { return cheapNo(Capability.CAVEAT_LIMIT_REASON) }
        var pqHops = 0
        for (i, hop) in chain.enumerated() {
            let label = "hop \(i)"
            if !Capability.wellTyped(hop) { return cheapNo("\(label): malformed capability") }
            guard let c = hop.asObject else { return cheapNo("\(label): malformed capability") }
            let alg = c["alg"]?.asString ?? "ed25519"
            guard PCASuites.registered.contains(alg), let suite = PQ.suites[alg] else { return cheapNo("\(label): unknown signature alg '\(alg)'") }
            if let e = Capability.suitePolicyError(c["alg"]?.asString, label, allowedSuites) { return cheapNo(e) }
            let parent = i == 0 ? nil : chain[i - 1].asObject
            if i == 0 {
                if c["parent"] != nil { return cheapNo("hop 0: root must not have a parent") }
                if let exp = expectedRootIssuer, c["issuer"]?.asString != exp { return cheapNo("hop 0: root issuer is not the expected principal") }
            } else {
                guard let parent = parent else { return cheapNo("\(label): malformed capability") }
                if c["parent"]?.asString != Capability.capHash(chain[i - 1]) { return cheapNo("\(label): broken parent link") }
                if c["issuer"] != parent["holder"] { return cheapNo("\(label): issuer is not the parent's bound holder") }
            }
            var body: JObject = ["issuer": c["issuer"] ?? .null, "holder": c["holder"] ?? .null, "caveats": c["caveats"] ?? .null, "parent": c["parent"] ?? .null]
            if let hp = c["holder_pq"], hp.asString != nil { body["holder_pq"] = hp }
            if suite.alg != .ed25519 {
                body["alg"] = .string(alg)
                if suite.needsPqPk, let pk = c["pq_pk"], pk.asString != nil { body["pq_pk"] = pk }
            }
            guard let digest = IV.strictHash(.object(body)) else { return cheapNo("\(label): malformed body") }
            if c["body_digest"]?.asString != digest || c["id"]?.asString != digest { return cheapNo("\(label): body digest mismatch") }
            if alg == "ed25519" || alg.hasPrefix("hybrid-") {
                let signer = i == 0 ? (c["issuer"]?.asString ?? "") : (parent?["holder"]?.asString ?? "")
                guard let raw = Base64URLStrict.decode(digest, length: 32), Ed25519Strict.verifyB64u(signer, Capability.CAP_DOMAIN + raw, c["sig"]?.asString ?? "") else {
                    return cheapNo("\(label): bad signature (not signed by expected key)")
                }
            }
            if suite.needsPqPk { pqHops += 1 }
        }
        return CheapChain(ok: true, pqHops: pqHops, reason: nil)
    }

    /// The PQ verification key (b64u) for a signature by `holder` (a chain leaf or threshold share) under suite `alg`: minted from the holder's
    /// `holder_pq` commitment. nil for ed25519, an unknown suite, and when the artifact's `pq_pk` is not the committed key (the signature check then
    /// fails closed). Natives never accept an unbound PQ key.
    public static func holderPqKey(alg: JSONValue?, holder: String, artifactPqPk: String?, holderPq: String?) -> String? {
        if let a = alg, !(a.asString.map { PCASuites.registered.contains($0) } ?? false) { return nil }
        guard let name = alg?.asString, name != "ed25519" else { return nil }
        return PQ.resolvePqKey(identity: holder, artifactPk: artifactPqPk, holderPq: holderPq)?.key
    }

    /// Collect shares into a threshold signature `{shares}` (a defensive copy; anything but a list is no shares).
    public static func assembleThreshold(_ shares: JSONValue?) -> JSONValue { .object(["shares": .array(shares?.asArray ?? [])]) }

    /// The meet over a list of decisions (`allow` for the empty list, the neutral element).
    public static func meetAll(_ ds: [String]) -> String { ds.reduce("allow") { meet($0, $1) } }

    /// A `budget_alloc` caveat with a finite limit >= 0.
    public static func isBudgetAllocCaveat(_ cv: JSONValue?) -> Bool {
        guard let c = cv?.asObject, c[JKey("type")]?.asString == "budget_alloc", let l = IV.num(c[JKey("limit")]), l.isFinite, l >= 0 else { return false }
        return true
    }
}
