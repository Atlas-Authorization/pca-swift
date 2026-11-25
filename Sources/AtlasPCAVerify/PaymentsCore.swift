import Foundation

/// The charge decision on the built-in policy engine, and the bonded claim over a charge PCActn.
extension PCAPayments {
    /// `authorizeCharge` with the NATIVE policy engine as the decider (no injected `decide`).
    public static func authorizeChargeCore(_ mandate: JSONValue, _ charge: JSONValue, _ verifiedGrant: JSONValue) throws -> JSONValue {
        try authorizeCharge(mandate, charge, verifiedGrant, decide: { try PCAPolicyVm.decide($0) })
    }

    /// Opens a challenge-windowed bonded claim for a charge's PCActn: if the charge is later disputed, a fraud proof slashes the bond and
    /// the charge is rolled back. A thin wrapper over `Optimistic.open`; REFUSES (throws) an irreversible charge.
    public static func openChargeBond(_ pcactn: JSONValue, _ opts: Optimistic.OpenOptions, signer: PCAEdKey) throws -> JSONValue {
        try Optimistic.open(pcactn, opts, signer: signer)
    }
}

extension Optimistic {
    /// The library default challenge window when a claim names none (5 minutes).
    public static let DEFAULT_WINDOW_MS: Double = 300_000

    /// Options of `open`; nil members take the defaults (window policy default, server time = now, issued_at = server time).
    public struct OpenOptions {
        public var bondRef: String
        public var claimedR: Double
        public var challengeWindowMs: Double?
        public var issuedAt: Double?
        public var serverNow: Double?
        public var windowPolicy: ChallengeWindowPolicy?
        public init(bondRef: String, claimedR: Double, challengeWindowMs: Double? = nil, issuedAt: Double? = nil, serverNow: Double? = nil,
                    windowPolicy: ChallengeWindowPolicy? = nil) {
            self.bondRef = bondRef
            self.claimedR = claimedR
            self.challengeWindowMs = challengeWindowMs
            self.issuedAt = issuedAt
            self.serverNow = serverNow
            self.windowPolicy = windowPolicy
        }
    }

    /// The reason a window is outside the policy, or nil.
    public static func validateWindow(issuedAt: Double, windowMs: Double, serverNow: Double, policy p: ChallengeWindowPolicy) -> String? {
        if !serverNow.isFinite { return "server time is not finite" }
        if !issuedAt.isFinite || !windowMs.isFinite { return "malformed challenge window" }
        if !(abs(issuedAt - serverNow) <= p.maxSkewMs) { return "issued_at is outside the allowed skew of server time" }
        if !(windowMs >= p.minWindowMs) { return "challenge window is below the minimum" }
        if !(windowMs <= p.maxWindowMs) { return "challenge window exceeds the maximum" }
        return nil
    }

    /// Opens a bonded optimistic claim for `pcactn`, signed by the agent-leaf key. REFUSES (throws) an irreversible action, a non-finite
    /// `claimedR` and a window outside the policy.
    public static func open(_ pcactn: JSONValue, _ o: OpenOptions, signer: PCAEdKey) throws -> JSONValue {
        let rc = pcactn.get("action")?.get("reversibility_class")
        if rc?.asString == IRREVERSIBLE { throw JSError("openOptimistic: irreversible actions cannot use the optimistic fast-path (\u{a7}9A)") }
        guard o.claimedR.isFinite else { throw JSError("openOptimistic: claimedR must be finite") }
        let policy = o.windowPolicy ?? .default
        let serverNow = o.serverNow.flatMap { $0.isFinite ? $0 : nil } ?? (Date().timeIntervalSince1970 * 1000).rounded(.down)
        let issuedAt = o.issuedAt.flatMap { $0.isFinite ? $0 : nil } ?? serverNow
        let windowMs = o.challengeWindowMs ?? DEFAULT_WINDOW_MS
        if let bad = validateWindow(issuedAt: issuedAt, windowMs: windowMs, serverNow: serverNow, policy: policy) { throw JSError("openOptimistic: " + bad) }
        let body: JObject = ["pcactn_digest": .string(Canonical.hashCanonical(pcactn)), "bond_ref": .string(o.bondRef), "claimed_r": PayJS.num(o.claimedR),
                             "reversibility_class": .string(rc?.asString ?? "unknown"), "issued_at": PayJS.num(issuedAt), "challenge_window_ms": PayJS.num(windowMs)]
        let msg = Canonical.utf8(CLAIM_DOMAIN) + Canonical.utf8(Canonical.canonicalize(.object(body)))
        var claim = body
        let sig: [UInt8]
        do { sig = try signer.sign(msg) } catch let e as PCAProducerError { throw JSError(e.description) }
        claim["sig"] = .string(Base64URLStrict.encode(sig))
        return .object(claim)
    }
}
