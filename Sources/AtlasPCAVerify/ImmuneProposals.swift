import Foundation

/// The adapt side of the immune system: a tightening proposal signed by a guardian key and verified before it is applied, and a durable store of
/// the immune state and the applied epoch over an `AtomicKV`, so a restart keeps the history and the replay floor. A proposal can only tighten
/// (`noWidenViolation`), is bound to the base policy and (optionally) to the state it was derived from, and each epoch applies at most once.
extension PCAImmune {
    public static let TIGHTENING_DOMAIN = "atlas-pca/immune-tightening/v1\u{0}"

    // MARK: state as JSON

    /// The immune state of `{baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}`; nil when any member is missing or of the wrong type.
    public static func state(json v: JSONValue?) -> State? {
        guard case let .object(o)? = v, case let .object(b)? = o["baseline"], let n = IV.num(b["n"]), let mean = IV.num(b["mean"]), let m2 = IV.num(b["m2"]),
              let ewma = IV.num(o["ewma"]), let stepUps = IV.num(o["stepUps"]), let denies = IV.num(o["denies"]), let lastAt = IV.num(o["lastAt"]),
              case let .bool(seeded)? = o["seeded"] else { return nil }
        var s = State()
        s.baseline = Baseline(n: n, mean: mean, m2: m2)
        s.ewma = ewma
        s.stepUps = stepUps
        s.denies = denies
        s.lastAt = lastAt
        s.seeded = seeded
        return s
    }

    public static func json(of s: State) -> JSONValue {
        .object(["baseline": .object(["n": PCAFacade.jsNum(s.baseline.n), "mean": PCAFacade.jsNum(s.baseline.mean), "m2": PCAFacade.jsNum(s.baseline.m2)]),
                 "ewma": PCAFacade.jsNum(s.ewma), "stepUps": PCAFacade.jsNum(s.stepUps), "denies": PCAFacade.jsNum(s.denies),
                 "lastAt": PCAFacade.jsNum(s.lastAt), "seeded": .bool(s.seeded)])
    }

    // MARK: digests

    static func digest(_ v: JSONValue) -> String { Base64URLStrict.encode(Canonical.sha256(Array(v.canonicalText.utf8))) }

    public static func policyDigest(_ policy: JSONValue) -> String { digest(policy) }

    public static func immuneStateDigest(_ state: JSONValue) -> String { digest(state) }

    // MARK: signed tightening proposals

    static func tighteningMessage(_ claim: JObject) -> [UInt8] { Array(TIGHTENING_DOMAIN.utf8) + Array(JSONValue.object(claim).canonicalText.utf8) }

    /// `Number.isSafeInteger(v)`: a number, integral, within +-(2^53 - 1) (a -0 is one; the callers that refuse it say so).
    static func isSafeInteger(_ v: JSONValue?) -> Bool { IV.num(v).map { $0.isFinite && $0.rounded() == $0 && abs($0) <= Double(Canonical.MAX_SAFE) } ?? false }

    /// `validateImmuneState` over any value: why it is malformed, nil when it is well formed. An array is an object with no named members.
    public static func validate(json v: JSONValue?) -> String? {
        switch v {
        case .object?, .array?: break
        default: return "state must be an object"
        }
        let o = v?.asObject ?? [:]
        guard let bv = o["baseline"], JS.truthy(bv), bv.isObject || bv.asArray != nil else { return "baseline missing" }
        let b = bv.asObject ?? [:]
        func inRange(_ x: JSONValue?, _ lo: Double, _ hi: Double) -> Bool { IV.num(x).map { $0.isFinite && $0 >= lo && $0 <= hi } ?? false }
        if !inRange(b["n"], 0, MAX_COUNT) || !isSafeInteger(b["n"]) || (IV.num(b["n"])! == 0 && IV.num(b["n"])!.sign == .minus) { return "baseline.n must be an integer in [0, 1e9]" }
        if !inRange(b["mean"], 0, 1) { return "baseline.mean must be in [0, 1]" }
        if !inRange(b["m2"], 0, MAX_COUNT) { return "baseline.m2 must be finite and >= 0" }
        if !inRange(o["ewma"], 0, 1) { return "ewma must be in [0, 1]" }
        if !inRange(o["stepUps"], 0, MAX_COUNT) { return "stepUps must be finite and >= 0" }
        if !inRange(o["denies"], 0, MAX_COUNT) { return "denies must be finite and >= 0" }
        if !inRange(o["lastAt"], 0, Double(Canonical.MAX_SAFE)) { return "lastAt must be a finite non-negative time" }
        guard case .bool? = o["seeded"] else { return "seeded must be a boolean" }
        return nil
    }

    /// `assess` over any value: a malformed state reads as the worst case (high, every component 1), never as calm.
    public static func assess(json v: JSONValue?) -> Assessment {
        let bad = validate(json: v)
        if bad == nil, let s = state(json: v) { return assess(s) }
        return Assessment(level: "high", score: 1, signals: ["invalid immune state: \(bad ?? "state must be an object")"], drift: 1, volatility: 1, violation: 1)
    }

    /// Derive and sign the tightening for `state`. Throws on a malformed base or state, an epoch that is not an integer >= 1 or a non-finite `now`
    /// (never an unsigned loosening). `guardian` is the guardian's Ed25519 key.
    public static func issueTighteningProposal(base: JSONValue, state: JSONValue, epoch: JSONValue, now: JSONValue, guardian: PCAEdKey) throws -> JSONValue {
        if let bad = PCA.validateRiskPolicy(base) { throw JSError("issueTighteningProposal: \(bad)") }
        guard isSafeInteger(epoch), let e = IV.num(epoch), e >= 1 else { throw JSError("issueTighteningProposal: epoch must be an integer >= 1") }
        guard let n = IV.num(now), n.isFinite else { throw JSError("issueTighteningProposal: now must be finite") }
        guard case let .object(baseObj) = base else { throw JSError("issueTighteningProposal: malformed base") }
        let ad = adapt(baseObj, assess(json: state))
        let claim: JObject = ["v": .int(1), "base_digest": .string(policyDigest(base)), "state_digest": .string(immuneStateDigest(state)), "epoch": epoch, "issued_at": now,
                              "policy": .object(ad.policy), "rationale": .string(ad.rationale), "guardian": .string(guardian.id)]
        var p = claim
        p["sig"] = .string(Base64URLStrict.encode(try guardian.sign(tighteningMessage(claim))))
        return .object(p)
    }

    private static func refused(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    /// Verify a proposal: `{ok: true, policy, epoch}` or `{ok: false, reason}`; never throws. `o` holds the pinned `guardian` (base64url, required),
    /// `lastEpoch`, `now`, `maxAgeMs` and optionally `state` (a recompute check).
    public static func applyTightening(base: JSONValue, proposal p: JSONValue?, options o: JSONValue?) -> JSONValue {
        guard case let .object(po)? = p, IV.num(po["v"]) == 1, case let .string(sig)? = po["sig"], case let .string(guardian)? = po["guardian"] else { return refused("malformed") }
        guard case let .string(pinned)? = o?.get("guardian"), pinned == guardian else { return refused("guardian") }
        var claim = po
        claim["sig"] = nil
        guard Ed25519Strict.verifyB64u(guardian, tighteningMessage(claim), sig) else { return refused("signature") }
        guard case let .object(baseObj) = base, case let .object(pol)? = po["policy"],
              PCA.validateRiskPolicy(base) == nil, PCA.validateRiskPolicy(po["policy"]) == nil else { return refused("invalid-policy") }
        guard po["base_digest"] == .string(policyDigest(base)) else { return refused("base") }
        let now = IV.num(o?.get("now")) ?? .nan, at = IV.num(po["issued_at"]) ?? .nan
        // `o.now - p.issued_at <= o.maxAgeMs` compares as JS does (an absent or non-numeric maxAgeMs is NaN or a coerced number)
        if !now.isFinite || !at.isFinite || at > now || !JSLoose.le(.double(now - at), o?.get("maxAgeMs")) { return refused("stale") }
        let epoch = po["epoch"]
        // `Number.isSafeInteger(p.epoch) && !Object.is(p.epoch, -0) && p.epoch > o.lastEpoch` (the floor coerces: null is 0, "1" is 1, absent never admits)
        guard isSafeInteger(epoch), !(IV.num(epoch) == 0 && IV.num(epoch)!.sign == .minus), JSLoose.gt(epoch, o?.get("lastEpoch")) else { return refused("replayed-epoch") }
        if noWidenViolation(baseObj, pol) != nil { return refused("widens") }
        if let st = o?.get("state"), JS.truthy(st) {
            if po["state_digest"] != .string(immuneStateDigest(st)) || policyDigest(.object(adapt(baseObj, assess(json: st)).policy)) != policyDigest(.object(pol)) { return refused("state-mismatch") }
        }
        return .object(["ok": .bool(true), "policy": .object(pol), "epoch": epoch ?? .null])
    }

    // MARK: durable store

    /// The immune state and the applied epoch of one subject over an atomic key/value store.
    public final class ImmuneStore: @unchecked Sendable {
        private let kv: AtomicKV
        private let stateKey: String, epochKey: String

        public init(kv: AtomicKV, subject: String) {
            self.kv = kv
            stateKey = "immune/state/" + subject
            epochKey = "immune/epoch/" + subject
        }

        /// The stored state, or the initial one.
        public func get() throws -> JSONValue { try kv.get(stateKey) ?? PCAImmune.json(of: PCAImmune.INITIAL_STATE) }

        /// Folds one observation `{r, at, stepUp?, denied?}` atomically; throws when the stored state is malformed (it is never silently reset to calm).
        @discardableResult public func observe(_ obs: JSONValue) throws -> JSONValue {
            var out: JSONValue?
            var failure: String?
            try kv.update(stateKey) { prev in
                let cur = prev ?? PCAImmune.json(of: PCAImmune.INITIAL_STATE)
                guard let s = PCAImmune.state(json: cur) else { failure = "malformed"; return nil }
                if let bad = PCAImmune.validate(s) { failure = bad; return nil }
                let next = PCAImmune.json(of: PCAImmune.observe(s, r: IV.num(obs.get("r")) ?? .nan, at: IV.num(obs.get("at")) ?? .nan,
                                                               stepUp: JS.truthy(obs.get("stepUp")), denied: JS.truthy(obs.get("denied"))))
                out = next
                return next
            }
            if let f = failure { throw JSError("immune store: stored state invalid (\(f))") }
            return out ?? .null
        }

        public func lastEpoch() throws -> Int64 {
            guard let stored = try kv.get(epochKey), let v = IV.num(stored) else { return 0 }
            // stored data is untrusted: an epoch that is not a safe integer is invalid state (refused), never converted (an out-of-range conversion traps)
            guard PCAImmune.isSafeInteger(stored) else { throw JSError("immune store: stored epoch invalid") }
            return Int64(v)
        }

        /// Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. `o` is as for
        /// `applyTightening` without `lastEpoch`.
        public func apply(base: JSONValue, proposal p: JSONValue?, options o: JSONValue?) throws -> JSONValue {
            var out = PCAImmune.refused("malformed")
            try kv.update(epochKey) { prev in
                var oo = o?.asObject ?? [:]
                // a stored floor that is not a safe integer is invalid state: it admits no epoch
                oo["lastEpoch"] = IV.num(prev).map { PCAImmune.isSafeInteger(prev) ? PCAFacade.jsNum($0) : JSONValue.double(Double.greatestFiniteMagnitude) } ?? .int(0)
                out = PCAImmune.applyTightening(base: base, proposal: p, options: .object(oo))
                return out.get("ok") == .bool(true) ? out.get("epoch") : nil
            }
            return out
        }
    }
}
