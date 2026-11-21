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

    static func isInteger(_ v: JSONValue?) -> Bool { IV.num(v).map { $0.isFinite && $0.rounded() == $0 } ?? false }

    /// Derive and sign the tightening for `state`. Throws on a malformed base or state, an epoch that is not an integer >= 1 or a non-finite `now`
    /// (never an unsigned loosening). `guardian` is the guardian's Ed25519 key.
    public static func issueTighteningProposal(base: JSONValue, state: JSONValue, epoch: JSONValue, now: JSONValue, guardian: PCAEdKey) throws -> JSONValue {
        if let bad = PCA.validateRiskPolicy(base) { throw JSError("issueTighteningProposal: \(bad)") }
        guard isInteger(epoch), let e = IV.num(epoch), e >= 1 else { throw JSError("issueTighteningProposal: epoch must be an integer >= 1") }
        guard let n = IV.num(now), n.isFinite else { throw JSError("issueTighteningProposal: now must be finite") }
        guard let st = Self.state(json: state), case let .object(baseObj) = base else { throw JSError("issueTighteningProposal: malformed state") }
        let ad = adapt(baseObj, assess(st))
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
        let now = IV.num(o?.get("now")) ?? .nan, at = IV.num(po["issued_at"]) ?? .nan, maxAge = IV.num(o?.get("maxAgeMs")) ?? .nan
        if !now.isFinite || !at.isFinite || at > now || !(now - at <= maxAge) { return refused("stale") }
        let epoch = po["epoch"]
        guard isInteger(epoch), let e = IV.num(epoch), e > (IV.num(o?.get("lastEpoch")) ?? .nan) else { return refused("replayed-epoch") }
        if noWidenViolation(baseObj, pol) != nil { return refused("widens") }
        if let st = o?.get("state"), JS.truthy(st) {
            guard let s = Self.state(json: st) else { return refused("malformed") }
            if po["state_digest"] != .string(immuneStateDigest(st)) || policyDigest(.object(adapt(baseObj, assess(s)).policy)) != policyDigest(.object(pol)) { return refused("state-mismatch") }
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
            guard let v = IV.num(try kv.get(epochKey)), v.isFinite else { return 0 }
            return Int64(v)
        }

        /// Verify and apply a proposal; the epoch floor advances atomically, so two racing applies of one epoch cannot both win. `o` is as for
        /// `applyTightening` without `lastEpoch`.
        public func apply(base: JSONValue, proposal p: JSONValue?, options o: JSONValue?) throws -> JSONValue {
            var out = PCAImmune.refused("malformed")
            try kv.update(epochKey) { prev in
                var oo = o?.asObject ?? [:]
                oo["lastEpoch"] = IV.num(prev).map { PCAFacade.jsNum($0) } ?? .int(0)
                out = PCAImmune.applyTightening(base: base, proposal: p, options: .object(oo))
                return out.get("ok") == .bool(true) ? out.get("epoch") : nil
            }
            return out
        }
    }
}
