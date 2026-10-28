import Foundation
import CryptoKit

// Revocation staleness (T9): a verifier-side cap on how old the revocation state may be, per reversibility class, the
// guardian-signed revocation epoch (Ed25519 and every suite this build verifies, under the pin rules of the ledger verifiers),
// and the gate that combines them. Mirrors the reference revocation module (`checkRevocationAge`, `revocationMaxAgeMs`,
// `effectiveReversibility`, `checkRevocationEpoch` and the staleness branch of `createRevocationChecker`). Inputs are parsed JSON
// values: nothing here traps on a hostile epoch.

/// The per-class maximum ages (ms); nil keeps the default. Each is capped by `maxRevocationAgeMs`.
public struct StalenessWindows: Equatable, Sendable {
    public var irreversible: Double?
    public var costly: Double?
    public init(irreversible: Double? = nil, costly: Double? = nil) {
        self.irreversible = irreversible
        self.costly = costly
    }
}

/// The verifier-side staleness policy. ON when `maxRevocationAgeMs` or `staleness` is set (`isOn`); the empty policy changes
/// nothing. The class is the stricter of the server's authoritative class and the PCActn's signed class; a missing or unknown
/// class counts as irreversible.
public struct RevocationStalenessPolicy: Equatable, Sendable {
    /// Maximum age for any action (nil: `PCA.REVOCATION_EPOCH_VALIDITY_MS`).
    public var maxRevocationAgeMs: Double?
    /// Per-class windows (irreversible default 2 min; costly and rate_limited default `maxRevocationAgeMs`).
    public var staleness: StalenessWindows?
    /// Accept revocation state that is not guardian-signed for an irreversible action.
    public var allowUnsignedRootForIrreversible: Bool

    public init(maxRevocationAgeMs: Double? = nil, staleness: StalenessWindows? = nil, allowUnsignedRootForIrreversible: Bool = false) {
        self.maxRevocationAgeMs = maxRevocationAgeMs
        self.staleness = staleness
        self.allowUnsignedRootForIrreversible = allowUnsignedRootForIrreversible
    }

    /// True when the policy turns the staleness check on.
    public var isOn: Bool { maxRevocationAgeMs != nil || staleness != nil }

    /// Every window that is set must be a finite positive number of milliseconds (a configuration error): nil when valid.
    public func validate() -> String? {
        func bad(_ name: String, _ v: Double?) -> String? {
            guard let x = v else { return nil }
            return (x.isFinite && x > 0) ? nil : "\(name) must be a positive number of milliseconds"
        }
        return bad("maxRevocationAgeMs", maxRevocationAgeMs) ?? bad("staleness.irreversible", staleness?.irreversible)
            ?? bad("staleness.costly", staleness?.costly)
    }

    /// Reads `{maxRevocationAgeMs?, staleness?: {irreversible?, costly?}, allowUnsignedRootForIrreversible?}` from parsed JSON. A
    /// set value that is not a number becomes NaN (`validate` refuses it). nil when `v` is not an object.
    public static func fromJSON(_ v: JSONValue?) -> RevocationStalenessPolicy? {
        guard let o = v?.asObject else { return nil }
        func num(_ m: JObject, _ k: String) -> Double? {
            guard let x = m[JKey(k)] else { return nil }
            return IV.num(x) ?? .nan
        }
        var p = RevocationStalenessPolicy(maxRevocationAgeMs: num(o, "maxRevocationAgeMs"))
        if case .bool(true)? = o["allowUnsignedRootForIrreversible"] { p.allowUnsignedRootForIrreversible = true }
        if let s = o["staleness"] {
            let sm = s.asObject ?? [:]
            p.staleness = StalenessWindows(irreversible: num(sm, "irreversible"), costly: num(sm, "rate_limited") ?? num(sm, "costly"))
        }
        return p
    }
}

/// The answer of `PCA.checkRevocationAge`, `PCA.checkRevocationEpoch` and `PCA.revocationGate`.
public struct RevocationAgeResult: Equatable, Sendable {
    public let ok: Bool
    public let reason: String?
    static let pass = RevocationAgeResult(ok: true, reason: nil)
    static func fail(_ r: String) -> RevocationAgeResult { RevocationAgeResult(ok: false, reason: r) }
}

/// What a guardian signs (`PCA.signRevocationEpoch`).
public struct RevocationEpochBody: Sendable {
    public var instanceId: String
    public var grantRef: String
    public var epoch: Int64
    public var setSize: Int64
    public var root: String
    public var issuedAt: Int64
    public var notAfter: Int64
    public init(instanceId: String, grantRef: String, epoch: Int64 = 0, setSize: Int64 = 0, root: String, issuedAt: Int64, notAfter: Int64) {
        self.instanceId = instanceId
        self.grantRef = grantRef
        self.epoch = epoch
        self.setSize = setSize
        self.root = root
        self.issuedAt = issuedAt
        self.notAfter = notAfter
    }
}

/// The revocation state an `authorize` call holds for a grant: a guardian-signed `epoch` (parsed JSON), or a bare `root` with the
/// time `rootIssuedAt` it was issued. Both nil: no verifiable state.
public struct RevocationState {
    public var epoch: JSONValue?
    public var root: String?
    public var rootIssuedAt: Double?
    public var lastAcceptedEpoch: Double?
    public init(epoch: JSONValue? = nil, root: String? = nil, rootIssuedAt: Double? = nil, lastAcceptedEpoch: Double? = nil) {
        self.epoch = epoch
        self.root = root
        self.rootIssuedAt = rootIssuedAt
        self.lastAcceptedEpoch = lastAcceptedEpoch
    }
}

/// `checkRevocationEpoch` options.
public struct EpochCheckOptions {
    /// The pinned Ed25519 identity (b64u) of the guardian.
    public var guardianPublic: String
    /// Pins the post-quantum key of a PQ or hybrid guardian: `{Ed25519 b64u: ML-DSA public key b64u}`. Without a pin such an epoch is refused.
    public var pins: [String: String]?
    /// The epoch-ms clock (required: no implicit clock).
    public var now: Double
    /// When set, must equal the epoch's `grant_ref`.
    public var grantRef: String?
    /// The newest epoch number already accepted for the grant; an older one is a rollback.
    public var lastAcceptedEpoch: Double?
    /// The PCActn's signed `freshness.epoch`; must be >= the epoch (no pre-revocation action).
    public var pcactnEpoch: Double?
    /// Verifier-side maximum age (`now - issued_at`); nil: only the signed `not_after` bounds it.
    public var maxAgeMs: Double?
    public init(guardianPublic: String, now: Double, pins: [String: String]? = nil, grantRef: String? = nil, lastAcceptedEpoch: Double? = nil,
                pcactnEpoch: Double? = nil, maxAgeMs: Double? = nil) {
        self.guardianPublic = guardianPublic
        self.now = now
        self.pins = pins
        self.grantRef = grantRef
        self.lastAcceptedEpoch = lastAcceptedEpoch
        self.pcactnEpoch = pcactnEpoch
        self.maxAgeMs = maxAgeMs
    }
}

/// One decision of the staleness gate (`PCA.revocationGate`).
public struct RevocationGateInput {
    public var policy: RevocationStalenessPolicy
    /// The epoch guardian (Ed25519 identity and optional PQ pins).
    public var guardianPublic: String?
    public var pins: [String: String]?
    /// From the PCActn: `grant_ref` and `freshness.epoch`.
    public var grantRef: String
    public var pcactnEpoch: Double?
    public var now: Double
    /// The authoritative reversibility class (nil = none) and the PCActn's signed `action.reversibility_class`.
    public var serverClass: String?
    public var signedClass: JSONValue?
    /// A signed epoch is the expected source of revocation state; `epoch` is the one presented (nil: none).
    public var epochSource: Bool
    public var epoch: JSONValue?
    public var lastAcceptedEpoch: Double?
    /// A bare revocation root (with `epochSource` it must equal the signed epoch's root) and the time your trusted source issued it.
    public var root: String?
    public var rootIssuedAt: Double?
    /// The capability ids that must each be proven NOT in the revocation set (`proofFor(id)` returns the proof `{size, lo?, hi?}`;
    /// nil or no `proofFor` denies, fail closed). Empty: the freshness step alone.
    public var ids: [String] = []
    public var proofFor: ((String) -> JSONValue?)?
    public init(policy: RevocationStalenessPolicy, guardianPublic: String? = nil, pins: [String: String]? = nil, grantRef: String, pcactnEpoch: Double? = nil,
                now: Double, serverClass: String? = nil, signedClass: JSONValue? = nil, epochSource: Bool = false, epoch: JSONValue? = nil,
                lastAcceptedEpoch: Double? = nil, root: String? = nil, rootIssuedAt: Double? = nil) {
        self.policy = policy
        self.guardianPublic = guardianPublic
        self.pins = pins
        self.grantRef = grantRef
        self.pcactnEpoch = pcactnEpoch
        self.now = now
        self.serverClass = serverClass
        self.signedClass = signedClass
        self.epochSource = epochSource
        self.epoch = epoch
        self.lastAcceptedEpoch = lastAcceptedEpoch
        self.root = root
        self.rootIssuedAt = rootIssuedAt
    }
}

/// `ok`, or the `reason` it was refused. `root` is the revocation root the state commits to.
public struct RevocationGateResult: Equatable, Sendable {
    public let ok: Bool
    public let reason: String?
    public let root: String?
}

extension PCA {
    /// The server re-signs the epoch at least this often.
    public static let REVOCATION_EPOCH_REFRESH_MS: Double = 60_000
    /// How long a signed epoch is acceptable (longer than the refresh period).
    public static let REVOCATION_EPOCH_VALIDITY_MS: Double = 5 * 60_000
    /// The default maximum age of revocation state for an irreversible action (two refreshes).
    public static let REVOCATION_IRREVERSIBLE_MAX_AGE_MS: Double = 2 * 60_000
    static let REVOCATION_SKEW_MS: Double = 60_000
    static let REVEPOCH_DOMAIN = "atlas-pca/revepoch/v1\u{0}"
    static let EPOCH_BODY_KEYS = ["instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"]

    /// A number as JavaScript prints it (NaN and the infinities included).
    static func msStr(_ d: Double) -> String {
        d.isNaN ? "NaN" : (d.isInfinite ? (d < 0 ? "-Infinity" : "Infinity") : Canonical.numberString(d))
    }

    /// Severity of a reversibility class (reversible 0, rate_limited 1, costly 1, irreversible 2); unknown or non-string = 2.
    static func revClassRank(_ c: JSONValue?) -> Int { classRank(c) }

    /// The stricter of the server's class (nil = none) and the signed one: `reversible`, `rate_limited` or `irreversible`. A missing or
    /// unknown signed class is irreversible.
    public static func effectiveReversibility(serverClass: String?, signedClass: JSONValue?) -> String {
        var rank = revClassRank(signedClass)
        if let s = serverClass { rank = max(rank, revClassRank(.string(s))) }
        return rank >= 2 ? "irreversible" : (rank == 1 ? "rate_limited" : "reversible")
    }

    /// The maximum age of revocation state the policy allows for an action of class `cls`. A NaN anywhere stays NaN, so the age
    /// check then fails closed.
    public static func revocationMaxAgeMs(_ p: RevocationStalenessPolicy, class cls: String) -> Double {
        let mx = p.maxRevocationAgeMs ?? REVOCATION_EPOCH_VALIDITY_MS
        func pick(_ w: Double?, _ def: Double) -> Double {
            let v = w ?? def
            return (mx.isNaN || v.isNaN) ? .nan : min(mx, v)
        }
        switch cls {
        case "irreversible": return pick(p.staleness?.irreversible, REVOCATION_IRREVERSIBLE_MAX_AGE_MS)
        case "costly", "rate_limited": return pick(p.staleness?.costly, mx)
        default: return mx
        }
    }

    /// Age check of revocation state issued (or fetched from a trusted source) at `issuedAt` (nil or non-finite: unknown, denied).
    /// `what` names the state in the reason. A time more than 60 s in the future denies.
    public static func checkRevocationAge(issuedAt: Double?, now: Double, maxAgeMs: Double, what: String = "revocation state") -> RevocationAgeResult {
        guard let t = issuedAt, t.isFinite else { return .fail("\(what) age is unknown (unverifiable revocation state)") }
        if !(t <= now + REVOCATION_SKEW_MS) { return .fail("\(what) issued in the future") }
        if !(now - t <= maxAgeMs) {
            return .fail("\(what) is \(msStr(now - t)) ms old, over the verifier's maximum of \(msStr(maxAgeMs)) ms (stale revocation state)")
        }
        return .pass
    }

    /// Verifies a signed revocation epoch (parsed JSON): the pinned guardian, a registered suite, shape, signature, grant binding,
    /// `not_after`, issue time, the verifier's age cap, rollback and the PCActn's freshness. Never traps.
    public static func checkRevocationEpoch(_ ep: JSONValue?, _ o: EpochCheckOptions) -> RevocationAgeResult {
        let unpinned = RevocationAgeResult.fail("revocation epoch not signed by the pinned guardian")
        guard case let .object(m)? = ep, IV.same(m["guardian"]?.asString, o.guardianPublic) else { return unpinned }
        // the reference's registry check: an absent alg is ed25519, a string must name a registered suite (a registered suite this
        // build cannot verify is refused by the signature check below)
        if let a = m["alg"] {
            guard let s = a.asString, PCASuites.registered.contains(where: { IV.same($0, s) }) else { return unpinned }
        }
        guard let epoch = IV.safe(m["epoch"]), epoch >= 0, let setSize = IV.safe(m["set_size"]), setSize >= 0,
              let issued = IV.safe(m["issued_at"]), let notAfter = IV.safe(m["not_after"]) else {
            return .fail("malformed revocation epoch")
        }
        guard let body = Ledger.pick(m, EPOCH_BODY_KEYS) else { return .fail("revocation epoch check error") }
        if !Ledger.signed(o.guardianPublic, REVEPOCH_DOMAIN, body, m, o.pins) { return .fail("revocation epoch signature invalid") }
        if let g = o.grantRef, !IV.same(m["grant_ref"]?.asString, g) { return .fail("revocation epoch is for a different grant") }
        if !(o.now <= notAfter) { return .fail("revocation epoch expired (stale revocation root)") }
        if !(issued <= o.now + REVOCATION_SKEW_MS) { return .fail("revocation epoch issued in the future") }
        if let cap = o.maxAgeMs {
            let r = checkRevocationAge(issuedAt: issued, now: o.now, maxAgeMs: cap, what: "revocation epoch")
            if !r.ok { return r }
        }
        if let last = o.lastAcceptedEpoch, epoch < last {
            return .fail("revocation epoch \(msStr(epoch)) is older than the last accepted \(msStr(last)) (rollback)")
        }
        if let pe = o.pcactnEpoch, !(pe >= epoch) {
            return .fail("PCActn freshness.epoch \(msStr(pe)) predates the revocation epoch \(msStr(epoch))")
        }
        return .pass
    }

    /// Signs an Ed25519 revocation epoch with the guardian's 32-byte seed, in the wire form `checkRevocationEpoch` verifies (a PQ or
    /// hybrid guardian signs with its own tooling). nil for a seed that is not 32 bytes.
    public static func signRevocationEpoch(guardianSeed: [UInt8], _ b: RevocationEpochBody) -> JSONValue? {
        guard guardianSeed.count == 32, let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: Data(guardianSeed)) else { return nil }
        let body: JObject = ["instance_id": .string(b.instanceId), "grant_ref": .string(b.grantRef), "epoch": .int(b.epoch), "set_size": .int(b.setSize),
                             "root": .string(b.root), "issued_at": .int(b.issuedAt), "not_after": .int(b.notAfter)]
        guard let msg = IV.message(REVEPOCH_DOMAIN, .object(body)), let sig = try? key.signature(for: Data(msg)) else { return nil }
        var out = body
        out["guardian"] = .string(Base64URLStrict.encode(Array(key.publicKey.rawRepresentation)))
        out["sig"] = .string(Base64URLStrict.encode(Array(sig)))
        return .object(out)
    }

    /// Decides whether the revocation state is fresh enough: the staleness branch of the reference revocation checker. With `ids` set it also
    /// proves each capability id is not revoked. Fail closed: a missing signed epoch, an unverifiable
    /// one, a mismatching root or no root at all is a refusal.
    public static func revocationGate(_ g: RevocationGateInput) -> RevocationGateResult {
        func refuse(_ why: String) -> RevocationGateResult { RevocationGateResult(ok: false, reason: why, root: nil) }
        if let err = g.policy.validate() { return refuse("revocation staleness policy invalid: \(err)") }
        let staleness = g.policy.isOn
        var root = g.root
        var maxAge: Double?
        var cls: String?
        if staleness {
            let c = effectiveReversibility(serverClass: g.serverClass, signedClass: g.signedClass)
            cls = c
            maxAge = revocationMaxAgeMs(g.policy, class: c)
        }
        if g.epochSource {
            guard let ep = g.epoch, let guardian = g.guardianPublic, !guardian.isEmpty else { return refuse("no signed revocation epoch") }
            let chk = checkRevocationEpoch(ep, EpochCheckOptions(guardianPublic: guardian, now: g.now, pins: g.pins, grantRef: g.grantRef,
                                                                  lastAcceptedEpoch: g.lastAcceptedEpoch, pcactnEpoch: g.pcactnEpoch, maxAgeMs: maxAge))
            if !chk.ok { return refuse(chk.reason ?? "revocation epoch check error") }
            let epRoot = ep.get("root")?.asString
            if let r = root, !IV.same(r, epRoot) { return refuse("revocation root does not match the signed epoch") }
            root = epRoot
        } else if staleness, let c = cls, let mx = maxAge {
            if c == "irreversible" && !g.policy.allowUnsignedRootForIrreversible {
                return refuse("unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)")
            }
            let age = checkRevocationAge(issuedAt: g.rootIssuedAt, now: g.now, maxAgeMs: mx, what: "revocation root")
            if !age.ok { return refuse(age.reason ?? "revocation root age is unknown (unverifiable revocation state)") }
        }
        guard let r = root, !r.isEmpty else { return refuse("no revocation root") }
        for id in g.ids {
            guard let proof = g.proofFor?(id) else { return refuse("no non-membership proof for \(id)") }
            if !verifyNonMembership(root: r, proof: proof, id: id) { return refuse("capability \(id) is revoked or proof invalid") }
        }
        return RevocationGateResult(ok: true, reason: nil, root: r)
    }

    /// `verifyNonMembership`: `id` is NOT in the sorted revocation set `root` commits to, proved by `{size, lo?, hi?}` (adjacent
    /// neighbours in UTF-8 byte order with inclusion proofs against the size-bound root, or the empty-set root). Anything malformed is false.
    public static func verifyNonMembership(root: String, proof: JSONValue, id: String) -> Bool {
        guard case let .object(p) = proof else { return false }
        for k in ["lo", "hi"] {
            // a neighbour is null, absent or `{id: string, proof: object}`; any other shape is malformed, never "absent"
            guard let v = p[JKey(k)], !v.isNull else { continue }
            guard case let .object(n) = v, n["id"]?.asString != nil, n["proof"]?.asObject != nil else { return false }
        }
        return Mesh.nonMembership(root, p, id)
    }

    /// The gate for one `authorize` decision (policy on). nil = fresh; else the refusal reason. `state` may be nil (the source had nothing).
    static func revocationFreshness(_ input: AuthorizeInput, _ ctx: AuthorizeContext, _ p: JObject, _ state: RevocationState?, _ now: Int64) -> String? {
        guard let policy = input.revocationStaleness else { return nil }
        let signed = p["action"]?.get("reversibility_class")
        let grantRef = p["grant_ref"]?.asString ?? ""
        var g = RevocationGateInput(policy: policy, guardianPublic: input.guardianPublic, pins: input.guardianPins, grantRef: grantRef,
                                    now: Double(now), serverClass: ctx.reversibilityClass, signedClass: signed)
        if let e = IV.num(p["freshness"]?.get("epoch")) { g.pcactnEpoch = e }
        guard let st = state, st.epoch != nil || !(st.root ?? "").isEmpty else {
            if effectiveReversibility(serverClass: g.serverClass, signedClass: signed) == "irreversible" && !policy.allowUnsignedRootForIrreversible {
                return "no verifiable (guardian-signed) revocation state for an irreversible action"
            }
            return "no signed revocation epoch"
        }
        g.ids = input.revocationIds?(JSONValue.object(p)) ?? (p["cap_chain"]?.asArray ?? []).compactMap { $0.get("id")?.asString }
        let proofSource = input.revocationProof
        g.proofFor = { id in proofSource?(JSONValue.object(p), id) }
        g.lastAcceptedEpoch = st.lastAcceptedEpoch
        g.root = st.root
        g.rootIssuedAt = st.rootIssuedAt
        if let e = st.epoch {
            g.epochSource = true
            g.epoch = e
        }
        let r = revocationGate(g)
        return r.ok ? nil : (r.reason ?? "revocation state is not fresh")
    }
}
