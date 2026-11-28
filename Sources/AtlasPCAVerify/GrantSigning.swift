import Foundation

/// The operational plane of `pca-grants` (TypeScript: sig.ts, blueprint.ts, blueprint-admission.ts, fresh-at.ts): the signing side of the lease, lease
/// revocation, agent blueprint, break-glass and review records (a record is signed only when the verifier would take its shape), the domain-separated body
/// signature they share, attestation-gated blueprint admission, the group kill, and the freshness-token fold and issuer. The verifiers are `Lease`,
/// `Blueprint`, `BreakGlass` and `FreshAt`; the TypeScript names that this SDK carries under another name are aliased at the end.
public enum PCAGrants {
    static let LEASE_KEYS = ["v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at", "renewed_at", "expires_at", "max_ttl", "authority"]
    static let REVOKE_KEYS = ["v", "target", "value", "revoked_at", "authority"]
    static let BLUEPRINT_KEYS = ["v", "id", "key", "ceiling", "max_depth", "expires_at", "runtime_pins", "epoch", "status", "issued_at", "operator"]
    static let BG_KEYS = ["v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"]
    static let REVIEW_KEYS = ["v", "id", "outcome", "notes_digest", "at", "reviewer"]

    // ---- sig.ts ----

    /// The signer id of a secret key (its public key, base64url).
    public static func signerOf(_ secret: PCAEdKey) -> String { secret.id }

    /// base64url Ed25519 signature over `domain || strictCanonicalJSON(body)`.
    public static func signBody(_ domain: String, _ body: JSONValue, _ secret: PCAEdKey) throws -> String {
        try PCAIssue.signBody(secret, domain: domain, body: body)
    }

    /// True iff `sig` is a canonical 64-byte base64url signature by `signer` over exactly `body`. Never throws.
    public static func verifyBody(_ domain: String, _ body: JSONValue, _ signer: String, _ sig: JSONValue?) -> Bool {
        K3Sig.verifyBody(domain, body, signer: signer, sig: sig)
    }

    private static func base(_ rec: JObject, _ authorityKey: String, _ secret: PCAEdKey) -> JObject {
        var b: JObject = ["v": .int(1)]
        for (k, v) in rec { b[k] = v }
        b[JKey(authorityKey)] = .string(secret.id)
        return b
    }

    private static func signed(_ b0: JObject, _ domain: String, _ keys: [String], _ secret: PCAEdKey) throws -> JSONValue {
        var b = b0
        b["sig"] = .string(try signBody(domain, .object(K3Sig.pick(b0, keys)), secret))
        return .object(b)
    }

    public static func signLease(_ secret: PCAEdKey, _ l: JObject) throws -> JSONValue {
        let b = base(l, "authority", secret)
        guard Lease.wellFormed(.object(b)) != nil, K3Sig.safeInt(b["expires_at"]).map({ $0 <= Lease.cap(b) }) == true else {
            throw PCAProducerError("signLease: a malformed lease, or one past issued_at + max_ttl")
        }
        return try signed(b, Lease.DOMAIN, LEASE_KEYS, secret)
    }

    /// Conformance-vector builder only: signs a record that outlives its cap, to prove verifiers refuse it.
    public static func signLeaseUnsafeOverCap(_ secret: PCAEdKey, _ l: JObject) throws -> JSONValue {
        let b = base(l, "authority", secret)
        guard Lease.wellFormed(.object(b)) != nil else { throw PCAProducerError("signLeaseUnsafeOverCap: malformed") }
        return try signed(b, Lease.DOMAIN, LEASE_KEYS, secret)
    }

    public static func signLeaseRevocation(_ secret: PCAEdKey, _ r: JObject) throws -> JSONValue {
        let b = base(r, "authority", secret)
        guard Lease.revWellFormed(.object(b)) != nil else { throw PCAProducerError("signLeaseRevocation: malformed") }
        return try signed(b, Lease.REVOKE_DOMAIN, REVOKE_KEYS, secret)
    }

    public static func signBlueprint(_ secret: PCAEdKey, _ bp: JObject) throws -> JSONValue {
        let b = base(bp, "operator", secret)
        guard Blueprint.wellFormed(.object(b)) != nil else { throw PCAProducerError("signBlueprint: a malformed blueprint") }
        return try signed(b, Blueprint.DOMAIN, BLUEPRINT_KEYS, secret)
    }

    public static func signBreakGlass(_ secret: PCAEdKey, _ bg: JObject) throws -> JSONValue {
        let b = base(bg, "authority", secret)
        guard BreakGlass.wellFormed(.object(b)) != nil else {
            throw PCAProducerError("signBreakGlass: malformed, or the window is longer than 24 hours, or the budget is outside 1..16")
        }
        return try signed(b, BreakGlass.DOMAIN, BG_KEYS, secret)
    }

    public static func signBreakGlassReview(_ secret: PCAEdKey, _ r: JObject) throws -> JSONValue {
        let b = base(r, "reviewer", secret)
        guard BreakGlass.reviewWellFormed(.object(b)) != nil else { throw PCAProducerError("signBreakGlassReview: malformed") }
        return try signed(b, BreakGlass.REVIEW_DOMAIN, REVIEW_KEYS, secret)
    }

    // ---- blueprint-admission.ts ----

    private static func denied(_ code: String, _ reason: String? = nil) -> JSONValue {
        var m: JObject = ["admitted": .bool(false), "code": .string(code)]
        if let r = reason { m["reason"] = .string(r) }
        return .object(m)
    }

    /// `Object.entries(pin).every(([k, v]) => v !== undefined && id[k] === v) && Object.keys(pin).length > 0`.
    private static func pinMatches(_ pin: JObject, _ id: JObject) -> Bool {
        if pin.isEmpty { return false }
        for (k, v) in pin { guard let have = id[k], IV.strictEq(have, v) else { return false } }
        return true
    }

    /// Admit from adapter evidence: a parsed `{ok, bound, identity?, reason?}`. `ok` and `bound` must both be exactly true; `identity` is what the adapter
    /// established, never what the instance claims. A thrown error or malformed result denies. Returns `{admitted: true, identity, pin}` or
    /// `{admitted: false, code, reason?}`.
    public static func admitWithEvidence(_ blueprint: JSONValue, _ getEvidence: () throws -> JSONValue?) -> JSONValue {
        guard let pins = blueprint.get("runtime_pins")?.asArray, !pins.isEmpty else { return denied("no_pins") }
        let r: JSONValue?
        do { r = try getEvidence() } catch { return denied("verifier_error", (error as? JSError)?.name ?? "Error") }
        guard let ev = r?.asObject, ev["ok"] == .bool(true) else {
            return denied("not_ok", r?.get("reason")?.asString)
        }
        if ev["bound"] != .bool(true) { return denied("not_bound") }
        guard let ident = ev["identity"], !ident.isNull else { return denied("no_identity") }
        if ident.isArray { return denied("no_matching_pin") } // typeof [] is "object": no pin key is ever a member of an array
        guard let id = ident.asObject else { return denied("no_identity") }
        for p in pins {
            if let pin = p.asObject, pinMatches(pin, id) { return .object(["admitted": .bool(true), "identity": ident, "pin": p]) }
        }
        return denied("no_matching_pin")
    }

    /// What a hardware attestation verifier reports: `ok` and `bound` (evidence tied to THIS instance key and the challenge), the measured identity.
    public struct HardwareResult {
        public var ok: Bool
        public var bound: Bool
        public var measured: JObject?
        public var reason: String?
        public init(ok: Bool, bound: Bool, measured: JObject? = nil, reason: String? = nil) { self.ok = ok; self.bound = bound; self.measured = measured; self.reason = reason }
    }

    /// Admit through a hardware attestation verifier already bound to the document, context and expected binding (`verify`). `hasDocument` false is a deny.
    public static func admitBlueprintInstance(_ blueprint: JSONValue, hasDocument: Bool, verify: () throws -> HardwareResult?) -> JSONValue {
        guard let pins = blueprint.get("runtime_pins")?.asArray, !pins.isEmpty else { return denied("no_pins") }
        if !hasDocument { return denied("not_ok", "no evidence") }
        return admitWithEvidence(blueprint) {
            let h = try verify()
            var ev: JObject = ["ok": .bool(h?.ok == true), "bound": .bool(h?.bound == true)]
            if let m = h?.measured { ev["identity"] = .object(m) }
            if let r = h?.reason { ev["reason"] = .string(r) }
            return .object(ev)
        }
    }

    /// Holds admissions by instance key, blueprint key and the blueprint EPOCH they were made under, so a group kill or any new record invalidates them; they
    /// also expire. Plug `checker(now)` into `Blueprint.check(admitted:)`.
    public final class AdmissionRegistry: @unchecked Sendable {
        private var m: [String: (epoch: Int64, until: Int64)] = [:]
        private let lock = PCALock()
        public init() {}
        private static func k(_ bpKey: String, _ instance: String) -> String { bpKey + "\u{0}" + instance }

        /// Record an admission made under `bp` (its epoch), valid until `until` (epoch ms).
        public func admit(_ instanceKey: String, _ bp: JObject, until: Int64) {
            lock.lock(); defer { lock.unlock() }
            m[Self.k(bp["key"]?.asString ?? "", instanceKey)] = (K3Sig.safeInt(bp["epoch"]) ?? 0, until)
        }

        @discardableResult
        public func revoke(_ instanceKey: String, _ bpKey: String) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return m.removeValue(forKey: Self.k(bpKey, instanceKey)) != nil
        }

        /// True only for an unexpired admission made under the record's current epoch.
        public func checker(_ now: Int64) -> (String, JObject) throws -> Bool {
            return { [self] instance, bp in
                lock.lock(); defer { lock.unlock() }
                guard let a = m[Self.k(bp["key"]?.asString ?? "", instance)] else { return false }
                return a.epoch == (K3Sig.safeInt(bp["epoch"]) ?? -1) && now < a.until
            }
        }
    }

    // ---- blueprint.ts: group kill ----

    /// GROUP KILL: the operator signs the blueprint as `disabled` at the next epoch; the verifier accepts it and, when given `revokeIssuer`, also revokes the
    /// blueprint key as an ISSUER there, and, when given `advanceFreshAt` (the freshness issuer's `advance(revocation_epoch:now:)`), advances its
    /// `revocation_epoch` to the record's epoch and returns the token. Returns `{ok: true, record, freshAt?}` or `{ok: false, code}`. The epoch moves
    /// strictly forward.
    public static func groupKill(_ secret: PCAEdKey, _ registry: Blueprint.Registry, key: String, now: Int64, reason: String? = nil,
                                 revokeIssuer: ((String, String, Int64) throws -> Void)? = nil,
                                 advanceFreshAt: ((Int64, Int64) throws -> JSONValue)? = nil) throws -> JSONValue {
        func fail(_ code: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(code)]) }
        guard let cur = try registry.get(key) else { return fail("unknown_blueprint") }
        var rest = cur
        for k in ["sig", "operator", "v"] { rest[JKey(k)] = nil }
        rest["status"] = .string("disabled")
        let epoch = (K3Sig.safeInt(cur["epoch"]) ?? 0) + 1
        rest["epoch"] = .int(epoch)
        rest["issued_at"] = .int(now)
        let record = try signBlueprint(secret, rest)
        let r = registry.accept(record)
        if !r.ok { return fail(r.code ?? "bad_record") }
        if let rev = revokeIssuer { try rev(key, reason ?? "blueprint disabled (group kill)", now) }
        var out: JObject = ["ok": .bool(true), "record": record]
        if let adv = advanceFreshAt { out["freshAt"] = try adv(epoch, now) }
        return .object(out)
    }

    // ---- fresh-at.ts ----

    static let NUMERIC = ["revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"]

    private static func dbl(_ s: JObject, _ k: String) throws -> Double {
        guard let d = IV.num(s[JKey(k)]) else { throw PCAProducerError("fresh_at state: \(k) is not a number") }
        return d
    }

    /// Field-wise maximum of two states (the client-side fold); equal revisions with different digests keep `a`'s digest.
    public static func mergeFreshAt(_ a: JObject, _ b: JObject) throws -> JSONValue {
        var m: JObject = [:]
        for k in NUMERIC { m[JKey(k)] = try dbl(b, k) > dbl(a, k) ? b[JKey(k)] : a[JKey(k)] }
        m["policy_digest"] = try dbl(b, "policy_revision") > dbl(a, "policy_revision") ? b["policy_digest"] : a["policy_digest"]
        return .object(m)
    }

    /// Sign a token for `state`; throws on a malformed state (the reference's RangeError).
    public static func signFreshAt(_ secret: PCAEdKey, scope: String, state: JObject, issuedAt: Int64) throws -> JSONValue {
        var ok = K3Sig.str(.string(scope), 256) != nil && K3Sig.str(state["policy_digest"], 128) != nil && issuedAt >= 0
        for k in NUMERIC { ok = ok && K3Sig.safeInt(state[JKey(k)]) != nil }
        guard ok else { throw PCAProducerError("signFreshAt: a malformed state") }
        return try PCAIssue.signFreshAt(rs: secret, scope: scope, state: state, issuedAt: issuedAt)
    }

    /// Compose a freshness verdict into a decision: it can only tighten (allow to escalate or deny), never loosen.
    public static func gateDecision(_ decision: String, _ verdict: String) -> String {
        if decision == "deny" || verdict == "deny" { return "deny" }
        if verdict == "escalate" { return "escalate" }
        return decision
    }

    /// Verifier-side state holder: advance on every write, mint the token for the write, check incoming tokens.
    public final class FreshAtIssuer: @unchecked Sendable {
        private var state: JObject
        private let secret: PCAEdKey
        public let scope: String
        private let lock = PCALock()

        public init(_ secret: PCAEdKey, scope: String, initial: JObject) { self.secret = secret; self.scope = scope; self.state = initial }

        public func current() -> JSONValue { lock.lock(); defer { lock.unlock() }; return .object(state) }

        /// Apply a write (any subset of counters; each only moves forward) and return its token.
        public func advance(_ patch: JObject, now: Int64) throws -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            var next = state
            for (k, v) in patch { next[k] = v }
            guard case let .object(merged) = try PCAGrants.mergeFreshAt(state, next) else { throw PCAProducerError("fresh_at state") }
            state = merged
            return try PCAGrants.signFreshAt(secret, scope: scope, state: state, issuedAt: now)
        }

        public func check(_ token: JSONValue?, now: Int64, maxTokenAgeMs: Int64? = nil) -> FreshAt.Verdict {
            lock.lock(); defer { lock.unlock() }
            return FreshAt.check(token, local: FreshAt.State(json: .object(state)), signer: secret.id, scope: scope, now: now, maxTokenAgeMs: maxTokenAgeMs)
        }
    }

    // ---- TypeScript names this SDK carries under another name ----

    public static let AGENT_BLUEPRINT_DOMAIN = Blueprint.DOMAIN
    public static let FRESH_AT_DOMAIN = FreshAt.DOMAIN
    public static let FRESH_AT_REF_DOMAIN = FreshAt.REF_DOMAIN
    public static let BREAK_GLASS_DOMAIN = BreakGlass.DOMAIN
    public static let BREAK_GLASS_REVIEW_DOMAIN = BreakGlass.REVIEW_DOMAIN
    public static let MAX_BREAK_GLASS_USES = BreakGlass.MAX_USES
    public static let MAX_BREAK_GLASS_WINDOW_MS = BreakGlass.MAX_WINDOW_MS
    public static let LEASE_DOMAIN = Lease.DOMAIN
    public static let LEASE_REVOKE_DOMAIN = Lease.REVOKE_DOMAIN

    public static func verifyBlueprint(_ v: JSONValue?) -> Bool { Blueprint.verify(v) }
    public static func verifyFreshAt(_ t: JSONValue?, signer: String) -> Bool { FreshAt.verify(t, signer: signer) }
    public static func freshAtDigest(_ token: JSONValue) -> String? { FreshAt.digest(token) }
    public static func checkFreshAt(_ token: JSONValue?, local: FreshAt.State, signer: String, scope: String, now: Int64, maxTokenAgeMs: Int64? = nil) -> FreshAt.Verdict {
        FreshAt.check(token, local: local, signer: signer, scope: scope, now: now, maxTokenAgeMs: maxTokenAgeMs)
    }
}
