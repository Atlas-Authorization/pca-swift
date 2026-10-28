import Foundation

/// LEASES (verification side): a time-boxed grant or credential that must be renewed to stay alive, has a hard `max_ttl` it can never
/// outlive, and dies at once when revoked. A lease authority signs a record; `LeaseRegistry` keeps the newest record per `lease_id`.
/// Port of packages/pca-grants/src/lease.ts; replays packages/pca/conformance/lease-vectors.json. Everything is total.
public enum Lease {
    public static let DOMAIN = "atlas-pca/lease/v1\u{0}"
    public static let REVOKE_DOMAIN = "atlas-pca/lease-revoke/v1\u{0}"
    static let MAX_APPROVERS = 16
    static let BODY_KEYS = ["v", "lease_id", "path", "grant_ref", "holder", "requester", "approvers", "justification_digest", "seq", "issued_at",
                            "renewed_at", "expires_at", "max_ttl", "authority"]
    static let REV_KEYS = ["v", "target", "value", "revoked_at", "authority"]

    /// `^[a-z0-9_.-]{1,64}(/[a-z0-9_.-]{1,64}){0,7}$`, checked by hand (ASCII only).
    static func pathOk(_ s: String) -> Bool {
        let segs = s.utf8.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false)
        if segs.count < 1 || segs.count > 8 { return false }
        for seg in segs {
            if seg.count < 1 || seg.count > 64 { return false }
            for b in seg {
                let ok = (b >= 97 && b <= 122) || (b >= 48 && b <= 57) || b == 95 || b == 46 || b == 45
                if !ok { return false }
            }
        }
        return true
    }

    static func num(_ o: JObject, _ k: String) -> Int64 { K3Sig.safeInt(o[JKey(k)]) ?? 0 }
    static func text(_ o: JObject, _ k: String) -> String { o[JKey(k)]?.asString ?? "" }

    static func wellFormed(_ v: JSONValue?) -> JObject? {
        guard let l = v?.asObject, l[JKey("v")]?.safeInt == 1,
              K3Sig.str(l[JKey("lease_id")], 128) != nil, K3Sig.str(l[JKey("grant_ref")], 256) != nil,
              K3Sig.str(l[JKey("holder")], 128) != nil, K3Sig.str(l[JKey("requester")], 128) != nil,
              K3Sig.str(l[JKey("authority")], 128) != nil, K3Sig.str(l[JKey("justification_digest")], 128) != nil,
              let path = l[JKey("path")]?.asString, pathOk(path),
              let seq = K3Sig.safeInt(l[JKey("seq")]), let issued = K3Sig.safeInt(l[JKey("issued_at")]),
              let renewed = K3Sig.safeInt(l[JKey("renewed_at")]), let expires = K3Sig.safeInt(l[JKey("expires_at")]),
              let ttl = K3Sig.safeInt(l[JKey("max_ttl")]), seq >= 1, ttl >= 1 else { return nil }
        if renewed < issued || expires <= renewed || (seq == 1 && renewed != issued) { return nil }
        guard let ap = l[JKey("approvers")]?.asArray, ap.count <= MAX_APPROVERS, ap.allSatisfy({ K3Sig.str($0, 128) != nil }) else { return nil }
        return l
    }

    /// `issued_at + max_ttl`.
    static func cap(_ l: JObject) -> Int64 { num(l, "issued_at") + num(l, "max_ttl") }

    /// Well formed and signed by its `authority` over exactly its content. Does NOT check the cap (the registry reports `over_max_ttl`).
    public static func verifyLease(_ v: JSONValue?) -> Bool {
        guard let l = wellFormed(v), let authority = l[JKey("authority")]?.asString else { return false }
        return K3Sig.verifyBody(DOMAIN, .object(K3Sig.pick(l, BODY_KEYS)), signer: authority, sig: l[JKey("sig")])
    }

    static func revWellFormed(_ v: JSONValue?) -> JObject? {
        guard let r = v?.asObject, r[JKey("v")]?.safeInt == 1, let value = K3Sig.str(r[JKey("value")], 256),
              K3Sig.str(r[JKey("authority")], 128) != nil, K3Sig.safeInt(r[JKey("revoked_at")]) != nil,
              let t = r[JKey("target")]?.asString, t == "lease" || t == "prefix" || t == "grant" else { return nil }
        if t == "prefix" && !pathOk(value) { return nil }
        return r
    }

    public static func verifyLeaseRevocation(_ v: JSONValue?) -> Bool {
        guard let r = revWellFormed(v), let authority = r[JKey("authority")]?.asString else { return false }
        return K3Sig.verifyBody(REVOKE_DOMAIN, .object(K3Sig.pick(r, REV_KEYS)), signer: authority, sig: r[JKey("sig")])
    }

    /// `prefix` covers `path` iff equal or `path` continues it at a segment boundary.
    public static func pathUnder(_ path: String, _ prefix: String) -> Bool {
        IV.same(path, prefix) || IV.startsWith(path, prefix + "/")
    }

    static func covers(_ r: JObject, _ l: JObject) -> Bool {
        if num(l, "issued_at") > num(r, "revoked_at") { return false }
        let value = text(r, "value")
        switch text(r, "target") {
        case "lease": return IV.same(text(l, "lease_id"), value)
        case "grant": return IV.same(text(l, "grant_ref"), value)
        default: return pathUnder(text(l, "path"), value)
        }
    }

    /// Separation of duties over one record: a reason, or nil. `chain` is every key in the holder's delegation chain.
    public static func sodError(requester: String, holder: String, approvers: [String], minApprovals: Int64 = 1,
                                eligibleApprovers: [String]? = nil, chain: [String] = []) -> String? {
        if minApprovals < 1 { return "minApprovals must be a positive integer" }
        var seen = Set<JKey>()
        for a in approvers {
            if !seen.insert(JKey(a)).inserted { return "an approver is listed twice" }
            if IV.same(a, requester) { return "the requester may not approve their own request" }
            if IV.same(a, holder) { return "the holder may not approve its own lease" }
            if chain.contains(where: { IV.same($0, a) }) { return "an approver appears in the holder's delegation chain" }
            if let el = eligibleApprovers, !el.contains(where: { IV.same($0, a) }) { return "an approver is not eligible" }
        }
        return Int64(approvers.count) < minApprovals ? "\(approvers.count) approver(s), need \(minApprovals)" : nil
    }

    public struct Policy {
        public var authorities: [String]
        public var minApprovals: Int64 = 1
        public var eligibleApprovers: [String]? = nil
        public var freshJustification = true
        public init(authorities: [String], minApprovals: Int64 = 1, eligibleApprovers: [String]? = nil, freshJustification: Bool = true) {
            self.authorities = authorities
            self.minApprovals = minApprovals
            self.eligibleApprovers = eligibleApprovers
            self.freshJustification = freshJustification
        }
    }

    /// `ok` true: `replaced` and `seq` are set. Otherwise `code` names the refusal.
    public struct Accept: Equatable {
        public var ok: Bool
        public var code: String? = nil
        public var replaced = false
        public var seq: Int64 = 0
        public var reason: String? = nil
    }

    public struct Revoke: Equatable {
        public var ok: Bool
        public var code: String? = nil
        public var revoked = 0
    }

    public struct HistoryEntry: Equatable {
        public var seq: Int64
        public var renewedAt: Int64
        public var expiresAt: Int64
        public var justificationDigest: String
    }

    struct State {
        var current: JObject
        var history: [HistoryEntry]
    }

    public final class Registry {
        let policy: Policy
        var leases: [JKey: State] = [:]
        var revocations: [JObject] = []
        let lock = NSLock()

        public init(policy: Policy) { self.policy = policy }

        /// Take an issue (seq 1) or a renewal (seq = current + 1). `chain`: the keys in the holder's delegation chain.
        public func accept(_ rec: JSONValue?, chain: [String] = []) -> Accept {
            lock.lock()
            defer { lock.unlock() }
            guard Lease.verifyLease(rec), let l = Lease.wellFormed(rec) else { return Accept(ok: false, code: "bad_record") }
            let authority = Lease.text(l, "authority")
            if !policy.authorities.contains(where: { IV.same($0, authority) }) { return Accept(ok: false, code: "unknown_authority") }
            let approvers = (l[JKey("approvers")]?.asArray ?? []).compactMap { $0.asString }
            if let sod = Lease.sodError(requester: Lease.text(l, "requester"), holder: Lease.text(l, "holder"), approvers: approvers,
                                        minApprovals: policy.minApprovals, eligibleApprovers: policy.eligibleApprovers, chain: chain) {
                return Accept(ok: false, code: "sod", reason: sod)
            }
            if Lease.num(l, "expires_at") > Lease.cap(l) { return Accept(ok: false, code: "over_max_ttl") }
            if revocations.contains(where: { Lease.covers($0, l) }) { return Accept(ok: false, code: "revoked") }
            let id = JKey(Lease.text(l, "lease_id"))
            let seq = Lease.num(l, "seq")
            let existing = leases[id]
            if let st = existing {
                let cur = st.current
                let curSeq = Lease.num(cur, "seq")
                if seq < curSeq { return Accept(ok: false, code: "stale_seq") }
                if seq == curSeq {
                    return l[JKey("sig")] == cur[JKey("sig")] ? Accept(ok: true, replaced: false, seq: seq) : Accept(ok: false, code: "lease_fork")
                }
                if seq != curSeq + 1 { return Accept(ok: false, code: "bad_seq", reason: "renewals advance seq by exactly 1") }
                for k in ["authority", "path", "grant_ref", "holder", "requester", "max_ttl", "issued_at"] {
                    if l[JKey(k)] != cur[JKey(k)] { return Accept(ok: false, code: "renewal_mismatch") }
                }
                if Lease.num(l, "renewed_at") >= Lease.num(cur, "expires_at") { return Accept(ok: false, code: "expired_lease", reason: "an expired lease cannot be renewed") }
                if Lease.num(l, "renewed_at") < Lease.num(cur, "renewed_at") || Lease.num(l, "expires_at") <= Lease.num(cur, "expires_at") {
                    return Accept(ok: false, code: "not_extending")
                }
                if policy.freshJustification && l[JKey("justification_digest")] == cur[JKey("justification_digest")] { return Accept(ok: false, code: "stale_justification") }
            } else if seq != 1 {
                return Accept(ok: false, code: "bad_seq", reason: "a new lease starts at seq 1")
            }
            let entry = HistoryEntry(seq: seq, renewedAt: Lease.num(l, "renewed_at"), expiresAt: Lease.num(l, "expires_at"),
                                     justificationDigest: Lease.text(l, "justification_digest"))
            var hist = existing?.history ?? []
            hist.append(entry)
            leases[id] = State(current: l, history: hist)
            return Accept(ok: true, replaced: true, seq: seq)
        }

        /// Take a signed revocation. Idempotent.
        public func revoke(_ rec: JSONValue?) -> Revoke {
            lock.lock()
            defer { lock.unlock() }
            guard Lease.verifyLeaseRevocation(rec), let r = Lease.revWellFormed(rec) else { return Revoke(ok: false, code: "bad_record") }
            let authority = Lease.text(r, "authority")
            if !policy.authorities.contains(where: { IV.same($0, authority) }) { return Revoke(ok: false, code: "unknown_authority") }
            if !revocations.contains(where: { $0[JKey("sig")] == r[JKey("sig")] }) { revocations.append(r) }
            return Revoke(ok: true, revoked: leases.values.filter { Lease.covers(r, $0.current) }.count)
        }

        public func get(_ id: String) -> JObject? {
            lock.lock()
            defer { lock.unlock() }
            return leases[JKey(id)]?.current
        }

        public func history(_ id: String) -> [HistoryEntry] {
            lock.lock()
            defer { lock.unlock() }
            return leases[JKey(id)]?.history ?? []
        }
    }

    /// `decision` is allow or deny; `code` is set on deny; `leaseId` when known; `expiresAt` on allow.
    public struct Decision: Equatable {
        public var decision: String
        public var code: String? = nil
        public var leaseId: String? = nil
        public var expiresAt: Int64? = nil
    }

    /// Is `presented` a live lease? It must verify, be the newest record the registry holds, be inside its window and its cap, and not be
    /// covered by a revocation. Fails closed.
    public static func checkLease(_ presented: JSONValue?, registry: Registry, now: JSONValue?) -> Decision {
        guard let n = K3Sig.safeInt(now) else { return Decision(decision: "deny", code: "bad_input") }
        guard verifyLease(presented), let p = wellFormed(presented) else { return Decision(decision: "deny", code: "bad_record") }
        let id = text(p, "lease_id")
        registry.lock.lock()
        defer { registry.lock.unlock() }
        guard let cur = registry.leases[JKey(id)]?.current else { return Decision(decision: "deny", code: "unknown_lease", leaseId: id) }
        if cur[JKey("sig")] != p[JKey("sig")] { return Decision(decision: "deny", code: "superseded", leaseId: id) }
        if registry.revocations.contains(where: { covers($0, cur) }) { return Decision(decision: "deny", code: "revoked", leaseId: id) }
        if n < num(cur, "renewed_at") { return Decision(decision: "deny", code: "not_yet_valid", leaseId: id) }
        if n >= cap(cur) { return Decision(decision: "deny", code: "past_max_ttl", leaseId: id) }
        if n >= num(cur, "expires_at") { return Decision(decision: "deny", code: "expired", leaseId: id) }
        return Decision(decision: "allow", leaseId: id, expiresAt: num(cur, "expires_at"))
    }
}
