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
        public var minApprovals: Int64
        public var eligibleApprovers: [String]? = nil
        public var freshJustification: Bool
        /// Longest `max_ttl` (ms) this registry accepts (`ttl_ceiling`). nil: no ceiling.
        public var maxTtlCeiling: Int64? = nil
        public init(authorities: [String], minApprovals: Int64 = 1, eligibleApprovers: [String]? = nil, freshJustification: Bool = true, maxTtlCeiling: Int64? = nil) {
            self.maxTtlCeiling = maxTtlCeiling
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

    /// Run `body` as ONE atomic read-modify-write of `key`: it sees the stored value (nil: none) and returns the value to store (nil: leave
    /// the key unchanged) plus the result handed back. A kv failure throws (the caller answers `store_unreachable`).
    static func atomically<T>(_ kv: any AtomicKV, _ key: String, _ body: (JSONValue?) -> (next: JSONValue?, out: T)) throws -> T {
        var out: T?
        try kv.update(key) { prev in
            let r = body(prev)
            out = r.out
            return r.next
        }
        guard let o = out else { throw PCAProducerError("the store did not run the update") }
        return o
    }

    public static let DEFAULT_SHARDS = 16
    public static let MAX_SHARDS = 4096
    static let META_KEY = "lease/meta"
    static func shardKey(_ n: Int, _ i: Int) -> String { "lease/\(n)/\(i)" }
    /// The shard a lease id lives in: the first four bytes of SHA-256 of the id, modulo the shard count. Stable across processes.
    static func shardOf(_ id: String, _ shards: Int) -> Int {
        let h = Canonical.sha256(Canonical.utf8(id))
        let v = UInt32(h[0]) << 24 | UInt32(h[1]) << 16 | UInt32(h[2]) << 8 | UInt32(h[3])
        return Int(v % UInt32(shards))
    }

    /// One shard's document: the leases whose id hashes here and every prefix / grant revocation (replicated to all shards).
    struct Shard {
        var leases: [JKey: State] = [:]
        var revocations: [JObject] = []

        init() {}
        init(_ v: JSONValue?) {
            guard let o = v?.asObject, let ls = o[JKey("leases")]?.asObject, let rs = o[JKey("revocations")]?.asArray else { return }
            for (k, e) in ls {
                guard let eo = e.asObject, let cur = eo[JKey("current")]?.asObject, let hs = eo[JKey("history")]?.asArray else { continue }
                var hist: [HistoryEntry] = []
                for h in hs {
                    guard let ho = h.asObject else { continue }
                    hist.append(HistoryEntry(seq: Lease.num(ho, "seq"), renewedAt: Lease.num(ho, "renewed_at"), expiresAt: Lease.num(ho, "expires_at"),
                                             justificationDigest: Lease.text(ho, "justification_digest")))
                }
                leases[k] = State(current: cur, history: hist)
            }
            revocations = rs.compactMap { $0.asObject }
        }

        var json: JSONValue {
            var ls: JObject = [:]
            for (k, st) in leases {
                let hist: [JSONValue] = st.history.map { h in
                    .object(["seq": .int(h.seq), "renewed_at": .int(h.renewedAt), "expires_at": .int(h.expiresAt), "justification_digest": .string(h.justificationDigest)])
                }
                ls[k] = .object(["current": .object(st.current), "history": .array(hist)])
            }
            return .object(["leases": .object(ls), "revocations": .array(revocations.map { .object($0) })])
        }
    }

    /// The registry keeps each lease in the shard its id hashes to, over a REQUIRED durable key-value store (`AtomicKV`): a process-local
    /// default would forget revocations on restart. `MemoryAtomicKV` is for tests and single-process use (TS `memoryLeaseKv()`).
    public final class Registry {
        let policy: Policy
        let kv: any AtomicKV
        let shards: Int
        let clock: @Sendable () -> Int64
        private var metaOk = false

        public init(policy: Policy, kv: any AtomicKV, shards: Int = Lease.DEFAULT_SHARDS, clock: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }) throws {
            if shards < 1 || shards > Lease.MAX_SHARDS { throw PCAProducerError("LeaseRegistry: shards must be an integer from 1 to 4096") }
            if let c = policy.maxTtlCeiling, c < 1 || c > Canonical.MAX_SAFE { throw PCAProducerError("LeaseRegistry: maxTtlCeiling must be a positive integer") }
            self.policy = policy
            self.kv = kv
            self.shards = shards
            self.clock = clock
        }

        public var shardCount: Int { shards }

        /// Pin the shard count in the store on first use; a different count would make existing leases invisible, so it is refused.
        func ready() throws -> Bool {
            if metaOk { return true }
            let n = shards
            let ok: Bool = try Lease.atomically(kv, Lease.META_KEY) { prev in
                if let o = prev?.asObject { return (nil, o[JKey("shards")]?.safeInt == Int64(n)) }
                return (.object(["v": .int(1), "shards": .int(Int64(n))]), true)
            }
            metaOk = ok
            return ok
        }

        /// Drop the revocations whose window is over: `revoked_at + ceiling` is past (every lease they could cover is beyond its own cap).
        func prune(_ st: inout Shard) {
            guard let c = policy.maxTtlCeiling else { return }
            let now = clock()
            st.revocations = st.revocations.filter { Lease.num($0, "revoked_at") + c >= now }
        }

        /// Take an issue (seq 1) or a renewal (seq = current + 1). `chain`: the keys in the holder's delegation chain.
        public func accept(_ rec: JSONValue?, chain: [String] = []) -> Accept {
            guard Lease.verifyLease(rec), let l = Lease.wellFormed(rec) else { return Accept(ok: false, code: "bad_record") }
            let authority = Lease.text(l, "authority")
            if !policy.authorities.contains(where: { IV.same($0, authority) }) { return Accept(ok: false, code: "unknown_authority") }
            let approvers = (l[JKey("approvers")]?.asArray ?? []).compactMap { $0.asString }
            if let sod = Lease.sodError(requester: Lease.text(l, "requester"), holder: Lease.text(l, "holder"), approvers: approvers,
                                        minApprovals: policy.minApprovals, eligibleApprovers: policy.eligibleApprovers, chain: chain) {
                return Accept(ok: false, code: "sod", reason: sod)
            }
            if Lease.num(l, "expires_at") > Lease.cap(l) { return Accept(ok: false, code: "over_max_ttl") }
            if let c = policy.maxTtlCeiling, Lease.num(l, "max_ttl") > c { return Accept(ok: false, code: "ttl_ceiling") }
            let id = JKey(Lease.text(l, "lease_id"))
            do {
                if !(try ready()) { return Accept(ok: false, code: "store_unreachable") }
                return try Lease.atomically(kv, Lease.shardKey(shards, Lease.shardOf(id.s, shards))) { prev in
                    var st = Shard(prev)
                    func fail(_ code: String, _ reason: String? = nil) -> (next: JSONValue?, out: Accept) { (nil, Accept(ok: false, code: code, reason: reason)) }
                    if st.revocations.contains(where: { Lease.covers($0, l) }) { return fail("revoked") }
                    let existing = st.leases[id]
                    let seq = Lease.num(l, "seq")
                    if let ex = existing {
                        let cur = ex.current
                        let curSeq = Lease.num(cur, "seq")
                        if seq < curSeq { return fail("stale_seq") }
                        if seq == curSeq {
                            return l[JKey("sig")] == cur[JKey("sig")] ? (nil, Accept(ok: true, replaced: false, seq: seq)) : fail("lease_fork")
                        }
                        if seq != curSeq + 1 { return fail("bad_seq", "renewals advance seq by exactly 1") }
                        for k in ["authority", "path", "grant_ref", "holder", "requester", "max_ttl", "issued_at"] {
                            if l[JKey(k)] != cur[JKey(k)] { return fail("renewal_mismatch") }
                        }
                        if Lease.num(l, "renewed_at") >= Lease.num(cur, "expires_at") { return fail("expired_lease", "an expired lease cannot be renewed") }
                        if Lease.num(l, "renewed_at") < Lease.num(cur, "renewed_at") || Lease.num(l, "expires_at") <= Lease.num(cur, "expires_at") {
                            return fail("not_extending")
                        }
                        if policy.freshJustification && l[JKey("justification_digest")] == cur[JKey("justification_digest")] { return fail("stale_justification") }
                    } else if seq != 1 {
                        return fail("bad_seq", "a new lease starts at seq 1")
                    }
                    let entry = HistoryEntry(seq: seq, renewedAt: Lease.num(l, "renewed_at"), expiresAt: Lease.num(l, "expires_at"),
                                             justificationDigest: Lease.text(l, "justification_digest"))
                    st.leases[id] = State(current: l, history: (existing?.history ?? []) + [entry])
                    prune(&st)
                    return (st.json, Accept(ok: true, replaced: true, seq: seq))
                }
            } catch {
                return Accept(ok: false, code: "store_unreachable")
            }
        }

        /// Take a signed revocation. Idempotent. A prefix or grant revocation is written to every shard; the count is leases covered across all of them.
        public func revoke(_ rec: JSONValue?) -> Revoke {
            guard Lease.verifyLeaseRevocation(rec), let r = Lease.revWellFormed(rec) else { return Revoke(ok: false, code: "bad_record") }
            let authority = Lease.text(r, "authority")
            if !policy.authorities.contains(where: { IV.same($0, authority) }) { return Revoke(ok: false, code: "unknown_authority") }
            let targets: [Int] = Lease.text(r, "target") == "lease" ? [Lease.shardOf(Lease.text(r, "value"), shards)] : Array(0..<shards)
            var n = 0
            do {
                if !(try ready()) { return Revoke(ok: false, code: "store_unreachable") }
                for i in targets {
                    let c: Int = try Lease.atomically(kv, Lease.shardKey(shards, i)) { prev in
                        var st = Shard(prev)
                        if !st.revocations.contains(where: { $0[JKey("sig")] == r[JKey("sig")] }) { st.revocations.append(r) }
                        let covered = st.leases.values.filter { Lease.covers(r, $0.current) }.count
                        prune(&st)
                        return (st.json, covered)
                    }
                    n += c
                }
            } catch {
                return Revoke(ok: false, code: "store_unreachable")
            }
            return Revoke(ok: true, revoked: n)
        }

        func shard(_ id: String) throws -> Shard {
            if !(try ready()) { throw PCAProducerError("shard count mismatch") }
            return Shard(try kv.get(Lease.shardKey(shards, Lease.shardOf(id, shards))))
        }

        /// nil when unknown or when the store cannot answer (fails closed).
        public func get(_ id: String) -> JObject? { (try? shard(id))?.leases[JKey(id)]?.current }

        public func history(_ id: String) -> [HistoryEntry] { (try? shard(id))?.leases[JKey(id)]?.history ?? [] }

        /// The newest record of a lease and whether a stored revocation covers it; throws when the store cannot answer.
        func lookup(_ id: String) throws -> (current: JObject, revoked: Bool)? {
            let st = try shard(id)
            guard let cur = st.leases[JKey(id)]?.current else { return nil }
            return (cur, st.revocations.contains { Lease.covers($0, cur) })
        }

        /// Revocations held by one shard (for operators and the conformance kit).
        public func shardRevocations(_ i: Int) throws -> [JObject] {
            if i < 0 || i >= shards { throw PCAProducerError("no such shard") }
            return Shard(try kv.get(Lease.shardKey(shards, i))).revocations
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
    /// covered by a revocation. Fails closed (a store that cannot answer is `store_unreachable`).
    public static func checkLease(_ presented: JSONValue?, registry: Registry, now: JSONValue?) -> Decision {
        guard let n = K3Sig.safeInt(now) else { return Decision(decision: "deny", code: "bad_input") }
        guard verifyLease(presented), let p = wellFormed(presented) else { return Decision(decision: "deny", code: "bad_record") }
        let id = text(p, "lease_id")
        let found: (current: JObject, revoked: Bool)?
        do { found = try registry.lookup(id) } catch { return Decision(decision: "deny", code: "store_unreachable", leaseId: id) }
        guard let f = found else { return Decision(decision: "deny", code: "unknown_lease", leaseId: id) }
        let cur = f.current
        if cur[JKey("sig")] != p[JKey("sig")] { return Decision(decision: "deny", code: "superseded", leaseId: id) }
        if f.revoked { return Decision(decision: "deny", code: "revoked", leaseId: id) }
        if n < num(cur, "renewed_at") { return Decision(decision: "deny", code: "not_yet_valid", leaseId: id) }
        if n >= cap(cur) { return Decision(decision: "deny", code: "past_max_ttl", leaseId: id) }
        if n >= num(cur, "expires_at") { return Decision(decision: "deny", code: "expired", leaseId: id) }
        return Decision(decision: "allow", leaseId: id, expiresAt: num(cur, "expires_at"))
    }
}
