import Foundation

/// BREAK-GLASS GRANTS (verification side): a pre-authorized, short-lived, small-budget emergency grant with a mandatory signed review
/// after the fact. A use is recorded only when the enforcement point reports the notification delivered; a holder whose review is
/// overdue, or whose use was judged unjustified, is frozen. Port of packages/pca-grants/src/breakglass.ts; replays
/// packages/pca/conformance/break-glass-vectors.json. Everything is total. State is kept per holder (one atomic document per holder).
public enum BreakGlass {
    public static let DOMAIN = "atlas-pca/break-glass/v1\u{0}"
    public static let REVIEW_DOMAIN = "atlas-pca/break-glass-review/v1\u{0}"
    public static let MAX_WINDOW_MS: Int64 = 86_400_000
    public static let MAX_USES: Int64 = 16
    public static let MAX_REVIEW_WITHIN_MS: Int64 = 30 * 86_400_000
    static let BODY_KEYS = ["v", "id", "holder", "grant_ref", "reason_digest", "max_uses", "issued_at", "expires_at", "review_within", "notify_to", "authority"]
    static let REVIEW_KEYS = ["v", "id", "outcome", "notes_digest", "at", "reviewer"]

    static func num(_ o: JObject, _ k: String) -> Int64 { K3Sig.safeInt(o[JKey(k)]) ?? 0 }
    static func text(_ o: JObject, _ k: String) -> String { o[JKey(k)]?.asString ?? "" }

    static func wellFormed(_ v: JSONValue?) -> JObject? {
        guard let b = v?.asObject, b[JKey("v")]?.safeInt == 1,
              K3Sig.str(b[JKey("id")], 128) != nil, K3Sig.str(b[JKey("holder")], 128) != nil, K3Sig.str(b[JKey("grant_ref")], 256) != nil,
              K3Sig.str(b[JKey("reason_digest")], 128) != nil, K3Sig.str(b[JKey("notify_to")], 256) != nil, K3Sig.str(b[JKey("authority")], 128) != nil,
              let uses = K3Sig.safeInt(b[JKey("max_uses")]), let issued = K3Sig.safeInt(b[JKey("issued_at")]),
              let expires = K3Sig.safeInt(b[JKey("expires_at")]), let within = K3Sig.safeInt(b[JKey("review_within")]),
              uses >= 1, uses <= MAX_USES, expires > issued, expires - issued <= MAX_WINDOW_MS,
              within >= 1, within <= MAX_REVIEW_WITHIN_MS else { return nil }
        return b
    }

    public static func verifyBreakGlass(_ v: JSONValue?) -> Bool {
        guard let b = wellFormed(v), let authority = b[JKey("authority")]?.asString else { return false }
        return K3Sig.verifyBody(DOMAIN, .object(K3Sig.pick(b, BODY_KEYS)), signer: authority, sig: b[JKey("sig")])
    }

    static func reviewWellFormed(_ v: JSONValue?) -> JObject? {
        guard let r = v?.asObject, r[JKey("v")]?.safeInt == 1,
              K3Sig.str(r[JKey("id")], 128) != nil, K3Sig.str(r[JKey("notes_digest")], 128) != nil, K3Sig.str(r[JKey("reviewer")], 128) != nil,
              let outcome = r[JKey("outcome")]?.asString, outcome == "justified" || outcome == "unjustified",
              K3Sig.safeInt(r[JKey("at")]) != nil else { return nil }
        return r
    }

    public static func verifyBreakGlassReview(_ v: JSONValue?) -> Bool {
        guard let r = reviewWellFormed(v), let reviewer = r[JKey("reviewer")]?.asString else { return false }
        return K3Sig.verifyBody(REVIEW_DOMAIN, .object(K3Sig.pick(r, REVIEW_KEYS)), signer: reviewer, sig: r[JKey("sig")])
    }

    public struct Policy {
        public var authorities: [String]
        public var reviewers: [String]
        public init(authorities: [String], reviewers: [String]) {
            self.authorities = authorities
            self.reviewers = reviewers
        }
    }

    /// `ok` true: `replaced` is set. Otherwise `code` names the refusal.
    public struct Result: Equatable {
        public var ok: Bool
        public var code: String? = nil
        public var replaced = false
    }

    /// `decision` is allow or deny; `code` on deny; `id` when known; `use`, `remaining`, `reviewDue` on allow.
    public struct Decision: Equatable {
        public var decision: String
        public var code: String? = nil
        public var id: String? = nil
        public var use: Int64 = 0
        public var remaining: Int64 = 0
        public var reviewDue: Int64 = 0
    }

    struct Entry {
        var rec: JObject
        var uses: [Int64]
        var review: JObject?
        /// The action digest of each use (parallel to `uses`; the numbered use log is kept in the store).
        var digests: [String] = []
    }

    static func isFrozen(_ grants: [JKey: Entry]?, _ now: Int64) -> Bool {
        guard let g = grants else { return false }
        return g.values.contains { e in
            if let rv = e.review { return rv[JKey("outcome")]?.asString == "unjustified" }
            guard let first = e.uses.first else { return false }
            return now >= first + num(e.rec, "review_within")
        }
    }

    /// One shard's document: the grants of the holders hashing here, keyed by id.
    struct Shard {
        var grants: [JKey: Entry] = [:]

        init() {}
        init(_ v: JSONValue?) {
            guard let gs = v?.asObject?[JKey("grants")]?.asObject else { return }
            for (k, e) in gs {
                guard let eo = e.asObject, let rec = eo[JKey("rec")]?.asObject, let us = eo[JKey("uses")]?.asArray else { continue }
                var times: [Int64] = [], digs: [String] = []
                for u in us {
                    guard let uo = u.asObject else { continue }
                    times.append(BreakGlass.num(uo, "at"))
                    digs.append(BreakGlass.text(uo, "action_digest"))
                }
                grants[k] = Entry(rec: rec, uses: times, review: eo[JKey("review")]?.asObject, digests: digs)
            }
        }

        var json: JSONValue {
            var gs: JObject = [:]
            for (k, e) in grants {
                var uses: [JSONValue] = []
                for (i, at) in e.uses.enumerated() {
                    uses.append(.object(["n": .int(Int64(i + 1)), "action_digest": .string(i < e.digests.count ? e.digests[i] : ""), "at": .int(at)]))
                }
                var eo: JObject = ["rec": .object(e.rec), "uses": .array(uses)]
                if let rv = e.review { eo["review"] = .object(rv) }
                gs[k] = .object(eo)
            }
            return .object(["grants": .object(gs)])
        }

        /// The holder's own grants (the shard also holds other holders').
        func grants(of holder: String) -> [JKey: Entry] { grants.filter { IV.same(BreakGlass.text($0.value.rec, "holder"), holder) } }
    }

    /// The registry keeps each holder's grants in the shard the holder hashes to, over a REQUIRED durable key-value store (`AtomicKV`): a
    /// process-local default would forget uses and reviews on restart. `MemoryAtomicKV` is for tests and single-process use.
    public final class Registry {
        let policy: Policy
        let kv: any AtomicKV
        let shards: Int
        private var metaOk = false

        public init(policy: Policy, kv: any AtomicKV, shards: Int = Lease.DEFAULT_SHARDS) throws {
            if shards < 1 || shards > Lease.MAX_SHARDS { throw PCAProducerError("BreakGlassRegistry: shards must be an integer from 1 to 4096") }
            self.policy = policy
            self.kv = kv
            self.shards = shards
        }

        func ready() throws -> Bool {
            if metaOk { return true }
            let n = shards
            let ok: Bool = try Lease.atomically(kv, "breakglass/meta") { prev in
                if let o = prev?.asObject { return (nil, o[JKey("shards")]?.safeInt == Int64(n)) }
                return (.object(["v": .int(1), "shards": .int(Int64(n))]), true)
            }
            metaOk = ok
            return ok
        }

        func key(_ holder: String) -> String { "breakglass/\(shards)/\(Lease.shardOf(holder, shards))" }

        /// Register an issued record. A frozen holder gets no new one.
        public func accept(_ rec: JSONValue?, now: JSONValue?) -> Result {
            guard BreakGlass.verifyBreakGlass(rec), let r = BreakGlass.wellFormed(rec), let n = K3Sig.safeInt(now) else { return Result(ok: false, code: "bad_record") }
            let authority = BreakGlass.text(r, "authority")
            if !policy.authorities.contains(where: { IV.same($0, authority) }) { return Result(ok: false, code: "unknown_authority") }
            let holder = BreakGlass.text(r, "holder")
            let id = JKey(BreakGlass.text(r, "id"))
            do {
                if !(try ready()) { return Result(ok: false, code: "store_unreachable") }
                return try Lease.atomically(kv, key(holder)) { prev in
                    var st = Shard(prev)
                    if let cur = st.grants[id] {
                        return (nil, cur.rec[JKey("sig")] == r[JKey("sig")] ? Result(ok: true, replaced: false) : Result(ok: false, code: "id_conflict"))
                    }
                    if BreakGlass.isFrozen(st.grants(of: holder), n) { return (nil, Result(ok: false, code: "holder_frozen")) }
                    st.grants[id] = Entry(rec: r, uses: [], review: nil)
                    return (st.json, Result(ok: true, replaced: true))
                }
            } catch { return Result(ok: false, code: "store_unreachable") }
        }

        /// Record one use; `notified` must be true. Checks in order: input, existence, holder, freeze, revocation, window, budget, notification.
        public func use(id: JSONValue?, holder: JSONValue?, actionDigest: JSONValue?, now: JSONValue?, notified: JSONValue?) -> Decision {
            guard let idText = K3Sig.str(id, 128), let holderText = K3Sig.str(holder, 128), let digest = K3Sig.str(actionDigest, 128),
                  let n = K3Sig.safeInt(now), case .bool(let delivered)? = notified else { return Decision(decision: "deny", code: "bad_input") }
            let ek = JKey(idText)
            func deny(_ code: String) -> (next: JSONValue?, out: Decision) { (nil, Decision(decision: "deny", code: code, id: idText)) }
            do {
                if !(try ready()) { return Decision(decision: "deny", code: "store_unreachable", id: idText) }
                return try Lease.atomically(kv, key(holderText)) { prev in
                    var st = Shard(prev)
                    guard var e = st.grants[ek] else { return deny("unknown_break_glass") }
                    if !IV.same(BreakGlass.text(e.rec, "holder"), holderText) { return deny("wrong_holder") }
                    if BreakGlass.isFrozen(st.grants(of: holderText), n) { return deny("holder_frozen") }
                    if e.review?[JKey("outcome")]?.asString == "unjustified" { return deny("revoked") }
                    if n < BreakGlass.num(e.rec, "issued_at") { return deny("not_yet_valid") }
                    if n >= BreakGlass.num(e.rec, "expires_at") { return deny("expired") }
                    let maxUses = BreakGlass.num(e.rec, "max_uses")
                    if Int64(e.uses.count) >= maxUses { return deny("budget_exhausted") }
                    if !delivered { return deny("not_notified") }
                    e.uses.append(n)
                    e.digests.append(digest)
                    st.grants[ek] = e
                    let used = Int64(e.uses.count)
                    return (st.json, Decision(decision: "allow", id: idText, use: used, remaining: maxUses - used, reviewDue: e.uses[0] + BreakGlass.num(e.rec, "review_within")))
                }
            } catch { return Decision(decision: "deny", code: "store_unreachable", id: idText) }
        }

        /// Record the signed review. The first review of a grant is final; a late one lifts an overdue freeze.
        public func review(_ rec: JSONValue?, holder: JSONValue?, now: JSONValue?) -> Result {
            guard BreakGlass.verifyBreakGlassReview(rec), let r = BreakGlass.reviewWellFormed(rec), let holderText = K3Sig.str(holder, 128),
                  let n = K3Sig.safeInt(now) else { return Result(ok: false, code: "bad_record") }
            let reviewer = BreakGlass.text(r, "reviewer")
            if !policy.reviewers.contains(where: { IV.same($0, reviewer) }) { return Result(ok: false, code: "unknown_reviewer") }
            let ek = JKey(BreakGlass.text(r, "id"))
            func fail(_ code: String) -> (next: JSONValue?, out: Result) { (nil, Result(ok: false, code: code)) }
            do {
                if !(try ready()) { return Result(ok: false, code: "store_unreachable") }
                return try Lease.atomically(kv, key(holderText)) { prev in
                    var st = Shard(prev)
                    guard var e = st.grants[ek], IV.same(BreakGlass.text(e.rec, "holder"), holderText) else { return fail("unknown_break_glass") }
                    if IV.same(reviewer, BreakGlass.text(e.rec, "holder")) || IV.same(reviewer, BreakGlass.text(e.rec, "authority")) { return fail("sod") }
                    if let rv = e.review {
                        return rv[JKey("sig")] == r[JKey("sig")] ? (nil, Result(ok: true, replaced: false)) : fail("already_reviewed")
                    }
                    guard let first = e.uses.first else { return fail("nothing_to_review") }
                    let at = BreakGlass.num(r, "at")
                    if at < first || at > n { return fail("bad_time") }
                    e.review = r
                    st.grants[ek] = e
                    return (st.json, Result(ok: true, replaced: true))
                }
            } catch { return Result(ok: false, code: "store_unreachable") }
        }

        /// Fail closed: malformed input, or a store that cannot answer, is frozen.
        public func frozen(holder: JSONValue?, now: JSONValue?) -> Bool {
            guard let holderText = K3Sig.str(holder, 128), let n = K3Sig.safeInt(now) else { return true }
            do {
                if !(try ready()) { return true }
                return BreakGlass.isFrozen(Shard(try kv.get(key(holderText))).grants(of: holderText), n)
            } catch { return true }
        }
    }
}
