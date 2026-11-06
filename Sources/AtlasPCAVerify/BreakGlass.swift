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
    }

    static func isFrozen(_ grants: [JKey: Entry]?, _ now: Int64) -> Bool {
        guard let g = grants else { return false }
        return g.values.contains { e in
            if let rv = e.review { return rv[JKey("outcome")]?.asString == "unjustified" }
            guard let first = e.uses.first else { return false }
            return now >= first + num(e.rec, "review_within")
        }
    }

    public final class Registry {
        let policy: Policy
        var holders: [JKey: [JKey: Entry]] = [:]
        let lock = NSLock()

        public init(policy: Policy) { self.policy = policy }

        /// Register an issued record. A frozen holder gets no new one.
        public func accept(_ rec: JSONValue?, now: JSONValue?) -> Result {
            lock.lock()
            defer { lock.unlock() }
            guard BreakGlass.verifyBreakGlass(rec), let r = BreakGlass.wellFormed(rec), let n = K3Sig.safeInt(now) else { return Result(ok: false, code: "bad_record") }
            let authority = BreakGlass.text(r, "authority")
            if !policy.authorities.contains(where: { IV.same($0, authority) }) { return Result(ok: false, code: "unknown_authority") }
            let hk = JKey(BreakGlass.text(r, "holder"))
            let id = JKey(BreakGlass.text(r, "id"))
            var grants = holders[hk] ?? [:]
            if let cur = grants[id] {
                return cur.rec[JKey("sig")] == r[JKey("sig")] ? Result(ok: true, replaced: false) : Result(ok: false, code: "id_conflict")
            }
            if BreakGlass.isFrozen(grants, n) { return Result(ok: false, code: "holder_frozen") }
            grants[id] = Entry(rec: r, uses: [], review: nil)
            holders[hk] = grants
            return Result(ok: true, replaced: true)
        }

        /// Record one use; `notified` must be true. Checks in order: input, existence, holder, freeze, revocation, window, budget, notification.
        public func use(id: JSONValue?, holder: JSONValue?, actionDigest: JSONValue?, now: JSONValue?, notified: JSONValue?) -> Decision {
            lock.lock()
            defer { lock.unlock() }
            guard let idText = K3Sig.str(id, 128), let holderText = K3Sig.str(holder, 128), K3Sig.str(actionDigest, 128) != nil,
                  let n = K3Sig.safeInt(now), case .bool(let delivered)? = notified else { return Decision(decision: "deny", code: "bad_input") }
            let hk = JKey(holderText)
            let ek = JKey(idText)
            guard var grants = holders[hk], var e = grants[ek] else { return Decision(decision: "deny", code: "unknown_break_glass", id: idText) }
            if BreakGlass.isFrozen(grants, n) { return Decision(decision: "deny", code: "holder_frozen", id: idText) }
            if e.review?[JKey("outcome")]?.asString == "unjustified" { return Decision(decision: "deny", code: "revoked", id: idText) }
            if n < BreakGlass.num(e.rec, "issued_at") { return Decision(decision: "deny", code: "not_yet_valid", id: idText) }
            if n >= BreakGlass.num(e.rec, "expires_at") { return Decision(decision: "deny", code: "expired", id: idText) }
            let maxUses = BreakGlass.num(e.rec, "max_uses")
            if Int64(e.uses.count) >= maxUses { return Decision(decision: "deny", code: "budget_exhausted", id: idText) }
            if !delivered { return Decision(decision: "deny", code: "not_notified", id: idText) }
            e.uses.append(n)
            grants[ek] = e
            holders[hk] = grants
            let used = Int64(e.uses.count)
            return Decision(decision: "allow", id: idText, use: used, remaining: maxUses - used, reviewDue: e.uses[0] + BreakGlass.num(e.rec, "review_within"))
        }

        /// Record the signed review. The first review of a grant is final; a late one lifts an overdue freeze.
        public func review(_ rec: JSONValue?, holder: JSONValue?, now: JSONValue?) -> Result {
            lock.lock()
            defer { lock.unlock() }
            guard BreakGlass.verifyBreakGlassReview(rec), let r = BreakGlass.reviewWellFormed(rec), let holderText = K3Sig.str(holder, 128),
                  let n = K3Sig.safeInt(now) else { return Result(ok: false, code: "bad_record") }
            let reviewer = BreakGlass.text(r, "reviewer")
            if !policy.reviewers.contains(where: { IV.same($0, reviewer) }) { return Result(ok: false, code: "unknown_reviewer") }
            let hk = JKey(holderText)
            let ek = JKey(BreakGlass.text(r, "id"))
            guard var grants = holders[hk], var e = grants[ek] else { return Result(ok: false, code: "unknown_break_glass") }
            if IV.same(reviewer, BreakGlass.text(e.rec, "holder")) || IV.same(reviewer, BreakGlass.text(e.rec, "authority")) { return Result(ok: false, code: "sod") }
            if let rv = e.review {
                return rv[JKey("sig")] == r[JKey("sig")] ? Result(ok: true, replaced: false) : Result(ok: false, code: "already_reviewed")
            }
            guard let first = e.uses.first else { return Result(ok: false, code: "nothing_to_review") }
            let at = BreakGlass.num(r, "at")
            if at < first || at > n { return Result(ok: false, code: "bad_time") }
            e.review = r
            grants[ek] = e
            holders[hk] = grants
            return Result(ok: true, replaced: true)
        }

        /// Fail closed: malformed input is frozen.
        public func frozen(holder: JSONValue?, now: JSONValue?) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            guard let holderText = K3Sig.str(holder, 128), let n = K3Sig.safeInt(now) else { return true }
            return BreakGlass.isFrozen(holders[JKey(holderText)], n)
        }
    }
}
