import Foundation

/// The verifier's `fresh_at` configuration (`FreshAtPolicy` of `packages/pca/src/fresh-at.ts`).
public struct FreshAtPolicy {
    /// The pinned token signer (base64url Ed25519 public key).
    public var signer: String
    /// The scope this verifier decides for; a token for another scope is refused.
    public var scope: String
    /// The verifier's OWN current state counters.
    public var local: FreshAt.State
    /// Refuse a token whose own age exceeds this (ms). nil: only the state ordering applies.
    public var maxTokenAgeMs: Int64?
    /// Every PCActn must carry (or have side-carried) a token; none is `escalate: a consistency token is required`.
    public var require: Bool
    /// The pre-member form: a token that travelled beside the PCActn. Read only when the PCActn has no member. nil = none presented; `.null` = a null token was presented.
    public var sideCarried: JSONValue?

    public init(signer: String, scope: String, local: FreshAt.State, maxTokenAgeMs: Int64? = nil, require: Bool = false, sideCarried: JSONValue? = nil) {
        self.signer = signer
        self.scope = scope
        self.local = local
        self.maxTokenAgeMs = maxTokenAgeMs
        self.require = require
        self.sideCarried = sideCarried
    }

    /// Lenient construction from the JSON form `{signer, scope, local, max_token_age_ms?, require?, side_carried?}`. A member that is
    /// missing or ill-typed makes the policy refuse (fail closed): an unusable signer or scope matches no token, an unusable age refuses every token.
    public init(json v: JSONValue?) {
        let o = v?.asObject ?? [:]
        var age: Int64?
        if let a = o["max_token_age_ms"] { age = IV.safe(a).map { Int64($0) } ?? Int64.min }
        self.init(signer: o["signer"]?.asString ?? "", scope: o["scope"]?.asString ?? "", local: FreshAt.State(json: o["local"]),
                  maxTokenAgeMs: age, require: o["require"] == .bool(true), sideCarried: o["side_carried"])
    }
}

extension FreshAt {
    /// Closed key set of the `fresh_at` member (an unknown key is unsigned malleability inside a signed member).
    static let MEMBER_KEYS = ["v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer", "sig"]

    /// Wire shape of the member: the problem, or nil. Does NOT check the signature (that is the `fresh_at` check).
    public static func validateWire(_ v: JSONValue) -> String? {
        guard let o = v.asObject else { return "'fresh_at' must be an object" }
        for k in o.keys.map({ $0.s }).sorted() where !MEMBER_KEYS.contains(where: { IV.same($0, k) }) {
            return "'fresh_at' has an unknown field '\(k)'"
        }
        if o["v"]?.safeInt != 1 { return "'fresh_at.v' must be 1" }
        if K3Sig.str(o["scope"], 256) == nil || K3Sig.str(o["policy_digest"], 128) == nil {
            return "'fresh_at' scope and policy_digest must be non-empty strings"
        }
        for k in ["revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "issued_at"] where K3Sig.safeInt(o[JKey(k)]) == nil {
            return "'fresh_at.\(k)' must be a non-negative safe integer"
        }
        guard let signer = o["signer"]?.asString, Base64URLStrict.isValid(signer, length: 32) else { return "'fresh_at.signer' is not canonical base64url (32 bytes)" }
        guard let sig = o["sig"]?.asString, Base64URLStrict.isValid(sig, length: 64) else { return "'fresh_at.sig' is not canonical base64url (64 bytes)" }
        return nil
    }

    /// Outcome of the PCActn `fresh_at` check.
    public enum Check: Equatable {
        /// Not reported: no member, no side-carried token, and the policy does not require one.
        case absent
        case pass
        case fail(String)
    }

    /// The verifier's `fresh_at` check. Reported only when the PCActn carries the member, a side-carried token is read, or the
    /// policy requires one. A stale verifier is an ESCALATE-class failure (`escalate: stale_state ...`), anything else is a hard failure.
    public static func decide(_ member: JSONValue?, _ policy: FreshAtPolicy?, now: Int64) -> Check {
        guard let policy = policy else {
            return member != nil ? .fail("the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)") : .absent
        }
        guard let token = member ?? policy.sideCarried else {
            return policy.require ? .fail("escalate: a consistency token is required (refresh and retry with the token of your latest write)") : .absent
        }
        switch check(token, local: policy.local, signer: policy.signer, scope: policy.scope, now: now, maxTokenAgeMs: policy.maxTokenAgeMs) {
        case .ok: return .pass
        case let .escalate(behind): return .fail("escalate: stale_state (verifier state is behind the token on \(behind.joined(separator: ", ")))")
        case let .deny(code): return .fail(code)
        }
    }
}
