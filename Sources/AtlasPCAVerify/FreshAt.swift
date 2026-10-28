import Foundation

/// Consistency tokens (`fresh_at`): a signed high-water mark of verifier-side state (`packages/pca/src/fresh-at.ts`).
/// A verifier refuses to DECIDE against state older than the token (`stale_state` = escalate, never allow). Verification
/// only; every function is total.
public enum FreshAt {
    public static let DOMAIN = "atlas-pca/fresh-at/v1\u{0}"
    public static let REF_DOMAIN = "atlas-pca/fresh-at-ref/v1"
    static let COUNTERS = ["revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision"]
    static let BODY_KEYS = ["v", "scope", "revocation_epoch", "ledger_tree_size", "budget_version", "policy_revision", "policy_digest", "issued_at", "signer"]
    static let MAX_FUTURE_SKEW_MS: Int64 = 60_000

    /// The verifier's own state counters.
    public struct State: Equatable, Sendable {
        public var revocationEpoch: Int64
        public var ledgerTreeSize: Int64
        public var budgetVersion: Int64
        public var policyRevision: Int64
        public var policyDigest: String

        public init(revocationEpoch: Int64, ledgerTreeSize: Int64, budgetVersion: Int64, policyRevision: Int64, policyDigest: String) {
            self.revocationEpoch = revocationEpoch
            self.ledgerTreeSize = ledgerTreeSize
            self.budgetVersion = budgetVersion
            self.policyRevision = policyRevision
            self.policyDigest = policyDigest
        }

        /// A counter that is missing or not a non-negative safe integer reads as Int64.min (behind every token: fail closed).
        public init(json v: JSONValue?) {
            let o = v?.asObject ?? [:]
            func n(_ k: String) -> Int64 { K3Sig.safeInt(o[JKey(k)]) ?? Int64.min }
            self.init(revocationEpoch: n("revocation_epoch"), ledgerTreeSize: n("ledger_tree_size"), budgetVersion: n("budget_version"),
                      policyRevision: n("policy_revision"), policyDigest: o["policy_digest"]?.asString ?? "")
        }

        func counter(_ k: String) -> Int64 {
            switch k {
            case "revocation_epoch": return revocationEpoch
            case "ledger_tree_size": return ledgerTreeSize
            case "budget_version": return budgetVersion
            default: return policyRevision
            }
        }
    }

    public enum Verdict: Equatable, Sendable {
        case ok
        /// The verifier is behind the token on these counters: refresh and retry (never an allow).
        case escalate(behind: [String])
        /// `bad_token`, `wrong_scope`, `token_from_the_future`, `token_too_old` or `policy_fork`.
        case deny(code: String)
    }

    /// Well formed and signed by `signer` over exactly its content.
    public static func verify(_ t: JSONValue?, signer: String) -> Bool {
        guard let o = t?.asObject, o["v"]?.safeInt == 1, K3Sig.eq(o["signer"]?.asString, signer),
              K3Sig.str(o["scope"], 256) != nil, K3Sig.str(o["policy_digest"], 128) != nil,
              K3Sig.safeInt(o["issued_at"]) != nil,
              COUNTERS.allSatisfy({ K3Sig.safeInt(o[JKey($0)]) != nil }) else { return false }
        return K3Sig.verifyBody(DOMAIN, .object(K3Sig.pick(o, BODY_KEYS)), signer: signer, sig: o["sig"])
    }

    /// The content address a PCActn or request signs to bind the token it carried; nil where the reference throws.
    public static func digest(_ token: JSONValue) -> String? {
        K3Sig.digest(REF_DOMAIN, "t", token)
    }

    /// May the verifier decide against `local` for a request carrying `token`? Order: signature/shape, scope, issued in the
    /// future (> 60 s skew), token age, policy fork (same revision, different digest), then any counter behind the token.
    public static func check(_ token: JSONValue?, local: State, signer: String, scope: String, now: Int64, maxTokenAgeMs: Int64? = nil) -> Verdict {
        guard verify(token, signer: signer), let o = token?.asObject,
              let issuedAt = K3Sig.safeInt(o["issued_at"]), let rev = K3Sig.safeInt(o["policy_revision"]) else { return .deny(code: "bad_token") }
        if !K3Sig.eq(o["scope"]?.asString, scope) { return .deny(code: "wrong_scope") }
        if !(issuedAt <= now &+ MAX_FUTURE_SKEW_MS) { return .deny(code: "token_from_the_future") }
        if let max = maxTokenAgeMs, !(now &- issuedAt <= max) { return .deny(code: "token_too_old") }
        if rev == local.policyRevision && !K3Sig.eq(o["policy_digest"]?.asString, local.policyDigest) { return .deny(code: "policy_fork") }
        let behind = COUNTERS.filter { k in !(local.counter(k) >= (K3Sig.safeInt(o[JKey(k)]) ?? Int64.max)) }
        return behind.isEmpty ? .ok : .escalate(behind: behind)
    }
}
