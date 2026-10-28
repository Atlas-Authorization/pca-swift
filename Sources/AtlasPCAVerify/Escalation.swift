import Foundation

// Escalation on the wire: a port of packages/pca/src/escalation.ts. A decision of `escalate` is admitted only with a
// principal-signed answer bound to (policy digest, action digest, history head), spent by the replay counter, never
// upgrading a deny. Every signature suite this SDK verifies is accepted (Ed25519; ML-DSA, SLH-DSA and hybrids under a
// pinned `pq_pk`, as `PQ.resolve` allows); a suite it cannot verify is refused with `unsupported_suite`.

/// A pinned answering principal: its Ed25519 identity and, for a post-quantum or hybrid suite, the pinned `pq_pk`.
public struct PinnedSigner: Equatable, Sendable {
    public let pk: String
    public let pqPk: String?
    public init(_ pk: String, pqPk: String? = nil) {
        self.pk = pk
        self.pqPk = pqPk
    }
}

/// What an answer must be bound to.
public struct EscalationBinding: Equatable, Sendable {
    public let policyDigest: String
    public let actionDigest: String
    public let historyHead: String
    /// K7: the H(R) the verifier recomputed from the executed parameters and its own definition. When set, the answer MUST carry
    /// exactly it; when nil, an answer that carries a `render_digest` is refused (the verifier did not check what was shown).
    public let renderDigest: String?
    public init(policyDigest: String, actionDigest: String, historyHead: String, renderDigest: String? = nil) {
        self.policyDigest = policyDigest
        self.actionDigest = actionDigest
        self.historyHead = historyHead
        self.renderDigest = renderDigest
    }
}

/// The result of `PCA.verifyEscalationAnswer`. A valid `deny` answer is `ok` with decision `deny`: the caller must not admit it.
public struct EscalationVerdict: Equatable, Sendable {
    public let ok: Bool
    public let principal: String
    public let decision: String
    public let reason: String
    static func no(_ r: String) -> EscalationVerdict { EscalationVerdict(ok: false, principal: "", decision: "", reason: r) }
}

extension PCA {
    public static let ESCALATION_ANSWER_DOMAIN = "atlas-pca/escalation-answer/v1\u{0}"
    static let ESCALATION_POLICY_DOMAIN = "atlas-pca/escalation-policy/v1"
    static let ESCALATION_ACTION_DOMAIN = "atlas-pca/escalation-action/v1"
    static let ESCALATION_HISTORY_DOMAIN = "atlas-pca/escalation-history/v1"
    /// An answer lives at most 24 hours.
    public static let ESCALATION_MAX_LIFETIME_MS: Int64 = 86_400_000

    /// The digest of the policy in force: the stored grant.
    public static func escalationPolicyDigest(grant: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(ESCALATION_POLICY_DOMAIN), "grant": grant]))
    }

    /// The digest of the exact PCActn (counter and signature included): one answer, one action.
    public static func escalationActionDigest(pcactn: JSONValue) -> String? {
        IV.strictHash(.object(["d": .string(ESCALATION_ACTION_DOMAIN), "pcactn": pcactn]))
    }

    /// The head of the holder's history: its highest admitted replay counter (nil = none yet).
    public static func escalationHistoryHead(lastCounter: Int64?) -> String? {
        IV.strictHash(.object(["d": .string(ESCALATION_HISTORY_DOMAIN), "last_counter": lastCounter.map { .int($0) } ?? .null]))
    }

    /// The request a refused `escalate` carries for the principal. nil when a digest cannot be computed.
    public static func buildEscalationRequest(aud: String?, grant: JSONValue, pcactn: JSONValue, lastCounter: Int64?, reasons: [String], now: Int64,
                                              ttlMs: Int64 = 3_600_000, renderDigest: String? = nil) -> JSONValue? {
        guard let pd = escalationPolicyDigest(grant: grant), let ad = escalationActionDigest(pcactn: pcactn),
              let hh = escalationHistoryHead(lastCounter: lastCounter) else { return nil }
        let act = pcactn.get("action")
        // String(x).slice(0, 512) counts UTF-16 units
        func clip(_ r: String) -> String { r.utf16.count <= 512 ? r : String(decoding: Array(r.utf16.prefix(512)), as: UTF16.self) }
        var req: JObject = [
            "v": .int(1), "kind": .string("pca-escalation-request"), "aud": .string(aud ?? ""), "policy_digest": .string(pd),
            "action_digest": .string(ad), "history_head": .string(hh), "verb": .string(IntentWB.jsOpt(act?.get("verb"))),
            "resource": .string(IntentWB.jsOpt(act?.get("resource"))), "reasons": .array(reasons.prefix(16).map { .string(clip($0)) }),
            "expires_at": .int(now + ttlMs),
        ]
        if let rd = renderDigest { req["render_digest"] = .string(rd) }
        return .object(req)
    }

    static let ESC_REQUIRED = ["v", "kind", "principal", "policy_digest", "action_digest", "history_head", "decision", "iat", "expires_at", "nonce", "sig"]
    static let ESC_OPTIONAL = ["alg", "pq_pk", "pq_sig", "render_digest"]

    /// nil = well-formed (closed members, canonical digests, safe-integer times, sane lifetime).
    public static func escalationAnswerShapeError(_ a: JSONValue?) -> String? {
        guard case let .object(o)? = a else { return "not an object" }
        if let e = closedMembers(o, ESC_REQUIRED, ESC_OPTIONAL, "answer") { return e }
        if IV.num(o["v"]) != 1 || !IV.same(o["kind"]?.asString, "pca-escalation-answer") { return "not a pca-escalation-answer v1" }
        guard let pr = o["principal"]?.asString, IV.u16(pr) <= 64, Base64URLStrict.decode(pr, length: 32) != nil else {
            return "principal must be canonical base64url (32 bytes)"
        }
        for k in ["policy_digest", "action_digest", "history_head"] {
            guard let d = o[JKey(k)]?.asString, Base64URLStrict.decode(d, length: 32) != nil else { return "\(k) must be canonical base64url (32 bytes)" }
        }
        let dec = o["decision"]?.asString
        if dec != "allow" && dec != "deny" { return "decision must be 'allow' or 'deny'" }
        guard let iat = IV.nonNeg(o["iat"]), let exp = IV.nonNeg(o["expires_at"]) else { return "iat and expires_at must be non-negative safe integers" }
        if !(exp > iat) { return "expires_at must be greater than iat" }
        if exp - iat > ESCALATION_MAX_LIFETIME_MS { return "an answer lives at most \(ESCALATION_MAX_LIFETIME_MS) ms" }
        guard let n = o["nonce"]?.asString, let nb = Base64URLStrict.decode(n), nb.count >= 16 else { return "nonce must be canonical base64url of at least 16 bytes" }
        if o["sig"]?.asString == nil { return "sig must be a string" }
        if let rd = o["render_digest"], rd.asString.flatMap({ Base64URLStrict.decode($0, length: 32) }) == nil { return "render_digest must be canonical base64url (32 bytes)" }
        return IntentWB.artifactSuiteError(o)
    }

    /// Verify an answer against the verifier's pinned principals and the binding of THIS decision. Total; every failure is a
    /// `no` verdict. `now` must be a safe integer.
    public static func verifyEscalationAnswer(_ answer: JSONValue?, principals: [PinnedSigner], bind: EscalationBinding, now: Int64) -> EscalationVerdict {
        if now > Canonical.MAX_SAFE || now < -Canonical.MAX_SAFE { return .no("the verifier clock is not a safe integer (fail closed)") }
        if let e = escalationAnswerShapeError(answer) { return .no("malformed escalation answer: \(e)") }
        guard case let .object(a)? = answer, let principal = a["principal"]?.asString else { return .no("malformed escalation answer: not an object") }
        if principals.isEmpty { return .no("no principal is pinned for escalation answers") }
        guard let pin = principals.first(where: { IV.same($0.pk, principal) }) else { return .no("the answering principal is not pinned by this verifier") }
        if let pq = pin.pqPk, pq.isEmpty { return .no("escalation answer error (fail closed): the pinned pq_pk is empty") }
        if !IntentWB.verifyArtifactSig(ESCALATION_ANSWER_DOMAIN, a, pin.pk, pqPin: pin.pqPk) { return .no("escalation answer signature invalid") }
        if !IV.same(a["policy_digest"]?.asString, bind.policyDigest) { return .no("the answer is bound to another policy") }
        if !IV.same(a["action_digest"]?.asString, bind.actionDigest) { return .no("the answer is bound to another action") }
        if !IV.same(a["history_head"]?.asString, bind.historyHead) { return .no("the answer is bound to another state of the history") }
        if let want = bind.renderDigest {
            guard let got = a["render_digest"] else { return .no("the answer is not bound to the canonical approval render") }
            if !IV.same(got.asString, want) { return .no("the answer was given for another approval render") }
        } else if a["render_digest"] != nil {
            return .no("the answer carries an approval render this verifier did not recompute")
        }
        guard let iat = IV.nonNeg(a["iat"]), let exp = IV.nonNeg(a["expires_at"]), let dec = a["decision"]?.asString else { return .no("malformed escalation answer") }
        if now < iat { return .no("the answer is from the future") }
        if now > exp { return .no("the answer has expired") }
        return EscalationVerdict(ok: true, principal: principal, decision: dec, reason: "")
    }

    /// The answer a request header carries (`PCA-Escalation-Answer`): strict unpadded base64url of the JSON; nil when it is
    /// not (an unreadable answer is no answer).
    public static func escalationAnswer(fromHeader h: String) -> JSONValue? {
        guard let raw = Base64URLStrict.decode(h), let v = try? StrictJSON.parse(String(decoding: raw, as: UTF8.self)) else { return nil }
        return v
    }
}
