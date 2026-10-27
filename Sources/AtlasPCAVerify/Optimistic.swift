import Foundation

/// Optimistic-path verification (extension layer): bonded claims, the challenge window, fraud proofs (wire level) and
/// guardian-signed settlement records. Inputs are parsed JSON values; nothing here traps on hostile input.
///
/// A fraud proof is only convincing because the settlement layer RE-RUNS the Policy VM on its server-held open-time snapshot;
/// `fraudProofWireCheck` does not do that (no native SDK evaluates the Policy VM decision). It checks that the proof is well
/// formed, names this claim and bond, and carries the decision its kind requires.
public enum Optimistic {
    public static let CLAIM_DOMAIN = "atlas-pca/optimistic/v1\u{0}"
    public static let SETTLEMENT_DOMAIN = "atlas-pca/bond-settlement/v1\u{0}"
    static let IRREVERSIBLE = "irreversible"
    static let DEFAULT_R_MARGIN = 1e-9

    /// Bounds on a claim's issued_at skew and window length (milliseconds).
    public struct ChallengeWindowPolicy: Equatable, Sendable {
        public var minWindowMs: Double
        public var maxWindowMs: Double
        public var maxSkewMs: Double
        public init(minWindowMs: Double, maxWindowMs: Double, maxSkewMs: Double) {
            self.minWindowMs = minWindowMs
            self.maxWindowMs = maxWindowMs
            self.maxSkewMs = maxSkewMs
        }
        /// The library default (1 s minimum, 24 h maximum, 5 s skew).
        public static let `default` = ChallengeWindowPolicy(minWindowMs: 1000, maxWindowMs: 86_400_000, maxSkewMs: 5000)
    }

    static func finite(_ v: JSONValue?) -> Double? {
        guard let d = IV.num(v), d.isFinite else { return nil }
        return d
    }

    /// A JSON object (and, like JavaScript, an array) is an object; anything else is not.
    static func object(_ v: JSONValue?) -> JObject? {
        switch v {
        case let .object(o)?: return o
        case .array?: return [:]
        default: return nil
        }
    }

    /// `sig` over domain || lenient-canonical(body); a body the lenient form refuses is `canon == false`.
    static func signedLenient(_ pub: String, _ domain: String, _ body: JObject, _ sig: JSONValue?) -> (ok: Bool, canon: Bool) {
        let c = Canonical.canonicalize(.object(body))
        if c.isEmpty { return (false, false) }
        guard let s = sig?.asString else { return (false, true) }
        return (Ed25519Strict.verifyB64u(pub, Canonical.utf8(domain) + Canonical.utf8(c), s), true)
    }

    /// The FIRST check a bonded claim fails, or "ok": malformed, irreversible, digest, claimed_r, window, signature. The claim
    /// must cover `expectedPcactnDigest`, be signed by `signerPublic`, and its window must sit within the policy of `serverNow`.
    public static func claimCheck(_ claim: JSONValue?, expectedPcactnDigest: String, signerPublic: String, serverNow: Double,
                                  policy: ChallengeWindowPolicy = .default) -> String {
        guard let c = object(claim) else { return "malformed" }
        if IV.same(c["reversibility_class"]?.asString, IRREVERSIBLE) { return "irreversible" }
        guard let d = c["pcactn_digest"]?.asString, IV.same(d, expectedPcactnDigest) else { return "digest" }
        if finite(c["claimed_r"]) == nil { return "claimed_r" }
        guard let issued = finite(c["issued_at"]), let window = finite(c["challenge_window_ms"]), serverNow.isFinite,
              abs(issued - serverNow) <= policy.maxSkewMs, window >= policy.minWindowMs, window <= policy.maxWindowMs else { return "window" }
        var body = c
        body["sig"] = nil
        let r = signedLenient(signerPublic, CLAIM_DOMAIN, body, c["sig"])
        if !r.canon { return "malformed" }
        return r.ok ? "ok" : "signature"
    }

    /// The last instant (epoch ms) at which a challenge is accepted: issued_at + window.
    public static func challengeWindowEnd(issuedAt: Double, windowMs: Double) -> Double { issuedAt + windowMs }

    /// True while challenges are accepted: now <= issued_at + window (inclusive end).
    public static func withinChallengeWindow(issuedAt: Double, windowMs: Double, now: Double) -> Bool {
        now.isFinite && now <= challengeWindowEnd(issuedAt: issuedAt, windowMs: windowMs)
    }

    /// "open" while challenges are accepted, else "finalized".
    public static func claimStatus(issuedAt: Double, windowMs: Double, now: Double) -> String {
        withinChallengeWindow(issuedAt: issuedAt, windowMs: windowMs, now: now) ? "open" : "finalized"
    }

    /// JavaScript === between two members (numbers by value, otherwise by canonical form; both absent equal).
    static func memberEq(_ m1: JObject, _ m2: JObject, _ k: String) -> Bool {
        let a = m1[JKey(k)], b = m2[JKey(k)]
        if a == nil && b == nil { return true }
        guard let x = a, let y = b else { return false }
        if let nx = IV.num(x) {
            guard let ny = IV.num(y) else { return false }
            return nx == ny
        }
        return Ledger.same(x, y)
    }

    /// The first wire-level check a fraud proof fails against the claim it names, or "ok": malformed, digest, bond,
    /// claimed_r, kind, consistency.
    public static func fraudProofWireCheck(_ claim: JSONValue?, _ proof: JSONValue?) -> String {
        guard case let .object(c)? = claim, case let .object(p)? = proof, case let .object(d)? = p["decision"] else { return "malformed" }
        guard case let .bool(rel)? = d["releaseGuardianShare"], case let .bool(opt)? = d["optimisticAllowed"], let r = finite(d["r"]),
              p["pcactn_digest"]?.asString != nil, p["bond_ref"]?.asString != nil, p["reason"]?.asString != nil else { return "malformed" }
        if !memberEq(p, c, "pcactn_digest") { return "digest" }
        if !memberEq(p, c, "bond_ref") { return "bond" }
        if !memberEq(p, c, "claimed_r") { return "claimed_r" }
        let kind = p["kind"]?.asString ?? ""
        var margin = DEFAULT_R_MARGIN
        if let m = finite(p["r_margin"]) { margin = max(0, m) }
        let holds: Bool
        switch kind {
        case "irreversible":
            // proof.evidence?.action?.action?.reversibility_class
            let ev = p["evidence"]?.asObject?["action"]?.asObject?["action"]?.asObject?["reversibility_class"]?.asString ?? ""
            let cc = c["reversibility_class"]?.asString ?? ""
            holds = IV.same(cc, IRREVERSIBLE) || IV.same(ev, IRREVERSIBLE)
        case "policy-denied": holds = !rel
        case "optimistic-not-allowed": holds = rel && !opt
        case "risk-understated":
            if let cr = finite(c["claimed_r"]) { holds = rel && opt && r > cr + margin } else { holds = false }
        default: return "kind"
        }
        return holds ? "ok" : "consistency"
    }

    static func nonEmpty(_ v: JSONValue?) -> Bool { !(v?.asString ?? "").isEmpty }

    static func nonNeg(_ v: JSONValue?) -> Double? {
        guard let f = finite(v), f >= 0 else { return nil }
        return f
    }

    /// The first check a settlement record fails, or "ok": malformed, suite, shape, split, signature. The record's guardian
    /// signature (any suite this SDK verifies; a PQ half only under `pins[guardianPublic]`) is checked last, over the lenient canonical
    /// body without `sig` / `pq_sig`.
    public static func settlementWireCheck(_ record: JSONValue?, guardianPublic: String, pins: [String: String]? = nil) -> String {
        guard case let .object(r)? = record else { return "malformed" }
        // TS answers `suite` only for an alg outside the registry; a registered suite this SDK does not implement (slh-dsa, fn-dsa, less) is `suite` here too
        if let a = r["alg"], !(a.asString.map { PQ.suites[$0] != nil } ?? false) { return "suite" }
        let action = r["action"]?.asString ?? ""
        let slash = action == "slash"
        let amount = finite(r["amount"])
        let hasSplit = r["split"] != nil
        let ev = r["evidenceDigest"]?.asString
        var epochOK = true
        if let e = r["guardian_epoch"] { epochOK = IV.safe(e).map { $0 >= 0 } ?? false }
        let splitObj = r["split"]?.asObject
        var shapeOK = nonEmpty(r["claimId"]) && (action == "open" || action == "release" || slash)
        guard let amt = amount, amt > 0 else { return "shape" }
        shapeOK = shapeOK && nonEmpty(r["from"]) && nonEmpty(r["to"]) && finite(r["at"]) != nil
        guard let evidence = ev else { return "shape" }
        shapeOK = shapeOK && (slash ? !evidence.isEmpty : evidence.isEmpty)
        shapeOK = shapeOK && (slash ? splitObj != nil : !hasSplit)
        shapeOK = shapeOK && r["sig"]?.asString != nil && epochOK
        if !shapeOK { return "shape" }
        if slash, let sp = splitObj {
            let cr = nonNeg(sp["challengerReward"]), vc = nonNeg(sp["victimCompensation"]), tr = nonNeg(sp["treasuryRemainder"])
            guard let sa = IV.num(sp["amount"]), sa == amt, let c1 = cr, let v1 = vc, let t1 = tr, (c1 + v1) + t1 == amt else { return "split" }
            var conserved = nonEmpty(sp["victimAccount"])
            if let ta = sp["treasuryAccount"]?.asString { conserved = conserved && IV.same(ta, r["to"]?.asString ?? "") } else { conserved = false }
            if conserved {
                if let ca = sp["challengerAccount"], !ca.isNull {
                    conserved = nonEmpty(ca)
                } else {
                    conserved = sp["challengerAccount"] != nil && c1 == 0 && v1 == 0 && t1 == amt
                }
            }
            if !conserved { return "split" }
        }
        var body = r
        body["sig"] = nil
        body["pq_sig"] = nil
        // alg / pq_pk stay in the signed body (as the reference); both signatures are dropped.
        let c = Canonical.canonicalize(.object(body))
        if c.isEmpty { return "malformed" }
        let ok = IV.verifyPinned(alg: r["alg"], identity: guardianPublic, artifactPqPk: r["pq_pk"], msg: Canonical.utf8(SETTLEMENT_DOMAIN) + Canonical.utf8(c),
                                 sig: r["sig"], pqSig: r["pq_sig"], pin: pins?[guardianPublic]) == .valid
        return ok ? "ok" : "signature"
    }
}
