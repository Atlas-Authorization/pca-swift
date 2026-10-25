import Foundation

/// Intent revocation (Intent Layer v2 V10; rule 13 step 7, T22). Mirrors `packages/pca/src/intent-revocation.ts` and the
/// parts of `revocation.ts` it uses: the signed revocation epoch (`atlas-pca/revepoch/v1`) of the session's DEDICATED
/// revocation authority, carrying its FULL revoked list (sorted by UTF-8 bytes, distinct; its sorted-set root
/// `revset_root(L) = base64url(SHA-256("pca-revset/v1\0" || canonical({size, tree})))` is the signed `root`), checked
/// append-only against the last epoch this verifier accepted.
enum IntentRevocation {
    static let EPOCH_DOMAIN = "atlas-pca/revepoch/v1\u{0}"
    static let SET_DOMAIN = "pca-revset/v1\u{0}"

    static func sessionId(_ s: String) -> String { "pca-intent:session:" + s }
    static func mapId(_ m: String) -> String { "pca-intent:map:" + m }
    static func deltaId(_ g: String) -> String { "pca-intent:delta:" + g }
    static func profileId(_ p: String, _ v: Int64) -> String { "pca-intent:profile:\(p)@\(v)" }
    static func sessionScope(_ s: String) -> String { "pca-intent-session:" + s }

    static let EMPTY_TREE = Base64URLStrict.encode(Canonical.sha256([]))

    static func bindRoot(_ size: JSONValue, _ tree: String) -> String? {
        guard let c = IV.strictCanon(.object(["size": size, "tree": .string(tree)])) else { return nil }
        return Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(SET_DOMAIN) + Canonical.utf8(c)))
    }

    /// `revset_root(L)`: the RFC-6962-shaped Merkle root (leaf `SHA-256(0x00 || canonical(id))`, node `SHA-256(0x01 || l || r)`)
    /// over `L` in order, bound to its size; nil when an id is not strictly canonical.
    static func revsetRoot(_ ids: [String]) -> String? {
        var hs: [[UInt8]] = []
        for id in ids {
            guard let c = IV.strictCanon(.string(id)) else { return nil }
            hs.append(Canonical.sha256([0x00] + Canonical.utf8(c)))
        }
        let tree = hs.isEmpty ? EMPTY_TREE : Base64URLStrict.encode(Merkle.build(hs))
        return bindRoot(.int(Int64(ids.count)), tree)
    }

    /// Strict shape of a revocation epoch as rule 13 consumes it: every number a non-negative safe integer, every string a
    /// string, the suite one the dispatch implements, optional members absent or of their type (null is malformed).
    static func epochShapeError(_ epV: JSONValue?) -> String? {
        guard case let .object(ep)? = epV else { return "the revocation epoch must be an object" }
        for k in ["instance_id", "grant_ref", "root", "guardian", "sig"] where ep[JKey(k)]?.asString == nil { return "revocation epoch \(k) must be a string" }
        for k in ["epoch", "set_size", "issued_at", "not_after"] where !IV.isSafeNonNeg(ep[JKey(k)]) {
            return "revocation epoch \(k) must be a non-negative safe integer"
        }
        if let ge = ep["guardian_epoch"], !IV.isSafeNonNeg(ge) { return "revocation epoch guardian_epoch must be a non-negative safe integer" }
        if let se = IV.suiteError(ep["alg"]) { return "revocation epoch alg: \(se)" }
        if let x = ep["pq_pk"], x.asString == nil { return "revocation epoch pq_pk must be a string" }
        if let x = ep["pq_sig"], x.asString == nil { return "revocation epoch pq_sig must be a string" }
        return nil
    }

    /// `checkRevocationEpoch(ep, {guardianPublic: ep.guardian, now, grantRef, pqPins})` on a strictly shaped epoch. A PQ epoch
    /// verifies only under the PQ key the session root pins for its guardian.
    static func checkEpoch(_ ep: JObject, now: Double, grantRef: String, pqPins: [String: String]) -> IV.SuiteVerdict {
        checkEpochReason(ep, now: now, grantRef: grantRef, pqPins: pqPins).0
    }

    /// `checkEpoch` with the reference's reason for a refusal.
    static func checkEpochReason(_ ep: JObject, now: Double, grantRef: String, pqPins: [String: String]) -> (IV.SuiteVerdict, String) {
        let check = "revocation epoch check error"
        guard let guardian = ep["guardian"]?.asString else { return (.invalid, check) }
        var body: JObject = [:]
        for k in ["instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"] {
            guard let x = ep[JKey(k)] else { return (.invalid, check) }
            body[JKey(k)] = x
        }
        guard let bound = IV.bindSuite(body, alg: ep["alg"], pqPk: ep["pq_pk"]), let msg = IV.message(EPOCH_DOMAIN, .object(bound)) else { return (.invalid, check) }
        let sv = IV.verifyPinned(alg: ep["alg"], identity: guardian, artifactPqPk: ep["pq_pk"], msg: msg, sig: ep["sig"], pqSig: ep["pq_sig"],
                                 pin: pqPins[guardian])
        if sv == .invalid { return (.invalid, "revocation epoch signature invalid") }
        if sv != .valid { return (sv, "") }
        if !IV.strictEq(ep["grant_ref"], .string(grantRef)) { return (.invalid, "revocation epoch is for a different grant") }
        guard let notAfter = IV.nonNeg(ep["not_after"]), let issued = IV.nonNeg(ep["issued_at"]) else { return (.invalid, check) }
        if !(now <= Double(notAfter)) { return (.invalid, "revocation epoch expired (stale revocation root)") }
        if !(Double(issued) <= now + 60_000) { return (.invalid, "revocation epoch issued in the future") }
        return (.valid, "")
    }

    /// The revoked list is well-formed and is exactly what the epoch signs (root, size, epoch == size); nil = ok.
    static func revokedListError(_ ep: JObject, _ rv: JSONValue?) -> String? {
        guard case let .array(a)? = rv else { return "revoked must be an array of ids" }
        let r = a.compactMap { $0.asString }
        if r.count != a.count { return "revoked must be an array of ids" }
        for i in r.indices.dropFirst() where !(Canonical.compareUtf8(r[i - 1], r[i]) < 0) { return "revoked must be sorted by UTF-8 bytes and distinct" }
        guard let size = IV.nonNeg(ep["set_size"]), Int64(r.count) == size, IV.nonNeg(ep["epoch"]) == size else {
            return "the epoch must be numbered by its set size and list exactly set_size ids"
        }
        guard let root = revsetRoot(r) else {
            // the reference's RevocationSet throws on an id that is not strictly canonical
            return "session revocation check error (fail closed): \(r.lazy.compactMap { IV.strictCanonError(.string($0)) }.first ?? "canonicalize error")"
        }
        if !IV.same(root, ep["root"]?.asString) { return "the revoked list is not the signed set (root mismatch)" }
        return nil
    }

    /// The evidence is CLOSED to `{epoch, revoked}` (an extra member is malformed; a missing one fails at its own step).
    static func evidenceError(_ o: JObject) -> String? {
        for k in o.keys.map({ $0.s }).sorted(by: IV.utf8Less) where k != "epoch" && k != "revoked" { return "has the unknown member '\(k)' (it is exactly {epoch, revoked})" }
        return nil
    }

    static func evidence(_ v: JSONValue?) -> JObject? {
        guard case let .object(o)? = v, evidenceError(o) == nil else { return nil }
        return o
    }

    /// `checkSessionRevocation(ev, {session, authority, ids, now, maxAgeMs, pin, last?})`, steps a-g in order. (ok, reason).
    static func check(_ ev: JSONValue?, session: String, authority: String, ids: [String], now: Double, maxAgeMs: Double, scope: String? = nil,
                      pqPins: [String: String] = [:], last: JSONValue? = nil) -> (Bool, String) {
        // a.
        if !(IV.isSafeDouble(maxAgeMs) && maxAgeMs >= 0 && maxAgeMs.sign == .plus) { return (false, "revocation max age misconfigured (fail closed)") }
        if !IV.isSafeDouble(now) || IV.isNegZero(now) { return (false, "the verifier clock is not a safe integer (fail closed)") }
        guard case let .object(e)? = ev else { return (false, "no session revocation epoch supplied") }
        if let ee = evidenceError(e) { return (false, "the revocation evidence \(ee)") }
        // b.
        if let shape = epochShapeError(e["epoch"]) { return (false, shape) }
        let ep = e["epoch"]!.asObject!
        guard IV.same(ep["guardian"]?.asString, authority) else { return (false, "the revocation epoch is not signed by the session revocation authority") }
        // c.
        let ce = checkEpochReason(ep, now: now, grantRef: scope ?? sessionScope(session), pqPins: pqPins)
        switch ce.0 {
        case .valid: break
        case .unsupported: return (false, IV.UNSUPPORTED_SUITE)
        case .invalid: return (false, ce.1)
        }
        // d.
        guard let ia = IV.nonNeg(ep["issued_at"]), now - Double(ia) <= maxAgeMs else { return (false, "the session revocation epoch is older than \(IntentV2.jsString(.double(maxAgeMs))) ms") }
        // e.
        if let le = revokedListError(ep, e["revoked"]) { return (false, le) }
        let revoked = Set(e["revoked"]!.asArray!.map { JKey($0.asString!) })
        // f. append-only against the tracked last epoch
        if let lv = last {
            guard let L = evidence(lv), epochShapeError(L["epoch"]) == nil, let lep = L["epoch"]?.asObject, revokedListError(lep, L["revoked"]) == nil else {
                return (false, "the tracked last epoch is malformed (fail closed)")
            }
            let n = IV.nonNeg(ep["epoch"])!, ln = IV.nonNeg(lep["epoch"])!
            if n < ln { return (false, "revocation epoch rollback (older than the last accepted)") }
            for id in L["revoked"]!.asArray!.compactMap({ $0.asString }) where !revoked.contains(JKey(id)) {
                return (false, "the epoch drops '\(id)', revoked in the last accepted epoch (not append-only)")
            }
            if n == ln && !IV.same(ep["root"]?.asString, lep["root"]?.asString) { return (false, "two different revocation sets under one epoch number (equivocation)") }
        }
        // g.
        for id in ids where revoked.contains(JKey(id)) { return (false, "'\(id)' is revoked") }
        return (true, "")
    }
}

extension PCA {
    /// Rule 13 step 7 on its own (`primitives.intent_revocation`): `{epoch, revoked, session, authority, ids, now, max_age_ms,
    /// last?: {epoch, revoked}}` -> ok.
    public static func intentRevocationPrimitive(_ input: JSONValue) -> Bool {
        let i = IV.normalized(input)
        guard let session = i.get("session")?.asString, let authority = i.get("authority")?.asString, let now = IV.num(i.get("now")),
              case let .array(idv)? = i.get("ids") else { return false }
        let ids = idv.compactMap { $0.asString }
        if ids.count != idv.count { return false }
        // the EVIDENCE is the input without the check parameters (closed: any other member is malformed)
        var ev = i.asObject ?? [:]
        for k in ["session", "scope", "authority", "ids", "now", "max_age_ms", "last"] { ev[JKey(k)] = nil }
        return IntentRevocation.check(.object(ev), session: session, authority: authority, ids: ids, now: now,
                                      maxAgeMs: IV.num(i.get("max_age_ms")) ?? .nan, last: i.get("last")).0
    }
}
