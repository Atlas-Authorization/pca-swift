import Foundation

/// Transparency-ledger verification (extension layer): RFC 6962 inclusion of ledger commits, RFC 9162 consistency,
/// guardian-signed tree heads, witness cosignatures, head-to-head consistency, checkpoint chains and legacy witnessed heads.
/// Inputs are parsed JSON values, so a hostile wire object cannot trap any function here: every verifier returns false on
/// malformed input. Every suite this SDK verifies (Ed25519, ML-DSA, the hybrids) is accepted through the PCA suite dispatch; a PQ half verifies only under
/// the caller's pin for the signing identity (`pins`: identity b64u -> ML-DSA public key b64u); any other suite is refused (false).
public enum Ledger {
    static let STH_DOMAIN = "atlas-pca/sth/v1\u{0}"
    static let STH_WITNESS_DOMAIN = "atlas-pca/sth-witness/v2\u{0}"
    static let LEDGER_HEAD_DOMAIN = "atlas-pca/ledger-head/v1\u{0}"
    /// The longest consistency path any tree of fewer than 2^53 leaves can need (2*53+1), plus one of slack as the reference.
    static let MAX_CONSISTENCY_PATH = 2 * 53 + 2

    /// The root of the empty tree (RFC 9162 2.1.1: SHA-256 of the empty string), base64url.
    public static let EMPTY_TREE_ROOT = Base64URLStrict.encode(Canonical.sha256([]))

    /// A signature of `m` (`alg`, `pq_pk`, `sig`, `pq_sig`) over domain || strict-canonical(bindSuite(base)) under `identity`
    /// (b64u Ed25519 key), suite-agile; the PQ key must equal `pins[identity]`.
    static func signed(_ identity: String, _ domain: String, _ base: JObject, _ m: JObject, _ pins: [String: String]?) -> Bool {
        guard let bound = IV.bindSuite(base, alg: m["alg"], pqPk: m["pq_pk"]), let msg = IV.message(domain, .object(bound)) else { return false }
        return IV.verifyPinned(alg: m["alg"], identity: identity, artifactPqPk: m["pq_pk"], msg: msg, sig: m["sig"], pqSig: m["pq_sig"], pin: pins?[identity]) == .valid
    }

    /// The named members; nil when one is absent (the reference throws on undefined).
    static func pick(_ m: JObject, _ keys: [String]) -> JObject? {
        var out: JObject = [:]
        for k in keys {
            guard let v = m[JKey(k)] else { return nil }
            out[JKey(k)] = v
        }
        return out
    }

    /// JavaScript === on JSON values (compared through their strict canonical form); both absent are equal, one absent is not.
    static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?):
            guard let cx = IV.strictCanon(x), let cy = IV.strictCanon(y) else { return false }
            return IV.same(cx, cy)
        default: return false
        }
    }

    /// A ledger commit (string leaf) against a root with an RFC 6962 inclusion proof.
    public static func verifyInclusion(_ root: String, _ proof: JSONValue?, _ commit: JSONValue?) -> Bool {
        guard case let .object(p)? = proof, let c = commit else { return false }
        return Merkle.verifyInclusion(root, p, c)
    }

    /// RFC 9162 2.1.4.2 consistency verification. Sizes are JSON safe integers; the index arithmetic is done in UInt64. Size 0
    /// pins oldRoot to the empty-tree root and requires an empty path. Never traps.
    public static func verifyConsistency(_ oldRoot: JSONValue?, _ newRoot: JSONValue?, _ proof: JSONValue?) -> Bool {
        guard let or = oldRoot?.asString, let nr = newRoot?.asString, case let .object(p)? = proof else { return false }
        guard let ff = IV.safe(p["oldSize"]), let sf = IV.safe(p["newSize"]), case let .array(rawPath)? = p["path"],
              ff >= 0, ff <= sf, rawPath.count <= MAX_CONSISTENCY_PATH else { return false }
        let first = UInt64(ff), second = UInt64(sf)
        if first == 0 {
            if !rawPath.isEmpty || !IV.same(or, EMPTY_TREE_ROOT) { return false }
            if second == 0 { return IV.same(nr, EMPTY_TREE_ROOT) }
            return true // vacuous for a non-empty new tree
        }
        if first == second { return rawPath.isEmpty && IV.same(or, nr) }
        var path: [[UInt8]] = []
        if first & (first - 1) == 0 {
            guard let h = Base64URLStrict.decode(or) else { return false }
            path.append(h)
        }
        for e in rawPath {
            guard let s = e.asString, let h = Base64URLStrict.decode(s) else { return false }
            path.append(h)
        }
        if path.isEmpty { return false }
        var fn = first - 1, sn = second - 1
        while fn & 1 == 1 {
            fn >>= 1
            sn >>= 1
        }
        var fr = path[0], sr = path[0]
        for c in path.dropFirst() {
            if sn == 0 { return false }
            if fn & 1 == 1 || fn == sn {
                fr = Merkle.nodeHash(c, fr)
                sr = Merkle.nodeHash(c, sr)
                while fn & 1 == 0 && fn != 0 {
                    fn >>= 1
                    sn >>= 1
                }
            } else {
                sr = Merkle.nodeHash(sr, c)
            }
            fn >>= 1
            sn >>= 1
        }
        return sn == 0 && IV.same(Base64URLStrict.encode(fr), or) && IV.same(Base64URLStrict.encode(sr), nr)
    }

    /// A legacy witnessed head {principal,size,root,witness,sig} against the witness key.
    public static func verifyWitnessedHead(_ wh: JSONValue?, _ witnessPublic: String, _ pins: [String: String]? = nil) -> Bool {
        guard case let .object(m)? = wh else { return false }
        if !IV.same(m["witness"]?.asString, witnessPublic) { return false }
        guard let body = pick(m, ["principal", "size", "root"]) else { return false }
        return signed(witnessPublic, LEDGER_HEAD_DOMAIN, body, m, pins)
    }

    /// True when a and b are both validly witnessed by the witness for the same principal and size but carry different roots.
    public static func detectEquivocation(_ a: JSONValue?, _ b: JSONValue?, _ witnessPublic: String, _ pins: [String: String]? = nil) -> Bool {
        guard case let .object(am)? = a, case let .object(bm)? = b, verifyWitnessedHead(a, witnessPublic, pins), verifyWitnessedHead(b, witnessPublic, pins) else { return false }
        let asz = IV.num(am["size"]), bsz = IV.num(bm["size"])
        let ar = am["root"]?.asString ?? "", br = bm["root"]?.asString ?? ""
        return same(am["principal"], bm["principal"]) && asz == bsz && !IV.same(ar, br)
    }

    /// One cosignature of a tree head under a trusted witness key, bound to {instance_id, principal, size, root, prev_root,
    /// guardian_epoch (absent or null = 0)}.
    public static func verifyWitnessCosignature(_ sth: JSONValue?, _ cosig: JSONValue?, _ witnessPublic: String, _ pins: [String: String]? = nil) -> Bool {
        guard case let .object(sm)? = sth, case let .object(cm)? = cosig else { return false }
        if !IV.same(cm["key"]?.asString, witnessPublic) { return false }
        guard var body = pick(sm, ["instance_id", "principal", "size", "root", "prev_root"]) else { return false }
        if let e = sm["guardian_epoch"], !e.isNull { body["guardian_epoch"] = e } else { body["guardian_epoch"] = .int(0) }
        return signed(witnessPublic, STH_WITNESS_DOMAIN, body, cm, pins)
    }

    /// `policy.pqPins` (identity -> ML-DSA key); non-string entries are dropped.
    static func policyPins(_ pol: JObject) -> [String: String] { pinsOf(pol["pqPins"]) }

    static func pinsOf(_ v: JSONValue?) -> [String: String] {
        var out: [String: String] = [:]
        for (k, p) in v?.asObject ?? [:] { if let ps = p.asString { out[k.s] = ps } }
        return out
    }

    /// The k-of-n check: at least policy.threshold DISTINCT trusted witnesses (policy witnessKeys) carry a valid cosignature
    /// over this exact head. Unknown, duplicate and mis-bound cosignatures do not count; threshold 0 is vacuously met; a
    /// non-integer or negative threshold fails.
    public static func verifyWitnessCosignatures(_ sth: JSONValue?, _ policy: JObject?, _ pins: [String: String]? = nil) -> Bool {
        guard case let .object(sm)? = sth, let pol = policy else { return false }
        let pins = pins ?? policyPins(pol)
        guard let tf = IV.num(pol["threshold"]), tf == tf.rounded(.towardZero), tf >= 0 else { return false }
        if tf == 0 { return true }
        var trusted = Set<JKey>()
        if case let .array(ks)? = pol["witnessKeys"] { for k in ks { if let s = k.asString { trusted.insert(JKey(s)) } } }
        if trusted.isEmpty { return false }
        guard case let .array(ws)? = sm["witnesses"] else { return false }
        var counted = Set<JKey>()
        for w in ws {
            guard case let .object(wm) = w, let key = wm["key"]?.asString, wm["sig"]?.asString != nil else { continue }
            if !trusted.contains(JKey(key)) || counted.contains(JKey(key)) { continue }
            if !verifyWitnessCosignature(sth, w, key, pins) { continue }
            counted.insert(JKey(key))
            if Double(counted.count) >= tf { return true }
        }
        return Double(counted.count) >= tf
    }

    /// A guardian-signed tree head against the pinned guardian key: the head names that guardian, its size is a non-negative
    /// safe integer, the signature covers {instance_id, principal, size, root, prev_root, timestamp}, and, when `policy` is
    /// non-nil, enough trusted witnesses cosigned it.
    public static func verifyTreeHead(_ sth: JSONValue?, _ guardianPublic: String, _ policy: JObject?, _ pins: [String: String]? = nil) -> Bool {
        guard case let .object(m)? = sth else { return false }
        if !IV.same(m["guardian"]?.asString, guardianPublic) { return false }
        guard let sz = IV.safe(m["size"]), sz >= 0 else { return false }
        guard let body = pick(m, ["instance_id", "principal", "size", "root", "prev_root", "timestamp"]),
              signed(guardianPublic, STH_DOMAIN, body, m, pins) else { return false }
        // The guardian is verified under `pins` only; the cosigners fall back to the policy's own pins ONLY when `pins` is absent (nil), as
        // the reference does (`pin ?? policy`): an explicit empty set pins nothing.
        return policy == nil || verifyWitnessCosignatures(sth, policy, pins)
    }

    /// Both heads are genuine for the pinned guardian, belong to the same instance and log, the proof connects exactly their
    /// sizes, the signed prev_root equals older.root when the heads are adjacent, and the RFC 9162 path verifies.
    public static func verifyHeadConsistency(_ older: JSONValue?, _ newer: JSONValue?, _ proof: JSONValue?, _ guardianPublic: String, _ policy: JObject?, _ pins: [String: String]? = nil) -> Bool {
        guard verifyTreeHead(older, guardianPublic, policy, pins), verifyTreeHead(newer, guardianPublic, policy, pins),
              case let .object(om)? = older, case let .object(nm)? = newer, case let .object(pm)? = proof else { return false }
        if !same(om["instance_id"], nm["instance_id"]) || !same(om["principal"], nm["principal"]) { return false }
        let osz = IV.num(om["size"]), nsz = IV.num(nm["size"]), ps = IV.num(pm["oldSize"]), pn = IV.num(pm["newSize"])
        guard let o = osz, let n = nsz, let a = ps, let b = pn, a == o, b == n else { return false }
        if n == o + 1 && !same(nm["prev_root"], om["root"]) { return false }
        return verifyConsistency(om["root"], nm["root"], proof)
    }

    /// OK, or `at` = the index of the first checkpoint that fails.
    public struct CheckpointVerdict: Equatable { public let ok: Bool; public let at: Int }

    /// Pinned checkpoints end to end: every head is genuine (and witnessed when `policy` is non-nil), the first needs no proof,
    /// every later one carries a consistency proof from the checkpoint before. An empty or non-array chain fails at 0.
    public static func verifyCheckpointChain(_ chain: JSONValue?, _ guardianPublic: String, _ policy: JObject?, _ pins: [String: String]? = nil) -> CheckpointVerdict {
        guard case let .array(cs)? = chain, !cs.isEmpty else { return CheckpointVerdict(ok: false, at: 0) }
        var prev: JSONValue?
        for (i, c) in cs.enumerated() {
            guard case let .object(cm) = c, verifyTreeHead(cm["sth"], guardianPublic, policy, pins) else { return CheckpointVerdict(ok: false, at: i) }
            if i > 0 {
                let proof = cm["proof"]
                if proof == nil || proof == .null || proof == .bool(false) { return CheckpointVerdict(ok: false, at: i) }
                if !verifyHeadConsistency(prev, cm["sth"], proof, guardianPublic, policy, pins) { return CheckpointVerdict(ok: false, at: i) }
            }
            prev = cm["sth"]
        }
        return CheckpointVerdict(ok: true, at: 0)
    }
}
