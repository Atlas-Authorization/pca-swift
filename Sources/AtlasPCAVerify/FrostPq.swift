import Foundation

/// The post-quantum side of a FROST group: the group-algorithm registry (classical `ed25519`, or the hybrid that adds a guardian ML-DSA-65 co-signature over a
/// representative binding the group key, the message and the signer set), and the quorum block of `t` ML-DSA-65 signatures by distinct trusted keys.
public enum PCAFrostPq {
    public static let DEFAULT_FROST_GROUP_ALG = "ed25519"
    public static let PQ_QUORUM_VERSION = 2
    public static let PQ_QUORUM_ALG = "ml-dsa-65"
    public static let MAX_PQ_QUORUM_ENTRIES = 256
    static let COSIGN_DOMAIN = "atlas-pca/frost-pq-cosign/v1\u{0}"
    static let SIGNER_SET_DOMAIN = "atlas-pca/frost-signer-set/v1\u{0}"
    static let QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\u{0}"

    private static func b64(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }
    private static func known(_ x: String?) -> Bool { x == "ed25519" || x == "hybrid-ed25519-ml-dsa-65" }

    /// The group algorithm named by `groupAlg`: absent is the default; anything but a known name is nil.
    public static func resolveFrostGroupAlg(_ groupAlg: JSONValue?) -> String? {
        guard let g = groupAlg else { return DEFAULT_FROST_GROUP_ALG }
        return known(g.asString) ? g.asString : nil
    }

    /// sha256(domain || canonical JSON of the distinct identifiers in ascending order); throws for an empty set or an identifier that is not a positive safe integer.
    public static func frostSignerSetDigest(_ signerSet: JSONValue?) throws -> [UInt8] {
        guard case let .array(a)? = signerSet, !a.isEmpty else { throw JSError("frostSignerSetDigest: empty signer set") }
        var ids: [Int64] = []
        for v in a {
            guard v.isNumber, let d = IV.num(v), d == d.rounded(), d > 0, d <= 9_007_199_254_740_991 else {
                throw JSError("frostSignerSetDigest: participant identifiers must be positive safe integers")
            }
            if !ids.contains(Int64(d)) { ids.append(Int64(d)) }
        }
        ids.sort()
        return Canonical.sha256(Array(SIGNER_SET_DOMAIN.utf8) + Array(Canonical.canonicalize(.array(ids.map { .int($0) })).utf8))
    }

    /// The bytes the guardian ML-DSA key signs: domain, group algorithm, 0, group key, sha256(message), signer-set digest.
    public static func frostCosignRepresentative(_ groupPublicKey: JSONValue?, _ message: [UInt8]?, _ signerSet: JSONValue?, _ groupAlg: String?) throws -> [UInt8] {
        guard case let .string(g)? = groupPublicKey, let gpk = Base64URLStrict.decode(g, length: 32) else {
            throw JSError("frostCosignRepresentative: groupPublicKey must be a 32-byte base64url point")
        }
        let alg = groupAlg ?? "null"   // the reference's utf8(null) is the text "null"
        guard let m = message else { throw JSError("sha256: message must be bytes") }
        return Array(COSIGN_DOMAIN.utf8) + Array(alg.utf8) + [0] + gpk + Canonical.sha256(m) + (try frostSignerSetDigest(signerSet))
    }

    /// The FROST aggregate signature, plus under the hybrid algorithm the guardian's ML-DSA-65 co-signature and key: `{sig, groupAlg?, pq_sig?, pq_pk?}`.
    public static func signHybridFrostCosign(groupPublicKey: [UInt8], quorum: [PCAFrost.ParticipantShare], message: [UInt8], groupAlg: String? = nil, guardianMlDsa: PCAPQKey?,
                                             threshold: JSONValue? = nil) throws -> JSONValue {
        let alg = groupAlg ?? DEFAULT_FROST_GROUP_ALG
        guard known(alg) else { throw JSError("signHybridFrostCosign: unknown groupAlg '\(alg)'") }
        let sig = b64(try PCAFrost.cosign(groupPublicKey, quorum, message, threshold: threshold))
        if alg == "ed25519" { return .object(["sig": .string(sig)]) }
        guard let g = guardianMlDsa else { throw JSError("signHybridFrostCosign: '\(alg)' requires a guardian ML-DSA-65 key pair") }
        let rep = try frostCosignRepresentative(.string(b64(groupPublicKey)), message, .array(quorum.map { .int($0.identifier) }), alg)
        return .object(["sig": .string(sig), "groupAlg": .string(alg), "pq_sig": .string(b64(try g.signFn(rep))), "pq_pk": .string(g.pkB64u)])
    }

    /// `{ok, groupAlg?, edOk, pqOk, reason?}`: the Ed25519 group signature must verify and, under the hybrid, the guardian ML-DSA co-signature over the representative
    /// with the registered guardian key. Never throws.
    public static func verifyHybridFrostCosign(_ artifact: JSONValue?, _ message: [UInt8]?, _ groupPublicKey: JSONValue?, _ signerSet: JSONValue?,
                                               guardianPqPublicKey: JSONValue? = nil, expectGroupAlg: JSONValue? = nil) -> JSONValue {
        func deny(_ r: String, _ alg: String? = nil) -> JSONValue {
            PCAFrostNet.present([("ok", .bool(false)), ("edOk", .bool(false)), ("pqOk", .bool(false)), ("groupAlg", alg.map { .string($0) }), ("reason", .string(r))])
        }
        guard artifact?.isObject == true || artifact?.asArray != nil, case let .string(sig)? = artifact?.get("sig") else { return deny("malformed artifact") }
        guard case let .string(gtext)? = groupPublicKey, Base64URLStrict.decode(gtext, length: 32) != nil else { return deny("malformed group public key") }
        guard let alg = resolveFrostGroupAlg(artifact?.get("groupAlg")) else { return deny("unknown groupAlg '\(JS.toString(artifact?.get("groupAlg")))'") }
        if let e = expectGroupAlg {
            guard known(e.asString) else { return deny("unknown expected groupAlg '\(JS.toString(e))'") }
            if e.asString != alg { return deny("groupAlg '\(alg)' does not match the required '\(e.asString!)'", alg) }
        }
        let edOk = message.map { Ed25519Strict.verifyB64u(gtext, $0, sig) } ?? false
        func verdict(_ ok: Bool, _ ed: Bool, _ pq: Bool, _ reason: String?) -> JSONValue {
            PCAFrostNet.present([("ok", .bool(ok)), ("groupAlg", .string(alg)), ("edOk", .bool(ed)), ("pqOk", .bool(pq)), ("reason", reason.map { .string($0) })])
        }
        if alg == "ed25519" { return edOk ? verdict(true, true, false, nil) : deny("FROST Ed25519 group signature did not verify", alg) }
        guard case let .string(registered)? = guardianPqPublicKey, Base64URLStrict.decode(registered, length: PQ.ML_DSA_65_PUBLIC_KEY_BYTES) != nil else {
            return deny("hybrid groupAlg requires a registered guardian ML-DSA-65 public key", alg)
        }
        if let pk = artifact?.get("pq_pk"), !IV.same(pk.asString, registered) { return deny("artifact pq_pk does not match the registered guardian ML-DSA key", alg) }
        guard case let .string(pqSig)? = artifact?.get("pq_sig") else { return deny("hybrid groupAlg declared but the guardian ML-DSA co-signature is missing", alg) }
        var pqOk = false
        if let m = message, let rep = try? frostCosignRepresentative(groupPublicKey, m, signerSet, alg) { pqOk = MLDSA.verifyB64u(registered, rep, pqSig) }
        if !edOk || !pqOk { return verdict(false, edOk, pqOk, !edOk ? "FROST Ed25519 group signature did not verify" : "guardian ML-DSA-65 co-signature did not verify") }
        return verdict(true, true, true, nil)
    }

    // ---- the post-quantum quorum block ----

    public static func pqQuorumRepresentative(_ message: [UInt8]) -> [UInt8] { Array(QUORUM_DOMAIN.utf8) + Canonical.sha256(message) }

    /// `{v: 2, alg: "ml-dsa-65", pqT, signers: [{pk, sig}]}` signed by every key over the quorum representative; `pqT` defaults to the number of keys.
    public static func signPqQuorum(_ message: [UInt8], keys: [PCAPQKey], pqT: JSONValue? = nil) throws -> JSONValue {
        let rep = pqQuorumRepresentative(message)
        let signers: [JSONValue] = try keys.map { .object(["pk": .string($0.pkB64u), "sig": .string(b64(try $0.signFn(rep)))]) }
        return .object(["v": .int(Int64(PQ_QUORUM_VERSION)), "alg": .string(PQ_QUORUM_ALG), "pqT": pqT ?? .int(Int64(signers.count)), "signers": .array(signers)])
    }

    /// The keys of `pks` that are canonical ML-DSA-65 public keys, distinct, in first-seen order (a JavaScript Set iterates in insertion order).
    public static func normalizePqQuorumPool(_ pks: [JSONValue]) -> [String] {
        var pool: [String] = []
        for p in pks { if case let .string(s) = p, Base64URLStrict.decode(s, length: PQ.ML_DSA_65_PUBLIC_KEY_BYTES) != nil, !pool.contains(s) { pool.append(s) } }
        return pool
    }

    /// `{ok, count, need, reason?}`: at least `pqT` entries signed by distinct keys of the trusted pool, each over the quorum representative.
    public static func verifyPqQuorum(_ block: JSONValue?, _ message: [UInt8], trustedPool: Set<String>, pqT: JSONValue?) -> JSONValue {
        func res(_ ok: Bool, _ count: Int, _ reason: String? = nil) -> JSONValue {
            PCAFrostNet.present([("ok", .bool(ok)), ("count", .int(Int64(count))), ("need", pqT), ("reason", reason.map { .string($0) })])
        }
        guard let t = IV.safe(pqT), t == t.rounded(), t >= 1 else { return res(false, 0, "pqT must be a positive integer") }
        guard block?.isObject == true || block?.asArray != nil else { return res(false, 0, "malformed pq block") }
        guard let v = block?.get("v") else { return res(false, 0, "pq quorum version missing (pre-0.5 format is refused)") }
        if IV.num(v) == 1 { return res(false, 0, "pq quorum version 1 is no longer accepted (pre-0.5 format)") }
        if !(v.isNumber && IV.num(v) == Double(PQ_QUORUM_VERSION)) { return res(false, 0, "unsupported pq quorum version") }
        guard IV.same(block?.get("alg")?.asString, PQ_QUORUM_ALG), case let .array(entries)? = block?.get("signers") else { return res(false, 0, "malformed pq block") }
        let rep = pqQuorumRepresentative(message)
        var counted = Set<String>()
        for e in entries.prefix(MAX_PQ_QUORUM_ENTRIES) {
            guard e.isObject, case let .string(pk)? = e.get("pk"), case let .string(sig)? = e.get("sig") else { continue }
            if !trustedPool.contains(pk) || counted.contains(pk) { continue }
            if !MLDSA.verifyB64u(pk, rep, sig) { continue }
            counted.insert(pk)
        }
        if Double(counted.count) >= t { return res(true, counted.count) }
        return res(false, counted.count, "post-quantum quorum short: \(counted.count) of \(JS.toString(pqT)) required ML-DSA co-signatures")
    }
}
