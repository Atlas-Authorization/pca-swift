import Foundation
import CryptoKit

/// A key as a caller supplies it: its canonical base64url text, the raw bytes, or anything else (a number, null, an object: never a key).
public enum PQTKey {
    case b64u(String)
    case bytes([UInt8])
    case other

    /// The canonical-text form (raw bytes are encoded); nil for anything that is not a key.
    var text: String? {
        switch self {
        case let .b64u(s): return s
        case let .bytes(b): return Base64URLStrict.encode(b)
        case .other: return nil
        }
    }

    /// The text form when it is a canonical base64url value of exactly `length` bytes.
    func canonical(_ length: Int) -> String? {
        guard let s = text, Base64URLStrict.decode(s, length: length) != nil else { return nil }
        return s
    }
}

/// One participant of a FROST group: a positive safe integer identifier (kept as the raw value so a hostile one is refused) and its verification share.
public struct PQTParticipant {
    public var identifier: JSONValue?
    public var publicKey: PQTKey
    public init(identifier: JSONValue?, publicKey: PQTKey) { self.identifier = identifier; self.publicKey = publicKey }
}

/// The signed group descriptor that pins a FROST threshold to its group key. A FROST aggregate is a plain Ed25519 signature, so its threshold is a
/// label until an authority the verifier pins attests how the group was formed (a group dealt 1-of-n can self-sign a claim of 3-of-n).
public enum PCAGroupDescriptor {
    public static let VERSION: Int64 = 1
    public static let SUITE = "frost-ed25519"
    static let DESCRIPTOR_DOMAIN = "atlas-pca-pq-threshold/group-descriptor/v1\0"
    static let SIGNER_SET_DOMAIN = "atlas-pca-pq-threshold/signer-set/v1\0"
    public static let MAX_GROUP_SIZE = 1024

    /// `Number.isInteger`.
    static func isInteger(_ v: JSONValue?) -> Bool {
        guard let d = IV.num(v), d.isFinite else { return false }
        return d.rounded(.towardZero) == d
    }

    /// The JavaScript text of an integer-valued number (`${n}`).
    static func show(_ v: JSONValue?) -> String { IV.num(v).map { JS.number($0) } ?? "undefined" }

    /// An object or an array (`typeof x === 'object'` and not null).
    static func isObj(_ v: JSONValue?) -> Bool { v?.isObject == true || v?.isArray == true }

    private static func withDomain(_ domain: String, _ body: [UInt8]) -> [UInt8] { Canonical.utf8(domain) + body }

    private static func canon(_ v: JSONValue) throws -> [UInt8] {
        guard let c = IV.strictCanon(v) else { throw JSError("canonicalize: \(IV.strictCanonError(v) ?? "out of profile")") }
        return Canonical.utf8(c)
    }

    /// `sha256(DOMAIN || canonical(sorted [{id, pk}]))`: order-insensitive, identifiers distinct. A nil participant, a nil list, 0 or more than
    /// 1024 participants, a non-positive / non-integer / unsafe identifier, a duplicate and a verification share that is not a canonical
    /// base64url 32-byte value all throw.
    public static func signerSetCommitment(_ participants: [PQTParticipant?]?) throws -> String {
        guard let ps = participants, !ps.isEmpty, ps.count <= MAX_GROUP_SIZE else { throw JSError("signerSetCommitment: need 1..\(MAX_GROUP_SIZE) participants") }
        var rows: [(id: Int64, pk: String)] = []
        for p in ps {
            guard let p = p else { throw JSError("signerSetCommitment: participant is null") }
            guard JSLoose.isInt(p.identifier), let id = p.identifier?.safeInt, id > 0 else { throw JSError("signerSetCommitment: participant identifiers must be positive safe integers") }
            guard let pk = p.publicKey.canonical(32) else { throw JSError("signerSetCommitment: verification share is not a canonical b64u(32) value") }
            rows.append((id, pk))
        }
        rows.sort { $0.id < $1.id }
        for i in 1..<max(rows.count, 1) where rows[i].id == rows[i - 1].id { throw JSError("signerSetCommitment: duplicate participant identifier") }
        let body = try canon(.array(rows.map { .object(["id": .int($0.id), "pk": .string($0.pk)]) }))
        return Base64URLStrict.encode(Canonical.sha256(withDomain(SIGNER_SET_DOMAIN, body)))
    }

    private static func descriptorBytes(v: JSONValue?, suite: JSONValue?, groupPk: JSONValue?, t: JSONValue?, n: JSONValue?, signerSet: JSONValue?) throws -> [UInt8] {
        let body: JSONValue = .object(["v": v ?? .null, "suite": suite ?? .null, "group_pk": groupPk ?? .null, "t": t ?? .null, "n": n ?? .null, "signer_set": signerSet ?? .null])
        return withDomain(DESCRIPTOR_DOMAIN, try canon(body))
    }

    /// Issue a descriptor at dealing time: {descriptor: {v, suite, groupPublicKey, t, n, signerSetCommitment}, authority, sig}. Throws on an impossible group
    /// (t < 1, t > n, a non-canonical group key), a missing authority key and a bad signer set.
    public static func issueGroupDescriptor(authority: PCAEdKey?, groupPublicKey: PQTKey, t: JSONValue?, participants: [PQTParticipant?]?) throws -> JSONValue {
        guard let ps = participants else { throw JSError("issueGroupDescriptor: participants must be an array") }
        let n = ps.count
        guard isInteger(t), let td = IV.num(t), td >= 1, td <= Double(n) else { throw JSError("issueGroupDescriptor: need 1 <= t <= n (t=\(show(t)), n=\(n))") }
        guard let gpk = groupPublicKey.canonical(32) else { throw JSError("issueGroupDescriptor: group public key is not canonical b64u(32)") }
        guard let ak = authority else { throw JSError("issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key") }
        let commitment = try signerSetCommitment(ps)
        let ti = Int64(td)
        let sig = try ak.sign(try descriptorBytes(v: .int(VERSION), suite: .string(SUITE), groupPk: .string(gpk), t: .int(ti), n: .int(Int64(n)), signerSet: .string(commitment)))
        return .object([
            "descriptor": .object(["v": .int(VERSION), "suite": .string(SUITE), "groupPublicKey": .string(gpk), "t": .int(ti), "n": .int(Int64(n)), "signerSetCommitment": .string(commitment)]),
            "authority": .string(ak.id),
            "sig": .string(Base64URLStrict.encode(sig)),
        ])
    }

    private static func fail(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    /// Check a signed descriptor against the verifier's pins; never throws. `trustedAuthorities` are the pinned authority keys (nil = not a list),
    /// `groupKey` the pinned group key, `t` the threshold the verifier requires (the descriptor's must EQUAL it), `signerSetCommitment` an optional pin
    /// (nil = absent; any present value must equal the descriptor's). Returns {ok: true, descriptor} or {ok: false, reason}.
    public static func verifyGroupDescriptor(_ s: JSONValue?, trustedAuthorities: [PQTKey]?, groupKey: PQTKey, t: JSONValue?, signerSetCommitment pin: JSONValue? = nil) -> JSONValue {
        guard isObj(s) else { return fail("no signed group descriptor: the threshold is unattested") }
        let d = JSLoose.get(s, "descriptor")
        guard isObj(d), let authority = JSLoose.get(s, "authority")?.asString, let sig = JSLoose.get(s, "sig")?.asString else { return fail("malformed group descriptor") }
        guard IV.num(JSLoose.get(d, "v")) == Double(VERSION), let suite = JSLoose.get(d, "suite")?.asString, IV.same(suite, SUITE) else { return fail("unsupported group descriptor version or suite") }
        guard let gpk = JSLoose.get(d, "groupPublicKey")?.asString, let ssc = JSLoose.get(d, "signerSetCommitment")?.asString else { return fail("malformed group descriptor") }
        let dt = JSLoose.get(d, "t"), dn = JSLoose.get(d, "n")
        guard isInteger(dt), isInteger(dn), let tn = IV.num(dt), let nn = IV.num(dn), tn >= 1, nn >= tn, nn <= Double(MAX_GROUP_SIZE) else { return fail("malformed group descriptor: need 1 <= t <= n") }
        guard let trusted = trustedAuthorities else { return fail("group descriptor could not be verified (malformed)") }
        guard trusted.contains(where: { $0.text.map { IV.same($0, authority) } ?? false }) else { return fail("group descriptor authority is not trusted") }
        guard Base64URLStrict.decode(authority, length: 32) != nil, Base64URLStrict.decode(sig, length: 64) != nil else { return fail("malformed authority key or signature") }
        guard let msg = try? descriptorBytes(v: JSLoose.get(d, "v"), suite: .string(suite), groupPk: .string(gpk), t: dt, n: dn, signerSet: .string(ssc)) else { return fail("group descriptor could not be verified (malformed)") }
        guard Ed25519Strict.verifyB64u(authority, msg, sig) else { return fail("group descriptor signature does not verify") }
        guard let want = groupKey.text, IV.same(gpk, want) else { return fail("group descriptor is for a different group key") }
        guard isInteger(t), let rt = IV.num(t), rt >= 1 else { return fail("required t must be a positive integer") }
        guard tn == rt else { return fail("group was set up as \(show(dt))-of-\(show(dn)) but \(show(t)) is required: the threshold is not bound to this key") }
        if let p = pin, !(p.asString.map { IV.same($0, ssc) } ?? false) { return fail("group descriptor is for a different signer set") }
        return .object(["ok": .bool(true), "descriptor": d ?? .null])
    }
}

/// Post-quantum threshold step-up: a hybrid of a classical FROST(Ed25519) aggregate (verified as the plain Ed25519 signature it is, under the
/// verifier's pinned group key, with the threshold bound by a signed `PCAGroupDescriptor`) AND a pqT-of-m ML-DSA-65 co-signature quorum over the same
/// action digest. Both must hold; either short fails closed. The lattice-threshold research prototype of the reference is not carried.
public enum PCAPqThreshold {
    public static let HYBRID_ARTIFACT_VERSION: Int64 = 2
    public static let PQ_QUORUM_VERSION: Int64 = 2
    public static let MAX_PQ_QUORUM_ENTRIES = 256
    /// The cap on PQ co-signer entries (the reference: `MAX_PQ_SIGNER_ENTRIES = MAX_PQ_QUORUM_ENTRIES`).
    public static let MAX_PQ_SIGNER_ENTRIES = MAX_PQ_QUORUM_ENTRIES
    public static let HYBRID_CLASSICAL_ALG = "frost-ed25519"
    public static let PQ_QUORUM_ALG = "ml-dsa-65"
    static let PQ_QUORUM_DOMAIN = "atlas-pca/pq-quorum/v2\0"

    private typealias D = PCAGroupDescriptor

    private static func verdict(_ ok: Bool, _ count: Int64, _ need: JSONValue?, _ reason: String?) -> JSONValue {
        var m: JObject = ["ok": .bool(ok), "count": .int(count)]
        if let n = need { m["need"] = n }
        if let r = reason { m["reason"] = .string(r) }
        return .object(m)
    }

    /// The bytes every quorum co-signature covers: DOMAIN || sha256(message).
    public static func pqQuorumRepresentative(_ message: [UInt8]) -> [UInt8] { Canonical.utf8(PQ_QUORUM_DOMAIN) + Canonical.sha256(message) }

    /// The trusted pool as canonical base64url ML-DSA-65 public keys; anything that is not a well-formed key is ignored.
    public static func normalizePqQuorumPool(_ pks: [PQTKey]) -> Set<String> {
        var pool = Set<String>()
        for p in pks { if let s = p.canonical(MLDSA.PUBLIC_KEY_BYTES) { pool.insert(s) } }
        return pool
    }

    /// One ML-DSA-65 co-signature per key over the representative; `pqT` defaults to the signer count. Throws on a key of another level.
    public static func signPqQuorum(_ message: [UInt8], signers: [PCAPQKey], pqT: Int? = nil) throws -> JSONValue {
        let rep = pqQuorumRepresentative(message)
        var entries: [JSONValue] = []
        for k in signers {
            guard k.level == .mlDsa65 else { throw JSError("signPqQuorum: every co-signer must hold an ML-DSA-65 key") }
            entries.append(.object(["pk": .string(k.pkB64u), "sig": .string(Base64URLStrict.encode(try k.signFn(rep)))]))
        }
        return .object(["v": .int(PQ_QUORUM_VERSION), "alg": .string(PQ_QUORUM_ALG), "pqT": .int(Int64(pqT ?? entries.count)), "signers": .array(entries)])
    }

    /// Count DISTINCT trusted keys whose co-signature verifies over `message`; ok iff the count reaches `pqT`. Total: never throws. A key outside the pool,
    /// a repeated key, a signature over another message and every malformed entry count for nothing; a block whose version is missing, 1 or unknown is
    /// refused before any verification. Returns {ok, count, need?, reason?}.
    public static func verifyPqQuorum(_ block: JSONValue?, message: [UInt8], pool: Set<String>, pqT: JSONValue?) -> JSONValue {
        guard D.isInteger(pqT), let need = IV.num(pqT), need >= 1 else { return verdict(false, 0, pqT, "pqT must be a positive integer") }
        guard D.isObj(block) else { return verdict(false, 0, pqT, "malformed pq block") }
        guard let v = JSLoose.get(block, "v") else { return verdict(false, 0, pqT, "pq quorum version missing (pre-0.5 format is refused)") }
        let vn = IV.num(v)
        if vn == 1 { return verdict(false, 0, pqT, "pq quorum version 1 is no longer accepted (pre-0.5 format)") }
        guard vn == Double(PQ_QUORUM_VERSION) else { return verdict(false, 0, pqT, "unsupported pq quorum version") }
        guard let alg = JSLoose.get(block, "alg")?.asString, IV.same(alg, PQ_QUORUM_ALG), let signers = JSLoose.get(block, "signers")?.asArray else { return verdict(false, 0, pqT, "malformed pq block") }
        let rep = pqQuorumRepresentative(message)
        var counted = Set<String>()
        for (i, entry) in signers.enumerated() {
            if i >= MAX_PQ_QUORUM_ENTRIES { break }
            guard let pk = entry.get("pk")?.asString, let sig = entry.get("sig")?.asString else { continue }
            if !pool.contains(pk) || counted.contains(pk) { continue }
            if !MLDSA.verifyB64u(pk, rep, sig) { continue }
            counted.insert(pk)
        }
        let count = Int64(counted.count)
        if Double(count) >= need { return verdict(true, count, pqT, nil) }
        return verdict(false, count, pqT, "post-quantum quorum short: \(count) of \(D.show(pqT)) required ML-DSA co-signatures")
    }

    // MARK: hybrid

    /// The verifier's pins for `verifyHybridThreshold` (every field a wire / config value; nil = absent or not of the required kind).
    public struct HybridOpts {
        public var groupKey: PQTKey
        public var pqPublicKeys: [PQTKey]?
        public var t: JSONValue?
        public var pqT: JSONValue?
        public var groupDescriptor: JSONValue?
        public var trustedAuthorities: [PQTKey]?
        public var signerSetCommitment: JSONValue?
        public init(groupKey: PQTKey, pqPublicKeys: [PQTKey]?, t: JSONValue?, pqT: JSONValue?, groupDescriptor: JSONValue?, trustedAuthorities: [PQTKey]?, signerSetCommitment: JSONValue? = nil) {
            self.groupKey = groupKey; self.pqPublicKeys = pqPublicKeys; self.t = t; self.pqT = pqT
            self.groupDescriptor = groupDescriptor; self.trustedAuthorities = trustedAuthorities; self.signerSetCommitment = signerSetCommitment
        }
    }

    private static func descriptorReason(_ o: HybridOpts) -> String? {
        let r = D.verifyGroupDescriptor(o.groupDescriptor, trustedAuthorities: o.trustedAuthorities, groupKey: o.groupKey, t: o.t, signerSetCommitment: o.signerSetCommitment)
        return r.get("ok") == .bool(true) ? nil : r.get("reason")?.asString
    }

    private static func malformed() -> JSONValue {
        let reason = "malformed action or verifier options"
        return .object(["ok": .bool(false), "frost": .bool(false), "pq": verdict(false, 0, .int(0), reason), "reason": .string(reason)])
    }

    /// Verify a standalone hybrid artifact over `action` (a PCActn or its body). BOTH the classical aggregate and the pqT-of-m quorum must hold; the
    /// declared classical threshold must not be below the required t (downgrade). Never throws: malformed input is a refusal. Returns {ok, frost, pq, reason?}.
    public static func verifyHybridThreshold(action: JSONValue?, artifact: JSONValue?, opts: HybridOpts) -> JSONValue {
        let hasV = artifact?.isObject == true && artifact?.get("v") != nil
        let vn = IV.num(JSLoose.get(artifact, "v"))
        if !hasV || vn != Double(HYBRID_ARTIFACT_VERSION) {
            let reason = !hasV ? "artifact version missing (pre-0.5 format is refused)" : vn == 1 ? "artifact version 1 is no longer accepted (pre-0.5 format)" : "unsupported artifact version"
            return .object(["ok": .bool(false), "frost": .bool(false), "pq": verdict(false, 0, opts.pqT, reason), "reason": .string(reason)])
        }
        guard let a = action?.asObject, let message = try? PCA.thresholdMessage(a), let keys = opts.pqPublicKeys else { return malformed() }
        let pool = normalizePqQuorumPool(keys)
        let trustedGroupKey = opts.groupKey.canonical(32)
        let frost = JSLoose.get(artifact, "frost")
        var frostOk = false
        var frostReason: String?
        if !D.isInteger(opts.t) || (IV.num(opts.t) ?? 0) < 1 {
            frostReason = "t must be a positive integer"
        } else if trustedGroupKey == nil {
            frostReason = "trusted FROST group key is not a canonical b64u(32) point"
        } else if !D.isObj(frost) || !(JSLoose.get(frost, "alg")?.asString.map { IV.same($0, HYBRID_CLASSICAL_ALG) } ?? false) {
            frostReason = "malformed or missing FROST part"
        } else if let why = descriptorReason(opts) {
            frostReason = why
        } else if !D.isInteger(JSLoose.get(frost, "t")) || (IV.num(JSLoose.get(frost, "t")) ?? 0) < (IV.num(opts.t) ?? 0) {
            frostReason = "FROST declared threshold \(D.show(JSLoose.get(frost, "t"))) is below the required t=\(D.show(opts.t)) (downgrade)"
        } else if !(JSLoose.get(frost, "sig")?.asString.map { Ed25519Strict.verifyB64u(trustedGroupKey ?? "", message, $0) } ?? false) {
            frostReason = "FROST aggregate does not verify under the trusted group key (quorum short, wrong group, or forged)"
        } else {
            frostOk = true
        }
        let pq = verifyPqQuorum(JSLoose.get(artifact, "pq"), message: message, pool: pool, pqT: opts.pqT)
        let ok = frostOk && pq.get("ok") == .bool(true)
        var out: JObject = ["ok": .bool(ok), "frost": .bool(frostOk), "pq": pq]
        if !ok, let r = frostOk ? pq.get("reason")?.asString : frostReason { out["reason"] = .string(r) }
        return .object(out)
    }

    /// Assemble a hybrid artifact from a FROST aggregate and the ML-DSA co-signers. Fails closed: a sub-threshold quorum count, no co-signer, a group key
    /// that is not 32 bytes, or an aggregate that does not verify under the group key all throw.
    public static func hybridThresholdAssemble(action: JObject, groupPublicKey: [UInt8], frostAggregate: [UInt8], t: Int, quorum: Int, pqSigners: [PCAPQKey], pqT: Int? = nil) throws -> JSONValue {
        guard t >= 1 else { throw JSError("hybridThresholdAssemble: t must be a positive integer (got \(t))") }
        guard quorum >= t else { throw JSError("hybridThresholdAssemble: FROST quorum of \(quorum) is below the threshold t=\(t)") }
        guard !pqSigners.isEmpty else { throw JSError("hybridThresholdAssemble: at least one ML-DSA co-signer is required") }
        guard groupPublicKey.count == 32 else { throw JSError("hybridThresholdAssemble: FROST group public key must be 32 bytes") }
        let message = try PCA.thresholdMessage(action)
        guard Ed25519Strict.verifyB64u(Base64URLStrict.encode(groupPublicKey), message, Base64URLStrict.encode(frostAggregate)) else {
            throw JSError("hybridThresholdAssemble: the FROST aggregate does not verify under the group key")
        }
        let frost: JSONValue = .object(["alg": .string(HYBRID_CLASSICAL_ALG), "group_pk": .string(Base64URLStrict.encode(groupPublicKey)), "sig": .string(Base64URLStrict.encode(frostAggregate)), "t": .int(Int64(t)), "quorum": .int(Int64(quorum))])
        return .object(["v": .int(HYBRID_ARTIFACT_VERSION), "digest": .string(Base64URLStrict.encode(Canonical.sha256(message))), "frost": frost, "pq": try signPqQuorum(message, signers: pqSigners, pqT: pqT)])
    }

    /// A hybrid artifact for `action`: the FROST t-of-n aggregate over the action message (produced here by `PCAFrost.cosign`, which throws on a short
    /// quorum or an invalid share) plus one ML-DSA-65 co-signature per signer over the same message.
    public static func hybridThresholdSign(action: JObject, groupPublicKey: [UInt8], quorum: [PCAFrost.ParticipantShare], t: Int, pqSigners: [PCAPQKey], pqT: Int? = nil) throws -> JSONValue {
        guard t >= 1 else { throw JSError("hybridThresholdSign: frost.t must be a positive integer (got \(t))") }
        guard quorum.count >= t else { throw JSError("hybridThresholdSign: FROST quorum of \(quorum.count) is below the threshold t=\(t)") }
        guard !pqSigners.isEmpty else { throw JSError("hybridThresholdSign: at least one ML-DSA co-signer is required") }
        guard groupPublicKey.count == 32 else { throw JSError("hybridThresholdSign: FROST group public key must be 32 bytes") }
        let message = try PCA.thresholdMessage(action)
        let aggregate = try PCAFrost.cosign(groupPublicKey, quorum, message, threshold: .int(Int64(t)))
        return try hybridThresholdAssemble(action: action, groupPublicKey: groupPublicKey, frostAggregate: aggregate, t: t, quorum: quorum.count, pqSigners: pqSigners, pqT: pqT)
    }

    /// Fold a hybrid artifact into a PCActn step-up: the FROST aggregate becomes a 'guardian' share (publicKey = the group key, sig = the aggregate) in
    /// `threshold.shares`; the signed message excludes `threshold`, so neither quorum's signed bytes change. The PQ block rides alongside.
    public static func foldHybridStepUp(action: JObject, artifact: JSONValue) throws -> (pcactn: JSONValue, pq: JSONValue?) {
        guard let f = artifact.get("frost")?.asObject else { throw JSError("foldHybridStepUp: artifact has no FROST part") }
        var share: JObject = ["role": .string("guardian")]
        if let g = f["group_pk"] { share["publicKey"] = g }
        if let s = f["sig"] { share["sig"] = s }
        var shares = action["threshold"]?.get("shares")?.asArray ?? []
        shares.append(.object(share))
        var pcactn = action
        pcactn["threshold"] = .object(["shares": .array(shares)])
        let pq = artifact.get("pq")
        return (.object(pcactn), (pq == nil || pq == .null) ? nil : pq)
    }

    /// The core verifier's threshold hook enforcing the hybrid step-up on one PCActn: the FROST aggregate folded into `pcactn.threshold` (a plain Ed25519
    /// signature under the TRUSTED group key) AND the ML-DSA quorum block. Always enforced; ok only when both hold. `pqBlock` is the block that rode alongside.
    /// Throws (like the reference factory) when `pqPublicKeys` is not a list.
    public static func thresholdHook(_ opts: HybridOpts, pqBlock: JSONValue?) throws -> (_ pcactn: JSONValue) -> (enforced: Bool, ok: Bool, reason: String?) {
        guard let keys = opts.pqPublicKeys else { throw JSError("pqPublicKeys is not iterable") }
        let pool = normalizePqQuorumPool(keys)
        let trusted = opts.groupKey.canonical(32)
        return { pcactn in
            if let why = descriptorReason(opts) { return (true, false, why) }
            guard let p = pcactn.asObject, let message = try? PCA.thresholdMessage(p) else { return (true, false, "malformed PCActn") }
            guard let tk = trusted else { return (true, false, "trusted FROST group key is not a canonical b64u(32) point") }
            var found: String?
            if let shares = pcactn.get("threshold")?.get("shares")?.asArray {
                for s in shares {
                    if let sig = s.get("sig")?.asString, let pk = s.get("publicKey")?.asString, IV.same(pk, tk) { found = sig; break }
                }
            }
            guard let sig = found else { return (true, false, "no FROST aggregate for the trusted group key in the step-up") }
            guard Ed25519Strict.verifyB64u(tk, message, sig) else { return (true, false, "FROST aggregate does not verify under the trusted group key (quorum short or forged)") }
            let pq = verifyPqQuorum(pqBlock, message: message, pool: pool, pqT: opts.pqT)
            guard pq.get("ok") == .bool(true) else { return (true, false, pq.get("reason")?.asString ?? "post-quantum quorum short") }
            return (true, true, nil)
        }
    }
}
