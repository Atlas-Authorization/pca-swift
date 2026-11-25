import Foundation
import CryptoKit
import Clibsodium

/// FROST threshold signatures for Ed25519 (RFC 9591, FROST(Ed25519, SHA-512)): trusted-dealer key split, round 1 (commit), round 2
/// (sign), aggregation into one ordinary 64-byte Ed25519 signature under the group key, and the per-share check. All group and scalar
/// arithmetic is libsodium's (crypto_core_ed25519_*, crypto_scalarmult_ed25519_*noclamp): nothing here is a hand-rolled primitive.
///
/// Every point a caller can influence goes through `decodeSafePoint` (canonical, on the curve, not small order, prime-order subgroup).
/// Identifiers are positive safe integers. Nonces are one-shot: zeroed after use, and a byte-clone is refused by its public commitment
/// (per process; callers must not persist nonces). Secrets are ordinary Swift arrays: no constant-time or zeroisation guarantee beyond
/// the nonce wipe (shortcut: use a platform enclave for the share when that matters).
public enum PCAFrost {
    static let CTX = Array("FROST-ED25519-SHA512-v1".utf8)
    static let identity: [UInt8] = [1] + [UInt8](repeating: 0, count: 31)
    /// 2^53 - 1: a JS safe integer.
    static let MAX_ID: Int64 = 9_007_199_254_740_991
    public static let SPENT_COMMITMENT_CAP = 262_144
    /// The prime order of the Ed25519 base-point subgroup, L = 2^252 + 27742317777372353535851937790883648493, as 32 little-endian bytes.
    public static let L: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]

    public struct ParticipantShare { public var identifier: Int64; public var share: [UInt8]; public var publicKey: [UInt8]
        public init(identifier: Int64, share: [UInt8], publicKey: [UInt8]) { self.identifier = identifier; self.share = share; self.publicKey = publicKey } }
    public struct Commitment { public var identifier: Int64; public var hiding: [UInt8]; public var binding: [UInt8]
        public init(identifier: Int64, hiding: [UInt8], binding: [UInt8]) { self.identifier = identifier; self.hiding = hiding; self.binding = binding } }
    public struct SigShare { public var identifier: Int64; public var sigShare: [UInt8]
        public init(identifier: Int64, sigShare: [UInt8]) { self.identifier = identifier; self.sigShare = sigShare } }
    public struct VerificationShare { public var identifier: Int64; public var publicKey: [UInt8]
        public init(identifier: Int64, publicKey: [UInt8]) { self.identifier = identifier; self.publicKey = publicKey } }
    public struct KeygenResult { public var groupPublicKey: [UInt8]; public var participantShares: [ParticipantShare]; public var groupCommitment: [[UInt8]] }
    public struct CommitResult { public var hidingNonce: [UInt8]; public var bindingNonce: [UInt8]; public var commitment: Commitment }
    public struct SignOpts {
        public var threshold: JSONValue?
        public var verificationShare: [UInt8]?
        public var verificationShares: [VerificationShare]?
        public init(threshold: JSONValue? = nil, verificationShare: [UInt8]? = nil, verificationShares: [VerificationShare]? = nil) {
            self.threshold = threshold; self.verificationShare = verificationShare; self.verificationShares = verificationShares }
    }
    /// A signer's secret nonce pair for one session; frozen (zeroed) by `sign`.
    public final class Nonces {
        public var hiding: [UInt8]; public var binding: [UInt8]
        public init(hiding: [UInt8], binding: [UInt8]) { self.hiding = hiding; self.binding = binding }
    }

    private static let ready: Bool = sodium_init() >= 0
    private static func ensure() { precondition(ready, "libsodium failed to initialise") }
    private static let lock = NSLock()
    private static var spent: [String] = []
    private static var spentSet = Set<String>()

    // ---- scalars (32-byte little endian, always canonical) ----

    static func isZero(_ b: [UInt8]) -> Bool { b.allSatisfy { $0 == 0 } }
    static func sAdd(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { ensure(); var z = [UInt8](repeating: 0, count: 32); crypto_core_ed25519_scalar_add(&z, a, b); return z }
    static func sSub(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { ensure(); var z = [UInt8](repeating: 0, count: 32); crypto_core_ed25519_scalar_sub(&z, a, b); return z }
    static func sMul(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] { ensure(); var z = [UInt8](repeating: 0, count: 32); crypto_core_ed25519_scalar_mul(&z, a, b); return z }
    static func sInv(_ a: [UInt8]) throws -> [UInt8] {
        ensure(); var z = [UInt8](repeating: 0, count: 32)
        guard crypto_core_ed25519_scalar_invert(&z, a) == 0 else { throw JSError("frost: modular inverse of zero") }
        return z
    }

    /// 0..64 little-endian bytes reduced mod L (65 or more is refused).
    public static func bytesToScalar(_ b: [UInt8]) throws -> [UInt8] {
        ensure()
        guard b.count <= 64 else { throw JSError("frost: scalar input longer than 64 bytes") }
        if b.isEmpty { return [UInt8](repeating: 0, count: 32) }
        var wide = b + [UInt8](repeating: 0, count: 64 - b.count)
        var z = [UInt8](repeating: 0, count: 32)
        crypto_core_ed25519_scalar_reduce(&z, &wide)
        return z
    }
    static func scalarOf(id: Int64) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var v = id.magnitude
        for i in 0..<8 { out[i] = UInt8(v & 0xff); v >>= 8 }
        // a negative id is the scalar's additive inverse mod L (BigInt(id) reduced in the reference), never a trap
        if id < 0 { var neg = [UInt8](repeating: 0, count: 32); crypto_core_ed25519_scalar_negate(&neg, out); return neg }
        return out
    }
    /// True iff `b` is exactly 32 bytes encoding a scalar < L.
    public static func isCanonicalScalar(_ b: [UInt8]?) -> Bool {
        guard let b = b, b.count == 32 else { return false }
        // L = 2^252 + 27742317777372353535851937790883648493, little endian
        let L: [UInt8] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]
        for i in stride(from: 31, through: 0, by: -1) where b[i] != L[i] { return b[i] < L[i] }
        return false
    }

    // ---- points (32-byte encodings; the identity is `identity`) ----

    public static func mulBase(_ s: [UInt8]) -> [UInt8] {
        ensure()
        if isZero(s) { return identity }
        var q = [UInt8](repeating: 0, count: 32)
        return crypto_scalarmult_ed25519_base_noclamp(&q, s) == 0 ? q : identity
    }
    static func mulPoint(_ p: [UInt8], _ s: [UInt8]) throws -> [UInt8] {
        ensure()
        if isZero(s) || p == identity { return identity }
        var q = [UInt8](repeating: 0, count: 32)
        guard crypto_scalarmult_ed25519_noclamp(&q, s, p) == 0 else { throw JSError("frost: point multiplication refused") }
        return q
    }
    static func add(_ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
        ensure()
        if a == identity { return b }
        if b == identity { return a }
        var r = [UInt8](repeating: 0, count: 32)
        guard crypto_core_ed25519_add(&r, a, b) == 0 else { throw JSError("frost: point addition refused") }
        return r
    }

    /// k * P by double-and-add over the plain group law (crypto_core_ed25519_add needs only a point on the curve), most significant bit first.
    /// The result is the 32-byte encoding, or nil for the identity. Public points only: not constant time.
    static func mulPlain(_ p: [UInt8], _ k: [UInt8]) -> [UInt8]? {
        func add(_ a: [UInt8], _ b: [UInt8]) -> [UInt8]? {
            var r = [UInt8](repeating: 0, count: 32)
            return crypto_core_ed25519_add(&r, a, b) == 0 && r != identity ? r : nil
        }
        var acc: [UInt8]? = nil
        for byte in k.reversed() {
            for bit in stride(from: 7, through: 0, by: -1) {
                if let a = acc { acc = add(a, a) }
                if (byte >> UInt8(bit)) & 1 == 1 { if let a = acc { acc = add(a, p) } else { acc = p } }
            }
        }
        return acc
    }

    /// Strict point decode: 32 bytes, canonical, on the curve, not small order (so not the identity), in the prime-order subgroup.
    /// The torsion and small-order tests use the group law alone, so a mixed-order point is refused whatever libsodium's validity query answers
    /// (1.0.20's subgroup test looks only at the X coordinate of L*P, which an order-2 torsion component leaves at zero).
    @discardableResult
    public static func decodeSafePoint(_ b: [UInt8]?) throws -> [UInt8] {
        ensure()
        guard let b = b, b.count == 32 else { throw JSError("frost: point must be 32 bytes") }
        // on the curve, and canonical: adding the identity re-encodes the point, which must give back the same bytes
        var re = [UInt8](repeating: 0, count: 32)
        guard crypto_core_ed25519_add(&re, b, identity) == 0 else { throw JSError("frost: point is not on the curve") }
        guard re == b else { throw JSError("frost: non-canonical point encoding") }
        // small order: 8*P is the identity
        guard mulPlain(b, [8] + [UInt8](repeating: 0, count: 31)) != nil else { throw JSError("frost: small-order point rejected") }
        // prime-order subgroup: L*P is the identity
        guard mulPlain(b, L) == nil else { throw JSError("frost: point is not in the prime-order subgroup") }
        guard crypto_core_ed25519_is_valid_point(b) == 1 else { throw JSError("frost: point rejected (not a valid prime-order point)") }
        return b
    }

    // ---- ciphersuite hashes (RFC 9591 section 6.1) ----

    static func sha512(_ m: [UInt8]) -> [UInt8] { Array(SHA512.hash(data: m)) }
    static func hashToScalar(_ m: [UInt8]) throws -> [UInt8] { try bytesToScalar(sha512(m)) }
    public static func H1(_ m: [UInt8]) throws -> [UInt8] { try hashToScalar(CTX + Array("rho".utf8) + m) }
    public static func H2(_ m: [UInt8]) throws -> [UInt8] { try hashToScalar(m) }
    public static func H3(_ m: [UInt8]) throws -> [UInt8] { try hashToScalar(CTX + Array("nonce".utf8) + m) }
    public static func H4(_ m: [UInt8]) -> [UInt8] { sha512(CTX + Array("msg".utf8) + m) }
    public static func H5(_ m: [UInt8]) -> [UInt8] { sha512(CTX + Array("com".utf8) + m) }

    static func assertValidId(_ id: Int64) throws {
        guard id > 0, id <= MAX_ID else { throw JSError("frost: participant identifier must be a positive safe integer") }
    }

    /// A threshold JS number: a safe integer >= 1, else a refusal (nil = absent).
    static func thresholdValue(_ t: JSONValue?) throws -> Int? {
        guard let t = t else { return nil }
        guard let n = t.safeInt, n >= 1 else { throw JSError("frost: invalid threshold") }
        return Int(n)
    }

    static func validateCommitments(_ list: [Commitment], threshold: JSONValue? = nil) throws {
        guard !list.isEmpty else { throw JSError("frost: empty commitment list") }
        if let t = try thresholdValue(threshold), list.count < t { throw JSError("frost: need at least t=\(t) commitments (got \(list.count))") }
        var seen = Set<Int64>()
        for c in list {
            try assertValidId(c.identifier)
            guard seen.insert(c.identifier).inserted else { throw JSError("frost: duplicate commitment identifier \(c.identifier)") }
            try decodeSafePoint(c.hiding)
            try decodeSafePoint(c.binding)
        }
    }

    // ---- key generation ----

    public static func randomScalar() throws -> [UInt8] {
        var b = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { b[i] = UInt8.random(in: 0...255) }
        return try bytesToScalar(b)
    }

    /// Trusted-dealer t-of-n split: f(x) = a0 + a1 x + ..., share_i = f(i), group key = a0*B. `secret` / `coefficients` fix the polynomial.
    public static func trustedDealerKeygen(t: Int64, n: Int64, secret: [UInt8]? = nil, coefficients: [[UInt8]]? = nil, identifiers: [Int64]? = nil) throws -> KeygenResult {
        guard t >= 1, n >= t, n <= 100_000 else { throw JSError("frostTrustedDealerKeygen: need 1 <= t <= n (got t=\(t), n=\(n))") }
        let ids = identifiers ?? (1...n).map { $0 }
        guard Int64(ids.count) == n else { throw JSError("frostTrustedDealerKeygen: identifiers.length must equal n") }
        guard Set(ids).count == ids.count else { throw JSError("frostTrustedDealerKeygen: identifiers must be distinct") }
        guard ids.allSatisfy({ $0 > 0 && $0 <= MAX_ID }) else { throw JSError("frostTrustedDealerKeygen: identifiers must be positive integers") }
        var coeffs: [[UInt8]] = [try secret.map(bytesToScalar) ?? randomScalar()]
        for i in 1..<Int(max(t, 1)) {
            if let c = (coefficients != nil && i - 1 < coefficients!.count) ? coefficients![i - 1] : nil { coeffs.append(try bytesToScalar(c)) }
            else { coeffs.append(try randomScalar()) }
        }
        let shares = ids.map { id -> ParticipantShare in
            let x = scalarOf(id: id)
            var acc = [UInt8](repeating: 0, count: 32)
            for a in coeffs.reversed() { acc = sAdd(sMul(acc, x), a) }
            return ParticipantShare(identifier: id, share: acc, publicKey: mulBase(acc))
        }
        let gc = coeffs.map(mulBase)
        return KeygenResult(groupPublicKey: gc[0], participantShares: shares, groupCommitment: gc)
    }

    /// The verification share of a secret signing share: share*B (a raw scalar, not a clamped Ed25519 secret).
    public static func verifyingShare(_ share: [UInt8]) throws -> [UInt8] { mulBase(try bytesToScalar(share)) }

    // ---- round 1 ----

    static func nonceGenerate(_ randomness: [UInt8], _ secretShare: [UInt8]) throws -> [UInt8] {
        guard randomness.count == 32 else { throw JSError("frostCommit: nonce randomness must be 32 bytes") }
        return try H3(randomness + (try bytesToScalar(secretShare)))
    }

    public static func commit(_ p: ParticipantShare, hidingRandomness: [UInt8]? = nil, bindingRandomness: [UInt8]? = nil) throws -> CommitResult {
        let hr = try hidingRandomness ?? randomScalar()
        let br = try bindingRandomness ?? randomScalar()
        let h = try nonceGenerate(hr, p.share), b = try nonceGenerate(br, p.share)
        return CommitResult(hidingNonce: h, bindingNonce: b, commitment: Commitment(identifier: p.identifier, hiding: mulBase(h), binding: mulBase(b)))
    }

    // ---- binding factors, group commitment, challenge ----

    static func sorted(_ l: [Commitment]) -> [Commitment] { l.sorted { $0.identifier < $1.identifier } }

    static func bindingFactors(_ group: [UInt8], _ list: [Commitment], _ msg: [UInt8]) throws -> [Int64: [UInt8]] {
        var enc: [UInt8] = []
        for c in list { enc += scalarOf(id: c.identifier) + c.hiding + c.binding }
        let prefix = group + H4(msg) + H5(enc)
        var out: [Int64: [UInt8]] = [:]
        for c in list { out[c.identifier] = try H1(prefix + scalarOf(id: c.identifier)) }
        return out
    }

    static func groupCommitment(_ list: [Commitment], _ bf: [Int64: [UInt8]]) throws -> [UInt8] {
        var r = identity
        for c in list {
            guard let f = bf[c.identifier] else { throw JSError("frost: missing binding factor") }
            r = try add(add(r, decodeSafePoint(c.hiding)), mulPoint(decodeSafePoint(c.binding), f))
        }
        return r
    }

    static func interpolatingValue(_ participants: [Int64], _ i: Int64) throws -> [UInt8] {
        guard participants.contains(i) else { throw JSError("frost: identifier not in participant list") }
        var num = scalarOf(id: 1), den = scalarOf(id: 1)
        let xi = scalarOf(id: i)
        for j in participants where j != i {
            let xj = scalarOf(id: j)
            num = sMul(num, xj)
            den = sMul(den, sSub(xj, xi))
        }
        let lam = sMul(num, try sInv(den))
        guard !isZero(lam) else { throw JSError("frost: zero Lagrange coefficient") }
        return lam
    }

    // ---- round 2 ----

    private static func commitmentKey(_ kind: String, _ p: [UInt8]) -> String { kind + p.map { String(format: "%02x", $0) }.joined() }

    /// One-shot signing share z_i = hiding + binding*bf + lambda*share*c. The nonces are zeroed afterwards and their commitments recorded.
    public static func sign(_ identifier: Int64, _ share: [UInt8], _ groupPublicKey: [UInt8], _ nonces: Nonces?, _ message: [UInt8],
                            _ signingCommitments: [Commitment], _ opts: SignOpts = SignOpts()) throws -> SigShare {
        try assertValidId(identifier)
        try validateCommitments(signingCommitments, threshold: opts.threshold)
        try decodeSafePoint(groupPublicKey)
        guard let nonces = nonces else { throw JSError("frostSign: malformed nonces") }
        if isZero(nonces.hiding) || isZero(nonces.binding) { throw JSError("frostSign: zero/zeroized nonce (one-shot; reuse would leak the signing share)") }
        if nonces.hiding == nonces.binding { throw JSError("frostSign: hiding and binding nonce must differ") }
        let list = sorted(signingCommitments)
        guard let mine = list.first(where: { $0.identifier == identifier }) else { throw JSError("frostSign: this identifier has no commitment in the set") }
        let hiding = try bytesToScalar(nonces.hiding), binding = try bytesToScalar(nonces.binding), sk = try bytesToScalar(share)
        guard mulBase(hiding) == (try decodeSafePoint(mine.hiding)), mulBase(binding) == (try decodeSafePoint(mine.binding)) else {
            throw JSError("frostSign: own commitment does not match nonces")
        }
        let hKey = commitmentKey("h", mine.hiding), bKey = commitmentKey("b", mine.binding)
        lock.lock(); let used = spentSet.contains(hKey) || spentSet.contains(bKey); lock.unlock()
        if used { throw JSError("frostSign: nonces already used (one-shot; reuse would leak the signing share)") }
        if let vs = opts.verificationShare, mulBase(sk) != (try decodeSafePoint(vs)) { throw JSError("frostSign: share does not match verification share") }
        let participants = list.map { $0.identifier }
        if let all = opts.verificationShares {
            var acc = identity
            for id in participants {
                guard let vs = all.first(where: { $0.identifier == id }) else { throw JSError("frostSign: missing verification share for \(id)") }
                acc = try add(acc, mulPoint(decodeSafePoint(vs.publicKey), interpolatingValue(participants, id)))
            }
            guard acc == (try decodeSafePoint(groupPublicKey)) else { throw JSError("frostSign: group public key does not match the verification shares") }
        }
        let bfs = try bindingFactors(groupPublicKey, list, message)
        guard let bf = bfs[identifier] else { throw JSError("frost: missing binding factor") }
        let R = try groupCommitment(list, bfs)
        let lambda = try interpolatingValue(participants, identifier)
        let c = try H2(R + groupPublicKey + message)
        let z = sAdd(sAdd(hiding, sMul(binding, bf)), sMul(sMul(lambda, sk), c))
        lock.lock()
        for k in [hKey, bKey] where spentSet.insert(k).inserted {
            spent.append(k)
            if spent.count > SPENT_COMMITMENT_CAP { spentSet.remove(spent.removeFirst()) }
        }
        lock.unlock()
        nonces.hiding = [UInt8](repeating: 0, count: nonces.hiding.count)
        nonces.binding = [UInt8](repeating: 0, count: nonces.binding.count)
        return SigShare(identifier: identifier, sigShare: z)
    }

    // ---- aggregation / share check ----

    /// Check one signature share: z_i*B == (hiding_i + bf_i*binding_i) + (c*lambda_i)*PK_i. Never throws; any malformed input is false.
    public static func verifySigShare(identifier: Int64, publicKey: [UInt8], commitment: Commitment, sigShare: SigShare,
                                      signingCommitments: [Commitment], groupPublicKey: [UInt8], message: [UInt8]) -> Bool {
        do {
            try validateCommitments(signingCommitments)
            let list = sorted(signingCommitments)
            let bfs = try bindingFactors(groupPublicKey, list, message)
            guard let bf = bfs[identifier] else { return false }
            let R = try groupCommitment(list, bfs)
            let commShare = try add(decodeSafePoint(commitment.hiding), mulPoint(decodeSafePoint(commitment.binding), bf))
            let c = try H2(R + groupPublicKey + message)
            let lambda = try interpolatingValue(list.map { $0.identifier }, identifier)
            guard isCanonicalScalar(sigShare.sigShare) else { return false }
            let lhs = mulBase(try bytesToScalar(sigShare.sigShare))
            let rhs = try add(commShare, mulPoint(decodeSafePoint(publicKey), sMul(c, lambda)))
            return lhs == rhs
        } catch { return false }
    }

    /// Aggregate verified signature shares into a standard Ed25519 signature R || z. `verificationShares` is required: every share is
    /// verified first, and the result is verified under the group key before it is returned.
    public static func aggregate(_ message: [UInt8], _ signingCommitments: [Commitment], _ sigShares: [SigShare], _ groupPublicKey: [UInt8],
                                 threshold: JSONValue? = nil, verificationShares: [VerificationShare]?) throws -> [UInt8] {
        try validateCommitments(signingCommitments, threshold: threshold)
        try decodeSafePoint(groupPublicKey)
        let list = sorted(signingCommitments)
        guard sigShares.count == list.count else { throw JSError("frostAggregate: need exactly one signature share per commitment") }
        var ids = Set<Int64>()
        for s in sigShares {
            guard list.contains(where: { $0.identifier == s.identifier }) else { throw JSError("frostAggregate: share from non-signer") }
            guard ids.insert(s.identifier).inserted else { throw JSError("frostAggregate: duplicate signature share") }
        }
        guard let vss = verificationShares else { throw JSError("frostAggregate: verificationShares are required (every signature share is verified before aggregation)") }
        for s in sigShares {
            guard let vs = vss.first(where: { $0.identifier == s.identifier }), let cm = list.first(where: { $0.identifier == s.identifier }),
                  verifySigShare(identifier: s.identifier, publicKey: vs.publicKey, commitment: cm, sigShare: s, signingCommitments: list,
                                 groupPublicKey: groupPublicKey, message: message) else {
                throw JSError("frostAggregate: invalid signature share from participant \(s.identifier)")
            }
        }
        let R = try groupCommitment(list, try bindingFactors(groupPublicKey, list, message))
        var z = [UInt8](repeating: 0, count: 32)
        for s in sigShares { z = sAdd(z, try bytesToScalar(s.sigShare)) }
        let sig = R + z
        guard Ed25519Strict.verify(publicKey: groupPublicKey, message: message, signature: sig) else {
            throw JSError("frostAggregate: aggregate signature does not verify (a share is invalid)")
        }
        return sig
    }

    /// One-shot in-process coordinator over a quorum: commit, sign (every safety check on), aggregate (re-verified).
    public static func cosign(_ groupPublicKey: [UInt8], _ quorum: [ParticipantShare], _ message: [UInt8], threshold: JSONValue? = nil) throws -> [UInt8] {
        guard !quorum.isEmpty else { throw JSError("frostCosign: empty signing quorum") }
        if let t = try thresholdValue(threshold), quorum.count < t { throw JSError("frostCosign: quorum of \(quorum.count) is below the threshold t=\(t)") }
        var ids = Set<Int64>()
        for p in quorum {
            try assertValidId(p.identifier)
            guard ids.insert(p.identifier).inserted else { throw JSError("frostCosign: duplicate participant \(p.identifier) in quorum") }
        }
        let vss = quorum.map { VerificationShare(identifier: $0.identifier, publicKey: $0.publicKey) }
        let commits = try quorum.map { try commit($0) }
        let cs = commits.map { $0.commitment }
        let shares = try quorum.enumerated().map { (i, p) in
            try sign(p.identifier, p.share, groupPublicKey, Nonces(hiding: commits[i].hidingNonce, binding: commits[i].bindingNonce), message, cs,
                     SignOpts(threshold: threshold, verificationShare: p.publicKey, verificationShares: vss))
        }
        return try aggregate(message, cs, shares, groupPublicKey, threshold: threshold, verificationShares: vss)
    }
}
