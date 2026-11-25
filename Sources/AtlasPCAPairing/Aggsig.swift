import Foundation
import CBlst
import AtlasPCAVerify

/// BLS12-381 signature aggregation for Proof-Carrying Authority (draft-irtf-cfrg-bls-signature, proof-of-possession
/// ciphersuite, 48-byte G1 public keys, 96-byte G2 signatures), on blst. Rogue-key safety by construction: the aggregate
/// verifiers take `RegisteredKey`s only, and a `RegisteredKey` can only come from `registerKey` / `KeyRegistry.register`,
/// which verify KeyValidate and a proof of possession first. Verification is total: malformed input is `false`, never a trap.
public enum Aggsig {
    public static let sigDST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    public static let popDST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    /// The reference's spellings of the two domain-separation tags.
    public static let SIG_DST = sigDST
    public static let POP_DST = popDST
    public static let publicKeyLength = 48
    public static let signatureLength = 96

    public struct KeyPair {
        public let secretKey: [UInt8]
        public let publicKey: [UInt8]
    }

    /// A public key whose proof of possession was verified. The initializer is file-private: the only producers are
    /// `registerKey` and `KeyRegistry.register`.
    public struct RegisteredKey: Hashable {
        public let bytes: [UInt8]
        fileprivate init(_ b: [UInt8]) { bytes = b }
    }

    public enum Registration {
        case ok(RegisteredKey)
        case refused(String)
        public var isOk: Bool { if case .ok = self { return true } else { return false } }
        public var key: RegisteredKey? { if case let .ok(k) = self { return k } else { return nil } }
        public var reason: String? { if case let .refused(r) = self { return r } else { return nil } }
    }

    // ---- keys

    static func secret(_ sk: [UInt8]) throws -> Fr {
        guard sk.count == 32 else { throw PairingError("secret key must be 32 bytes") }
        guard let s = Fr(canonical: sk), !s.isZero else { throw PairingError("secret key must be a scalar in [1, r-1]") }
        return s
    }

    public static func publicKeyOf(_ sk: [UInt8]) throws -> [UInt8] { (try secret(sk) * G1.generator).compressed }

    /// A fresh key pair; refuses the degenerate key 1 (a stuck entropy source).
    public static func keyGen() throws -> KeyPair {
        var rng = SystemRandomNumberGenerator()
        while true {
            let wide = (0..<64).map { _ in UInt8.random(in: 0...255, using: &rng) }
            let s = Fr(reducing: wide)
            if s.isZero { continue }
            if s == Fr(1) { throw PairingError("keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue") }
            let sk = s.bytes
            return KeyPair(secretKey: sk, publicKey: try publicKeyOf(sk))
        }
    }

    /// KeyValidate (draft 2.5): a canonical compressed G1 point, not the identity, in the prime-order subgroup.
    static func validKey(_ pk: [UInt8]) -> G1? {
        guard pk.count == publicKeyLength, let p = G1(compressed: pk), !p.isIdentity else { return nil }
        return p
    }

    public static func keyValidate(_ pk: [UInt8]) -> Bool { validKey(pk) != nil }

    // ---- sign / verify

    static func signWith(_ dst: String, _ sk: [UInt8], _ msg: [UInt8]) throws -> [UInt8] {
        let s = try secret(sk)
        return (s * G2.hash(msg, dst: Array(dst.utf8))).compressed
    }

    public static func sign(_ sk: [UInt8], _ msg: [UInt8]) throws -> [UInt8] { try signWith(sigDST, sk, msg) }

    static func verifyWith(_ dst: String, _ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        guard sig.count == signatureLength, let s = G2(compressed: sig), let p = validKey(pk) else { return false }
        return Bls12.pairingEq(p, G2.hash(msg, dst: Array(dst.utf8)), G1.generator, s)
    }

    /// CoreVerify of one signature. Never traps.
    public static func verify(_ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool { verifyWith(sigDST, pk, msg, sig) }

    /// Sums the G2 signature points into one 96-byte aggregate; throws on an empty list or a non-canonical signature.
    public static func aggregate(_ sigs: [[UInt8]]) throws -> [UInt8] {
        if sigs.isEmpty { throw PairingError("aggregate: need at least one signature") }
        var sum = G2()
        for s in sigs {
            guard s.count == signatureLength, let p = G2(compressed: s) else { throw PairingError("aggregate: every signature must be a 96-byte compressed G2 point") }
            sum = sum + p
        }
        return sum.compressed
    }

    public static func popProve(_ sk: [UInt8]) throws -> [UInt8] { try signWith(popDST, sk, try publicKeyOf(sk)) }

    static func popVerify(_ pk: [UInt8], _ pop: [UInt8]) -> Bool { verifyWith(popDST, pk, pk, pop) }

    // ---- raw aggregate verification (internal: only sound after a proof-of-possession check)

    /// AggregateVerify (draft 3.1.1) over pairwise-distinct messages: e(g1, aggSig) == prod e(pk_i, H(msg_i)).
    static func rawAggregateVerify(_ pks: [[UInt8]], _ msgs: [[UInt8]], _ aggSig: [UInt8]) -> Bool {
        guard aggSig.count == signatureLength, let s = G2(compressed: aggSig), !pks.isEmpty, pks.count == msgs.count, Set(msgs).count == msgs.count else { return false }
        let dst = Array(sigDST.utf8)
        var pairs: [(G1, G2)] = []
        for i in pks.indices {
            guard let p = validKey(pks[i]) else { return false }
            pairs.append((p, G2.hash(msgs[i], dst: dst)))
        }
        pairs.append((-G1.generator, s))
        return Bls12.pairingProductIsOne(pairs)
    }

    /// FastAggregateVerify (draft 3.3.4): one message; the aggregate key is KeyValidate'd too ({P, -P} sums to the identity).
    static func rawFastAggregateVerify(_ pks: [[UInt8]], _ msg: [UInt8], _ aggSig: [UInt8]) -> Bool {
        guard aggSig.count == signatureLength, let s = G2(compressed: aggSig), !pks.isEmpty else { return false }
        var agg = G1()
        for pk in pks {
            guard let p = validKey(pk) else { return false }
            agg = agg + p
        }
        if agg.isIdentity { return false }
        return Bls12.pairingEq(agg, G2.hash(msg, dst: Array(sigDST.utf8)), G1.generator, s)
    }

    // ---- registration

    /// Admits a key: KeyValidate plus a valid proof of possession. Never traps.
    public static func registerKey(_ pk: [UInt8], _ pop: [UInt8]) -> Registration {
        if !keyValidate(pk) { return .refused("public key fails KeyValidate (not a canonical, non-identity, prime-order G1 point)") }
        if pop.count != signatureLength { return .refused("proof of possession is not a 96-byte compressed G2 signature") }
        if !popVerify(pk, pop) { return .refused("proof of possession does not verify for this key") }
        return .ok(RegisteredKey(pk))
    }

    /// AggregateVerify over distinct messages, registered keys only (an empty list is refused).
    public static func aggregateVerify(_ keys: [RegisteredKey], _ msgs: [[UInt8]], _ aggSig: [UInt8]) -> Bool {
        if keys.isEmpty { return false }
        return rawAggregateVerify(keys.map { $0.bytes }, msgs, aggSig)
    }

    /// FastAggregateVerify: one message, registered keys only; one signer may not be counted twice.
    public static func fastAggregateVerify(_ keys: [RegisteredKey], _ msg: [UInt8], _ aggSig: [UInt8]) -> Bool {
        if keys.isEmpty || Set(keys).count != keys.count { return false }
        return rawFastAggregateVerify(keys.map { $0.bytes }, msg, aggSig)
    }

    /// A verifier's pinned set of admitted keys, indexed by key bytes.
    public final class KeyRegistry {
        private var keys: [[UInt8]: RegisteredKey] = [:]
        private let lock = NSLock()
        public init() {}

        /// Verifies the proof of possession and admits the key (idempotent).
        @discardableResult
        public func register(_ pk: [UInt8], _ pop: [UInt8]) -> Registration {
            let r = Aggsig.registerKey(pk, pop)
            if let k = r.key { lock.lock(); keys[pk] = k; lock.unlock() }
            return r
        }

        public func get(_ pk: [UInt8]) -> RegisteredKey? {
            guard pk.count == Aggsig.publicKeyLength else { return nil }
            lock.lock(); defer { lock.unlock() }
            return keys[pk]
        }

        public func has(_ pk: [UInt8]) -> Bool { get(pk) != nil }
        public var size: Int { lock.lock(); defer { lock.unlock() }; return keys.count }
    }
}
