import CLweOt
import Foundation

/// A lattice or protocol refusal. Nothing is returned on a refusal.
public enum LweOtError: Error, Equatable {
    /// A wrong size or a malformed input, refused before the library is called.
    case invalid(String)
    /// The library refused (a non-zero status).
    case refused(String)
    /// The endemic base OT aborted: malformed peer input, or a sender ciphertext failing its commitment.
    case abort(String)
}

/// The endemic OT's lattice core: Kyber-768 K-PKE keygen, CPA encrypt and decrypt, ring add and subtract, and the hash to a uniform ring vector. Every
/// operation is the audited pqc_kyber reference reached through the C library liblweot (pca_lwe_ot.h); nothing lattice-related is implemented here.
public enum LweLattice {
    public static let pkBytes = 1184, skBytes = 1152, ctBytes = 1088, tvecBytes = 1152, symBytes = 32, hashinCap = 4096

    /// The sizes this enum hard-codes must be the ones the library was built with, or nothing is safe.
    public static func sizesMatch() -> Bool {
        lweot_len_pk() == pkBytes && lweot_len_sk() == skBytes && lweot_len_ct() == ctBytes && lweot_len_tvec() == tvecBytes
            && lweot_len_sym() == symBytes && lweot_hashin_cap() == hashinCap
    }

    private static func need(_ b: [UInt8], _ n: Int, _ what: String) throws {
        guard sizesMatch() else { throw LweOtError.refused("liblweot reports different Kyber-768 sizes") }
        guard b.count == n else { throw LweOtError.invalid("lattice: \(what) must be exactly \(n) bytes") }
    }

    private static func ok(_ rc: Int32, _ op: String) throws {
        guard rc == 0 else { throw LweOtError.refused("lattice: \(op) refused (\(rc))") }
    }

    /// The K-PKE key pair derived deterministically from a 32-byte seed.
    public static func keygen(_ seed: [UInt8]) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        try need(seed, symBytes, "seed")
        var pk = [UInt8](repeating: 0, count: pkBytes), sk = [UInt8](repeating: 0, count: skBytes)
        try ok(lweot_kpke_keygen(seed, seed.count, &pk, pk.count, &sk, sk.count), "keygen")
        return (pk, sk)
    }

    /// The K-PKE key pair exactly as FIPS 203 Algorithm 13 derives it (the derivation the endemic receiver uses).
    public static func keygenFips203(_ seed: [UInt8]) throws -> (publicKey: [UInt8], secretKey: [UInt8]) {
        try need(seed, symBytes, "seed")
        var pk = [UInt8](repeating: 0, count: pkBytes), sk = [UInt8](repeating: 0, count: skBytes)
        try ok(lweot_kpke_keygen_fips203(seed, seed.count, &pk, pk.count, &sk, sk.count), "keygen (FIPS 203)")
        return (pk, sk)
    }

    public static func enc(_ publicKey: [UInt8], _ message: [UInt8], _ coins: [UInt8]) throws -> [UInt8] {
        try need(publicKey, pkBytes, "public key"); try need(message, symBytes, "message"); try need(coins, symBytes, "coins")
        var ct = [UInt8](repeating: 0, count: ctBytes)
        try ok(lweot_kpke_enc(publicKey, publicKey.count, message, message.count, coins, coins.count, &ct, ct.count), "enc")
        return ct
    }

    public static func dec(_ secretKey: [UInt8], _ ciphertext: [UInt8]) throws -> [UInt8] {
        try need(secretKey, skBytes, "secret key"); try need(ciphertext, ctBytes, "ciphertext")
        var m = [UInt8](repeating: 0, count: symBytes)
        try ok(lweot_kpke_dec(secretKey, secretKey.count, ciphertext, ciphertext.count, &m, m.count), "dec")
        return m
    }

    public static func ringAdd(_ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
        try need(a, tvecBytes, "a"); try need(b, tvecBytes, "b")
        var o = [UInt8](repeating: 0, count: tvecBytes)
        try ok(lweot_ring_add(a, a.count, b, b.count, &o, o.count), "ring add")
        return o
    }

    public static func ringSub(_ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
        try need(a, tvecBytes, "a"); try need(b, tvecBytes, "b")
        var o = [UInt8](repeating: 0, count: tvecBytes)
        try ok(lweot_ring_sub(a, a.count, b, b.count, &o, o.count), "ring sub")
        return o
    }

    /// SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes.
    public static func hashToRing(_ input: [UInt8]) throws -> [UInt8] {
        guard sizesMatch() else { throw LweOtError.refused("liblweot reports different Kyber-768 sizes") }
        guard input.count <= hashinCap else { throw LweOtError.invalid("lattice: hash input must be at most \(hashinCap) bytes") }
        var o = [UInt8](repeating: 0, count: tvecBytes)
        try ok(lweot_hash_to_ring(input, input.count, &o, o.count), "hash to ring")
        return o
    }
}
