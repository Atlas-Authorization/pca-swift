import AtlasPCAVerify
import CFnDsa
import Foundation

/// The real FN-DSA primitive: Pornin's fn-dsa 0.4.0 reached through the C library libfndsa (pca_fndsa.h). Nothing lattice-related is implemented
/// here. FIPS 206 is unpublished, so this is a draft best guess pinned in lockstep with the TypeScript reference (@atlasauth/pca-fndsa) and
/// interoperates with it byte for byte; a round-3 Falcon (liboqs, BouncyCastle, circl) is not the same scheme. Parameter sets 512 and 1024 only.
/// Every length is checked before the library is called, and any non-zero library status is a refusal; verification is true only on status 0.
public enum FnDsaNative {
    public static let seedBytes = 32, messageCap = 8192

    private static func tag(_ variant: String) -> Int32? { variant == "fn-dsa-512" ? 512 : variant == "fn-dsa-1024" ? 1024 : nil }

    /// The sizes this file relies on must be the ones the library was built with, or nothing is safe.
    public static func sizesMatch() -> Bool {
        fndsa_len_seed() == seedBytes && fndsa_cap_msg() == messageCap
            && fndsa_len_vk(512) == FnDsa.pk512 && fndsa_len_sig(512) == FnDsa.sig512 && fndsa_len_vk(1024) == FnDsa.pk1024 && fndsa_len_sig(1024) == FnDsa.sig1024
            && fndsa_len_sk(512) > 0 && fndsa_len_sk(1024) > 0
    }

    private static func need(_ variant: String) throws -> Int32 {
        guard sizesMatch() else { throw FnDsaError.backendMissing("libfndsa is absent or reports different FN-DSA sizes") }
        guard let t = tag(variant) else { throw FnDsaError.invalid("unknown FN-DSA variant \(variant)") }
        return t
    }

    /// Byte lengths of a variant's verifying key, signing key and signature, as the library reports them (the reference's `sizes`).
    public static func sizes(_ variant: String) throws -> (verifyingKey: Int, signingKey: Int, signature: Int) {
        let t = try need(variant)
        return (Int(fndsa_len_vk(t)), Int(fndsa_len_sk(t)), Int(fndsa_len_sig(t)))
    }

    public static func secretKeyBytes(_ variant: String) throws -> Int { Int(fndsa_len_sk(try need(variant))) }

    /// (sk, vk) = KeyGen(seed), deterministic in the 32-byte seed.
    public static func keygen(_ variant: String, seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8]) {
        let t = try need(variant)
        guard seed.count == seedBytes else { throw FnDsaError.invalid("keygen: the seed must be exactly \(seedBytes) bytes") }
        var sk = [UInt8](repeating: 0, count: Int(fndsa_len_sk(t))), vk = [UInt8](repeating: 0, count: Int(fndsa_len_vk(t)))
        let rc = fndsa_c_keygen(t, seed, seed.count, &sk, sk.count, &vk, vk.count)
        guard rc == 0 else { throw FnDsaError.invalid("keygen refused (\(rc))") }
        return (sk, vk)
    }

    /// The signature over `msg`. `seed` makes it deterministic (replays); nil takes 32 fresh CSPRNG bytes, which is what real signing does.
    public static func sign(_ variant: String, sk: [UInt8], msg: [UInt8], seed: [UInt8]? = nil) throws -> [UInt8] {
        let t = try need(variant)
        guard sk.count == Int(fndsa_len_sk(t)) else { throw FnDsaError.invalid("sign: the secret key must be exactly \(fndsa_len_sk(t)) bytes") }
        guard msg.count <= messageCap else { throw FnDsaError.invalid("sign: the message is over \(messageCap) bytes") }
        let s = seed ?? (0..<seedBytes).map { _ in UInt8.random(in: 0...255) }
        guard s.count == seedBytes else { throw FnDsaError.invalid("sign: the seed must be exactly \(seedBytes) bytes") }
        var sig = [UInt8](repeating: 0, count: Int(fndsa_len_sig(t)))
        let rc = fndsa_c_sign(t, sk, sk.count, msg, msg.count, s, s.count, &sig, sig.count)
        guard rc == 0 else { throw FnDsaError.invalid("sign refused (\(rc))") }
        return sig
    }

    /// True only when the library answers 0. A wrong length, an over-cap message, an unknown variant or any non-zero status is false.
    public static func verify(_ variant: String, vk: [UInt8], msg: [UInt8], sig: [UInt8]) throws -> Bool {
        let t = try? need(variant)
        guard sizesMatch() else { throw FnDsaError.backendMissing("libfndsa is absent or reports different FN-DSA sizes") }
        guard let t = t, vk.count == Int(fndsa_len_vk(t)), sig.count == Int(fndsa_len_sig(t)), msg.count <= messageCap else { return false }
        return fndsa_c_verify(t, vk, vk.count, sig, sig.count, msg, msg.count) == 0
    }

    /// Explicit opt-in: makes the core verifier's fn-dsa-512 / fn-dsa-1024 suites verify AND the core agent-side signer (`PCASuiteKey(alg:fnDsa:)`) sign
    /// through libfndsa (nothing registers at import). `PCAFnDsaHook.unregister()` undoes both.
    public static func registerCoreSuites() throws {
        guard sizesMatch() else { throw FnDsaError.backendMissing("libfndsa is absent or reports different FN-DSA sizes") }
        PCAFnDsaHook.register { v, vk, msg, sig in try verify(v, vk: vk, msg: msg, sig: sig) }
        PCAFnDsaHook.registerSigner(PCAFnDsaHook.Signer(
            keygen: { v, seed in try keygen(v, seed: seed) },
            sign: { v, sk, msg, seed in try sign(v, sk: sk, msg: msg, seed: seed) }))
    }

    /// A signing key bundle {vk, sk, sign seed} from a 32-byte keygen seed (deterministic). `signSeed` nil: every signature draws 32 fresh CSPRNG bytes.
    /// Needs no core registration; pass the result to `PCASuiteKey(alg:fnDsa:)` once `registerCoreSuites()` has run.
    public static func keyFromSeed(_ variant: String, seed: [UInt8], signSeed: [UInt8]? = nil) throws -> PCAFnDsaKey {
        guard signSeed == nil || signSeed!.count == seedBytes else { throw FnDsaError.invalid("keyFromSeed: the sign seed must be exactly \(seedBytes) bytes") }
        let kp = try keygen(variant, seed: seed)
        return PCAFnDsaKey(variant: variant, vk: kp.vk, sk: kp.sk, signSeed: signSeed)
    }

    private static func variant(vkBytes n: Int) -> String? { n == FnDsa.pk512 ? "fn-dsa-512" : n == FnDsa.pk1024 ? "fn-dsa-1024" : nil }

    /// The backend for `FnDsa.setBackend`: the variant follows the public-key (verify) or secret-key (sign) length; signing draws a fresh seed.
    public static func backend() throws -> FalconBackend {
        guard sizesMatch() else { throw FnDsaError.backendMissing("libfndsa is absent or reports different FN-DSA sizes") }
        return FalconBackend(
            verify: { pk, msg, sig in try variant(vkBytes: pk.count).map { try verify($0, vk: pk, msg: msg, sig: sig) } ?? false },
            sign: { sk, msg in
                guard let v = ["fn-dsa-512", "fn-dsa-1024"].first(where: { (try? secretKeyBytes($0)) == sk.count }) else {
                    throw FnDsaError.invalid("sign: unrecognised FN-DSA secret-key length")
                }
                return try sign(v, sk: sk, msg: msg)
            })
    }
}
