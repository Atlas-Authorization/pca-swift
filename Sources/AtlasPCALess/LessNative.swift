import AtlasPCAVerify
import CLess
import Foundation

/// The real LESS verifier and signer (less-252-45, the `less-cat1` suites of the PCA suite registry; a NIST additional-signature round-2 candidate, not a
/// standard): the repository's patched reference C, compiled as the CLess target, behind its C API. Nothing code-based is implemented
/// here. The C side reads only within the given lengths, runs the reference on its own 16 MiB-stack thread and answers 0 when that thread cannot be
/// created (fail closed). Every length is checked before the library is called; verification is true only when the library answers 1.
/// Signing and key generation go through `atlas_less_cat1_keygen` / `atlas_less_cat1_sign`: the reference draws its randomness from one process-global
/// generator, so the C side takes the entropy from here (fresh `SystemRandomNumberGenerator` bytes unless a seed is given) and serializes the calls.
public enum LessNative {
    public static let publicKeyBytes = PCALessHook.pkBytes
    public static let signatureMinBytes = PCALessHook.sigMin
    public static let signatureMaxBytes = PCALessHook.sigMax

    /// The sizes this file relies on must be the ones the library was built with, or nothing is safe.
    public static func sizesMatch() -> Bool {
        Int(atlas_less_cat1_public_key_bytes()) == PCALessHook.pkBytes
            && Int(atlas_less_cat1_signature_min_bytes()) == PCALessHook.sigMin
            && Int(atlas_less_cat1_signature_max_bytes()) == PCALessHook.sigMax
    }

    /// True iff `sig` is a valid detached signature over `msg` under `vk` (the attached signed message `msg || sig` opens under `vk` and yields exactly
    /// `msg`). A wrong key length, a signature length the parameter set cannot produce or a library that reports other sizes is false.
    public static func verify(vk: [UInt8], msg: [UInt8], sig: [UInt8]) -> Bool {
        guard sizesMatch(), vk.count == PCALessHook.pkBytes, PCALessHook.sigLenOK(sig.count) else { return false }
        return vk.withUnsafeBufferPointer { v in
            msg.withUnsafeBufferPointer { m in
                sig.withUnsafeBufferPointer { s in
                    atlas_less_cat1_verify(v.baseAddress, v.count, m.baseAddress, m.count, s.baseAddress, s.count) == 1
                }
            }
        }
    }

    /// Byte lengths of the compiled parameter set (the reference's `sizes`): `seed` is the per-leaf seed length, the step by which a signature shrinks.
    public struct Sizes: Equatable { public let publicKey: Int, secretKey: Int, signatureMax: Int, seed: Int }

    /// The sizes the library reports; throws when it reports other sizes than the suite tables assume.
    public static func sizes() throws -> Sizes {
        guard sizesMatch() else { throw LessError.sizeMismatch }
        return Sizes(publicKey: Int(atlas_less_cat1_public_key_bytes()), secretKey: Int(atlas_less_cat1_secret_key_bytes()),
                     signatureMax: Int(atlas_less_cat1_signature_max_bytes()), seed: PCALessHook.sigStep)
    }

    public static let secretKeyBytes = 32
    public static let minSeedBytes = 32

    private static func freshSeed() -> [UInt8] {
        var g = SystemRandomNumberGenerator()
        return (0..<minSeedBytes).map { _ in UInt8.random(in: 0...255, using: &g) }
    }

    /// A key pair from a seed of at least 32 bytes (the same seed gives the same pair). A short seed or a library that reports other sizes throws.
    public static func keygen(seed: [UInt8]) throws -> (sk: [UInt8], vk: [UInt8]) {
        guard sizesMatch(), Int(atlas_less_cat1_secret_key_bytes()) == secretKeyBytes else { throw LessError.sizeMismatch }
        guard seed.count >= minSeedBytes else { throw LessError.badInput("the keygen seed is at least \(minSeedBytes) bytes") }
        var pk = [UInt8](repeating: 0, count: PCALessHook.pkBytes)
        var sk = [UInt8](repeating: 0, count: secretKeyBytes)
        let ok = atlas_less_cat1_keygen(&pk, pk.count, &sk, sk.count, seed, seed.count)
        guard ok == 1 else { throw LessError.badInput("LESS key generation failed") }
        return (sk, pk)
    }

    /// The detached signature of `msg` under `sk`. `seed` (at least 32 bytes) makes it reproducible; nil draws 32 fresh CSPRNG bytes (what real signing
    /// does: a repeated seed repeats the salt). The length is checked against the parameter set before it is returned.
    public static func sign(sk: [UInt8], msg: [UInt8], seed: [UInt8]? = nil) throws -> [UInt8] {
        guard sizesMatch() else { throw LessError.sizeMismatch }
        let sd = seed ?? freshSeed()
        guard sk.count == secretKeyBytes, sd.count >= minSeedBytes else { throw LessError.badInput("LESS signing needs a 32-byte secret key and a seed of at least 32 bytes") }
        var out = [UInt8](repeating: 0, count: PCALessHook.sigMax)
        var n = 0
        let ok = msg.withUnsafeBufferPointer { m in atlas_less_cat1_sign(sk, sk.count, m.baseAddress, m.count, sd, sd.count, &out, out.count, &n) }
        guard ok == 1, PCALessHook.sigLenOK(n) else { throw LessError.badInput("LESS signing failed") }
        return Array(out[0..<n])
    }

    /// A signing key bundle {vk, sk, sign seed} from a keygen seed of at least 32 bytes (deterministic). `signSeed` nil: every signature draws fresh
    /// CSPRNG bytes. Pass the result to `PCASuiteKey(alg:ed:less:)` once `registerCoreSuites()` has run.
    public static func keyFromSeed(_ seed: [UInt8], signSeed: [UInt8]? = nil) throws -> PCALessKey {
        guard signSeed == nil || signSeed!.count >= minSeedBytes else { throw LessError.badInput("the sign seed is at least \(minSeedBytes) bytes") }
        let kp = try keygen(seed: seed)
        return PCALessKey(vk: kp.vk, sk: kp.sk, signSeed: signSeed)
    }

    /// Explicit opt-in: makes the core verifier's `less-cat1` and `hybrid-ed25519-less-cat1` suites verify through the C library AND the core agent-side
    /// signer (`PCASuiteKey(alg:ed:less:)`) sign through it (nothing registers at import). `PCALessHook.unregister()` undoes both. Throws when the library
    /// reports sizes other than the ones the suite tables assume.
    public static func registerCoreSuites() throws {
        guard sizesMatch(), Int(atlas_less_cat1_secret_key_bytes()) == secretKeyBytes else { throw LessError.sizeMismatch }
        PCALessHook.register { vk, msg, sig in verify(vk: vk, msg: msg, sig: sig) }
        PCALessHook.registerSigner(PCALessHook.Signer(keygen: { seed in try keygen(seed: seed) }, sign: { sk, msg, seed in try sign(sk: sk, msg: msg, seed: seed) }))
    }
}

public enum LessError: Error, CustomStringConvertible {
    case sizeMismatch
    case badInput(String)
    public var description: String {
        switch self {
        case .sizeMismatch: return "the LESS library reports different sizes than the suite tables assume"
        case let .badInput(m): return m
        }
    }
}
