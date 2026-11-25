import Foundation
import CryptoKit
import CMLDSA // the vendored ML-DSA reference code, the backend where CryptoKit has no ML-DSA

/// ML-DSA (FIPS-204) signature verification, pure mode with an EMPTY context, via CryptoKit's `MLDSA65` / `MLDSA87` where the OS has them and otherwise via the vendored CMLDSA target.
/// Matches `pq.ts` (`@noble/post-quantum`'s `ml_dsa65` / `ml_dsa87`): ML-DSA-65 public key 1952 / signature 3309 bytes,
/// ML-DSA-87 2592 / 4627 bytes. Never throws; a wrong length / malformed input returns false.
///
/// `MLDSA65` / `MLDSA87` require macOS 26 / iOS 26 (and the other 26.0 platforms). Everywhere else (macOS and iOS before 26, Linux) the vendored CMLDSA target
/// (liboqs 0.14.0's pq-crystals reference code, compiled into the package) verifies, so ML-DSA is available on every platform with no extra install.
enum MLDSA {
    enum Level { case mlDsa65, mlDsa87 }

    static let PUBLIC_KEY_BYTES = 1952
    static let SIGNATURE_BYTES = 3309

    /// (public key bytes, signature bytes).
    static func lens(_ l: Level) -> (pk: Int, sig: Int) {
        switch l {
        case .mlDsa65: return (PUBLIC_KEY_BYTES, SIGNATURE_BYTES)
        case .mlDsa87: return (2592, 4627)
        }
    }

    /// Always true: CryptoKit provides ML-DSA where the OS has it and the vendored target everywhere else.
    static var available: Bool { true }

    /// CryptoKit's verdict, or nil where this OS has no CryptoKit ML-DSA (before 26) or the build has no CryptoKit (Linux).
    static func verifyCryptoKit(_ level: Level, publicKey pk: [UInt8], message msg: [UInt8], signature sig: [UInt8]) -> Bool? {
        #if !canImport(Darwin)
        return nil
        #else
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            switch level {
            case .mlDsa65: // an encoding CryptoKit refuses (nil) is not a valid signature
                return (try? MLDSA65.PublicKey(rawRepresentation: Data(pk)))?.isValidSignature(Data(sig), for: Data(msg)) == true
            case .mlDsa87:
                return (try? MLDSA87.PublicKey(rawRepresentation: Data(pk)))?.isValidSignature(Data(sig), for: Data(msg)) == true
            }
        }
        return nil
        #endif
    }

    /// The vendored target's verdict (FIPS 204 final, pure ML-DSA with the EMPTY context). Always available.
    static func verifyVendored(_ level: Level, publicKey pk: [UInt8], message msg: [UInt8], signature sig: [UInt8]) -> Bool {
        let lv: Int32 = level == .mlDsa65 ? 65 : 87
        return msg.withUnsafeBufferPointer { mb in sig.withUnsafeBufferPointer { sb in pk.withUnsafeBufferPointer { pb in
            cmldsa_verify(lv, mb.baseAddress, mb.count, sb.baseAddress, sb.count, pb.baseAddress, pb.count) == 1 } } }
    }

    /// A key pair from the vendored target: random (OS CSPRNG) when `seed` is nil, else KeyGen(xi) for the 32-byte FIPS 204 seed. Nil if the library refuses.
    static func vendoredKeyPair(_ level: Level, seed: [UInt8]?) -> (pk: [UInt8], sk: [UInt8])? {
        let lv: Int32 = level == .mlDsa65 ? 65 : 87
        // the sizes come from the library itself, and each buffer is written by the library (no fill value to get wrong)
        let pkLen = Int(cmldsa_len(lv, 0)), skLen = Int(cmldsa_len(lv, 1))
        var made: Int32 = .zero
        var sk = [UInt8]()
        let pk = [UInt8](unsafeUninitializedCapacity: pkLen) { pb, pc in
            sk = [UInt8](unsafeUninitializedCapacity: skLen) { sb, sc in
                made = seed.map { sd in cmldsa_keygen(lv, sd, pb.baseAddress, sb.baseAddress) } ?? cmldsa_keygen(lv, nil, pb.baseAddress, sb.baseAddress)
                sc = skLen
            }
            pc = pkLen
        }
        // post-condition of the capacity closures above: each array committed exactly the length the library reported (a closure that did not set its
        // count would leave an empty or short key behind)
        guard made == 1, sk.count == skLen, pk.count == pkLen else { return nil }
        return (pk, sk)
    }

    /// A pure ML-DSA signature (EMPTY context, hedged) from the vendored target, or nil if the library refuses.
    static func vendoredSign(_ level: Level, secretKey: [UInt8], message msg: [UInt8]) -> [UInt8]? {
        let lv: Int32 = level == .mlDsa65 ? 65 : 87
        let sigBytes = Int(cmldsa_len(lv, 2))
        guard secretKey.count == Int(cmldsa_len(lv, 1)) else { return nil }
        var written: Int = .zero
        var signed: Int32 = .zero
        let sig = [UInt8](unsafeUninitializedCapacity: sigBytes) { sb, sc in
            signed = cmldsa_sign(lv, msg, msg.count, secretKey, sb.baseAddress, &written)
            sc = sigBytes
        }
        guard signed == 1, written == sigBytes else { return nil }
        return sig
    }

    /// CryptoKit where this OS has it, else the vendored target.
    static func verify(_ level: Level, publicKey pk: [UInt8], message msg: [UInt8], signature sig: [UInt8]) -> Bool {
        let (pkLen, sigLen) = lens(level)
        guard pk.count == pkLen, sig.count == sigLen else { return false }
        if let v = verifyCryptoKit(level, publicKey: pk, message: msg, signature: sig) { return v }
        return verifyVendored(level, publicKey: pk, message: msg, signature: sig)
    }

    static func verify(publicKey pk: [UInt8], message msg: [UInt8], signature sig: [UInt8]) -> Bool {
        verify(.mlDsa65, publicKey: pk, message: msg, signature: sig)
    }

    static func verifyB64u(_ level: Level, _ pkB64u: String, _ msg: [UInt8], _ sigB64u: String) -> Bool {
        let (pkLen, sigLen) = lens(level)
        guard let pk = Base64URLStrict.decode(pkB64u, length: pkLen),
              let sg = Base64URLStrict.decode(sigB64u, length: sigLen) else { return false }
        return verify(level, publicKey: pk, message: msg, signature: sg)
    }

    static func verifyB64u(_ pkB64u: String, _ msg: [UInt8], _ sigB64u: String) -> Bool {
        verifyB64u(.mlDsa65, pkB64u, msg, sigB64u)
    }
}
