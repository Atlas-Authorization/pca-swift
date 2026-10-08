import Foundation
import CryptoKit

/// ML-DSA-65 (FIPS-204, CRYSTALS-Dilithium category 3) signature verification via CryptoKit's `MLDSA65`.
/// Matches `pq.ts`'s `mlDsa65Verify` (`@noble/post-quantum`'s `ml_dsa65`): public key 1952 bytes, signature
/// 3309 bytes, empty context. Never throws; a wrong length / malformed input / unsupported OS returns false.
///
/// `MLDSA65` requires macOS 26 / iOS 26; on older systems verification returns false (the classical `ed25519`
/// suite is unaffected).
enum MLDSA {
    static let PUBLIC_KEY_BYTES = 1952
    static let SIGNATURE_BYTES = 3309

    static func verify(publicKey pk: [UInt8], message msg: [UInt8], signature sig: [UInt8]) -> Bool {
        guard pk.count == PUBLIC_KEY_BYTES, sig.count == SIGNATURE_BYTES else { return false }
        if #available(macOS 26.0, iOS 26.0, *) {
            guard let key = try? MLDSA65.PublicKey(rawRepresentation: Data(pk)) else { return false }
            return key.isValidSignature(Data(sig), for: Data(msg))
        }
        return false
    }

    static func verifyB64u(_ pkB64u: String, _ msg: [UInt8], _ sigB64u: String) -> Bool {
        guard let pk = Base64URLStrict.decode(pkB64u, length: PUBLIC_KEY_BYTES),
              let sg = Base64URLStrict.decode(sigB64u, length: SIGNATURE_BYTES) else { return false }
        return verify(publicKey: pk, message: msg, signature: sg)
    }
}
