import Foundation
import CryptoKit
#if canImport(COQS)
import COQS // a Linux build verifies through liboqs (tools/pca-audit/swift-mutate/linux-prep.sh adds the COQS shim target)
#endif

/// ML-DSA (FIPS-204) signature verification via CryptoKit's `MLDSA65` / `MLDSA87`, pure mode with an EMPTY context.
/// Matches `pq.ts` (`@noble/post-quantum`'s `ml_dsa65` / `ml_dsa87`): ML-DSA-65 public key 1952 / signature 3309 bytes,
/// ML-DSA-87 2592 / 4627 bytes. Never throws; a wrong length / malformed input / unsupported OS returns false.
///
/// `MLDSA65` / `MLDSA87` require macOS 26 / iOS 26 (and the other 26.0 platforms). On older systems `available` is false,
/// so the ML-DSA suites drop out of the capability manifest (`PCASuites.supported`) and are refused with
/// `unsupported_suite` instead of verifying (the classical `ed25519` suite is unaffected).
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

    /// True iff this OS provides CryptoKit's ML-DSA.
    static var available: Bool {
        #if canImport(COQS)
        return true // verification goes through liboqs; `#available` below is always true on Linux and says nothing about the backend
        #else
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) { return true }
        return false
        #endif
    }

    static func verify(_ level: Level, publicKey pk: [UInt8], message msg: [UInt8], signature sig: [UInt8]) -> Bool {
        let (pkLen, sigLen) = lens(level)
        guard pk.count == pkLen, sig.count == sigLen else { return false }
        #if canImport(COQS)
        // liboqs >= 0.12 (FIPS 204 final): plain verify is pure ML-DSA with the EMPTY context, as CryptoKit below
        let lv: Int32 = level == .mlDsa65 ? 65 : 87
        return msg.withUnsafeBufferPointer { mb in sig.withUnsafeBufferPointer { sb in pk.withUnsafeBufferPointer { pb in
            atlas_mldsa_verify(lv, mb.baseAddress, mb.count, sb.baseAddress, sb.count, pb.baseAddress, pb.count) == 1 } } }
        #else
        if #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *) {
            switch level {
            case .mlDsa65: // an encoding CryptoKit refuses (nil) is not a valid signature
                return (try? MLDSA65.PublicKey(rawRepresentation: Data(pk)))?.isValidSignature(Data(sig), for: Data(msg)) == true
            case .mlDsa87: // an encoding CryptoKit refuses (nil) is not a valid signature
                return (try? MLDSA87.PublicKey(rawRepresentation: Data(pk)))?.isValidSignature(Data(sig), for: Data(msg)) == true
            }
        }
        return false
        #endif
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
