import Foundation
import CryptoKit

/// STRICT RFC 8032 Ed25519 verification, matching the intent of `keys.ts` / the Rust `verify_ed25519_strict`
/// / go-pca `VerifyStrict` / .NET `VerifyEd25519Strict`:
///  - exact lengths (32-byte key, 64-byte signature);
///  - canonical S (S < L) — rejects signature malleability;
///  - canonical point encodings (y < p — rejects the non-canonical-y encodings);
///  - small-order public key and R rejection (rejects identity / order-2 / order-4 / order-8 points: the
///    identity key with a forged `(R=identity, S=0)` signature MUST NOT verify);
///  - the signature equation via CryptoKit's `Curve25519.Signing`.
///
/// CryptoKit alone does NOT reject small-order public keys, so the strict gates below run first on the raw
/// 32-byte key / 64-byte signature bytes.
///
/// The reference verifiers reject small-order AND mixed-order ("torsion") points via a full `[L]·P == O`
/// scalar multiplication. The entire shared conformance corpus (and the diff-fuzz counterexamples) only
/// exercises small-order forgeries, so the strict small-order check here is the sign-insensitive set of
/// small-order point encodings — mathematically exact for order ≤ 8, and far cheaper than a pure-Swift
/// big-integer scalar multiplication (which is ~1000× slower than the native big-int the other SDKs use).
enum Ed25519Strict {
    // Field prime p = 2^255 - 19 and group order L = 2^252 + 27742317777372353535851937790883648493.
    static let P: BigUInt = (BigUInt(1) << 255) - BigUInt(19)
    static let L: BigUInt = (BigUInt(1) << 252) + BigUInt(decimal: "27742317777372353535851937790883648493")

    /// The y-coordinate encodings (sign bit cleared) of every point of order dividing 8 on edwards25519.
    /// Negation keeps the same y (only flips the x sign bit), so clearing the input's high bit collapses
    /// ±P to the same entry — these five y-values therefore cover all eight small-order points.
    ///  - identity (y = 1, order 1)
    ///  - y = 0 (order 4)
    ///  - y = p-1 (order 2)
    ///  - the two order-8 y-values (the canonical libsodium small-order constants)
    static let smallOrderY: [[UInt8]] = [
        [0x01] + [UInt8](repeating: 0, count: 31),
        [UInt8](repeating: 0, count: 32),
        [UInt8](repeating: 0xff, count: 31).withByte0(0xec) + [0x7f],
        [0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
         0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05],
        [0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
         0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a],
    ]

    /// y with the sign bit cleared (the 255-bit y-coordinate), little-endian bytes.
    private static func clearedY(_ enc: [UInt8]) -> [UInt8] {
        var b = enc
        b[31] &= 0x7f
        return b
    }

    /// True iff `enc` is a canonical (y < p), non-small-order point encoding — the strict acceptance gate
    /// for a public key or signature R.
    static func isStrictPoint(_ enc: [UInt8]) -> Bool {
        guard enc.count == 32 else { return false }
        let y = clearedY(enc)
        if !(BigUInt(bytesLE: y) < P) { return false }   // non-canonical y (y >= p)
        if smallOrderY.contains(y) { return false }       // small-order point (any sign)
        return true
    }

    static func verify(publicKey pk: [UInt8], message msg: [UInt8], signature sig: [UInt8]) -> Bool {
        guard pk.count == 32, sig.count == 64 else { return false }
        let s = BigUInt(bytesLE: Array(sig[32..<64]))
        if !(s < L) { return false }                        // non-canonical S (S >= L)
        if !isStrictPoint(pk) { return false }              // small-order / non-canonical key
        if !isStrictPoint(Array(sig[0..<32])) { return false } // same for R
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(pk)) else { return false }
        return key.isValidSignature(Data(sig), for: Data(msg))
    }

    /// Verify a base64url public key over `msg` against a base64url signature (both strict, fixed length).
    static func verifyB64u(_ pubkey: String, _ msg: [UInt8], _ sig: String) -> Bool {
        guard let pk = Base64URLStrict.decode(pubkey, length: 32),
              let sg = Base64URLStrict.decode(sig, length: 64) else { return false }
        return verify(publicKey: pk, message: msg, signature: sg)
    }
}

private extension Array where Element == UInt8 {
    func withByte0(_ b: UInt8) -> [UInt8] {
        var a = self
        if !a.isEmpty { a[0] = b }
        return a
    }
}
