import Foundation
import CryptoKit

/// Word-array kernels of the OT-extension hot path: the AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four little-endian u32 words, and
/// the batched tweakable correlation-robust hash H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a fixed-key AES-128 truncated to 64 bits.
///
/// AES-128 and SHAKE256 are OpenSSL libcrypto's (CLibcrypto) on every platform; no cipher is written out here. SHAKE256 (the KOS
/// challenge expander) is OpenSSL libcrypto's (CLibcrypto), with the NIST SHAKE256 known answers checked in the test suite.
extension PCAMpc {
    enum Shake256 {
        /// SHAKE256 of the concatenation of `chunks`, `outLen` bytes (OpenSSL libcrypto; a failing call throws, never a wrong digest).
        static func hash(_ chunks: [[UInt8]], outLen: Int) throws -> [UInt8] { try Libcrypto.shake256(chunks, outLen: outLen) }
    }

    enum Aes128 {
        /// AES-128-ECB encryption of whole blocks (libcrypto).
        static func ecb(_ key: [UInt8], _ data: [UInt8]) throws -> [UInt8] { try Libcrypto.aes128ecb(key, data) }
    }

    enum Otx {
        /// Number of bit columns of the IKNP matrix (kappa).
        static let COLS = 128

        static let TAG_PRG_KEY = Array("atlas-pca-mpc/ot-prg-aes".utf8)
        static let TAG_CRH_KEY = Array("atlas-pca-mpc/ot-crh-aes-fixed-key".utf8)
        static let TAG_TWEAK_DOMAIN = Array("atlas-pca-mpc/ot-crh-tweak-domain/v2".utf8)

        static func leWords(_ b: [UInt8], _ off: Int, _ n: Int) throws -> [UInt32] {
            guard off >= 0, n >= 0, off + 4 * n <= b.count else { throw MpcError("leWords: out of range") }
            return (0..<n).map { i in
                let o = off + 4 * i
                return UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
            }
        }

        static func leBytes(_ w: [UInt32], _ n: Int) throws -> [UInt8] {
            guard n >= 0, n <= w.count else { throw MpcError("leBytes: out of range") }
            var out = [UInt8](repeating: 0, count: 4 * n)
            for i in 0..<n { for b in 0..<4 { out[4 * i + b] = UInt8((w[i] >> UInt32(8 * b)) & 0xff) } }
            return out
        }

        /// The bytes of a non-negative integer, little endian, exactly `len` bytes (the low bytes).
        static func bigToBytes(_ mag: [UInt64], _ len: Int) -> [UInt8] { Dec.bytesLE(mag, max(0, len)) }
        /// The integer (as 64-bit limbs) with the given little-endian bytes.
        static func bytesToBig(_ b: [UInt8]) -> [UInt64] { Dec.limbs(b) }

        /// `nwords` u32 words of the PRG stream of `seed` from AES block `startBlock` (high tail bits unmasked).
        static func prgColumn(_ seed: [UInt8], _ startBlock: UInt64, _ nwords: Int) throws -> [UInt32] {
            guard nwords >= 0 else { throw MpcError("prgColumn: negative length") }
            let key = Array(MpcHash.sha256([TAG_PRG_KEY, seed])[0..<16])
            let blocks = (nwords * 4 + 15) / 16
            var ctr = [UInt8](repeating: 0, count: blocks * 16)
            for k in 0..<blocks {
                let c = startBlock &+ UInt64(k)
                for i in 0..<8 { ctr[16 * k + 15 - i] = UInt8((c >> UInt64(8 * i)) & 0xff) }
            }
            let ks = try Aes128.ecb(key, ctr)
            return try leWords(ks, 0, nwords)
        }

        /// Clears the bits at positions >= nbits in a little-endian word column.
        static func maskTail(_ col: inout [UInt32], _ nbits: Int) throws {
            guard nbits >= 0 else { throw MpcError("maskTail: negative bit count") }
            let full = nbits >> 5, rem = nbits & 31
            if rem != 0 {
                guard full < col.count else { throw MpcError("maskTail: out of range") }
                col[full] &= (UInt32(1) << UInt32(rem)) &- 1
            }
            var i = rem != 0 ? full + 1 : full
            while i < col.count { col[i] = 0; i += 1 }
        }

        /// In-place transpose of a 32x32 bit matrix held as 32 u32 words from `off`.
        static func transpose32(_ a: inout [UInt32], _ off: Int) throws {
            guard off >= 0, off + 32 <= a.count else { throw MpcError("transpose32: need 32 words") }
            var m: UInt32 = 0x0000ffff
            var j = 16
            while j != 0 {
                var k = 0
                while k < 32 {
                    let t = ((a[off + k] >> UInt32(j)) ^ a[off + k + j]) & m
                    a[off + k] ^= t << UInt32(j)
                    a[off + k + j] ^= t
                    k = (k + j + 1) & ~j
                }
                j >>= 1
                m = m ^ (m << UInt32(j))
            }
        }

        /// Transposes COLS bit-columns (each `W` words, concatenated) into `rows` rows of four words.
        static func transposeCols(_ cols: [UInt32], _ W: Int, _ rows: Int) throws -> [UInt32] {
            guard W >= 0, rows >= 0 else { throw MpcError("transposeCols: negative size") }
            var out = [UInt32](repeating: 0, count: rows * 4)
            var tmp = [UInt32](repeating: 0, count: 32)
            let blocks = (rows + 31) >> 5
            for rb in 0..<blocks {
                for cb in 0..<4 {
                    for c in 0..<32 {
                        let idx = (cb * 32 + c) * W + rb
                        guard idx < cols.count else { throw MpcError("transposeCols: column table too short") }
                        tmp[c] = cols[idx]
                    }
                    try transpose32(&tmp, 0)
                    let lim = min(32, rows - rb * 32)
                    for r in 0..<lim { out[(rb * 32 + r) * 4 + cb] = tmp[r] }
                }
            }
            return out
        }

        static func gfXorInto(_ acc: inout [UInt32], _ v: [UInt32], _ vo: Int) throws {
            guard acc.count >= 4, vo >= 0, vo + 4 <= v.count else { throw MpcError("gfXorInto: out of range") }
            for i in 0..<4 { acc[i] ^= v[vo + i] }
        }

        /// acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1).
        static func gfMulX(_ acc: inout [UInt32]) throws {
            guard acc.count >= 4 else { throw MpcError("gfMulX: need 4 words") }
            let carry = acc[3] >> 31
            acc[3] = (acc[3] << 1) | (acc[2] >> 31)
            acc[2] = (acc[2] << 1) | (acc[1] >> 31)
            acc[1] = (acc[1] << 1) | (acc[0] >> 31)
            acc[0] = (acc[0] << 1) ^ (carry != 0 ? 0x87 : 0)
        }

        /// XORs into `acc` chi[j] (four words) for every set bit j of the word column `col[off..<off+len]`.
        static func accumColumn(_ col: [UInt32], _ off: Int, _ len: Int, _ chi: [UInt32], _ acc: inout [UInt32]) throws {
            guard off >= 0, len >= 0, off + len <= col.count, acc.count >= 4 else { throw MpcError("accumColumn: out of range") }
            for w in 0..<len {
                var x = col[off + w]
                let base = w << 5
                while x != 0 {
                    let o = (base + x.trailingZeroBitCount) << 2
                    guard o + 4 <= chi.count else { throw MpcError("accumColumn: challenge table too short") }
                    acc[0] ^= chi[o]; acc[1] ^= chi[o + 1]; acc[2] ^= chi[o + 2]; acc[3] ^= chi[o + 3]
                    x &= x &- 1
                }
            }
        }

        /// sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns: the KOS combination of both roles.
        static func kosCombine(_ cols: [UInt32], _ W: Int, _ chi: [UInt32]) throws -> [UInt32] {
            guard W >= 0, COLS * W <= cols.count else { throw MpcError("kosCombine: column table too short") }
            var acc = [UInt32](repeating: 0, count: 4)
            for i in stride(from: COLS - 1, through: 0, by: -1) {
                try gfMulX(&acc)
                var part = [UInt32](repeating: 0, count: 4)
                try accumColumn(cols, i * W, W, chi, &part)
                try gfXorInto(&acc, part, 0)
            }
            return acc
        }

        static func gfFromBig(_ v: Gf128) -> [UInt32] { [UInt32(truncatingIfNeeded: v.lo), UInt32(truncatingIfNeeded: v.lo >> 32), UInt32(truncatingIfNeeded: v.hi), UInt32(truncatingIfNeeded: v.hi >> 32)] }

        static func gfToBig(_ w: [UInt32], _ off: Int = 0) throws -> Gf128 {
            guard off >= 0, off + 4 <= w.count else { throw MpcError("gfToBig: need 4 words") }
            return Gf128(hi: UInt64(w[off + 3]) << 32 | UInt64(w[off + 2]), lo: UInt64(w[off + 1]) << 32 | UInt64(w[off]))
        }

        /// The 64-bit session domain of a channel: SHA-256(tag, binding)[0..8] as two little-endian words.
        static func otTweakDomain(_ binding: [UInt8]) throws -> [UInt32] { try leWords(MpcHash.sha256([TAG_TWEAK_DOMAIN, binding]), 0, 2) }

        /// H(tweak, row_j) for n rows of four words: two u32 words per row (the low 64 bits of the TMMO hash). `offset` must be a non-negative safe integer.
        static func tmmoCrh(_ rows: [UInt32], _ n: Int, offset: Int64 = 0, domain: [UInt32] = [0, 0]) throws -> [UInt32] {
            guard offset >= 0, offset <= (Int64(1) << 53) - 1 else { throw MpcError("tmmoCrh: tweak offset must be a non-negative safe integer") }
            guard domain.count == 2 else { throw MpcError("tmmoCrh: tweak domain must be 2 words") }
            guard n >= 0 else { throw MpcError("tmmoCrh: negative row count") }
            let key = Array(MpcHash.sha256([TAG_CRH_KEY])[0..<16])
            let aw = try leWords(try Aes128.ecb(key, try leBytes(rows, n * 4)), 0, n * 4)
            var b = [UInt32](repeating: 0, count: n * 4)
            for j in 0..<n {
                let o = j * 4
                let v = UInt64(offset) &+ UInt64(j)
                b[o] = aw[o] ^ UInt32(truncatingIfNeeded: v)
                b[o + 1] = aw[o + 1] ^ UInt32(truncatingIfNeeded: v >> 32)
                b[o + 2] = aw[o + 2] ^ domain[0]
                b[o + 3] = aw[o + 3] ^ domain[1]
            }
            let cw = try leWords(try Aes128.ecb(key, try leBytes(b, n * 4)), 0, n * 4)
            var out = [UInt32](repeating: 0, count: n * 2)
            for j in 0..<n {
                out[2 * j] = cw[4 * j] ^ aw[4 * j]
                out[2 * j + 1] = cw[4 * j + 1] ^ aw[4 * j + 1]
            }
            return out
        }

        /// The 64-bit value of the two words at index j of a `tmmoCrh` output.
        static func word64(_ h: [UInt32], _ j: Int) throws -> UInt64 {
            guard j >= 0, 2 * j + 1 < h.count else { throw MpcError("word64: out of range") }
            return UInt64(h[2 * j + 1]) << 32 | UInt64(h[2 * j])
        }
    }
}
