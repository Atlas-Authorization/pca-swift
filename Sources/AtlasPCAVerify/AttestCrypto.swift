import Foundation
import CryptoKit

// Crypto the attestation verifiers need beyond the package's Ed25519 / ML-DSA: hashes, ECDSA over P-256 / P-384 / P-521
// (CryptoKit on Apple, swift-crypto on Linux), and RSA signature verification (PKCS#1 v1.5 and PSS) over a small unsigned
// big-integer with Montgomery multiplication (the public exponent is small, so a verification is a handful of multiplications).

enum AHash {
    case sha1, sha256, sha384, sha512

    var length: Int {
        switch self {
        case .sha1: return 20
        case .sha256: return 32
        case .sha384: return 48
        case .sha512: return 64
        }
    }

    func digest(_ b: [UInt8]) -> [UInt8] {
        switch self {
        case .sha1: return Array(Insecure.SHA1.hash(data: Data(b)))
        case .sha256: return Array(SHA256.hash(data: Data(b)))
        case .sha384: return Array(SHA384.hash(data: Data(b)))
        case .sha512: return Array(SHA512.hash(data: Data(b)))
        }
    }

    /// The DER DigestInfo prefix of EMSA-PKCS1-v1_5.
    var digestInfoPrefix: [UInt8] {
        switch self {
        case .sha1: return [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]
        case .sha256: return [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
        case .sha384: return [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
        case .sha512: return [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
        }
    }
}

enum ACrypto {
    static func sha256(_ b: [UInt8]) -> [UInt8] { AHash.sha256.digest(b) }
    static func sha384(_ b: [UInt8]) -> [UInt8] { AHash.sha384.digest(b) }
    static func sha512(_ b: [UInt8]) -> [UInt8] { AHash.sha512.digest(b) }

    static func hex(_ b: [UInt8]) -> String {
        let d = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(b.count * 2)
        for x in b {
            out.append(d[Int(x >> 4)])
            out.append(d[Int(x & 15)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        case 0x41...0x46: return c - 0x41 + 10
        default: return nil
        }
    }

    /// Hex text to bytes; nil on an odd length or a non-hex character.
    static func unhex(_ s: String) -> [UInt8]? {
        let u = Array(s.utf8)
        if u.count % 2 != 0 { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(u.count / 2)
        var i = 0
        while i < u.count {
            guard let h = nibble(u[i]), let l = nibble(u[i + 1]) else { return nil }
            out.append(h << 4 | l)
            i += 2
        }
        return out
    }

    /// Constant-time-ish equality (lengths differ: false).
    static func eq(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return false }
        var d: UInt8 = 0
        for i in 0..<a.count { d |= a[i] ^ b[i] }
        return d == 0
    }

    // ---- ECDSA ----

    /// ECDSA over `message` hashed with `hash`, public key given as the uncompressed SEC1 point, signature as raw r||s
    /// (equal halves, the curve's size) or ASN.1 DER. `curve` is "P-256", "P-384", "P-521" or "P-224" (pure Swift, AttestP224.swift). Anything else is false.
    static func ecVerify(curve: String, point: [UInt8], hash: AHash, message: [UInt8], raw: [UInt8]? = nil, der: [UInt8]? = nil) -> Bool {
        switch curve {
        case "P-256":
            guard let k = try? P256.Signing.PublicKey(x963Representation: Data(point)) else { return false }
            guard let sig = ecSig(raw, der, { try P256.Signing.ECDSASignature(rawRepresentation: $0) }, { try P256.Signing.ECDSASignature(derRepresentation: $0) }, 64) else { return false }
            switch hash {
            case .sha256: return k.isValidSignature(sig, for: SHA256.hash(data: Data(message)))
            case .sha384: return k.isValidSignature(sig, for: SHA384.hash(data: Data(message)))
            case .sha512: return k.isValidSignature(sig, for: SHA512.hash(data: Data(message)))
            case .sha1: return k.isValidSignature(sig, for: Insecure.SHA1.hash(data: Data(message)))
            }
        case "P-384":
            guard let k = try? P384.Signing.PublicKey(x963Representation: Data(point)) else { return false }
            guard let sig = ecSig(raw, der, { try P384.Signing.ECDSASignature(rawRepresentation: $0) }, { try P384.Signing.ECDSASignature(derRepresentation: $0) }, 96) else { return false }
            switch hash {
            case .sha256: return k.isValidSignature(sig, for: SHA256.hash(data: Data(message)))
            case .sha384: return k.isValidSignature(sig, for: SHA384.hash(data: Data(message)))
            case .sha512: return k.isValidSignature(sig, for: SHA512.hash(data: Data(message)))
            case .sha1: return k.isValidSignature(sig, for: Insecure.SHA1.hash(data: Data(message)))
            }
        case "P-521":
            guard let k = try? P521.Signing.PublicKey(x963Representation: Data(point)) else { return false }
            guard let sig = ecSig(raw, der, { try P521.Signing.ECDSASignature(rawRepresentation: $0) }, { try P521.Signing.ECDSASignature(derRepresentation: $0) }, 132) else { return false }
            switch hash {
            case .sha256: return k.isValidSignature(sig, for: SHA256.hash(data: Data(message)))
            case .sha384: return k.isValidSignature(sig, for: SHA384.hash(data: Data(message)))
            case .sha512: return k.isValidSignature(sig, for: SHA512.hash(data: Data(message)))
            case .sha1: return k.isValidSignature(sig, for: Insecure.SHA1.hash(data: Data(message)))
            }
        case "P-224":
            return P224.verify(point: point, hash: hash, message: message, raw: raw, der: der)
        default:
            return false
        }
    }

    /// The signature from its raw (exact length) or DER form; nil when neither is given or it does not parse.
    private static func ecSig<S>(_ raw: [UInt8]?, _ der: [UInt8]?, _ fromRaw: (Data) throws -> S, _ fromDer: (Data) throws -> S, _ rawLen: Int) -> S? {
        if let r = raw {
            guard r.count == rawLen else { return nil }
            return try? fromRaw(Data(r))
        }
        if let d = der { return try? fromDer(Data(d)) }
        return nil
    }

    /// Does this uncompressed point lie on the named curve?
    static func ecPointValid(curve: String, point: [UInt8]) -> Bool {
        switch curve {
        case "P-256": return (try? P256.Signing.PublicKey(x963Representation: Data(point))) != nil
        case "P-384": return (try? P384.Signing.PublicKey(x963Representation: Data(point))) != nil
        case "P-521": return (try? P521.Signing.PublicKey(x963Representation: Data(point))) != nil
        case "P-224": return P224.pointValid(point)
        default: return false
        }
    }

    static func ed25519Verify(pub: [UInt8], message: [UInt8], sig: [UInt8]) -> Bool {
        guard pub.count == 32, sig.count == 64, let k = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(pub)) else { return false }
        return k.isValidSignature(Data(sig), for: Data(message))
    }

    // ---- RSA ----

    /// RSASSA-PKCS1-v1_5 verification (the encoded message is rebuilt and compared).
    static func rsaVerifyPKCS1(n: [UInt8], e: [UInt8], hash: AHash, message: [UInt8], sig: [UInt8]) -> Bool {
        guard let em = rsaPublic(n: n, e: e, sig: sig) else { return false }
        let k = em.count
        let t = hash.digestInfoPrefix + hash.digest(message)
        if k < t.count + 11 { return false }
        var want = [UInt8](repeating: 0xff, count: k)
        want[0] = 0x00
        want[1] = 0x01
        want[k - t.count - 1] = 0x00
        for i in 0..<t.count { want[k - t.count + i] = t[i] }
        return eq(want, em)
    }

    /// RSASSA-PSS verification with MGF1 over the same hash and an explicit salt length.
    static func rsaVerifyPSS(n: [UInt8], e: [UInt8], hash: AHash, message: [UInt8], sig: [UInt8], saltLength: Int) -> Bool {
        guard var em = rsaPublic(n: n, e: e, sig: sig), saltLength >= 0 else { return false }
        let nBits = BigNat(bytes: n).bitLength
        let emBits = nBits - 1
        let emLen = (emBits + 7) / 8
        if emLen < em.count && em[0] != 0 { return false }
        while emLen < em.count && em[0] == 0 { em.removeFirst() }
        if emLen != em.count { return false }
        let hLen = hash.length
        if emLen < hLen + saltLength + 2 { return false }
        if em[emLen - 1] != 0xbc { return false }
        let dbLen = emLen - hLen - 1
        let masked = Array(em[0..<dbLen])
        let h = Array(em[dbLen..<(dbLen + hLen)])
        let topBits = 8 * emLen - emBits
        if topBits > 0 && (masked[0] >> UInt8(8 - topBits)) != 0 { return false }
        var db = mgf1(seed: h, length: dbLen, hash: hash)
        for i in 0..<dbLen { db[i] ^= masked[i] }
        if topBits > 0 { db[0] &= UInt8(0xff >> topBits) }
        let psLen = emLen - hLen - saltLength - 2
        for i in 0..<psLen where db[i] != 0 { return false }
        if db[psLen] != 0x01 { return false }
        let salt = Array(db[(dbLen - saltLength)...])
        let mHash = hash.digest(message)
        let hp = hash.digest([UInt8](repeating: 0, count: 8) + mHash + salt)
        return eq(hp, h)
    }

    static func mgf1(seed: [UInt8], length: Int, hash: AHash) -> [UInt8] {
        var out: [UInt8] = []
        var counter: UInt32 = 0
        while out.count < length {
            let c: [UInt8] = [UInt8(counter >> 24 & 0xff), UInt8(counter >> 16 & 0xff), UInt8(counter >> 8 & 0xff), UInt8(counter & 0xff)]
            out += hash.digest(seed + c)
            counter += 1
        }
        return Array(out[0..<length])
    }

    /// s^e mod n as exactly |n| bytes; nil when the signature is out of range or the key is unusable.
    static func rsaPublic(n: [UInt8], e: [UInt8], sig: [UInt8]) -> [UInt8]? {
        let nn = BigNat(bytes: n)
        let k = (nn.bitLength + 7) / 8
        if nn.bitLength < 512 || nn.isEven || sig.count != k { return nil }
        let ee = BigNat(bytes: e)
        if ee.isZero || ee.bitLength > 32 { return nil }
        let s = BigNat(bytes: sig)
        if !(s < nn) { return nil }
        let m = BigNat.modPowOdd(base: s, exp: ee, mod: nn)
        return m.bytes(length: k)
    }
}

/// An unsigned big integer on little-endian 32-bit limbs (no trailing zero limb).
struct BigNat: Comparable {
    var limbs: [UInt32]

    init(limbs: [UInt32]) {
        var l = limbs
        while let last = l.last, last == 0 { l.removeLast() }
        self.limbs = l
    }

    init(bytes b: [UInt8]) {
        var l = [UInt32](repeating: 0, count: (b.count + 3) / 4)
        for (i, x) in b.reversed().enumerated() { l[i / 4] |= UInt32(x) << UInt32(8 * (i % 4)) }
        self.init(limbs: l)
    }

    var isZero: Bool { limbs.isEmpty }
    var isEven: Bool { limbs.isEmpty || limbs[0] & 1 == 0 }

    var bitLength: Int {
        guard let top = limbs.last else { return 0 }
        return (limbs.count - 1) * 32 + (32 - top.leadingZeroBitCount)
    }

    /// Big-endian bytes, left-padded with zeros to `length` (nil when the value does not fit).
    func bytes(length: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: length)
        for i in 0..<(limbs.count * 4) {
            let b = UInt8((limbs[i / 4] >> UInt32(8 * (i % 4))) & 0xff)
            if i < length { out[length - 1 - i] = b } else if b != 0 { return nil }
        }
        return out
    }

    static func < (a: BigNat, b: BigNat) -> Bool {
        if a.limbs.count != b.limbs.count { return a.limbs.count < b.limbs.count }
        var i = a.limbs.count - 1
        while i >= 0 {
            if a.limbs[i] != b.limbs[i] { return a.limbs[i] < b.limbs[i] }
            i -= 1
        }
        return false
    }

    /// base^exp mod mod for an ODD modulus (Montgomery, CIOS).
    static func modPowOdd(base: BigNat, exp: BigNat, mod: BigNat) -> BigNat {
        let k = mod.limbs.count
        let n = mod.limbs
        // nPrime = -n^-1 mod 2^32
        var inv = n[0]
        for _ in 0..<5 { inv = inv &* (2 &- n[0] &* inv) }
        let nPrime = 0 &- inv
        func pad(_ x: [UInt32]) -> [UInt32] { x + [UInt32](repeating: 0, count: k - x.count) }
        func geq(_ a: [UInt32], _ b: [UInt32]) -> Bool {
            var i = k - 1
            while i >= 0 {
                if a[i] != b[i] { return a[i] > b[i] }
                i -= 1
            }
            return true
        }
        func sub(_ a: inout [UInt32], _ b: [UInt32]) {
            var borrow: Int64 = 0
            for i in 0..<k {
                let d = Int64(a[i]) - Int64(b[i]) - borrow
                a[i] = UInt32(truncatingIfNeeded: d)
                borrow = d < 0 ? 1 : 0
            }
        }
        func montMul(_ a: [UInt32], _ b: [UInt32]) -> [UInt32] {
            var t = [UInt32](repeating: 0, count: k + 2)
            for i in 0..<k {
                var carry: UInt64 = 0
                let ai = UInt64(a[i])
                for j in 0..<k {
                    let cur = UInt64(t[j]) + ai * UInt64(b[j]) + carry
                    t[j] = UInt32(truncatingIfNeeded: cur)
                    carry = cur >> 32
                }
                let c2 = UInt64(t[k]) + carry
                t[k] = UInt32(truncatingIfNeeded: c2)
                t[k + 1] = UInt32(truncatingIfNeeded: c2 >> 32)
                let m = UInt64(t[0] &* nPrime)
                carry = (UInt64(t[0]) + m * UInt64(n[0])) >> 32
                if k > 1 {
                    for j in 1..<k {
                        let cur = UInt64(t[j]) + m * UInt64(n[j]) + carry
                        t[j - 1] = UInt32(truncatingIfNeeded: cur)
                        carry = cur >> 32
                    }
                }
                let c3 = UInt64(t[k]) + carry
                t[k - 1] = UInt32(truncatingIfNeeded: c3)
                t[k] = t[k + 1] &+ UInt32(truncatingIfNeeded: c3 >> 32)
            }
            var r = Array(t[0..<k])
            if t[k] != 0 || geq(r, n) { sub(&r, n) }
            return r
        }
        // R^2 mod n by 64k doublings of 1
        var r2 = pad([1])
        for _ in 0..<(64 * k) {
            var carry: UInt32 = 0
            for i in 0..<k {
                let next = r2[i] >> 31
                r2[i] = (r2[i] << 1) | carry
                carry = next
            }
            if carry != 0 || geq(r2, n) { sub(&r2, n) }
        }
        let one = pad([1])
        var x = montMul(pad(base.limbs), r2) // base in Montgomery form (base < mod)
        var acc = montMul(one, r2)           // 1 in Montgomery form
        var bit = exp.bitLength - 1
        while bit >= 0 {
            acc = montMul(acc, acc)
            if (exp.limbs[bit / 32] >> UInt32(bit % 32)) & 1 == 1 { acc = montMul(acc, x) }
            bit -= 1
        }
        x = montMul(acc, one)
        return BigNat(limbs: x)
    }
}
