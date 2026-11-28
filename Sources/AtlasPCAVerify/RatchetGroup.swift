import Foundation
import CryptoKit
import Clibsodium

/// A refusal of the capability ratchet or the risk accumulator. `code` is the stable code of the reference
/// (invalid_depth, invalid_seed, leaf_out_of_range, leaf_punctured, invalid_value, length_mismatch, invalid_proof_shape) where it has one.
public struct PCARatchetError: Error, CustomStringConvertible {
    public let code: String?
    public let message: String
    public init(_ code: String?, _ message: String) { self.code = code; self.message = message }
    public var description: String { message }
}

/// An arbitrary-precision signed integer for the accumulator's units and blindings (the reference uses BigInt there).
public struct PCABigInt: Equatable, CustomStringConvertible {
    let neg: Bool
    let mag: BigUInt

    init(neg: Bool, mag: BigUInt) { self.neg = neg && !mag.isZero; self.mag = mag }
    public init(_ v: Int64) { self.init(neg: v < 0, mag: BigUInt(v.magnitude)) }
    /// `BigInt(text)`: a decimal string (optionally signed) or a 0x / 0o / 0b literal; nil where the reference throws.
    public init?(_ text: String) {
        guard let j = JSBigInt.parse(text) else { return nil }
        self.init(neg: j.neg, mag: j.mag)
    }

    public var isNegative: Bool { neg }

    public var description: String { (neg ? "-" : "") + mag.ratchetDecimal }

    /// `BigInt(x)` for a JSON value (an integral number, a boolean, a numeric string); nil where it throws.
    static func js(_ v: JSONValue?) -> PCABigInt? {
        if case let .double(d)? = v {
            guard d.isFinite, d.rounded(.towardZero) == d else { return nil }
            return PCABigInt(neg: d < 0, mag: BigUInt.ratchetFrom(double: abs(d)))
        }
        return JSBigInt.of(v).map { PCABigInt(neg: $0.neg, mag: $0.mag) }
    }

    /// The accumulator's units: a non-negative integer number (never a boolean, string or fraction).
    public static func units(_ v: JSONValue?) throws -> PCABigInt {
        let bad = PCARatchetError("invalid_value", "risk/budget must be a non-negative integer")
        switch v {
        case let .int(i)?:
            if i < 0 { throw PCARatchetError("invalid_value", "risk/budget must be >= 0") }
            return PCABigInt(i)
        case let .double(d)?:
            guard d.isFinite, d.rounded(.towardZero) == d, d >= 0 else { throw bad }
            return PCABigInt(neg: false, mag: BigUInt.ratchetFrom(double: d))
        default: throw bad
        }
    }
}

extension BigUInt {
    /// Exactly `count` little-endian bytes (the value must fit).
    func ratchetBytesLE(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        for (i, l) in limbs.enumerated() {
            for j in 0..<4 where i * 4 + j < count { out[i * 4 + j] = UInt8(truncatingIfNeeded: l >> UInt32(8 * j)) }
        }
        return out
    }

    var ratchetLow32: UInt32 { limbs.first ?? 0 }
    var ratchetLow64: UInt64 { UInt64(limbs.first ?? 0) | (limbs.count > 1 ? UInt64(limbs[1]) << 32 : 0) }

    /// (self / d, self % d).
    func ratchetDivMod(_ d: UInt32) -> (BigUInt, UInt32) {
        var out = [UInt32](repeating: 0, count: limbs.count)
        var rem: UInt64 = 0
        for i in stride(from: limbs.count - 1, through: 0, by: -1) {
            let cur = (rem << 32) | UInt64(limbs[i])
            out[i] = UInt32(cur / UInt64(d))
            rem = cur % UInt64(d)
        }
        var bytes: [UInt8] = []
        for l in out { for j in 0..<4 { bytes.append(UInt8(truncatingIfNeeded: l >> UInt32(8 * j))) } }
        return (BigUInt(bytesLE: bytes), UInt32(rem))
    }

    var ratchetDecimal: String {
        if isZero { return "0" }
        var chunks: [UInt32] = []
        var n = self
        while !n.isZero { let (q, r) = n.ratchetDivMod(1_000_000_000); chunks.append(r); n = q }
        var s = String(chunks.last!)
        for c in chunks.dropLast().reversed() { let t = String(c); s += String(repeating: "0", count: 9 - t.count) + t }
        return s
    }

    /// The exact value of a finite, integral, non-negative double.
    static func ratchetFrom(double d: Double) -> BigUInt {
        if !(d >= 1) { return BigUInt() }
        let e = Int(d.exponent)
        let sig = d.significandBitPattern | (UInt64(1) << 52)
        return e >= 52 ? BigUInt(sig) << (e - 52) : BigUInt(sig >> UInt64(52 - e))
    }
}

/// The prime-order group of the accumulator: ristretto255 (RFC 9496) from libsodium, Pedersen generators G and H, the scalar field and
/// the Fiat-Shamir transcript hash. Points are their canonical 32-byte encodings (equality is byte equality); scalars are 32-byte
/// little-endian values below the group order. libsodium is the only implementation of the group arithmetic; nothing here re-derives it.
enum RatchetGroup {
    typealias Point = [UInt8]
    typealias Scalar = [UInt8]

    private static let ready: Bool = sodium_init() >= 0
    private static func ensure() { precondition(ready, "libsodium failed to initialise") }

    static let zero = [UInt8](repeating: 0, count: 32)

    static func scalar(_ v: UInt64) -> Scalar {
        (0..<32).map { $0 < 8 ? UInt8(truncatingIfNeeded: v >> UInt64(8 * $0)) : 0 }
    }

    /// The Pedersen generator G: the ristretto255 base point.
    static let G: Point = {
        ensure()
        var q = zero
        let rc = crypto_scalarmult_ristretto255_base(&q, scalar(1))
        precondition(rc == 0, "ristretto255 base point")
        return q
    }()

    /// The Pedersen generator H = hash-to-group(SHA-512(label)): no known discrete log relative to G.
    static let H: Point = {
        ensure()
        return try! hashToCurve(Array(SHA512.hash(data: Data("atlas-pca-ratchet/pedersen-generator-H/v1".utf8))))
    }()

    // MARK: points

    /// RFC 9496 one-way map from 64 uniform bytes.
    static func hashToCurve(_ b: [UInt8]) throws -> Point {
        ensure()
        guard b.count == 64 else { throw PCARatchetError(nil, "hash_to_curve: need 64 bytes") }
        var p = zero
        guard crypto_core_ristretto255_from_hash(&p, b) == 0 else { throw PCARatchetError(nil, "hash_to_curve failed") }
        return p
    }

    /// The all-zero encoding is the identity (RFC 9496), which libsodium treats separately in a few places.
    static func isValid(_ p: [UInt8]) -> Bool {
        ensure()
        // RFC 9496: bit 255 must be clear; libsodium 1.0.18 (the Ubuntu package) ignores it, so it is checked here
        return p.count == 32 && p[31] & 0x80 == 0 && (p == zero || crypto_core_ristretto255_is_valid_point(p) == 1)
    }

    static func decode(_ raw: [UInt8]) throws -> Point {
        guard isValid(raw) else { throw PCARatchetError(nil, "ristretto255: invalid encoding") }
        return raw
    }

    static func encode(_ p: Point) -> String { Base64URLStrict.encode(p) }

    /// A canonical 32-byte base64url string that is a valid ristretto255 encoding.
    static func decodePoint(_ v: JSONValue?) throws -> Point {
        guard let s = v?.asString, let raw = Base64URLStrict.decode(s, length: 32) else {
            throw PCARatchetError(nil, "decode_point: not a canonical 32-byte base64url string")
        }
        return try decode(raw)
    }

    static func add(_ a: Point, _ b: Point) throws -> Point {
        ensure()
        var r = zero
        guard crypto_core_ristretto255_add(&r, a, b) == 0 else { throw PCARatchetError(nil, "ristretto255: invalid point") }
        return r
    }

    static func sub(_ a: Point, _ b: Point) throws -> Point {
        ensure()
        var r = zero
        guard crypto_core_ristretto255_sub(&r, a, b) == 0 else { throw PCARatchetError(nil, "ristretto255: invalid point") }
        return r
    }

    /// k * p. libsodium refuses a zero scalar and an identity result; the multiplication is always performed (by 1 when k = 0)
    /// and the identity selected afterwards, like the reference.
    static func mul(_ p: Point, _ k: Scalar) throws -> Point {
        ensure()
        let isZero = k == zero
        var q = zero
        let rc = crypto_scalarmult_ristretto255(&q, isZero ? scalar(1) : k, p)
        if isZero { guard isValid(p) else { throw PCARatchetError(nil, "ristretto255: invalid point") }; return zero }
        if rc != 0 {
            guard isValid(p) else { throw PCARatchetError(nil, "ristretto255: invalid point") }
            return zero // a non-zero scalar below the order of the prime-order group on the identity
        }
        return q
    }

    static func mul(_ p: Point, small k: UInt64) throws -> Point { try mul(p, scalar(k)) }

    // MARK: scalars

    /// `n` reduced modulo the group order, in constant time while it has at most 512 bits.
    static func scalar(_ n: BigUInt) -> Scalar {
        ensure()
        if n.bitLength <= 512 {
            var r = zero
            crypto_core_ristretto255_scalar_reduce(&r, n.ratchetBytesLE(64))
            return r
        }
        return Ed25519Deterministic.bytes32(Ed25519Deterministic.modL(n))
    }

    static func scalar(_ v: PCABigInt) -> Scalar {
        let s = scalar(v.mag)
        return v.neg ? scalarNegate(s) : s
    }

    static func scalarAdd(_ a: Scalar, _ b: Scalar) -> Scalar { ensure(); var z = zero; crypto_core_ristretto255_scalar_add(&z, a, b); return z }
    static func scalarSub(_ a: Scalar, _ b: Scalar) -> Scalar { ensure(); var z = zero; crypto_core_ristretto255_scalar_sub(&z, a, b); return z }
    static func scalarMul(_ a: Scalar, _ b: Scalar) -> Scalar { ensure(); var z = zero; crypto_core_ristretto255_scalar_mul(&z, a, b); return z }
    static func scalarNegate(_ a: Scalar) -> Scalar { ensure(); var z = zero; crypto_core_ristretto255_scalar_negate(&z, a); return z }

    static func randScalar() -> Scalar {
        ensure()
        while true {
            var r = zero
            crypto_core_ristretto255_scalar_random(&r)
            if r != zero { return r }
        }
    }

    static func encodeScalar(_ k: Scalar) -> String { Base64URLStrict.encode(k) }

    /// Strict: canonical base64url, exactly 32 bytes, value below the order (a reduced scalar would make every proof malleable).
    static func decodeScalar(_ v: JSONValue?) throws -> Scalar {
        guard let s = v?.asString, let raw = Base64URLStrict.decode(s, length: 32) else {
            throw PCARatchetError(nil, "decode_scalar: not a canonical 32-byte base64url string")
        }
        guard BigUInt(bytesLE: raw) < Ed25519Strict.L else { throw PCARatchetError(nil, "decode_scalar: non-canonical scalar (>= L)") }
        return raw
    }

    /// Length-prefixed (4-byte big-endian) transcript, SHA-512, reduced modulo the order.
    static func hashToScalar(_ parts: [[UInt8]]) -> Scalar {
        ensure()
        var buf: [UInt8] = []
        for p in parts {
            let n = UInt32(p.count)
            buf += [UInt8(truncatingIfNeeded: n >> 24), UInt8(truncatingIfNeeded: n >> 16), UInt8(truncatingIfNeeded: n >> 8), UInt8(truncatingIfNeeded: n)]
            buf += p
        }
        var r = zero
        crypto_core_ristretto255_scalar_reduce(&r, Array(SHA512.hash(data: Data(buf))))
        return r
    }
}
