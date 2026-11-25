import Foundation

/// The deterministic layer of the multi-party authorization package (the reference is @atlasauth/pca-mpc): arithmetic in F_p (p = 2^61 - 1), additive
/// secret sharing, Beaver-triple multiplication, GF(2^128), the thermometer encoding and the cleartext composition of stakeholder decisions. Every random
/// draw comes from an explicit `Field.Rng` (SplitMix64) the caller seeds, so a test reproduces every share and transcript; protocol randomness is the
/// caller's responsibility (there is no ambient generator here).
///
/// The encrypted-bit gadgets, the SPDZ engine and malicious runner, the oblivious-transfer stack (Ed25519 base OT, KOS extension, ML-KEM and hybrid base OTs,
/// the MASCOT no-dealer offline phase) and the pure parts of the networked runner (wire, pairwise-authenticated shares, forensics, codecs) are in the sibling
/// files. Not carried: the socket / TLS driver of the networked runner.
public enum PCAMpc {
    public struct MpcError: Error, CustomStringConvertible {
        public let description: String
        init(_ m: String) { description = m }
    }

    // MARK: F_p, p = 2^61 - 1

    public enum Field {
        public static let prime: UInt64 = (1 << 61) - 1

        /// hi * 2^64 + lo reduced mod p (2^61 = 1, so the value folds by 61-bit chunks); hi must be below 2^58 (a product of two field elements).
        static func reduce(_ hi: UInt64, _ lo: UInt64) -> UInt64 {
            var t = (lo & prime) &+ ((lo >> 61) | (hi << 3))
            t = (t & prime) &+ (t >> 61)
            return t >= prime ? t - prime : t
        }

        public static func add(_ a: UInt64, _ b: UInt64) -> UInt64 { let s = a &+ b; return s >= prime ? s - prime : s }
        public static func sub(_ a: UInt64, _ b: UInt64) -> UInt64 { a >= b ? a - b : a &+ prime &- b }
        public static func neg(_ a: UInt64) -> UInt64 { a == 0 ? 0 : prime - a }
        public static func mul(_ a: UInt64, _ b: UInt64) -> UInt64 { let p = a.multipliedFullWidth(by: b); return reduce(p.high, p.low) }

        /// A decimal integer (optionally signed, any length) reduced into [0, p); nil when `s` is not a decimal integer.
        public static func parse(_ s: String) -> UInt64? {
            var u = Array(s.utf8)
            var negative = false
            if let f = u.first, f == UInt8(ascii: "-") || f == UInt8(ascii: "+") { negative = f == UInt8(ascii: "-"); u.removeFirst() }
            guard !u.isEmpty else { return nil }
            var r: UInt64 = 0
            for c in u {
                guard c >= 48 && c <= 57 else { return nil }
                r = add(mul(r, 10), UInt64(c - 48))
            }
            return negative ? neg(r) : r
        }

        /// The low 64 bits of a decimal integer in two's complement (BigInt.asUintN(64, x)); nil when `s` is not a decimal integer.
        public static func low64(_ s: String) -> UInt64? {
            var u = Array(s.utf8)
            var negative = false
            if let f = u.first, f == UInt8(ascii: "-") || f == UInt8(ascii: "+") { negative = f == UInt8(ascii: "-"); u.removeFirst() }
            guard !u.isEmpty else { return nil }
            var r: UInt64 = 0
            for c in u {
                guard c >= 48 && c <= 57 else { return nil }
                r = r &* 10 &+ UInt64(c - 48)
            }
            return negative ? 0 &- r : r
        }

        /// Draws unbiased field elements by rejection sampling: from the seeded SplitMix64 of the reference (reproducible tests behind an explicit
        /// seed) or, via `secure()`, from the system CSPRNG (the default for protocol randomness).
        public struct Rng {
            private var s: UInt64
            private let system: Bool
            public init(seed: UInt64 = 0x243f6a8885a308d3) { s = seed; system = false }
            private init(system: Bool) { s = 0; self.system = system }
            /// The CSPRNG-backed source.
            public static func secure() -> Rng { Rng(system: true) }
            /// `seed` when given, else the CSPRNG.
            public static func make(seed: UInt64?) -> Rng { seed.map { Rng(seed: $0) } ?? secure() }
            mutating func nextU64() -> UInt64 {
                if system { return UInt64.random(in: 0...UInt64.max) }
                s = s &+ 0x9e3779b97f4a7c15
                var z = s
                z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
                z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
                return z ^ (z >> 31)
            }
            /// A uniform element of [0, p): draws at or above the largest multiple of p below 2^64 are rejected.
            public mutating func next() -> UInt64 {
                while true {
                    let u = nextU64()
                    if u < 0xFFFF_FFFF_FFFF_FFF8 { return u % PCAMpc.Field.prime }
                }
            }
        }
    }

    // MARK: additive sharing

    /// Largest party count accepted (bounds allocation).
    public static let MAX_PARTIES = 1024

    public enum Sharing {
        public static func share(_ secret: UInt64, _ n: Int, _ rng: inout Field.Rng) throws -> [UInt64] {
            guard n >= 1 && n <= PCAMpc.MAX_PARTIES else { throw MpcError("share: n must be an integer in [1, \(PCAMpc.MAX_PARTIES)]") }
            var out: [UInt64] = []
            var acc: UInt64 = 0
            for _ in 0..<(n - 1) { let s = rng.next(); out.append(s); acc = Field.add(acc, s) }
            out.append(Field.sub(secret, acc))
            return out
        }

        /// All-or-nothing: fails closed on no shares and on an absent one.
        public static func reconstruct(_ shares: [UInt64?]) throws -> UInt64 {
            guard !shares.isEmpty else { throw MpcError("reconstruct: no shares (fail closed)") }
            var acc: UInt64 = 0
            for s in shares {
                guard let s = s else { throw MpcError("reconstruct: missing share (fail closed)") }
                acc = Field.add(acc, s)
            }
            return acc
        }

        public static func shareConstant(_ c: UInt64, _ n: Int) throws -> [UInt64] {
            guard n >= 1 && n <= PCAMpc.MAX_PARTIES else { throw MpcError("shareConstant: n must be an integer in [1, \(PCAMpc.MAX_PARTIES)]") }
            var out = [UInt64](repeating: 0, count: n)
            out[0] = c
            return out
        }

        private static func same(_ x: [UInt64], _ y: [UInt64]) throws {
            guard x.count == y.count else { throw MpcError("shared values must have the same party count") }
        }

        public static func add(_ x: [UInt64], _ y: [UInt64]) throws -> [UInt64] { try same(x, y); return zip(x, y).map { Field.add($0, $1) } }
        public static func sub(_ x: [UInt64], _ y: [UInt64]) throws -> [UInt64] { try same(x, y); return zip(x, y).map { Field.sub($0, $1) } }
        public static func neg(_ x: [UInt64]) -> [UInt64] { x.map(Field.neg) }
        public static func scale(_ x: [UInt64], _ c: UInt64) -> [UInt64] { x.map { Field.mul($0, c) } }
        public static func addPublic(_ x: [UInt64], _ c: UInt64) -> [UInt64] {
            var o = x
            if !o.isEmpty { o[0] = Field.add(o[0], c) }
            return o
        }
        public static func notBit(_ b: [UInt64]) -> [UInt64] { addPublic(neg(b), 1) }
    }

    // MARK: Beaver triples

    public enum Beaver {
        public struct Triple { public var a: [UInt64]; public var b: [UInt64]; public var c: [UInt64] }
        /// One opened (public) protocol message; `label` is "d" or "e".
        public struct Opened { public var label: String; public var value: UInt64; public var shares: [UInt64] }

        public static func genTriple(_ n: Int, _ rng: inout Field.Rng) throws -> Triple {
            let a = rng.next(), b = rng.next()
            let c = Field.mul(a, b)
            return Triple(a: try Sharing.share(a, n, &rng), b: try Sharing.share(b, n, &rng), c: try Sharing.share(c, n, &rng))
        }

        /// x*y consuming `triple`; the opened values d = x - a and e = y - b come back as the transcript.
        public static func mul(_ x: [UInt64], _ y: [UInt64], _ t: Triple) throws -> (z: [UInt64], opened: [Opened]) {
            guard x.count == y.count else { throw MpcError("beaverMul: operand party counts differ") }
            for part in [t.a, t.b, t.c] where part.count != x.count { throw MpcError("beaverMul: triple party count differs from the operands") }
            let dShares = try Sharing.sub(x, t.a), eShares = try Sharing.sub(y, t.b)
            let d = try Sharing.reconstruct(dShares), e = try Sharing.reconstruct(eShares)
            let de = Field.mul(d, e)
            var z: [UInt64] = []
            for i in x.indices {
                let zi = Field.add(t.c[i], Field.add(Field.mul(d, t.b[i]), Field.mul(e, t.a[i])))
                z.append(i == 0 ? Field.add(zi, de) : zi)
            }
            return (z, [Opened(label: "d", value: d, shares: dShares), Opened(label: "e", value: e, shares: eShares)])
        }
    }

    // MARK: thermometer encoding and composition

    public enum Thermometer {
        /// ge[k] = [v >= k] for k = 1..M; v is truncated and clamped into [0, M] (NaN encodes all zeros).
        public static func encode(_ v: Double, _ M: Int) throws -> [Int] {
            guard M >= 0 else { throw MpcError("thermometerEncode: M must be a non-negative integer") }
            let tr = v.rounded(.towardZero)
            let clamped = tr.isNaN ? Double.nan : max(0, min(Double(M), tr))
            return (0..<M).map { clamped >= Double($0 + 1) ? 1 : 0 }
        }

        /// The number of 1s (robust to non-monotone input).
        public static func decode(_ bits: [Int]) -> Int { bits.filter { $0 == 1 }.count }
    }

    public static let DEFAULT_Q = 100

    /// Quantizes r in [0, 1] to {0..Q}; a non-finite r is the worst case (Q).
    public static func quantizeR(_ r: Double, _ Q: Int = DEFAULT_Q) -> Int {
        if !r.isFinite { return Q }
        let q = (max(0, min(1, r)) * Double(Q) + 0.5).rounded(.down) // Math.round for the non-negative values reached here
        return max(0, min(Q, Int(q)))
    }

    /// The decision a party contributes: allow in {0,1}, t in {1,2,3}, rQuant in {0..Q}.
    public struct DecisionVector: Equatable {
        public var allow: Int, t: Int, rQuant: Int
        public init(allow: Int, t: Int, rQuant: Int) { self.allow = allow; self.t = t; self.rQuant = rQuant }
    }

    /// Rejects a malformed decision vector (a nil entry is "not an object").
    public static func assertDecisionVectors(_ vectors: [DecisionVector?]?, _ Q: Int) throws {
        guard let vs = vectors else { throw MpcError("decision vectors must be an array") }
        for (i, v) in vs.enumerated() {
            guard let v = v else { throw MpcError("party \(i): decision vector must be an object") }
            guard v.allow == 0 || v.allow == 1 else { throw MpcError("party \(i): allow must be 0 or 1") }
            guard v.t >= 1 && v.t <= 3 else { throw MpcError("party \(i): t must be 1, 2 or 3") }
            guard v.rQuant >= 0 && v.rQuant <= Q else { throw MpcError("party \(i): rQuant must be an integer in [0, \(Q)]") }
        }
    }

    /// The meet of the stakeholders' authorities: allow = AND, t = MAX, rQuant = MAX. Composition can only tighten.
    public static func composeClear(_ vectors: [DecisionVector?], _ Q: Int = DEFAULT_Q) throws -> DecisionVector {
        guard !vectors.isEmpty else { throw MpcError("composeClear: no parties (fail closed)") }
        try assertDecisionVectors(vectors, Q)
        var out = DecisionVector(allow: 1, t: 1, rQuant: 0)
        for case let v? in vectors {
            if v.allow == 0 { out.allow = 0 }
            out.t = max(out.t, v.t)
            out.rQuant = max(out.rQuant, v.rQuant)
        }
        return out
    }

    // MARK: GF(2^128), x^128 + x^7 + x^2 + x + 1 (the field of the KOS correlation check)

    public struct Gf128: Equatable {
        public var hi: UInt64, lo: UInt64
        public init(hi: UInt64, lo: UInt64) { self.hi = hi; self.lo = lo }

        /// A decimal integer taken modulo 2^128 (two's complement for a negative one); nil when `s` is not a decimal integer.
        public init?(decimal s: String) {
            var u = Array(s.utf8)
            var negative = false
            if let f = u.first, f == UInt8(ascii: "-") || f == UInt8(ascii: "+") { negative = f == UInt8(ascii: "-"); u.removeFirst() }
            guard !u.isEmpty else { return nil }
            var r = Gf128(hi: 0, lo: 0)
            for c in u {
                guard c >= 48 && c <= 57 else { return nil }
                let p = r.lo.multipliedFullWidth(by: 10)
                let (lo, carry) = p.low.addingReportingOverflow(UInt64(c - 48))
                r = Gf128(hi: r.hi &* 10 &+ p.high &+ (carry ? 1 : 0), lo: lo)
            }
            if negative { // 0 - r
                let (lo, borrow) = (0 as UInt64).subtractingReportingOverflow(r.lo)
                r = Gf128(hi: 0 &- r.hi &- (borrow ? 1 : 0), lo: lo)
            }
            self = r
        }

        public var decimal: String {
            if hi == 0 && lo == 0 { return "0" }
            let base: UInt64 = 10_000_000_000_000_000_000
            var h = hi, l = lo
            var chunks: [UInt64] = []
            while h != 0 || l != 0 {
                let qh = h / base, rh = h % base
                let (ql, rl) = base.dividingFullWidth((rh, l))
                chunks.append(rl)
                h = qh; l = ql
            }
            var s = String(chunks.last ?? 0)
            for c in chunks.dropLast().reversed() { let t = String(c); s += String(repeating: "0", count: 19 - t.count) + t }
            return s
        }

        public static func add(_ a: Gf128, _ b: Gf128) -> Gf128 { Gf128(hi: a.hi ^ b.hi, lo: a.lo ^ b.lo) }

        public func mulX() -> Gf128 {
            let carry = hi >> 63 == 1
            let r = Gf128(hi: (hi << 1) | (lo >> 63), lo: lo << 1)
            return carry ? Gf128(hi: r.hi, lo: r.lo ^ 0x87) : r
        }

        public func mulByXi(_ i: Int) -> Gf128 {
            var r = self
            for _ in 0..<max(i, 0) { r = r.mulX() }
            return r
        }

        public static func mul(_ a: Gf128, _ b: Gf128) -> Gf128 {
            var res = Gf128(hi: 0, lo: 0), v = a
            for i in 0..<128 {
                let bit = i < 64 ? (b.lo >> UInt64(i)) & 1 : (b.hi >> UInt64(i - 64)) & 1
                if bit == 1 { res = add(res, v) }
                v = v.mulX()
            }
            return res
        }
    }
}
