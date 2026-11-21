import Foundation
import AtlasPCAVerify

/// The reference's flat names for the arithmetic, sharing and authenticated-share operations of the MPC package (the implementations are the
/// namespaced ones: `Field`, `Sharing`, `Beaver`, `Spdz`, `Gf128`).
extension PCAMpc {
    // MARK: field and GF(2^128)

    /// `-x` in F_p.
    public static func fneg(_ x: UInt64) -> UInt64 { Field.neg(x) }

    /// The canonical representative in [0, q) of a signed decimal integer (q = 2^255 - 19, the Ed25519 field prime), as a decimal string; nil
    /// when `x` is not a decimal integer (or exceeds 512 bits).
    public static func modFq(_ x: String) -> String? { Fe(decimal: x)?.decimal }

    /// The canonical representative in [0, p) of a signed decimal integer of any length (p = 2^61 - 1, the sharing field); nil when `x` is not a decimal integer.
    public static func mod(_ x: String) -> UInt64? { Field.parse(x) }
    /// a + b, a - b and a * b in F_p; the operands are reduced into the field first (the reference reduces whatever bigint it is given).
    public static func fadd(_ a: UInt64, _ b: UInt64) -> UInt64 { Field.add(a % Field.prime, b % Field.prime) }
    public static func fsub(_ a: UInt64, _ b: UInt64) -> UInt64 { Field.sub(a % Field.prime, b % Field.prime) }
    public static func fmul(_ a: UInt64, _ b: UInt64) -> UInt64 { Field.mul(a % Field.prime, b % Field.prime) }

    // MARK: Ed25519 group elements as canonical 32-byte compressed points (the contract of the reference's wasm group core)

    /// The prime order of the base-point subgroup, L = 2^252 + 27742317777372353535851937790883648493, as 32 little-endian bytes (scalars live in [0, L)); `LDecimal` is the same in decimal.
    public static let L: [UInt8] = Sodium.L
    public static let LDecimal: String = Sodium.decimal(Sodium.L)

    private static func point(_ p: [UInt8]) -> Ec.Point? { p.count == 32 ? try? Ec.decompressPoint(p) : nil }

    /// Whether `p` is the strict canonical compressed encoding of a curve point (a non-canonical y, or x = 0 with the sign bit set, is refused, never reduced).
    public static func isOnCurve(_ p: [UInt8]) -> Bool { point(p) != nil }
    /// Whether `p` is a valid NON-identity point of the prime-order subgroup (on curve, not the identity, [L]P = O).
    public static func isInSubgroup(_ p: [UInt8]) -> Bool { point(p).map { Ec.isInSubgroup($0) } ?? false }
    /// Throws a `PointValidationError` unless `p` is a valid non-identity prime-order-subgroup point; the messages are the reference's, prefixed by `label`.
    public static func assertInSubgroup(_ p: [UInt8], _ label: String = "point") throws {
        guard let q = point(p) else { throw PointValidationError("\(label): not on curve") }
        try Ec.assertInSubgroup(q, label)
    }
    /// Whether `a` and `b` are valid curve points equal as group elements (false when either is not a valid point).
    public static func equal(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard let x = point(a), let y = point(b) else { return false }
        return Ec.equal(x, y)
    }
    /// A copy of the canonical compressed encoding of `p`; throws when `p` is not a valid point.
    public static func encodePoint(_ p: [UInt8]) throws -> [UInt8] {
        guard isOnCurve(p) else { throw PointValidationError("encodePoint: point not on curve") }
        return p
    }
    /// Decodes and validates a 32-byte compressed point; throws when it is not on the curve.
    public static func decodePoint(_ bytes: [UInt8]) throws -> [UInt8] {
        guard isOnCurve(bytes) else { throw PointValidationError("decodePoint: point not on curve") }
        return bytes
    }

    /// v * x in GF(2^128).
    public static func gf128MulX(_ v: Gf128) -> Gf128 { v.mulX() }

    /// v * x^i in GF(2^128).
    public static func gf128MulByXi(_ v: Gf128, _ i: Int) -> Gf128 { v.mulByXi(i) }

    // MARK: randomness

    /// A field-element source drawing from the system CSPRNG (the default for protocol randomness).
    public struct SecureFieldRng {
        private var rng = Field.Rng.secure()
        public init() {}
        /// A uniform element of [0, p).
        public mutating func next() -> UInt64 { rng.next() }
    }

    /// The protocol source of field elements: the CSPRNG, or the seeded SplitMix64 stream when a test seed is given (reproducible tests only).
    public static func fieldRandom(testSeed: UInt64? = nil) -> Field.Rng { Field.Rng.make(seed: testSeed) }

    // MARK: Beaver triples

    /// `count` independent Beaver triples shared among `n` parties.
    public static func genTriples(_ count: Int, _ n: Int, _ rng: inout Field.Rng) throws -> [Beaver.Triple] {
        var out: [Beaver.Triple] = []
        for _ in 0..<max(count, 0) { out.append(try Beaver.genTriple(n, &rng)) }
        return out
    }

    // MARK: additive shared values

    public static func subSV(_ x: [UInt64], _ y: [UInt64]) throws -> [UInt64] { try Sharing.sub(x, y) }
    public static func negSV(_ x: [UInt64]) -> [UInt64] { Sharing.neg(x) }
    /// x * c, c reduced into the field first.
    public static func scaleSV(_ x: [UInt64], _ c: UInt64) -> [UInt64] { Sharing.scale(x, c % Field.prime) }
    /// x + c (added to the first party's share), c reduced into the field first.
    public static func addPublicSV(_ x: [UInt64], _ c: UInt64) -> [UInt64] { Sharing.addPublic(x, c % Field.prime) }
    public static func notBitSV(_ b: [UInt64]) -> [UInt64] { Sharing.notBit(b) }

    // MARK: authenticated shared values (SPDZ)

    public static func addAuth(_ x: Spdz.AuthSV, _ y: Spdz.AuthSV) throws -> Spdz.AuthSV { try Spdz.add(x, y) }
    public static func subAuth(_ x: Spdz.AuthSV, _ y: Spdz.AuthSV) throws -> Spdz.AuthSV { try Spdz.sub(x, y) }
    public static func negAuth(_ x: Spdz.AuthSV) -> Spdz.AuthSV { Spdz.neg(x) }
    /// x * c, c reduced into the field first.
    public static func scaleAuth(_ x: Spdz.AuthSV, _ c: UInt64) -> Spdz.AuthSV { Spdz.scale(x, c % Field.prime) }
    public static func notBitAuth(_ b: Spdz.AuthSV, _ ctx: Spdz.MacContext) throws -> Spdz.AuthSV { try Spdz.notBit(b, ctx) }
    /// The reconstructed value of an authenticated share (unchecked: the MAC check is `Spdz.Engine.macCheck`).
    public static func authValue(_ x: Spdz.AuthSV) -> UInt64 { Spdz.value(x) }
    /// x*y from an authenticated triple, opening d and e through `engine` (MAC-checked later).
    public static func beaverMulAuth(_ x: Spdz.AuthSV, _ y: Spdz.AuthSV, _ t: Spdz.AuthTriple, _ ctx: Spdz.MacContext, _ engine: Spdz.Engine,
                                     _ label: String) throws -> Spdz.AuthSV { try Spdz.beaverMul(x, y, t, ctx, engine, label) }
}

// MARK: per-stakeholder local evaluation

extension PCAMpc {
    /// A stakeholder and its PRIVATE Policy-VM input (never shared with other parties).
    public struct PartyPolicy {
        public var id: String
        public var decideInput: JSONValue
        public init(id: String, decideInput: JSONValue) { self.id = id; self.decideInput = decideInput }
    }

    /// Evaluates a party's own policy through the Policy VM to its decision vector: allow = releaseGuardianShare, t = requiredThreshold.t,
    /// rQuant = quantized r. Fails closed (deny, t = 3, worst risk) when the input cannot be decided.
    public static func evaluateParty(_ policy: PartyPolicy, _ Q: Int = DEFAULT_Q) -> DecisionVector {
        guard let d = try? PCAPolicyVm.decide(policy.decideInput), let t = IV.num(d.mpcGet("requiredThreshold")?.mpcGet("t")), t >= 1, t <= 3 else {
            return DecisionVector(allow: 0, t: 3, rQuant: Q)
        }
        return DecisionVector(allow: d.mpcGet("releaseGuardianShare") == .bool(true) ? 1 : 0, t: Int(t), rQuant: quantizeR(IV.num(d.mpcGet("r")) ?? .nan, Q))
    }
}
