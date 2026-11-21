import Foundation
import CryptoKit

/// Homomorphic risk accumulator with a zero-knowledge spend ceiling: Pedersen commitments on ristretto255 plus a bit-decomposition
/// range proof. Wire format of the reference: proofs are JSON objects with its camelCase member names. Group arithmetic is libsodium's
/// (constant time); verification needs no secret and never throws, malformed input is `false`.
public enum PCARatchetAccumulator {
    typealias RG = RatchetGroup
    typealias Point = RatchetGroup.Point
    typealias Scalar = RatchetGroup.Scalar

    public static let N_BITS = 32
    /// The largest ceiling a proof can express (2^N_BITS - 1); a larger ceiling is clamped, which only strengthens "sum <= ceiling".
    public static let MAX_PROVABLE_CEILING: UInt64 = (1 << 32) - 1

    public struct Commitment {
        public let commitment: String
        public let blinding: PCABigInt
    }

    // MARK: commitments

    private static func units(_ x: PCABigInt) throws -> BigUInt {
        if x.neg { throw PCARatchetError("invalid_value", "risk/budget must be >= 0") }
        return x.mag
    }

    /// Commit to a non-negative integer risk in units, with the given or a fresh random blinding.
    public static func commitRisk(_ risk: PCABigInt, blinding: PCABigInt? = nil) throws -> Commitment {
        let v = try units(risk)
        let b = blinding.map { RG.scalar($0) } ?? RG.randScalar()
        let c = try RG.add(RG.mul(RG.G, RG.scalar(v)), RG.mul(RG.H, b))
        return Commitment(commitment: RG.encode(c), blinding: PCABigInt(neg: false, mag: BigUInt(bytesLE: b)))
    }

    /// Homomorphic sum; an empty input commits to (0, 0), the identity.
    public static func addCommitments(_ commitments: [String]) throws -> String {
        var acc = RG.zero
        for c in commitments { acc = try RG.add(acc, RG.decodePoint(.string(c))) }
        return RG.encode(acc)
    }

    /// Never throws; malformed input is false.
    public static func openCommitment(_ commitment: JSONValue?, risk: PCABigInt, blinding: PCABigInt) -> Bool {
        do {
            let v = try units(risk)
            let expected = try RG.add(RG.mul(RG.G, RG.scalar(v)), RG.mul(RG.H, RG.scalar(blinding)))
            return try RG.decodePoint(commitment) == expected
        } catch { return false }
    }

    // MARK: transcripts

    private static func u(_ s: String) -> [UInt8] { Array(s.utf8) }
    private static let ctxDomain = u("atlas-pca-ratchet/budget/ctx/v1")
    private static let riskCtxDomain = u("atlas-pca-ratchet/risk-range/ctx/v1")
    private static let orDomain = u("atlas-pca-ratchet/budget/bit-or/v1")
    private static let aggDomain = u("atlas-pca-ratchet/budget/agg/v1")

    private static func effectiveCeiling(_ bMax: BigUInt) -> UInt64 {
        bMax > BigUInt(MAX_PROVABLE_CEILING) ? MAX_PROVABLE_CEILING : bMax.ratchetLow64
    }

    private static func contextHash(ceiling: UInt64, sum: Point, bits: [Point]) -> [UInt8] {
        RG.hashToScalar([ctxDomain, [UInt8(N_BITS & 0xFF)], RG.scalar(ceiling), sum] + bits)
    }

    private static func riskContextHash(commitment: Point, bits: [Point]) -> [UInt8] {
        RG.hashToScalar([riskCtxDomain, [UInt8(N_BITS & 0xFF)], commitment] + bits)
    }

    // MARK: bit (OR) and aggregate (Schnorr) proofs

    private static func member(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.get(k) }

    private static func proveBit(_ ctx: [UInt8], _ index: Int, _ bPt: Point, _ bit: Int, _ s: Scalar) throws -> JSONValue {
        let p0 = bPt
        let p1 = try RG.sub(bPt, RG.G)
        let real = bit == 1 ? 1 : 0
        let eFake = RG.randScalar(), zFake = RG.randScalar()
        let pFake = real == 1 ? p0 : p1
        let aFake = try RG.sub(RG.mul(RG.H, zFake), RG.mul(pFake, eFake))
        let k = RG.randScalar()
        let aReal = try RG.mul(RG.H, k)
        let a0 = real == 0 ? aReal : aFake
        let a1 = real == 1 ? aReal : aFake
        let e = RG.hashToScalar([orDomain, ctx, [UInt8(index & 0xFF)], a0, a1])
        let eReal = RG.scalarSub(e, eFake)
        let zReal = RG.scalarAdd(k, RG.scalarMul(eReal, s))
        let (e0, e1) = real == 0 ? (eReal, eFake) : (eFake, eReal)
        let (z0, z1) = real == 0 ? (zReal, zFake) : (zFake, zReal)
        return .object(["e0": .string(RG.encodeScalar(e0)), "e1": .string(RG.encodeScalar(e1)),
                        "z0": .string(RG.encodeScalar(z0)), "z1": .string(RG.encodeScalar(z1))])
    }

    private static func verifyBit(_ ctx: [UInt8], _ index: Int, _ bPt: Point, _ proof: JSONValue?) throws -> Bool {
        let e0 = try RG.decodeScalar(member(proof, "e0")), e1 = try RG.decodeScalar(member(proof, "e1"))
        let z0 = try RG.decodeScalar(member(proof, "z0")), z1 = try RG.decodeScalar(member(proof, "z1"))
        let a0 = try RG.sub(RG.mul(RG.H, z0), RG.mul(bPt, e0))
        let a1 = try RG.sub(RG.mul(RG.H, z1), RG.mul(RG.sub(bPt, RG.G), e1))
        let e = RG.hashToScalar([orDomain, ctx, [UInt8(index & 0xFF)], a0, a1])
        return RG.scalarAdd(e0, e1) == e
    }

    private static func proveSchnorr(_ ctx: [UInt8], _ d: Point, _ w: Scalar) throws -> JSONValue {
        let k = RG.randScalar()
        let a = try RG.mul(RG.H, k)
        let e = RG.hashToScalar([aggDomain, ctx, d, a])
        let z = RG.scalarAdd(k, RG.scalarMul(e, w))
        return .object(["a": .string(RG.encode(a)), "z": .string(RG.encodeScalar(z))])
    }

    private static func verifySchnorr(_ ctx: [UInt8], _ d: Point, _ proof: JSONValue?) throws -> Bool {
        let a = try RG.decodePoint(member(proof, "a"))
        let z = try RG.decodeScalar(member(proof, "z"))
        let e = RG.hashToScalar([aggDomain, ctx, d, a])
        return try RG.mul(RG.H, z) == RG.add(a, RG.mul(d, e))
    }

    // MARK: range proof

    /// `value` is the low N_BITS bits (two's complement for a negative slack) of the committed value; `gamma` its blinding.
    private static func rangeProve(_ makeCtx: ([Point]) -> [UInt8], _ vPt: Point, _ value: UInt32, _ gamma: Scalar) throws -> JSONValue {
        var bitCommitments: [Point] = [], blindings: [Scalar] = [], bits: [Int] = []
        for i in 0..<N_BITS {
            let bit = Int((value >> UInt32(i)) & 1)
            let s = RG.randScalar()
            bits.append(bit)
            blindings.append(s)
            bitCommitments.append(try RG.add(RG.mul(RG.G, small: UInt64(bit)), RG.mul(RG.H, s)))
        }
        let ctx = makeCtx(bitCommitments)
        var orp: [JSONValue] = []
        for i in 0..<N_BITS { orp.append(try proveBit(ctx, i, bitCommitments[i], bits[i], blindings[i])) }
        var sStar = RG.zero
        var aggPoint = RG.zero
        for i in 0..<N_BITS {
            let w = RG.scalar(UInt64(1) << UInt64(i))
            sStar = RG.scalarAdd(sStar, RG.scalarMul(w, blindings[i]))
            aggPoint = try RG.add(aggPoint, RG.mul(bitCommitments[i], w))
        }
        let agg = try proveSchnorr(ctx, RG.sub(aggPoint, vPt), RG.scalarSub(sStar, gamma))
        return .object(["n": .int(Int64(N_BITS)), "bitCommitments": .array(bitCommitments.map { .string(RG.encode($0)) }),
                        "or": .array(orp), "agg": agg])
    }

    private static func rangeVerify(_ makeCtx: ([Point]) -> [UInt8], _ vPt: Point, _ proof: JSONValue?) throws -> Bool {
        guard proof?.isObject == true, let n = proof?.get("n"), n.isNumber, JS.toNumber(n) == Double(N_BITS),
              let bc = proof?.get("bitCommitments")?.asArray, let orp = proof?.get("or")?.asArray, bc.count == N_BITS, orp.count == N_BITS,
              let agg = proof?.get("agg"), agg.isObject else { return false }
        let b = try bc.map { try RG.decodePoint($0) }
        let ctx = makeCtx(b)
        for i in 0..<N_BITS { if !(try verifyBit(ctx, i, b[i], orp[i])) { return false } }
        var aggPoint = RG.zero
        for i in 0..<N_BITS { aggPoint = try RG.add(aggPoint, RG.mul(b[i], small: UInt64(1) << UInt64(i))) }
        return try verifySchnorr(ctx, RG.sub(aggPoint, vPt), agg)
    }

    // MARK: budget and risk range

    /// Prove sum(risk) <= bMax over the committed values. An over-budget input yields a well-formed proof the verifier rejects.
    public static func proveBudget(risks: [PCABigInt], blindings: [PCABigInt], bMax: PCABigInt) throws -> JSONValue {
        guard risks.count == blindings.count else { throw PCARatchetError("length_mismatch", "risks and blindings must have equal length") }
        let ceiling = effectiveCeiling(try units(bMax))
        var sumRisk = BigUInt()
        var sumBlind = RG.zero
        for i in risks.indices {
            sumRisk = sumRisk + (try units(risks[i]))
            sumBlind = RG.scalarAdd(sumBlind, RG.scalar(blindings[i]))
        }
        let cSum = try RG.add(RG.mul(RG.G, RG.scalar(sumRisk)), RG.mul(RG.H, sumBlind))
        let vPt = try RG.sub(RG.mul(RG.G, RG.scalar(ceiling)), cSum)
        let slack = UInt32(truncatingIfNeeded: ceiling) &- sumRisk.ratchetLow32
        return try rangeProve({ contextHash(ceiling: ceiling, sum: cSum, bits: $0) }, vPt, slack, RG.scalarNegate(sumBlind))
    }

    /// Never throws; malformed input is false. Ceilings above 2^N_BITS - 1 are clamped.
    public static func verifyBudget(_ commitmentSum: JSONValue?, bMax: PCABigInt, proof: JSONValue?) -> Bool {
        do {
            let ceiling = effectiveCeiling(try units(bMax))
            let cSum = try RG.decodePoint(commitmentSum)
            let vPt = try RG.sub(RG.mul(RG.G, RG.scalar(ceiling)), cSum)
            return try rangeVerify({ contextHash(ceiling: ceiling, sum: cSum, bits: $0) }, vPt, proof)
        } catch { return false }
    }

    /// Prove that commitRisk(risk, blinding) holds a value in [0, 2^N_BITS).
    public static func proveRiskRange(_ risk: PCABigInt, blinding: PCABigInt) throws -> JSONValue {
        let v = try units(risk)
        let b = RG.scalar(blinding)
        let c = try RG.add(RG.mul(RG.G, RG.scalar(v)), RG.mul(RG.H, b))
        return try rangeProve({ riskContextHash(commitment: c, bits: $0) }, c, v.ratchetLow32, b)
    }

    public static func verifyRiskRange(_ commitment: JSONValue?, proof: JSONValue?) -> Bool {
        do {
            let c = try RG.decodePoint(commitment)
            return try rangeVerify({ riskContextHash(commitment: c, bits: $0) }, c, proof)
        } catch { return false }
    }

    /// Every commitment carries a valid range proof and the budget proof verifies for their sum. Never throws.
    public static func verifyBoundedBudget(_ commitments: JSONValue?, rangeProofs: JSONValue?, bMax: PCABigInt, budgetProof: JSONValue?) -> Bool {
        guard let cs = commitments?.asArray, let rps = rangeProofs?.asArray, cs.count == rps.count else { return false }
        for i in cs.indices { if !verifyRiskRange(cs[i], proof: rps[i]) { return false } }
        do {
            var strings: [String] = []
            for c in cs { guard let s = c.asString else { return false }; strings.append(s) }
            return verifyBudget(.string(try addCommitments(strings)), bMax: bMax, proof: budgetProof)
        } catch { return false }
    }
}
