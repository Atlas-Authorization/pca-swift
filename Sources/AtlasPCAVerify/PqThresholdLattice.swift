import Foundation

/// EXPERIMENTAL, NOT PRODUCTION. A TOY additive secret-sharing sketch of the Raccoon / Ringtail-style lattice-threshold idea (the reference's
/// experimental lattice-threshold module): it documents the future, it is not a signature scheme.
///
/// The sharing is n-of-n over Z_q (all shares reconstruct), the arithmetic is variable-time, and the default sampler is not a vetted key generator.
/// The shippable post-quantum threshold is the hybrid in `PQThreshold`. Every function is gated behind an explicit opt-in and refuses with the banner
/// without it (fail closed).
public enum PCALatticeThresholdToy {
    /// The banner every refusal carries.
    public static let experimentalBanner = "EXPERIMENTAL \u{2014} NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign."

    /// The explicit, loud opt-in a caller must set to run any routine here.
    public struct OptIn: Sendable {
        public var iUnderstandThisIsNotProduction: Bool
        public init(iUnderstandThisIsNotProduction: Bool = false) { self.iUnderstandThisIsNotProduction = iUnderstandThisIsNotProduction }
    }

    /// Toy lattice parameters: the modulus and the key dimension.
    public struct Params: Equatable, Sendable {
        public var q: UInt64
        public var dim: Int
        public init(q: UInt64, dim: Int) { self.q = q; self.dim = dim }
        /// The ML-DSA modulus, used only so the arithmetic looks familiar.
        public static let `default` = Params(q: 8_380_417, dim: 4)
    }

    /// One party's additive share: a coefficient vector mod q.
    public struct KeyShare: Equatable, Sendable {
        /// 1-based party index.
        public var index: Int
        public var coeffs: [UInt64]
        public init(index: Int, coeffs: [UInt64]) { self.index = index; self.coeffs = coeffs }
    }

    /// A source of a random coefficient in `[0, q)`.
    public typealias Sampler = (UInt64) -> UInt64

    private static func assertOptIn(_ o: OptIn) throws {
        if !o.iUnderstandThisIsNotProduction { throw JSError("\(experimentalBanner) Pass { iUnderstandThisIsNotProduction: true } to proceed.") }
    }

    /// Additively share a toy key vector into `n` shares over Z_q: shares 1..n-1 are random, the last absorbs the remainder, so the shares sum
    /// to the key coefficient-wise. `n` is 1...1024 and the key has `params.dim` coefficients.
    public static func additiveShareLatticeKey(_ key: [Int64], n: Int, optIn: OptIn, params: Params = .default, sampler: Sampler? = nil) throws -> [KeyShare] {
        try assertOptIn(optIn)
        if params.q == 0 { throw JSError("additiveShareLatticeKey: q must be positive") }
        if !(1...1024).contains(n) { throw JSError("additiveShareLatticeKey: n must be an integer in [1, 1024]") }
        if key.count != params.dim { throw JSError("additiveShareLatticeKey: key must have \(params.dim) coefficients") }
        let q = params.q
        let sample: Sampler = sampler ?? { m in
            var g = SystemRandomNumberGenerator() // the OS random source, never a fixed coefficient
            return g.next() % m
        }
        var shares = [[UInt64]](repeating: [UInt64](repeating: 0, count: params.dim), count: n)
        for c in 0..<params.dim {
            let target = modSigned(key[c], q)
            var running: UInt64 = 0
            for i in 0..<(n - 1) {
                let r = sample(q) % q
                shares[i][c] = r
                running = addMod(running, r, q)
            }
            shares[n - 1][c] = subMod(target, running, q)
        }
        return shares.enumerated().map { KeyShare(index: $0.offset + 1, coeffs: $0.element) }
    }

    /// Reconstruct the toy key by summing ALL shares mod q (n-of-n: every share must be present, no index twice).
    public static func reconstructLatticeKey(_ shares: [KeyShare], optIn: OptIn, params: Params = .default) throws -> [UInt64] {
        try assertOptIn(optIn)
        if shares.isEmpty { throw JSError("reconstructLatticeKey: need at least one share") }
        var seen = Set<Int>()
        for s in shares where !seen.insert(s.index).inserted { throw JSError("reconstructLatticeKey: duplicate share index") }
        var out = [UInt64](repeating: 0, count: params.dim)
        for s in shares {
            if s.coeffs.count != params.dim { throw JSError("reconstructLatticeKey: a share has the wrong dimension") }
            for c in 0..<params.dim { out[c] = addMod(out[c], s.coeffs[c] % params.q, params.q) }
        }
        return out
    }

    // a + b and a - b mod q for a, b < q without overflowing UInt64 (q may be near 2^64)
    private static func addMod(_ a: UInt64, _ b: UInt64, _ q: UInt64) -> UInt64 {
        let (s, o) = a.addingReportingOverflow(b)
        return o || s >= q ? s &- q : s
    }

    private static func subMod(_ a: UInt64, _ b: UInt64, _ q: UInt64) -> UInt64 { a >= b ? a - b : q - (b - a) }

    /// The non-negative remainder of a signed 64-bit coefficient modulo a positive UInt64 modulus.
    private static func modSigned(_ x: Int64, _ q: UInt64) -> UInt64 {
        if x >= 0 { return UInt64(x) % q }
        let m = x.magnitude % q
        return m == 0 ? 0 : q - m
    }
}
