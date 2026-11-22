import Foundation

/// Opt-in, privacy-preserving population priors for the wallet (PCA Intent Layer v2, V16, T23): one vote per principal, cell and
/// period; a central (epsilon, delta)-DP Gaussian release; local-DP randomized response; the mixture prior for the learner and the mass
/// it admits beyond the base prior. Native port of the TypeScript reference (@atlasauth/pca-wallet, population.ts). Votes, releases and
/// priors are `JSONValue`s with the reference's member names; the randomness source is an injected closure (the platform CSPRNG by
/// default). The learner-side `priorAdmittedPpm` needs the intent learner, which this SDK does not carry, and is not ported.
public enum PCAWalletPopulation {
    public static let POPULATION_VOTE_DOMAIN = "atlas-pca/intent-population-cell/v1"
    public static let BETA_MAX = 0.9

    /// The semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb.
    public static func populationCellKey(_ schemaDigest: String, _ vs: WalletVerb, _ idx: [Int]) throws -> String {
        try WJ.hash(WJ.obj([("d", .string(POPULATION_VOTE_DOMAIN)), ("s", .string(schemaDigest)), ("v", .string(vs.verb)), ("c", try PCAWallet.coordsOfCell(vs, idx))]))
    }

    /// Uniform (0, 1) from 53 random bits of the platform CSPRNG.
    public static func cryptoRand() -> Double {
        var g = SystemRandomNumberGenerator()
        let hi = UInt32.random(in: 0...UInt32.max, using: &g) >> 5
        let lo = UInt32.random(in: 0...UInt32.max, using: &g) >> 6
        return (Double(hi) * 67108864 + Double(lo) + 0.5) / 9007199254740992
    }

    /// A standard normal draw (Box-Muller) from a uniform source.
    public static func gaussian(_ rand: () throws -> Double) throws -> Double {
        var u = try rand()
        while u <= 0 { u = try rand() }
        let v = try rand()
        return (-2 * FdLibm.log(u)).squareRoot() * cos(2 * Double.pi * v)
    }

    /// Sigma of the Gaussian mechanism for L2 sensitivity (requires epsilon in (0, 1), delta in (0, 1)).
    public static func gaussianSigma(_ epsilon: Double, _ delta: Double, _ l2Sensitivity: Double) throws -> Double {
        if !(epsilon > 0 && epsilon < 1) { throw JSError("gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)") }
        if !(delta > 0 && delta < 1) { throw JSError("gaussianSigma: delta must be in (0, 1)") }
        if !(l2Sensitivity > 0) { throw JSError("gaussianSigma: sensitivity must be > 0") }
        return (l2Sensitivity * (2 * FdLibm.log(1.25 / delta)).squareRoot()) / epsilon
    }

    /// `a === b` over JSON numbers and strings.
    static func sameScalar(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if let x = IV.num(a), let y = IV.num(b) { return x == y }
        if let x = a?.asString, let y = b?.asString { return IV.same(x, y) }
        return false
    }

    public final class Aggregator {
        let schemaDigest: String
        let period: JSONValue
        let maxCells: Double
        let rand: () throws -> Double
        private var votes: [JKey: (yes: Double, total: Double)] = [:]
        private var perPrincipal: [JKey: Set<JKey>] = [:]

        public init(schemaDigest: JSONValue?, period: JSONValue, maxCellsPerPrincipal: JSONValue? = nil, rand: (() throws -> Double)? = nil) throws {
            guard let s = schemaDigest?.asString, PCAWallet.isB64u32(.string(s)) else { throw JSError("PopulationAggregator: schemaDigest must be a canonical b64u digest") }
            self.schemaDigest = s
            self.period = period
            let mc = JS.present(maxCellsPerPrincipal).map { IV.num($0) ?? .nan } ?? 32
            guard mc.isFinite, mc.rounded(.towardZero) == mc, mc > 0 else { throw JSError("PopulationAggregator: maxCellsPerPrincipal must be a positive integer") }
            maxCells = mc
            self.rand = rand ?? { PCAWalletPopulation.cryptoRand() }
        }

        /// Accept a vote; refuses a second vote on a cell, a vote past the per-principal cell cap, or a foreign schema/period.
        public func contribute(_ v: JSONValue?) -> JSONValue {
            func no(_ r: String) -> JSONValue { WJ.obj([("ok", .bool(false)), ("reason", .string(r))]) }
            if !IV.same(v?.get("schemaDigest")?.asString, schemaDigest) { return no("vote for another schema") }
            if !PCAWalletPopulation.sameScalar(v?.get("period"), period) { return no("vote for another period") }
            guard let y = IV.num(v?.get("y")), y == 0 || y == 1 else { return no("y must be 0 or 1") }
            guard let principal = v?.get("principal")?.asString, !principal.isEmpty else { return no("an accountable principal is required") }
            // a missing / non-string cell key is the key "undefined" (a JS Map key) for every such vote
            let key = JKey(v?.get("cellKey")?.asString ?? "\u{0}undefined")
            var mine = perPrincipal[JKey(principal)] ?? []
            if mine.contains(key) { return no("one vote per principal per cell per period (sensitivity 1)") }
            if !(Double(mine.count) < maxCells) { return no("at most \(JS.number(maxCells)) cells per principal per period") }
            mine.insert(key)
            perPrincipal[JKey(principal)] = mine
            let c = votes[key] ?? (0, 0)
            votes[key] = (c.yes + y, c.total + 1)
            return WJ.obj([("ok", .bool(true))])
        }

        /// The (epsilon, delta)-DP release. Cells whose noisy count is below `minCount` are suppressed.
        public func release(_ opts: JSONValue?) throws -> JSONValue {
            let sensitivity = (2 * maxCells).squareRoot()
            let sigma = try PCAWalletPopulation.gaussianSigma(IV.num(opts?.get("epsilon")) ?? .nan, IV.num(opts?.get("delta")) ?? .nan, sensitivity)
            let qMin = JS.present(opts?.get("qMin")).map { IV.num($0) ?? .nan } ?? 0.02
            if !(qMin > 0 && qMin < 0.5) { throw JSError("release: qMin must be in (0, 0.5)") }
            let minCount = JS.present(opts?.get("minCount")).map { IV.num($0) ?? .nan } ?? 3 * sigma
            var cells = JObject()
            for key in votes.keys.sorted(by: { WJ.u16Less($0.s, $1.s) }) {
                let c = votes[key]!
                let yes = c.yes + sigma * (try PCAWalletPopulation.gaussian(rand))
                let total = c.total + sigma * (try PCAWalletPopulation.gaussian(rand))
                if !(total >= minCount) { continue }
                cells[key] = WJ.obj([("q", .double(min(1 - qMin, max(qMin, yes / total)))), ("n", .double(WJ.jsRound(total)))])
            }
            return WJ.obj([("v", WJ.i(1)), ("kind", .string("pca-intent-population-prior")), ("schema", .string(schemaDigest)), ("period", period),
                           ("epsilon", opts?.get("epsilon") ?? .null), ("delta", opts?.get("delta") ?? .null), ("sigma", .double(sigma)),
                           ("sensitivity", .double(sensitivity)), ("cells", .object(cells))])
        }
    }

    // ---- local DP ----

    public static func rrKeepProbability(_ epsilon: JSONValue?) throws -> Double {
        guard let e = IV.num(epsilon), e > 0, e.isFinite else { throw JSError("randomized response: epsilon must be > 0") }
        return FdLibm.exp(e) / (1 + FdLibm.exp(e))
    }

    /// epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y.
    public static func randomizedResponse(_ y: JSONValue?, _ epsilon: JSONValue?, _ rand: () throws -> Double) throws -> JSONValue {
        guard let yn = IV.num(y) else { throw JSError("randomizedResponse: y is not a number") }
        return try rand() < (try rrKeepProbability(epsilon)) ? y! : .double(1 - yn)
    }

    /// Unbiased estimate of the true yes-rate from randomized reports: (ybar - (1 - p)) / (2p - 1).
    public static func debiasRandomizedResponse(_ yes: JSONValue?, _ total: JSONValue?, _ epsilon: JSONValue?) throws -> Double {
        guard WJ.isIntegral(yes), WJ.isIntegral(total), let t = IV.num(total), let y = IV.num(yes), t > 0, y >= 0, y <= t else { throw JSError("debias: bad counts") }
        let p = try rrKeepProbability(epsilon)
        return (y / t - (1 - p)) / (2 * p - 1)
    }

    // ---- the mixture prior ----

    public struct Prior {
        public let beta: Double
        let weightOf: (WalletVerb, (Int) -> Bool) throws -> Double
        /// The prior weight of the hypothesis holding exactly the flat cells `contains` accepts, over one verb's space.
        public func weight(_ vs: WalletVerb, _ contains: (Int) -> Bool) throws -> Double { try weightOf(vs, contains) }
    }

    /// The learner's priorMix for a release: weight(theta) = prod_c q_c^{1[c in theta]} (1 - q_c)^{1[c not in theta]} over the released
    /// cells of the verb (unreleased cells drop out), mixed with weight beta <= BETA_MAX < 1.
    public static func populationPrior(_ release: JSONValue?, _ beta: Double) throws -> Prior {
        if !(beta >= 0 && beta <= BETA_MAX) { throw JSError("populationPrior: beta must be in [0, \(BETA_MAX)] (full support needs beta < 1)") }
        var cache: [String: (cells: [Int], lq: [Double], lnq: [Double])] = [:]
        func tables(_ vs: WalletVerb) throws -> (cells: [Int], lq: [Double], lnq: [Double]) {
            if let hit = cache[vs.verb] { return hit }
            guard let schema = release?.get("schema")?.asString, let released = release?.get("cells") else { throw JSError("Cannot read properties of undefined (reading 'cells')") }
            var t: (cells: [Int], lq: [Double], lnq: [Double]) = ([], [], [])
            for c in 0..<WalletOmegaMath.verbCellCount(vs) {
                guard let r = released.get(try populationCellKey(schema, vs, WalletOmegaMath.decodeCell(vs, c))), JS.truthy(r) else { continue }
                let q = IV.num(r.get("q")) ?? .nan
                t.cells.append(c); t.lq.append(FdLibm.log(q)); t.lnq.append(FdLibm.log(1 - q))
            }
            cache[vs.verb] = t
            return t
        }
        return Prior(beta: beta) { vs, contains in
            let t = try tables(vs)
            var lw = 0.0
            for i in 0..<t.cells.count { lw += contains(t.cells[i]) ? t.lq[i] : t.lnq[i] }
            return FdLibm.exp(lw)
        }
    }
}
