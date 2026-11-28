import Foundation

/// The wallet's default view over an intent learner (reference: @atlasauth/pca-wallet channel.ts learnerView) and the population prior's
/// measured effect (population.ts priorAdmittedPpm).
public struct PCAWalletLearnerView {
    let learner: PCAIntentLearner
    let insideCeiling: ((String, [Int]) -> Bool)?

    /// `insideCeiling` true means inside every ceiling; nil places no ceiling.
    public init(_ learner: PCAIntentLearner, insideCeiling: ((String, [Int]) -> Bool)? = nil) {
        self.learner = learner
        self.insideCeiling = insideCeiling
    }

    private func rep(_ verb: String, _ idx: [Int]) throws -> JSONValue {
        guard let vs = learner.omega.verbs.first(where: { IV.same($0.verb, verb) }) else { throw JSError("learnerView: unknown verb \(verb)") }
        guard idx.count == vs.dims.count, zip(idx, vs.dims).allSatisfy({ $0 >= 0 && $0 < WalletOmegaMath.cellCount($1) }) else {
            throw JSError("learnerView: cell out of range")
        }
        return WalletOmegaMath.cellRep(vs, idx)
    }

    public func p(_ verb: String, _ idx: [Int]) throws -> Double { learner.acceptance(try rep(verb, idx)) }
    public func vetoed(_ verb: String, _ idx: [Int]) throws -> Bool { learner.isVetoed(try rep(verb, idx)) }
    public func outsideCeiling(_ verb: String, _ idx: [Int]) -> Bool { insideCeiling.map { !$0(verb, idx) } ?? false }
    /// Cells currently in the effective grant (for near-boundary canaries).
    public func confirmed() -> [(verb: String, idx: [Int])] { learner.cells().filter { $0.inGrant }.map { ($0.verb, $0.cell) } }
}

public enum PCAWalletLearner {
    /// Mass (ppm) of the cells admitted only because of the population prior: in the grant with the prior, not without it, after the
    /// same observations. Zero at tau = 1 under noise-free answers.
    public static func priorAdmittedPpm(omega: JSONValue?, base: PCAIntentLearner.Options, observations: [PCAIntentLearner.Observation],
                                        mix: PCAWalletPopulation.Prior) throws -> Int {
        var rest = base
        rest.priorMix = nil
        let without = try PCAIntentLearner.replay(omega: omega, options: rest, observations: observations)
        var withMix = rest
        withMix.priorMix = (mix.beta, { vs, has in try mix.weight(vs, has) })
        let withPop = try PCAIntentLearner.replay(omega: omega, options: withMix, observations: observations)
        let a = without.cells(), b = withPop.cells()
        var mass = 0.0
        for (i, c) in b.enumerated() where c.inGrant && !a[i].inGrant { mass += c.mass }
        return Int(WJ.jsRound(mass * 1_000_000))
    }
}
