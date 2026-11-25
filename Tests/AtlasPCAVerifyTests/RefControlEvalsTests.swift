import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAControlEvals (the seeded PRNG and seed mixing, the Wilson bound, the CI gate, the red policies, the modeled
/// environments and the example DLP policy, and the episode runner / evaluation aggregation). The blue decisions come from the TypeScript
/// stack and are replayed from the recorded decisions through a stub session, as the corpus documents.
final class RefControlEvalsTests: XCTestCase {
    static let file = "ref-control-evals.json.gz"
    typealias CE = PCAControlEvals

    static func red(_ name: String) -> CE.RedPolicy? {
        switch name {
        case "over-cap": return CE.overCapRed
        case "off-verb": return CE.offVerbRed
        case "slow-burn": return CE.slowBurnRed
        case "taint-exfil": return CE.taintExfilRed
        case "replay": return CE.replayRed
        case "immune-probe": return CE.immuneProbeBurstRed
        case "benign": return CE.benignBaselineRed
        case "gap-exploit": return CE.gapExploitRed()
        default: return nil
        }
    }

    /// Replays recorded decisions: the i-th decision of the episode answers the i-th action.
    final class Replay: CE.ControlBlueSession {
        let steps: [JSONValue]
        let end: Double
        var i = 0
        init(_ rec: JSONValue?) {
            steps = rec?.get("steps")?.asArray ?? []
            end = IV.num(rec?.get("endBudget")) ?? 0
        }
        var budget: Double { end }
        func decide(_ action: JObject, at: Double) -> CE.BlueDecision {
            let s = i < steps.count ? steps[i] : .null
            i += 1
            return CE.BlueDecision(outcome: s.get("outcome")?.asString ?? "deny", caughtBy: s.get("caughtBy")?.asString, r: IV.num(s.get("r")) ?? 0, threat: s.get("threat")?.asString ?? "",
                                   reason: s.get("reason")?.asString, money: IV.num(s.get("money")) ?? 0)
        }
    }

    static func gen(_ r: CE.RedPolicy) -> JSONValue { .array(r.gen().map { .object($0) }) }

    func testControlEvals() throws {
        try K042.requireCovers(["ControlEvals"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "mulberry32":
                guard let seed = IV.num(c.arg(0)), let k = IV.num(c.arg(1)) else { d.skip("mulberry32: untyped"); return }
                let rng = CE.mulberry32(seed)
                got = .value(.array((0..<Int(k)).map { _ in .double(rng()) }))
            case "mixSeed":
                guard let s = IV.num(c.arg(0)), let a = IV.num(c.arg(1)), let b = IV.num(c.arg(2)) else { d.skip("mixSeed: untyped"); return }
                got = .value(.int(Int64(CE.mixSeed(s, a, b))))
            case "wilsonLowerBound":
                guard let s = IV.num(c.arg(0)), let n = IV.num(c.arg(1)) else { d.skip("wilsonLowerBound: untyped"); return }
                got = .value(PCASandbox.num(c.args.count > 2 ? CE.wilsonLowerBound(s, n, z: IV.num(c.arg(2)) ?? .nan) : CE.wilsonLowerBound(s, n)))
            case "assertControlGate":
                got = Base.run { try CE.assertControlGate(c.arg(0), c.arg(1)); return .null }
            case "redGen":
                guard let r = c.arg(0)?.asString.flatMap({ Self.red($0) }) else { d.skip("redGen: unknown"); return }
                got = .value(.object(["name": .string(r.name), "strategy": .string(r.strategy), "actions": Self.gen(r)]))
            case "gapExploitCustom":
                let r = CE.gapExploitRed(prodResource: "file:x")
                got = .value(.object(["name": .string(r.name), "actions": Self.gen(r)]))
            case "redLists":
                got = .value(.object(["builtin": .array(CE.BUILTIN_RED_POLICIES.map { .string($0.strategy) }), "example": .array(CE.EXAMPLE_RED_POLICIES.map { .string($0.strategy) })]))
            case "exampleDlpPolicy": got = .value(CE.exampleDlpPolicy())
            case "envJudge":
                guard let env = c.arg(0)?.asString.flatMap({ CE.Env(name: $0) }), let action = c.arg(1), let ctx = c.arg(2), let soFar = ctx.get("allowedSoFar")?.asArray, let spend = IV.num(ctx.get("allowedSpend")) else { d.skip("envJudge: untyped"); return }
                got = Base.run { .bool(try env.unacceptableIfAllowed(action, allowedSoFar: soFar, allowedSpend: spend)) }
            case "runEpisode":
                guard let spec = c.arg(0), let red = spec.get("red")?.asString.flatMap({ Self.red($0) }), let env = spec.get("env")?.asString.flatMap({ CE.Env(name: $0) }), let seed = IV.num(spec.get("seed")) else { d.skip("runEpisode: untyped"); return }
                let rec = spec.get("recorded")
                let blue = CE.ControlBlue(startMs: IV.num(spec.get("startMs")) ?? 0, stepMs: IV.num(spec.get("stepMs")) ?? 1000, analyticBound: 1) { Replay(rec) }
                got = Base.run { try CE.runEpisode(red, blue, env, seed: seed).json }
            case "controlEval":
                guard let spec = c.arg(0) else { d.skip("controlEval: untyped"); return }
                guard let names = spec.get("reds")?.asArray, let reds = Optional(names.compactMap { $0.asString.flatMap { Self.red($0) } }), reds.count == names.count,
                      let envName = spec.get("env")?.asString, let env = CE.Env(name: envName), let episodes = IV.num(spec.get("episodes")), let seed = IV.num(spec.get("seed")) else {
                    // a non-array suite, a non-number episodes or seed: the reference refuses all of them
                    got = .threw(nil)
                    break
                }
                let recorded: [[JSONValue]] = (spec.get("recorded")?.asArray ?? []).map { $0.asArray ?? [] }
                var next = (0, 0)
                let blue = CE.ControlBlue(startMs: IV.num(spec.get("startMs")) ?? 0, stepMs: IV.num(spec.get("stepMs")) ?? 1000, analyticBound: IV.num(spec.get("analyticBound")) ?? 1) {
                    let (ri, e) = next
                    next = e + 1 >= Int(episodes) ? (ri + 1, 0) : (ri, e + 1)
                    return Replay(ri < recorded.count && e < recorded[ri].count ? recorded[ri][e] : nil)
                }
                got = Base.run { try CE.controlEval(reds, blue, env, episodes: episodes, seed: seed) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(3500)
    }
}
