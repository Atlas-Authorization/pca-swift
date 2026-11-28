import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The blue control protocol corpus (ref-control-blue.json.gz, 362 cases): the example agent and its review battery, the example blue protocol, every
/// episode of the decision procedure (replay, predicates and caveats, data-flow governance, the immune-adapted metered budget) under eight blue
/// configurations, and the example evaluation, all against the real native blue stack (ref-control-evals replays only the aggregation from a stub blue).
/// Numbers compare to a relative 1e-12 (the leak decays exponentially).
///
/// Counted deviation (asserted, never skipped): a params value that cannot be canonical JSON (an integer past 2^53) makes the reference's reviewAction
/// throw out of the episode (5 cases, all under the agent without limits); the native blue refuses that action up front ("params are not JSON"), so
/// the episode completes with a denial at that action: fail closed, asserted as a denial.
final class RefControlBlueTests: XCTestCase {
    typealias CE = PCAControlEvals

    private static let PERMS: [(String, [String])] = [("stripe", ["refund"]), ("gmail", ["send", "draft"]), ("files", ["read", "write"]), ("github", ["read"])]

    private static func agent(_ name: String) throws -> PCAFacadeAgent {
        if name == "example" { return try CE.buildExampleAgent() }
        return try PCAAgent.fromPrincipal(PCAAgentOptions(principal: .ed25519(PCAEdKey.generate()), goal: "handle refunds and customer email for October", permissions: PERMS,
                                                          limits: name == "cap50" ? ["refund": "$50/day"] : nil, aud: "ins_example", now: 0))
    }

    private static func blueSpec(_ spec: JSONValue?) throws -> CE.ExampleBlue {
        var b = CE.exampleBlueSpec(try agent(spec?.get("agent")?.asString ?? "example"))
        if spec?.get("dlp") == .bool(false) { b.dlp = nil }
        if spec?.get("theta")?.asString == "agent" { b.basePolicy = nil }
        if let x = IV.num(spec?.get("stepMs")) { b.stepMs = x }
        if let x = IV.num(spec?.get("startMs")) { b.startMs = x }
        if let im = spec?.get("immune") {
            var c = PCAImmune.Config()
            c.alpha = IV.num(im.get("alpha")) ?? c.alpha
            c.halfLifeMs = IV.num(im.get("halfLifeMs")) ?? c.halfLifeMs
            c.driftZSat = IV.num(im.get("driftZSat")) ?? c.driftZSat
            c.stepUpSat = IV.num(im.get("stepUpSat")) ?? c.stepUpSat
            c.denySat = IV.num(im.get("denySat")) ?? c.denySat
            b.immune = c
        }
        if let ad = spec?.get("adapt") {
            var c = PCAImmune.AdaptConfig()
            c.maxKappaMult = IV.num(ad.get("maxKappaMult")) ?? c.maxKappaMult
            c.minThetaMult = IV.num(ad.get("minThetaMult")) ?? c.minThetaMult
            b.adapt = c
        }
        return b
    }

    private static func strs(_ l: [String]) -> JSONValue { .array(l.map { .string($0) }) }

    private static func buildExampleAgent(_ expected: JSONValue) throws -> JSONValue {
        let a = try CE.buildExampleAgent()
        let p = a.policy
        let actions: [JSONValue] = p.actions.map { s in
            var m: JObject = ["connector": .string(s.connector), "action": .string(s.action), "verb": .string(s.verb), "reversibility": .string(s.reversibility), "blastRadius": PCAFacade.jsNum(s.blastRadius)]
            if let f = s.amountField { m["amountField"] = .string(f) }
            if let r = s.resource { m["resource"] = .string(r) }
            return .object(m)
        }
        let reviews: [JSONValue] = (expected.get("reviews")?.asArray ?? []).map { e in
            let now = Int64(IV.num(e.get("now")) ?? 0)
            let r = PCAApprovals.reviewAction(a, verb: e.get("verb")?.asString ?? "", resource: e.get("resource")?.asString ?? "", params: e.get("params"),
                                              PCAApprovals.ReviewOptions(now: now, insecureUnboundApproval: true))
            var rv: JObject = ["kind": r.get("kind") ?? .null]
            if let reason = r.get("reason") { rv["reason"] = reason }
            var out = e.asObject ?? [:]
            out["review"] = .object(rv)
            return .object(out)
        }
        return .object(["policy": .object(["predicates": .array(p.predicates), "caveats": .array(p.caveats), "riskPolicy": .object(p.riskPolicy), "budgetModel": .string(p.budgetModel),
                                           "approximations": strs(p.approximations), "inputLimits": .object(p.inputLimits.reduce(into: JObject()) { $0[JKey($1.key)] = .string($1.value) }),
                                           "actions": .array(actions)]),
                        "reviews": .array(reviews)])
    }

    private static func exampleBlue(_ name: String) throws -> JSONValue {
        let b = CE.exampleBlueSpec(try agent(name))
        return .object(["name": .string(b.name), "basePolicy": .object(b.base), "dlp": b.dlp ?? .null, "startMs": PCAFacade.jsNum(b.startMs), "stepMs": PCAFacade.jsNum(b.stepMs)])
    }

    private static func blueEpisode(_ c: BaseCase) throws -> JSONValue {
        let spec = c.arg(0)
        let b = try blueSpec(spec?.get("blue"))
        guard let env = CE.Env(name: spec?.get("env")?.asString ?? "") else { throw JSError("unknown env") }
        let red: CE.RedPolicy
        if let list = c.arg(1)?.asArray {
            red = CE.RedPolicy(name: "custom", strategy: "custom") { list.map { $0.asObject ?? [:] } }
        } else if let r = RefControlEvalsTests.red(spec?.get("red")?.asString ?? "") {
            red = r
        } else { throw JSError("unknown red") }
        return try CE.runEpisode(red, b.blue, env, seed: IV.num(spec?.get("seed")) ?? .nan).json
    }

    // ---- comparison (numbers to a relative 1e-12) ----

    private static func same(_ w: JSONValue, _ g: JSONValue) -> Bool {
        if w.isNumber, g.isNumber, let a = IV.num(w), let b = IV.num(g) { return a == b || abs(a - b) <= 1e-12 * max(1, abs(a)) }
        switch (w, g) {
        case let (.object(a), .object(b)): return Set(a.keys) == Set(b.keys) && a.allSatisfy { same($0.value, b[$0.key]!) }
        case let (.array(a), .array(b)): return a.count == b.count && zip(a, b).allSatisfy { same($0, $1) }
        default: return Base.canon(w) == Base.canon(g)
        }
    }

    func testEveryCaseOfTheBlueCorpus() throws {
        let doc = K042.parse(String(decoding: try K042.bytes("ref-control-blue.json.gz"), as: UTF8.self))
        let cases = doc.get("cases")?.asArray ?? []
        var seen: [String: Int] = [:]
        var bad: [String] = []
        var deviations = 0
        for raw in cases {
            let c = BaseCase(fn: raw.get("fn")?.asString ?? "", name: raw.get("name")?.asString ?? "?", args: raw.get("args")?.asArray ?? [], out: raw.get("out") ?? .null, suspect: false, raw: raw)
            seen[c.fn, default: 0] += 1
            var got: JSONValue?
            var refusal: Error?
            do {
                switch c.fn {
                case "buildExampleAgent": got = try Self.buildExampleAgent(c.out)
                case "exampleBlue": got = try Self.exampleBlue(c.arg(0)?.asString ?? "")
                case "blueEpisode": got = try Self.blueEpisode(c)
                case "exampleEval": got = try CE.exampleControlEval(episodes: IV.num(c.arg(0)?.get("episodes")) ?? .nan, seed: IV.num(c.arg(0)?.get("seed")) ?? .nan)
                default: bad.append("\(c.name): unhandled fn \(c.fn)"); continue
                }
            } catch { refusal = error }
            if c.threw {
                // the reference refused the params: the episode ends in a denial at that action
                let steps = got?.get("steps")?.asArray ?? []
                if refusal == nil, steps.contains(where: { $0.get("reason")?.asString?.contains("params are not JSON") == true }) { deviations += 1 } else {
                    bad.append("\(c.name): reference refuses (\(c.out.get("$throws")?.asString ?? "")); native has no 'params are not JSON' denial (\(refusal.map { "\($0)" } ?? "completed"))")
                }
                continue
            }
            guard let g = got else { bad.append("\(c.name): native refused: \(refusal.map { "\($0)" } ?? "?")"); continue }
            if !Self.same(c.out, g) { bad.append("\(c.name): \(Base.firstDiff(c.out, g, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(g).prefix(300))") }
        }
        XCTAssertEqual(cases.count, 362)
        XCTAssertEqual(doc.get("count"), .int(362))
        XCTAssertEqual(seen, ["buildExampleAgent": 1, "exampleBlue": 3, "blueEpisode": 352, "exampleEval": 6])
        XCTAssertEqual(deviations, 5, "the reference refuses 5 episodes on params that are not canonical JSON")
        XCTAssert(bad.isEmpty, "\(bad.count)/362 divergent:\n" + bad.prefix(30).joined(separator: "\n"))
    }
}
