import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The policy fixtures of the simulator and forecast corpora: `{permissions, limits?, budgetModel?, riskPolicy?, now}` compiled by the facade.
enum RefPolicyFixture {
    /// The compiled policy and the order the limit names were written in.
    static func compile(_ spec: JSONValue?) throws -> (policy: PCACompiledPolicy, limitOrder: [String]) {
        guard case let .object(s)? = spec, case let .object(perms)? = s["permissions"] else { throw PCAProducerError("spec") }
        let permissions = JS.keyOrder(perms).map { k in (k.s, (perms[k]?.asArray ?? []).compactMap { $0.asString }) }
        var limits: [String: String]?
        var order: [String] = []
        if case let .object(l)? = s["limits"] {
            var m: [String: String] = [:]
            for k in JS.keyOrder(l) { if let t = l[k]?.asString { m[k.s] = t; order.append(k.s) } }
            limits = m
        }
        let policy = try PCAFacade.compilePolicy(permissions: permissions, limits: limits, budgetModel: s["budgetModel"]?.asString, riskPolicy: s["riskPolicy"]?.asObject,
                                                 now: s["now"]?.safeInt)
        return (policy, order)
    }
}

/// The budget forecast and the policy recommender against the reference corpus: every case, every fn.
final class RefBudgetForecastTests: XCTestCase {
    typealias A = RefAnalyzer

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "forecast":
            return A.run {
                let policy = try RefPolicyFixture.compile(a0).policy
                guard case let .array(plan)? = a1 else { throw PCAProducerError("plan") }
                // a start that is given must be a number (the typed option); null = not given
                var start = 0.0
                if let s = JS.present(a2) { guard let v = IV.num(s) else { throw PCAProducerError("start") }; start = v }
                let catalog = try JS.present(a3).map { Catalog.buildCatalog(try ($0.asArray ?? []).map { try Catalog.defineAction($0) }) } ?? Catalog.DEFAULT_CATALOG
                return PolicySim.forecast(policy, plan, catalog: catalog, start: start)
            }
        case "recommendPolicy":
            return A.run {
                // the typed API takes numbers: anything else is refused as the reference refuses a non-finite value
                guard let n = IV.num(a0), let r = IV.num(a1) else { throw PCAProducerError("not a number") }
                guard let k = JS.present(a2) else { return try PolicySim.recommendPolicy(targetActions: n, perActionRisk: r) }
                guard let kappa = IV.num(k) else { throw PCAProducerError("kappa") }
                return try PolicySim.recommendPolicy(targetActions: n, perActionRisk: r, kappa: kappa)
            }
        case "autonomyBoundOf": return A.run { PD.num(PolicySim.autonomyBoundOf(a0)) }
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-budget-forecast.json.gz") { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 326)
        d.finish(326)
    }

    func testAPlanThatExhaustsTheBudgetForcesACosign() throws {
        let policy = try PCAFacade.compilePolicy(permissions: [("github", ["read"])], budgetModel: "risk", riskPolicy: ["bMax": .double(0.12), "kappa": .int(1)], now: 0)
        let plan = (0..<4).map { _ in K042.parse(#"{"verb":"github.read","resource":"org/repo"}"#) }
        let f = PolicySim.forecast(policy, plan)
        // each read costs 0.05: two fit in 0.12, the third is forced to a step-up
        XCTAssertEqual(f.get("firstStepUpAt"), .int(2), JS.stringify(f))
        XCTAssertEqual(f.get("forcesCosign"), .bool(true))
        XCTAssertEqual(PolicySim.simulate(policy, plan).get("auto"), .int(2))
        XCTAssertEqual(PolicySim.simulate(policy, [K042.parse(#"{"verb":"github.read","resource":"r","at":"soon"}"#)]).get("deny"), .int(1))
        XCTAssertThrowsError(try PolicySim.recommendPolicy(targetActions: 10, perActionRisk: 0.1, kappa: 0))
        XCTAssertEqual(try PolicySim.recommendPolicy(targetActions: 10, perActionRisk: 0.1, kappa: 2).get("bMax"), .int(2))
    }
}
