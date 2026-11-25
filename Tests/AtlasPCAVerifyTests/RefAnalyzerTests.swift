import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the policy analyzer core (caveat satisfiability, the interval and probe engines, the decision engine,
/// reachability / vacuity / totality / subsumption / disjointness / equivalence, intent conformance) against the reference
/// (@atlasauth/pca-analyzer). Policies and results are plain JSON; a non-finite number is {"$num": "Infinity"}.
final class RefAnalyzerTests: XCTestCase {
    typealias A = PCAAnalyzer
    static let fns: Set<String> = ["analyzeCaveats", "numericConjunctionSatisfiable", "predicateNumericSatisfiable", "tightenInterval", "intervalEmpty", "fieldProbes",
                                   "vetoesFromConstitution", "toModel", "collectProbes", "representatives", "decideAction", "admitsConcrete", "vetoApplies", "reachable",
                                   "alwaysDenies", "alwaysAllows", "subsumes", "disjoint", "equivalent", "intentConformance"]

    static func list(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("not iterable") }
        return a
    }

    static func interval(_ v: JSONValue?) -> A.Interval {
        guard case let .object(o)? = v else { return .full }
        return A.Interval(lo: IV.num(o["lo"]) ?? 0, loInc: o["loInclusive"] == .bool(true), hi: IV.num(o["hi"]) ?? 0, hiInc: o["hiInclusive"] == .bool(true))
    }

    static func probeInputs(_ v: JSONValue?) throws -> A.ProbeInputs {
        guard case let .object(o)? = v else { throw JSError("probe inputs are not an object") }
        func strings(_ k: String) throws -> [String] {
            try (o[JKey(k)]?.asArray ?? []).map { x in
                guard let s = x.asString else { throw JSError("r.startsWith is not a function") }
                return s
            }
        }
        let sets = try list(o["predicateSets"]).map { try list($0) }
        let extra = try (o["extraFieldConditions"]?.asArray ?? []).map { e -> (path: String, cond: JSONValue) in
            guard let p = e.get("path")?.asString, let c = e.get("cond") else { throw JSError("extraFieldConditions") }
            return (p, c)
        }
        return A.ProbeInputs(predicateSets: sets, extraVerbs: try strings("extraVerbs"), extraResources: try strings("extraResources"), extraFieldConditions: extra,
                             varyReversibility: JS.truthy(o["varyReversibility"]))
    }

    func testAnalyzerCore() throws {
        try K042.requireCovers(["Analyzer", "Predicates", "Prohibitions", "JSLoose"])
        let d = Base.Diffs()
        var seen = Set<String>()
        try Base.each(RefAnalyzer.file, Self.fns) { c in
            let a0 = RefAnalyzer.arg(c, 0), a1 = RefAnalyzer.arg(c, 1), a2 = RefAnalyzer.arg(c, 2)
            seen.insert(c.fn)
            let got: BaseGot
            switch c.fn {
            case "analyzeCaveats": got = RefAnalyzer.run { A.analyzeCaveats(a0).json }
            case "numericConjunctionSatisfiable": got = RefAnalyzer.run { .bool(A.numericConjunctionSatisfiable(try Self.list(a0))) }
            case "predicateNumericSatisfiable": got = RefAnalyzer.run { .bool(A.predicateNumericSatisfiable(a0)) }
            case "tightenInterval": got = RefAnalyzer.run { A.tightenInterval(Self.interval(a0), a1, a2).json }
            case "intervalEmpty": got = RefAnalyzer.run { .bool(A.intervalEmpty(Self.interval(a0))) }
            case "fieldProbes": got = RefAnalyzer.run { .array(A.fieldProbes(try Self.list(a0))) }
            case "vetoesFromConstitution": got = RefAnalyzer.run { try A.vetoesFromConstitution(a0) }
            case "toModel": got = RefAnalyzer.run { try A.toModel(a0).json }
            case "collectProbes": got = RefAnalyzer.run { try A.collectProbes(try Self.probeInputs(a0)).json }
            case "representatives":
                got = RefAnalyzer.run {
                    let pr = try A.collectProbes(try Self.probeInputs(a0))
                    if A.productSize(pr) > 400 { throw JSError("grid too large for the corpus") }
                    var out: [JSONValue] = []
                    A.eachRep(pr) { r in
                        out.append(A.obj([("verb", r.verb), ("resource", r.resource), ("revClass", r.revClass), ("assignments", r.assignmentsJson), ("action", A.repToAction(r))]))
                        return false
                    }
                    return .array(out)
                }
            case "decideAction": got = RefAnalyzer.run { .string(try A.decideAction(try A.toModel(a0), a1)) }
            case "admitsConcrete": got = RefAnalyzer.run { .bool(try A.admitsConcrete(a0, a1)) }
            case "vetoApplies":
                got = RefAnalyzer.run {
                    var action = a1?.asObject ?? [:]
                    if action["params"] == nil { action["params"] = .object([:]) }
                    let ctx = JSONValue.object(["action": .object(action), "subject": JS.present(a1?.get("subject")) ?? .object([:]), "env": JS.present(a1?.get("env")) ?? .object([:])])
                    return .bool(try A.vetoApplies(a0, ctx))
                }
            case "reachable": got = RefAnalyzer.run { try A.reachable(a0, a1, a2) }
            case "alwaysDenies": got = RefAnalyzer.run { try A.alwaysDenies(a0, a1 == .null ? nil : a1, a2) }
            case "alwaysAllows": got = RefAnalyzer.run { try A.alwaysAllows(a0, a1 == .null ? nil : a1, a2) }
            case "subsumes": got = RefAnalyzer.run { try A.subsumes(a0, a1, a2) }
            case "disjoint": got = RefAnalyzer.run { try A.disjoint(a0, a1, a2) }
            case "equivalent": got = RefAnalyzer.run { try A.equivalent(a0, a1, a2) }
            case "intentConformance": got = RefAnalyzer.run { try A.intentConformance(a0, a1, a2) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(seen, Self.fns)
        d.finish(2800)
    }
}
