import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the goal benchmark (PCAGoalBench: seeded generator, case generation, truth goals, simulated model
/// outputs, recorded fixtures, the four-level evaluation, compile-widening and the calibrated report) against the reference
/// (@atlasauth/pca-goal). A reference throw requires a native refusal. Doubles are compared bit for bit first and within 1e-12
/// relative otherwise (the report's Clopper-Pearson bound goes through log / exp); the count of the latter is printed.
final class RefGoalBenchTests: XCTestCase {
    typealias B = PCAGoalBench
    static let file = "ref-goal-bench.json.gz"
    static let tol = 1e-12
    var inexact = 0

    func close(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.object(x)?, .object(y)?): return Set(x.keys) == Set(y.keys) && x.allSatisfy { close($0.value, y[$0.key]) }
        case let (.array(x)?, .array(y)?): return x.count == y.count && zip(x, y).allSatisfy { close($0, $1) }
        default:
            if let p = IV.num(a), let q = IV.num(b) {
                if p == q || (p.isNaN && q.isNaN) { return true }
                inexact += 1
                return abs(p - q) <= Self.tol * max(abs(p), abs(q)) + 1e-15
            }
            return Base.canon(a) == Base.canon(b)
        }
    }

    static func long(_ v: JSONValue?) throws -> Int64 {
        guard let d = IV.num(v), d.isFinite, abs(d) < 9.0e18 else { throw JSError("not an integer") }
        return Int64(d)
    }

    static func cases(_ v: JSONValue?) throws -> JSONValue {
        guard let a = v?.asArray, a.allSatisfy({ $0.asObject != nil }) else { throw JSError("cases must be objects") }
        return .array(a)
    }

    func testGoalBenchAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "rngSeq":
                    let r = B.rng(try Self.long(a[0]))
                    var out: [JSONValue] = []
                    var i: Int64 = 0
                    let n = try Self.long(a[1])
                    while i < n { out.append(.double(r.next())); i += 1 }
                    return .array(out)
                case "generateCases":
                    guard let dom = a[0].asString else { throw JSError("domain") }
                    let he: Int? = a[3].isNull ? nil : Int(try Self.long(a[3]))
                    return try B.generateCases(dom, Int(try Self.long(a[1])), try Self.long(a[2]), he, a[4] == .bool(true))
                case "truthGoalOf": return try B.truthGoal(a[0])
                case "simulateOutputOf":
                    guard let sp = B.SIM_SPECS.first(where: { IV.same($0.id, a[1].asString ?? "") }) else { throw JSError("unknown spec") }
                    return .string(try B.simulateOutput(a[0], sp.id, sp.err, sp.follow))
                case "recordFixturesOf": return try B.recordFixtures(try Self.cases(a[0]))
                case "caseSetDigest": return .string(try B.caseSetDigest(try Self.cases(a[0])))
                case "evalCaseOf":
                    let rec = try B.recordFixtures(.array([a[0]]))
                    return try B.evalCase(a[0], try B.completionsFrom(rec), nil, false, nil)
                case "compileWideningOf":
                    var items: [(JSONValue, JSONValue)] = []
                    for x in try Self.cases(a[0]).asArray ?? [] {
                        let g = try B.truthGoal(x)
                        items.append((g, try B.truthOnt(x, g)))
                    }
                    return try B.compileWideningCount(items, nil)
                case "summarizeOf":
                    guard let dom = a[0].asString, let ms = a[2].asString else { throw JSError("summarize args") }
                    return try B.summarize(dom, try Self.cases(a[1]), ms, a[3].asObject != nil ? a[3] : nil)
                case "runDomainOf":
                    guard let dom = a[0].asString else { throw JSError("domain") }
                    let cs = try Self.cases(a[1])
                    return try B.runDomain(dom, cs, try B.recordFixtures(cs), nil, false)
                default: throw JSError("not mapped: \(c.fn)")
                }
            }
            if case let .value(v) = got, !c.threw {
                if close(c.out, v) { d.add(c, nil) }
                else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
            } else { d.add(c, Base.diff(c, got)) }
        }
        print("goal bench: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(400)
    }
}
