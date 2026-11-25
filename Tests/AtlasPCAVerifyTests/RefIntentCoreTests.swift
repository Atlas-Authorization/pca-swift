import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the intent core modules against the reference (@atlasauth/pca-intent): the exact Clopper-Pearson numerics,
/// the layered lattice, outcome verification and its Monte Carlo risk, the world / provenance / classifier dimensions and wallet-side
/// provenance with within-grant regret. A reference throw requires a native refusal. Doubles are compared exactly, except the reported diagnostic statistics
/// (binomialCdf, hoeffdingHalfWidth, wilsonInterval), which keep a 1e-12 relative tolerance; the count of those is printed.
final class RefIntentCoreTests: XCTestCase {
    static let tol = 1e-12
    var inexact = 0
    var curFn = ""
    /// Statistics that are reported and decide nothing: 1e-12 relative.
    static let diagnostics: Set<String> = ["binomialCdf", "hoeffdingHalfWidth", "wilsonInterval"]

    func close(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.object(x)?, .object(y)?): return Set(x.keys) == Set(y.keys) && x.allSatisfy { close($0.value, y[$0.key]) }
        case let (.array(x)?, .array(y)?): return x.count == y.count && zip(x, y).allSatisfy { close($0, $1) }
        default:
            if let p = IV.num(a), let q = IV.num(b) {
                if p == q || (p.isNaN && q.isNaN) { return true }
                if !Self.diagnostics.contains(curFn) { return false } // decisions are exact; only the diagnostic statistics keep a documented tolerance
                inexact += 1
                return abs(p - q) <= Self.tol * max(abs(p), abs(q)) + 1e-15
            }
            return Base.canon(a) == Base.canon(b)
        }
    }

    func run(_ file: String, _ min: Int, _ fns: Set<String>? = nil, _ body: (BaseCase) throws -> JSONValue) throws {
        let d = Base.Diffs()
        try Base.each(file, fns) { c in
            curFn = c.fn
            let got = Base.run { try body(c) }
            if case let .value(v) = got, !c.threw {
                if close(c.out, v) { d.add(c, nil) }
                else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
            } else { d.add(c, Base.diff(c, got)) }
        }
        print("\(file): \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(min)
    }

    // ---- helpers ----

    static func dbl(_ v: JSONValue?) throws -> Double {
        guard let d = IV.num(v) else { throw JSError("not a number") }
        return d
    }

    static func int(_ v: JSONValue?) throws -> Int {
        let d: Double = try dbl(v)
        guard d.isFinite, abs(d) < 9.0e15 else { throw JSError("not a safe integer") }
        return Int(d)
    }

    /// The reference prints a non-finite double as {"$num": "NaN" | "Infinity" | "-Infinity"}.
    static func num(_ v: Double) -> JSONValue {
        if v.isNaN { return .object(["$num": .string("NaN")]) }
        if v.isInfinite { return .object(["$num": .string(v > 0 ? "Infinity" : "-Infinity")]) }
        return PCAIntentOmega.jn(v)
    }

    static func decimal(_ b: BigUInt) -> String {
        var limbs: [UInt32] = b.limbs
        if limbs.isEmpty { return "0" }
        var chunks: [UInt32] = []
        while !limbs.isEmpty {
            var rem: UInt64 = 0
            var i = limbs.count - 1
            while i >= 0 {
                let cur: UInt64 = (rem << 32) | UInt64(limbs[i])
                limbs[i] = UInt32(cur / 1_000_000_000)
                rem = cur % 1_000_000_000
                i -= 1
            }
            chunks.append(UInt32(rem))
            while let l = limbs.last, l == 0 { limbs.removeLast() }
        }
        var s = String(chunks[chunks.count - 1])
        var k = chunks.count - 2
        while k >= 0 {
            let part = String(chunks[k])
            s += String(repeating: "0", count: 9 - part.count) + part
            k -= 1
        }
        return s
    }

    static func bigJ(_ b: BigUInt) -> JSONValue { return .object(["$bigint": .string(decimal(b))]) }
    static func bigJ(_ n: Int64) -> JSONValue { return .object(["$bigint": .string(String(n))]) }

    static func big(_ v: JSONValue?) throws -> BigUInt {
        guard let s = v?.get("$bigint")?.asString else { throw JSError("not a bigint") }
        // an unsigned big integer holds digits only: a signed or malformed text is a refusal here, not a trap inside the parser
        guard !s.isEmpty, s.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { throw JSError("not an unsigned bigint") }
        return BigUInt(decimal: s)
    }

    // ---- stats ----

    func testIntentStatsAgainstTheReference() throws {
        try K042.requireCovers(["IntentStats", "IntentMath", "WalletOmega"])
        try run("ref-intent-stats.json.gz", 700) { c in
            let a = c.args
            switch c.fn {
            case "clopperPearsonUpper": return Self.num(try PCAIntentStats.clopperPearsonUpper(try Self.dbl(a[0]), try Self.dbl(a[1]), try Self.dbl(a[2])))
            case "clopperPearsonCertified":
                let r = try PCAIntentStats.clopperPearsonCertified(try Self.dbl(a[0]), try Self.dbl(a[1]), try Self.dbl(a[2]))
                return .object(["upper": Self.num(r.upper), "upperUnits": Self.bigJ(r.upperUnits), "lowerUnits": Self.bigJ(r.lowerUnits)])
            case "binomialCdf": return Self.num(PCAIntentStats.binomialCdf(try Self.int(a[0]), try Self.int(a[1]), try Self.dbl(a[2])))
            case "doubleToDyadic":
                let y = try PCAIntentStats.doubleToDyadic(try Self.dbl(a[0]))
                return .object(["num": Self.bigJ(y.num), "exp": .int(Int64(y.exp))])
            case "cdfRecNumerator": return Self.bigJ(try PCAIntentStats.cdfRecNumerator(try Self.int(a[0]), try Self.int(a[1]), try Self.big(a[2])))
            case "cdfExceeds":
                let al = PCAIntentStats.Dyadic(try Self.big(a[3].get("num")), try Self.int(a[3].get("exp")))
                return .bool(try PCAIntentStats.cdfExceeds(try Self.int(a[0]), try Self.int(a[1]), try Self.big(a[2]), al))
            case "hoeffdingHalfWidth":
                let r = a.count > 2 ? PCAIntentStats.hoeffdingHalfWidth(try Self.dbl(a[0]), try Self.dbl(a[1]), try Self.dbl(a[2]))
                                    : PCAIntentStats.hoeffdingHalfWidth(try Self.dbl(a[0]), try Self.dbl(a[1]))
                return Self.num(r)
            case "wilsonInterval":
                let w = a.count > 2 ? PCAIntentStats.wilsonInterval(try Self.dbl(a[0]), try Self.dbl(a[1]), try Self.dbl(a[2]))
                                    : PCAIntentStats.wilsonInterval(try Self.dbl(a[0]), try Self.dbl(a[1]))
                return .object(["p": Self.num(w.p), "lo": Self.num(w.lo), "hi": Self.num(w.hi)])
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    func testIntentMathLog2IsFdlibm() {
        XCTAssertEqual(PCAIntentMath.log2(8), 3)
        XCTAssertEqual(PCAIntentMath.log2(1), 0)
        XCTAssertEqual(PCAIntentMath.log2(0), -Double.infinity)
        XCTAssertTrue(PCAIntentMath.log2(-1).isNaN)
        XCTAssertEqual(PCAIntentMath.log2(0.5), -1)
        XCTAssertEqual(PCAIntentMath.log2(1024), 10)
        XCTAssertTrue(abs(PCAIntentMath.log2(3) - 1.584962500721156) < 1e-15)
        XCTAssertEqual(PCAIntentMath.log2(Double.infinity), Double.infinity)
    }

    // ---- lattice and outcome (over a learner) ----

    static func learner(_ omega: JSONValue?, _ mapOpts: JSONValue?, _ obs: JSONValue?) throws -> PCAIntentLearner {
        let l = try PCAIntentMap.createLearner(omega: omega, options: mapOpts)
        for x in obs?.asArray ?? [] {
            guard let y = IV.num(x.get("y")), let source = x.get("source")?.asString else { throw JSError("bad observation") }
            try l.observe(.object(["verb": x.get("verb") ?? .null, "values": x.get("values") ?? .null]), y: Int(y), source: source)
        }
        return l
    }

    func testIntentLatticeAgainstTheReference() throws {
        try K042.requireCovers(["IntentLattice", "IntentLayers", "IntentMultiAgg", "IntentLearner"])
        try run("ref-intent-lattice.json.gz", 80) { c in
            let a = c.args
            switch c.fn {
            case "latticeScenario":
                let l = try Self.learner(a[0], a[1], a[2])
                let ceilings = try PCAIntentLayers.ceilingAdmitters(a[3])
                let view = try PCAIntentLattice.latticeView(l, ceilings)
                var decisions: [JSONValue] = []
                for o in a[4].asArray ?? [] { decisions.append(PCAIntentLattice.decideOutcomeLayers(l, ceilings, o)) }
                return .object(["view": view, "decisions": .array(decisions)])
            case "orgScenario": return try PCAIntentLattice.orgLayerFromMaps(a[0].asArray ?? [], a[1])
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    func testIntentOutcomeAgainstTheReference() throws {
        try K042.requireCovers(["IntentOutcome", "IntentEffects", "IntentLearner"])
        try run("ref-intent-outcome.json.gz", 45) { c in
            let a = c.args
            switch c.fn {
            case "verifyScenario":
                let l = try Self.learner(a[0], a[1], a[2])
                let pcs: [JSONValue]? = a.count > 5 ? a[5].asArray : nil
                let result = try PCAIntentOutcome.verifyOutcome(l, a[3], a[4], pcs)
                return .object(["result": result, "metrics": l.metrics().json])
            case "mcScenario":
                let l = try Self.learner(a[0], a[1], a[2])
                return Self.num(try PCAIntentOutcome.estimateResidualRiskMC(l, try Self.int(a[3]), try Self.dbl(a[4])))
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    // ---- world ----

    func testIntentWorldAgainstTheReference() throws {
        try K042.requireCovers(["IntentWorld", "IntentOmega"])
        func nums(_ v: JSONValue?) throws -> [Double]? {
            guard let v = v, !v.isNull else { return nil }
            return try (v.asArray ?? []).map { try Self.dbl($0) }
        }
        func strs(_ v: JSONValue?) throws -> [String] {
            return try (v?.asArray ?? []).map { guard let s = $0.asString else { throw JSError("not a string") }; return s }
        }
        try run("ref-intent-world.json.gz", 15, ["worldDim", "excessDim", "optimalityCondition", "provenanceDim", "classifierDim"]) { c in
            let a = c.args
            guard let name = a.first?.asString else { throw JSError("name") }
            switch c.fn {
            case "worldDim":
                let s = a[1]
                return PCAIntentOmega.dimToJson(PCAIntentWorld.worldDim(name, try Self.dbl(s.get("lo")), try Self.dbl(s.get("hi")), try nums(s.get("cuts")), s.get("dist")?.asString))
            case "excessDim": return PCAIntentOmega.dimToJson(PCAIntentWorld.excessDim(name, try Self.dbl(a[1]), try nums(a.count > 2 ? a[2] : nil)))
            case "optimalityCondition":
                let slack: Double = try (a.count > 1 ? Self.dbl(a[1]) : 0.0)
                return PCAIntentWorld.optimalityCondition(name, slack)
            case "provenanceDim": return PCAIntentOmega.dimToJson(PCAIntentWorld.provenanceDim(name))
            case "classifierDim": return PCAIntentOmega.dimToJson(PCAIntentWorld.classifierDim(name, try strs(a[1])))
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    func testIntentWorldSpaceAndLiftAgainstTheReference() throws {
        try K042.requireCovers(["IntentWorld", "IntentOmega"])
        try run("ref-intent-world.json.gz", 20, ["withDims", "liftOutcome"]) { c in
            let a = c.args
            switch c.fn {
            case "withDims":
                guard let verb = a[1].asString else { throw JSError("verb") }
                let dims: [PCAIntentOmega.Dim] = try (a[2].asArray ?? []).map { try PCAIntentOmega.dimFromJson($0) }
                return PCAIntentOmega.omegaToJson(try PCAIntentWorld.withDims(try PCAIntentOmega.omegaFromJson(a[0]), verb, dims))
            case "liftOutcome":
                let paths: [String] = try (a[2].asArray ?? []).map { guard let s = $0.asString else { throw JSError("path") }; return s }
                return PCAIntentOmega.outcomeToJson(PCAIntentWorld.liftOutcome(try PCAIntentOmega.outcomeFromJson(a[0]), a[1].asObject ?? [:], paths))
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    // ---- provenance ----

    private static let prefix = "action.params."

    private static func amt(_ o: PCAIntentOmega.Outcome) -> Double { return IV.num(o.values[JKey(prefix + "amount")]) ?? 0.0 }

    private static func admits(_ n: String?) -> (PCAIntentOmega.Outcome) -> Bool {
        switch n {
        case "all"?: return { _ in true }
        case "none"?: return { _ in false }
        case "amountLe50"?: return { o in amt(o) <= 50 }
        default: return { o in IV.same(o.verb, "stripe.refund") }
        }
    }

    private static func utility(_ n: String?) -> (PCAIntentOmega.Outcome) -> Double {
        switch n {
        case "amount"?: return { o in amt(o) }
        case "negAmount"?: return { o in -amt(o) }
        case "zero"?: return { _ in 0.0 }
        case "nan"?: return { _ in Double.nan }
        default: return { o in amt(o) + (o.values[JKey(prefix + "recipient")]?.asString == "bob" ? 1000.0 : 0.0) }
        }
    }

    private static func bind(_ c: JSONValue?) throws -> PCAIntentProvenance.RegretCase {
        let feasible: [PCAIntentOmega.Outcome] = try (c?.get("feasible")?.asArray ?? []).map { try PCAIntentOmega.outcomeFromJson($0) }
        return PCAIntentProvenance.RegretCase(feasible, try PCAIntentOmega.outcomeFromJson(c?.get("chosen")), admits(c?.get("admits")?.asString), utility(c?.get("utility")?.asString))
    }

    func testIntentProvenanceAgainstTheReference() throws {
        try K042.requireCovers(["IntentProvenance", "IntentOmega"])
        try run("ref-intent-provenance.json.gz", 250) { c in
            let a = c.args
            switch c.fn {
            case "provenanceBanner":
                return PCAIntentProvenance.provenanceBanner(a[0].asString, a.count > 1 ? a[1].asString : nil).map { JSONValue.string($0) } ?? JSONValue.null
            case "isTainted": return .bool(PCAIntentProvenance.isTainted(a[0].asString))
            case "provenanceFriction": return .string(PCAIntentProvenance.provenanceFriction(a[0].asString, a[1].asString, a[2].asString))
            case "regret": return PCAIntentProvenance.withinGrantRegret(try Self.bind(a[0]))
            case "report":
                let cases: [PCAIntentProvenance.RegretCase] = try (a[0].asArray ?? []).map { try Self.bind($0) }
                let scale: Double = try (a.count > 1 ? Self.dbl(a[1]) : 1.0)
                return PCAIntentProvenance.regretReport(cases, scale)
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }
}
