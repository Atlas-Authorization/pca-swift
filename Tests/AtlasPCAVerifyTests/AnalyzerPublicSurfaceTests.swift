import XCTest
import Foundation
import AtlasPCAVerify // NOT @testable: this file proves the analyzer entry points are reachable through the public surface alone

/// The reference's analyzer entry points (toModel, probeSet, collectProbes, decideAction, admitsAction, repToAction, analyzeCaveats, tightenInterval, intervalEmpty, alwaysDenies, subsumes)
/// through public API only. The corpus replay of the same functions is RefAnalyzerTests.
final class AnalyzerPublicSurfaceTests: XCTestCase {
    typealias A = PCAAnalyzer
    static func policy(_ verb: String) -> JSONValue { .object(["predicates": .array([.object(["verb": .string(verb), "resource": .string("*")])])]) }
    static func m(_ v: JSONValue, _ k: String) -> JSONValue? { if case let .object(o) = v { return o[JKey(k)] }; return nil }
    static func action(_ verb: String, _ resource: String = "doc") -> JSONValue { .object(["verb": .string(verb), "resource": .string(resource), "params": .object([:])]) }

    func testModelProbesAndDecisions() throws {
        let m = try A.toModel(Self.policy("read"))
        XCTAssertTrue(m.caveatSat)
        XCTAssertEqual(try A.probeSet(m).count, 1)
        XCTAssertEqual(try A.decideAction(m, Self.action("read")), "allow")
        XCTAssertEqual(try A.decideAction(m, Self.action("write")), "deny")
        XCTAssertTrue(try A.admitsAction(m, Self.action("read")))
        XCTAssertFalse(try A.admitsAction(m, Self.action("write")))
        let probes = try A.collectProbes(A.ProbeInputs(predicateSets: [m.predicates], varyReversibility: false))
        XCTAssertTrue(probes.verbs.contains { $0 == JSONValue.string("read") })
        XCTAssertEqual(probes.revClasses.count, 1)
        // every representative of the grid renders as an action the model decides, and the model's own verb is admitted
        let rep = A.Rep(verb: .string("read"), resource: .string("x"), revClass: nil, assignments: [])
        let act = A.repToAction(rep)
        XCTAssertEqual(Self.m(act, "verb"), .string("read"))
        XCTAssertTrue(try A.admitsAction(m, act))
        XCTAssertEqual(Self.m(m.json, "caveatSat"), .bool(true))
    }

    func testCaveatsAndIntervals() {
        let bad = A.analyzeCaveats(.array([.object(["type": .string("not_before"), "at": .int(20)]), .object(["type": .string("expires"), "at": .int(10)])]))
        XCTAssertFalse(bad.sat)
        XCTAssertNotNil(bad.reason)
        XCTAssertTrue(A.analyzeCaveats(.array([])).sat)
        XCTAssertFalse(A.analyzeCaveats(.string("x")).sat)
        XCTAssertEqual(A.analyzeCaveats(.array([.object(["type": .string("reversibility_max"), "class": .string("rate_limited")])])).revCap, 1)
        var iv = A.tightenInterval(.full, .string("gt"), .int(5))
        XCTAssertEqual(iv.lo, 5)
        XCTAssertFalse(iv.loInc)
        XCTAssertFalse(A.intervalEmpty(iv))
        iv = A.tightenInterval(iv, .string("lt"), .int(3))
        XCTAssertTrue(A.intervalEmpty(iv))
        XCTAssertTrue(A.intervalEmpty(A.Interval(lo: 4, loInc: true, hi: 4, hiInc: false)))
        XCTAssertFalse(A.intervalEmpty(A.Interval(lo: 4, loInc: true, hi: 4, hiInc: true)))
        XCTAssertEqual(A.tightenInterval(.full, .string("nope"), .int(1)).json, A.Interval.full.json, "an unknown operator leaves the interval alone")
    }

    func testVacuityAndSubsumption() throws {
        let order = A.WitnessOrder()
        let dead = try A.alwaysDenies(.object(["predicates": .array([])]), nil, nil, order: order)
        XCTAssertEqual(Self.m(dead, "alwaysDenies"), .bool(true))
        let live = try A.alwaysDenies(Self.policy("read"), .string("read"))
        XCTAssertEqual(Self.m(live, "alwaysDenies"), .bool(false))
        XCTAssertNotNil(Self.m(live, "witness"))
        // read-only subsumes nothing wider: {read} does not subsume {read, write}, and {read, write} subsumes {read}
        let wide: JSONValue = .object(["predicates": .array([.object(["verb": .string("read"), "resource": .string("*")]), .object(["verb": .string("write"), "resource": .string("*")])])])
        XCTAssertEqual(try Self.m(A.subsumes(Self.policy("read"), wide), "subsumes"), .bool(false))
        XCTAssertEqual(try Self.m(A.subsumes(wide, Self.policy("read")), "subsumes"), .bool(true))
    }
}

/// `boxCells` is reachable without @testable (the planner `planClarification` is replayed over the wallet corpus in RefWalletTests).
final class WalletPublicSurfaceTests: XCTestCase {
    func testBoxCellsLexicographic() {
        XCTAssertEqual(PCAWallet.boxCells([[0, 1], [2]]), [[0, 2], [1, 2]])
        XCTAssertEqual(PCAWallet.boxCells([[0, 1], [5, 6]]), [[0, 5], [0, 6], [1, 5], [1, 6]])
        XCTAssertEqual(PCAWallet.boxCells([]), [[]])
        XCTAssertEqual(PCAWallet.boxCells([[1], []]), [])
    }
}
