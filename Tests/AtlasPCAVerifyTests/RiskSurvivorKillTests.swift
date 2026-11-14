import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Risk.swift: the primitives, the threshold map, escalation, the budget JSON, leaking and ageing, the plan geodesic and its references.
final class RiskSurvivorKillTests: XCTestCase {
    private let w: JObject = ["alpha": .double(0.25), "beta": .double(0.2), "gamma": .double(0.2), "delta": .double(0.2), "epsilon": .double(0.1), "zeta": .double(0.05)]

    func node(_ id: String, _ extra: JObject = [:]) -> JSONValue {
        var o: JObject = ["id": .string(id)]
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }

    // ---- primitives ----

    func testWorstCaseVector() {
        XCTAssertEqual(Risk.WORST, [1, 0, 1, 1, 0, 1])
    }

    func testSignedZeroAndNonFinitePrimitives() {
        XCTAssertEqual(Risk.clamp01(-0.0).sign, .minus, "zero is passed through, not replaced")
        XCTAssertEqual(Risk.wt(-0.0).sign, .plus, "a non-positive weight is the plain zero")
        XCTAssertEqual(Risk.nz(-0.0).sign, .plus)
        XCTAssertEqual(Risk.nz(-5), 0)
        XCTAssertEqual(Risk.nz(.infinity), 0)
        XCTAssertEqual(Risk.nz(.nan), 0)
        XCTAssertEqual(Risk.nz(2.5), 2.5)
        XCTAssertEqual(Risk.wt(nil), 0)
        XCTAssertEqual(Risk.wt(.infinity), 0)
        XCTAssertEqual(Risk.wt(0.5), 0.5)
    }

    // ---- risk score ----

    func testEveryAbsentInputIsPricedAtItsOwnWorstCase() {
        XCTAssertEqual(Risk.riskScore([0, 1, nil, 0, 1, 0], weights: w), 0.2, accuracy: 1e-12, "blast radius absent: worst case 1")
        XCTAssertEqual(Risk.riskScore([0, 1, 0, nil, 1, 0], weights: w), 0.2, accuracy: 1e-12, "taint absent: worst case 1")
        XCTAssertEqual(Risk.riskScore([0, 1, 0, 0, 1, nil], weights: w), 0.05, accuracy: 1e-12, "age absent: worst case 1")
    }

    func testAShortInputListPricesTheMissingTailAtTheWorstCase() {
        XCTAssertEqual(Risk.riskScore([0, 1, 0], weights: w), 0.35, accuracy: 1e-12)
        XCTAssertEqual(Risk.riskScore([], weights: w), 1, accuracy: 1e-12)
    }

    // ---- threshold map and escalation ----

    func testRequiredThresholdBands() {
        XCTAssertEqual(Risk.requiredThreshold(0.5, theta1: 0.25, theta2: 0.6), Risk.Required(t: 2, proof: "standard", optimisticAllowed: false))
        XCTAssertEqual(Risk.requiredThreshold(0.9, theta1: 0.25, theta2: 0.6), Risk.Required(t: 3, proof: "strong", optimisticAllowed: false))
        XCTAssertEqual(Risk.requiredThreshold(0.5, theta1: 0.25, theta2: 0.6, irreversible: true), Risk.Required(t: 2, proof: "standard", optimisticAllowed: false))
        XCTAssertEqual(Risk.requiredThreshold(0.9, theta1: 0.25, theta2: 0.6, irreversible: false), Risk.Required(t: 3, proof: "strong", optimisticAllowed: false))
        XCTAssertEqual(Risk.requiredThreshold(.nan, theta1: 1.5, theta2: 3).t, 1, "a non-finite r is priced at exactly 1")
        XCTAssertEqual(Risk.requiredThreshold(.infinity, theta1: 1.5, theta2: 3).t, 1)
    }

    func testEscalateKeepsTheProofCoherent() {
        let std = Risk.Required(t: 1, proof: "standard", optimisticAllowed: true)
        XCTAssertEqual(Risk.escalate(std, minT: 3).proof, "strong", "a standard proof is below the strong floor")
        XCTAssertEqual(Risk.escalate(Risk.Required(t: 2, proof: "standard", optimisticAllowed: false), minT: 2).proof, "standard")
        XCTAssertEqual(Risk.escalate(Risk.Required(t: 1, proof: "strong", optimisticAllowed: false), minT: 2).proof, "strong", "never lowers")
        XCTAssertEqual(Risk.escalate(Risk.Required(t: 1, proof: "claim", optimisticAllowed: true), minT: 2).proof, "standard")
        // an unknown proof name ranks as the strongest: it is kept (the floor is not stronger)
        XCTAssertEqual(Risk.escalate(Risk.Required(t: 3, proof: "bogus", optimisticAllowed: false), minT: 3).proof, "bogus")
        XCTAssertEqual(Risk.escalate(Risk.Required(t: 2, proof: "bogus", optimisticAllowed: false), minT: 2).proof, "bogus")
    }

    // ---- the budget ----

    func testBudgetJSON() {
        XCTAssertEqual(Risk.Budget(json: .object(["B": .double(2), "tau": .int(7), "asOf": .double(9)])), Risk.Budget(b: 2, tau: 7, asOf: 9))
        XCTAssertEqual(Risk.Budget(json: .object(["B": .int(2), "tau": .int(7)])), Risk.Budget(b: 2, tau: 7, asOf: nil))
        XCTAssertNil(Risk.Budget(json: .object(["B": .double(2)])))
        XCTAssertNil(Risk.Budget(json: .object(["tau": .double(2)])))
        XCTAssertNil(Risk.Budget(json: .string("x")))
        XCTAssertNil(Risk.Budget(json: nil))
        XCTAssertEqual(Risk.Budget(b: 1, tau: 2, asOf: 3).json, .object(["B": .double(1), "tau": .double(2), "asOf": .double(3)]))
        XCTAssertEqual(Risk.Budget(b: 1, tau: 2).json, .object(["B": .double(1), "tau": .double(2)]))
    }

    func testLeakWithANonFiniteTimeLeaksNothing() {
        XCTAssertEqual(Risk.leak(Risk.Budget(b: 1, tau: -.infinity), now: 1000, lambda: 0.001).b, 1)
        XCTAssertEqual(Risk.leak(Risk.Budget(b: 1, tau: .nan), now: 1000, lambda: 1).b, 1)
        XCTAssertEqual(Risk.leak(Risk.Budget(b: 1, tau: 0), now: .nan, lambda: 1).b, 1)
    }

    func testAgeSinceTouchEdges() {
        let b = Risk.Budget(b: 1, tau: 0)
        XCTAssertEqual(Risk.ageSinceTouch(b, now: 0, horizonMs: 0), 1, "a zero horizon is unusable: the worst case")
        XCTAssertEqual(Risk.ageSinceTouch(b, now: 1000, horizonMs: -3_600_000), 1, "a negative horizon is unusable")
        XCTAssertEqual(Risk.ageSinceTouch(b, now: 0.25, horizonMs: 0.5), 0.5, accuracy: 1e-12, "a horizon below one millisecond is usable")
        XCTAssertEqual(Risk.ageSinceTouch(Risk.Budget(b: 1, tau: .nan), now: 0), 1)
        XCTAssertEqual(Risk.ageSinceTouch(Risk.Budget(b: 1, tau: .infinity), now: 0), 1)
    }

    // ---- references and the geodesic ----

    func testRefsOf() {
        XCTAssertEqual(Risk.refsOf(.string("a"), Risk.PRE_KEYS), ["a"])
        XCTAssertEqual(Risk.refsOf(.array([.string("a"), .int(1), .string("b")]), Risk.PRE_KEYS), ["a", "b"])
        let o: JSONValue = .object(["after": .string("x"), "depends_on": .array([.string("y")]), "ignored": .string("z"), "nodes": .array([.string("w")])])
        XCTAssertEqual(Risk.refsOf(o, Risk.PRE_KEYS), ["x", "y", "w"])
        XCTAssertEqual(Risk.refsOf(.string("a"), Risk.POST_KEYS), ["a"])
        XCTAssertEqual(Risk.refsOf(nil, Risk.PRE_KEYS), [])
    }

    func testAPlanNodeThatReferencesItselfIsNoEdge() {
        let plan = [node("a", ["pre": .string("a")]), node("b"), node("c"), node("d")]
        XCTAssertEqual(Risk.planGeodesic(plan, from: "a", to: "c"), 2.0 / 3.0, accuracy: 1e-12, "no edge: index distance")
    }

    func testEdgesDecideBetweenHopsAndIndexDistance() {
        let chain = [node("a", ["post": .string("c")]), node("b"), node("c", ["post": .string("d")]), node("d")]
        let d = S2Deadline.within(5, "plan geodesic over a chain") { Risk.planGeodesic(chain, from: "a", to: "d") }
        XCTAssertEqual(d ?? -1, 2.0 / 3.0, accuracy: 1e-12, "two hops over four nodes, not the index distance 1")
    }

    func testIndexDistanceWithoutEdges() {
        let flat = [node("a"), node("b"), node("c"), node("d")]
        XCTAssertEqual(Risk.planGeodesic(flat, from: "b", to: "d"), 2.0 / 3.0, accuracy: 1e-12)
        XCTAssertEqual(Risk.planGeodesic(flat, from: "d", to: "b"), 2.0 / 3.0, accuracy: 1e-12)
    }
}
