import XCTest
import Foundation
@testable import AtlasPCAVerify

/// F2: the risk functional, threshold map and trust budget (risk.ts), and their enforcement in `PCA.authorize`.
final class A0F2RiskFunctionTests: XCTestCase {
    private let w: JObject = ["alpha": .double(0.25), "beta": .double(0.2), "gamma": .double(0.2), "delta": .double(0.2), "epsilon": .double(0.1), "zeta": .double(0.05)]

    func testRiskScore() {
        XCTAssertEqual(Risk.riskScore([1, 0, 1, 1, 0, 1], weights: w), 1, accuracy: 1e-12, "the worst case")
        XCTAssertEqual(Risk.riskScore([0, 1, 0, 0, 1, 0], weights: w), 0, accuracy: 1e-12, "calm")
        XCTAssertEqual(Risk.riskScore([1, 1, 0, 0, 1, 0], weights: w), 0.25, accuracy: 1e-12, "only the semantic distance")
        XCTAssertEqual(Risk.riskScore([0, 0, 0, 0, 1, 0], weights: w), 0.2, accuracy: 1e-12, "irreversible only")
        XCTAssertEqual(Risk.riskScore([nil, nil, nil, nil, nil, nil], weights: w), 1, accuracy: 1e-12, "absent inputs are the worst case")
        XCTAssertEqual(Risk.riskScore([Double.nan, 1, 0, 0, 1, 0], weights: w), 0.25, accuracy: 1e-12, "a non-finite input is the worst case")
        XCTAssertEqual(Risk.riskScore([2, 1, 0, 0, 1, 0], weights: w), 0.25, accuracy: 1e-12, "clamped to 1")
        XCTAssertEqual(Risk.riskScore([-1, 1, 0, 0, 1, 0], weights: w), 0, accuracy: 1e-12, "clamped to 0")
        var neg = w
        neg[JKey("alpha")] = .double(-5)
        XCTAssertEqual(Risk.riskScore([1, 1, 0, 0, 1, 0], weights: neg), 0, accuracy: 1e-12, "a negative weight counts as 0")
    }

    func testRequiredThresholdAndEscalate() {
        XCTAssertEqual(Risk.requiredThreshold(0.25, theta1: 0.25, theta2: 0.6).t, 1)
        XCTAssertEqual(Risk.requiredThreshold(0.2500001, theta1: 0.25, theta2: 0.6).t, 2)
        XCTAssertEqual(Risk.requiredThreshold(0.6, theta1: 0.25, theta2: 0.6).t, 2)
        XCTAssertEqual(Risk.requiredThreshold(0.6000001, theta1: 0.25, theta2: 0.6).t, 3)
        XCTAssertEqual(Risk.requiredThreshold(.nan, theta1: 0.25, theta2: 0.6).t, 3)
        XCTAssertEqual(Risk.requiredThreshold(0, theta1: 0.25, theta2: 0.6, irreversible: true), Risk.Required(t: 1, proof: "claim", optimisticAllowed: false))
        XCTAssertEqual(Risk.requiredThreshold(0, theta1: 0.25, theta2: 0.6), Risk.Required(t: 1, proof: "claim", optimisticAllowed: true))
        XCTAssertEqual(Risk.requiredThreshold(0.5, theta1: 0.25, theta2: 0.6).proof, "standard")
        XCTAssertEqual(Risk.requiredThreshold(0.9, theta1: 0.25, theta2: 0.6).proof, "strong")
        let t1 = Risk.Required(t: 1, proof: "claim", optimisticAllowed: true)
        XCTAssertEqual(Risk.escalate(t1, minT: 2), Risk.Required(t: 2, proof: "standard", optimisticAllowed: false))
        XCTAssertEqual(Risk.escalate(t1, minT: 3).proof, "strong")
        XCTAssertEqual(Risk.escalate(Risk.Required(t: 3, proof: "strong", optimisticAllowed: false), minT: 1).t, 3, "never lowers")
        XCTAssertEqual(Risk.escalate(t1, minT: 1), t1)
    }

    func testBudgetArithmetic() {
        XCTAssertEqual(Risk.cost(0.5, kappa: 2), 1)
        XCTAssertEqual(Risk.cost(.nan, kappa: 2), 2, "non-finite r costs r = 1")
        XCTAssertEqual(Risk.cost(5, kappa: 2), 2, "r is clamped")
        let b = Risk.Budget(b: 1, tau: 0)
        let l = Risk.leak(b, now: 1_000_000, lambda: 0.0005)
        XCTAssertEqual(l.b, 0.5, accuracy: 1e-12)
        XCTAssertEqual(l.asOf, 1_000_000)
        XCTAssertEqual(Risk.leak(l, now: 1_000_000, lambda: 0.0005).b, 0.5, accuracy: 1e-12, "idempotent at the same time")
        XCTAssertEqual(Risk.leak(b, now: 4_000_000, lambda: 0.0005).b, 0, "never below zero")
        XCTAssertEqual(Risk.leak(b, now: -5, lambda: 0.0005).b, 1, "time going backwards leaks nothing")
        XCTAssertEqual(Risk.debit(Risk.Budget(b: 1, tau: 0), 0.4).b, 0.6, accuracy: 1e-12)
        XCTAssertEqual(Risk.debit(Risk.Budget(b: 0.1, tau: 0), 0.4).b, 0)
        XCTAssertEqual(Risk.ageSinceTouch(Risk.Budget(b: 1, tau: 0), now: 1_800_000), 0.5, accuracy: 1e-12)
        XCTAssertEqual(Risk.ageSinceTouch(Risk.Budget(b: 1, tau: 0), now: 9_000_000), 1)
        XCTAssertEqual(Risk.ageSinceTouch(Risk.Budget(b: 1, tau: 0), now: .nan), 1)
        XCTAssertEqual(Risk.ageSinceTouch(Risk.Budget(b: 1, tau: 5), now: 0), 0, "before the last touch")
    }

    func testAdmit() {
        XCTAssertEqual(Risk.admit(t: 1, covers: true), Risk.Admission(admit: true, needStepUp: false, t: 1, metered: true))
        XCTAssertEqual(Risk.admit(t: 2, covers: true), Risk.Admission(admit: false, needStepUp: true, t: 2, metered: true))
        XCTAssertEqual(Risk.admit(t: 3, covers: true), Risk.Admission(admit: false, needStepUp: true, t: 3, metered: false))
        XCTAssertEqual(Risk.admit(t: 1, covers: false), Risk.Admission(admit: false, needStepUp: true, t: 3, metered: false), "no budget: a human step-up")
        XCTAssertEqual(Risk.admit(t: 2, covers: false).t, 3)
        XCTAssertEqual(Risk.admit(t: 3, covers: false).t, 3)
    }

    func testPlanGeodesic() {
        func node(_ id: String, _ extra: JObject = [:]) -> JSONValue { var o: JObject = ["id": .string(id)]; for (k, v) in extra { o[k] = v }; return .object(o) }
        let flat = [node("a"), node("b"), node("c")]
        XCTAssertEqual(Risk.planGeodesic(flat, from: "a", to: "a"), 0)
        XCTAssertEqual(Risk.planGeodesic(flat, from: "a", to: "b"), 0.5, accuracy: 1e-12, "no edges: index distance")
        XCTAssertEqual(Risk.planGeodesic(flat, from: "a", to: "c"), 1, accuracy: 1e-12)
        XCTAssertEqual(Risk.planGeodesic(flat, from: "a", to: "zzz"), 1, "unknown node")
        XCTAssertEqual(Risk.planGeodesic(flat, from: "zzz", to: "a"), 1)
        let dag = [node("a", ["post": .string("b")]), node("b", ["pre": .string("a"), "post": .array([.string("c")])]), node("c"), node("d")]
        XCTAssertEqual(Risk.planGeodesic(dag, from: "a", to: "c"), 2.0 / 3.0, accuracy: 1e-12, "two hops over four nodes")
        XCTAssertEqual(Risk.planGeodesic(dag, from: "c", to: "a"), 2.0 / 3.0, accuracy: 1e-12, "undirected")
        XCTAssertEqual(Risk.planGeodesic(dag, from: "a", to: "d"), 1, "unreachable")
        let named = [node("x", ["pre": .object(["after": .string("y")])]), node("y")]
        XCTAssertEqual(Risk.planGeodesic(named, from: "x", to: "y"), 1, accuracy: 1e-12, "a reference under `after` is an edge: 1 hop over 2 nodes")
    }
}

final class A0F2RiskAuthorizeTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// A grant whose risk policy really weighs the inputs (the AZ default weighs nothing, so its risk is always 0).
    static let REAL: JSONValue = .object([
        "bMax": .double(1), "kappa": .double(1), "lambda": .double(0), "rho": .double(0.5), "theta1": .double(0.25), "theta2": .double(0.6),
        "weights": .object(["alpha": .double(0.25), "beta": .double(0.2), "gamma": .double(0.2), "delta": .double(0.2), "epsilon": .double(0.1), "zeta": .double(0.05)]),
    ])

    private func run(_ s: AZ.Signed = AZ.signed(riskPolicy: A0F2RiskAuthorizeTests.REAL), _ edit: (inout PCA.AuthorizeInput) -> Void) -> PCA.AuthorizeResult {
        AZ.run(s) { $0.riskSource = nil; edit(&$0) }
    }

    private func risk(_ d: Double, _ extra: JObject = [:]) -> (PCA.Operation, JSONValue, JSONValue) throws -> JObject? {
        // every input calm except the semantic distance and blast radius at `d`
        return { _, _, _ in
            var o: JObject = ["semanticDistance": .double(d), "reversibility": .int(1), "blastRadius": .double(d), "taint": .int(0), "confidence": .int(1), "age": .int(0)]
            for (k, v) in extra { o[k] = v }
            return o
        }
    }

    func testWithoutAnyRiskSourceEveryInputIsWorstCaseAndTheActionNeedsAStepUp() {
        let r = run { _ in }
        XCTAssertFalse(r.allow)
        XCTAssertTrue(r.reasons.contains("threshold: t=3 (strong) required but no threshold verifier is enforced"), "\(r.reasons)")
        XCTAssertTrue(r.reasons.contains { $0.hasPrefix("policy: risk input(s) missing, assumed worst case:") }, "\(r.reasons)")
        XCTAssertEqual(r.checks["threshold"], .fail)
    }

    func testACalmOperationIsAdmittedAndTheStreamBudgetIsStored() {
        let s = AZ.signed(riskPolicy: Self.REAL)
        let store = MemoryStateStore()
        let r = run(s) { $0.stateStore = store; $0.riskSource = PCA.insecureCalmRisk }
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(r.checks["budget"], .pass, "a fresh stream is seeded with bMax")
        let gid = s.grant.get("id")?.asString ?? ""
        let holder = s.pcactn.get("cap_chain")?.asArray?.last?.get("holder")?.asString ?? ""
        XCTAssertEqual(store.budget(key: PCA.stateKey(grantId: gid, leafHolder: holder))?.b, 1, "cost 0 at r = 0")
    }

    func testAMidRiskNeedsAThresholdHookThatEnforcedAtLeastTheServerT() {
        // r = 0.25 * 0.5 + 0.2 * 0.5 = 0.225 -> t = 1; use d = 1: 0.45 -> t = 2
        let none = run { $0.riskSource = self.risk(1) }
        XCTAssertFalse(none.allow)
        XCTAssertTrue(none.reasons.contains("threshold: t=2 (standard) required but no threshold verifier is enforced"), "\(none.reasons)")
        let ok = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: 2) } }
        XCTAssertTrue(ok.allow, "\(ok.reasons)")
        XCTAssertEqual(ok.checks["threshold"], .pass)
        let below = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: 1) } }
        XCTAssertFalse(below.allow)
        XCTAssertTrue(below.reasons.contains("threshold: threshold hook enforced t=1 but the server requires t=2 (below the server-derived threshold; derive t from server-held data)"), "\(below.reasons)")
        // the reference prints the t the hook reported, unfloored; NaN is unreported to the comparison but prints as NaN
        let frac = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: 1.9) } }
        XCTAssertTrue(frac.reasons.contains("threshold: threshold hook enforced t=1.9 but the server requires t=2 (below the server-derived threshold; derive t from server-held data)"), "\(frac.reasons)")
        let nan = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: .nan) } }
        XCTAssertFalse(nan.allow)
        XCTAssertTrue(nan.reasons.contains { $0.hasPrefix("threshold: threshold hook enforced t=NaN but") }, "\(nan.reasons)")
        let inf = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: .infinity) } }
        XCTAssertTrue(inf.allow, "\(inf.reasons)")
        let noReason = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: false, t: 2) } }
        XCTAssertFalse(noReason.allow)
        let unreported = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: nil) } }
        XCTAssertTrue(unreported.reasons.contains { $0.contains("threshold hook enforced t=unreported") }, "\(unreported.reasons)")
        let rejected = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: false, t: 2) } }
        XCTAssertTrue(rejected.reasons.contains("threshold: t=2 required and the threshold proof was rejected"), "\(rejected.reasons)")
        struct Boom: Error {}
        let threw = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in throw Boom() } }
        XCTAssertFalse(threw.allow)
        let silent = run { $0.riskSource = self.risk(1); $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: false, ok: true, t: 3) } }
        XCTAssertFalse(silent.allow, "a hook that did not enforce is not a proof")
    }

    func testRequiredRiskInputsAndARiskSourceThatThrows() {
        let missing = run { $0.riskSource = { _, _, _ in ["blastRadius": .int(0)] }; $0.requireRiskInputs = ["taint", "confidence"] }
        XCTAssertEqual(missing.checks["risk_inputs"], .fail)
        XCTAssertTrue(missing.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: taint, confidence"), "\(missing.reasons)")
        let present = run { $0.riskSource = PCA.insecureCalmRisk; $0.requireRiskInputs = ["taint", "confidence"] }
        XCTAssertEqual(present.checks["risk_inputs"], .pass)
        XCTAssertTrue(present.allow, "\(present.reasons)")
        struct Boom: Error {}
        let thrown = run { $0.riskSource = { _, _, _ in throw Boom() } }
        XCTAssertFalse(thrown.allow)
        XCTAssertTrue(thrown.reasons.contains("risk: the risk source failed (fail closed)"), "\(thrown.reasons)")
    }

    func testAnAdaptivePolicyCanOnlyNarrow() {
        var tight = Self.REAL.asObject ?? [:]
        tight[JKey("theta1")] = .double(0)
        tight[JKey("theta2")] = .double(0.01)
        let refused = run { $0.riskSource = self.risk(0.5); $0.adaptivePolicy = { _ in .object(tight) } }
        XCTAssertFalse(refused.allow)
        XCTAssertTrue(refused.reasons.contains { $0.hasPrefix("adaptive: tightened policy requires threshold t=3") || $0.hasPrefix("adaptive: tightened policy requires threshold t=2") }, "\(refused.reasons)")
        let same = run { $0.riskSource = PCA.insecureCalmRisk; $0.adaptivePolicy = { _ in AZ.RISK } }
        XCTAssertTrue(same.allow, "\(same.reasons)")
        let invalid = run { $0.riskSource = PCA.insecureCalmRisk; $0.adaptivePolicy = { _ in .object(["theta1": .double(2)]) } }
        XCTAssertFalse(invalid.allow)
        XCTAssertEqual(invalid.checks["adaptive"], .fail)
        let unreadable = run { $0.riskSource = PCA.insecureCalmRisk; $0.adaptivePolicy = { _ in nil } }
        XCTAssertFalse(unreadable.allow)
    }
}

final class A0F2BudgetStoreTests: XCTestCase {
    func testTheCounterAndTheBudgetMoveInOneAtomicStep() {
        let s = MemoryStateStore()
        XCTAssertNil(s.budget(key: "k"))
        let b0 = Risk.Budget(b: 1, tau: 0, asOf: 0)
        XCTAssertTrue(s.claim(key: "k", counter: 1, budgetBefore: nil, budgetAfter: b0).ok, "both absent counts as equal")
        XCTAssertEqual(s.budget(key: "k"), b0)
        let b1 = Risk.Budget(b: 0.5, tau: 0, asOf: 10)
        let conflict = s.claim(key: "k", counter: 2, budgetBefore: Risk.Budget(b: 9, tau: 0, asOf: 0), budgetAfter: b1)
        XCTAssertEqual(conflict, ClaimResult(ok: false, lastCounter: nil, conflict: true))
        XCTAssertEqual(s.budget(key: "k"), b0, "a conflict changes nothing")
        XCTAssertTrue(s.claim(key: "k", counter: 2, budgetBefore: b0, budgetAfter: b1).ok)
        XCTAssertEqual(s.budget(key: "k"), b1)
        XCTAssertEqual(s.claim(key: "k", counter: 2, budgetBefore: b1, budgetAfter: nil), ClaimResult(ok: false, lastCounter: 2), "a replay is a replay")
        XCTAssertTrue(s.claim(key: "k", counter: 3, budgetBefore: b1, budgetAfter: nil).ok)
        XCTAssertEqual(s.budget(key: "k"), b1, "nil keeps the stored budget")
    }
}
