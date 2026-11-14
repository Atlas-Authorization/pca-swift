import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A budget / pin store that forwards to a `MemoryStateStore` and can be told to fail a pin or to report a budget conflict.
final class ScriptedPinBudgetStore: PCABudgetStore, PCAPinStore {
    struct Refused: Error {}
    let inner = MemoryStateStore()
    /// `raisePin` throws for a key with one of these suffixes.
    var failPinSuffixes: [String] = []
    var conflict = false

    var scope: PCAStoreScope { .process }
    func claim(key: String, counter: Int64) throws -> ClaimResult { inner.claim(key: key, counter: counter) }
    func budget(key: String) throws -> Risk.Budget? { inner.budget(key: key) }
    func claim(key: String, counter: Int64, budgetBefore: Risk.Budget?, budgetAfter: Risk.Budget?) throws -> ClaimResult {
        if conflict { return ClaimResult(ok: false, conflict: true) }
        return inner.claim(key: key, counter: counter, budgetBefore: budgetBefore, budgetAfter: budgetAfter)
    }
    func pin(key: String) throws -> Double? { inner.pin(key: key) }
    func raisePin(key: String, value: Double) throws {
        if failPinSuffixes.contains(where: { key.hasSuffix($0) }) { throw Refused() }
        inner.raisePin(key: key, value: value)
    }
}

/// A counter shared with a closure that is called more than once.
final class SurvivorCallCounter: @unchecked Sendable { var n = 0 }

/// `AtomicKV` whose reads work and whose writes fail: a contract peek (read only) passes, the commit does not.
final class WriteFailingKV: AtomicKV, @unchecked Sendable {
    struct Refused: Error {}
    let inner = MemoryAtomicKV()
    func get(_ key: String) throws -> JSONValue? { inner.get(key) }
    func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws { throw Refused() }
}

// ---- units ----

final class AuthorizeUnitSurvivorKillTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testMemoryStateStoreLocksOncePerCall() {
        let s = MemoryStateStore()
        let b = Risk.Budget(b: 1, tau: 0)
        S2LK.check(s.lock, "putBudget") { s.putBudget(key: "k", b) }
        XCTAssertEqual(S2LK.check(s.lock, "budget") { s.budget(key: "k") }, b)
        XCTAssertTrue(S2LK.check(s.lock, "claim with a budget") { s.claim(key: "k", counter: 1, budgetBefore: b, budgetAfter: nil) }.ok)
        S2LK.check(s.lock, "raisePin") { s.raisePin(key: "p", value: 3) }
        XCTAssertEqual(S2LK.check(s.lock, "pin") { s.pin(key: "p") }, 3)
    }

    func testRevocationStalenessNeedsAStoreWithPins() {
        struct NoPins: PCAStateStore { func claim(key: String, counter: Int64) throws -> ClaimResult { ClaimResult(ok: true) } }
        var i = PCA.AuthorizeInput(audience: "a", resolveGrant: { _ in nil }, stateStore: NoPins(), isRevoked: { _, _ in false })
        i.revocationStaleness = RevocationStalenessPolicy(maxRevocationAgeMs: 1000)
        i.revocationState = { _, _ in nil }
        XCTAssertEqual(PCA.missingAuthorizeComponents(i), ["stateStore (revocation staleness needs a state store that implements pins (rollback protection))"])
        i.stateStore = MemoryStateStore()
        XCTAssertEqual(PCA.missingAuthorizeComponents(i), [])
    }

    func testRiskierMergesPerInput() {
        let a: JObject = ["reversibility": .double(0.8), "confidence": .double(0.9), "taint": .double(0.2), "age": .string("x")]
        let b: JObject = ["reversibility": .double(0.4), "confidence": .double(0.95), "taint": .double(0.7), "extra": .double(0.3), "bad": .string("x"), "age": .double(0.1)]
        let m = PCA.riskier(a, b)
        XCTAssertEqual(m?[JKey("reversibility")], .double(0.4), "lower is riskier")
        XCTAssertEqual(m?[JKey("confidence")], .double(0.9), "lower is riskier")
        XCTAssertEqual(m?[JKey("taint")], .double(0.7), "higher is riskier")
        XCTAssertEqual(m?[JKey("extra")], .double(0.3), "an input only the second source supplies")
        XCTAssertEqual(m?[JKey("age")], .double(0.1), "the first source's value is not a number")
        XCTAssertNil(m?[JKey("bad")], "a non-numeric input is ignored")
        XCTAssertEqual(PCA.riskier(nil, b), b)
        XCTAssertEqual(PCA.riskier(a, nil), a)
        XCTAssertNil(PCA.riskier(nil, nil))
    }

    func testAmountRisk() throws {
        func risk(kappa: Double, amount: JSONValue?) throws -> JObject? {
            var rp = A0F2RiskAuthorizeTests.REAL.asObject ?? [:]
            rp[JKey("kappa")] = .double(kappa)
            let grant = AZ.grant(envelope: AZ.envelope(riskPolicy: .object(rp)))
            var params: JObject = [:]
            if let a = amount { params["amount"] = a }
            return try PCA.amountRisk(PCA.Operation(verb: "v", resource: "r", params: .object(params)), grant, .null)
        }
        let half: JObject = ["blastRadius": .double(0.5)]
        XCTAssertEqual(try risk(kappa: 100, amount: .int(50)), half)
        XCTAssertEqual(try risk(kappa: 1, amount: .int(50)), ["blastRadius": .double(1)], "clamped to 1; a kappa of 1 is valid")
        XCTAssertEqual(try risk(kappa: 100, amount: .int(-5)), ["blastRadius": .double(0)], "clamped to 0")
        XCTAssertNil(try risk(kappa: 100, amount: nil))
        XCTAssertNil(try risk(kappa: 100, amount: .string("50")))
        XCTAssertNil(try PCA.amountRisk(PCA.Operation(verb: "v", resource: "r", params: .object(["amount": .int(1)])), .null, .null))
    }

    func testTheCalmRiskHelperIsExactlyTheSafestInputs() throws {
        let r = try PCA.insecureCalmRisk(PCA.Operation(verb: "v", resource: "r", params: .object([:])), .null, .null)
        let want: JObject = ["semanticDistance": .int(0), "reversibility": .int(1), "blastRadius": .int(0), "taint": .int(0), "confidence": .int(1), "age": .int(0)]
        XCTAssertEqual(r, want)
    }
}

// ---- the risk step of authorize ----

final class AuthorizeRiskSurvivorKillTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    struct Boom: Error {}
    static let NOTE = "budget: no budget supplied \u{2014} fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge"

    static func policy(_ w: [String: Double], theta1: Double = 0.25, theta2: Double = 0.6, kappa: Double = 1, bMax: Double = 1) -> JSONValue {
        var weights: JObject = [:]
        for k in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] { weights[JKey(k)] = .double(w[k] ?? 0) }
        return .object(["bMax": .double(bMax), "kappa": .double(kappa), "lambda": .double(0), "rho": .double(0), "theta1": .double(theta1),
                        "theta2": .double(theta2), "weights": .object(weights)])
    }

    /// Every input calm, `over` replaced, `drop` removed.
    static func source(_ over: JObject = [:], drop: [String] = []) -> (PCA.Operation, JSONValue, JSONValue) throws -> JObject? {
        return { _, _, _ in
            var o: JObject = ["semanticDistance": .double(0), "reversibility": .double(1), "blastRadius": .double(0), "taint": .double(0),
                              "confidence": .double(1), "age": .double(0)]
            for (k, v) in over { o[k] = v }
            for k in drop { o[JKey(k)] = nil }
            return o
        }
    }

    func run(_ p: JSONValue, predicates: [JSONValue] = [AZ.ANY], extra: JObject = [:], _ edit: (inout PCA.AuthorizeInput) -> Void) -> PCA.AuthorizeResult {
        AZ.run(AZ.signed(predicates: predicates, riskPolicy: p, extra: extra)) { $0.riskSource = nil; edit(&$0) }
    }

    func withBudget(_ b: Risk.Budget) -> ((JSONValue) throws -> PCA.AuthorizeContext?) { { _ in PCA.AuthorizeContext(budget: b) } }

    func testAFailedPolicyReleasesNoThresholdDemand() {
        let other: JSONValue = .object(["verb": .string("payments.refund"), "resource": .string("payments/*")])
        let r = run(Self.policy(["gamma": 1]), predicates: [other]) { $0.riskSource = Self.source(["blastRadius": .double(0.5)]) }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["policy"], .fail)
        XCTAssertNil(r.checks["threshold"])
        XCTAssertFalse(r.reasons.contains { $0.hasPrefix("threshold:") }, "\(r.reasons)")
    }

    func testAFailingRiskSourceStopsTheRiskStep() {
        let r = run(Self.policy(["gamma": 1])) { $0.riskSource = { _, _, _ in throw Boom() } }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["risk"], .fail)
        XCTAssertNil(r.checks["budget"])
        XCTAssertNil(r.checks["threshold"])
        XCTAssertFalse(r.reasons.contains { $0.hasPrefix("threshold:") || $0.hasPrefix("policy: risk") }, "\(r.reasons)")
    }

    func testTheMissingInputsAreNamedExactlyAndAgeIsNeverMissing() {
        let r = run(Self.policy(["alpha": 1])) { _ in }
        XCTAssertTrue(r.reasons.contains("policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence"), "\(r.reasons)")
    }

    func testTheSemanticDistanceComesFromThePlanWhenNobodySuppliesIt() {
        let r = run(Self.policy(["alpha": 1])) { $0.riskSource = Self.source(drop: ["semanticDistance"]) }
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertNil(r.reasons.first { $0.hasPrefix("policy: risk input(s) missing") })
    }

    func testAPlanWithoutAGoalIdPricesTheSemanticDistanceAtTheWorstCase() {
        let plan: [JSONValue] = [.object(["verb": .string("payments.send"), "resource": .string("payments/acme")])]
        let alpha = run(Self.policy(["alpha": 1])) {
            $0.riskSource = Self.source(drop: ["semanticDistance"])
            $0.context = { _ in PCA.AuthorizeContext(plan: plan, planAuthorized: true) }
        }
        XCTAssertTrue(alpha.reasons.contains("policy: risk 1.000 exceeds auto threshold: step-up to t=3"), "\(alpha.reasons)")
        // only the semantic distance slot is set: reversibility (weighted alone) stays as the source supplied it
        let beta = run(Self.policy(["beta": 1])) {
            $0.riskSource = Self.source(["reversibility": .double(0)], drop: ["semanticDistance"])
            $0.context = { _ in PCA.AuthorizeContext(plan: plan, planAuthorized: true) }
        }
        XCTAssertTrue(beta.reasons.contains("policy: risk 1.000 exceeds auto threshold: step-up to t=3"), "\(beta.reasons)")
    }

    func testTheAgeInputIsTheTimeSinceTheLastHumanTouch() {
        let budget = Risk.Budget(b: 1, tau: Double(AZ.NOW) - 1_800_000)
        let r = run(Self.policy(["zeta": 1])) {
            $0.riskSource = Self.source(drop: ["age"])
            $0.context = self.withBudget(budget)
        }
        XCTAssertTrue(r.reasons.contains("policy: risk 0.500 exceeds auto threshold: step-up to t=2"), "\(r.reasons)")
    }

    func testCautionSetsAFloorOnTheRisk() {
        let calm = Self.policy([:])
        func go(_ c: JSONValue) -> PCA.AuthorizeResult { run(calm, extra: ["caution": c]) { $0.riskSource = PCA.insecureCalmRisk } }
        XCTAssertTrue(go(.int(0)).allow, "caution 0 is no floor")
        let one = go(.int(1))
        XCTAssertFalse(one.allow)
        XCTAssertTrue(one.reasons.contains("threshold: t=3 (strong) required but no threshold verifier is enforced"), "\(one.reasons)")
        let half = go(.double(0.5))
        XCTAssertFalse(half.allow)
        XCTAssertTrue(half.reasons.contains("threshold: t=2 (standard) required but no threshold verifier is enforced"), "\(half.reasons)")
    }

    func testTheStepUpReasonSaysWhyTheActionLeavesTheMachineOnlyBand() {
        let p = Self.policy(["gamma": 1])
        let now = Double(AZ.NOW)
        func reasons(_ x: Double, _ budget: Risk.Budget?) -> [String] {
            run(p) {
                $0.riskSource = Self.source(["blastRadius": .double(x)])
                if let b = budget { $0.context = self.withBudget(b) }
            }.reasons
        }
        XCTAssertTrue(reasons(0.5, nil).contains("policy: risk 0.500 exceeds auto threshold: step-up to t=2"))
        XCTAssertTrue(reasons(0.9, nil).contains("policy: risk 0.900 exceeds auto threshold: step-up to t=3"))
        let poor = Risk.Budget(b: 0.1, tau: now, asOf: now)
        XCTAssertTrue(reasons(0.5, poor).contains("policy: trust budget depleted: human recharge required"))
        XCTAssertTrue(reasons(0.2, poor).contains("policy: trust budget depleted: human recharge required"))
        XCTAssertFalse(reasons(0.9, poor).contains("policy: trust budget depleted: human recharge required"), "already in the human band")
    }

    func testTheMissingBudgetNoteIsExplainedOnlyWhenItDecidedAStepUp() {
        struct Plain: PCAStateStore { func claim(key: String, counter: Int64) throws -> ClaimResult { ClaimResult(ok: true) } }
        let p = Self.policy(["gamma": 1])
        let calm = run(p) { $0.stateStore = Plain(); $0.riskSource = Self.source() }
        XCTAssertTrue(calm.allow, "\(calm.reasons)")
        XCTAssertFalse(calm.reasons.contains(Self.NOTE), "a calm allow on a store that keeps no budget stays free of the note")
        let mid = run(p) { $0.stateStore = Plain(); $0.riskSource = Self.source(["blastRadius": .double(0.5)]) }
        XCTAssertFalse(mid.allow)
        XCTAssertTrue(mid.reasons.contains(Self.NOTE), "\(mid.reasons)")
        let seeded = run(p) { $0.riskSource = Self.source(["blastRadius": .double(0.5)]) }
        XCTAssertTrue(seeded.reasons.contains("policy: risk 0.500 exceeds auto threshold: step-up to t=2"))
        XCTAssertFalse(seeded.reasons.contains(Self.NOTE), "a seeded budget exists")
    }

    func testAHumanStepUpIsNotDebited() {
        let store = MemoryStateStore()
        let s = AZ.signed(riskPolicy: Self.policy(["gamma": 1]))
        let r = AZ.run(s) {
            $0.stateStore = store
            $0.riskSource = Self.source(["blastRadius": .double(0.9)])
            $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: 3) }
        }
        XCTAssertTrue(r.allow, "\(r.reasons)")
        let gid = s.grant.get("id")?.asString ?? ""
        let holder = s.pcactn.get("cap_chain")?.asArray?.last?.get("holder")?.asString ?? ""
        XCTAssertEqual(store.budget(key: PCA.stateKey(grantId: gid, leafHolder: holder))?.b, 1, "t = 3 is unmetered")
    }

    func testAThresholdHookThatThrowsEnforcedAndRejected() {
        let r = run(Self.policy(["gamma": 1])) {
            $0.riskSource = Self.source(["blastRadius": .double(0.5)])
            $0.thresholdHook = { _ in throw Boom() }
        }
        XCTAssertFalse(r.allow)
        XCTAssertTrue(r.reasons.contains("threshold: t=2 required and the threshold proof was rejected"), "\(r.reasons)")
    }

    func testAnEnforcingHookIsHeardEvenWhenNoThresholdIsDemanded() {
        let calm = Self.policy([:])
        let rejected = run(calm) {
            $0.riskSource = Self.source()
            $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: false, reason: "nope") }
        }
        XCTAssertFalse(rejected.allow)
        XCTAssertEqual(rejected.checks["threshold"], .fail)
        XCTAssertTrue(rejected.reasons.contains("threshold: nope"), "\(rejected.reasons)")
        let accepted = run(calm) {
            $0.riskSource = Self.source()
            $0.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true) }
        }
        XCTAssertTrue(accepted.allow, "\(accepted.reasons)")
        XCTAssertEqual(accepted.checks["threshold"], .pass)
    }

    func testAnAdaptivePolicyThatCannotBeReadIsRefusedOnce() {
        let r = run(Self.policy([:])) {
            $0.riskSource = Self.source()
            $0.adaptivePolicy = { _ in throw Boom() }
        }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.reasons.filter { $0 == "adaptive: the adaptive policy could not be read (fail closed)" }.count, 1, "\(r.reasons)")
    }

    func testRequiredRiskInputsCountThePlanAsTheSemanticDistance() {
        let src = Self.source(drop: ["semanticDistance", "taint"])
        let planned = run(Self.policy([:])) { $0.riskSource = src; $0.requireRiskInputs = ["semanticDistance", "taint"] }
        XCTAssertTrue(planned.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: taint"), "\(planned.reasons)")
        let unplanned = run(Self.policy([:])) { $0.riskSource = src; $0.requireRiskInputs = ["semanticDistance", "taint"]; $0.plan = nil }
        XCTAssertTrue(unplanned.reasons.contains("risk_inputs: required risk input(s) not supplied by the server: semanticDistance, taint"), "\(unplanned.reasons)")
    }

    func testAConcurrentBudgetChangeIsARefusalWithItsOwnReason() {
        let store = ScriptedPinBudgetStore()
        store.conflict = true
        let r = AZ.run(AZ.signed(riskPolicy: A0F2RiskAuthorizeTests.REAL)) { $0.stateStore = store }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["replay"], .fail)
        XCTAssertTrue(r.reasons.contains("replay: the trust budget changed under this decision (concurrent update): retry"), "\(r.reasons)")
    }
}

// ---- the F3 gates inside authorize ----

final class AuthorizeGateFlowSurvivorKillTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    struct Boom: Error {}

    func testAThrowingClauseSourceIsAFailClosed403() {
        let r = AZ.run(AZ.signed()) { $0.forbid = PCA.ForbidGate(clauses: { _, _ in throw Boom() }) }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.checks["authorize"], .fail)
        XCTAssertTrue(r.reason?.hasPrefix("authorize error (fail closed)") ?? false, r.reason ?? "nil")
    }

    func testALinkedTemplateIsCheckedBeforeThePCActnIsVerified() throws {
        let t = try LinkedTemplateFixture.make()
        let gate = PCA.LinkedTemplateGate(registry: t.registry)
        let r = AZ.run(AZ.signed()) { $0.requireLinkedTemplate = gate }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.checkNames, ["template"], "refused before any other check ran")
        XCTAssertNil(r.verdict)
        XCTAssertEqual(r.reason, "template: the grant carries no template_ref")
        // a grant that cannot be read is left to the verification that follows
        let unreadable = AZ.run(AZ.signed()) {
            $0.resolveGrant = { _ in throw Boom() }
            $0.requireLinkedTemplate = gate
        }
        XCTAssertEqual(unreadable.reason, "resolve_grant: grant resolution failed (fail closed)")
    }

    private func linked(_ t: (registry: JSONValue, ref: JSONValue, digest: String)) -> AZ.Signed {
        let g = AZ.grant(envelope: LinkedTemplateFixture.envelope(ref: t.ref))
        return AZ.Signed(grant: g, pcactn: AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: AZ.NOW, aud: AZ.AUD), params: AuthorizeTests.P50)
    }

    func testALinkedGrantIsAdmittedAndRecordedAsLinked() throws {
        let t = try LinkedTemplateFixture.make()
        let r = AZ.run(linked(t)) { $0.requireLinkedTemplate = PCA.LinkedTemplateGate(registry: t.registry) }
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(r.template, "linked")
    }

    func testTheGrantThatWasUsedIsJudgedAgainstTheTemplateOnceMore() throws {
        let t = try LinkedTemplateFixture.make()
        let calls = SurvivorCallCounter()
        let flipping = PCA.LinkedTemplateGate(registry: { calls.n += 1; return calls.n == 1 ? t.registry : LinkedTemplateFixture.empty })
        let r = AZ.run(linked(t)) { $0.requireLinkedTemplate = flipping }
        XCTAssertEqual(calls.n, 2, "once before the PCActn is verified, once for the grant that was used")
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["template"], .fail)
        XCTAssertTrue(r.reasons.contains("template: template version is not in the registry"), "\(r.reasons)")
    }

    func testARegistryThatFailsAfterTheFirstLookIsRefused() throws {
        let t = try LinkedTemplateFixture.make()
        let calls = SurvivorCallCounter()
        let failing = PCA.LinkedTemplateGate(registry: { calls.n += 1; if calls.n > 1 { throw Boom() }; return t.registry })
        let r = AZ.run(linked(t)) { $0.requireLinkedTemplate = failing }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["template"], .fail)
        XCTAssertTrue(r.reasons.contains("template: the template registry failed (fail closed)"), "\(r.reasons)")
        // a registry that is down for both looks
        let down = PCA.LinkedTemplateGate(registry: { throw Boom() })
        let r2 = AZ.run(linked(t)) { $0.requireLinkedTemplate = down }
        XCTAssertFalse(r2.allow)
        XCTAssertTrue(r2.reasons.contains("template: the template registry failed (fail closed)"), "\(r2.reasons)")
    }

    // ---- contracts ----

    private lazy var key = try! PCAEdKey(seed: [UInt8](repeating: 4, count: 32))

    private func contract(_ verb: String) throws -> JSONValue {
        let c = try XCTUnwrap(JSONValue.parse(#"{"version":1,"principal":"\#(key.id)","clauses":[{"id":"no-pay","kind":"never","p":{"verb":"\#(verb)"}}]}"#))
        return try Contracts.signContract(c, principal: key)
    }

    func testAViolatedContractIsA403BeforeTheCounterIsTouched() throws {
        let e = try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: try contract("payments.send"), principal: key.id)
        let r = AZ.run(AZ.signed()) { $0.contracts = e }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.reason, "contract: violated (no-pay)")
    }

    func testAContractWhoseCommitFailsRefusesTheAction() throws {
        let e = try ContractEnforcer.open(kv: WriteFailingKV(), contract: try contract("delete"), principal: key.id)
        let store = MemoryStateStore()
        let s = AZ.signed()
        let r = AZ.run(s) { $0.stateStore = store; $0.contracts = e }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["contract"], .fail)
        XCTAssertTrue(r.reasons.contains("contract: store-error"), "\(r.reasons)")
        XCTAssertTrue(AZ.run(s) { $0.stateStore = store }.allow, "the refusal cost the PCActn nothing")
    }
}

// ---- liveness beacons inside authorize ----

final class AuthorizeBeaconSurvivorKillTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    private lazy var key = try! PCAEdKey(seed: [UInt8](repeating: 4, count: 32))

    private func beacon(_ seq: Int64) throws -> JSONValue {
        try Beacons.issueLivenessBeacon(issuer: PCASuiteKey.ed25519(key), instance: "inst", seq: seq, issuedAt: AZ.NOW)
    }

    private func run(seq: Int64, store: ScriptedPinBudgetStore, ref: String? = nil, lastAccepted: Int64? = nil) throws -> (result: PCA.AuthorizeResult, grantId: String) {
        let b = try beacon(seq)
        let bound: String
        if let r = ref { bound = r } else { bound = try Beacons.beaconRef(b) }
        let s = AZ.signed(extra: ["freshness": .object(["epoch": .int(100), "beacon_ref": .string(bound), "accumulator_witness": .string("w")])])
        let kid = key.id
        let r = AZ.run(s) {
            $0.stateStore = store
            $0.beacon = { _, _ in PCA.BeaconInput(beacon: b, issuers: [kid], instance: "inst", lastAcceptedSeq: lastAccepted) }
        }
        return (r, s.grant.get("id")?.asString ?? "")
    }

    func testABoundFreshBeaconPassesAndRaisesThePin() throws {
        let store = ScriptedPinBudgetStore()
        let (r, gid) = try run(seq: 5, store: store)
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(r.checks["beacon"], .pass)
        XCTAssertEqual(store.inner.pin(key: gid + ":beacon"), 5)
    }

    func testABeaconAtTheLastAcceptedSeqIsNotAReplay() throws {
        let store = ScriptedPinBudgetStore()
        let gid = AZ.signed().grant.get("id")?.asString ?? ""
        store.inner.raisePin(key: gid + ":beacon", value: 5)
        let (r, _) = try run(seq: 5, store: store)
        XCTAssertTrue(r.allow, "\(r.reasons)")
        XCTAssertEqual(r.checks["beacon"], .pass)
    }

    func testAnOlderBeaconThanThePinOrTheHostIsAReplay() throws {
        let store = ScriptedPinBudgetStore()
        let gid = AZ.signed().grant.get("id")?.asString ?? ""
        store.inner.raisePin(key: gid + ":beacon", value: 5)
        let (r, _) = try run(seq: 4, store: store)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["beacon"], .fail)
        XCTAssertTrue(r.reasons.contains("beacon: beacon seq 4 is older than the last accepted 5 (replay)"), "\(r.reasons)")
        let host = try run(seq: 4, store: ScriptedPinBudgetStore(), lastAccepted: 9).result
        XCTAssertFalse(host.allow)
        XCTAssertTrue(host.reasons.contains("beacon: beacon seq 4 is older than the last accepted 9 (replay)"), "\(host.reasons)")
    }

    func testABeaconThePCActnDoesNotBindIsRefused() throws {
        let (r, _) = try run(seq: 5, store: ScriptedPinBudgetStore(), ref: "not-the-beacon")
        XCTAssertFalse(r.allow)
        XCTAssertTrue(r.reasons.contains("beacon: PCActn freshness.beacon_ref does not bind the presented beacon"), "\(r.reasons)")
    }

    func testAPinThatCannotBeStoredRefusesTheAction() throws {
        let store = ScriptedPinBudgetStore()
        store.failPinSuffixes = [":beacon"]
        let (r, _) = try run(seq: 5, store: store)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["beacon"], .fail)
        XCTAssertTrue(r.reasons.contains("beacon: the beacon pin could not be stored (fail closed)"), "\(r.reasons)")
    }
}

// ---- the revocation-epoch pin ----

final class AuthorizeEpochPinSurvivorKillTests: XCTestCase {
    func testAnEpochPinThatCannotBeRaisedRefusesTheAction() throws {
        let seed = [UInt8](repeating: 9, count: 32)
        let s = AZ.signed(extra: ["freshness": .object(["epoch": .int(100), "beacon_ref": .string("b"), "accumulator_witness": .string("w")])])
        let gref = try XCTUnwrap(s.pcactn.get("grant_ref")?.asString)
        let root = try XCTUnwrap(IntentRevocation.bindRoot(JSONValue.int(0), IntentRevocation.EMPTY_TREE))
        let ep = try XCTUnwrap(PCA.signRevocationEpoch(guardianSeed: seed, RevocationEpochBody(instanceId: "i", grantRef: gref, epoch: 6, setSize: 0, root: root,
                                                                                         issuedAt: AZ.NOW - 10, notAfter: AZ.NOW + 100_000)))
        let guardian = try XCTUnwrap(ep.get("guardian")?.asString)
        func go(_ store: ScriptedPinBudgetStore) -> PCA.AuthorizeResult {
            AZ.run(s) {
                $0.stateStore = store
                $0.revocationStaleness = RevocationStalenessPolicy(maxRevocationAgeMs: 100_000)
                $0.guardianPublic = guardian
                $0.revocationState = { _, _ in RevocationState(epoch: ep, lastAcceptedEpoch: nil) }
                $0.revocationProof = { _, _ in JSONValue.object(["size": JSONValue.int(0)]) }
            }
        }
        let healthy = ScriptedPinBudgetStore()
        XCTAssertTrue(go(healthy).allow)
        XCTAssertEqual(healthy.inner.pin(key: "\(gref):epoch"), 6)
        let broken = ScriptedPinBudgetStore()
        broken.failPinSuffixes = [":epoch"]
        let r = go(broken)
        XCTAssertFalse(r.allow)
        XCTAssertTrue(r.reasons.contains("freshness: the revocation epoch pin could not be raised (fail closed)"), "\(r.reasons)")
    }
}
