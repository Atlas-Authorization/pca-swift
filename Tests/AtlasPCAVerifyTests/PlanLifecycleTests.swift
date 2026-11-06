import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A settable clock for the registry under test.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var t: Int64
    init(_ t: Int64) { self.t = t }
    var now: Int64 {
        get { lock.lock(); defer { lock.unlock() }; return t }
        set { lock.lock(); defer { lock.unlock() }; t = newValue }
    }
}

/// Plan lifecycle (T10): replays plan-vectors.json scenario by scenario (the roots are Merkle roots of the plan-node leaves, so this proves
/// the commitment equals the reference's), then one-winner concurrency, the `authorize` wiring and the executor.
final class PlanLifecycleTests: XCTestCase {
    func approval(_ v: JSONValue?) -> PlanApproval? {
        guard case let .object(o)? = v else { return nil }
        var a = PlanApproval(by: o["by"]?.asString ?? "")
        if let e = o["expiresAt"] { a.expiresAt = IV.num(e) ?? .nan }
        return a
    }

    func runStep(_ reg: PlanRegistry, _ clock: TestClock, _ s: JSONValue) -> JSONValue {
        let at = s.get("at")?.safeInt ?? 0
        clock.now = at
        let g = s.get("grant")?.asString ?? ""
        let root = s.get("root")?.asString ?? ""
        switch s.get("op")?.asString {
        case "draft"?: return reg.draft(grantRef: g, nodes: s.get("nodes") ?? .null).json
        case "validate"?: return reg.validate(grantRef: g, root: root).json
        case "commit"?: return reg.commit(grantRef: g, root: root).json
        case "authorize"?: return reg.authorize(grantRef: g, root: root, approval: approval(s.get("approval"))).json
        case "revoke"?: return reg.revoke(grantRef: g, root: root, reason: s.get("reason")?.asString ?? "").json
        case "status"?: return reg.status(grantRef: g, root: root, now: at).json
        case "check"?:
            var o = PlanCheckOptions(nodeId: s.get("node_id")?.asString, now: at)
            if let op = s.get("operation") {
                o.operation = PCA.Operation(verb: op.get("verb")?.asString ?? "", resource: op.get("resource")?.asString ?? "", params: op.get("params") ?? .object([:]))
            }
            return reg.check(grantRef: g, root: root, o).json
        case "is_plan_authorized"?: return .bool(reg.isPlanAuthorized(grantRef: g, planRoot: root))
        case "context"?: return reg.context(grantRef: g, root: root, now: at)?.json ?? .null
        default:
            XCTFail("unknown op \(String(describing: s.get("op")))")
            return .null
        }
    }

    func testPlanVectors() throws {
        let doc = try ConformanceTests.load("plan-vectors.json")
        let scenarios = doc.get("scenarios")?.asArray ?? []
        XCTAssertEqual(scenarios.count, 12)
        for sc in scenarios {
            let name = sc.get("name")?.asString ?? "?"
            let clock = TestClock(0)
            var validator: ((PlanRecord) throws -> PlanValidation)?
            switch sc.get("validator")?.asString {
            case "accept"?: validator = { _ in .accept }
            case "refuse"?: validator = { _ in .refuse("node outside the grant") }
            case "throw"?: validator = { _ in throw PCAFailure("policy down") }
            default: break
            }
            let reg = PlanRegistry(now: { clock.now }, validator: validator)
            let steps = sc.get("steps")?.asArray ?? []
            let expect = sc.get("expect")?.asArray ?? []
            XCTAssertEqual(steps.count, expect.count, name)
            for (i, st) in steps.enumerated() where i < expect.count {
                XCTAssertEqual(Canonical.canonicalize(runStep(reg, clock, st)), Canonical.canonicalize(expect[i]),
                               "\(name) step \(i) (\(st.get("op")?.asString ?? "?"))")
            }
        }
    }

    static let NODE: JSONValue = .object(["id": .string("n1"), "verb": .string("v"), "resource": .string("/r")])

    // Of N concurrent claims of one transition exactly one succeeds.
    func testOneWinnerPerTransition() async throws {
        let reg = PlanRegistry()
        let d = reg.draft(grantRef: "g", nodes: .array([Self.NODE]))
        let root = try XCTUnwrap(d.record?.root)
        XCTAssertTrue(reg.validate(grantRef: "g", root: root).ok)
        let wins = CallCounter()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<64 {
                group.addTask { if reg.commit(grantRef: "g", root: root).ok { wins.increment() } }
            }
        }
        XCTAssertEqual(wins.value, 1, "commit won more than once")
        let auth = CallCounter()
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<64 {
                group.addTask { if reg.authorize(grantRef: "g", root: root, approval: PlanApproval(by: "p\(i)")).ok { auth.increment() } }
            }
        }
        XCTAssertEqual(auth.value, 1, "authorize won more than once")
        XCTAssertTrue(reg.isPlanAuthorized(grantRef: "g", planRoot: root))
        // concurrent drafts of one plan: one creates it
        let drafts = CallCounter()
        let reg2 = PlanRegistry()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<64 {
                group.addTask { if reg2.draft(grantRef: "g", nodes: .array([Self.NODE])).ok { drafts.increment() } }
            }
        }
        XCTAssertEqual(drafts.value, 1)
    }

    func testTamperedStoreIsNotExecutable() throws {
        let kv = MemoryAtomicKV()
        let reg = PlanRegistry(kv: kv)
        let root = try XCTUnwrap(reg.draft(grantRef: "g", nodes: .array([Self.NODE])).record?.root)
        _ = reg.validate(grantRef: "g", root: root)
        _ = reg.commit(grantRef: "g", root: root)
        XCTAssertTrue(reg.authorize(grantRef: "g", root: root, approval: PlanApproval(by: "p")).ok)
        XCTAssertTrue(reg.isPlanAuthorized(grantRef: "g", planRoot: root))
        // swap a stored node under the registry: the nodes no longer hash to the root
        let key = "pca-plan:g:" + root
        var rec = try XCTUnwrap(try reg.get(grantRef: "g", root: root))
        rec.nodes = [.object(["id": .string("n1"), "verb": .string("v"), "resource": .string("/other")])]
        kv.update(key) { _ in rec.json }
        let st = reg.status(grantRef: "g", root: root)
        XCTAssertFalse(st.executable)
        XCTAssertEqual(st.reason, "plan \(root): the stored nodes no longer hash to the root")
        XCTAssertFalse(reg.isPlanAuthorized(grantRef: "g", planRoot: root))
    }

    // ---- the authorize wiring ----

    /// Case 0 of the authorize fixtures, without the single-step mode: the plan comes from the registry.
    func authorizeWithPlans(_ reg: PlanRegistry, prov: Bool = true, _ edit: (inout PCA.AuthorizeInput) -> Void = { _ in }) throws -> (PCA.AuthorizeResult, String, String) {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let s = try XCTUnwrap(c.get("steps")?.asArray?.first)
        let g = try XCTUnwrap(c.get("grant"))
        let p = try XCTUnwrap(s.get("pcactn"))
        let ref = try XCTUnwrap(p.get("grant_ref")?.asString)
        var input = PCA.AuthorizeInput(operation: AuthorizeTests.op(s.get("operation")), audience: AuthorizeTests.AUD, resolveGrant: { _ in g },
                                       stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: AuthorizeTests.NOW)
        input.plans = reg
        edit(&input)
        return (PCA.authorize(pcactn: p, prov ? input.withProv() : input), ref, try XCTUnwrap(p.get("plan")?.get("root")?.asString))
    }

    func fixtureNode() throws -> JSONValue {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let p = try XCTUnwrap(c.get("steps")?.asArray?.first?.get("pcactn"))
        let a = try XCTUnwrap(p.get("action"))
        return .object(["id": try XCTUnwrap(p.get("plan")?.get("node_id")), "verb": try XCTUnwrap(a.get("verb")), "resource": try XCTUnwrap(a.get("resource")),
                        "params_digest": try XCTUnwrap(a.get("params_digest")), "reversibility_class": try XCTUnwrap(a.get("reversibility_class"))])
    }

    func testAuthorizePlansUnknownThenAuthorized() throws {
        let reg = PlanRegistry()
        let (unknown, ref, root) = try authorizeWithPlans(reg)
        XCTAssertFalse(unknown.allow)
        XCTAssertEqual(unknown.checks["plan_state"], .fail)
        XCTAssertTrue(unknown.reasons.contains("plan_state: plan \(root) is unknown to the plan registry"), "\(unknown.reasons)")
        // the registry's commitment equals the one the PCActn signed
        let d = reg.draft(grantRef: ref, nodes: .array([try fixtureNode()]))
        XCTAssertEqual(d.record?.root, root)
        XCTAssertTrue(reg.validate(grantRef: ref, root: root).ok)
        XCTAssertTrue(reg.commit(grantRef: ref, root: root).ok)
        let (committed, _, _) = try authorizeWithPlans(reg)
        XCTAssertFalse(committed.allow)
        XCTAssertTrue(committed.reasons.contains("plan_state: plan \(root) is committed but not authorized by the principal"), "\(committed.reasons)")
        XCTAssertTrue(reg.authorize(grantRef: ref, root: root, approval: PlanApproval(by: "principal")).ok)
        let (ok, _, _) = try authorizeWithPlans(reg)
        XCTAssertTrue(ok.allow, "\(ok.reasons)")
        XCTAssertEqual(ok.checks["plan_state"], .pass)
        XCTAssertEqual(ok.checks["plan_root_authorized"], .pass)
        // provenance: an executable plan the principal authorized in the registry is the principal's own choice and values, so no
        // bundle is needed (principal_plan)
        let (bare, _, _) = try authorizeWithPlans(reg, prov: false)
        XCTAssertTrue(bare.allow, "\(bare.reasons)")
        XCTAssertEqual(bare.checks["provenance_flow"], .pass)
    }

    /// Only the registry makes a principal plan: the single-step mode (the plan is whatever the proof carries) does not, so without a
    /// bundle the same call escalates.
    func testTheSingleStepModeIsNotAPrincipalPlan() throws {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let s = try XCTUnwrap(c.get("steps")?.asArray?.first)
        let g = try XCTUnwrap(c.get("grant"))
        let p = try XCTUnwrap(s.get("pcactn"))
        let input = PCA.AuthorizeInput(operation: AuthorizeTests.op(s.get("operation")), audience: AuthorizeTests.AUD, resolveGrant: { _ in g },
                                       stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: AuthorizeTests.NOW, plan: PCA.SINGLE_STEP)
        let r = PCA.authorize(pcactn: p, input)
        XCTAssertEqual(r.decision, "escalate")
        XCTAssertEqual(r.failedChecks, ["provenance_flow"])
    }

    // ---- the executor ----

    func executor(revokedAfter: Int?) throws -> (PCAExecutor, JSONValue, PCA.Operation) {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let s = try XCTUnwrap(c.get("steps")?.asArray?.first)
        let g = try XCTUnwrap(c.get("grant"))
        let calls = CallCounter()
        let revoked: (JSONValue, JSONValue) throws -> Bool? = { _, _ in
            calls.increment()
            guard let n = revokedAfter else { return false }
            return calls.value > n
        }
        let op = try XCTUnwrap(AuthorizeTests.op(s.get("operation")))
        // the executor sets the operation per run; the bundle is the principal-direct one of this operation
        let input = PCA.AuthorizeInput(audience: AuthorizeTests.AUD, resolveGrant: { _ in g }, stateStore: MemoryStateStore(), isRevoked: revoked,
                                       now: AuthorizeTests.NOW, plan: PCA.SINGLE_STEP, argProvenance: ArgProvenanceOptions(mediators: [ProvHarness.pin]),
                                       provenance: ProvHarness.bundle(op))
        let ex = PCAExecutor(ExecutorOptions(operations: MemoryOperationStore(), authorize: input, now: { AuthorizeTests.NOW }))
        return (ex, try XCTUnwrap(s.get("pcactn")), op)
    }

    func testExecutorRunsOnceAndAnswersRetryFromRecord() async throws {
        let (ex, pcactn, op) = try executor(revokedAfter: nil)
        let calls = CallCounter()
        let first = await ex.run(pcactn: pcactn, operation: op) { h in calls.increment(); return .string("sent:" + String(h.idempotencyKey.prefix(4))) }
        XCTAssertEqual(first.execution.status, .committed, "\(String(describing: first.authorization?.reasons))")
        XCTAssertFalse(first.execution.replayed)
        XCTAssertEqual(calls.value, 1)
        let retry = await ex.run(pcactn: pcactn, operation: op) { _ in calls.increment(); return nil }
        XCTAssertEqual(retry.execution.status, .committed)
        XCTAssertTrue(retry.execution.replayed, "a retry must be answered from the record")
        XCTAssertEqual(retry.execution.result, first.execution.result)
        XCTAssertEqual(calls.value, 1)
        // the same proof for a DIFFERENT operation is a plain denial, never the record
        let other = PCA.Operation(verb: op.verb, resource: op.resource, params: .object(["amount": .int(999)]))
        let o = await ex.run(pcactn: pcactn, operation: other) { _ in calls.increment(); return nil }
        XCTAssertEqual(o.execution.status, .denied)
        XCTAssertNotNil(o.authorization)
        XCTAssertEqual(calls.value, 1)
    }

    func testExecutorRecheckSeesRevocationAfterAuthorize() async throws {
        let (ex, pcactn, op) = try executor(revokedAfter: 1) // authorize sees "not revoked", the pre-execution re-check sees "revoked"
        let ran = CallCounter()
        let o = await ex.run(pcactn: pcactn, operation: op) { _ in ran.increment(); return nil }
        XCTAssertEqual(o.execution.status, .aborted)
        XCTAssertEqual(o.execution.reason, "recheck: the grant has been revoked")
        XCTAssertEqual(ran.value, 0)
        // revoked now: the retry is a plain denial (a revocation failure, not only a replay)
        let again = await ex.run(pcactn: pcactn, operation: op) { _ in ran.increment(); return nil }
        XCTAssertEqual(again.execution.status, .denied)
        XCTAssertEqual(ran.value, 0)
    }

    func testExecutorWithoutOperationsRefuses() async throws {
        let (_, pcactn, op) = try executor(revokedAfter: nil)
        let input = PCA.AuthorizeInput(audience: "x", resolveGrant: { _ in nil }, stateStore: MemoryStateStore(), isRevoked: { _, _ in false })
        let ex = PCAExecutor(ExecutorOptions(operations: nil, authorize: input))
        let o = await ex.run(pcactn: pcactn, operation: op) { _ in nil }
        XCTAssertEqual(o.execution.status, .refused)
    }
}
