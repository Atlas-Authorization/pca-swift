import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The executor's clock, timeout and pre-execution re-check, against packages/pca/src/server/operations.ts.
final class ExecutorK05Tests: XCTestCase {
    private struct K05Boom: Error {}

    private struct Fixture {
        let grant: JSONValue, pcactn: JSONValue, op: PCA.Operation
        var ref: String { pcactn.get("grant_ref")?.asString ?? "" }
        var root: String { pcactn.get("plan")?.get("root")?.asString ?? "" }

        func input(isRevoked: @escaping (JSONValue, JSONValue) throws -> Bool? = { _, _ in false }, now: Int64? = AuthorizeTests.NOW,
                   plan: String? = PCA.SINGLE_STEP) -> PCA.AuthorizeInput {
            let g = grant
            return PCA.AuthorizeInput(audience: AuthorizeTests.AUD, resolveGrant: { _ in g }, stateStore: MemoryStateStore(), isRevoked: isRevoked, now: now, plan: plan,
                                      argProvenance: ArgProvenanceOptions(mediators: [ProvHarness.pin]), provenance: ProvHarness.bundle(op))
        }
        /// The plan the proof signed, authorized by the principal.
        func registry() throws -> PlanRegistry {
            let a = try XCTUnwrap(pcactn.get("action"))
            let node: JSONValue = .object(["id": try XCTUnwrap(pcactn.get("plan")?.get("node_id")), "verb": try XCTUnwrap(a.get("verb")), "resource": try XCTUnwrap(a.get("resource")),
                                           "params_digest": try XCTUnwrap(a.get("params_digest")), "reversibility_class": try XCTUnwrap(a.get("reversibility_class"))])
            let reg = PlanRegistry()
            XCTAssertEqual(reg.draft(grantRef: ref, nodes: .array([node])).record?.root, root)
            XCTAssertTrue(reg.validate(grantRef: ref, root: root).ok)
            XCTAssertTrue(reg.commit(grantRef: ref, root: root).ok)
            XCTAssertTrue(reg.authorize(grantRef: ref, root: root, approval: PlanApproval(by: "principal")).ok)
            return reg
        }
    }

    private func fixture() throws -> Fixture {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let s = try XCTUnwrap(c.get("steps")?.asArray?.first)
        return Fixture(grant: try XCTUnwrap(c.get("grant")), pcactn: try XCTUnwrap(s.get("pcactn")), op: try XCTUnwrap(AuthorizeTests.op(s.get("operation"))))
    }

    private func executor(_ input: PCA.AuthorizeInput, now: (() -> Int64)? = { AuthorizeTests.NOW }) -> PCAExecutor {
        PCAExecutor(ExecutorOptions(operations: MemoryOperationStore(), authorize: input, now: now))
    }

    func testOptionDefaultsAndTimeout() throws {
        let f = try fixture()
        let unset = ExecutorOptions(operations: nil, authorize: f.input())
        XCTAssertNil(unset.pendingTimeoutMs)
        XCTAssertEqual(PCAExecutor(unset).timeout, PCA.OPERATION_PENDING_TIMEOUT_MS)
        XCTAssertEqual(PCAExecutor(ExecutorOptions(operations: nil, authorize: f.input(), pendingTimeoutMs: 1)).timeout, 1)
        XCTAssertEqual(PCAExecutor(ExecutorOptions(operations: nil, authorize: f.input(), pendingTimeoutMs: 0)).timeout, 0) // operations.ts:403: 0 is zero, only unset is the default
    }

    func testTheDefaultClockIsTheWallClockInMilliseconds() throws {
        let c = PCAExecutor(ExecutorOptions(operations: nil, authorize: try fixture().input())).clock()
        let wall = Int64(Date().timeIntervalSince1970 * 1000)
        XCTAssertLessThan(abs(c - wall), 60_000)
    }

    func testRecheckRefusesWhenRevocationCannotBeRead() async throws {
        let f = try fixture()
        for behaviour in ["nil", "throw"] {
            let calls = CallCounter()
            let ex = executor(f.input(isRevoked: { _, _ in
                calls.increment()
                if calls.value == 1 { return false }
                if behaviour == "throw" { throw K05Boom() }
                return nil
            }))
            let ran = CallCounter()
            let o = await ex.run(pcactn: f.pcactn, operation: f.op) { _ in ran.increment(); return nil }
            XCTAssertEqual(o.execution.status, .aborted, behaviour)
            XCTAssertEqual(o.execution.reason, "recheck: revocation could not be checked", behaviour)
            XCTAssertEqual(ran.value, 0, behaviour)
        }
    }

    func testAPlanTheRegistryDoesNotKnowIsNotRechecked() async throws {
        let f = try fixture()
        var input = f.input()
        input.plans = PlanRegistry()
        let o = await executor(input).run(pcactn: f.pcactn, operation: f.op) { _ in .string("done") }
        XCTAssertEqual(o.execution.status, .committed, "\(String(describing: o.execution.reason)) \(String(describing: o.authorization?.reasons))")
    }

    func testAnExecutableRegisteredPlanPassesTheRecheck() async throws {
        let f = try fixture()
        var input = f.input(plan: nil)
        input.plans = try f.registry()
        let o = await executor(input).run(pcactn: f.pcactn, operation: f.op) { _ in .string("done") }
        XCTAssertEqual(o.execution.status, .committed, "\(String(describing: o.execution.reason)) \(String(describing: o.authorization?.reasons))")
    }

    func testAPlanRevokedAfterAuthorizeStopsTheExecution() async throws {
        let f = try fixture()
        let reg = try f.registry()
        let calls = CallCounter()
        let ref = f.ref, root = f.root
        var input = f.input(isRevoked: { _, _ in
            calls.increment()
            if calls.value == 2 { _ = reg.revoke(grantRef: ref, root: root, reason: "r") }
            return false
        }, plan: nil)
        input.plans = reg
        let ran = CallCounter()
        let o = await executor(input).run(pcactn: f.pcactn, operation: f.op) { _ in ran.increment(); return nil }
        XCTAssertEqual(o.execution.status, .aborted, "\(String(describing: o.authorization?.reasons))")
        XCTAssertEqual(o.execution.reason, "recheck: plan \(root) is revoked (r)")
        XCTAssertEqual(ran.value, 0)
    }

    func testAuthorizeNowWinsForTheAuthorization() async throws {
        let f = try fixture()
        let text = try XCTUnwrap(IV.strictCanon(f.pcactn))
        let later: () -> Int64 = { AuthorizeTests.NOW + 100_000_000 }
        // the authorization is judged at authorize.now (allowed); the pre-execution re-check on the executor's clock finds the proof expired
        let a = await executor(f.input(), now: later).run(pcactn: f.pcactn, operation: f.op) { _ in nil }
        XCTAssertEqual(a.execution.status, .aborted, "\(String(describing: a.authorization?.reasons))")
        XCTAssertTrue(a.execution.reason?.hasPrefix("recheck: the PCActn expired") ?? false, "\(String(describing: a.execution.reason))")
        let b = await executor(f.input(), now: later).run(json: text, operation: f.op) { _ in nil }
        XCTAssertEqual(b.execution.status, .aborted, "\(String(describing: b.authorization?.reasons))")
        XCTAssertTrue(b.execution.reason?.hasPrefix("recheck: the PCActn expired") ?? false, "\(String(describing: b.execution.reason))")
    }

    func testTheExecutorClockFillsAMissingAuthorizeNow() async throws {
        let f = try fixture()
        let text = try XCTUnwrap(IV.strictCanon(f.pcactn))
        let a = await executor(f.input(now: nil)).run(pcactn: f.pcactn, operation: f.op) { _ in .string("done") }
        XCTAssertEqual(a.execution.status, .committed, "\(String(describing: a.authorization?.reasons))")
        let b = await executor(f.input(now: nil)).run(json: text, operation: f.op) { _ in .string("done") }
        XCTAssertEqual(b.execution.status, .committed, "\(String(describing: b.authorization?.reasons))")
    }

    func testJsonRunNeedsTheRecordStore() async throws {
        let f = try fixture()
        let ex = PCAExecutor(ExecutorOptions(operations: nil, authorize: f.input()))
        let o = await ex.run(json: "{}", operation: f.op) { _ in nil }
        XCTAssertEqual(o.execution.status, .refused)
        XCTAssertEqual(o.execution.reason, "PCAExecutor: missing required component: operations (fail closed)")
    }
}
