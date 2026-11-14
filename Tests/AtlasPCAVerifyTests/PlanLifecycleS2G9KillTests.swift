import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the PlanLifecycle.swift survivors of group 9: the approval number form, the default clock, the stored-root check of `validate`,
/// a failing store, the approval expiry instant and the node digest match of `check`.
final class S2G9PlanLifecycleKillTests: XCTestCase {
    private func node(_ over: JObject = [:]) -> JSONValue {
        var o: JObject = ["id": .string("n1"), "verb": .string("v"), "resource": .string("r")]
        for (k, v) in over { o[k] = v }
        return .object(o)
    }

    func testApprovalJSONWritesIntegersAsIntegers() {
        func json(_ e: Double) -> JSONValue? { PlanApproval(by: "p", expiresAt: e).json.get("expiresAt") }
        XCTAssertEqual(json(5), .int(5), "line 41")
        XCTAssertEqual(json(2.5), .double(2.5), "line 41: a fraction is not whole")
        XCTAssertEqual(json(9_007_199_254_740_991), .int(9_007_199_254_740_991), "line 41: 2^53-1 is whole")
        XCTAssertEqual(json(9_007_199_254_740_992), .double(9_007_199_254_740_992), "line 41: 2^53 is not")
        XCTAssertEqual(PlanApproval(by: "p").json, .object(["by": .string("p")]))
    }

    func testTheDefaultClockIsMilliseconds() throws {
        let reg = PlanRegistry()
        let t = reg.draft(grantRef: "g", nodes: .array([node()]))
        let created = try XCTUnwrap(t.record?.createdAt)
        let real = Int64(Date().timeIntervalSince1970 * 1000)
        XCTAssertLessThan(abs(created - real), 10_000, "line 189: \(created) vs \(real)")
    }

    func testValidateRefusesNodesThatNoLongerHashToTheRoot() throws {
        let kv = MemoryAtomicKV()
        let reg = PlanRegistry(kv: kv)
        let rec = PlanRecord(grantRef: "g", root: "badroot", nodes: [node()], state: .draft, createdAt: 1)
        kv.update("pca-plan:g:badroot") { _ in rec.json }
        let t = reg.validate(grantRef: "g", root: "badroot")
        XCTAssertFalse(t.ok, "line 290")
        XCTAssertEqual(t.reason, "plan badroot is invalid: the stored nodes no longer hash to the root")
        XCTAssertEqual(t.state, .draft)
    }

    struct DownKV: AtomicKV {
        func get(_ key: String) throws -> JSONValue? { throw PCAFailure("down") }
        func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws { throw PCAFailure("down") }
    }

    func testAFailingStoreIsNeverExecutable() {
        let s = PlanRegistry(kv: DownKV()).status(grantRef: "g", root: "r", now: 1)
        XCTAssertFalse(s.executable, "line 338")
        XCTAssertEqual(s.state, .unknown)
        XCTAssertEqual(s.reason, "the plan store failed (fail closed): down")
    }

    private func authorized(_ reg: PlanRegistry, nodes: [JSONValue], expiresAt: Double? = nil) throws -> String {
        let d = reg.draft(grantRef: "g", nodes: .array(nodes))
        let root = try XCTUnwrap(d.record?.root)
        XCTAssertTrue(reg.validate(grantRef: "g", root: root).ok)
        XCTAssertTrue(reg.commit(grantRef: "g", root: root).ok)
        XCTAssertTrue(reg.authorize(grantRef: "g", root: root, approval: PlanApproval(by: "p", expiresAt: expiresAt)).ok)
        return root
    }

    func testTheApprovalExpiresAtItsInstant() throws {
        let reg = PlanRegistry()
        let root = try authorized(reg, nodes: [node()], expiresAt: 1000)
        XCTAssertTrue(reg.status(grantRef: "g", root: root, now: 999).executable)
        let at = reg.status(grantRef: "g", root: root, now: 1000)
        XCTAssertFalse(at.executable, "line 350: the instant of expiry is already expired")
        XCTAssertTrue(at.reason?.contains("approval expired") ?? false, at.reason ?? "")
    }

    func testCheckComparesTheNodesParamsDigest() throws {
        let reg = PlanRegistry()
        let op = PCA.Operation(verb: "v", resource: "r", params: .object([:]))
        let plain = try authorized(reg, nodes: [node()])
        XCTAssertTrue(reg.check(grantRef: "g", root: plain, PlanCheckOptions(operation: op)).executable, "a node without a digest matches empty params")
        // a node whose params_digest is neither a string nor absent never matches (lines 378)
        let reg2 = PlanRegistry()
        let odd = try authorized(reg2, nodes: [node(["params_digest": .int(5)])])
        let r = reg2.check(grantRef: "g", root: odd, PlanCheckOptions(operation: op))
        XCTAssertFalse(r.executable, "line 378")
        XCTAssertTrue(r.reason?.contains("is not what the principal approved") ?? false, r.reason ?? "")
    }
}
