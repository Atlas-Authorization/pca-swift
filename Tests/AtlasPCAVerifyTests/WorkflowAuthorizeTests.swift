import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Workflow admission inside `PCA.authorize` (K5, C-308): replays packages/pca/conformance/authorize-workflow-fixtures.json. Each case threads
/// its steps through ONE replay store; a missing fixture file FAILS (load throws).
final class WorkflowAuthorizeTests: XCTestCase {
    func testSharedFixtures() throws {
        let F = try ConformanceTests.load("authorize-workflow-fixtures.json")
        XCTAssertEqual(F.get("format")?.asString, "pca-authorize-workflow-fixtures/1")
        let cases = F.get("cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 14)
        let grant = F.get("grant") ?? .null
        let gid = grant.get("id")?.asString ?? ""
        let plan = F.get("plan")?.asArray
        XCTAssertNotNil(plan)
        let now = F.get("now")?.safeInt ?? -1
        var bad: [String] = []
        var steps = 0
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let store = MemoryStateStore()
            let required = c.get("required") == .bool(true)
            for (i, s) in (c.get("steps")?.asArray ?? []).enumerated() {
                steps += 1
                var inp = PCA.AuthorizeInput(
                    operation: AuthorizeTests.op(s.get("operation")), audience: F.get("audience")?.asString,
                    resolveGrant: { ref in ref == gid ? grant : nil }, stateStore: store, isRevoked: { _, _ in false }, now: now,
                    context: { _ in PCA.AuthorizeContext(plan: plan, planAuthorized: true) })
                inp.workflow = PCA.WorkflowGate(principal: F.get("principal")?.asString ?? "", rsSigner: F.get("rs_signer")?.asString ?? "", required: required)
                if let w = s.get("workflow"), !w.isNull {
                    var units: [String: String] = [:]
                    for (k, v) in w.get("units")?.asObject ?? [:] { units[k.s] = v.asString ?? "" }
                    inp.workflowStep = PCA.WorkflowCall(commitment: w.get("commitment") ?? .null, receipts: w.get("receipts") ?? .null,
                                                        step: w.get("step")?.asString ?? "", units: units, goalDigest: w.get("goal_digest")?.asString)
                }
                let r = PCA.authorize(pcactn: s.get("pcactn"), inp.withProv())
                let e = s.get("expect")
                let wantFailed = (e?.get("failed")?.asArray ?? []).compactMap { $0.asString }
                let got = "allow=\(r.allow) decision=\(r.decision) status=\(r.status) failed=\(r.failedChecks)"
                let want = "allow=\(e?.get("allow") == .bool(true)) decision=\(e?.get("decision")?.asString ?? "?") status=\(e?.get("status")?.safeInt ?? 0) failed=\(wantFailed)"
                if got != want { bad.append("\(name)[\(i)]: got \(got) want \(want)") }
                if let why = e?.get("reason")?.asString, !(r.reason ?? "").contains(why) { bad.append("\(name)[\(i)]: reason \(r.reason ?? "nil") lacks \(why)") }
            }
        }
        XCTAssertGreaterThanOrEqual(steps, 14)
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    /// An admitted principal-signed workflow step makes the CHOICE the principal's (principal_control), not the values: without a
    /// bundle the step still escalates, on its arguments only.
    func testAnAdmittedStepTrustsTheChoiceNotTheValues() throws {
        let F = try ConformanceTests.load("authorize-workflow-fixtures.json")
        let grant = F.get("grant") ?? .null
        let c = try XCTUnwrap(F.get("cases")?.asArray?.first { $0.get("name")?.asString == "pay-after-quote" })
        let s = try XCTUnwrap(c.get("steps")?.asArray?[1])
        let w = try XCTUnwrap(s.get("workflow"))
        var units: [String: String] = [:]
        for (k, v) in w.get("units")?.asObject ?? [:] { units[k.s] = v.asString ?? "" }
        func run(_ withStep: Bool, prov: Bool) -> PCA.AuthorizeResult {
            var inp = PCA.AuthorizeInput(
                operation: AuthorizeTests.op(s.get("operation")), audience: F.get("audience")?.asString, resolveGrant: { _ in grant },
                stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: F.get("now")?.safeInt,
                context: { _ in PCA.AuthorizeContext(plan: F.get("plan")?.asArray, planAuthorized: true) })
            if withStep {
                inp.workflow = PCA.WorkflowGate(principal: F.get("principal")?.asString ?? "", rsSigner: F.get("rs_signer")?.asString ?? "")
                inp.workflowStep = PCA.WorkflowCall(commitment: w.get("commitment") ?? .null, receipts: w.get("receipts") ?? .null,
                                                    step: w.get("step")?.asString ?? "", units: units, goalDigest: w.get("goal_digest")?.asString)
            }
            return PCA.authorize(pcactn: s.get("pcactn"), prov ? inp.withProv() : inp)
        }
        XCTAssertTrue(run(true, prov: true).allow)
        let step = run(true, prov: false)
        XCTAssertEqual(step.decision, "escalate")
        XCTAssertFalse(step.reason?.contains("the choice of") ?? true, step.reason ?? "nil")
        XCTAssertTrue(step.reason?.hasPrefix("provenance_flow: escalate: amount, order derive from untrusted content") ?? false, step.reason ?? "nil")
        // the same call as a standalone (no workflow step): the choice is untrusted too
        let standalone = run(false, prov: false)
        XCTAssertTrue(standalone.reason?.contains("the choice of payments.refund derives from untrusted content") ?? false, standalone.reason ?? "nil")
    }

    /// Hostile gate input never traps: a bad commitment / receipts / step is a 403 `workflow` refusal.
    func testHostileWorkflowCallIsRefused() throws {
        let F = try ConformanceTests.load("authorize-workflow-fixtures.json")
        let grant = F.get("grant") ?? .null
        let first = F.get("cases")?.asArray?.first?.get("steps")?.asArray?.first
        let hostile: [JSONValue] = [.null, .int(1), .string("x"), .array([]), .object([:])]
        for h in hostile {
            var inp = PCA.AuthorizeInput(operation: AuthorizeTests.op(first?.get("operation")), audience: F.get("audience")?.asString,
                                         resolveGrant: { _ in grant }, stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: F.get("now")?.safeInt)
            inp.workflow = PCA.WorkflowGate(principal: F.get("principal")?.asString ?? "", rsSigner: F.get("rs_signer")?.asString ?? "")
            inp.workflowStep = PCA.WorkflowCall(commitment: h, receipts: h, step: "quote")
            let r = PCA.authorize(pcactn: first?.get("pcactn"), inp.withProv())
            XCTAssertFalse(r.allow)
            XCTAssertEqual(r.status, 403)
            XCTAssertEqual(r.failedChecks, ["workflow"])
        }
    }
}

/// The workflow option through `PcaGuard` (what the Vapor and Hummingbird middlewares wrap): the step comes from the config callback, else
/// the JSON body member `workflow`. Built from the first cases of authorize-workflow-fixtures.json.
final class WorkflowGuardTests: XCTestCase {
    private func fixture() throws -> JSONValue { try ConformanceTests.load("authorize-workflow-fixtures.json") }

    private func guardFor(_ F: JSONValue, _ s: JSONValue, required: Bool, withGate: Bool = true,
                          step: ((PcaGuardRequest) -> PCA.WorkflowCall?)? = nil) throws -> PcaGuard {
        let grant = F.get("grant") ?? .null
        let gid = grant.get("id")?.asString ?? ""
        let plan = F.get("plan")?.asArray
        let op = AuthorizeTests.op(s.get("operation"))
        var az = PcaAuthorizeConfig(stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, plan: "context",
                                    context: { _, _ in PCA.AuthorizeContext(plan: plan, planAuthorized: true) }, operation: { _ in op })
        if withGate {
            az.workflow = PCA.WorkflowGate(principal: F.get("principal")?.asString ?? "", rsSigner: F.get("rs_signer")?.asString ?? "", required: required)
        }
        az.workflowStep = step
        az.pinProvHarness()
        let now = F.get("now")?.safeInt ?? 0
        var cfg = PcaGuardConfig(audience: F.get("audience")?.asString ?? "", resolveGrant: { ref in ref == gid ? grant : nil }, now: { now })
        cfg.authorize = az
        return try PcaGuard(cfg)
    }

    private func body(_ s: JSONValue, workflow: Bool) -> [UInt8] {
        var o: JObject = ["pcactn": s.get("pcactn") ?? .null]
        if workflow, let w = s.get("workflow") { o["workflow"] = w }
        if let op = AuthorizeTests.op(s.get("operation")), let b = ProvHarness.bundle(op) { o["pca_provenance"] = b }
        return Canonical.utf8(Canonical.canonicalize(.object(o)))
    }

    private func step(_ F: JSONValue, _ name: String, _ i: Int = 0) throws -> JSONValue {
        let c = try XCTUnwrap(F.get("cases")?.asArray?.first { $0.get("name")?.asString == name })
        return try XCTUnwrap(c.get("steps")?.asArray?[i])
    }

    private func reason(_ d: PcaGuardDecision) -> (Int, String)? {
        guard case let .deny(x) = d else { return nil }
        return (x.status, JSONValue.parse(x.bodyText)?.get("reason")?.asString ?? "")
    }

    func testValidStepFromBodyPasses() throws {
        let F = try fixture()
        let s = try step(F, "pay-after-quote", 1) // the pay step; the quote step's receipt is in its workflow member
        let g = try guardFor(F, s, required: false)
        guard case .allow = g.handle(PcaGuardRequest(method: "POST", path: "/x", body: body(s, workflow: true))) else { return XCTFail("expected allow") }
    }

    func testStepViolatingAnEdgeIs403() throws {
        let F = try fixture()
        let s = try step(F, "amount-over-the-quote")
        let g = try guardFor(F, s, required: false)
        let got = reason(g.handle(PcaGuardRequest(method: "POST", path: "/x", body: body(s, workflow: true))))
        XCTAssertEqual(got?.0, 403)
        XCTAssertEqual(got?.1, "workflow: edge_relation (step pay)")
    }

    func testRequiredAndAbsentIs403() throws {
        let F = try fixture()
        let s = try step(F, "workflow-required-but-absent")
        let g = try guardFor(F, s, required: true)
        let got = reason(g.handle(PcaGuardRequest(method: "POST", path: "/x", body: body(s, workflow: false))))
        XCTAssertEqual(got?.0, 403)
        XCTAssertEqual(got?.1, "workflow: this call carries no workflow step (fail closed)")
    }

    func testNoWorkflowOptionIgnoresTheBodyMember() throws {
        let F = try fixture()
        let s = try step(F, "amount-over-the-quote") // would be refused with the gate on
        let g = try guardFor(F, s, required: false, withGate: false)
        XCTAssertFalse(reason(g.handle(PcaGuardRequest(method: "POST", path: "/x", body: body(s, workflow: true))))?.1.hasPrefix("workflow") ?? false)
    }

    func testCallbackWinsOverTheBody() throws {
        let F = try fixture()
        let s = try step(F, "amount-over-the-quote")
        // the callback says "no step"; not required -> standalone (no workflow refusal), required -> refused, whatever the body carries
        let g = try guardFor(F, s, required: false, step: { _ in nil })
        XCTAssertFalse(reason(g.handle(PcaGuardRequest(method: "POST", path: "/x", body: body(s, workflow: true))))?.1.hasPrefix("workflow") ?? false)
        let req = try guardFor(F, s, required: true, step: { _ in nil })
        XCTAssertEqual(reason(req.handle(PcaGuardRequest(method: "POST", path: "/x", body: body(s, workflow: true))))?.1,
                       "workflow: this call carries no workflow step (fail closed)")
    }

    func testMalformedBodyMemberIsRefusedNotIgnored() throws {
        let F = try fixture()
        let s = try step(F, "pay-after-quote")
        let g = try guardFor(F, s, required: false)
        for bad: JSONValue in [.null, .int(1), .string("x"), .object([:]), .object(["commitment": .null, "receipts": .null, "step": .int(1)])] {
            let o: JSONValue = .object(["pcactn": s.get("pcactn") ?? .null, "workflow": bad])
            let got = reason(g.handle(PcaGuardRequest(method: "POST", path: "/x", body: Canonical.utf8(Canonical.canonicalize(o)))))
            XCTAssertEqual(got?.0, 403)
            XCTAssertTrue(got?.1.hasPrefix("workflow: ") ?? false, "\(String(describing: got))")
        }
    }
}
