import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the PcaGuard.swift survivors of group 9: the recorded-response status range, the executor-mode `isAuthorized`, the workflow body member,
/// the wiring of the authorize options into `PCA.AuthorizeInput`, the signature-only denials, the wall clock and the executor replies.
final class S2G9PcaGuardKillTests: XCTestCase {
    private func denial(_ d: PcaGuardDecision) -> PcaGuardDenial? {
        if case let .deny(x) = d { return x }
        return nil
    }

    private func realNowSigned() -> AZ.Signed {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let g = AZ.grant(envelope: AZ.envelope())
        let p = AZ.proof(g, params: AuthorizeTests.P50, declared: "irreversible", now: now, aud: AZ.AUD)
        return AZ.Signed(grant: g, pcactn: p, params: AuthorizeTests.P50)
    }

    // ---- small values ----

    func testDefaultsAndDecisionFlags() {
        XCTAssertFalse(PcaAuthorizeConfig().insecureUnboundApproval, "line 68: the insecure opt-out is off by default")
        let d = PcaGuardDecision.deny(PcaGuardDenial(status: 401, code: "c", wwwAuthenticate: "w", body: [], decision: "deny", escalation: nil, authorization: nil))
        XCTAssertFalse(d.allowed, "line 288")
    }

    func testRecordedResponseStatusRange() {
        func from(_ st: Int64) -> PcaRecordedResponse? {
            PcaRecordedResponse.from(.object(["status": .int(st), "headers": .object([:]), "body": .string("")]))
        }
        XCTAssertNil(from(99), "line 170")
        XCTAssertEqual(from(100)?.status, 100, "line 170")
        XCTAssertEqual(from(101)?.status, 101)
        XCTAssertEqual(from(598)?.status, 598)
        XCTAssertEqual(from(599)?.status, 599, "line 170")
        XCTAssertNil(from(600), "line 170")
    }

    func testExecutorModeIsAuthorizedChecksTheOperationItself() {
        let op = PCA.Operation(verb: "payments.send", resource: "payments/acme", params: AuthorizeTests.P50)
        let digest = IV.strictHash(op.params)!
        let b = PCA.AuthorizedOperation(verb: "payments.send", resource: "payments/acme", paramsDigest: digest, id: "i")
        let a = PcaGuardAllow(pcactn: .null, verdict: nil, authorization: nil, idempotencyKey: nil, authorizedOperation: b)
        XCTAssertTrue(a.isAuthorized(for: op))
        XCTAssertFalse(a.isAuthorized(for: PCA.Operation(verb: "payments.refund", resource: "payments/acme", params: AuthorizeTests.P50)))
        XCTAssertFalse(a.isAuthorized(for: PCA.Operation(verb: "payments.send", resource: "payments/other", params: AuthorizeTests.P50)))
        XCTAssertFalse(a.isAuthorized(for: PCA.Operation(verb: "payments.send", resource: "payments/acme", params: AuthorizeTests.P400)))
        XCTAssertFalse(a.isAuthorized(for: PCA.Operation(verb: "", resource: "", params: AuthorizeTests.P50)), "line 252: an invalid operation is never authorized")
        let none = PcaGuardAllow(pcactn: .null, verdict: nil, authorization: nil, idempotencyKey: nil, authorizedOperation: nil)
        XCTAssertFalse(none.isAuthorized(for: op))
    }

    // ---- extraction ----

    func testTheHeaderSizeLimitIsInclusive() throws {
        let g = try PcaGuard(PcaGuardConfig(audience: "a", signatureOnly: true, insecureSkipPlanRootCheck: true))
        func text(_ total: Int) -> String { #"{"a":""# + String(repeating: "a", count: total - 8) + #""}"# }
        let limit = PCA.MAX_ARTIFACT_BYTES
        let atLimit = text(limit)
        XCTAssertEqual(atLimit.utf8.count, limit)
        let ok = denial(g.handle(PcaGuardRequest(method: "POST", path: "/", headers: ["PCA-Action": Base64URLStrict.encode(Array(atLimit.utf8))])))
        XCTAssertEqual(ok?.wwwAuthenticate.contains("PCActn has no grant_ref"), true, "line 336: exactly the limit is read (\(ok?.wwwAuthenticate ?? "nil"))")
        let over = text(limit + 1)
        let no = denial(g.handle(PcaGuardRequest(method: "POST", path: "/", headers: ["PCA-Action": Base64URLStrict.encode(Array(over.utf8))])))
        XCTAssertEqual(no?.wwwAuthenticate.contains("not a valid PCActn JSON object"), true, no?.wwwAuthenticate ?? "nil")
    }

    // ---- the workflow body member (lines 366-378) ----

    private func workflow(_ w: JObject) throws -> PCA.WorkflowCall? {
        let g = try PcaGuard(PcaGuardConfig(audience: "a"))
        let body = Canonical.utf8(Canonical.canonicalize(.object(["workflow": .object(w)])))
        return g.workflowCall(PcaGuardRequest(method: "POST", path: "/", body: body), PcaAuthorizeConfig())
    }

    func testWorkflowBodyMember() throws {
        let base: JObject = ["commitment": .object([:]), "receipts": .array([]), "step": .string("s")]
        func with(_ extra: JObject) -> JObject { base.merging(extra) { $1 } }
        let plain = try XCTUnwrap(workflow(base))
        XCTAssertEqual(plain.step, "s")
        XCTAssertEqual(plain.units, [:])
        XCTAssertNil(plain.goalDigest)
        let full = try XCTUnwrap(workflow(with(["units": .object(["a": .string("b")]), "goal_digest": .string("gd")])))
        XCTAssertEqual(full.step, "s", "a well-formed member is not the refused call (lines 369, 375)")
        XCTAssertEqual(full.units, ["a": "b"], "lines 366, 370")
        XCTAssertEqual(full.goalDigest, "gd", "lines 374, 376")
        let nulls = try XCTUnwrap(workflow(with(["units": .null, "goal_digest": .null])))
        XCTAssertEqual(nulls.step, "s", "line 366: a null member is absent, not malformed")
        XCTAssertEqual(nulls.units, [:])
        XCTAssertNil(nulls.goalDigest)
        XCTAssertEqual(try XCTUnwrap(workflow(with(["units": .int(1)]))).step, "", "units that are not an object are refused")
        XCTAssertEqual(try XCTUnwrap(workflow(with(["units": .object(["a": .int(1)])]))).step, "")
        XCTAssertEqual(try XCTUnwrap(workflow(with(["goal_digest": .int(1)]))).step, "")
    }

    // ---- the wiring into AuthorizeInput (lines 458-482) ----

    func testAuthorizeOptionsReachTheAuthorizeInput() throws {
        let registry = PlanRegistry()
        let policy = RevocationStalenessPolicy(maxRevocationAgeMs: 5)
        var az = PcaAuthorizeConfig()
        az.plan = "context"
        az.escalationRender = { _ in "r" }
        az.revocationStaleness = policy
        az.revocationState = { _, _, _ in nil }
        az.guardianPublic = "gp"
        az.guardianPins = ["a": "b"]
        az.revocationIds = { _, _ in ["x"] }
        az.revocationProof = { _, _, _ in .int(1) }
        az.plans = registry
        az.requireAssurance = AssuranceRequirement()
        az.allowUnsupported = ["bond"]
        az.assuranceHooks.revocation = "h"
        az.undo = { _ in nil }
        let g = try PcaGuard(PcaGuardConfig(audience: "a", intentV2: { _, _ in nil }, authorize: az))
        let input = g.authorizeInput(PcaGuardRequest(method: "POST", path: "/"), 7)
        XCTAssertNil(input.plan, "line 458: plan 'context' means the plan comes from the context")
        XCTAssertEqual(input.escalationRender?(.null), "r", "line 463")
        XCTAssertNotNil(input.intentV2, "line 466")
        XCTAssertEqual(input.revocationStaleness, policy, "line 467")
        XCTAssertEqual(input.guardianPublic, "gp", "line 468")
        XCTAssertEqual(input.guardianPins, ["a": "b"], "line 469")
        XCTAssertNotNil(input.revocationState, "line 470")
        XCTAssertEqual(input.revocationIds?(.null), ["x"], "line 471")
        XCTAssertEqual(input.revocationProof?(.null, "i"), .int(1), "line 472")
        XCTAssertTrue(input.plans === registry, "line 473")
        XCTAssertNotNil(input.requireAssurance, "line 474")
        XCTAssertEqual(input.allowUnsupported, ["bond"], "line 475")
        XCTAssertEqual(input.assuranceHooks.revocation as? String, "h", "line 476")
        XCTAssertNotNil(input.undo, "line 482")
        XCTAssertEqual(input.now, 7)

        var other = PcaAuthorizeConfig()
        other.plan = "p2"
        XCTAssertEqual(try PcaGuard(PcaGuardConfig(audience: "a", authorize: other)).authorizeInput(PcaGuardRequest(method: "POST", path: "/"), 1).plan, "p2")
        XCTAssertEqual(try PcaGuard(PcaGuardConfig(audience: "a", authorize: PcaAuthorizeConfig())).authorizeInput(PcaGuardRequest(method: "POST", path: "/"), 1).plan,
                       nil, "a bare guard configures no plan (it denies plan_root_authorized)")
        var single = PcaAuthorizeConfig()
        single.plan = PCA.SINGLE_STEP
        XCTAssertEqual(try PcaGuard(PcaGuardConfig(audience: "a", authorize: single)).authorizeInput(PcaGuardRequest(method: "POST", path: "/"), 1).plan, PCA.SINGLE_STEP)
        var ctxMode = PcaAuthorizeConfig()
        ctxMode.plan = "context"
        XCTAssertNil(try PcaGuard(PcaGuardConfig(audience: "a", authorize: ctxMode)).authorizeInput(PcaGuardRequest(method: "POST", path: "/"), 1).plan)
    }

    // ---- signature-only denials ----

    private func headerRequest(_ p: JSONValue) -> PcaGuardRequest {
        PcaGuardRequest(method: "POST", path: "/", headers: ["PCA-Action": PcaGuardTests.headerValue(p)])
    }

    func testSignatureOnlyConfigurationDenials() throws {
        let noResolver = try PcaGuard(PcaGuardConfig(audience: "a", signatureOnly: true, insecureSkipPlanRootCheck: true))
        let d1 = try XCTUnwrap(denial(noResolver.handle(headerRequest(.object(["grant_ref": .string("g")])))))
        XCTAssertEqual(d1.status, 401, "line 432")
        XCTAssertEqual(d1.code, "invalid_request")
        XCTAssertTrue(d1.wwwAuthenticate.contains("no grant resolver configured"))
        let d2 = try XCTUnwrap(denial(noResolver.handle(headerRequest(.object(["x": .int(1)])))))
        XCTAssertEqual(d2.status, 401, "line 430")
        XCTAssertTrue(d2.wwwAuthenticate.contains("PCActn has no grant_ref"))
    }

    func testSignatureOnlyCallsTheIntentV2Provider() throws {
        let s = AZ.signed()
        let calls = PcaGuardTests.Calls()
        let g = try PcaGuardTests.guardFor(s) { cfg, _ in
            cfg.signatureOnly = true; cfg.insecureSkipPlanRootCheck = true
            cfg.intentV2 = { _, _ in calls.bump(); return nil }
        }
        XCTAssertTrue(g.handle(PcaGuardTests.request(s)).allowed)
        XCTAssertEqual(calls.count, 1, "line 437: the verifier state is asked for once per request")
        let failing = try PcaGuardTests.guardFor(s) { cfg, _ in
            cfg.signatureOnly = true; cfg.insecureSkipPlanRootCheck = true
            cfg.intentV2 = { _, _ in throw PCAFailure("down") }
        }
        let d = try XCTUnwrap(denial(failing.handle(PcaGuardTests.request(s))))
        XCTAssertEqual(d.status, 403, "line 438")
        XCTAssertEqual(d.code, "verification_error")
        XCTAssertTrue(d.bodyText.contains("intent_v2: verifier state unavailable (fail closed)"))
    }

    func testSignatureOnlyDenialCarriesTheChecks() throws {
        let s = AZ.signed()
        let g = try PcaGuardTests.guardFor(s) { cfg, _ in
            cfg.signatureOnly = true; cfg.insecureSkipPlanRootCheck = true
            cfg.audience = "somebody-else"
        }
        let d = try XCTUnwrap(denial(g.handle(PcaGuardTests.request(s))))
        XCTAssertEqual(d.status, 403)
        XCTAssertNotNil(JSONValue.parse(d.bodyText)?.get("checks"), "line 400: \(d.bodyText)")
    }

    // ---- the wall clock (lines 424, 523) ----

    func testTheDefaultClockIsMilliseconds() throws {
        let s = realNowSigned()
        let g = try PcaGuardTests.guardFor(s) { cfg, _ in
            cfg.signatureOnly = true; cfg.insecureSkipPlanRootCheck = true
            cfg.now = nil
        }
        let a = g.handle(PcaGuardTests.request(s))
        XCTAssertTrue(a.allowed, "line 424: \(denial(a)?.bodyText ?? "")")
    }

    func testTheExecutorsDefaultClockIsMilliseconds() async throws {
        let s = realNowSigned()
        let g = try PcaGuardTests.guardFor(s) { cfg, _ in
            cfg.executor = PcaGuardExecutorConfig(operations: MemoryOperationStore())
            cfg.now = nil
        }
        let r = await g.handle(PcaGuardTests.request(s), run: { _ in PcaRecordedResponse(status: 200, body: Array("ok".utf8)) })
        XCTAssertEqual(r.status, 200, "line 523: \(String(decoding: r.body, as: UTF8.self))")
    }

    // ---- the executor's replies ----

    private func header(_ r: PcaGuardReply, _ name: String) -> [String]? { r.headers.first { $0.key.lowercased() == name.lowercased() }?.value }

    func testExecutorErrorRepliesCarryTheirChallenge() async throws {
        let s = AZ.signed()
        let run: (PcaGuardAllow) async throws -> PcaRecordedResponse = { _ in PcaRecordedResponse(status: 200) }
        // no executor configured: 403 authorize_config WITH a challenge (line 507)
        let plain = try PcaGuardTests.guardFor(s)
        let r = await plain.handle(PcaGuardTests.request(s), run: run)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(header(r, "WWW-Authenticate"), [#"PCA realm="pca", error="authorize_config""#], "line 507")
        // nothing presented: the 401 keeps the described challenge of the fixed denial (line 520)
        let ex = try PcaGuardTests.guardFor(s) { cfg, _ in cfg.executor = PcaGuardExecutorConfig(operations: MemoryOperationStore()) }
        let none = await ex.handle(PcaGuardRequest(method: "POST", path: "/"), run: run)
        XCTAssertEqual(none.status, 401)
        XCTAssertEqual(header(none, "WWW-Authenticate"),
                       [#"PCA realm="pca", error="invalid_request", error_description="no PCActn presented (missing PCA-Action header and request body)""#], "line 520")
    }

    func testExecutorUncertainRecordIs409() async throws {
        let s = AZ.signed()
        let ops = MemoryOperationStore()
        let g = try PcaGuardTests.guardFor(s) { cfg, _ in cfg.executor = PcaGuardExecutorConfig(operations: ops) }
        let first = await g.handle(PcaGuardTests.request(s), run: { _ in PcaRecordedResponse(status: 200) })
        XCTAssertEqual(first.status, 200)
        let id = try XCTUnwrap(IV.strictHash(s.pcactn))
        var rec = try XCTUnwrap(ops.get(id))
        rec.state = .uncertain
        rec.error = "unknown outcome"
        XCTAssertTrue(ops.transition(id, from: .committed, to: rec))
        let again = await g.handle(PcaGuardTests.request(s), run: { _ in PcaRecordedResponse(status: 200) })
        XCTAssertEqual(again.status, 409, "line 546")
        XCTAssertTrue(String(decoding: again.body, as: UTF8.self).contains("operation_uncertain"))
    }
}
