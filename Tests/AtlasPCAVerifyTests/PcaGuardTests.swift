import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The framework-free request guard: header and body transport, 401 vs 403, the default full authorize path (missing configuration is a
/// 403 `authorize_config`, signature-only only by explicit opt-in), the operation handed to the handler, the ternary decision with a signed
/// escalation answer (escalate never allow) and the atomic replay claim.
final class PcaGuardTests: XCTestCase {
    static func headerValue(_ pcactn: JSONValue) -> String { Base64URLStrict.encode(Canonical.utf8(Canonical.canonicalize(pcactn))) }

    static func paramsBody(_ s: AZ.Signed) -> [UInt8] { Canonical.utf8(Canonical.canonicalize(s.params)) }

    static func request(_ s: AZ.Signed, body: [UInt8]? = nil, extra: [String: String] = [:]) -> PcaGuardRequest {
        var h = ["PCA-Action": headerValue(s.pcactn), "Content-Type": "application/json"]
        // provenance by default: the principal-direct bundle of the operation the mapper derives from the body
        if let p = ProvHarness.header(paymentsBody: body ?? paramsBody(s)) { h[PCA.PROV_HEADER] = p }
        for (k, v) in extra { h[k] = v }
        return PcaGuardRequest(method: "POST", path: "/payments", headers: h, body: body ?? paramsBody(s))
    }

    /// Maps the request body to the operation (what the route will run).
    static let mapper: (PcaGuardRequest) throws -> PCA.Operation? = { req in
        guard let params = JSONValue.parse(String(decoding: req.body, as: UTF8.self)) else { return nil }
        return PCA.Operation(verb: "payments.send", resource: "payments/acme", params: params)
    }

    static func guardFor(_ s: AZ.Signed, store: PCAStateStore = MemoryStateStore(), edit: (inout PcaGuardConfig, inout PcaAuthorizeConfig) -> Void = { _, _ in }) throws -> PcaGuard {
        let g = s.grant
        var az = PcaAuthorizeConfig(stateStore: store, isRevoked: { _, _ in false }, operation: mapper)
        az.pinProvHarness()
        var cfg = PcaGuardConfig(audience: AZ.AUD, resolveGrant: { _ in g }, now: { AZ.NOW })
        edit(&cfg, &az)
        if !cfg.signatureOnly { cfg.authorize = az }
        return try PcaGuard(cfg)
    }

    func denial(_ d: PcaGuardDecision, file: StaticString = #filePath, line: UInt = #line) -> PcaGuardDenial? {
        guard case let .deny(x) = d else {
            XCTFail("expected a denial", file: file, line: line)
            return nil
        }
        return x
    }

    func allow(_ d: PcaGuardDecision, file: StaticString = #filePath, line: UInt = #line) -> PcaGuardAllow? {
        guard case let .allow(x) = d else {
            XCTFail("expected an allow, got \(String(describing: denial(d)?.bodyText))", file: file, line: line)
            return nil
        }
        return x
    }

    func testAllowsAndHandsTheBoundOperationToTheHandler() throws {
        let s = AZ.signed()
        let g = try Self.guardFor(s)
        let a = try XCTUnwrap(allow(g.handle(Self.request(s))))
        XCTAssertEqual(a.authorization?.decision, "allow")
        XCTAssertEqual(a.operation?.verb, "payments.send")
        XCTAssertEqual(a.operation?.resource, "payments/acme")
        XCTAssertTrue(a.verdict?.allow ?? false)
        XCTAssertEqual(a.pcactn, s.pcactn)
        XCTAssertTrue(a.isAuthorized(for: PCA.Operation(verb: "payments.send", resource: "payments/acme", params: s.params)))
        XCTAssertFalse(a.isAuthorized(for: PCA.Operation(verb: "payments.send", resource: "payments/acme", params: AuthorizeTests.P400)))
        XCTAssertFalse(a.isAuthorized(for: PCA.Operation(verb: "payments.refund", resource: "payments/acme", params: s.params)))
    }

    func testBodyTransport() throws {
        let s = AZ.signed()
        let g = try Self.guardFor(s) { _, az in az.operation = { _ in PCA.Operation(verb: "payments.send", resource: "payments/acme", params: s.params) } }
        let op = PCA.Operation(verb: "payments.send", resource: "payments/acme", params: s.params)
        let body = Canonical.utf8(Canonical.canonicalize(.object(["pcactn": s.pcactn, "pca_provenance": try XCTUnwrap(ProvHarness.bundle(op))])))
        let r = PcaGuardRequest(method: "POST", path: "/payments", body: body)
        XCTAssertNotNil(allow(g.handle(r)))
    }

    func testMissingConfigurationIsAuthorizeConfig403() throws {
        let s = AZ.signed()
        // no authorize options at all
        let none = try PcaGuard(PcaGuardConfig(audience: AZ.AUD, resolveGrant: { _ in s.grant }, now: { AZ.NOW }))
        let d1 = try XCTUnwrap(denial(none.handle(Self.request(s))))
        XCTAssertEqual(d1.status, 403)
        let b1 = JSONValue.parse(d1.bodyText)
        XCTAssertTrue(b1?.get("reason")?.asString?.hasPrefix("authorize_config: missing required component(s): ") ?? false, d1.bodyText)
        XCTAssertEqual(b1?.get("missing")?.asArray?.compactMap { $0.asString }, ["stateStore", "isRevoked"])
        XCTAssertEqual(b1?.get("checks")?.get("authorize_config")?.asString, "fail")
        // a store but no revocation check, and no operation mapper
        let partial = try PcaGuard(PcaGuardConfig(audience: AZ.AUD, resolveGrant: { _ in s.grant }, now: { AZ.NOW },
                                                  authorize: PcaAuthorizeConfig(stateStore: MemoryStateStore())))
        let d2 = try XCTUnwrap(denial(partial.handle(Self.request(s))))
        XCTAssertEqual(d2.status, 403)
        XCTAssertEqual(JSONValue.parse(d2.bodyText)?.get("missing")?.asArray?.compactMap { $0.asString }, ["isRevoked"])
        // nothing presented is still the 401 (the configuration is judged once a PCActn is there)
        let d3 = try XCTUnwrap(denial(none.handle(PcaGuardRequest(method: "GET", path: "/"))))
        XCTAssertEqual(d3.status, 401)
    }

    func testNoOrUndecodableProofIs401() throws {
        let s = AZ.signed()
        let g = try Self.guardFor(s)
        let none = try XCTUnwrap(denial(g.handle(PcaGuardRequest(method: "POST", path: "/"))))
        XCTAssertEqual(none.status, 401)
        XCTAssertEqual(none.code, "invalid_request")
        XCTAssertEqual(none.wwwAuthenticate, "PCA realm=\"pca\", error=\"invalid_request\", error_description=\"no PCActn presented (missing PCA-Action header and request body)\"")
        let good = Self.headerValue(s.pcactn)
        let arr = Base64URLStrict.encode(Canonical.utf8("[1]"))
        let text = Base64URLStrict.encode(Canonical.utf8("not json"))
        for (name, h) in ["padded": good + "=", "standard alphabet": good.replacingOccurrences(of: "-", with: "+") + "+", "whitespace": " " + good,
                          "not json": text, "array": arr, "not base64": "!!!"] {
            let d = try XCTUnwrap(denial(g.handle(PcaGuardRequest(method: "POST", path: "/", headers: ["pca-action": h], body: Self.paramsBody(s)))), name)
            XCTAssertEqual(d.status, 401, name)
            XCTAssertEqual(d.code, "invalid_request", name)
        }
        // a body that is not {"pcactn": object}
        for (name, b) in ["not json": "x", "array": "[]", "no member": "{}", "not an object": "{\"pcactn\":1}"] {
            let d = try XCTUnwrap(denial(g.handle(PcaGuardRequest(method: "POST", path: "/", body: Canonical.utf8(b)))), name)
            XCTAssertEqual(d.status, 401, name)
        }
        // a header always wins over a body
        let hb = PcaGuardRequest(method: "POST", path: "/", headers: ["PCA-Action": "!!!"], body: Canonical.utf8(Canonical.canonicalize(.object(["pcactn": s.pcactn]))))
        XCTAssertEqual(denial(g.handle(hb))?.status, 401)
    }

    func testUnknownGrantIs401() throws {
        let s = AZ.signed()
        let g = try Self.guardFor(s) { cfg, _ in cfg.resolveGrant = { _ in nil } }
        let d = try XCTUnwrap(denial(g.handle(Self.request(s))))
        XCTAssertEqual(d.status, 401)
        XCTAssertEqual(d.code, "invalid_pcactn")
        // a resolver that throws is a denial too, never an allow
        let t = try Self.guardFor(s) { cfg, _ in cfg.resolveGrant = { _ in throw PCAFailure("db down") } }
        XCTAssertEqual(denial(t.handle(Self.request(s)))?.status, 403)
    }

    func testPolicyFailureIs403AndDoesNotConsumeTheCounter() throws {
        let s = AZ.signed() // signed for a 50 payment
        let store = MemoryStateStore()
        let g = try Self.guardFor(s, store: store)
        // the handler would execute a 400 payment: the proof is for 50
        let bad = try XCTUnwrap(denial(g.handle(Self.request(s, body: Canonical.utf8(Canonical.canonicalize(AuthorizeTests.P400))))))
        XCTAssertEqual(bad.status, 403)
        XCTAssertEqual(bad.code, "insufficient_authority")
        XCTAssertEqual(bad.decision, "deny")
        XCTAssertTrue(bad.authorization?.failedChecks.contains("operation") ?? false)
        XCTAssertNotNil(allow(g.handle(Self.request(s))), "the refusal must leave the replay counter untouched")
        // the same PCActn again: replayed
        let again = try XCTUnwrap(denial(g.handle(Self.request(s))))
        XCTAssertEqual(again.status, 403)
        XCTAssertEqual(again.authorization?.checks["replay"], .fail)
    }

    func testOperationMapperFailuresDeny() throws {
        let s = AZ.signed()
        for (name, m) in [("throws", { (_: PcaGuardRequest) throws -> PCA.Operation? in throw PCAFailure("x") }),
                          ("nil", { (_: PcaGuardRequest) throws -> PCA.Operation? in nil })] {
            let g = try Self.guardFor(s) { _, az in az.operation = m }
            let d = try XCTUnwrap(denial(g.handle(Self.request(s))), name)
            XCTAssertEqual(d.status, 403, name)
            XCTAssertTrue(d.authorization?.reason?.hasPrefix("operation: ") ?? false, name)
        }
        // a body over the limit is never given to the mapper
        let g = try Self.guardFor(s)
        let big = PcaGuardRequest(method: "POST", path: "/", headers: ["PCA-Action": Self.headerValue(s.pcactn)], body: Self.paramsBody(s), bodyComplete: false)
        XCTAssertEqual(denial(g.handle(big))?.status, 403)
        // no mapper at all
        let nm = try Self.guardFor(s) { _, az in az.operation = nil }
        XCTAssertEqual(denial(nm.handle(Self.request(s)))?.status, 403)
    }

    func testSignatureOnlyIsAnExplicitOptIn() throws {
        let s = AZ.signed()
        let g = try Self.guardFor(s) { cfg, _ in cfg.signatureOnly = true }
        let a = try XCTUnwrap(allow(g.handle(Self.request(s))))
        XCTAssertNil(a.authorization, "signature-only binds no operation")
        XCTAssertNil(a.operation)
        XCTAssertTrue(a.verdict?.allow ?? false)
        XCTAssertNotNil(allow(g.handle(Self.request(s))), "signature-only does not enforce the replay counter")
        let wrongAud = try Self.guardFor(s) { cfg, _ in
            cfg.signatureOnly = true
            cfg.audience = "somebody-else"
        }
        XCTAssertEqual(denial(wrongAud.handle(Self.request(s)))?.status, 403)
        let unknown = try Self.guardFor(s) { cfg, _ in
            cfg.signatureOnly = true
            cfg.resolveGrant = { _ in nil }
        }
        XCTAssertEqual(denial(unknown.handle(Self.request(s)))?.status, 401)
        // both is a configuration error
        var cfg = PcaGuardConfig(audience: "a", signatureOnly: true, authorize: PcaAuthorizeConfig())
        XCTAssertThrowsError(try PcaGuard(cfg))
        cfg.authorize = nil
        XCTAssertNoThrow(try PcaGuard(cfg))
        // escalation principals need a store that reports the history head
        struct BareStore: PCAStateStore {
            func claim(key: String, counter: Int64) throws -> ClaimResult { ClaimResult(ok: true) }
        }
        let esc = PcaGuardConfig(audience: "a", authorize: PcaAuthorizeConfig(stateStore: BareStore(), escalationPrincipals: [PinnedSigner(V2F.pub(V2F.principal))]))
        XCTAssertThrowsError(try PcaGuard(esc))
    }

    func testRequestDerivedTextNeverReachesTheChallengeHeader() throws {
        let s = AZ.signed()
        let g = try Self.guardFor(s)
        let d = try XCTUnwrap(denial(g.handle(Self.request(s, body: Canonical.utf8(Canonical.canonicalize(AuthorizeTests.P400))))))
        XCTAssertEqual(d.wwwAuthenticate, "PCA realm=\"pca\", error=\"insufficient_authority\"")
        let body = JSONValue.parse(d.bodyText)
        XCTAssertNotNil(body?.get("reason")?.asString)
        XCTAssertFalse(d.wwwAuthenticate.contains(body?.get("reason")?.asString ?? "\u{0}"))
        XCTAssertEqual(d.contentType, "application/json")
    }

    func testEscalateIsNeverAnAllowAndOnlyASignedAnswerAdmits() throws {
        let s = EscalationTests.signed()
        let v2: (PcaGuardRequest, JSONValue) throws -> IntentV2Context? = { _, _ in IntentV2Context(.object([:])) }
        let plain = try Self.guardFor(s) { cfg, _ in cfg.intentV2 = v2 }
        let d = try XCTUnwrap(denial(plain.handle(Self.request(s))))
        XCTAssertEqual(d.status, 403)
        XCTAssertEqual(d.decision, "escalate")
        XCTAssertEqual(d.escalation?.get("kind")?.asString, "pca-escalation-request")
        let body = JSONValue.parse(d.bodyText)
        XCTAssertEqual(body?.get("decision")?.asString, "escalate")
        XCTAssertEqual(body?.get("escalation")?.get("kind")?.asString, "pca-escalation-request")
        // an answer is ignored unless its principal is pinned
        let answer = Self.headerValue(EscalationTests.answer(s))
        let unpinned = try Self.guardFor(s) { cfg, _ in cfg.intentV2 = v2 }
        XCTAssertEqual(denial(unpinned.handle(Self.request(s, extra: [PcaGuard.ESCALATION_HEADER: answer])))?.decision, "escalate")
        // pinned: the answer admits, once
        let store = MemoryStateStore()
        let pinned = try Self.guardFor(s, store: store) { cfg, az in
            cfg.intentV2 = v2
            az.escalationPrincipals = EscalationTests.pin
            az.insecureUnboundApproval = true
        }
        let a = try XCTUnwrap(allow(pinned.handle(Self.request(s, extra: [PcaGuard.ESCALATION_HEADER: answer]))))
        XCTAssertEqual(a.authorization?.escalation?.get("answered_by")?.asString, V2F.pub(V2F.principal))
        let replay = try XCTUnwrap(denial(pinned.handle(Self.request(s, extra: [PcaGuard.ESCALATION_HEADER: answer]))))
        XCTAssertEqual(replay.status, 403)
        // the answer in the body member escalation_answer works too
        let bodyAnswer = Canonical.utf8(Canonical.canonicalize(.object(["amount": .int(50), "currency": .string("usd"), "escalation_answer": EscalationTests.answer(s)])))
        let viaBody = try Self.guardFor(s) { cfg, az in
            cfg.intentV2 = v2
            az.escalationPrincipals = EscalationTests.pin
            az.insecureUnboundApproval = true
            az.operation = { _ in PCA.Operation(verb: "payments.send", resource: "payments/acme", params: s.params) }
        }
        let prov = try XCTUnwrap(ProvHarness.header(PCA.Operation(verb: "payments.send", resource: "payments/acme", params: s.params)))
        XCTAssertNotNil(allow(viaBody.handle(Self.request(s, body: bodyAnswer, extra: [PCA.PROV_HEADER: prov]))))
    }

    func testExecutionStatusMapping() {
        func o(_ s: ExecuteStatus) -> ExecuteOutcome { ExecuteOutcome(s, id: "x", reason: "r") }
        XCTAssertEqual(PcaGuard.operationStatus(o(.committed)), 200)
        XCTAssertEqual(PcaGuard.operationStatus(o(.failed)), 500)
        XCTAssertEqual(PcaGuard.operationStatus(o(.pending)), 409)
        XCTAssertEqual(PcaGuard.operationStatus(o(.uncertain)), 409)
        XCTAssertEqual(PcaGuard.operationStatus(o(.aborted)), 403)
        XCTAssertEqual(PcaGuard.operationStatus(o(.refused)), 403)
        XCTAssertEqual(PcaGuard.operationStatus(o(.denied)), 403)
        XCTAssertEqual(PcaGuard.operationBody(ExecuteOutcome.refused("why")), #"{"reason":"why","status":"refused"}"#)
    }

    // ---- the handler runs inside the executor ----

    final class Calls: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        var count: Int { lock.lock(); defer { lock.unlock() }; return n }
        func bump() { lock.lock(); n += 1; lock.unlock() }
    }

    static func executingGuard(_ s: AZ.Signed, _ ops: MemoryOperationStore, recheck: ((ExecutionHandle) async throws -> RecheckResult)? = nil,
                               recheckFor: String? = nil) throws -> PcaGuard {
        try guardFor(s) { cfg, _ in cfg.executor = PcaGuardExecutorConfig(operations: ops, recheck: recheck, recheckFor: recheckFor) }
    }

    func header(_ r: PcaGuardReply, _ name: String) -> String? { r.headers.first { $0.key.lowercased() == name.lowercased() }?.value.first }
    func text(_ r: PcaGuardReply) -> String { String(decoding: r.body, as: UTF8.self) }

    func testExecutorRunsTheHandlerOnceAndAnswersARetryFromTheRecord() async throws {
        let s = AZ.signed()
        let g = try Self.executingGuard(s, MemoryOperationStore())
        XCTAssertTrue(g.executes)
        let calls = Calls()
        let run: (PcaGuardAllow) async throws -> PcaRecordedResponse = { allow in
            calls.bump()
            XCTAssertEqual(allow.operation?.verb, "payments.send")
            XCTAssertEqual(allow.idempotencyKey, allow.operation?.id)
            XCTAssertTrue(allow.isAuthorized(for: PCA.Operation(verb: "payments.send", resource: "payments/acme", params: s.params)))
            XCTAssertFalse(allow.isAuthorized(for: PCA.Operation(verb: "payments.send", resource: "payments/acme", params: AuthorizeTests.P400)))
            return PcaRecordedResponse(status: 201, headers: ["X-Receipt": ["r1"], "Content-Length": ["4"]], body: Array("sent".utf8))
        }
        let first = await g.handle(Self.request(s), run: run)
        XCTAssertEqual(first.status, 201)
        XCTAssertEqual(text(first), "sent")
        XCTAssertEqual(header(first, "X-Receipt"), "r1")
        XCTAssertNil(header(first, "PCA-Replayed"))
        let again = await g.handle(Self.request(s), run: run)
        XCTAssertEqual(again.status, 201)
        XCTAssertEqual(text(again), "sent")
        XCTAssertEqual(header(again, "X-Receipt"), "r1")
        XCTAssertNil(header(again, "Content-Length"), "a length header is not recorded")
        XCTAssertEqual(header(again, "PCA-Replayed"), "true")
        XCTAssertEqual(calls.count, 1, "the handler ran more than once")
    }

    func testExecutorDeniesWithoutRunningTheHandler() async throws {
        let s = AZ.signed()
        let g = try Self.executingGuard(s, MemoryOperationStore())
        let calls = Calls()
        let run: (PcaGuardAllow) async throws -> PcaRecordedResponse = { _ in calls.bump(); return PcaRecordedResponse(status: 200) }
        let none = await g.handle(PcaGuardRequest(method: "POST", path: "/payments", body: Self.paramsBody(s)), run: run)
        XCTAssertEqual(none.status, 401)
        XCTAssertNotNil(header(none, "WWW-Authenticate"))
        // a proof for another operation: 403, and it consumed nothing
        let wrong = await g.handle(Self.request(s, body: Canonical.utf8(Canonical.canonicalize(AuthorizeTests.P400))), run: run)
        XCTAssertEqual(wrong.status, 403)
        XCTAssertTrue(text(wrong).contains("operation"), text(wrong))
        XCTAssertEqual(calls.count, 0)
        // the executor needs the authorize path and a store
        XCTAssertThrowsError(try PcaGuard(PcaGuardConfig(audience: "a", signatureOnly: true, executor: PcaGuardExecutorConfig(operations: MemoryOperationStore()))))
        XCTAssertThrowsError(try PcaGuard(PcaGuardConfig(audience: "a", executor: PcaGuardExecutorConfig(operations: MemoryOperationStore()))))
        let noStore = try Self.guardFor(s) { cfg, _ in cfg.executor = PcaGuardExecutorConfig(operations: nil) }
        let refused = await noStore.handle(Self.request(s), run: run)
        XCTAssertEqual(refused.status, 403)
        XCTAssertEqual(calls.count, 0)
        // without an executor the replying entry point refuses
        let plain = try Self.guardFor(s)
        XCTAssertFalse(plain.executes)
        let r = await plain.handle(Self.request(s), run: run)
        XCTAssertEqual(r.status, 403)
        XCTAssertTrue(text(r).contains("authorize_config"), text(r))
    }

    func testExecutorHandlerFailureIs500WithoutTheErrorText() async throws {
        let s = AZ.signed()
        let g = try Self.executingGuard(s, MemoryOperationStore())
        struct Boom: Error, CustomStringConvertible { var description: String { "secret-detail-7731" } }
        let r = await g.handle(Self.request(s), run: { _ in throw Boom() })
        XCTAssertEqual(r.status, 500)
        XCTAssertTrue(text(r).contains("operation_failed"), text(r))
        XCTAssertFalse(text(r).contains("secret-detail-7731"), "the handler's error text leaked")
        XCTAssertNil(header(r, "WWW-Authenticate"))
    }

    func testExecutorInFlightIs409AndTheHandlerDoesNotRunAgain() async throws {
        let s = AZ.signed()
        let g = try Self.executingGuard(s, MemoryOperationStore())
        let calls = Calls()
        var inner: PcaGuardReply?
        let outer = await g.handle(Self.request(s), run: { _ in
            calls.bump()
            inner = await g.handle(Self.request(s), run: { _ in calls.bump(); return PcaRecordedResponse(status: 200) }) // while the first is in flight
            return PcaRecordedResponse(status: 200, body: Array("ok".utf8))
        })
        XCTAssertEqual(outer.status, 200)
        XCTAssertEqual(inner?.status, 409)
        XCTAssertTrue(inner.map(text)?.contains("operation_in_progress") ?? false, inner.map(text) ?? "nil")
        XCTAssertEqual(calls.count, 1)
    }

    func testExecutorRefusedRecheckIs403OperationAborted() async throws {
        let s = AZ.signed()
        let calls = Calls()
        let g = try Self.executingGuard(s, MemoryOperationStore(), recheck: { _ in .refuse("approval withdrawn") }, recheckFor: "always")
        let r = await g.handle(Self.request(s), run: { _ in calls.bump(); return PcaRecordedResponse(status: 200) })
        XCTAssertEqual(r.status, 403)
        XCTAssertTrue(text(r).contains("operation_aborted"), text(r))
        XCTAssertEqual(calls.count, 0)
    }

    func testExecutorAnUnreadableRecordIs409OperationUncertain() async throws {
        let s = AZ.signed()
        let ops = MemoryOperationStore()
        let g = try Self.executingGuard(s, ops)
        let first = await g.handle(Self.request(s), run: { _ in PcaRecordedResponse(status: 200) })
        XCTAssertEqual(first.status, 200)
        let id = try XCTUnwrap(IV.strictHash(s.pcactn))
        var rec = try XCTUnwrap(ops.get(id))
        rec.result = .string("not a recorded response")
        XCTAssertTrue(ops.transition(id, from: .committed, to: rec))
        let again = await g.handle(Self.request(s), run: { _ in PcaRecordedResponse(status: 200) })
        XCTAssertEqual(again.status, 409)
        XCTAssertTrue(text(again).contains("operation_uncertain"), text(again))
    }
}
