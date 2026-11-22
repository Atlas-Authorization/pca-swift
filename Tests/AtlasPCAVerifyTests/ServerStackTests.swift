import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The server stack of core pca: the required-check profiles and their default-deny fold, the build-once authorizer, the guard helpers and the
/// key/value backed replay store (through the pca-state conformance profile).
final class ServerStackTests: XCTestCase {
    func testProfiles() {
        XCTAssertEqual(PCA.STATEFUL_REQUIRED_CHECKS.count, 7)
        XCTAssertEqual(Array(PCA.EXECUTION_REQUIRED_CHECKS.suffix(2)), ["params_digest", "policy"])
        XCTAssertEqual(PCA.missingExecutionComponents(audience: "", grant: nil, resolveGrant: nil, state: nil, isRevoked: nil), ["audience", "grant or resolveGrant", "state", "isRevoked"])
        XCTAssertEqual(PCA.missingExecutionComponents(audience: "a", grant: .object([:]), resolveGrant: nil, state: MemoryStateStore(), isRevoked: { _, _ in false }), [])
    }

    func testEnforceRequiredDefaultDeny() {
        let v: JSONValue = .object(["allow": .bool(true), "checks": .object(["audience": .string("pass"), "validity": .string("pass"), "replay": .string("not-enforced"), "x": .string("unsupported")]), "reasons": .array([])])
        let out = PCA.enforceRequired(v, ["audience", "replay", "revocation", "x"])
        XCTAssertEqual(out.get("allow"), .bool(false))
        XCTAssertEqual(out.get("checks")?.get("audience"), .string("pass"))
        XCTAssertEqual(out.get("checks")?.get("replay"), .string("fail"))
        XCTAssertEqual(out.get("checks")?.get("revocation"), .string("fail"))
        XCTAssertEqual(out.get("checks")?.get("x"), .string("fail"))
        let r = out.get("reasons")?.asArray?.compactMap { $0.asString } ?? []
        XCTAssertEqual(r, ["replay: required check is not-enforced (default-deny: not enforced by this resource server)",
                           "revocation: required check is absent (default-deny: not enforced by this resource server)",
                           "x: required check is unsupported (default-deny: not enforced by this resource server)"])
        // nothing required: a non-required unsupported check stays unsupported and the verdict is unchanged
        XCTAssertEqual(PCA.enforceRequired(v, []).get("checks")?.get("x"), .string("unsupported"))
        XCTAssertEqual(PCA.enforceRequired(v, []).get("allow"), .bool(true))
        // the old name of the replay check
        XCTAssertEqual(PCA.enforceRequired(v, ["counter"]).get("allow"), .bool(false))
        XCTAssertEqual(PCA.enforceRequired(v, ["counter"]).get("checks")?.get("replay"), .string("fail"))
        // an already failed check keeps its reason
        let f: JSONValue = .object(["allow": .bool(false), "checks": .object(["audience": .string("fail")]), "reasons": .array([.string("audience: wrong")])])
        XCTAssertEqual(PCA.enforceRequired(f, ["audience"]).get("reasons")?.asArray?.count, 1)
    }

    func testIncompleteAuthorizerRefusesEveryCall() {
        let az = PCA.createAuthorizer(PCA.AuthorizeInput())
        let r = az(nil, nil)
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.missing, ["audience", "resolveGrant", "stateStore", "isRevoked"])
    }

    func testGuardResultHasTheReferenceShape() {
        let esc: JSONValue = .object(["id": .string("r")])
        let deny = PCA.guardResult(.deny(PcaGuardDenial(status: 403, code: "insufficient_authority", wwwAuthenticate: "Bearer error=\"insufficient_authority\"", body: [], decision: "escalate",
                                                         escalation: esc, authorization: nil)))
        XCTAssertEqual(deny.get("ok"), .bool(false))
        XCTAssertEqual(deny.get("decision"), .string("escalate"))
        XCTAssertEqual(deny.get("status"), .int(403))
        XCTAssertEqual(deny.get("escalation"), esc)
        XCTAssertNotNil(deny.get("wwwAuthenticate"))
        let v = PCA.Verdict(allow: true, checks: ["audience": true], reason: "")
        let allow = PCA.guardResult(.allow(PcaGuardAllow(pcactn: .object(["counter": .int(1)]), verdict: v, authorization: nil)))
        XCTAssertEqual(allow.get("ok"), .bool(true))
        XCTAssertEqual(allow.get("decision"), .string("allow"))
        XCTAssertEqual(allow.get("verdict")?.get("checks")?.get("audience"), .bool(true))
        XCTAssertNil(allow.get("status"))
    }

    func testDecisionOfResult() {
        XCTAssertEqual(PCA.decisionOfResult(ok: true, decision: "deny"), "allow")
        XCTAssertEqual(PCA.decisionOfResult(ok: false, decision: "escalate"), "escalate")
        XCTAssertEqual(PCA.decisionOfResult(ok: false), "deny")
    }

    func testStoreShapes() {
        XCTAssertTrue(PCA.isAtomicPcaStateStore(PCA.atomicMemoryPcaStore()))
        XCTAssertTrue(PCA.isAtomicPcaStateStore(PCA.durablePcaStateStore(MemoryAtomicKV())))
        XCTAssertFalse(PCA.isAtomicPcaStateStore(nil))
        XCTAssertEqual(PCA.durablePcaStateStore(MemoryAtomicKV()).scope, .shared)
    }

    func testKvStoreClaimSemantics() throws {
        let kv = MemoryAtomicKV()
        let s = PCA.durablePcaStateStore(kv)
        XCTAssertTrue(try s.claim(key: "g:h", counter: 1).ok)
        XCTAssertEqual(try s.claim(key: "g:h", counter: 1), ClaimResult(ok: false, lastCounter: 1))
        XCTAssertTrue(try s.claim(key: "g:h", counter: 2).ok)
        let b = Risk.Budget(b: 5, tau: 1, asOf: 2)
        XCTAssertEqual(try s.claim(key: "g:h", counter: 3, budgetBefore: b, budgetAfter: b), ClaimResult(ok: false, conflict: true)) // stored budget absent
        XCTAssertTrue(try s.claim(key: "g:h", counter: 3, budgetBefore: nil, budgetAfter: b).ok)
        XCTAssertEqual(try s.budget(key: "g:h"), b)
        XCTAssertEqual(try s.last(key: "g:h"), 3)
        try s.raisePin(key: "g:h", value: 7)
        try s.raisePin(key: "g:h", value: 3)
        XCTAssertEqual(try s.pin(key: "g:h"), 7)
        XCTAssertEqual(kv.get("pca-state:g:h")?.get("lastCounter"), .int(3))
        XCTAssertTrue(try s.consumeOnce(key: "slot", retainUntil: 100, now: 10))
        XCTAssertFalse(try s.consumeOnce(key: "slot", retainUntil: 100, now: 20))
        XCTAssertTrue(try s.consumeOnce(key: "slot", retainUntil: 300, now: 150)) // the first record was past its horizon
        XCTAssertThrowsError(try s.consumeOnce(key: "", retainUntil: 1, now: 0))
    }

    func testKvStorePassesThePcaStateConformance() {
        let kv = MemoryAtomicKV()
        let report = PcaStateConformance(name: "kv", open: { (PCAKVStateStore(kv), {}) }, durable: false, shared: true).run()
        XCTAssertTrue(report.ok, report.description)
    }
}
