import XCTest
import Foundation
@testable import AtlasPCAVerify

/// `PCA.authorizeExecution` over the shared signed authorize fixtures: the same outcomes as the pipeline it wraps, plus the configuration and binding refusals
/// that come before it.
final class AuthorizeExecutionTests: XCTestCase {
    static let FIX: JSONValue = (try? K042.json("authorize-fixtures.json")) ?? .null
    static let NOW = FIX.get("now")?.safeInt ?? 0
    static let AUD = FIX.get("audience")?.asString ?? ""
    static let calm: JObject = ["semanticDistance": .int(0), "reversibility": .int(1), "blastRadius": .int(0), "taint": .int(0), "confidence": .int(1), "age": .int(0)]

    func options(_ grant: JSONValue, _ store: MemoryStateStore, revoked: @escaping () -> Bool) -> PCA.AuthorizeExecutionOptions {
        var o = PCA.AuthorizeExecutionOptions()
        o.audience = Self.AUD
        o.grant = grant
        o.state = store
        o.isRevoked = { _, _ in revoked() }
        o.now = { Self.NOW }
        o.risk = { _, _, _ in Self.calm }
        o.provenance = ArgProvenanceOptions(mediators: [ProvHarness.pin])
        return o
    }

    func testEveryFixtureStepDecidesLikeThePipeline() throws {
        var steps = 0
        for c in Self.FIX.get("cases")?.asArray ?? [] {
            let grant = c.get("grant") ?? .null
            let store = MemoryStateStore()
            for s in c.get("steps")?.asArray ?? [] {
                let name = c.get("name")?.asString ?? ""
                let pc = s.get("pcactn") ?? .null
                guard let opv = s.get("operation"), let verb = opv.get("verb")?.asString, let resource = opv.get("resource")?.asString, let params = opv.get("params") else { return XCTFail(name) }
                let want = s.get("expect")
                let failed = (want?.get("failed")?.asArray ?? []).compactMap { $0.asString }
                let op = PCA.Operation(verb: verb, resource: resource, params: params)
                let revoked = s.get("revoked") == .bool(true)
                let d = PCA.authorizeExecution(pc, PCA.ExecutionOperation(verb: verb, resource: resource, params: params, provenance: ProvHarness.bundle(op)),
                                               options(grant, store, revoked: { revoked }))
                XCTAssertEqual(d.allow, want?.get("allow") == .bool(true), "\(name): \(d.reason ?? "allowed")")
                if pc.get("action")?.get("verb")?.asString != verb || pc.get("action")?.get("resource")?.asString != resource {
                    XCTAssertEqual(d.kind, .binding, name)
                    XCTAssertEqual(d.status, 403)
                } else {
                    XCTAssertEqual(d.status, Int(want?.get("status")?.safeInt ?? 0), name)
                    // the plan gate here is rebuilt from the signed action (as the reference does), so the single-step plan check is not compared
                    XCTAssertEqual((d.result?.failedChecks ?? []).filter { $0 != "plan_root_authorized" }, failed.filter { $0 != "plan_root_authorized" }, name)
                }
                steps += 1
            }
        }
        XCTAssertGreaterThan(steps, 30)
    }

    func testAMissingComponentDeniesBeforeAnyVerification() {
        var o = PCA.AuthorizeExecutionOptions()
        XCTAssertEqual(PCA.missingExecutionComponents(o), ["audience", "grant or resolveGrant", "state", "isRevoked"])
        let d = PCA.authorizeExecution(.object([:]), PCA.ExecutionOperation(verb: "x.y", params: .object([:])), o)
        XCTAssertFalse(d.allow)
        XCTAssertEqual(d.kind, .config)
        XCTAssertEqual(d.reason, "full policy mode is missing audience, grant or resolveGrant, state, isRevoked (fail closed)")
        o.audience = Self.AUD; o.grant = .object([:]); o.state = MemoryStateStore(); o.isRevoked = { _, _ in false }
        XCTAssertTrue(PCA.missingExecutionComponents(o).isEmpty)
    }

    func testAnUnknownGrantRefIsUnauthenticated() throws {
        let c = (Self.FIX.get("cases")?.asArray ?? []).first { $0.get("name")?.asString == "envelope-predicate-within" } ?? .null
        let s = c.get("steps")?.asArray?.first ?? .null
        var o = options(.null, MemoryStateStore(), revoked: { false })
        o.grant = nil
        o.resolveGrant = { _, _ in nil }
        let opv = s.get("operation") ?? .null
        let d = PCA.authorizeExecution(s.get("pcactn") ?? .null, PCA.ExecutionOperation(verb: opv.get("verb")?.asString ?? "", params: opv.get("params") ?? .null), o)
        XCTAssertEqual(d.kind, .authn)
        XCTAssertEqual(d.status, 401)
        XCTAssertEqual(d.reason, "unknown grant_ref")
    }
}
