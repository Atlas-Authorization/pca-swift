import XCTest
import Foundation
@testable import AtlasPCAVerify

/// PcaGuard.swift: configuration defaults and the hand-over of every authorize option into `PCA.AuthorizeInput`.
final class PcaGuardSurvivorKillTests: XCTestCase {
    func testConfigurationDefaults() {
        XCTAssertTrue(PcaAuthorizeConfig().seedBudget, "a stream with no budget is seeded unless the host opts out")
        let c = PcaGuardConfig(audience: "a")
        XCTAssertFalse(c.insecureSkipPlanRootCheck, "the plan-root opt-out is off unless asked for")
        XCTAssertNil(c.authorizedPlanRoots)
    }

    func testEveryAuthorizeOptionReachesTheInput() throws {
        let key = try PCAEdKey(seed: [UInt8](repeating: 4, count: 32))
        let contract = try Contracts.signContract(
            try XCTUnwrap(JSONValue.parse(#"{"version":1,"principal":"\#(key.id)","clauses":[{"id":"no-del","kind":"never","p":{"verb":"delete"}}]}"#)), principal: key)
        let enforcer = try ContractEnforcer.open(kv: MemoryAtomicKV(), contract: contract, principal: key.id)

        var az = PcaAuthorizeConfig()
        az.pqPins = ["issuer": "pk"]
        az.riskSource = { _, _, _ in nil }
        az.thresholdHook = { _ in PCA.ThresholdOutcome(enforced: true, ok: true, t: 2) }
        az.requireRiskInputs = ["taint"]
        az.adaptivePolicy = { _ in .int(5) }
        az.seedBudget = false
        az.requirePassport = PCA.RequirePassport(trustedIssuers: ["x"])
        az.passport = { r in .string("passport:" + r.path) }
        az.forbid = PCA.ForbidGate(clauses: { _, _ in .array([]) }, precedence: ["p"])
        az.forbidCertificate = { r in .string("cert:" + r.path) }
        az.requireLinkedTemplate = PCA.LinkedTemplateGate(registry: JSONValue.null)
        az.contracts = enforcer
        az.enforceFreshness = PCA.FreshnessGate(maxAgeMs: 5)
        az.enforceTaint = PCA.TaintGate(registry: EmptyTrustedInputRegistry(), maxTaint: 0.5)
        az.beacon = { _, _ in nil }
        az.resolvePrincipal = { _, _ in PCA.PrincipalInfo(pub: "p", subjectType: "user", subjectId: nil, verified: true) }
        az.requireVerifiedPrincipal = true

        let g = try PcaGuard(PcaGuardConfig(audience: "a", authorize: az))
        let input = g.authorizeInput(PcaGuardRequest(method: "POST", path: "/p"), 7)

        XCTAssertEqual(input.pqPins, ["issuer": "pk"])
        XCTAssertNotNil(input.riskSource)
        XCTAssertEqual(try input.thresholdHook?(.null), PCA.ThresholdOutcome(enforced: true, ok: true, t: 2))
        XCTAssertEqual(input.requireRiskInputs, ["taint"])
        XCTAssertEqual(try input.adaptivePolicy?(1), .int(5))
        XCTAssertFalse(input.seedBudget)
        XCTAssertEqual(input.requirePassport?.trustedIssuers, ["x"])
        XCTAssertEqual(input.passport, .string("passport:/p"), "the passport is read from this request")
        XCTAssertEqual(input.forbid?.precedence, ["p"])
        XCTAssertEqual(input.forbidCertificate, .string("cert:/p"), "the certificate is read from this request")
        XCTAssertNotNil(input.requireLinkedTemplate)
        XCTAssertTrue(input.contracts === enforcer)
        XCTAssertEqual(input.enforceFreshness?.maxAgeMs, 5)
        XCTAssertEqual(input.enforceTaint?.maxTaint, 0.5)
        XCTAssertNotNil(input.beacon)
        XCTAssertEqual(try input.resolvePrincipal?("i", .null)?.pub, "p")
        XCTAssertTrue(input.requireVerifiedPrincipal)
    }

    func testTheDefaultsReachTheInputUnchanged() throws {
        let g = try PcaGuard(PcaGuardConfig(audience: "a", authorize: PcaAuthorizeConfig()))
        let input = g.authorizeInput(PcaGuardRequest(method: "POST", path: "/"), 1)
        XCTAssertTrue(input.seedBudget)
        XCTAssertNil(input.passport)
        XCTAssertNil(input.forbidCertificate)
        XCTAssertNil(input.contracts)
        XCTAssertFalse(input.requireVerifiedPrincipal)
        XCTAssertEqual(input.requireRiskInputs, [])
    }
}
