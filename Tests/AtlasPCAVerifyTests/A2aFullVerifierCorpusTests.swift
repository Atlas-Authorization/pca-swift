import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The A2A default full verifier (`A2a.CORE_VERIFIER`) over real signed proofs: every step of the shared authorize fixtures (signed grants and PCActns from
/// the reference) goes through the A2A path (`attachPcaToA2ATask` then `verifyA2ATask`). The checks the core verifier evaluates (params digest, plan root,
/// revocation, audience, signatures, validity) must agree with the fixture's recorded outcome; the checks it does not evaluate (envelope policy, delegated
/// caveats, replay, attestation) must not be invented here.
final class A2aFullVerifierCorpusTests: XCTestCase {
    static let FIX: JSONValue = (try? K042.json("authorize-fixtures.json")) ?? .null
    static let CORE = ["params_digest", "plan_root_authorized", "revocation", "audience"]

    func verify(_ grant: JSONValue, _ step: JSONValue, tweak: (inout JObject) -> Void = { _ in }) throws -> A2a.Verification {
        let failed = (step.get("expect")?.get("failed")?.asArray ?? []).compactMap { $0.asString }
        let revoked = step.get("revoked") == .bool(true)
        let params = step.get("operation")?.get("params") ?? .null
        var o = A2a.VerifyOptions(aud: Self.FIX.get("audience")?.asString, now: Self.FIX.get("now")?.safeInt, grant: grant.asObject)
        o.context = { _ in ["params": params, "planAuthorized": .bool(!failed.contains("plan_root_authorized"))] }
        o.isRevoked = { _, _ in revoked }
        var p = step.get("pcactn")?.asObject ?? [:]
        tweak(&p)
        return try A2a.verifyA2ATask(A2a.attachPcaToA2ATask(.object(["id": .string("t1")]), .object(p)), o)
    }

    func testEveryFixtureStepIsDecidedByTheRealCoreVerifier() throws {
        var steps = 0
        for c in Self.FIX.get("cases")?.asArray ?? [] {
            let grant = c.get("grant") ?? .null
            for s in c.get("steps")?.asArray ?? [] {
                let failed = (s.get("expect")?.get("failed")?.asArray ?? []).compactMap { $0.asString }
                let wantAllow = Set(failed).isDisjoint(with: Self.CORE)
                let v = try verify(grant, s)
                XCTAssertEqual(v.ok, wantAllow, "\(c.get("name")?.asString ?? ""): \(v.reason ?? "allowed"); fixture failed \(failed)")
                let checks = v.result?[JKey("checks")]?.asObject ?? [:]
                for name in ["params_digest", "revocation", "audience"] where failed.contains(name) { XCTAssertEqual(checks[JKey(name)], .string("fail"), "\(name) in \(c.get("name")?.asString ?? "")") }
                if wantAllow { XCTAssertEqual(checks[JKey("revocation")], .string("pass")); XCTAssertEqual(checks[JKey("params_digest")], .string("pass")) }
                steps += 1
            }
        }
        XCTAssertGreaterThan(steps, 30)
    }

    func testATamperedProofIsRefusedAndRevocationIsRequired() throws {
        let c = (Self.FIX.get("cases")?.asArray ?? []).first { $0.get("name")?.asString == "envelope-predicate-within" } ?? .null
        let grant = c.get("grant") ?? .null
        let step = c.get("steps")?.asArray?.first ?? .null
        XCTAssertTrue(try verify(grant, step).ok)
        // a flipped signature is a refusal, not a pass-through
        let sig = step.get("pcactn")?.get("sig")?.asString ?? ""
        let flipped = String(sig.dropLast()) + (sig.last == "A" ? "B" : "A")
        XCTAssertFalse(try verify(grant, step, tweak: { $0["sig"] = .string(flipped) }).ok)
        // another audience is refused by the core verifier itself
        var o = A2a.VerifyOptions(aud: "someone-else", now: Self.FIX.get("now")?.safeInt, grant: grant.asObject)
        o.isRevoked = { _, _ in false }
        XCTAssertFalse(try A2a.verifyA2ATask(A2a.attachPcaToA2ATask(.object([:]), step.get("pcactn") ?? .null), o).ok)
        // with no revocation predicate the default-required revocation check cannot pass: fail closed
        let noRev = A2a.VerifyOptions(aud: Self.FIX.get("audience")?.asString, now: Self.FIX.get("now")?.safeInt, grant: grant.asObject)
        XCTAssertFalse(try A2a.verifyA2ATask(A2a.attachPcaToA2ATask(.object([:]), step.get("pcactn") ?? .null), noRev).ok)
    }
}
