import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Heavy-fixture kill test (Authorize.swift line 1073, `v2Env`): a grant whose envelope predicate reads `env.canon.refundable`, a
/// verifier-computed member of the Intent v2 environment. Without the merge of IntentV2.decide's env the predicate cannot be decided.
final class AuthorizeS2HV2KillTests: XCTestCase {
    private func signed(refundable: String) -> AZ.Signed {
        let predicate: JSONValue = .object([
            "verb": .string("air.book"), "resource": .string("skyair.example/*"),
            "where": .array([.object(["field": .string("env.canon.refundable"), "op": .string("eq"), "value": .string(refundable)])]),
        ])
        let envelope: JSONValue = .object([
            "type": .string("envelope"), "goal_commit": .string(V2F.goalCommitV2(map: V2F.MAP0, salt: "salt0")), "predicates": .array([predicate]),
            "caveats": .array([]), "agent_binding": .object([:]), "risk_policy": AZ.RISK,
        ])
        let sc: JSONValue = .object(["type": .string("intent_session"), "session": .string(V2F.SESSION), "seq": .int(0), "root": .string(V2F.BASE.R)])
        let g = V2F.cap(issuer: V2F.principal, holder: V2F.agent, caveats: [envelope, sc])
        let intent: JSONValue = .object(["ref": .string(V2F.REF), "map_digest": .string(V2F.MAP0), "goal_salt": .string("salt0"),
                                         "fidelity_ppm": .int(1_000_000), "residual_risk_ppm": .int(0)])
        let p = AZ.proof(g, verb: "air.book", resource: "skyair.example/bookings", params: V2F.PARAMS, declared: "irreversible", now: V2F.NOW, aud: V2F.AUD,
                         extra: ["intent": intent, "intent_session": V2F.is0()])
        return AZ.Signed(grant: g, pcactn: p, params: V2F.PARAMS)
    }

    private func run(_ s: AZ.Signed) -> PCA.AuthorizeResult {
        AZ.run(s) {
            $0.operation = PCA.Operation(verb: "air.book", resource: "skyair.example/bookings", params: V2F.PARAMS)
            $0.audience = V2F.AUD
            $0.now = V2F.NOW
            $0.intentV2 = .context(IntentV2Context.fromJSON(V2F.ctx())!)
        }
    }

    func testAPredicateMayReadAVerifierComputedV2EnvironmentMember() {
        let yes = run(signed(refundable: "false"))
        XCTAssertTrue(yes.allow, "line 1073: env.canon.refundable is the verifier's \"false\"; \(yes.reasons)")
        let no = run(signed(refundable: "true"))
        XCTAssertFalse(no.allow, "control: the same predicate over another value is not met")
    }
}
