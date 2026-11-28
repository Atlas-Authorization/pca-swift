import XCTest
import Foundation
import AtlasPCAVerify
@testable import AtlasPCAFhe

final class FheSignedTests: XCTestCase {
    func testTheContextFactoryBuildsTheFixedBfvContext() throws {
        let c = try FheSeal.createFheContext()
        XCTAssertEqual(c.polyModulusDegree, 8192)
        XCTAssertEqual(c.slotCount, 8192)
        c.dispose()
    }

    func testTheSignedClaimPathEvaluatesOnlyAVerifiedClaim() throws {
        let keys = try FheSeal.keygen()
        let w: [Int64] = [250, 200, 200, 200, 100, 50]
        let pol = FheRiskPolicy(scale: 1000, dim: 6, weightsScaled: w, kappaWeightsScaled: w, budgetScaled: 600_000, kappa: 1)
        let policyJSON: JSONValue = .object(["scale": .int(1000), "dim": .int(6), "weightsScaled": .array(w.map { .int($0) }), "kappaWeightsScaled": .array(w.map { .int($0) }),
                                              "budgetScaled": .int(600_000), "kappa": .int(1)])
        let inputs: [Int64] = [100, 900, 100, 100, 100, 100]
        let binding: JSONValue = .object(["aud": .string("svc"), "counter": .int(1)])
        let claim: JSONValue = .object(["binding": binding, "policy": policyJSON, "encInputs": .string(try FheSeal.encryptRiskInputs(publicKey: keys.publicKey, inputsScaled: inputs))])
        let signer = try PCAEdKey(seed: [UInt8](repeating: 7, count: 32))
        let signed = try PCAFheOrigin.signRiskClaim(claim, key: signer, context: "grant-1")
        let guardrail = PCAFheNonceGuard()
        let exp = PCAFheOrigin.ClaimExpectations(trustedSigners: [signer.id], context: "grant-1", binding: binding, policy: policyJSON, nonces: guardrail)

        let r = FheSeal.evalSignedRiskClaim(publicKey: keys.publicKey, galoisKeys: keys.galoisKeys, signed: signed, expectations: exp)
        XCTAssertTrue(r.ok, r.reason ?? "")
        XCTAssertEqual(r.claimDigest, try PCAFheOrigin.signedClaimDigest(signed))
        let v = try FheSeal.decryptVerdict(secretKey: keys.secretKey, encRiskRaw: r.gate!.encRiskRaw, encSlack: r.gate!.encSlack, policy: pol)
        XCTAssertEqual(v.rScaled, zip(w, inputs).reduce(Int64(0)) { $0 + $1.0 * $1.1 })

        // the same claim again is a replay; another context, signer or binding never reaches SEAL
        XCTAssertFalse(FheSeal.evalSignedRiskClaim(publicKey: keys.publicKey, galoisKeys: keys.galoisKeys, signed: signed, expectations: exp).ok)
        let other = PCAFheOrigin.ClaimExpectations(trustedSigners: [signer.id], context: "grant-2", binding: binding, policy: policyJSON, nonces: PCAFheNonceGuard())
        XCTAssertFalse(FheSeal.evalSignedRiskClaim(publicKey: keys.publicKey, galoisKeys: keys.galoisKeys, signed: signed, expectations: other).ok)
        let stranger = PCAFheOrigin.ClaimExpectations(trustedSigners: ["nobody"], context: "grant-1", binding: binding, policy: policyJSON, nonces: PCAFheNonceGuard())
        XCTAssertFalse(FheSeal.evalSignedRiskClaim(publicKey: keys.publicKey, galoisKeys: keys.galoisKeys, signed: signed, expectations: stranger).ok)
        XCTAssertFalse(FheSeal.evalSignedRiskClaim(publicKey: keys.publicKey, galoisKeys: keys.galoisKeys, signed: .null, expectations: exp).ok)
    }
}
