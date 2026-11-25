import Foundation
import AtlasPCAVerify

/// The evaluator's signed-claim path (the reference's `evalSignedRiskClaim`) and the context factory.
public struct FheContext: Equatable, Sendable {
    /// BFV batching slots of the fixed context.
    public let slotCount: Int
    public let polyModulusDegree: UInt64
    /// A no-op: every call here builds its own SEAL context and frees it before returning, so nothing is held between calls.
    public func dispose() {}
}

/// `{ok: true, gate, claimDigest}` or `{ok: false, reason}`.
public struct FheSignedEval {
    public let ok: Bool
    public let gate: FheEncryptedGate?
    public let claimDigest: String?
    public let reason: String?
}

extension FheSeal {
    /// Build the deterministic BFV context once to check that SEAL accepts the parameters and the plain modulus is the documented constant.
    public static func createFheContext() throws -> FheContext {
        let s = Scope()
        defer { s.release() }
        let c = try context(s)
        return FheContext(slotCount: c.slots, polyModulusDegree: polyModulusDegree)
    }

    private static func member(_ v: JSONValue?, _ k: String) -> JSONValue? {
        if case let .object(o)? = v { return o[JKey(k)] }
        return nil
    }

    private static func int(_ v: JSONValue?) -> Int64? {
        switch v {
        case let .int(i)?: return i
        case let .double(d)?: return d.rounded() == d && abs(d) < 9_007_199_254_740_992 ? Int64(d) : nil
        default: return nil
        }
    }

    private static func ints(_ v: JSONValue?) -> [Int64]? {
        guard case let .array(a)? = v else { return nil }
        var out: [Int64] = []
        for x in a { guard let i = int(x) else { return nil }; out.append(i) }
        return out
    }

    /// Verify the signed claim, then run the gate: the ciphertext is not loaded into SEAL unless the signature, signer, context, binding, policy and nonce
    /// all check out. Never throws: every refusal is `ok: false` with its reason.
    public static func evalSignedRiskClaim(publicKey: String, galoisKeys: String, signed: JSONValue, expectations: PCAFheOrigin.ClaimExpectations) -> FheSignedEval {
        let chk = PCAFheOrigin.verifySignedRiskClaim(signed, expectations)
        guard chk.ok, let claim = chk.claim, let digest = chk.digest else { return FheSignedEval(ok: false, gate: nil, claimDigest: nil, reason: chk.reason) }
        func bad(_ why: String) -> FheSignedEval { FheSignedEval(ok: false, gate: nil, claimDigest: nil, reason: "evaluation failed: \(why)") }
        let p = member(claim, "policy")
        guard case let .string(enc)? = member(claim, "encInputs"), let scale = int(member(p, "scale")), let dim = int(member(p, "dim")), let w = ints(member(p, "weightsScaled")),
              let kw = ints(member(p, "kappaWeightsScaled")), let budget = int(member(p, "budgetScaled")) else { return bad("malformed policy") }
        var kappa = 1.0
        switch member(p, "kappa") {
        case let .int(i)?: kappa = Double(i)
        case let .double(d)?: kappa = d
        default: break
        }
        do {
            let gate = try evalRiskGate(publicKey: publicKey, galoisKeys: galoisKeys, encInputs: enc,
                                        policy: FheRiskPolicy(scale: scale, dim: dim, weightsScaled: w, kappaWeightsScaled: kw, budgetScaled: budget, kappa: kappa))
            return FheSignedEval(ok: true, gate: gate, claimDigest: digest, reason: nil)
        } catch {
            return bad("\(error)")
        }
    }
}
