import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the pure parts of pca-fhe (quantization, gate policy, signed-claim and verdict-attestation layer) against the
/// reference: test-data/ref-fhe.json.gz. The BFV evaluation itself is the AtlasPCAFhe product (FheSealTests).
final class RefFheTests: XCTestCase {
    static let file = "ref-fhe.json.gz"
    static let covers = ["FheRisk", "FheOrigin", "StrictJSON", "Canonical", "Base64URLStrict", "JSONValue", "Ed25519Strict"]

    static func doubles(_ a: [Double]) -> JSONValue { .array(a.map { PCAFheRisk.numVal($0) }) }

    static func strings(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    func run(_ c: BaseCase) throws -> JSONValue {
        let a0 = c.arg(0) ?? .null, a1 = c.arg(1) ?? .null
        func seed(_ v: JSONValue) throws -> PCAEdKey {
            guard let s = v.asString, let b = Base64URLStrict.decode(s) else { throw PCAProducerError("seed") }
            return try Ed25519Deterministic.key(seed: b)
        }
        switch c.fn {
        case "transformedInputs": return Self.doubles(try PCAFheRisk.transformedInputs(a0))
        case "quantizeRiskInputs": return Self.doubles(c.args.count == 1 ? try PCAFheRisk.quantizeRiskInputs(a0) : try PCAFheRisk.quantizeRiskInputs(a0, scale: a1))
        case "weightVector": return Self.doubles(try PCAFheRisk.weightVector(a0))
        case "fheRiskPolicy": return c.args.count == 2 ? try PCAFheRisk.fheRiskPolicy(a0, budget: a1) : try PCAFheRisk.fheRiskPolicy(a0, budget: a1, scale: c.arg(2) ?? .null)
        case "plaintextVerdict": return try PCAFheRisk.plaintextVerdict(a0, a1, budget: c.arg(2) ?? .null)
        case "fromActn": return Self.doubles(try PCAFheRisk.transformedInputs(try PCAFheRisk.riskInputsFromPCActn(a0)))
        case "binding": return try PCAFheRisk.bindingFromPCActn(a0)
        case "sign":
            guard let ctx = c.arg(2)?.asString, let n = Base.bytes(c.arg(3)) else { throw PCAProducerError("args") }
            return try PCAFheOrigin.signRiskClaim(a0, key: try seed(a1), context: ctx, nonce: n)
        case "claimDigest": return .string(try PCAFheOrigin.signedClaimDigest(a0))
        case "verifyClaim":
            let used = Set(Self.strings(a1.get("used")))
            let max = Int(IV.num(a1.get("max")) ?? 0)
            let guardSet = PCAFheNonceGuard(maxEntries: max)
            for u in used { _ = guardSet.claim(u) }
            let exp = PCAFheOrigin.ClaimExpectations(trustedSigners: Self.strings(a1.get("trustedSigners")), context: a1.get("context")?.asString ?? "",
                                                     binding: a1.get("binding") ?? .null, policy: a1.get("policy") ?? .null, nonces: guardSet)
            let r = PCAFheOrigin.verifySignedRiskClaim(a0, exp)
            return r.ok ? .object(["ok": .bool(true), "claim": r.claim ?? .null, "digest": .string(r.digest ?? "")]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
        case "nonceGuard":
            let g = PCAFheNonceGuard(maxEntries: Int(IV.num(a0) ?? 0))
            return .array(Self.strings(a1).map { .bool(g.claim($0)) })
        case "attest": return try PCAFheOrigin.attestVerdict(key: try seed(a0), signed: a1, gate: c.arg(2) ?? .null, admit: c.arg(3) == .bool(true))
        case "verifyAttest":
            let gate = a1.get("gate")
            let r = PCAFheOrigin.verifyVerdictAttestation(a0, trustedHolders: Self.strings(a1.get("trustedHolders")), claimDigest: a1.get("claimDigest")?.asString ?? "", gate: (gate?.isObject ?? false) ? gate : nil)
            return r.ok ? .object(["ok": .bool(true), "admit": .bool(r.admit)]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
        default: throw PCAProducerError("unmapped fn \(c.fn)")
        }
    }

    func testReplay() throws {
        try K042.requireCovers(Self.covers)
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in d.add(c, Base.diff(c, Base.run { try self.run(c) })) }
        d.finish(1400)   // 1569 cases
    }
}
