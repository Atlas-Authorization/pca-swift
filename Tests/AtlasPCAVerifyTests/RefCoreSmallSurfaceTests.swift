import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the small public surface of core pca against the TypeScript reference (ref-core-small-surface): the workflow commitment and
/// receipt-chain errors and the revocation membership proof. A reference throw requires a native refusal.
final class RefCoreSmallSurfaceTests: XCTestCase {
    static let file = "ref-core-small-surface.json.gz"

    func testSmallSurfaceAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["workflowCommitmentError", "workflowReceiptError", "verifyMembership", "isCanonicalCompactJws", "isCanonicalCompactJwsOpaque",
                                "isCanonicalCompactJwsFive", "assertCanonicalJwsSegments", "goalCommitOf", "verifyGoalCommit", "validateRevocationStaleness", "spcExpectation",
                                "cibaApprovalDetails"]
        let n = try Base.each(Self.file, fns) { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "workflowCommitmentError":
                    return Workflow.workflowCommitmentError(c.arg(0), principal: c.arg(1), now: c.arg(2)).map { .string($0) } ?? .null
                case "workflowReceiptError":
                    // the reference answers the index of the first bad receipt, or null; a signer or clock that is not usable is no receipt problem it can name (null)
                    guard let signer = c.arg(1)?.asString, let now = IV.safe(c.arg(3)) else { return .null }
                    return try Workflow.workflowReceiptError(c.arg(0), rsSigner: signer, receipts: c.arg(2), now: Int64(now)).map { .int(Int64($0)) } ?? .null
                case "verifyMembership":
                    return .bool(PCA.verifyMembership(root: c.arg(0)?.asString ?? "", proof: c.arg(1), id: c.arg(2)?.asString ?? ""))
                case "isCanonicalCompactJws": return .bool(Jose.isCanonicalCompactJws(c.arg(0)))
                case "isCanonicalCompactJwsOpaque": return .bool(Jose.isCanonicalCompactJws(c.arg(0), jsonPayload: false))
                case "isCanonicalCompactJwsFive": return .bool(Jose.isCanonicalCompactJws(c.arg(0), parts: 5))
                case "assertCanonicalJwsSegments":
                    do { return .object(["ok": .bool(true), "header": .object(try Jose.assertCanonicalJwsSegments(c.arg(0), c.arg(1)))]) } catch { return .object(["ok": .bool(false)]) }
                case "goalCommitOf": return .string(try PCA.goalCommitOf(c.arg(0)?.asString ?? "", c.arg(1)?.asString ?? ""))
                case "verifyGoalCommit": return .bool(PCA.verifyGoalCommit(c.arg(0)?.asString ?? "", c.arg(1)?.asString ?? "", c.arg(2)?.asString ?? ""))
                case "validateRevocationStaleness": return .object(["ok": .bool(RevocationStalenessPolicy.fromJSON(c.arg(0))?.validate() == nil && c.arg(0)?.isObject == true)])
                case "spcExpectation":
                    do { return .object(["ok": .bool(true), "v": try ActionApprovalProfiles.spcExpectation(c.arg(0) ?? .null, "https://shop.example", c.arg(1)?.asString ?? "name")]) } catch { return .object(["ok": .bool(false)]) }
                case "cibaApprovalDetails":
                    do { return .object(["ok": .bool(true), "v": try ActionApprovalProfiles.cibaApprovalDetails(c.arg(0) ?? .null)]) } catch { return .object(["ok": .bool(false)]) }
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 574 + 39, "the nine workflow / JWS / goal fns, the revocation staleness validator and the two approval profile fns of the corpus (the rest is RefCoreSmallSurface2Tests)")
        d.finish(601) // the corpus holds 12 cases whose text carries a lone surrogate, which the harness skips
    }
}
