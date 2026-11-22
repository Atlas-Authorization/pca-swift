import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the payments pieces that sit on the core decision (the native policy engine as the default decider) and the
/// optimistic path (the bonded claim over a charge PCActn).
final class RefPaymentsCoreTests: XCTestCase {
    static let file = "ref-payments-java-extra.json.gz"

    func testPaymentsCore() throws {
        try K042.requireCovers(["Payments", "Optimistic"])
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            let n0 = c.arg(0) ?? .null, n1 = c.arg(1) ?? .null, n2 = c.arg(2) ?? .null
            let got: BaseGot
            switch c.fn {
            case "authorizeChargeCore": got = Ref.v { try PCAPayments.authorizeChargeCore(n0, n1, n2) }
            case "openChargeBond":
                got = Ref.v {
                    guard let bondRef = n1.get("bondRef")?.asString, let claimedR = IV.num(n1.get("claimedR")), let seed = Base64URLStrict.decode(n2.asString ?? "") else {
                        throw JSError("openChargeBond: bad options")
                    }
                    var o = Optimistic.OpenOptions(bondRef: bondRef, claimedR: claimedR)
                    if n1.get("challengeWindowMs") != nil { o.challengeWindowMs = IV.num(n1.get("challengeWindowMs")) ?? .nan }
                    if n1.get("issuedAt") != nil { o.issuedAt = IV.num(n1.get("issuedAt")) ?? .nan }
                    if n1.get("serverNow") != nil { o.serverNow = IV.num(n1.get("serverNow")) ?? .nan }
                    return try PCAPayments.openChargeBond(n0, o, signer: try Ed25519Deterministic.key(seed: seed))
                }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(130)
    }
}
