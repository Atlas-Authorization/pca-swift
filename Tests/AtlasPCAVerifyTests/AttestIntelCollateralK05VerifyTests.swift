import XCTest
@testable import AtlasPCAVerify

/// `verifyIntelTdxCollateral` end to end on a really-signed quote and collateral (attest-intel-collateral.ts:458-487).
final class AttestIntelCollateralK05VerifyTests: XCTestCase {
    private func run(_ c: IntelCollateral, quote: [UInt8] = IntelForge.quote(), pol: CollateralPolicy? = nil) -> CollateralResult {
        IntelCollateral.verify(quote, c, IntelForge.NOW, pol, IntelForge.pin, false)
    }

    func testHonestCollateralIsAccepted() {
        let r = run(IntelForge.collateral())
        XCTAssertEqual(r.reason, "")
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.status, "UpToDate")
    }

    func testEvaluationNumberZeroIsPresent() {
        XCTAssertTrue(run(IntelForge.collateral(tcbEval: "0")).ok)
        XCTAssertTrue(run(IntelForge.collateral(qeEval: "0")).ok)
    }

    func testEvaluationNumberMissingOrNegative() {
        let why = "tcbEvaluationDataNumber missing"
        XCTAssertEqual(run(IntelForge.collateral(tcbEval: nil)).reason, why)
        XCTAssertEqual(run(IntelForge.collateral(qeEval: nil)).reason, why)
        XCTAssertEqual(run(IntelForge.collateral(tcbEval: "-1")).reason, why)
        XCTAssertEqual(run(IntelForge.collateral(qeEval: "-1")).reason, why)
        XCTAssertEqual(run(IntelForge.collateral(tcbEval: "\"17\"")).reason, why) // not a number
    }

    func testTheLastSeamAttributeByteIsCompared() {
        let r = run(IntelForge.collateral(), quote: IntelForge.quote(seamAttr7: 1))
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "TCB evaluation: TD report SEAM attributes do not match the TDX module identity")
    }

    func testAdvisoriesMergeSorted() {
        let r = run(IntelForge.collateral(tcbAdv: ["B", "D"], qeAdv: ["A", "C", "D"]))
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.advisoryIDs, ["A", "B", "C", "D"])
    }

    func testAcceptedStatuses() {
        let c = IntelForge.collateral()
        XCTAssertTrue(run(c, pol: CollateralPolicy()).ok) // no list: the default
        var other = CollateralPolicy()
        other.acceptStatuses = ["Revoked"]
        other.hasAccept = true
        let r = run(c, pol: other)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.status, "UpToDate")
        XCTAssertEqual(r.reason, "TCB status UpToDate is not accepted by policy")
        var empty = CollateralPolicy()
        empty.hasAccept = true
        XCTAssertFalse(run(c, pol: empty).ok) // [] accepts nothing, as accepted.includes on an empty array
    }
}
