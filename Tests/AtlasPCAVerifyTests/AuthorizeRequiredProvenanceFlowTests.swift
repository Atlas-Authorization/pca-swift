import XCTest
import Foundation
@testable import AtlasPCAVerify

/// `require: ['provenance_flow']` is refused by the require loop before the gate runs. The gate's own outcome must not lift that, as in
/// the reference (require-pca.ts): a required check's failure is never overwritten.
final class AuthorizeRequiredProvenanceFlowTests: XCTestCase {
    func testTheGatePassingDoesNotLiftTheRefusal() {
        let s = AZ.signed()
        let free = ProvenanceFlowTests.raw(s) {
            $0.argProvenance.mediators = [ProvHarness.pin]
            $0.provenance = ProvHarness.bundle(ProvenanceFlowTests.op(s))
        }
        XCTAssertTrue(free.allow, "\(free.reasons)")
        XCTAssertEqual(free.checks["provenance_flow"], .pass)

        let r = ProvenanceFlowTests.raw(s) {
            $0.argProvenance.mediators = [ProvHarness.pin]
            $0.provenance = ProvHarness.bundle(ProvenanceFlowTests.op(s))
            $0.require = ["provenance_flow"]
        }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "deny")
        XCTAssertEqual(r.checks["provenance_flow"], .fail)
        XCTAssertTrue(r.reasons.contains { $0.hasPrefix("provenance_flow: required check is absent") }, "\(r.reasons)")
    }

    func testTheGateNotEnforcedDoesNotLiftTheRefusal() {
        let s = ProvenanceFlowTests.signed(provenance: .object(["mode": .string("insecure_off")]))
        XCTAssertTrue(ProvenanceFlowTests.raw(s).allow)

        let r = ProvenanceFlowTests.raw(s) { $0.require = ["provenance_flow"] }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "deny")
        XCTAssertEqual(r.checks["provenance_flow"], .fail)
    }

    func testTheGateFailingStillAddsItsReason() {
        let r = ProvenanceFlowTests.raw(AZ.signed()) { $0.require = ["provenance_flow"] }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "deny")
        XCTAssertEqual(r.checks["provenance_flow"], .fail)
        XCTAssertTrue(r.reasons.contains { $0.hasPrefix("provenance_flow: required check is absent") }, "\(r.reasons)")
        XCTAssertTrue(r.reasons.contains { $0.hasPrefix("provenance_flow: escalate:") }, "\(r.reasons)")
    }

    func testAnotherEscalateClassFailureCannotMakeItAnswerable() {
        let s = EscalationTests.signed()
        let answer = EscalationTests.answer(s)
        // control: without the require the same setup escalates, and the same answer allows
        XCTAssertEqual(EscalationTests.go(s).decision, "escalate")
        XCTAssertTrue(EscalationTests.go(s, answer: answer, pins: EscalationTests.pin).allow)

        let r = AZ.run(s) {
            $0.stateStore = MemoryStateStore()
            $0.intentV2 = .context(IntentV2Context(.object([:])))
            $0.escalationAnswer = answer
            $0.escalationPrincipals = EscalationTests.pin
            $0.insecureUnboundApproval = true
            $0.require = ["provenance_flow"]
        }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.decision, "deny")
        XCTAssertEqual(r.checks["provenance_flow"], .fail)
    }
}
