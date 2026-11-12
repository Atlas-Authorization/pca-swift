import XCTest
@testable import AtlasPCAVerify

/// TD_ATTRIBUTES.DEBUG is refused unless `allowDebug` is exactly true (attest-intel-tdx.ts:625), on a really-signed quote.
final class AttestIntelK05QuoteTests: XCTestCase {
    private let debugReason = "TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)"

    func testAnHonestQuoteVerifies() {
        let r = DcapVerifier.verifyGenuineQuote(IntelForge.quote(), IntelForge.pin, IntelForge.NOW, nil, false)
        XCTAssertEqual(r.reason, "")
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.fmspc, "010203040506")
    }

    func testADebugTdIsRefusedWithoutAPolicy() {
        let r = DcapVerifier.verifyGenuineQuote(IntelForge.quote(tdAttr0: 1), IntelForge.pin, IntelForge.NOW, nil, false)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, debugReason)
    }

    func testADefaultPolicyDoesNotAllowDebug() {
        let r = DcapVerifier.verifyGenuineQuote(IntelForge.quote(tdAttr0: 1), IntelForge.pin, IntelForge.NOW, DcapVerifier.QuotePolicy(), false)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, debugReason)
    }

    func testAllowDebugOptsIn() {
        XCTAssertTrue(DcapVerifier.verifyGenuineQuote(IntelForge.quote(tdAttr0: 1), IntelForge.pin, IntelForge.NOW, nil, true).ok)
        var p = DcapVerifier.QuotePolicy()
        p.allowDebug = true
        XCTAssertTrue(DcapVerifier.verifyGenuineQuote(IntelForge.quote(tdAttr0: 1), IntelForge.pin, IntelForge.NOW, p, false).ok)
    }
}
