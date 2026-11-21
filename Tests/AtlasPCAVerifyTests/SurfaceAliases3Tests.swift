import XCTest
@testable import AtlasPCAVerify

final class SurfaceAliases3Tests: XCTestCase {
    func testEvidenceFromReportMatchesTheTolerantParse() throws {
        var r = [UInt8](repeating: 0, count: 0x2e8 + 72)
        r[0] = 2
        r[0x90] = 0xab
        r[0x08] = 0x01 // a policy bit pattern: the debug bit is bit 19 of the policy word, so this stays clear
        let ev = try PCAAttestEat.evidenceFromReport(r)
        XCTAssertEqual(ev.get("version"), .int(2))
        XCTAssertTrue(ev.get("measurement")?.asString?.hasPrefix("ab") ?? false)
        XCTAssertEqual(ev.get("debug"), .bool(false))
        XCTAssertEqual(PCAAttestEat.parseReportTolerant(r).get("evidence"), ev)
        XCTAssertEqual(try PCAAttestEat.measuredFromReport(r).get("weights_measured"), .bool(false))
        XCTAssertThrowsError(try PCAAttestEat.evidenceFromReport([UInt8](repeating: 0, count: 100)))
        XCTAssertThrowsError(try PCAAttestEat.measuredFromReport([]))
    }

    func testSigstoreNames() {
        XCTAssertEqual(PCA.SIGSTORE_BUNDLE_MEDIA_TYPES.count, 3)
        XCTAssertThrowsError(try PCA.parseTrustedRoot(.object([:])))
    }

    func testCborTagRoundTrip() {
        let t = CborTag(18, .text("x"))
        XCTAssertEqual(CborTag(t.cbor), t)
        XCTAssertNil(CborTag(.int(1)))
    }
}
