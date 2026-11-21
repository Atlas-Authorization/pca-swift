import XCTest
@testable import AtlasPCAVerify

/// parseDcapQuote field widths and bounds, exact reasons (attest-intel-tdx.ts:240-305).
final class AttestIntelK05ParseTests: XCTestCase {
    private let z = IntelForge.zeros

    private func head() -> [UInt8] {
        var h = z(632)
        h[0] = 4
        h[2] = 2
        h[4] = 0x81
        return h
    }

    /// Quote signature + AK at 0, outer header at 128, QE report at 134, QE signature at 518, auth size at 582, inner header at 584, PEM at 590.
    private func section(outerType: Int = 6, outerSize: Int, innerType: Int = 5, innerSize: Int = 0, pem: [UInt8] = []) -> [UInt8] {
        var s: [UInt8] = z(128)
        s += IntelForge.le16(outerType)
        s += IntelForge.le32(outerSize)
        s += z(384 + 64 + 2)
        s += IntelForge.le16(innerType)
        s += IntelForge.le32(innerSize)
        s += pem
        return s
    }

    private func quote(_ s: [UInt8], declared: Int) -> [UInt8] { head() + IntelForge.le32(declared) + s + z(16) }

    private func parse(_ q: [UInt8]) -> String? {
        guard let m = IntelForge.refusal({ try DcapVerifier.parseQuote(q) }) else { return nil }
        return String(m.dropFirst("parseDcapQuote: ".count))
    }

    /// The reason at signature-data length `k`, the outer wrapper sized to end exactly there.
    private func truncated(_ k: Int) -> String? { parse(quote(section(outerSize: max(0, k - 134)), declared: k)) }

    func testMinimumLength() {
        // 636 bytes is long enough for the header check; one byte fewer is not, whatever the version says
        XCTAssertEqual(parse(head() + z(4)), "truncated reading quote signature")
        var short = z(635)
        short[0] = 3
        XCTAssertEqual(parse(short), "too short for header + TD report + sig length")
    }

    func testHeaderFieldWidths() {
        var h = head()
        h[1] = 1
        XCTAssertEqual(parse(h + z(4)), "unsupported quote version 260 (expected 4)")
        h = head()
        h[3] = 1
        XCTAssertEqual(parse(h + z(4)), "unsupported attestation key type 258 (expected ECDSA-P256 = 2)")
        h = head()
        h[7] = 1
        XCTAssertEqual(parse(h + z(4)), "unexpected TEE type 0x1000081 (expected TDX = 0x81)")
        h = head()
        h[8] = 1 // past the 4-byte TEE type
        XCTAssertEqual(parse(h + z(4)), "truncated reading quote signature")
    }

    func testSignatureDataLengthIsFourBytes() {
        XCTAssertEqual(parse(quote(z(8), declared: 0x0100_0000)), "signature data (16777216) overruns the quote")
    }

    func testEveryTruncationNamesItsField() {
        XCTAssertEqual(truncated(63), "truncated reading quote signature")
        XCTAssertEqual(truncated(127), "truncated reading attestation public key")
        XCTAssertEqual(truncated(128), "truncated reading outer cert-data header")
        XCTAssertEqual(truncated(133), "truncated reading outer cert-data header")
        XCTAssertEqual(truncated(134), "truncated reading QE report")
        XCTAssertEqual(truncated(581), "truncated reading QE report signature")
        XCTAssertEqual(truncated(582), "truncated reading QE auth-data size")
        XCTAssertEqual(truncated(583), "truncated reading QE auth-data size")
        XCTAssertEqual(truncated(584), "truncated reading inner cert-data header")
        XCTAssertEqual(truncated(589), "truncated reading inner cert-data header")
    }

    func testOuterWrapperFieldWidths() {
        XCTAssertEqual(parse(quote(section(outerType: 0x0106, outerSize: 0), declared: 134)), "outer cert-data type 262 (expected QE-report-cert-data = 6)")
        XCTAssertEqual(parse(quote(section(outerSize: 0x0100_0000), declared: 134)), "outer cert-data overruns signature data")
    }

    func testInnerWrapperFieldWidths() {
        XCTAssertNil(parse(quote(section(outerSize: 456), declared: 590)))
        XCTAssertEqual(parse(quote(section(outerSize: 456, innerType: 0x0105), declared: 590)), "inner cert-data type 261 (expected PCK-cert-chain = 5)")
        XCTAssertEqual(parse(quote(section(outerSize: 456, innerSize: 0x0100_0000), declared: 590)), "inner cert-data overruns outer cert-data")
    }

    func testThePemStartsAfterTheSixByteInnerHeader() throws {
        let q = try DcapVerifier.parseQuote(quote(section(outerSize: 459, innerSize: 3, pem: Array("ABC".utf8)), declared: 593))
        XCTAssertEqual(q.pckChainPem, "ABC")
    }
}
