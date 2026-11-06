import XCTest
@testable import AtlasPCAVerify

/// The binding framing of packages/pca/src/attestation.ts and the base64 / hex helpers.
final class AttestCommonK05Tests: XCTestCase {
    func testResultDefaultsAreFailClosed() {
        let r = HardwareResult()
        XCTAssertFalse(r.ok)
        XCTAssertFalse(r.bound)
        XCTAssertFalse(HardwareResult.fail("x").bound)
        XCTAssertFalse(HardwareResult(ok: true).bound)
    }

    /// lp(): u32 big-endian over all four bytes. 0x01020304 is the smallest length that shows every byte.
    func testLengthPrefixIsBigEndian() {
        let out = Attest.lengthPrefixed(String(repeating: "a", count: 0x0102_0304))
        XCTAssertEqual(Array(out.prefix(4)), [0x01, 0x02, 0x03, 0x04])
        XCTAssertEqual(out.count, 4 + 0x0102_0304)
        XCTAssertEqual(Attest.lengthPrefixed("\u{e9}"), [0, 0, 0, 2, 0xc3, 0xa9])
        XCTAssertEqual(Attest.lengthPrefixed(""), [0, 0, 0, 0])
    }

    /// report_data = SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce))
    func testBindingPreimage() {
        let b = AttestationBinding(holderPub: "h", grantRef: "gr", epoch: Double(0x0001_0203_0405_0607), nonce: "nnn")
        var pre = Array("atlas-pca/attest-bind/v1\u{0}".utf8)
        pre += [0, 0, 0, 1] + Array("h".utf8)
        pre += [0, 0, 0, 2] + Array("gr".utf8)
        pre += [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        pre += [0, 0, 0, 3] + Array("nnn".utf8)
        XCTAssertEqual(Attest.bindingBytes(b).bytes, ACrypto.sha512(pre))
    }

    /// Number.isSafeInteger: 2^53 - 1 is in, 2^53 is out.
    func testEpochSafeIntegerBoundary() {
        func at(_ e: Double) -> (bytes: [UInt8]?, error: String) {
            Attest.bindingBytes(AttestationBinding(holderPub: "h", grantRef: "g", epoch: e, nonce: "n"))
        }
        XCTAssertNotNil(at(9_007_199_254_740_991).bytes)
        XCTAssertEqual(at(9_007_199_254_740_992).error, "binding: epoch must be a non-negative safe integer")
        XCTAssertNil(at(9_007_199_254_740_992).bytes)
        XCTAssertNotNil(at(0).bytes)
    }

    func testNodeB64RoundTripsEveryRemainder() {
        let bytes = (0..<64).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 0xa5) }
        for n in 0...bytes.count {
            let b = Array(bytes.prefix(n))
            XCTAssertEqual(Attest.nodeB64(Attest.base64StdEncode(b)), b, "\(n)")
        }
    }

    func testBase64StdPadding() {
        XCTAssertEqual(Attest.base64Std("QQ=="), [0x41])
        XCTAssertEqual(Attest.base64Std("QUI="), [0x41, 0x42])
        XCTAssertEqual(Attest.base64Std("QUJD"), [0x41, 0x42, 0x43])
        XCTAssertEqual(Attest.base64Std(""), [])
        let refused = [
            "QQ==QUJD", // padding before the last quad
            "QUI=QUJD",
            "====",
            "Q===",
            "=QQQ",
            "QQ=Q", // data after padding
        ]
        for s in refused { XCTAssertNil(Attest.base64Std(s), s) }
    }

    func testHexStringNeedsAnEvenLength() {
        XCTAssertFalse(Attest.isHexString("abc"))
        XCTAssertFalse(Attest.isHexString("a"))
        XCTAssertTrue(Attest.isHexString("abcd"))
        XCTAssertFalse(Attest.isHexString(""))
        XCTAssertFalse(Attest.isHexString("zz"))
        // odd hex falls through to base64
        XCTAssertEqual(Attest.decodeClaimBytes("abc"), Attest.nodeB64("abc"))
    }
}
