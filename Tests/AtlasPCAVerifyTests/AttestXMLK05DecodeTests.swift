import XCTest
@testable import AtlasPCAVerify

/// Character references and the byte searches of the RIM XML reader. The predefined entities and numeric references are xmldom's
/// (packages/pca/src/attest-nvidia-rim.ts parses with @xmldom/xmldom); the valid range is the XML 1.0 Char production, stricter than xmldom.
final class AttestXMLK05DecodeTests: XCTestCase {
    func dec(_ s: String) -> String {
        do { return try XML.decode(ArraySlice(Array(s.utf8))) } catch { return "ERR " + ((error as? AttestError)?.message ?? "?") }
    }

    func b(_ s: String) -> [UInt8] { Array(s.utf8) }

    func testDecodeKeepsTheTextAroundAReference() {
        XCTAssertEqual(dec("plain"), "plain")
        XCTAssertEqual(dec("a&amp;b"), "a&b")
        XCTAssertEqual(dec("x&lt;y"), "x<y")
        XCTAssertEqual(dec("abcd&gt;efgh"), "abcd>efgh")
        XCTAssertEqual(dec("&quot;&apos;"), "\"'")
        XCTAssertEqual(dec("\u{e9}&lt;\u{e9}"), "\u{e9}<\u{e9}")
        XCTAssertEqual(dec("&lt;ab"), "<ab")
        XCTAssertEqual(dec("a&lt;"), "a<")
    }

    func testDecodeRefusals() {
        XCTAssertEqual(dec("a&lt"), "ERR unterminated entity reference")
        XCTAssertEqual(dec("a&bogus;"), "ERR undefined entity &bogus;")
    }

    func testNumericReferencesAreDecimalOrHex() {
        XCTAssertEqual(dec("&#65;"), "A")
        XCTAssertEqual(dec("&#x41;"), "A")
        XCTAssertEqual(dec("x&#65;y&#x41;z"), "xAyAz")
    }

    /// The Char production of XML 1.0: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF].
    func testNumericReferenceRange() {
        for v in [0x9, 0xa, 0xd, 0x20, 0x41, 0xd7ff, 0xe000, 0xfffd, 0x10000, 0x10ffff] {
            XCTAssertEqual(dec("&#x" + String(v, radix: 16) + ";"), String(Unicode.Scalar(UInt32(v))!), String(v, radix: 16))
        }
        for v in [0x0, 0x8, 0xb, 0xc, 0xe, 0x1f, 0xd800, 0xdfff, 0xfffe, 0xffff, 0x110000] {
            let e = "#x" + String(v, radix: 16)
            XCTAssertEqual(dec("&" + e + ";"), "ERR invalid character reference &" + e + ";")
        }
        XCTAssertEqual(dec("&#-1;"), "ERR invalid character reference &#-1;")
        XCTAssertEqual(dec("&#;"), "ERR invalid character reference &#;")
    }

    func testIndexOf() {
        XCTAssertEqual(XML.index(of: [2, 3], in: [1, 2, 3], from: 1), 1, "a match ending at the end")
        XCTAssertEqual(XML.index(of: [1], in: [1, 2], from: 0), 0)
        XCTAssertEqual(XML.index(of: [2, 3], in: [2, 9, 2, 3], from: 0), 2, "a partial match is no match")
        XCTAssertEqual(XML.index(of: [2, 3], in: [1, 2, 2, 3], from: 0), 2)
        XCTAssertNil(XML.index(of: [2, 3], in: [2, 9], from: 0))
        XCTAssertNil(XML.index(of: [9], in: [1], from: 0))
        XCTAssertNil(XML.index(of: [1], in: [1], from: 5), "past the end")
        XCTAssertNil(XML.index(of: [1], in: [1], from: -1))
        XCTAssertNil(XML.index(of: [], in: [1], from: 0))
    }

    func testHasPrefix() {
        XCTAssertTrue(XML.hasPrefix(b("<!--"), 0, "<!--"), "a prefix reaching the end")
        XCTAssertTrue(XML.hasPrefix(b("x<!--"), 1, "<!--"))
        XCTAssertFalse(XML.hasPrefix(b("<"), 0, "<!--"), "shorter than the prefix")
    }
}
