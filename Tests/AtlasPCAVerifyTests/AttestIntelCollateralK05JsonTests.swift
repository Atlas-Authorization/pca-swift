import XCTest
@testable import AtlasPCAVerify

/// The source text of the signed value: `^\s*\{\s*"<name>"\s*:\s*` then string-aware brace matching (attest-intel-collateral.ts:219-236).
final class AttestIntelCollateralK05JsonTests: XCTestCase {
    private typealias C = IntelCollateral

    func testAsciiWhitespace() {
        for b: UInt8 in [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20] { XCTAssertEqual(C.skipJSSpace([b, 0x7b], 0), 1, "\(b)") }
        XCTAssertEqual(C.skipJSSpace([0x41], 0), 0)
        XCTAssertEqual(C.skipJSSpace([], 0), 0)
        XCTAssertEqual(C.skipJSSpace([0x7b, 0x20, 0x7b], 1), 2)
    }

    func testMultibyteWhitespace() {
        XCTAssertEqual(C.skipJSSpace([0xc2, 0xa0, 0x7b], 0), 2) // U+00A0
        XCTAssertEqual(C.skipJSSpace([0xc2, 0xa0], 0), 2)
        XCTAssertEqual(C.skipJSSpace([0xe2, 0x80, 0x80, 0x7b], 0), 3) // U+2000
        XCTAssertEqual(C.skipJSSpace([0xef, 0xbb, 0xbf, 0x7b], 0), 3) // U+FEFF
        XCTAssertEqual(C.skipJSSpace([0x20, 0xc2, 0xa0, 0x20, 0x7b], 0), 4)
    }

    func testMultibyteNonWhitespaceAndTruncation() {
        XCTAssertEqual(C.skipJSSpace([0xc2, 0xa1, 0x7b], 0), 0) // U+00A1
        XCTAssertEqual(C.skipJSSpace([0xe2, 0x80], 0), 0)
        XCTAssertEqual(C.skipJSSpace([0xc2], 0), 0)
    }

    private func raw(_ s: String) -> String? { C.rawJSONObject(Array(s.utf8), "n").map { String(decoding: $0, as: UTF8.self) } }

    func testTheLeadingStructureIsRequired() {
        XCTAssertNil(raw(#"x"n":{}"#))
        XCTAssertNil(raw(#"{"m":{}}"#))
        XCTAssertNil(raw(#"{"n"x{}}"#))
        XCTAssertNil(raw(#"{"n":[{}]}"#))
    }

    func testTextEndingAtEachStep() {
        for s in ["", "   ", #"{"#, #"{""#, #"{"n"#, #"{"n""#, #"{"n":"#, #"{"n":{"#, #"{"n":{"a":"}"#] { XCTAssertNil(raw(s), s) }
    }

    func testTheValueIsTheExactSource() {
        XCTAssertEqual(raw(#" { "n" : { "a" : 1 } , "signature":"x"}"#), #"{ "a" : 1 }"#)
    }

    func testStringsHideBraces() {
        XCTAssertEqual(raw(#"{"n":{"a":"}"}}"#), #"{"a":"}"}"#)
    }

    func testAnEscapeSkipsExactlyOneByte() {
        XCTAssertEqual(raw(#"{"n":{"a":"\""}}"#), #"{"a":"\""}"#)
        XCTAssertEqual(raw(#"{"n":{"a":"\"}"}}"#), #"{"a":"\"}"}"#)
    }
}
