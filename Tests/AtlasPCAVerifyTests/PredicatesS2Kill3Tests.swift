import XCTest
@testable import AtlasPCAVerify

/// showValue spells a string out unless it is long or holds a control character, quote, backslash or surrogate
/// (predicates.ts:623: /[\u0000-\u001f"\\\ud800-\udfff]/); U+FFFF is none of those.
final class S2G3PredicatesKillTests: XCTestCase {
    func testTheLastBasicMultilingualPlaneCodePointIsPlain() {
        let ffff = String(Unicode.Scalar(0xFFFF as UInt32)!), fffe = String(Unicode.Scalar(0xFFFE as UInt32)!)
        XCTAssertEqual(Predicates.showValue(JSONValue.string("a" + ffff + "b")), "\"a" + ffff + "b\"")
        XCTAssertEqual(Predicates.showValue(JSONValue.string(fffe)), "\"" + fffe + "\"")
    }

    func testAnAstralCharacterIsASurrogatePairInTheReference() {
        XCTAssertEqual(Predicates.showValue(JSONValue.string("a\u{10000}")), "\"...\"")
    }
}
