import XCTest
@testable import AtlasPCAVerify

/// `pca-need` scopes follow JS `\s` (pca-need.ts:69); the push token compare (a2a-auth.ts:273-278).
final class A2aScopeTokenTests: XCTestCase {
    private func err(_ scope: String) -> String? {
        A2a.needError(.object(["v": .int(1), "kind": .string("scope"), "verb": .string("v"), "resource": .string("r"), "scopes": .array([.string(scope)])]))
    }

    func testScopeWhitespaceIsJS() {
        XCTAssertNil(err("ab"))
        for ws in ["\u{FEFF}", "\u{A0}", " ", "\t", "\n", "\u{2028}", "\u{2029}", "\u{3000}", "\u{1680}", "\u{2000}", "\u{200A}", "\u{202F}", "\u{205F}", "\u{0B}", "\u{0C}", "\r"] {
            XCTAssertEqual(err("a\(ws)b"), "bad_field", "U+\(String(ws.unicodeScalars.first!.value, radix: 16))")
        }
        // not whitespace in JS: U+0085 and U+200B
        XCTAssertNil(err("a\u{85}b"))
        XCTAssertNil(err("a\u{200B}b"))
    }

    func testConstantTimeEq() {
        XCTAssertTrue(A2a.constantTimeEq("", ""))
        XCTAssertTrue(A2a.constantTimeEq("abc", "abc"))
        XCTAssertFalse(A2a.constantTimeEq("abc", "abd"))
        XCTAssertFalse(A2a.constantTimeEq("abc", "xbc"))
        XCTAssertFalse(A2a.constantTimeEq("abc", "ab"))
        XCTAssertFalse(A2a.constantTimeEq("ab", "abc"))
        XCTAssertFalse(A2a.constantTimeEq("\u{e9}", "e\u{301}")) // code units, not canonical equivalence
    }
}
