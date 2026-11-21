import XCTest
import AtlasPCAVerify
import AtlasPCAPairing // NOT @testable: the public surface alone

/// The reference's flat names of the aggsig and ABE packages (`SIG_DST`, `POP_DST`, `Attr`).
final class ReferenceNamesPairingTests: XCTestCase {
    func testAggsigTags() {
        XCTAssertEqual(Aggsig.SIG_DST, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
        XCTAssertEqual(Aggsig.POP_DST, "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
    }

    func testAttributeTokens() {
        XCTAssertEqual(Abe.Attr.holder("k"), "holder:k")
        XCTAssertEqual(Abe.Attr.verb("read"), "verb:read")
        XCTAssertEqual(Abe.Attr.resource("doc/*"), "resource:doc/*")
        XCTAssertEqual(Abe.Attr.scope("admin"), "scope:admin")
        XCTAssertEqual(Abe.Attr.act("read", "doc/*"), #"act:["read","doc/*"]"#)
        XCTAssertEqual(Abe.Attr.act("a\"b", "\u{e9}"), "act:[\"a\\\"b\",\"\u{e9}\"]", "JSON.stringify escaping, no \\u escapes for non-ASCII")
    }
}
