import XCTest
@testable import AtlasPCAVerify

/// The RIM XML reader over documents, and the inclusive canonical form. The profile violations are the reference's words
/// (assertStrictProfile, packages/pca/src/attest-nvidia-rim.ts:101); the canonical form is W3C C14N, which xml-crypto renders there.
final class AttestXMLK05ParseTests: XCTestCase {
    func err(_ s: String) -> String? {
        do {
            _ = try XML.parse(s)
            return nil
        } catch { return (error as? AttestError)?.message ?? "?" }
    }

    func text(_ s: String) throws -> String { try XML.parse(s).root?.textContent() ?? "<no root>" }

    func canon(_ s: String) throws -> String { XML.canonicalize(try XML.parse(s).root!, [:], nil) }

    func testPrefixBinding() throws {
        XCTAssertEqual(try XML.parse("<a/>").root?.name, "a", "no prefix needs no default namespace")
        XCTAssertEqual(err("<p:a/>"), "namespace prefix p is not bound")
    }

    func testCommentsAndInstructionsAreSkippedAndRecorded() throws {
        let c = "<a><!--x-->b</a>"
        XCTAssertEqual(try text(c), "b")
        XCTAssertEqual(try XML.parse(c).violation, "XML comments are not permitted")
        let p = "<a><?pi?>b</a>"
        XCTAssertEqual(try text(p), "b")
        XCTAssertEqual(try XML.parse(p).violation, "XML processing instructions are not permitted")
    }

    func testCData() throws {
        XCTAssertEqual(try text("<a>0123456789<![CDATA[abc]]>d</a>"), "0123456789abcd")
        XCTAssertEqual(try text("<a><![CDATA[]]></a>"), "")
    }

    func testDoctypeIsSkippedAndRecorded() throws {
        for d in [#"<!DOCTYPE a><a/>"#, #"<!DOCTYPE a [<!ENTITY x "y">]><a/>"#, #"<!DOCTYPE a [[]>]><a/>"#] {
            let doc = try XML.parse(d)
            XCTAssertEqual(doc.violation, "DTD / DOCTYPE is not permitted", d)
            XCTAssertEqual(doc.root?.name, "a", d)
        }
        XCTAssertEqual(err("<!DOCTYPE a"), "unterminated DOCTYPE")
    }

    func testStartTagRefusals() {
        let rows: [(String, String)] = [
            ("<a", "unterminated start tag"),
            ("<a ", "unterminated start tag"),
            ("<a/", "malformed start tag"),
            ("<a/x>", "malformed start tag"),
            ("<a b", "malformed attribute"),
            ("<a b ", "malformed attribute"),
            (#"<a b c="1"/>"#, "malformed attribute"),
            (#"<a ="1"/>"#, "malformed attribute"),
            ("<a b=", "unquoted attribute value"),
            ("<a b= ", "unquoted attribute value"),
            ("<a b=x/>", "unquoted attribute value"),
        ]
        for (doc, want) in rows { XCTAssertEqual(err(doc), want, doc) }
    }

    func testAttributeSpacingAndQuotes() throws {
        let r = try XML.parse(#"<a b ="1" c= "2" d = '3' e="&lt;"/>"#).root!
        XCTAssertEqual(r.attr("b"), "1")
        XCTAssertEqual(r.attr("c"), "2")
        XCTAssertEqual(r.attr("d"), "3")
        XCTAssertEqual(r.attr("e"), "<")
    }

    /// C14N: an element in no namespace below a default one must say so; a prefix cannot be unbound, so `xmlns:p=""` renders nothing.
    func testCanonicalNamespaceUndeclarations() throws {
        XCTAssertEqual(try canon(#"<a xmlns="u"><c xmlns=""/></a>"#), #"<a xmlns="u"><c xmlns=""></c></a>"#)
        XCTAssertEqual(try canon(#"<a xmlns=""/>"#), "<a></a>")
        XCTAssertEqual(try canon(#"<a xmlns:p="u"><c xmlns:p=""/></a>"#), #"<a xmlns:p="u"><c></c></a>"#)
    }

    /// Attributes order by (namespace, local name), no-namespace first; a tie keeps document order (a stable sort in the reference too).
    func testCanonicalAttributeOrder() throws {
        XCTAssertEqual(try canon(#"<a xmlns:p="u" z="1" p:y="2" b="3"/>"#), #"<a xmlns:p="u" b="3" z="1" p:y="2"></a>"#)
        XCTAssertEqual(try canon(#"<a xmlns:p="u" xmlns:q="u" q:x="2" p:x="1"/>"#), #"<a xmlns:p="u" xmlns:q="u" q:x="2" p:x="1"></a>"#)
    }
}
