import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Runs FIRST for AttestXML.swift mutants (class name sorts before every other *AttestXML* class). Every parse goes through a deadline:
/// the original finishes in milliseconds, a mutant that stops a scan loop advancing fails the deadline, a changed scan fails the values.
final class A0DeadlineAttestXMLTests: XCTestCase {
    private struct Summary: Equatable {
        var root: String, attrs: [String], decls: Int, kids: [String], ns: [String], text: String, violation: String
    }

    private func summarize(_ src: String, _ secs: Double = 10) -> Summary? {
        S2Deadline.within(secs, "XML.parse") { () -> Summary? in
            guard let d = try? XML.parse(src), let r = d.root else { return nil }
            let kids = r.elementChildren()
            return Summary(root: r.name, attrs: r.attrs.map { "\($0.name)=\($0.value)" }, decls: r.decls.count, kids: kids.map { $0.name },
                           ns: [r.ns] + kids.map { $0.ns } + [kids.first?.attr("q") ?? "-"], text: r.textContent(), violation: d.violation)
        } ?? nil
    }

    func testEveryScanLoopAdvancesOnADocumentWithEachConstruct() {
        let src = "  \n<?pi x?><!-- c --><r xmlns=\"urn:d\" xmlns:p=\"urn:p\" a = \"1\" b='2'  p:c=\"3\" ><p:k  q = 'v' > t1 &amp; t2 <![CDATA[<cd>]]></p:k ><e/><e2 /> tail</r  >\n "
        let got = summarize(src, 2) // decode appends per turn: the deadline must fire before the memory cap
        let want = Summary(root: "r", attrs: ["a=1", "b=2", "p:c=3"], decls: 2, kids: ["p:k", "e", "e2"], ns: ["urn:d", "urn:p", "urn:d", "urn:d", "v"],
                           text: " t1 & t2 <cd> tail", violation: "XML processing instructions are not permitted")
        XCTAssertEqual(got, want, "AttestXML.swift parse scan loops (lines 169-274)")
    }

    func testDecodeConsumesPlainBytesAndReferences() {
        // AttestXML.swift line 129: a plain byte advances the cursor (a mutant appends the same byte without bound)
        let got: String? = S2Deadline.within(2, "XML.decode") { () -> String? in
            try? XML.decode(Array("a&amp;b&#x41;c".utf8)[...])
        } ?? nil
        XCTAssertEqual(got, "a&bAc")
    }

    func testDoctypeIsSkippedToItsClosingBracket() {
        let got = summarize("<!DOCTYPE r [<!ELEMENT r ANY> <!ENTITY e \"x\">]><r/>")
        XCTAssertEqual(got?.root, "r", "AttestXML.swift line 217")
        XCTAssertEqual(got?.violation, "DTD / DOCTYPE is not permitted")
    }

    func testCommentSearchStartsRightAfterTheOpener() {
        // `<!---->` is a complete comment: the search for "-->" must start at the opener's end (+4); +5 would miss it
        let ok = summarize("<r><!----></r>")
        XCTAssertEqual(ok?.root, "r", "AttestXML.swift line 201: 4->5")
        XCTAssertEqual(ok?.violation, "XML comments are not permitted")
        // `<!--->` is NOT complete: "-->" overlapping the opener is not a terminator (+3 would accept it)
        let bad: String? = S2Deadline.within(10, "parse <!--->") { () -> String? in
            do { _ = try XML.parse("<r><!---></r>"); return nil } catch { return (error as? AttestError)?.message ?? "\(error)" }
        } ?? nil
        XCTAssertNotNil(bad, "AttestXML.swift line 201: 4->3 accepted an overlapping terminator")
        XCTAssertTrue(bad?.contains("unterminated comment") ?? false, "got \(bad ?? "nil")")
    }

    func testEndTagTrailingSpaceIsTrimmedAndAnUnclosedElementIsRefused() {
        XCTAssertEqual(summarize("<r></r \t>")?.root, "r", "AttestXML.swift line 225")
        let open: String? = S2Deadline.within(10, "parse <r>") { () -> String? in
            do { _ = try XML.parse("<r>"); return nil } catch { return (error as? AttestError)?.message ?? "\(error)" }
        } ?? nil
        XCTAssertTrue(open?.contains("element <r> is not closed") ?? false, "AttestXML.swift line 244: got \(open ?? "nil")")
    }
}
