import XCTest
@testable import AtlasPCAVerify

/// The JSON.parse wording the token verifiers embed in their reason: V8's messages and its JsonParser::CalculateFileLocation
/// (a CR LF pair is one line terminator; the column is 1-based).
final class AttestJWSK05V8Tests: XCTestCase {
    func testValidDocumentsHaveNoError() {
        for d in ["{\"a\":1,\"b\":2}", "[{\"a\":1},1]", "[[],1]", "[]", "[1]", "[1,2]", "[[1],2]"] { XCTAssertEqual(V8JSON.error(d), "", d) }
    }

    func testATrailingCommaInAnObject() {
        XCTAssertEqual(V8JSON.error("{\"a\":1,}"), "Expected double-quoted property name in JSON at position 7 (line 1 column 8)")
    }

    func testLineAndColumn() {
        let name = "Expected property name or '}' in JSON at position "
        XCTAssertEqual(V8JSON.error("{x\n"), name + "1 (line 1 column 2)", "a line break after the error does not count")
        XCTAssertEqual(V8JSON.error("\n{x"), name + "2 (line 2 column 2)")
        XCTAssertEqual(V8JSON.error("\r{x"), name + "2 (line 2 column 2)")
        XCTAssertEqual(V8JSON.error("\r\n{x"), name + "3 (line 2 column 2)")
        XCTAssertEqual(V8JSON.error(" \r\n{x"), name + "4 (line 2 column 2)")
        XCTAssertEqual(V8JSON.error("{\r\n"), name + "3 (line 2 column 1)")
        XCTAssertEqual(V8JSON.error("{\r"), name + "2 (line 2 column 1)")
    }

    func testALineBreakAtTheErrorPositionDoesNotCount() {
        XCTAssertEqual(V8JSON.error("\"a\nb\""), "Bad control character in string literal in JSON at position 2 (line 1 column 3)")
    }
}
