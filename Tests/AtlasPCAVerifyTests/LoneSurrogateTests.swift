import XCTest
import Foundation
@testable import AtlasPCAVerify

/// A lone UTF-16 unit is carried as its own scalar, so two different lone halves are two different values (one shared sentinel would make \udc00 equal \udbff).
final class LoneSurrogateTests: XCTestCase {
    func testDistinctLoneHalvesAreDistinctValues() {
        let low = Canonical.loneScalar(0xDC00), high = Canonical.loneScalar(0xDBFF)
        XCTAssertNotEqual(low, high)
        XCTAssertNotEqual(String(low), String(high))
        XCTAssertEqual(Canonical.loneUnit(low), 0xDC00)
        XCTAssertEqual(Canonical.loneUnit(high), 0xDBFF)
        XCTAssertTrue(Canonical.hasLoneSurrogate("a" + String(low)))
        XCTAssertTrue(Canonical.hasLoneSurrogate("a" + String(high)))
        XCTAssertFalse(Canonical.hasLoneSurrogate("a\u{1F600}\u{10FFFF}"), "a real astral character and U+10FFFF are not lone halves")
        XCTAssertNil(Canonical.loneUnit("a"))
    }

    func testTheYamlWriterEscapesEachHalfAsItself() throws {
        let low = JSONValue.string("x" + String(Canonical.loneScalar(0xDC00)))
        let high = JSONValue.string("x" + String(Canonical.loneScalar(0xDBFF)))
        XCTAssertEqual(try YamlEmit.stringify(.object(["k": low])), "k: \"x\\udc00\"\n")
        XCTAssertEqual(try YamlEmit.stringify(.object(["k": high])), "k: \"x\\udbff\"\n")
    }

    func testTheCorpusReaderKeepsEachUnit() {
        let v = Base.resolveSeeds(.object(["$utf16": .array([.int(0xDC00), .int(0x61), .int(0xDBFF), .int(0xD83D), .int(0xDE00)])]))
        let scalars = Array((v.asString ?? "").unicodeScalars)
        XCTAssertEqual(scalars.count, 4)
        XCTAssertEqual(Canonical.loneUnit(scalars[0]), 0xDC00)
        XCTAssertEqual(scalars[1], "a")
        XCTAssertEqual(Canonical.loneUnit(scalars[2]), 0xDBFF)
        XCTAssertEqual(scalars[3], "\u{1F600}")
    }

    func testTheAuthoringLoaderRewritesEachHalfToItsOwnScalar() {
        let (yaml, _) = ActionsText.rewriteSurrogateEscapes("k: \"\\udc00\\udbff\\ud83d\\ude00\"\n")
        XCTAssertEqual(yaml, "k: \"\\U000FDC00\\U000FDBFF\\U0001F600\"\n")
    }
}
