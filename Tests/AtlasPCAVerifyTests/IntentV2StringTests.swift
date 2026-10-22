import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Unit tests for IntentV2.actionString / jsString (ECMAScript String(p.action?.<k>) / String(v)): every branch.
final class IntentV2StringTests: XCTestCase {
    func testJsStringEveryCase() {
        XCTAssertEqual(IntentV2.jsString(.null), "null")
        XCTAssertEqual(IntentV2.jsString(.bool(true)), "true")
        XCTAssertEqual(IntentV2.jsString(.bool(false)), "false")
        XCTAssertEqual(IntentV2.jsString(.int(0)), "0")
        XCTAssertEqual(IntentV2.jsString(.int(5)), "5")
        XCTAssertEqual(IntentV2.jsString(.int(-7)), "-7")
        XCTAssertEqual(IntentV2.jsString(.int(9_007_199_254_740_991)), "9007199254740991")
        XCTAssertEqual(IntentV2.jsString(.double(0)), "0")
        XCTAssertEqual(IntentV2.jsString(.double(-0.0)), "0") // String(-0) is "0"
        XCTAssertEqual(IntentV2.jsString(.double(1)), "1")
        XCTAssertEqual(IntentV2.jsString(.double(2)), "2")
        XCTAssertEqual(IntentV2.jsString(.double(1.5)), "1.5")
        XCTAssertEqual(IntentV2.jsString(.double(-2.25)), "-2.25")
        XCTAssertEqual(IntentV2.jsString(.double(100)), "100")
        XCTAssertEqual(IntentV2.jsString(.double(0.1)), "0.1")
        XCTAssertEqual(IntentV2.jsString(.string("abc")), "abc")
        XCTAssertEqual(IntentV2.jsString(.string("")), "")
        XCTAssertEqual(IntentV2.jsString(.string("null")), "null")
        XCTAssertEqual(IntentV2.jsString(.array([])), "")
        XCTAssertEqual(IntentV2.jsString(.array([.int(1), .string("a"), .bool(true)])), "1,a,true")
        // null elements are EMPTY (not "null"), also first / last / alone
        XCTAssertEqual(IntentV2.jsString(.array([.null])), "")
        XCTAssertEqual(IntentV2.jsString(.array([.null, .null])), ",")
        XCTAssertEqual(IntentV2.jsString(.array([.null, .string("x"), .null])), ",x,")
        XCTAssertEqual(IntentV2.jsString(.array([.string("x"), .null, .string("y")])), "x,,y")
        // nested arrays join recursively; an object element is "[object Object]"
        XCTAssertEqual(IntentV2.jsString(.array([.array([.int(1), .int(2)]), .array([.int(3)])])), "1,2,3")
        XCTAssertEqual(IntentV2.jsString(.array([.array([.null, .string("a")]), .string("b")])), ",a,b")
        XCTAssertEqual(IntentV2.jsString(.array([.array([])])), "")
        XCTAssertEqual(IntentV2.jsString(.array([.object([:]), .int(1)])), "[object Object],1")
        XCTAssertEqual(IntentV2.jsString(.object([:])), "[object Object]")
        XCTAssertEqual(IntentV2.jsString(.object([JKey("a"): .int(1)])), "[object Object]")
    }

    func testActionStringEveryBranch() {
        let p: JObject = [JKey("action"): .object([JKey("verb"): .string("air.book"), JKey("resource"): .null, JKey("n"): .int(3),
                                                    JKey("z"): .double(-0.0), JKey("a"): .array([.null, .string("p")]), JKey("o"): .object([:]),
                                                    JKey("e"): .string("")])]
        XCTAssertEqual(IntentV2.actionString(p, "verb"), "air.book")
        XCTAssertEqual(IntentV2.actionString(p, "resource"), "null") // a present null is String(null), not "undefined"
        XCTAssertEqual(IntentV2.actionString(p, "n"), "3")
        XCTAssertEqual(IntentV2.actionString(p, "z"), "0")
        XCTAssertEqual(IntentV2.actionString(p, "a"), ",p")
        XCTAssertEqual(IntentV2.actionString(p, "o"), "[object Object]")
        XCTAssertEqual(IntentV2.actionString(p, "e"), "") // a present empty string is not "undefined"
        XCTAssertEqual(IntentV2.actionString(p, "missing"), "undefined")
        XCTAssertEqual(IntentV2.actionString(p, ""), "undefined")
        // no action / an action that is not an object
        XCTAssertEqual(IntentV2.actionString([:], "verb"), "undefined")
        XCTAssertEqual(IntentV2.actionString([JKey("action"): .null], "verb"), "undefined")
        XCTAssertEqual(IntentV2.actionString([JKey("action"): .string("verb")], "verb"), "undefined")
        XCTAssertEqual(IntentV2.actionString([JKey("action"): .array([.string("v")])], "verb"), "undefined")
        XCTAssertEqual(IntentV2.actionString([JKey("action"): .int(1)], "verb"), "undefined")
        // only the action's own member counts, never a top-level one
        XCTAssertEqual(IntentV2.actionString([JKey("verb"): .string("top"), JKey("action"): .object([:])], "verb"), "undefined")
    }
}
