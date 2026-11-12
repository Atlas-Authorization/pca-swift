import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the ToolSchema.swift survivors of group 2. Pinned to packages/pca/src/agent-native.ts (checkValue :520, evaluateToolSchema).
final class S2G2ToolSchemaKillTests: XCTestCase {
    private let boolSpec: JObject = ["type": .string("boolean")]

    func testIsIntRefusesNonNumbers() {
        XCTAssertFalse(ToolSchema.isInt(nil), "line 44")
        XCTAssertFalse(ToolSchema.isInt(.string("3")), "line 44")
        XCTAssertFalse(ToolSchema.isInt(.bool(true)), "line 44")
        XCTAssertFalse(ToolSchema.isInt(.null), "line 44")
        XCTAssertTrue(ToolSchema.isInt(.int(3)))
        XCTAssertTrue(ToolSchema.isInt(.double(3.0)))
        XCTAssertFalse(ToolSchema.isInt(.double(3.5)))
        XCTAssertFalse(ToolSchema.isInt(.double(-0.0)))
    }

    func testJsEqNeverEqualsAcrossKinds() {
        XCTAssertFalse(ToolSchema.jsEq(.bool(true), .string("true")), "line 63")
        XCTAssertFalse(ToolSchema.jsEq(.string("x"), .bool(false)), "line 63")
        XCTAssertFalse(ToolSchema.jsEq(.bool(true), .null), "line 63")
        XCTAssertFalse(ToolSchema.jsEq(.null, .bool(true)), "line 63")
        XCTAssertFalse(ToolSchema.jsEq(.null, .null), "line 65")
        XCTAssertFalse(ToolSchema.jsEq(nil, nil), "line 65")
        XCTAssertFalse(ToolSchema.jsEq(.string("a"), .null), "line 65")
        XCTAssertFalse(ToolSchema.jsEq(.array([]), .array([])), "line 65")
        XCTAssertTrue(ToolSchema.jsEq(.bool(true), .bool(true)))
        XCTAssertTrue(ToolSchema.jsEq(.string("a"), .string("a")))
        XCTAssertTrue(ToolSchema.jsEq(.int(1), .double(1.0)))
        XCTAssertFalse(ToolSchema.jsEq(.int(1), .string("1")))
        XCTAssertFalse(ToolSchema.jsEq(.int(1), .bool(true)))
    }

    func testSafeNameClassBoundaries() {
        for g in ["A", "Z", "a", "z", "0", "9", "_", "aZ09_"] { XCTAssertTrue(ToolSchema.safeName(g), "\(g) (line 77)") }
        for b in ["@", "[", "`", "{", "/", ":", "-", "", " ", "é"] { XCTAssertFalse(ToolSchema.safeName(b), "\(b) (line 77)") }
        XCTAssertTrue(ToolSchema.safeName(String(repeating: "a", count: 64)))
        XCTAssertFalse(ToolSchema.safeName(String(repeating: "a", count: 65)))
    }

    func testValueNodeBudgetBoundary() {
        let atLimit = ToolSchema.Counter()
        atLimit.n = 9999
        XCTAssertNil(ToolSchema.checkValue(boolSpec, .bool(true), "p", 2, atLimit), "the 10000th node is still allowed (line 20 / 176)")
        XCTAssertEqual(atLimit.n, 10000)
        let over = ToolSchema.Counter()
        over.n = 10000
        XCTAssertEqual(ToolSchema.checkValue(boolSpec, .bool(true), "p", 2, over), "p: too many values", "the 10001st node is refused (line 20 / 176)")
    }

    func testSchemaNodeBudgetBoundary() {
        let atLimit = ToolSchema.Counter()
        atLimit.n = 255
        XCTAssertNil(ToolSchema.objectSchemaError(.object([:]), nil, 1, atLimit), "the 256th schema node is allowed (line 115)")
        let over = ToolSchema.Counter()
        over.n = 256
        XCTAssertEqual(ToolSchema.objectSchemaError(.object([:]), nil, 1, over), "schema too large")
    }

    func testValueDepthBoundary() {
        XCTAssertNil(ToolSchema.checkValue(boolSpec, .bool(true), "p", 9, ToolSchema.Counter()), "depth 9 = MAX_SCHEMA_DEPTH + 1 is allowed (line 174)")
        XCTAssertEqual(ToolSchema.checkValue(boolSpec, .bool(true), "p", 10, ToolSchema.Counter()), "p: too deep", "depth 10 is refused (line 174)")
    }

    func testValueNodesAreCounted() {
        let c = ToolSchema.Counter()
        XCTAssertNil(ToolSchema.checkValue(boolSpec, .bool(true), "p", 2, c))
        XCTAssertEqual(c.n, 1, "line 175: one node per value")
        let arr: JObject = ["type": .string("array"), "items": .object(boolSpec)]
        let c2 = ToolSchema.Counter()
        XCTAssertNil(ToolSchema.checkValue(arr, .array([.bool(true), .bool(false), .bool(true)]), "p", 2, c2))
        XCTAssertEqual(c2.n, 4, "line 175: the array plus its three items")
    }

    func testArrayItemsAreOneDeeper() {
        let arr: JObject = ["type": .string("array"), "items": .object(boolSpec)]
        let one = JSONValue.array([.bool(true)])
        XCTAssertEqual(ToolSchema.checkValue(arr, one, "p", 9, ToolSchema.Counter()), "p[0]: too deep", "line 189: the item is at depth + 1 (not - 1, not + 0)")
        XCTAssertNil(ToolSchema.checkValue(arr, one, "p", 8, ToolSchema.Counter()), "line 189: the item at depth 9 is allowed (not + 2)")
    }

    func testObjectMembersAreOneDeeper() {
        let props: JObject = ["a": .object(boolSpec)]
        let obj: JObject = ["a": .bool(true)]
        XCTAssertEqual(ToolSchema.checkObject(props, nil, obj, "p", 9, ToolSchema.Counter()), "p.a: too deep", "line 220: the member is at depth + 1 (not - 1, not + 0)")
        XCTAssertNil(ToolSchema.checkObject(props, nil, obj, "p", 8, ToolSchema.Counter()))
    }

    // ---- evaluate: fail-closed values ----

    private func digest(_ v: JSONValue) -> String { IV.strictHash(v)! }

    private func caveat(tool: String, schema: JSONValue) -> JSONValue {
        .object(["type": .string("tool_schema"), "tool": .string(tool), "schema": schema, "schema_digest": .string("x"), "binding_digest": .string("y")])
    }

    func testEvaluationErrorWhenTheSchemaCannotBeHashed() {
        // type number with const -0 passes schema validation but is not strict-canonical.
        let schema = JSONValue.object(["props": .object(["a": .object(["type": .string("number"), "const": .double(-0.0)])])])
        XCTAssertNil(ToolSchema.validateArgSchema(schema))
        let r = ToolSchema.evaluate(caveat(tool: "t", schema: schema), PCA.ToolCall(tool: "t", args: .object([:])))
        XCTAssertFalse(r.ok, "line 231")
        XCTAssertEqual(r.reason, "evaluation error (fail closed)")
    }

    func testEvaluationErrorWhenTheBindingCannotBeHashed() {
        // the schema hashes, the binding (which also carries the tool name) does not: U+FDD0 marks a lone surrogate.
        let schema = JSONValue.object(["props": .object([:])])
        var c: JObject = ["type": .string("tool_schema"), "tool": .string("t" + String(Unicode.Scalar(0xFDD0)!)), "schema": schema, "schema_digest": .string(digest(schema)),
                          "binding_digest": .string("y")]
        c["signature_digest"] = .string("s")
        let r = ToolSchema.evaluate(.object(c), PCA.ToolCall(tool: "t", args: .object([:])))
        XCTAssertFalse(r.ok, "line 236")
        XCTAssertEqual(r.reason, "evaluation error (fail closed)")
    }
}
