import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The version diff compares unit, default, resource id and bindings by value: the order a definition wrote its members in is not a change.
final class ActionDiffKeyOrderTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }

    /// Members given as ordered pairs, so the two definitions really are parsed with different member positions.
    private func ordered(_ pairs: [(String, JSONValue)]) -> JSONValue {
        var o: JObject = [:]
        for (i, p) in pairs.enumerated() { o[JKey(p.0, ord: Int32(i + 1))] = p.1 }
        return .object(o)
    }

    private func def(unit: JSONValue, id: JSONValue, bindings: JSONValue) -> JObject {
        ["v": .int(1), "kind": s("pca-action-def"), "verb": s("a.pay"), "title": s("t"), "effects": .array([s("pay")]),
         "resource": .object(["type": s("t"), "id": id, "scope": s("one")]),
         "params": .object(["amount": .object(["type": s("integer"), "min": .int(0), "max": .int(10), "unit": unit, "default": ordered([("a", .int(1)), ("b", .int(2))])])]),
         "bindings": bindings, "review": .object(["state": s("authored")])]
    }

    func testReversedKeysAreNotAChange() throws {
        let u1 = ordered([("kind", s("money")), ("ccy", s("usd")), ("exp", .int(2))])
        let u2 = ordered([("exp", .int(2)), ("ccy", s("usd")), ("kind", s("money"))])
        let i1 = ordered([("prefix", s("p_")), ("class", s("any_safe"))])
        let i2 = ordered([("class", s("any_safe")), ("prefix", s("p_"))])
        let b1 = ordered([("x", ordered([("p", .int(1)), ("q", .int(2))])), ("y", .array([.int(1), .int(2)]))])
        let b2 = ordered([("y", .array([.int(1), .int(2)])), ("x", ordered([("q", .int(2)), ("p", .int(1))]))])
        let r = try ActionDiff.diffDefs(def(unit: u1, id: i1, bindings: b1), def(unit: u2, id: i2, bindings: b2))
        XCTAssertEqual(r.get("class"), s("equal"), JS.stringify(r))
        XCTAssertEqual(r.get("reasons"), .array([]), JS.stringify(r))
    }

    func testAReorderedArrayStillIsAChange() throws {
        let u = ordered([("kind", s("money"))])
        let i = ordered([("prefix", s("p_"))])
        let r = try ActionDiff.diffDefs(def(unit: u, id: i, bindings: .object(["y": .array([.int(1), .int(2)])])),
                                        def(unit: u, id: i, bindings: .object(["y": .array([.int(2), .int(1)])])))
        XCTAssertNotEqual(r.get("class"), s("equal"), JS.stringify(r))
    }
}
