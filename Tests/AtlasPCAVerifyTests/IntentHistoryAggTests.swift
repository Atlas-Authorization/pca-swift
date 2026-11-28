import XCTest
@testable import AtlasPCAVerify

/// accPost refuses an agg outside sum / count / max / distinct FIRST, selected or not, keyed or not (TS 80ad8c7ff, 'accPost: unknown
/// agg'; nil is the throw here). Before, an unknown agg read as distinct in the pre-state.
final class IntentHistoryAggTests: XCTestCase {
    static let T: Int64 = 1_000_000
    static let SUM: JObject = ["id": .string("spend"), "agg": .string("sum"), "val": .string("action.params.total"),
                               "sel": .object(["verbs": .array([.string("pay")])]), "win": .object(["kind": .string("task")]),
                               "key": .null, "holder": .object(["kind": .string("site_local")])]
    static let H: [JSONValue] = [.object(["id": .string("e1"), "verb": .string("pay"), "resource": .string("r"),
                                          "params": .object(["total": .int(10), "k": .string("x"), "to": .string("p")]),
                                          "t": .int(T), "status": .string("committed")])]
    func post(_ a: JObject, _ verb: String, _ params: JObject) -> Double? { IntentHistory.accPost(a, Self.H, verb, params, .int(Self.T), nil) }

    func testKnownAggControl() {
        XCTAssertEqual(post(Self.SUM, "pay", ["total": .int(5)]), 15)
        XCTAssertEqual(post(Self.SUM, "look", ["total": .int(5)]), 10)
        var keyed = Self.SUM; keyed["key"] = .string("action.params.k")
        XCTAssertEqual(post(keyed, "pay", ["total": .int(5), "k": .string("x")]), 15)
    }

    func testUnknownAggIsRefusedSelectedOrNotKeyedOrNot() {
        for agg: JSONValue? in [.string("SUM"), .string("tVm"), .string(""), .string("avg"), .null, .int(1), nil] {
            var bad = Self.SUM; bad["agg"] = agg
            for verb in ["pay", "look"] { XCTAssertNil(post(bad, verb, ["total": .int(5)]), "\(String(describing: agg)) \(verb)") }
            bad["key"] = .string("action.params.k")
            XCTAssertNil(post(bad, "pay", ["total": .int(5)]), "\(String(describing: agg)) keyed")
        }
    }
}
