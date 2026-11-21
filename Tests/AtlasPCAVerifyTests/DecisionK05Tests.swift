import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Rule 20 / 21 limits and character classes, against packages/pca/src/decision.ts and envelope-rules.ts.
final class DecisionK05Tests: XCTestCase {
    func testRanksAreTheReferences() {
        XCTAssertEqual(PCA.DECISION_RANK, ["deny": 0, "escalate": 1, "allow": 2])
    }

    func testDecisionOfNeedsAFailingCheck() {
        XCTAssertEqual(PCA.decisionOf(allow: false, checks: ["a": "pass"], reasons: []), "deny")
        XCTAssertEqual(PCA.decisionOf(allow: false, checks: ["a": "fail"], reasons: ["a: escalate: x"]), "escalate")
    }

    func testUnitParamPathCharacters() {
        for c in ["0", "5", "9", "A", "M", "Z", "a", "m", "z", "_", "-"] { XCTAssertTrue(PCA.isUnitParamPath("action.params." + c), c) }
        for c in ["/", ":", "@", "[", "`", "{", ".", " "] { XCTAssertFalse(PCA.isUnitParamPath("action.params." + c), c) }
    }

    private func tags(_ n: Int) -> JSONValue {
        var m: JObject = [:]
        for i in 0..<n { m[JKey("action.params.p\(i)")] = .object(["kind": .string("k")]) }
        return .object(m)
    }
    private func tag(_ t: JObject) -> JSONValue { .object(["action.params.a": .object(t)]) }

    func testUnitTagLimits() {
        XCTAssertNil(PCA.unitTagsError(tags(64)))
        XCTAssertEqual(PCA.unitTagsError(tags(65)), "units has more than 64 entries")
        let k: JSONValue = .string("k")
        XCTAssertEqual(PCA.unitTagsError(tag(["kind": k, "currency": .int(1)])), "units['action.params.a'].currency must be a string of 1..16 characters")
        XCTAssertEqual(PCA.unitTagsError(tag(["kind": k, "exponent": .string("x")])), "units['action.params.a'].exponent must be an integer in [0, 18]")
        XCTAssertEqual(PCA.unitTagsError(tag(["kind": k, "exponent": .int(19)])), "units['action.params.a'].exponent must be an integer in [0, 18]")
        XCTAssertNil(PCA.unitTagsError(tag(["kind": k, "exponent": .int(18)])))
    }

    func testAPathOfOneSegmentIsNotModelDerived() {
        // with the >= 2 guard gone this reads past the segments: the mutant is a trap, listed in the run errors
        XCTAssertFalse(PCA.isModelDerivedPath("env", []))
        XCTAssertTrue(PCA.isModelDerivedPath("env.class.x", []))
    }

    private func nested(_ depth: Int) -> JSONValue {
        var c: JSONValue = .object(["field": .string("env.class.x")])
        for _ in 0..<depth { c = .object(["all_of": .array([c])]) }
        return .array([.object(["where": .array([c])])])
    }

    func testPathCollectionStopsBelowDepth64() {
        XCTAssertEqual(PCA.modelPathsRead([nested(64)]), ["env.class.x"])
        XCTAssertEqual(PCA.modelPathsRead([nested(65)]), [])
    }

    func testSameTagComparesEveryMember() {
        XCTAssertTrue(PCA.sameTag(["kind": .string("a")], ["kind": .string("a")]))
        XCTAssertFalse(PCA.sameTag(["kind": .string("a")], ["kind": .string("b")]))
        XCTAssertFalse(PCA.sameTag(["kind": .string("a"), "currency": .string("USD")], ["kind": .string("a")]))
    }

    private func units(_ verb: JSONValue?) -> (ok: Bool, reason: String) {
        var p: JObject = ["where": .array([.object(["field": .string("action.params.a"), "op": .string("eq"), "value": .int(1)])])]
        if let v = verb { p["verb"] = v }
        return PCA.decideUnits(.object(["units": .object([:]), "verb": .string("v"), "schema_units": .object(["u": .object(["kind": .string("money")])]),
                                        "verb_params": .object(["action.params.a": .object(["unit": .string("u")])]), "predicates": .array([.array([.object(p)])])]))
    }

    func testVerbScope() {
        let refused = "a policy term reads 'action.params.a' (money) without a unit tag"
        XCTAssertEqual(units(.string("v")).reason, refused)
        XCTAssertEqual(units(.string("*")).reason, refused)
        XCTAssertEqual(units(.array([.string("v")])).reason, refused)
        XCTAssertTrue(units(.array([.int(1)])).ok)
        XCTAssertTrue(units(nil).ok)
        XCTAssertTrue(units(.int(1)).ok)
    }

    func testTheFirstUntaggedPathInByteOrderIsReported() {
        // read from a Set: 40 paths make an unsorted answer land on the first one about once in 40 runs
        var declared: JObject = [:]
        var terms: [JSONValue] = []
        for i in 0..<40 {
            let path = "action.params.p" + String(100 + i)
            declared[JKey(path)] = .object(["unit": .string("u")])
            terms.append(.object(["field": .string(path), "op": .string("eq"), "value": .int(1)]))
        }
        let r = PCA.decideUnits(.object(["units": .object([:]), "verb": .string("v"), "schema_units": .object(["u": .object(["kind": .string("money")])]),
                                         "verb_params": .object(declared),
                                         "predicates": .array([.array([.object(["verb": .string("v"), "where": .array(terms)])])])]))
        XCTAssertEqual(r.reason, "a policy term reads 'action.params.p100' (money) without a unit tag")
    }
}
