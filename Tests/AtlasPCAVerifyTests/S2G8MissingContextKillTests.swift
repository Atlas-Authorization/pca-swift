import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kill tests (mutation sheet swift-k05 group 8) for MissingContext.swift: supplier-table paths, the flattening depth of a supplied
/// context, the action.params scaffolding of a merge, and what `decideWithMissing` calls ill-typed.
final class S2G8MissingContextKillTests: XCTestCase {
    private func ok(_ key: String) -> Bool { MissingContext.supplierTableError(.object([JKey(key): .string("principal")])) == nil }

    // ---------------------------------------------------------------- supplier paths (lines 43, 44, 51, 52)

    func testIdentifierFirstCharacter() {
        for c in ["A", "Z", "a", "z", "_"] { XCTAssertTrue(ok("env." + c), "line 43 '\(c)' may start an identifier") }
        for c in ["@", "[", "`", "{", "^", "0", "9", "-", "/"] { XCTAssertFalse(ok("env." + c), "line 43 '\(c)' may not start an identifier") }
        XCTAssertFalse(ok("env."), "line 43 an empty segment")
        XCTAssertFalse(ok("env..a"))
        XCTAssertFalse(ok("env.a."))
    }

    func testIdentifierRestCharacters() {
        for c in ["0", "9", "A", "Z", "a", "z", "_"] { XCTAssertTrue(ok("env.a" + c), "line 44 '\(c)' may continue an identifier") }
        for c in ["/", ":", "@", "[", "`", "{", "-", " ", "^"] { XCTAssertFalse(ok("env.a" + c), "line 44 '\(c)' may not continue an identifier") }
    }

    func testPathPrefixes() {
        for k in ["env", "subject", "env.x", "subject.x.y", "action.params", "action.params.x", "action.params.x.y2"] { XCTAssertTrue(ok(k), k) }
        for k in ["action", "action.foo", "action.foo.x", "foo.params.x", "foo", "params.x", "action.params.1x", "action.params.__proto__",
                  "env.constructor", "env.a.prototype", "subject.__proto__"] {
            XCTAssertFalse(ok(k), k)
        }
    }

    func testSupplierValuesAreChecked() {
        XCTAssertEqual(MissingContext.supplierTableError(.object(["env.x": .string("nobody")])), "bad supplier for 'env.x'")
        XCTAssertEqual(MissingContext.supplierTableError(.object(["env.1": .string("principal")])), "bad supplier path 'env.1'")
        XCTAssertNil(MissingContext.supplierTableError(.object([:])))
        XCTAssertEqual(MissingContext.supplierTableError(.array([])), "the supplier table must be an object")
    }

    // ---------------------------------------------------------------- bindContext (lines 66-70, 116-121)

    private static let action: JSONValue = .object(["verb": .string("v"), "resource": .string("r")])

    private func chain(_ n: Int, leaf: Int64) -> JSONValue {
        var v: JSONValue = .int(leaf)
        for _ in 0..<n { v = .object(["a": v]) }
        return v
    }

    func testFlatteningStopsAtDepthSeventeen() {
        func boundWith(_ params: JSONValue) -> JSONValue { .object(["action": .object(["verb": .string("v"), "resource": .string("r"), "params": params])]) }
        let supplied: JSONValue = .object(["action": .object(["params": chain(20, leaf: 1)])])
        let b = MissingContext.bindContext(boundWith(chain(20, leaf: 2)), supplied: supplied)
        // the value at depth 17 (an object) is kept whole as one leaf; it differs from the bound one, so that path is the conflict
        XCTAssertEqual(b?.conflicts, ["action.params" + String(repeating: ".a", count: 17)], "lines 66, 67, 70")
        XCTAssertEqual(b?.dropped, [])
        // a leaf equal to the bound one is no conflict at all
        XCTAssertEqual(MissingContext.bindContext(boundWith(chain(20, leaf: 2)), supplied: .object(["action": .object(["params": chain(20, leaf: 2)])]))?.conflicts, [])
    }

    func testActionParamsScaffoldingForABoundContextWithoutAction() {
        let supplied: JSONValue = .object(["action": .object(["params": .object(["x": .int(1)])])])
        let b = MissingContext.bindContext(.object([:]), supplied: supplied)
        let want: JSONValue = .object(["action": .object(["verb": .string(""), "resource": .string(""), "params": .object(["x": .int(1)])])])
        XCTAssertEqual(b?.context, want, "lines 116, 121: a missing action gets an empty verb and resource")
        XCTAssertEqual(b?.conflicts, [])
    }

    func testExistingParamsAreKept() {
        let bound: JSONValue = .object(["action": .object(["verb": .string("v"), "resource": .string("r"), "params": .object(["y": .int(2)])])])
        let supplied: JSONValue = .object(["action": .object(["params": .object(["x": .int(1)])])])
        let b = MissingContext.bindContext(bound, supplied: supplied)
        let want: JSONValue = .object(["action": .object(["verb": .string("v"), "resource": .string("r"), "params": .object(["y": .int(2), "x": .int(1)])])])
        XCTAssertEqual(b?.context, want, "line 120: the bound params object is not replaced")
    }

    func testANonObjectParentBlocksTheMerge() {
        let bound: JSONValue = .object(["action": Self.action, "env": .int(5)])
        let b = MissingContext.bindContext(bound, supplied: .object(["env": .object(["x": .int(1)])]))
        XCTAssertEqual(b?.conflicts, ["env.x"])
        XCTAssertEqual(b?.context, bound)
    }

    // ---------------------------------------------------------------- decideWithMissing (lines 130-170)

    private func bound() -> JSONValue { .object(["action": Self.action, "env": .object(["name": .string("x")])]) }
    private let missing: JSONValue = .object(["field": .string("env.nothere"), "op": .string("eq"), "value": .int(1)])
    /// Unknown, yet naming no absent path: the field is present but the regex source is longer than the engine accepts.
    private var unnamed: JSONValue { .object(["field": .string("env.name"), "op": .string("matches"), "value": .string(String(repeating: "a", count: 201))]) }

    private func decide(_ wl: [JSONValue], bound b: JSONValue? = nil) -> MissingContext.Typed {
        MissingContext.decideWithMissing(where: .array(wl), bound: b ?? bound())
    }
    private let escalated = MissingContext.Typed(decision: "escalate", reason: "escalate: missing_context principal:env.nothere",
                                                 missing: [MissingContext.Missing(path: "env.nothere", supplier: "principal")])
    private let illTyped = MissingContext.Typed(decision: "deny", reason: "ill_typed_context")

    func testAnAbsentPathEscalates() {
        XCTAssertEqual(decide([missing]), escalated)
    }

    func testAnUndecidedConditionNamingNoPathIsIllTyped() {
        XCTAssertEqual(decide([unnamed]), illTyped, "line 138/148 an unknown condition that names no absent path")
        XCTAssertEqual(decide([missing, unnamed]), illTyped, "line 170 one named path does not rescue an ill-typed sibling")
    }

    func testANonObjectConditionIsIllTyped() {
        XCTAssertEqual(decide([missing, .string("x")]), illTyped, "line 130")
        XCTAssertEqual(decide([missing, .object(["all_of": .array([])])]), illTyped, "line 133 an empty group")
    }

    private func nest(_ n: Int) -> JSONValue {
        var c = missing
        for _ in 0..<n { c = .object(["all_of": .array([c])]) }
        return c
    }

    func testGroupNestingLimitIsSixtyFour() {
        XCTAssertEqual(decide([nest(64)]), escalated, "line 130 a condition at depth 64 is read")
        XCTAssertEqual(decide([nest(65)]), illTyped, "line 130 a condition at depth 65 is not")
        XCTAssertEqual(decide([nest(1)]), escalated)
    }

    func testAnActionParamsFieldWhoseParamsAreNotAContainer() {
        let b: JSONValue = .object(["action": .object(["verb": .string("v"), "resource": .string("r"), "params": .null])])
        let leaf: JSONValue = .object(["field": .string("action.params"), "op": .string("eq"), "value": .int(1)])
        let got = MissingContext.decideWithMissing(where: .array([leaf]), bound: b)
        XCTAssertEqual(got, MissingContext.Typed(decision: "escalate", reason: "escalate: missing_context principal:action.params",
                                                 missing: [MissingContext.Missing(path: "action.params", supplier: "principal")]), "lines 143, 144")
    }
}
