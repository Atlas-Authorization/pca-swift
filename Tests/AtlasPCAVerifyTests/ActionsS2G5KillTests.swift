import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the Actions.swift survivors of group 5: the normal form of an object reversibility, the covered domain of a string param, the
/// reversibility_by default of rule 22, and the exponential / endless walks (memoised depth, seen set).
final class S2G5ActionsKillTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }

    private func def(_ over: JObject = [:]) -> JObject {
        var d: JObject = ["v": .int(1), "kind": s("pca-action-def"), "verb": s("a.b"), "title": s("t"), "effects": .array([s("read")]),
                          "resource": .object(["type": s("t"), "id": s("*"), "scope": s("one")]), "params": .object([:]), "review": .object(["state": s("authored")])]
        for (k, v) in over { d[k] = v }
        return d
    }

    /// normalize: an object reversibility is rebuilt as exactly {by, map[, default]} (lines 672, 675).
    func testObjectReversibilityIsRebuiltFromByMapAndDefault() {
        let withExtra: JSONValue = .object(["by": s("p"), "map": .object(["a": s("reversible")]), "default": s("irreversible"), "junk": .int(1)])
        let n = Actions.normalize(def(["reversibility": withExtra]))
        XCTAssertEqual(n["reversibility"], .object(["by": s("p"), "map": .object(["a": s("reversible")]), "default": s("irreversible")]),
                       "extra members are dropped, the default is kept")
        let noDefault: JSONValue = .object(["by": s("p"), "map": .object(["a": s("reversible")]), "junk": .int(1)])
        XCTAssertEqual(Actions.normalize(def(["reversibility": noDefault]))["reversibility"], .object(["by": s("p"), "map": .object(["a": s("reversible")])]))
        // a string reversibility is untouched
        XCTAssertEqual(Actions.normalize(def(["reversibility": s("rate_limited")]))["reversibility"], s("rate_limited"))
    }

    /// worstReversibilityJS: the values of a string param are the covered domain (line 1001).
    func testAStringParamsValuesAreTheDomain() throws {
        let byName: [String: JObject] = ["p": ["type": s("string"), "values": .array([s("a"), s("b")])]]
        let r: JSONValue = .object(["by": s("p"), "map": .object(["a": s("reversible"), "b": s("reversible")])])
        XCTAssertEqual(try Actions.worstReversibilityJS(r, byName), "reversible", "every value is mapped: no default is mixed in")
        let partial: JSONValue = .object(["by": s("p"), "map": .object(["a": s("reversible")])])
        XCTAssertEqual(try Actions.worstReversibilityJS(partial, byName), "irreversible", "value b is unmapped: the default applies")
    }

    /// rule 22: the verb's reversibility_by.default is read (line 941), so a covered-by-default read is not irreversible.
    func testReversibilityByDefaultIsHonoured() throws {
        let reg = Actions.coreRegistry
        let top = Actions.topTraits(reg)
        let floor = try Actions.floorOf(reg, top).json
        let carried: [JSONValue] = top.filter { $0 != "pca.irreversible" }.map { .string($0) }
        let by: JSONValue = .object(["param": s("action.params.p"), "map": .object(["true": s("reversible")]), "default": s("reversible")])
        let v: JObject = ["verb": s("v"), "kind": s("read"), "effects": .array([s("read")]), "traits": .array(carried), "floors": floor,
                          "params": .object(["action.params.p": .object(["type": s("string")])]), "reversibility_by": by]
        XCTAssertEqual(Actions.schemaVerbFloorError(v, reg),
                       "schema_traits_forged: unconfirmed action must carry every trait (missing pca.irreversible)",
                       "with default reversible nothing implies pca.irreversible, only the unconfirmed rule asks for it")
    }

    // ---- loop / exponential mutants: lines 464, 474 (memoised depth), 516 (seen set) ----

    private func floor0() -> JSONValue { Profile.bottom.json }

    /// A ladder of n traits, trait i implying i-1 and i-2, declared top first: the memoised walk is linear, an unmemoised one is Fibonacci.
    func testALongLadderOfTraitsIsWalkedInLinearTime() {
        let n = 34
        func id(_ i: Int) -> String { "x.t\(i)" }
        var defs: [JSONValue] = []
        for i in stride(from: n, through: 1, by: -1) {
            var implies: [JSONValue] = []
            if i >= 2 { implies.append(s(id(i - 1))) }
            if i >= 3 { implies.append(s(id(i - 2))) }
            defs.append(.object(["id": s(id(i)), "implies": .array(implies), "floor": floor0(), "card_phrase": s("p")]))
        }
        let start = Date()
        XCTAssertEqual(Actions.registryError(defs), "trait '\(id(n))': implies depth \(n) exceeds 8")
        XCTAssertLessThan(Date().timeIntervalSince(start), 5.0, "memoised: linear in the number of traits")
    }

    /// closure of a registry with an implication cycle (hand-built, bypassing registryError) terminates through the seen set.
    func testClosureOfACycleTerminates() throws {
        func t(_ id: String, _ implies: [String]) -> TraitDef { TraitDef(id: id, implies: implies, floor: Profile.bottom, cardPhrase: "p") }
        let reg = TraitRegistry(traits: [JKey("x.a"): t("x.a", ["x.b"]), JKey("x.b"): t("x.b", ["x.a"])])
        let ids: [String] = ["x.a"]
        XCTAssertEqual(try Actions.closure(reg, ids), ["x.a", "x.b"])
    }
}
