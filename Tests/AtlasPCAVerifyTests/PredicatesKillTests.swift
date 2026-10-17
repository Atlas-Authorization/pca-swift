import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The predicate DSL (`Predicates`) pinned at its boundaries: size limits (accepted at the limit, unknown one past it), the
/// three-valued group logic with its depth limit, path/array-index rules, deep equality, ordering, the glob matcher, the
/// `is_a` tag rules and the member-of closure cap.
final class PredicatesKillTests: XCTestCase {
    private func s(_ x: String) -> JSONValue { .string(x) }
    private func a(_ n: Int) -> String { String(repeating: "a", count: n) }
    private func u(_ x: String) -> [UInt16] { Array(x.utf16) }
    private func ctx(_ params: JObject = [:], action: JObject = [:]) -> JSONValue {
        var act: JObject = ["verb": s("v"), "resource": s("r"), "params": .object(params)]
        for (k, v) in action { act[k] = v }
        return .object(["action": .object(act)])
    }
    private func leaf(_ field: String, _ op: String, _ value: JSONValue, _ c: JSONValue) -> Predicates.Tri {
        Predicates.conditionTri(.object(["field": s(field), "op": s(op), "value": value]), c, SafeRegex.Budget())
    }
    private func param(_ op: String, _ value: JSONValue, _ v: JSONValue) -> Predicates.Tri {
        leaf("action.params.p", op, value, ctx(["p": v]))
    }

    // ---- paths and array indices ---------------------------------------------------------------------------------------

    func testResolveStopsAtTheArrayEnd() {
        let c = ctx(["l": .array([.int(10), .int(20)])])
        XCTAssertEqual(Predicates.resolve(c, "action.params.l.0"), .int(10))
        XCTAssertEqual(Predicates.resolve(c, "action.params.l.1"), .int(20))
        XCTAssertNil(Predicates.resolve(c, "action.params.l.2"))
        XCTAssertNil(Predicates.resolve(c, "action.params.l.01"))
    }

    func testIsArrayIndex() {
        XCTAssertFalse(Predicates.isArrayIndex(""))
        XCTAssertTrue(Predicates.isArrayIndex("0"))
        XCTAssertFalse(Predicates.isArrayIndex("00"))
        XCTAssertFalse(Predicates.isArrayIndex("01"))
        XCTAssertTrue(Predicates.isArrayIndex("5"))
        XCTAssertTrue(Predicates.isArrayIndex("9"))
        XCTAssertTrue(Predicates.isArrayIndex("10"))
        XCTAssertTrue(Predicates.isArrayIndex("19"))
        XCTAssertTrue(Predicates.isArrayIndex("1" + String(repeating: "0", count: 17)))   // 18 digits
        XCTAssertFalse(Predicates.isArrayIndex("1" + String(repeating: "0", count: 18)))  // 19 digits
        XCTAssertFalse(Predicates.isArrayIndex("1a"))
        XCTAssertFalse(Predicates.isArrayIndex("a1"))
        XCTAssertFalse(Predicates.isArrayIndex("-1"))
        XCTAssertFalse(Predicates.isArrayIndex("1:"))
        XCTAssertFalse(Predicates.isArrayIndex("1/"))
    }

    func testParamsPresentAndRooted() {
        XCTAssertTrue(Predicates.paramsPresent(ctx()))
        XCTAssertTrue(Predicates.paramsPresent(.object(["action": .object(["params": .array([])])])))
        XCTAssertFalse(Predicates.paramsPresent(.object(["action": .object([:])])))
        XCTAssertFalse(Predicates.paramsPresent(.object(["action": .object(["params": s("x")])])))
        XCTAssertFalse(Predicates.paramsPresent(.object(["action": .object(["params": .int(1)])])))
        XCTAssertFalse(Predicates.paramsPresent(.object([:])))
        XCTAssertTrue(Predicates.paramsRooted("action.params"))
        XCTAssertTrue(Predicates.paramsRooted("action.params.x"))
        XCTAssertFalse(Predicates.paramsRooted("action.paramsx"))
        XCTAssertFalse(Predicates.paramsRooted("action"))
        XCTAssertFalse(Predicates.paramsRooted("subject.x"))
        // a params-rooted field on a context without params is unknown, even for `exists: false`
        let noParams: JSONValue = .object(["action": .object(["verb": s("v"), "resource": s("r")])])
        XCTAssertEqual(leaf("action.params.p", "exists", .bool(false), noParams), .u)
        XCTAssertEqual(leaf("action.params.p", "exists", .bool(false), ctx()), .t)
        XCTAssertEqual(leaf("action.params.p", "exists", .bool(true), ctx()), .f)
    }

    // ---- deepEq / ordered ----------------------------------------------------------------------------------------------

    func testDeepEq() {
        XCTAssertTrue(Predicates.deepEq(.null, .null))
        XCTAssertTrue(Predicates.deepEq(.bool(true), .bool(true)))
        XCTAssertTrue(Predicates.deepEq(.bool(false), .bool(false)))
        XCTAssertFalse(Predicates.deepEq(.bool(true), .bool(false)))
        XCTAssertTrue(Predicates.deepEq(s("a"), s("a")))
        XCTAssertFalse(Predicates.deepEq(s("a"), s("b")))
        // arrays: same length and element-wise equal
        XCTAssertTrue(Predicates.deepEq(.array([.int(1), .int(2)]), .array([.int(1), .int(2)])))
        XCTAssertFalse(Predicates.deepEq(.array([.int(1)]), .array([.int(2)])))
        XCTAssertFalse(Predicates.deepEq(.array([.int(1)]), .array([.int(1), .int(2)])))
        XCTAssertFalse(Predicates.deepEq(.array([.int(1), .int(2)]), .array([.int(1)])))
        XCTAssertFalse(Predicates.deepEq(.array([.int(1), .int(2)]), .array([.int(1), .int(3)])))
        XCTAssertTrue(Predicates.deepEq(.array([]), .array([])))
        // objects: same key set and equal values
        XCTAssertTrue(Predicates.deepEq(.object(["a": .int(1)]), .object(["a": .int(1)])))
        XCTAssertFalse(Predicates.deepEq(.object(["a": .int(1)]), .object(["a": .int(2)])))
        XCTAssertFalse(Predicates.deepEq(.object(["a": .int(1)]), .object(["a": .int(1), "b": .int(2)])))
        XCTAssertFalse(Predicates.deepEq(.object(["a": .int(1), "b": .int(2)]), .object(["a": .int(1)])))
        XCTAssertFalse(Predicates.deepEq(.object(["a": .int(1)]), .object(["b": .int(1)])))
        // numbers are binary64 values; non-finite numbers equal nothing
        XCTAssertTrue(Predicates.deepEq(.int(1), .double(1)))
        XCTAssertFalse(Predicates.deepEq(.int(1), .int(2)))
        XCTAssertFalse(Predicates.deepEq(.double(.infinity), .double(.infinity)))
        XCTAssertFalse(Predicates.deepEq(.double(.infinity), .int(1)))
        XCTAssertFalse(Predicates.deepEq(.int(1), .double(.infinity)))
        XCTAssertFalse(Predicates.deepEq(.double(.nan), .double(.nan)))
        // different kinds never equal
        XCTAssertFalse(Predicates.deepEq(.int(1), s("1")))
        XCTAssertFalse(Predicates.deepEq(s("1"), .int(1)))
        XCTAssertFalse(Predicates.deepEq(.bool(true), .int(1)))
        XCTAssertFalse(Predicates.deepEq(.null, .bool(false)))
        XCTAssertFalse(Predicates.deepEq(.array([]), .object([:])))
        XCTAssertFalse(Predicates.deepEq(.null, .int(0)))
    }

    func testOrdered() {
        XCTAssertEqual(Predicates.ordered(.int(1), .int(2)), -1)
        XCTAssertEqual(Predicates.ordered(.int(2), .int(1)), 1)
        XCTAssertEqual(Predicates.ordered(.int(2), .int(2)), 0)
        XCTAssertEqual(Predicates.ordered(.double(1.5), .int(2)), -1)
        XCTAssertNil(Predicates.ordered(.double(.infinity), .int(1)))
        XCTAssertNil(Predicates.ordered(.int(1), .double(.infinity)))
        XCTAssertNil(Predicates.ordered(.double(.nan), .int(1)))
        XCTAssertEqual(Predicates.ordered(s("a"), s("b")), -1)
        XCTAssertEqual(Predicates.ordered(s("c"), s("a")), 1)
        XCTAssertEqual(Predicates.ordered(s("b"), s("b")), 0)
        XCTAssertEqual(Predicates.ordered(s("a"), s("ab")), -1)
        XCTAssertEqual(Predicates.ordered(s("ab"), s("a")), 1)
        let lone = String(Canonical.LONE_SURROGATE_SENTINEL)
        XCTAssertNil(Predicates.ordered(s(lone + "a"), s("b")))
        XCTAssertNil(Predicates.ordered(s("a"), s(lone)))
        XCTAssertNil(Predicates.ordered(s("a"), .int(1)))
    }

    func testComparisonOperators() {
        XCTAssertEqual(param("lt", .int(5), .int(5)), .f)
        XCTAssertEqual(param("lt", .int(6), .int(5)), .t)
        XCTAssertEqual(param("lt", .int(4), .int(5)), .f)
        XCTAssertEqual(param("lte", .int(5), .int(5)), .t)
        XCTAssertEqual(param("lte", .int(4), .int(5)), .f)
        XCTAssertEqual(param("lte", .int(6), .int(5)), .t)
        XCTAssertEqual(param("gt", .int(5), .int(5)), .f)
        XCTAssertEqual(param("gt", .int(4), .int(5)), .t)
        XCTAssertEqual(param("gt", .int(6), .int(5)), .f)
        XCTAssertEqual(param("gte", .int(5), .int(5)), .t)
        XCTAssertEqual(param("gte", .int(6), .int(5)), .f)
        XCTAssertEqual(param("gte", .int(4), .int(5)), .t)
        XCTAssertEqual(param("lt", s("b"), s("a")), .t)   // "a" < "b"
        XCTAssertEqual(param("lt", s("a"), s("b")), .f)
        XCTAssertEqual(param("lt", s("a"), .int(1)), .u)
        XCTAssertEqual(param("eq", .int(5), .int(5)), .t)
        XCTAssertEqual(param("eq", .int(6), .int(5)), .f)
        XCTAssertEqual(param("ne", .int(5), .int(5)), .f)
        XCTAssertEqual(param("ne", .int(6), .int(5)), .t)
        XCTAssertEqual(param("in", .array([.int(5), .int(6)]), .int(5)), .t)
        XCTAssertEqual(param("in", .array([.int(7)]), .int(5)), .f)
        XCTAssertEqual(param("nin", .array([.int(5), .int(6)]), .int(5)), .f)
        XCTAssertEqual(param("nin", .array([.int(7)]), .int(5)), .t)
        XCTAssertEqual(param("in", .int(5), .int(5)), .u)
    }

    // ---- size limits ---------------------------------------------------------------------------------------------------

    func testLikeLimits() {
        // glob of 512 code units accepted, 513 unknown; subject of 512 accepted, 513 unknown
        XCTAssertEqual(param("like", s(a(512)), s(a(512))), .t)
        XCTAssertEqual(param("like", s(a(513)), s("a")), .u)
        XCTAssertEqual(param("like", s("*"), s(a(512))), .t)
        XCTAssertEqual(param("like", s("*"), s(a(513))), .u)
        XCTAssertEqual(param("like", s("a?c"), s("abc")), .t)
        XCTAssertEqual(param("like", s("a?c"), s("abd")), .f)
        XCTAssertEqual(param("like", s("\\"), s("a")), .u)
    }

    func testMatchesLimits() {
        XCTAssertEqual(param("matches", s(a(200)), s(a(200))), .t)
        XCTAssertEqual(param("matches", s(a(201)), s("a")), .u)
        XCTAssertEqual(param("matches", s("a*"), s(a(512))), .t)
        XCTAssertEqual(param("matches", s("a*"), s(a(513))), .u)
        XCTAssertEqual(param("matches", s("a+"), s("b")), .f)
    }

    func testReResourceLimits() {
        func res(_ pat: String, _ r: String) -> Bool { Predicates.resourceMatches(s(pat), r, SafeRegex.Budget()) }
        XCTAssertTrue(res("re:a*", a(512)))
        XCTAssertFalse(res("re:a*", a(513)))
        XCTAssertTrue(res("re:" + a(200), a(200)))
        XCTAssertFalse(res("re:" + a(201), a(201)))
        XCTAssertFalse(res("re:a+", "b"))
        XCTAssertTrue(res("re:a+", "aa"))
        XCTAssertTrue(Predicates.resourceMatches(nil, "anything", SafeRegex.Budget()))
        XCTAssertFalse(Predicates.resourceMatches(.int(1), "anything", SafeRegex.Budget()))
        XCTAssertTrue(res("*", "anything"))
        XCTAssertTrue(res("pre*", "prefix"))
        XCTAssertFalse(res("pre*", "xprefix"))
        XCTAssertTrue(res("exact", "exact"))
        XCTAssertFalse(res("exact", "exactly"))
    }

    // ---- predicate match -----------------------------------------------------------------------------------------------

    func testVerbMatches() {
        XCTAssertTrue(Predicates.verbMatches(s("*"), "v"))
        XCTAssertTrue(Predicates.verbMatches(s("v"), "v"))
        XCTAssertFalse(Predicates.verbMatches(s("w"), "v"))
        XCTAssertTrue(Predicates.verbMatches(.array([s("x"), s("v")]), "v"))
        XCTAssertTrue(Predicates.verbMatches(.array([s("*")]), "v"))
        XCTAssertFalse(Predicates.verbMatches(.array([.int(1)]), "v"))
        XCTAssertFalse(Predicates.verbMatches(.array([s("x")]), "v"))
        XCTAssertFalse(Predicates.verbMatches(nil, "v"))
        XCTAssertFalse(Predicates.verbMatches(.int(1), "v"))
        XCTAssertFalse(Predicates.verbMatches(.object([:]), "v"))
    }

    func testPredicateMatchesNeedsResourceAndWellFormedWhere() {
        let b = SafeRegex.Budget()
        let c = ctx()
        XCTAssertTrue(Predicates.predicateMatches(.object(["verb": s("v")]), c, b))
        let noResource: JSONValue = .object(["action": .object(["verb": s("v")])])
        XCTAssertFalse(Predicates.predicateMatches(.object(["verb": s("v")]), noResource, b))
        XCTAssertFalse(Predicates.predicateMatches(.object(["verb": s("v"), "where": s("bad")]), c, b))
        XCTAssertTrue(Predicates.predicateMatches(.object(["verb": s("v"), "where": .array([])]), c, b))
        XCTAssertFalse(Predicates.predicateMatches(.object(["verb": s("v"), "resource": s("other")]), c, b))
        XCTAssertTrue(Predicates.predicateMatches(.object(["verb": s("v"), "resource": s("r")]), c, b))
        let cc = ctx(["p": .int(1)])
        let ok: JSONValue = .object(["field": s("action.params.p"), "op": s("eq"), "value": .int(1)])
        let bad: JSONValue = .object(["field": s("action.params.p"), "op": s("eq"), "value": .int(2)])
        XCTAssertTrue(Predicates.predicateMatches(.object(["verb": s("v"), "where": .array([ok])]), cc, b))
        XCTAssertFalse(Predicates.predicateMatches(.object(["verb": s("v"), "where": .array([ok, bad])]), cc, b))
        XCTAssertTrue(Predicates.evaluate(.array([.object(["verb": s("x")]), .object(["verb": s("v")])]), c))
        XCTAssertFalse(Predicates.evaluate(.array([]), c))
        XCTAssertFalse(Predicates.evaluate(.object([:]), c))
    }

    // ---- three-valued groups and the depth limit -----------------------------------------------------------------------

    private var tLeaf: JSONValue { .object(["field": s("action.verb"), "op": s("exists")]) }
    private var fLeaf: JSONValue { .object(["field": s("action.verb"), "op": s("eq"), "value": s("zzz")]) }
    private var uLeaf: JSONValue { .object(["field": s("action.nope"), "op": s("eq"), "value": .int(1)]) }
    private func tri(_ c: JSONValue) -> Predicates.Tri { Predicates.conditionTri(c, ctx(), SafeRegex.Budget()) }

    func testLeafFixturesAreWhatTheyClaim() {
        XCTAssertEqual(tri(tLeaf), .t)
        XCTAssertEqual(tri(fLeaf), .f)
        XCTAssertEqual(tri(uLeaf), .u)
    }

    func testGroupsAreRecognisedByAnyOfTheirMembers() {
        XCTAssertEqual(tri(.object(["all_of": .array([tLeaf])])), .t)
        XCTAssertEqual(tri(.object(["all_of": .array([fLeaf])])), .f)
        XCTAssertEqual(tri(.object(["any_of": .array([tLeaf])])), .t)
        XCTAssertEqual(tri(.object(["any_of": .array([fLeaf])])), .f)
        XCTAssertEqual(tri(.object(["not": fLeaf])), .t)
        XCTAssertEqual(tri(.object(["not": tLeaf])), .f)
        XCTAssertEqual(tri(.object(["not": uLeaf])), .u)
        // a group member next to leaf members: the group wins
        XCTAssertEqual(tri(.object(["any_of": .array([tLeaf]), "field": s("action.nope"), "op": s("eq"), "value": .int(1)])), .t)
        XCTAssertEqual(tri(.object(["not": fLeaf, "field": s("action.nope"), "op": s("eq"), "value": .int(1)])), .t)
    }

    func testUnknownPropagatesThroughAllOfAndAnyOf() {
        XCTAssertEqual(tri(.object(["all_of": .array([uLeaf, tLeaf])])), .u)
        XCTAssertEqual(tri(.object(["all_of": .array([tLeaf, uLeaf])])), .u)
        XCTAssertEqual(tri(.object(["all_of": .array([uLeaf, fLeaf])])), .f)
        XCTAssertEqual(tri(.object(["all_of": .array([tLeaf, tLeaf])])), .t)
        XCTAssertEqual(tri(.object(["any_of": .array([uLeaf, fLeaf])])), .u)
        XCTAssertEqual(tri(.object(["any_of": .array([fLeaf, uLeaf])])), .u)
        XCTAssertEqual(tri(.object(["any_of": .array([uLeaf, tLeaf])])), .t)
        XCTAssertEqual(tri(.object(["any_of": .array([fLeaf])])), .f)
        XCTAssertEqual(tri(.object(["any_of": .array([fLeaf, fLeaf])])), .f)
        XCTAssertEqual(tri(.object(["all_of": .array([])])), .u)
        XCTAssertEqual(tri(.object(["any_of": .array([])])), .u)
        XCTAssertEqual(tri(.object(["all_of": s("x")])), .u)
    }

    private func nest(_ kind: String, _ n: Int) -> JSONValue {
        var c = tLeaf
        for _ in 0..<n { c = kind == "not" ? .object(["not": c]) : .object([JKey(kind): .array([c])]) }
        return c
    }

    func testNestingDepthLimitIsExactlyMaxLenientDepth() {
        let lim = Canonical.MAX_LENIENT_DEPTH
        XCTAssertEqual(lim, 1024)
        for kind in ["all_of", "any_of", "not"] {
            XCTAssertEqual(tri(nest(kind, lim)), .t, "\(kind) at the limit")
            XCTAssertEqual(tri(nest(kind, lim + 1)), .u, "\(kind) one past the limit")
        }
        XCTAssertEqual(tri(nest("all_of", 1)), .t)
        XCTAssertEqual(tri(nest("not", 3)), .f)
    }

    // ---- glob ----------------------------------------------------------------------------------------------------------

    func testParseGlob() {
        XCTAssertEqual(Predicates.parseGlob(u("a")), [.lit(0x61)])
        XCTAssertEqual(Predicates.parseGlob(u("a?b*")), [.lit(0x61), .one, .lit(0x62), .star])
        XCTAssertEqual(Predicates.parseGlob(u("a**b")), [.lit(0x61), .star, .lit(0x62)])
        XCTAssertEqual(Predicates.parseGlob(u("\\*")), [.lit(0x2a)])
        XCTAssertEqual(Predicates.parseGlob(u("\\?x")), [.lit(0x3f), .lit(0x78)])
        XCTAssertEqual(Predicates.parseGlob(u("\\*a")), [.lit(0x2a), .lit(0x61)])
        XCTAssertEqual(Predicates.parseGlob(u("\\\\")), [.lit(0x5c)])
        XCTAssertNil(Predicates.parseGlob(u("a\\")))
        XCTAssertNil(Predicates.parseGlob(u("\\")))
        XCTAssertEqual(Predicates.parseGlob(u("")), [])
        XCTAssertEqual(Predicates.parseGlob(u("a?")), [.lit(0x61), .one])
    }

    func testGlobMatch() {
        func g(_ glob: String, _ subj: String) -> Bool? { Predicates.globMatch(u(glob), u(subj)) }
        XCTAssertEqual(g("a", "a"), true)
        XCTAssertEqual(g("a", "b"), false)
        XCTAssertEqual(g("ab", "xab"), false)
        XCTAssertEqual(g("ab", "ac"), false)
        XCTAssertEqual(g("a?", "ab"), true)
        XCTAssertEqual(g("a?", "a"), false)
        XCTAssertEqual(g("?", "x"), true)
        XCTAssertEqual(g("*a", "bc"), false)
        XCTAssertEqual(g("*a", "ba"), true)
        XCTAssertEqual(g("*a", "a"), true)
        XCTAssertEqual(g("a*", "a"), true)
        XCTAssertEqual(g("a*", "abc"), true)
        XCTAssertEqual(g("a**", "a"), true)
        XCTAssertEqual(g("a*b*", "ab"), true)
        XCTAssertEqual(g("a*b*", "axbxx"), true)
        XCTAssertEqual(g("a*b", "axbx"), false)
        XCTAssertEqual(g("*", ""), true)
        XCTAssertEqual(g("", ""), true)
        XCTAssertEqual(g("", "a"), false)
        XCTAssertEqual(g("a", ""), false)
        XCTAssertEqual(g("\\*", "*"), true)
        XCTAssertEqual(g("\\*", "a"), false)
        XCTAssertNil(g("\\", "x"))
        XCTAssertEqual(g("*ab*cd*", "xxabyycdzz"), true)
    }

    // ---- is_a ----------------------------------------------------------------------------------------------------------

    func testTypeTagMatch() {
        XCTAssertEqual(Predicates.typeTagMatch(s("x"), "x"), true)
        XCTAssertEqual(Predicates.typeTagMatch(s("x::y"), "x"), true)
        XCTAssertEqual(Predicates.typeTagMatch(s("xy"), "x"), false)
        XCTAssertEqual(Predicates.typeTagMatch(s("y"), "x"), false)
        // objects: undecidable without `type` or `tags`
        XCTAssertNil(Predicates.typeTagMatch(.object([:]), "x"))
        XCTAssertNil(Predicates.typeTagMatch(.object(["other": s("x")]), "x"))
        XCTAssertEqual(Predicates.typeTagMatch(.object(["type": s("x")]), "x"), true)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["type": s("x::z")]), "x"), true)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["type": s("other")]), "x"), false)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["type": .int(1)]), "x"), nil)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["tags": .array([s("x")])]), "x"), true)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["tags": .array([s("y")])]), "x"), false)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["tags": .array([.int(1)])]), "x"), false)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["tags": .array([])]), "x"), false)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["type": s("other"), "tags": .array([s("x")])]), "x"), true)
        XCTAssertEqual(Predicates.typeTagMatch(.object(["type": s("x"), "tags": .array([s("y")])]), "x"), true)
        XCTAssertNil(Predicates.typeTagMatch(.int(1), "x"))
        XCTAssertNil(Predicates.typeTagMatch(.array([s("x")]), "x"))
        XCTAssertNil(Predicates.typeTagMatch(.null, "x"))
        XCTAssertEqual(param("is_a", s("x"), s("x::y")), .t)
        XCTAssertEqual(param("is_a", s("x"), s("z")), .f)
        XCTAssertEqual(param("is_a", s(""), s("z")), .u)
    }

    // ---- member_of closure ---------------------------------------------------------------------------------------------

    func testMemberClosureNodeCap() {
        var adj: JObject = [:]
        for i in 0..<10_050 { adj[JKey("n\(i)")] = s("n\(i + 1)") }
        let reach = Predicates.memberClosure("n0", adj)
        // 10,000 nodes are expanded; the 10,001st is reached but never expanded
        XCTAssertEqual(reach.count, 10_001)
        XCTAssertTrue(reach.contains(JKey("n10000")))
        XCTAssertFalse(reach.contains(JKey("n10001")))
    }

    func testMemberClosureSmallGraph() {
        let adj: JObject = ["a": .array([s("b"), s("c")]), "b": s("d"), "c": .array([s("a"), .int(1)]), "constructor": s("zz")]
        let reach = Predicates.memberClosure("a", adj)
        XCTAssertEqual(reach, [JKey("a"), JKey("b"), JKey("c"), JKey("d")])
        XCTAssertEqual(Predicates.memberClosure("constructor", adj), [JKey("constructor")])
        XCTAssertEqual(Predicates.memberClosure("zzz", adj), [JKey("zzz")])
    }
}
