import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Prohibitions.swift: the JavaScript-flavoured helpers, every limit at n-1 / n / n+1, the operands of each validation guard, the
/// ledger merge on overflow and the monitor defaults the differential corpus does not reach.
final class K05ProhibitionsKillTests: XCTestCase {
    func J(_ s: String) -> JSONValue { JSONValue.parse(s) ?? .null }
    func O(_ s: String) -> JObject { J(s).asObject ?? [:] }
    func nested(_ levels: Int) -> JSONValue {
        var v: JSONValue = .string("x")
        for _ in 0..<levels { v = .array([v]) }
        return v
    }

    // ---- PD helpers ------------------------------------------------------------------------------------------------------------

    func testKindPredicates() {
        XCTAssertTrue(PD.isArr(.array([])))
        XCTAssertFalse(PD.isArr(.object([:])))
        XCTAssertFalse(PD.isArr(nil))
        XCTAssertTrue(PD.isBool(.bool(false)))
        XCTAssertFalse(PD.isBool(.int(1)))
        XCTAssertFalse(PD.isBool(nil))
        XCTAssertTrue(PD.isObj(.object([:])))
        XCTAssertFalse(PD.isObj(.array([])))
    }

    func testIsIntegerAndFin() {
        XCTAssertTrue(PD.isInteger(.int(3)))
        XCTAssertTrue(PD.isInteger(.double(2.0)))
        XCTAssertFalse(PD.isInteger(.double(1.5)))
        XCTAssertFalse(PD.isInteger(nil))
        XCTAssertFalse(PD.isInteger(.string("1")))
        XCTAssertFalse(PD.isInteger(.double(.infinity)))
        XCTAssertFalse(PD.isInteger(.double(.nan)))
        XCTAssertNil(PD.fin(.double(.infinity)))
        XCTAssertNil(PD.fin(.string("1")))
        XCTAssertEqual(PD.fin(.int(4)), 4)
    }

    func testNumBuildsIntegersOnlyInsideTheSafeRange() {
        XCTAssertEqual(PD.num(3), .int(3))
        XCTAssertEqual(PD.num(-3), .int(-3))
        XCTAssertEqual(PD.num(9_007_199_254_740_991), .int(9_007_199_254_740_991))
        XCTAssertEqual(PD.num(-9_007_199_254_740_991), .int(-9_007_199_254_740_991))
        if case .double = PD.num(9_007_199_254_740_992) {} else { XCTFail("2^53 is not a safe integer") }
        if case .double = PD.num(1.5) {} else { XCTFail("1.5") }
        if case .double = PD.num(.nan) {} else { XCTFail("nan") }
        if case .double = PD.num(.infinity) {} else { XCTFail("inf") }
        if case let .double(d) = PD.num(-0.0) { XCTAssertEqual(d.sign, .minus) } else { XCTFail("-0 stays a double") }
    }

    func testTruthy() {
        XCTAssertFalse(PD.truthy(nil))
        let falsy: [JSONValue] = [JSONValue.null, JSONValue.bool(false), JSONValue.int(0), JSONValue.double(0.0), JSONValue.double(-0.0), JSONValue.double(.nan), JSONValue.string("")]
        for v in falsy { XCTAssertFalse(PD.truthy(v), "\(v)") }
        let truthy: [JSONValue] = [JSONValue.bool(true), JSONValue.int(1), JSONValue.int(-1), JSONValue.double(0.5), JSONValue.double(1.0), JSONValue.double(.infinity), JSONValue.string("a"), JSONValue.array([]), JSONValue.object([:])]
        for v in truthy { XCTAssertTrue(PD.truthy(v), "\(v)") }
    }

    func testNumStrIsEcmaNumberToString() {
        let cases: [(Double, String)] = [
            (.nan, "NaN"), (.infinity, "Infinity"), (-.infinity, "-Infinity"), (0, "0"), (-0.0, "0"), (1, "1"), (-1, "-1"), (25, "25"), (100, "100"),
            (100000, "100000"), (12.5, "12.5"), (-0.5, "-0.5"), (0.5, "0.5"), (1234.5678, "1234.5678"), (0.1 + 0.2, "0.30000000000000004"),
            (0.000001, "0.000001"), (0.00000123, "0.00000123"), (1e-7, "1e-7"), (1.5e-7, "1.5e-7"), (1e-10, "1e-10"), (1.23e-18, "1.23e-18"),
            (5e-324, "5e-324"), (-1e-7, "-1e-7"),
        ]
        for (v, want) in cases { XCTAssertEqual(PD.numStr(v), want, "\(v)") }
    }

    // The inputs at and past the edge of the plain-digits range sort last: a mutated range bound sends them into a digit slice past the end
    // of the digits, which is a trap, so every assertion that can fail on its own has already run.
    func testZNumStrJustBelowTheExponentRange() {
        XCTAssertEqual(PD.numStr(1e20), "100000000000000000000")
        XCTAssertEqual(PD.numStr(-1e20), "-100000000000000000000")
        XCTAssertEqual(PD.numStr(123456789012345680000.0), "123456789012345680000")
    }

    func testZNumStrExponentValues() {
        XCTAssertEqual(PD.numStr(1e21), "1e+21")
        XCTAssertEqual(PD.numStr(-1e21), "-1e+21")
        XCTAssertEqual(PD.numStr(1e22), "1e+22")
        XCTAssertEqual(PD.numStr(1.5e21), "1.5e+21")
        XCTAssertEqual(PD.numStr(1.2345e25), "1.2345e+25")
        XCTAssertEqual(PD.numStr(1.7976931348623157e308), "1.7976931348623157e+308")
    }

    func testJsStringConversion() {
        XCTAssertEqual(PD.js(nil), "undefined")
        XCTAssertEqual(PD.js(.null), "null")
        XCTAssertEqual(PD.js(.bool(true)), "true")
        XCTAssertEqual(PD.js(.int(5)), "5")
        XCTAssertEqual(PD.js(.double(1.5)), "1.5")
        XCTAssertEqual(PD.js(.string("s")), "s")
        XCTAssertEqual(PD.js(.object([:])), "[object Object]")
        XCTAssertEqual(PD.js(J(#"[1,null,[2,3],"a"]"#)), "1,,2,3,a")
        XCTAssertEqual(PD.join([.int(1), .null, .string("b")]), "1,,b")
    }

    func testJsStopsDescendingAfterSixtyFiveLevels() {
        XCTAssertEqual(PD.js(nested(1)), "x")
        XCTAssertEqual(PD.js(nested(65)), "x")
        XCTAssertEqual(PD.js(nested(66)), "")
        XCTAssertEqual(PD.js(nested(70)), "")
    }

    func testPropReadsMembersAndRefusesNullAndUndefined() throws {
        XCTAssertThrowsError(try PD.prop(nil, "a"))
        XCTAssertThrowsError(try PD.prop(.null, "a"))
        XCTAssertNil(try PD.prop(.int(1), "a"))
        XCTAssertNil(try PD.prop(.object([:]), "a"))
        XCTAssertEqual(try PD.prop(J(#"{"a":7}"#), "a"), .int(7))
    }

    func testJsMaxJsMinPropagateNaNFromEitherSide() {
        XCTAssertTrue(PD.jsMax(.nan, 1).isNaN)
        XCTAssertTrue(PD.jsMax(1, .nan).isNaN)
        XCTAssertTrue(PD.jsMax(.nan, .nan).isNaN)
        XCTAssertEqual(PD.jsMax(1, 2), 2)
        XCTAssertEqual(PD.jsMax(3, 2), 3)
        XCTAssertTrue(PD.jsMin(.nan, 1).isNaN)
        XCTAssertTrue(PD.jsMin(1, .nan).isNaN)
        XCTAssertTrue(PD.jsMin(.nan, .nan).isNaN)
        XCTAssertEqual(PD.jsMin(1, 2), 1)
        XCTAssertEqual(PD.jsMin(3, 2), 2)
    }

    func testLimits() {
        XCTAssertEqual(Prohibitions.MAX_LEDGER, 10_000)
        XCTAssertEqual(Prohibitions.MAX_INVARIANTS, 256)
        XCTAssertEqual(Prohibitions.MAX_DEADLINE, 1_000_000)
        XCTAssertEqual(Prohibitions.MAX_STATE_ENTRIES, 100_000)
        XCTAssertEqual(Prohibitions.MAX_STATE_KEYS, 1024)
        XCTAssertEqual(Prohibitions.MAX_ID_LEN, 128)
        XCTAssertEqual(Prohibitions.MAX_CONDITION_DEPTH, 32)
    }

    // ---- validation ------------------------------------------------------------------------------------------------------------

    let leaf = #"{"field":"a","op":"eq","value":1}"#
    func chain(_ key: String, _ n: Int) -> JSONValue {
        var c = J(leaf)
        for _ in 0..<n { c = key == "not" ? .object(["not": c]) : .object([JKey(key): .array([c])]) }
        return c
    }

    func testConditionNestingLimit() {
        for key in ["not", "all_of", "any_of"] {
            XCTAssertNil(Prohibitions.validateCondition(chain(key, 31)), key)
            XCTAssertNil(Prohibitions.validateCondition(chain(key, 32)), key)
            XCTAssertEqual(Prohibitions.validateCondition(chain(key, 33)), "condition nesting too deep", key)
            XCTAssertEqual(Prohibitions.validateCondition(chain(key, 40)), "condition nesting too deep", key)
        }
    }

    func testConditionCombinators() {
        XCTAssertNil(Prohibitions.validateCondition(J(#"{"all_of":[\#(leaf)]}"#)))
        XCTAssertNil(Prohibitions.validateCondition(J(#"{"any_of":[\#(leaf)]}"#)))
        XCTAssertNil(Prohibitions.validateCondition(J(#"{"not":\#(leaf)}"#)))
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"all_of":[]}"#)), "condition.all_of must be a non-empty array")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"any_of":[]}"#)), "condition.any_of must be a non-empty array")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"all_of":5}"#)), "condition.all_of must be a non-empty array")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"any_of":"x"}"#)), "condition.any_of must be a non-empty array")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"all_of":[\#(leaf),{"field":"","op":"eq"}]}"#)), "condition.field missing")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"field":"a"}"#)), "unknown condition op undefined")
        XCTAssertEqual(Prohibitions.validateCondition(.int(1)), "condition not an object")
    }

    func testConditionRefAndCollection() {
        XCTAssertNil(Prohibitions.validateCondition(J(#"{"field":"a","op":"eq","ref":"x"}"#)))
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"field":"a","op":"eq","ref":""}"#)), "bad condition.ref")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"field":"a","op":"eq","ref":5}"#)), "bad condition.ref")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"field":"a","op":"eq","ref":null}"#)), "bad condition.ref")
        XCTAssertNil(Prohibitions.validateCondition(J(#"{"field":"a","op":"member_of","collection":"c"}"#)))
        XCTAssertNil(Prohibitions.validateCondition(J(#"{"field":"a","op":"member_of"}"#)))
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"field":"a","op":"member_of","collection":""}"#)), "bad condition.collection")
        XCTAssertEqual(Prohibitions.validateCondition(J(#"{"field":"a","op":"member_of","collection":5}"#)), "bad condition.collection")
        XCTAssertNil(Prohibitions.validateCondition(J(#"{"field":"a","op":"eq","collection":5}"#)))
    }

    func testWhenVerbAndResource() {
        func w(_ s: String) -> String? { Prohibitions.validateWhen(J(s), "w") }
        XCTAssertNil(w(#"{"verb":"a"}"#))
        XCTAssertNil(w(#"{"verb":["a","b"]}"#))
        XCTAssertEqual(w(#"{}"#), "w: bad verb")
        XCTAssertEqual(w(#"{"verb":""}"#), "w: bad verb")
        XCTAssertEqual(w(#"{"verb":[]}"#), "w: bad verb")
        XCTAssertEqual(w(#"{"verb":["a",""]}"#), "w: bad verb")
        XCTAssertEqual(w(#"{"verb":["a",1]}"#), "w: bad verb")
        XCTAssertEqual(w(#"{"verb":5}"#), "w: bad verb")
        XCTAssertEqual(w(#"{"verb":"a","resource":5}"#), "w: bad resource")
        XCTAssertEqual(w(#"{"verb":"a","where":{}}"#), "w: where not an array")
        XCTAssertEqual(w(#"{"verb":"a","where":[{"field":"a","op":"zz"}]}"#), "w: unknown condition op zz")
        XCTAssertEqual(Prohibitions.validateWhen(.int(1), "w"), "w: not an object")
    }

    func testWhenRegexResourceSizeLimit() {
        func w(_ n: Int) -> String? { Prohibitions.validateWhen(J(#"{"verb":"a","resource":"re:\#(String(repeating: "a", count: n))"}"#), "w") }
        XCTAssertNil(w(199))
        XCTAssertNil(w(200))
        XCTAssertEqual(w(201), "w: unsafe regex resource")
        XCTAssertNil(Prohibitions.validateWhen(J(#"{"verb":"a","resource":"/plain/*"}"#), "w"))
    }

    func testActionPath() {
        XCTAssertTrue(Prohibitions.actionPath(.string("action.params.x")))
        XCTAssertFalse(Prohibitions.actionPath(.string("params.x")))
        XCTAssertFalse(Prohibitions.actionPath(.int(1)))
        XCTAssertFalse(Prohibitions.actionPath(nil))
    }

    func inv(_ s: String) -> [String] { Prohibitions.validateInvariant(J(s)) }

    func testEveryKindValidatesItsTriggers() {
        let bad = #"{"verb":""}"#
        XCTAssertEqual(inv(#"{"id":"i","kind":"never","when":\#(bad)}"#), ["i: when: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"never_unless","when":\#(bad),"unless":[\#(leaf)]}"#), ["i: when: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"cap","when":\#(bad),"amount":"action.x","max":1}"#), ["i: when: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"rate","when":\#(bad),"max":1,"window_secs":1}"#), ["i: when: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"never_after","after":\#(bad),"forbid":{"verb":"b"}}"#), ["i: after: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"never_after","after":{"verb":"b"},"forbid":\#(bad)}"#), ["i: forbid: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"require_prior","when":\#(bad),"prior":{"verb":"b"}}"#), ["i: when: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"require_prior","when":{"verb":"b"},"prior":\#(bad)}"#), ["i: prior: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"require_approval_over","when":\#(bad),"amount":"action.x","threshold":1,"approved":[\#(leaf)]}"#), ["i: when: bad verb"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"never_unless","when":{"verb":"a"},"unless":[]}"#), ["i: unless must be a non-empty array"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"require_approval_over","when":{"verb":"a"},"amount":"action.x","threshold":1,"approved":[]}"#), ["i: approved must be a non-empty array"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"zzz"}"#), ["i: unknown invariant kind zzz"])
    }

    func testIdLimits() {
        func with(_ n: Int) -> [String] { inv(#"{"id":"\#(String(repeating: "a", count: n))","kind":"never","when":{"verb":"a"}}"#) }
        XCTAssertEqual(with(127), [])
        XCTAssertEqual(with(128), [])
        XCTAssertEqual(with(129).count, 1)
        XCTAssertTrue(with(129)[0].hasSuffix(": id too long"))
        XCTAssertEqual(inv(#"{"id":"constructor","kind":"never","when":{"verb":"a"}}"#), ["constructor: forbidden id"])
        XCTAssertEqual(inv(#"{"id":"","kind":"never"}"#), ["<no id>: missing id"])
    }

    func testCapAndRateAndThresholdBounds() {
        func cap(_ max: String, _ ws: String? = nil) -> [String] {
            let tail = ws == nil ? "" : #","window_secs":"# + ws!
            return inv(#"{"id":"i","kind":"cap","when":{"verb":"a"},"amount":"action.x","max":"# + max + tail + "}")
        }
        XCTAssertEqual(cap("0"), [])
        XCTAssertEqual(cap("-1"), ["i: max must be a finite number >= 0"])
        XCTAssertEqual(cap("1", "1"), [])
        XCTAssertEqual(cap("1", "0.5"), [])
        XCTAssertEqual(cap("1", "0"), ["i: bad window_secs"])
        XCTAssertEqual(cap("1", "-1"), ["i: bad window_secs"])
        XCTAssertEqual(inv(#"{"id":"i","kind":"cap","when":{"verb":"a"},"amount":"x","max":1}"#), ["i: amount must be an action.* path"])
        func rate(_ max: String, _ ws: String) -> [String] { inv(#"{"id":"i","kind":"rate","when":{"verb":"a"},"max":\#(max),"window_secs":\#(ws)}"#) }
        XCTAssertEqual(rate("0", "1"), [])
        XCTAssertEqual(rate("10000", "1"), [])
        XCTAssertEqual(rate("9999", "1"), [])
        XCTAssertEqual(rate("10001", "1"), ["i: max must be an integer in [0,10000]"])
        XCTAssertEqual(rate("-1", "1"), ["i: max must be an integer in [0,10000]"])
        XCTAssertEqual(rate("1.5", "1"), ["i: max must be an integer in [0,10000]"])
        XCTAssertEqual(rate("1", "0"), ["i: window_secs must be > 0"])
        XCTAssertEqual(rate("1", "0.5"), [])
        func thr(_ t: String) -> [String] { inv(#"{"id":"i","kind":"require_approval_over","when":{"verb":"a"},"amount":"action.x","threshold":\#(t),"approved":[\#(leaf)]}"#) }
        XCTAssertEqual(thr("0"), [])
        XCTAssertEqual(thr("-1"), ["i: threshold must be a finite number >= 0"])
    }

    func testInvariantCountLimit() {
        func c(_ n: Int) -> JSONValue {
            let invs = (0..<n).map { #"{"id":"i\#($0)","kind":"never","when":{"verb":"a"}}"# }.joined(separator: ",")
            return J(#"{"version":1,"principal":"p","invariants":[\#(invs)]}"#)
        }
        XCTAssertEqual(Prohibitions.validateConstitution(c(255)), [])
        XCTAssertEqual(Prohibitions.validateConstitution(c(256)), [])
        XCTAssertEqual(Prohibitions.validateConstitution(c(257)), ["too many invariants"])
    }

    // ---- monitor state limits --------------------------------------------------------------------------------------------------

    func state(ledger: JObject = [:], latched: JObject = [:], extra: JObject = [:]) -> JSONValue {
        var o: JObject = ["now": .int(1000), "seq": .int(0), "parent": .null, "ledger": .object(ledger), "latched": .object(latched)]
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }
    func keys(_ n: Int, _ v: JSONValue) -> JObject {
        var o: JObject = [:]
        for i in 0..<n { o[JKey("k\(i)")] = v }
        return o
    }
    func entries(_ n: Int, amount: Int64 = 1) -> JSONValue { .array((0..<n).map { _ in .object(["t": .int(1000), "amount": .int(amount)]) }) }

    func testStateKeyCountLimits() {
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: keys(1023, .array([])))))
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: keys(1024, .array([])))))
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: keys(1025, .array([])))), "malformed monitor state: too many keys")
        XCTAssertNil(Prohibitions.stateProblem(state(latched: keys(1024, .int(5)))))
        XCTAssertEqual(Prohibitions.stateProblem(state(latched: keys(1025, .int(5)))), "malformed monitor state: too many keys")
    }

    func testStateKeyLengthLimits() {
        func k(_ n: Int) -> JKey { JKey(String(repeating: "a", count: n)) }
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: [k(127): .array([])])))
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: [k(128): .array([])])))
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: [k(129): .array([])])), "malformed monitor state: bad ledger key")
        XCTAssertNil(Prohibitions.stateProblem(state(latched: [k(128): .int(1)])))
        XCTAssertEqual(Prohibitions.stateProblem(state(latched: [k(129): .int(1)])), "malformed monitor state: bad latch key")
        XCTAssertNil(Prohibitions.stateProblem(state(extra: ["deadlines": .object([k(128): .int(1)])])))
        XCTAssertEqual(Prohibitions.stateProblem(state(extra: ["deadlines": .object([k(129): .int(1)])])), "malformed monitor state: bad deadline key")
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: ["__proto__": .array([])])), "malformed monitor state: bad ledger key")
    }

    func testStateLedgerSizes() {
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: ["a": entries(9999)])))
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: ["a": entries(10_000)])))
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: ["a": entries(10_001)])), "malformed monitor state: bad ledger")
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: ["a": entries(1, amount: 0)])))
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: ["a": entries(1, amount: -1)])), "malformed monitor state: bad ledger entry")
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: ["a": .array([.int(1)])])), "malformed monitor state: bad ledger entry")
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: ["a": .array([.object(["t": .int(1001), "amount": .int(1)])])])),
                       "malformed monitor state: ledger entry after now (clock regression)")
    }

    func testStateTotalEntryLimit() {
        var l: JObject = keys(10, entries(10_000))
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: l)))
        l["extra"] = entries(1)
        XCTAssertEqual(Prohibitions.stateProblem(state(ledger: l)), "malformed monitor state: too many entries")
        var m: JObject = keys(9, entries(10_000))
        m["last"] = entries(9_999)
        XCTAssertNil(Prohibitions.stateProblem(state(ledger: m)))
    }

    func testStateDeadlines() {
        func dl(_ v: JSONValue) -> String? { Prohibitions.stateProblem(state(extra: ["deadlines": .object(["d": v])])) }
        XCTAssertNil(Prohibitions.stateProblem(state(extra: ["deadlines": .object(keys(1024, .int(1)))])))
        XCTAssertEqual(Prohibitions.stateProblem(state(extra: ["deadlines": .object(keys(1025, .int(1)))])), "malformed monitor state: too many deadline keys")
        XCTAssertNil(dl(.int(1)))
        XCTAssertNil(dl(.int(999_999)))
        XCTAssertNil(dl(.int(1_000_000)))
        XCTAssertEqual(dl(.int(1_000_001)), "malformed monitor state: bad deadline")
        XCTAssertEqual(dl(.int(0)), "malformed monitor state: bad deadline")
        XCTAssertEqual(dl(.double(1.5)), "malformed monitor state: bad deadline")
        XCTAssertEqual(Prohibitions.stateProblem(state(extra: ["deadlines": .string("x")])), "malformed monitor state: deadlines")
        XCTAssertEqual(Prohibitions.stateProblem(state(extra: ["deadlines": .array([])])), "malformed monitor state: deadlines")
    }

    func testCanonicalStateRefusesAMalformedState() {
        XCTAssertThrowsError(try Prohibitions.canonicalState(state(extra: ["seq": .int(-1)]))) { XCTAssertEqual(($0 as? PDFail)?.what, "malformed monitor state: seq") }
        XCTAssertThrowsError(try Prohibitions.stateDigest(.int(1)))
    }

    func testEntryOrderUsesTimeThenAmount() {
        func e(_ t: Int64?, _ a: Int64?) -> JSONValue {
            var o: JObject = [:]
            if let t = t { o["t"] = .int(t) }
            if let a = a { o["amount"] = .int(a) }
            return .object(o)
        }
        XCTAssertTrue(Prohibitions.entryLess(e(1, 9), e(2, 0)))
        XCTAssertFalse(Prohibitions.entryLess(e(2, 0), e(1, 9)))
        XCTAssertTrue(Prohibitions.entryLess(e(1, 1), e(1, 2)))
        XCTAssertFalse(Prohibitions.entryLess(e(1, 2), e(1, 1)))
        XCTAssertFalse(Prohibitions.entryLess(e(1, 2), e(1, 2)))
        // a missing time or amount counts as 0
        XCTAssertTrue(Prohibitions.entryLess(e(nil, 1), e(nil, 2)))
        XCTAssertFalse(Prohibitions.entryLess(e(nil, 2), e(nil, 1)))
        XCTAssertFalse(Prohibitions.entryLess(e(nil, nil), e(nil, nil)))
        XCTAssertTrue(Prohibitions.entryLess(e(nil, 5), e(1, 0)))
        XCTAssertTrue(Prohibitions.entryLess(e(nil, nil), e(nil, 1)))
        XCTAssertFalse(Prohibitions.entryLess(e(1, 0), e(nil, 5)))
        XCTAssertTrue(Prohibitions.entryLess(e(1, nil), e(1, 1)))
        XCTAssertFalse(Prohibitions.entryLess(e(1, 0), e(1, nil)))
    }

    func testTickState() {
        let s = state()
        let same = Prohibitions.tickState(s, now: 1000)
        XCTAssertTrue(same.ok)
        XCTAssertEqual(same.state?.get("now"), .int(1000))
        let later = Prohibitions.tickState(s, now: 2000)
        XCTAssertTrue(later.ok)
        XCTAssertEqual(later.state?.get("now"), .int(2000))
        let back = Prohibitions.tickState(s, now: 999)
        XCTAssertFalse(back.ok)
        XCTAssertEqual(back.reason, "clock regression")
        XCTAssertEqual(Prohibitions.tickState(s, now: .nan).reason, "clock regression")
        XCTAssertEqual(Prohibitions.tickState(s, now: .infinity).reason, "clock regression")
        let bad = Prohibitions.tickState(.int(1), now: 1000)
        XCTAssertFalse(bad.ok)
        XCTAssertNil(bad.state)
        XCTAssertEqual(bad.reason, "malformed monitor state")
    }

    // ---- trigger matching ------------------------------------------------------------------------------------------------------

    func testRegexResourceSubjectLimit() {
        let w = J(#"{"verb":"v","resource":"re:^b+$"}"#)
        func ctx(_ n: Int) -> JSONValue { J(#"{"action":{"verb":"v","resource":"\#(String(repeating: "a", count: n))"}}"#) }
        XCTAssertFalse(Prohibitions.whenMatches(w, ctx(511)))
        XCTAssertFalse(Prohibitions.whenMatches(w, ctx(512)))
        XCTAssertTrue(Prohibitions.whenMatches(w, ctx(513)), "an oversized subject cannot be decided: the veto applies")
        XCTAssertTrue(Prohibitions.whenMatches(w, J(#"{"action":{"verb":"v","resource":"bbb"}}"#)))
    }

    func testWhenAffirmative() {
        let ctx = J(#"{"action":{"verb":"v","resource":"/r"}}"#)
        XCTAssertTrue(Prohibitions.whenAffirmative(J(#"{"verb":"v"}"#), ctx))
        XCTAssertFalse(Prohibitions.whenAffirmative(J(#"{"verb":"w"}"#), ctx))
        XCTAssertFalse(Prohibitions.whenAffirmative(J(#"{"verb":""}"#), ctx), "a malformed trigger is never affirmative")
        XCTAssertFalse(Prohibitions.whenAffirmative(nil, ctx))
        XCTAssertTrue(Prohibitions.whenMatches(J(#"{"verb":""}"#), ctx), "a malformed trigger always matches a veto")
    }

    func testWindowEntriesDefaultsAndEdges() {
        func entriesFor(_ state: String, _ ws: JSONValue?) -> [JSONValue] { Prohibitions.windowEntries(O(state), "x", ws) }
        // no `now`: 0
        XCTAssertEqual(entriesFor(#"{"ledger":{"x":[{"t":1,"amount":1}]}}"#, nil).count, 0)
        XCTAssertEqual(entriesFor(#"{"ledger":{"x":[{"t":0,"amount":1}]}}"#, nil).count, 1)
        // a window that is not a number is 0 seconds: only entries after `now` would count, so none
        XCTAssertEqual(entriesFor(#"{"now":5000,"ledger":{"x":[{"t":5000,"amount":1}]}}"#, .string("z")).count, 0)
        // an entry without a time is time 0: outside a window that starts at 0
        XCTAssertEqual(entriesFor(#"{"now":5000,"ledger":{"x":[{"amount":1}]}}"#, .int(5)).count, 0)
        XCTAssertEqual(entriesFor(#"{"now":5000,"ledger":{"x":[{"amount":1}]}}"#, nil).count, 1)
        // the window start is exclusive, `now` inclusive
        let s = #"{"now":10000,"ledger":{"x":[{"t":5000,"amount":1},{"t":5001,"amount":2},{"t":5004,"amount":5},{"t":10000,"amount":3},{"t":10001,"amount":4}]}}"#
        XCTAssertEqual(entriesFor(s, .int(5)).compactMap { $0.get("amount") }, [JSONValue.int(2), JSONValue.int(5), JSONValue.int(3)])
        XCTAssertEqual(entriesFor(#"{"now":1,"ledger":{}}"#, nil).count, 0)
    }

    // ---- evaluation ------------------------------------------------------------------------------------------------------------

    func eval(_ inv: String, _ ctx: String, _ state: String = #"{"now":1000,"ledger":{},"latched":{}}"#) -> (ok: Bool, reason: JSONValue?) {
        Prohibitions.evalOne(O(inv), J(ctx), O(state), SafeRegex.Budget())
    }
    func pay(_ amount: String) -> String { #"{"action":{"verb":"pay","resource":"/r","params":{"amount":\#(amount)}}}"# }

    func testCapAmounts() {
        let cap = #"{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.amount","max":5}"#
        XCTAssertTrue(eval(cap, pay("0")).ok, "a zero amount is a valid amount")
        XCTAssertTrue(eval(cap, pay("5")).ok)
        XCTAssertEqual(eval(cap, pay("6")).reason, .string("cap exceeded: 0 + 6 > 5"))
        XCTAssertEqual(eval(cap, pay("-1")).reason, .string("amount unresolvable (fail closed)"))
        XCTAssertEqual(eval(cap, #"{"action":{"verb":"pay","resource":"/r"}}"#).reason, .string("amount unresolvable (fail closed)"))
        XCTAssertTrue(eval(cap, #"{"action":{"verb":"other","resource":"/r"}}"#).ok)
        // an entry without an amount adds nothing; a cap without a max allows nothing positive
        XCTAssertTrue(eval(cap, pay("5"), #"{"now":1000,"ledger":{"c":[{"t":1000}]},"latched":{}}"#).ok)
        XCTAssertFalse(eval(#"{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.amount"}"#, pay("1")).ok)
        XCTAssertTrue(eval(#"{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.amount"}"#, pay("0")).ok)
    }

    func testRateWithoutMax() {
        let ctx = #"{"action":{"verb":"call","resource":"/r"}}"#
        XCTAssertFalse(eval(#"{"id":"r","kind":"rate","when":{"verb":"call"},"window_secs":10}"#, ctx).ok)
        let r = #"{"id":"r","kind":"rate","when":{"verb":"call"},"max":1,"window_secs":10}"#
        XCTAssertTrue(eval(r, ctx).ok)
        XCTAssertEqual(eval(r, ctx, #"{"now":1000,"ledger":{"r":[{"t":1000,"amount":1}]},"latched":{}}"#).reason, .string("rate exceeded: 2 > 1 per 10s"))
        XCTAssertTrue(eval(r, #"{"action":{"verb":"other","resource":"/r"}}"#).ok)
    }

    func testApprovalOverThreshold() {
        let fail = #"[{"field":"action.params.zzz","op":"eq","value":1}]"#
        let ra = #"{"id":"a","kind":"require_approval_over","when":{"verb":"pay"},"amount":"action.params.amount","threshold":50,"approved":\#(fail)}"#
        XCTAssertTrue(eval(ra, pay("0")).ok, "zero is not over the threshold")
        XCTAssertTrue(eval(ra, pay("50")).ok)
        XCTAssertEqual(eval(ra, pay("51")).reason, .string("approval required over 50"))
        XCTAssertFalse(eval(ra, pay("-1")).ok, "an unresolvable amount counts as over")
        XCTAssertFalse(eval(ra, #"{"action":{"verb":"pay","resource":"/r"}}"#).ok)
        XCTAssertTrue(eval(ra, #"{"action":{"verb":"other","resource":"/r"}}"#).ok, "a trigger that does not match leaves the action alone")
        // no threshold = 0
        XCTAssertFalse(eval(#"{"id":"a","kind":"require_approval_over","when":{"verb":"pay"},"amount":"action.params.amount","approved":\#(fail)}"#, pay("1")).ok)
    }

    func testNeverAfterAndRequirePriorAndUnknownKind() {
        let ctx = #"{"action":{"verb":"send","resource":"/net"}}"#
        let na = #"{"id":"n","kind":"never_after","after":{"verb":"read"},"forbid":{"verb":"send"}}"#
        XCTAssertTrue(eval(na, ctx).ok)
        XCTAssertEqual(eval(na, ctx, #"{"now":1000,"ledger":{},"latched":{"n":1000}}"#).reason, .string("forbidden after trigger"))
        XCTAssertTrue(eval(na, #"{"action":{"verb":"read","resource":"/net"}}"#, #"{"now":1000,"ledger":{},"latched":{"n":1000}}"#).ok)
        let rp = #"{"id":"p","kind":"require_prior","when":{"verb":"send"},"prior":{"verb":"review"}}"#
        XCTAssertEqual(eval(rp, ctx).reason, .string("required prior action not admitted"))
        XCTAssertTrue(eval(rp, ctx, #"{"now":1000,"ledger":{},"latched":{"p":1000}}"#).ok)
        XCTAssertTrue(eval(rp, #"{"action":{"verb":"other","resource":"/r"}}"#).ok, "a trigger that does not match leaves the action alone")
        let bogus = eval(#"{"id":"b","kind":"bogus"}"#, ctx)
        XCTAssertFalse(bogus.ok)
        XCTAssertEqual(bogus.reason, .string("evaluation error (fail closed)"))
    }

    // ---- advance ---------------------------------------------------------------------------------------------------------------

    let capNoWindow = #"{"version":1,"principal":"p","invariants":[{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.amount","max":1000000000}]}"#
    let capWindow = #"{"version":1,"principal":"p","invariants":[{"id":"c","kind":"cap","when":{"verb":"pay"},"amount":"action.params.amount","max":1000000000,"window_secs":10}]}"#
    let rateCons = #"{"version":1,"principal":"p","invariants":[{"id":"r","kind":"rate","when":{"verb":"call"},"max":10000,"window_secs":100000}]}"#
    func payAct(_ a: String) -> String { #"{"action":{"verb":"pay","resource":"/r","params":{"amount":\#(a)}}}"# }

    func stateOf(_ now: Int64, _ ledger: JObject) -> JSONValue {
        .object(["now": .int(now), "seq": .int(0), "parent": .null, "ledger": .object(ledger), "latched": .object([:])])
    }
    func ent(_ t: Int64, _ a: Int64) -> JSONValue { .object(["t": .int(t), "amount": .int(a)]) }
    func ledgerOf(_ r: AdvanceStateResult, _ id: String) -> [JSONValue] { r.state?.get("ledger")?.get(id)?.asArray ?? [] }

    func testAdvanceRefusesBadConstitutionAndState() {
        let badCons = Prohibitions.advanceStateStrict(J(payAct("1")), J(#"{"version":2,"principal":"p","invariants":[]}"#), state())
        XCTAssertFalse(badCons.ok)
        XCTAssertNil(badCons.state)
        XCTAssertEqual(badCons.reason, "unsupported version 2")
        let badState = Prohibitions.advanceStateStrict(J(payAct("1")), J(capNoWindow), state(extra: ["seq": .int(-1)]))
        XCTAssertFalse(badState.ok)
        XCTAssertEqual(badState.reason, "malformed monitor state: seq")
        XCTAssertEqual(Prohibitions.advanceStateStrict(J(payAct("1")), J(capNoWindow), state(), now: 999).reason, "clock regression")
        XCTAssertEqual(Prohibitions.advanceStateStrict(J(payAct("1")), J(capNoWindow), state(), now: .nan).reason, "clock regression")
        XCTAssertEqual(Prohibitions.advanceStateStrict(.int(1), J(capNoWindow), state()).reason, "malformed action")
    }

    func testAdvanceCapWindowPruning() {
        let s = stateOf(100_000, ["c": .array([ent(1, 1), ent(90_000, 2), ent(90_005, 7), ent(95_000, 3)])])
        let r = Prohibitions.advanceStateStrict(J(payAct("4")), J(capWindow), s)
        XCTAssertTrue(r.ok, r.reason ?? "")
        XCTAssertEqual(ledgerOf(r, "c"), [ent(90_005, 7), ent(95_000, 3), ent(100_000, 4)], "the entry exactly at the window start is gone")
        // no window: nothing is pruned
        let all = Prohibitions.advanceStateStrict(J(payAct("4")), J(capNoWindow), s)
        XCTAssertEqual(ledgerOf(all, "c"), [ent(1, 1), ent(90_000, 2), ent(90_005, 7), ent(95_000, 3), ent(100_000, 4)])
        XCTAssertEqual(all.state?.get("seq"), .int(1))
    }

    func testAdvanceCapAmounts() {
        let zero = Prohibitions.advanceStateStrict(J(payAct("0")), J(capNoWindow), state())
        XCTAssertTrue(zero.ok, zero.reason ?? "")
        XCTAssertEqual(ledgerOf(zero, "c"), [ent(1000, 0)])
        XCTAssertEqual(Prohibitions.advanceStateStrict(J(payAct("-1")), J(capNoWindow), state()).reason, "c: amount unresolvable")
        XCTAssertEqual(Prohibitions.advanceStateStrict(J(#"{"action":{"verb":"pay","resource":"/r"}}"#), J(capNoWindow), state()).reason, "c: amount unresolvable")
        let other = Prohibitions.advanceStateStrict(J(#"{"action":{"verb":"read","resource":"/r"}}"#), J(capNoWindow), state())
        XCTAssertTrue(other.ok)
        XCTAssertEqual(ledgerOf(other, "c"), [])
    }

    func testAdvanceKeepsEqualTimesOrderedByAmount() {
        let s = stateOf(1000, ["c": .array([ent(1000, 5)])])
        let r = Prohibitions.advanceStateStrict(J(payAct("1")), J(capNoWindow), s)
        XCTAssertEqual(ledgerOf(r, "c"), [ent(1000, 1), ent(1000, 5)])
    }

    func testAdvanceRateRecordsOneUnit() {
        let r = Prohibitions.advanceStateStrict(J(#"{"action":{"verb":"call","resource":"/r"}}"#), J(rateCons), state())
        XCTAssertTrue(r.ok, r.reason ?? "")
        XCTAssertEqual(ledgerOf(r, "r"), [ent(1000, 1)])
    }

    func testAdvanceMergesTheOldestTwoCapEntriesOnOverflow() {
        func full(_ n: Int) -> JSONValue { .array((0..<n).map { ent(Int64($0 + 1), Int64($0 + 1)) }) }
        let over = Prohibitions.advanceStateStrict(J(payAct("5")), J(capNoWindow), stateOf(1_000_000, ["c": full(10_000)]))
        XCTAssertTrue(over.ok, over.reason ?? "")
        let l = ledgerOf(over, "c")
        XCTAssertEqual(l.count, 10_000)
        XCTAssertEqual(l.first, ent(2, 3), "the oldest two merge, keeping the later time and the summed amount")
        XCTAssertEqual(l[1], ent(3, 3))
        XCTAssertEqual(l.last, ent(1_000_000, 5))
        // exactly at the limit nothing merges
        let exact = Prohibitions.advanceStateStrict(J(payAct("5")), J(capNoWindow), stateOf(1_000_000, ["c": full(9_999)]))
        let e = ledgerOf(exact, "c")
        XCTAssertEqual(e.count, 10_000)
        XCTAssertEqual(e.first, ent(1, 1))
        XCTAssertEqual(e[1], ent(2, 2))
    }

    func testAdvanceRefusesARateLedgerOverflow() {
        let s = stateOf(1_000_000, ["r": .array((0..<10_000).map { ent(Int64($0 + 1), 1) })])
        let r = Prohibitions.advanceStateStrict(J(#"{"action":{"verb":"call","resource":"/r"}}"#), J(rateCons), s)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "r: rate ledger overflow")
        let ok = stateOf(1_000_000, ["r": .array((0..<9_999).map { ent(Int64($0 + 1), 1) })])
        let fine = Prohibitions.advanceStateStrict(J(#"{"action":{"verb":"call","resource":"/r"}}"#), J(rateCons), ok)
        XCTAssertTrue(fine.ok, fine.reason ?? "")
        XCTAssertEqual(ledgerOf(fine, "r").count, 10_000)
    }

    // ---- evidence --------------------------------------------------------------------------------------------------------------

    func testEvidenceCarriesTheStateClock() {
        let cons = J(capNoWindow)
        let ev = Prohibitions.proveSafety(J(payAct("1")), cons, state())
        XCTAssertEqual(ev.get("now"), .int(1000))
        XCTAssertEqual(ev.get("ok"), .bool(true))
        let bad = Prohibitions.proveSafety(J(payAct("1")), cons, .int(1))
        XCTAssertEqual(bad.get("now"), .int(0))
        XCTAssertEqual(bad.get("state_digest"), .string(Prohibitions.UNHASHABLE))
        XCTAssertEqual(bad.get("ok"), .bool(false))
        XCTAssertEqual(bad.get("violated"), JSONValue.array([JSONValue.string("<state>")]))
    }

    // ---- signed evidence -------------------------------------------------------------------------------------------------------

    func key(_ n: UInt8) -> PCAEdKey { try! PCAEdKey(seed: [UInt8](repeating: n, count: 32)) }

    struct Signed {
        let signed: JSONValue
        let expected: JObject
    }

    func signedFixture(_ k: PCAEdKey, evidenceEdit: (inout JObject) -> Void = { _ in }) throws -> Signed {
        let cons = J(#"{"version":1,"principal":"\#(k.id)","invariants":[{"id":"n","kind":"never","when":{"verb":"delete"}}]}"#)
        let signedCons = try Prohibitions.signConstitution(cons, principal: k)
        let action = J(#"{"action":{"verb":"read","resource":"/r"}}"#)
        let st = state()
        var ev = Prohibitions.proveSafety(action, cons, st).asObject ?? [:]
        evidenceEdit(&ev)
        let signed = try Prohibitions.signSafetyEvidence(.object(ev), signer: k)
        return Signed(signed: signed, expected: ["signer": .string(k.id), "action": action, "constitution": signedCons, "state": st])
    }
    func verify(_ f: Signed, _ extra: JObject = [:], drop: [String] = []) -> ProhibitionVerdict {
        var ex = f.expected
        for (k, v) in extra { ex[k] = v }
        for k in drop { ex[JKey(k)] = nil }
        return Prohibitions.verifySignedSafetyEvidence(f.signed, .object(ex))
    }

    func testSignedEvidenceFullRecomputation() throws {
        let k = key(7)
        let f = try signedFixture(k)
        XCTAssertEqual(verify(f), .pass)
        XCTAssertEqual(verify(f, ["requireOk": .bool(false)]), .pass)
    }

    func testSignedEvidencePrincipalPin() throws {
        let k = key(7)
        let f = try signedFixture(k)
        XCTAssertEqual(verify(f, ["principal": .string(k.id)]), .pass)
        let other = verify(f, ["principal": .string(key(8).id)])
        XCTAssertFalse(other.ok)
        XCTAssertTrue(other.reason?.hasPrefix("constitution not authentic: ") ?? false, other.reason ?? "")
        XCTAssertEqual(verify(f, ["principal": .int(5)]), .no("constitution not authentic: principal mismatch"))
        // a pin needs a signed constitution
        let unsigned = J(#"{"version":1,"principal":"\#(k.id)","invariants":[{"id":"n","kind":"never","when":{"verb":"delete"}}]}"#)
        XCTAssertEqual(verify(f, ["principal": .string(k.id), "constitution": unsigned]), .no("principal pin requires a signed constitution"))
        XCTAssertEqual(verify(f, ["principal": .string(k.id), "constitution": .int(1)]), .no("principal pin requires a signed constitution"))
    }

    func testSignedEvidenceExpectedDigestsMustAgree() throws {
        let k = key(7)
        let f = try signedFixture(k)
        let ev = f.signed.get("evidence") ?? .null
        let cid = ev.get("constitution") ?? .null
        let sd = ev.get("state_digest") ?? .null
        let ad = ev.get("action_digest") ?? .null
        XCTAssertEqual(verify(f, ["constitutionId": cid]), .pass)
        XCTAssertEqual(verify(f, ["stateDigest": sd]), .pass)
        XCTAssertEqual(verify(f, ["actionDigest": ad]), .pass)
        XCTAssertEqual(verify(f, ["constitutionId": .string("zz")]), .no("expected constitution and id disagree"))
        XCTAssertEqual(verify(f, ["stateDigest": .string("zz")]), .no("expected state and digest disagree"))
        XCTAssertEqual(verify(f, ["actionDigest": .string("zz")]), .no("expected action and digest disagree"))
        // digests alone bind, but each side must be named
        XCTAssertEqual(verify(f, ["constitutionId": cid, "stateDigest": sd, "actionDigest": ad], drop: ["constitution", "state", "action"]), .pass)
        XCTAssertEqual(verify(f, drop: ["action"]), .no("unbound: action not specified"))
        XCTAssertEqual(verify(f, drop: ["constitution"]), .no("unbound: constitution not specified"))
        XCTAssertEqual(verify(f, drop: ["state"]), .no("unbound: state not specified"))
    }

    func testSignedEvidencePinnedSigners() throws {
        let k = key(7)
        let f = try signedFixture(k)
        XCTAssertEqual(verify(f, ["signer": .array([.string(key(9).id), .string(k.id)])]), .pass)
        for bad in [JSONValue.string(""), JSONValue.int(5), JSONValue.array([]), JSONValue.array([.string(k.id), .string("")]), JSONValue.array([.string(k.id), .int(5)])] {
            XCTAssertEqual(verify(f, ["signer": bad]), .no("no pinned signer"), "\(bad)")
        }
        XCTAssertEqual(verify(f, ["signer": .string(key(9).id)]), .no("signer not trusted"))
    }

    func testSignedEvidenceRowsMustSupportTheVerdict() throws {
        let k = key(7)
        let f = try signedFixture(k) { ev in
            ev["evaluated"] = .array([.object(["id": .string("n"), "kind": .string("never"), "result": .string("violated")])])
        }
        XCTAssertEqual(verify(f), .no("evidence verdict inconsistent with rows"))
        let nonObject = try signedFixture(k) { ev in ev["evaluated"] = .array([.string("pass")]) }
        XCTAssertEqual(verify(nonObject), .no("evidence verdict inconsistent with rows"))
        // digests-only expectations check the rows against the constitution's ids
        let missing = try signedFixture(k) { ev in ev["evaluated"] = .array([]) }
        let sd = missing.signed.get("evidence")?.get("state_digest") ?? .null
        let ad = missing.signed.get("evidence")?.get("action_digest") ?? .null
        let cons = missing.expected["constitution"] ?? .null
        XCTAssertEqual(verify(missing, ["actionDigest": ad, "stateDigest": sd, "constitution": cons], drop: ["action", "state"]),
                       .no("evidence does not cover every invariant"))
    }

    func testNullAndMissingStatesAreUnhashable() {
        XCTAssertEqual(Prohibitions.safeDigest { throw PDFail(what: "x") }, Prohibitions.UNHASHABLE)
        XCTAssertEqual(Prohibitions.safeDigest { "d" }, "d")
    }

    // ---- signer and bound fields are required (as the reference) -----------------------------------------------------------------

    func testSigningRequiresANonEmptySigner() throws {
        let k = key(7)
        let ev = Prohibitions.proveSafety(J(#"{"action":{"verb":"read","resource":"/r"}}"#), J(#"{"version":1,"principal":"p","invariants":[{"id":"n","kind":"never","when":{"verb":"delete"}}]}"#), state())
        XCTAssertThrowsError(try Prohibitions.signSafetyEvidence(ev, signer: k, signerPublic: "")) { XCTAssertEqual("\($0)", "signSafetyEvidence: signer missing") }
        let s = try Prohibitions.signSafetyEvidence(ev, signer: k, signerPublic: "other")
        XCTAssertEqual(s.get("signer")?.asString, "other")
        XCTAssertEqual(s.get("id")?.asString, try Prohibitions.safetyBindingId(ev, signer: "other"))
    }

    func testBindingIdNeedsEveryBoundFieldAndAnObject() throws {
        let ev = Prohibitions.proveSafety(J(#"{"action":{"verb":"read","resource":"/r"}}"#), J(#"{"version":1,"principal":"p","invariants":[{"id":"n","kind":"never","when":{"verb":"delete"}}]}"#), state())
        XCTAssertNoThrow(try Prohibitions.safetyBindingId(ev, signer: "s"))
        for k in ["constitution", "action_digest", "state_digest"] {
            var o = ev.asObject ?? [:]
            o[JKey(k)] = nil
            XCTAssertThrowsError(try Prohibitions.safetyBindingId(.object(o), signer: "s"), k)
        }
        XCTAssertThrowsError(try Prohibitions.safetyBindingId(.null, signer: "s"))
        XCTAssertThrowsError(try Prohibitions.safetyBindingId(.string("x"), signer: "s"))
    }

    func testVerifyFailsClosedWhenABoundFieldIsMissing() throws {
        let k = key(7)
        let f = try signedFixture(k)
        for name in ["constitution", "action_digest", "state_digest"] {
            var sg = f.signed.asObject ?? [:]
            var ev = sg[JKey("evidence")]?.asObject ?? [:]
            ev[JKey(name)] = nil
            sg[JKey("evidence")] = .object(ev)
            XCTAssertEqual(Prohibitions.verifySignedSafetyEvidence(.object(sg), .object(f.expected)), .no("verification error (fail closed)"), name)
        }
    }
}
