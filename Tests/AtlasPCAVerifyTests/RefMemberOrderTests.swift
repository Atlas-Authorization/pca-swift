import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Parsed objects keep the member order of the text (JavaScript `Object.keys` order: index keys first), so the walks that depend on it
/// (ontology checker, drift, selectors, frames) agree with the reference on documents with two or more unknown members.
final class RefMemberOrderTests: XCTestCase {
    func testKeyOrderFollowsTheText() throws {
        let v = try StrictJSON.parse(#"{"zz":1,"b":2,"10":3,"aa":4,"2":5}"#)
        XCTAssertEqual(JS.keyOrder(v.asObject!).map { $0.s }, ["2", "10", "zz", "b", "aa"])
    }

    func testStringifyKeepsTheTextOrder() throws {
        let v = try StrictJSON.parse(#"{"zz":1,"b":{"y":1,"x":2}}"#)
        XCTAssertEqual(JS.stringify(v), #"{"zz":1,"b":{"y":1,"x":2}}"#)
    }

    func testOntologyIssuesFollowUnitOrder() throws {
        func codes(_ text: String) throws -> [String] {
            let issues = try PCAGoalOntology.checkOntology(try StrictJSON.parse(text)).asArray ?? []
            return issues.compactMap { $0.asObject?[JKey("code")]?.asString == "unit_exponent" ? $0.asObject?[JKey("where")]?.asString : nil }
        }
        let a = try codes(#"{"types":[],"units":{"zz":{"kind":"count","exponent":1},"aa":{"kind":"count","exponent":1}}}"#)
        let b = try codes(#"{"types":[],"units":{"aa":{"kind":"count","exponent":1},"zz":{"kind":"count","exponent":1}}}"#)
        XCTAssertEqual(a, ["zz", "aa"])
        XCTAssertEqual(b, ["aa", "zz"])
    }

    /// Selectors: the `@role` parameters withRoleParams adds follow the roles' own order (the reference's insertion order), after the parameters.
    func testRoleParamsFollowTheRoleOrder() throws {
        let cat = try StrictJSON.parse(#"{"known":[],"verbs":[{"verb":"pay","traits":[],"roles":{"zz":["amt"],"aa":["to"],"mm":["memo"]}}]}"#)
        let act = try StrictJSON.parse(#"{"verb":"pay","params":{"to":"a","memo":"m","amt":5}}"#)
        let out = try PCAGoalSelectors.withRoleParams(act, cat)
        XCTAssertEqual(JS.stringify(out.get("params")!), #"{"to":"a","memo":"m","amt":5,"@zz":5,"@aa":"a","@mm":"m"}"#)
        // a caller-sent `@` member is dropped and replaced
        let sent = try StrictJSON.parse(#"{"verb":"pay","params":{"@zz":9,"amt":5}}"#)
        XCTAssertEqual(JS.stringify(try PCAGoalSelectors.withRoleParams(sent, cat).get("params")!), #"{"amt":5,"@zz":5}"#)
    }

    /// Index-like member names come first in ascending order whatever their place in the text (JavaScript `Object.keys`), also through a copy.
    func testIndexKeysComeFirstThroughACopy() throws {
        let v = try StrictJSON.parse(#"{"b":1,"2":2,"a":3,"1":4}"#)
        var copy = JObject()
        for (k, x) in v.asObject! { copy[k] = x }
        XCTAssertEqual(JS.keyOrder(copy).map { $0.s }, ["1", "2", "b", "a"])
        XCTAssertEqual(JS.stringify(.object(copy)), #"{"1":4,"2":2,"b":1,"a":3}"#)
    }

    /// Drift: the parameters a monitor remembers (`seenOrder`, and so the sealed state text and its MAC) follow the member order of the action's parameters (index-like
    /// names first). The goal is the first one of the drift corpus.
    func testDriftSeenOrderFollowsTheParameterOrder() throws {
        var goal: JSONValue?
        _ = try Base.each("ref-goal-drift.json.gz", ["flow"]) { c in if goal == nil { goal = c.arg(0) } }
        let g = try XCTUnwrap(goal)
        let q = #"{"k":"q","q":{"u":{"k":"money","ccy":"USD"},"n":1}}"#
        func observed(_ params: String) throws -> PCAGoalDrift.Monitor {
            let m = PCAGoalDrift.Monitor(g, nil)
            _ = try m.observe(try StrictJSON.parse(#"{"verb":"pay","res":"acct:a","params":{\#(params)},"t":0}"#), .int(0))
            return m
        }
        let a = try observed(#""zz":\#(q),"10":\#(q),"aa":\#(q),"2":\#(q)"#)
        XCTAssertEqual(a.seenOrder, ["2", "10", "zz", "aa"])
        let m1 = try observed(#""zz":\#(q),"aa":\#(q)"#), m2 = try observed(#""aa":\#(q),"zz":\#(q)"#)
        XCTAssertEqual(m1.seenOrder, ["zz", "aa"])
        XCTAssertEqual(m2.seenOrder, ["aa", "zz"])
        XCTAssertEqual(m1.state(), m2.state()) // the same remembered values ...
        let key = [UInt8](repeating: 7, count: 32)
        XCTAssertNotEqual(m1.seal(key).get("mac"), m2.seal(key).get("mac")) // ... sealed over the text in each monitor's own order
    }

    /// Frames: the monitored state names are nested into the environment in the member order of the pre and post states, so a name that is a prefix of another one
    /// (`a` and `a.b`) leaves a scalar or an object at `a` depending on which came last.
    func testFrameStateNestsInMemberOrder() throws {
        let spec = try StrictJSON.parse(#"{"state":[],"writes":{"pay":[]},"post":[{"id":"p1","verb":"pay","deltas":[{"path":"a","by":0}]}]}"#)
        let action = try StrictJSON.parse(#"{"verb":"pay"}"#)
        func report(_ state: String) throws -> JSONValue {
            let s = try StrictJSON.parse(state)
            return PCAIntentFrames.checkFrame(spec, action, s, s, nil)
        }
        // `a.b` then `a`: the scalar replaces the object, so a delta of 0 holds
        XCTAssertEqual(try report(#"{"a.b":{"digest":"d1","value":1},"a":{"digest":"d2","value":5}}"#).get("status")?.asString, "ok")
        // `a` then `a.b`: the object replaces the scalar, so `a` is not a number and the postcondition is pending
        let r = try report(#"{"a":{"digest":"d2","value":5},"a.b":{"digest":"d1","value":1}}"#)
        XCTAssertEqual(r.get("status")?.asString, "pending")
        XCTAssertEqual(r.get("missing")?.asArray?.compactMap { $0.asString }, ["p1:a"])
    }
}
