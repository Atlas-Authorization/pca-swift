import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of the goal examples against the reference: decision cells, boundary examples, review set, goal tests and the policy pin.
/// A reference throw requires a native refusal. Cases a Swift String cannot represent are counted and printed by `Base.Diffs`.
final class RefGoalExamplesTests: XCTestCase {
    typealias E = PCAGoalExamples
    static let file = "ref-goal-examples.json.gz"

    private static func arr(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return a
    }

    private static func strs(_ v: JSONValue?) throws -> [String]? {
        guard let x = v, x != .null else { return nil }
        return try arr(x).map { guard let s = $0.asString else { throw JSError("not a string") }; return s }
    }

    private static func space(_ c: BaseCase) throws -> E.Space {
        guard let s = try strs(c.arg(1)) else { throw JSError("verbs expected") }
        return try E.buildSpace(try arr(c.arg(0)), s)
    }

    private static func need(_ v: JSONValue?) throws -> JSONValue {
        guard let x = v else { throw JSError("missing argument") }
        return x
    }

    private static func call(_ c: BaseCase) throws -> JSONValue? {
        switch c.fn {
        case "buildSpace": return try space(c).toJson()
        case "cells": return try E.cells(try space(c), try strs(c.arg(2)))
        case "cellKey": return .string(try E.cellKey(try space(c), try need(c.arg(2))))
        case "decideCase": return try E.decideCase(try need(c.arg(0)), try need(c.arg(1)), try need(c.arg(2)))
        case "replay":
            var rels: [JSONValue]? = nil
            if let r3 = c.arg(3), r3 != JSONValue.null { rels = try arr(r3) }
            return try E.replay(try need(c.arg(0)), try need(c.arg(1)), try arr(c.arg(2)), rels)
        case "allowWitness":
            let g = try need(c.arg(0))
            guard let i = IV.int(c.arg(1)) else { throw JSError("index expected") }
            let grants = try arr(g.get("grants"))
            guard Int(i) >= 0 && Int(i) < grants.count else { throw JSError("grant index") }
            // no witness is a null (`undefined` in the reference)
            return try E.allowWitness(g, grants[Int(i)], try need(c.arg(2))) ?? .null
        case "boundaryExamples":
            var extra: [JSONValue]? = nil
            if let x = c.arg(2), x != .null { extra = try arr(x) }
            return try E.boundaryExamples(try need(c.arg(0)), try need(c.arg(1)), extra, try strs(c.arg(3)))
        case "reviewSet":
            guard let n = IV.int(c.arg(1)) else { throw JSError("cap expected") }
            return .array(try E.reviewSet(try arr(c.arg(0)), Int(n)))
        case "testsDigest": return .string(try E.testsDigest(try arr(c.arg(0))))
        case "makeGoalTests": return try E.makeGoalTests(try need(c.arg(0)), try arr(c.arg(1)))
        case "signGoalTestsSeed": return try E.signGoalTests(try need(c.arg(0)), try seed(c.arg(1)))
        case "checkGoalTests":
            let mode = c.arg(2)?.asString ?? ""
            let g = try need(c.arg(3))
            let ont = try need(c.arg(4))
            return try E.checkGoalTests(try need(c.arg(0)), try arr(c.arg(1))) { (t: JSONValue) throws -> String in
                if mode == "ref" { return try E.decideCase(g, ont, t).get("decision")?.asString ?? "" }
                if mode == "allow" { return "allow" }
                if mode == "deny" { return "deny" }
                return "escalate"
            }
        case "signPinSeed": return try E.signPin(try need(c.arg(0)), try seed(c.arg(1)))
        case "checkPin": return try E.checkPin(try need(c.arg(0)), try arr(c.arg(1)), try need(c.arg(2)))
        default: return nil
        }
    }

    private static func seed(_ v: JSONValue?) throws -> [UInt8] {
        guard let s = v?.asString, let b = Base64URLStrict.decode(s) else { throw JSError("seed expected") }
        return b
    }

    func testReplayAgainstReference() throws {
        let d = Base.Diffs()
        var unknown = 0
        // the signing cases name their key as a {$seed: label} object
        try Base.each(Self.file, seeds: true) { c in
            // checkGoalTests runs the policy through a closure: its failure is a refusal too
            var known = true
            let got: BaseGot = Base.run { () throws -> JSONValue in
                guard let v = try Self.call(c) else { known = false; return .null }
                return v
            }
            if !known { unknown += 1; d.skip("function not replayed: \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(unknown, 0, "every function of the corpus is replayed")
        d.finish(100)
    }
}
