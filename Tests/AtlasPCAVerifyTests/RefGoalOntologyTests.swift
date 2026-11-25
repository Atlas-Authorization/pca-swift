import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the intent ontology (PCAGoalOntology / PCAGoalOntologies: shipped data, digest, verb resolution, IR projection,
/// checker, template instantiation, slot typing, amount parsing) against the reference (@atlasauth/pca-goal). A reference throw
/// requires a native refusal.
final class RefGoalOntologyTests: XCTestCase {
    static let file = "ref-goal-ontology.json.gz"
    typealias O = PCAGoalOntology

    /// A shipped ontology travels by name; a hand-written one inline.
    static func ont(_ v: JSONValue?) throws -> JSONValue {
        if let name = v?.asString {
            guard let o = try PCAGoalOntologies.ontology(name) else { throw JSError("unknown ontology") }
            return o
        }
        guard let o = v, o.asObject != nil else { throw JSError("ontology expected") }
        return o
    }

    static func str(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("string expected") }
        return s
    }

    @discardableResult
    static func object(_ v: JSONValue?) throws -> JSONValue {
        guard let o = v, o.asObject != nil else { throw JSError("object expected") }
        return o
    }

    static func int(_ v: JSONValue?) throws -> Int {
        guard let d = IV.num(v), d.isFinite else { throw JSError("number expected") }
        return Int(d)
    }

    static func opt(_ v: JSONValue?) -> JSONValue? {
        guard let x = v, x != JSONValue.null else { return nil }
        return x
    }

    static func optStr(_ v: JSONValue?) -> String? { opt(v)?.asString }

    func testOntologyAgainstTheReference() throws {
        try K042.requireCovers(["GoalOntolog"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "shippedOntology": return (try PCAGoalOntologies.ontology(try Self.str(a[0]))) ?? JSONValue.null
                case "shippedCatalog": return (try PCAGoalOntologies.selCatalog(try Self.str(a[0]))) ?? JSONValue.null
                case "ontologyDigest": return .string(try O.ontologyDigest(try Self.ont(a[0])))
                case "resolveVerb": return Base.opt(try O.resolveVerb(try Self.ont(a[0]), try Self.str(a[1])))
                case "goalCcy": try Self.object(a[0]); return Base.opt(try O.goalCcy(a[0]))
                case "goalAnchors": try Self.object(a[0]); return try O.goalAnchors(a[0])
                case "toIrOntology":
                    let opts = Self.opt(a.count > 1 ? a[1] : nil)
                    return try O.toIrOntology(try Self.ont(a[0]), Self.optStr(opts?.get("ccy")), Self.opt(opts?.get("rels")))
                case "ontologyForGoal":
                    try Self.object(a[1])
                    return try O.ontologyForGoal(try Self.ont(a[0]), a[1], a.count > 2 ? Self.opt(a[2]) : nil)
                case "checkOntology": return try O.checkOntology(try Self.ont(a[0]))
                case "instantiateTemplate":
                    guard let opts = Self.opt(a[3]), opts.asObject != nil else { throw JSError("options expected") }
                    return try O.instantiateTemplate(try Self.ont(a[0]), try Self.str(a[1]), Self.opt(a[2]), try Self.str(opts.get("principal")),
                                                     try Self.str(opts.get("nl")), Self.opt(opts.get("sources")))
                case "slotLits":
                    guard a[1].asObject != nil else { throw JSError("slot expected") }
                    return try O.slotLits(try Self.ont(a[0]), a[1], a[2])
                case "parseHumanAmount": return try O.parseHumanAmount(try Self.str(a[0]), try Self.int(a[1]), Self.optStr(a[2]))
                case "parseMoney": return try O.parseMoney(try Self.str(a[0]), try Self.int(a[1]), Self.optStr(a[2]))
                default: throw JSError("not mapped")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(2500)
    }
}
