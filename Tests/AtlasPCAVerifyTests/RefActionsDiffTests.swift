import XCTest
import Foundation
@testable import AtlasPCAVerify

enum RefActions {
    static func code(_ e: Error) -> String? { (e as? ActionKitError)?.code ?? (e as? JSError)?.code }
    static func v(_ f: () throws -> JSONValue) -> BaseGot { Base.run(code) { try f() } }
    static func obj(_ v: JSONValue?) -> JObject { v?.asObject ?? [:] }
    static func strictObj(_ v: JSONValue?) throws -> JObject {
        guard let o = v?.asObject else { throw ActionKitError(code: "not_object", message: "not an object") }
        return o
    }
    static func list(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }
    static func strs(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }
}

/// Differential replay of the action toolkit's id patterns, effective traits, param rules and the semantic def / pack diffs against the reference.
final class RefActionsDiffTests: XCTestCase {
    static let file = "ref-actions-diff.json.gz"

    func testDiff() throws {
        try K042.requireCovers(["ActionIdPattern", "ActionEffective", "ActionDiff", "Actions"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let confirmed = c.args.count > 2 && c.arg(2) == .bool(true)
            let got: BaseGot
            switch c.fn {
            case "idMatches": got = RefActions.v { .bool(try ActionIdPattern.idMatches(a0, a1?.asString ?? "")) }
            case "idPatternContains": got = RefActions.v { .bool(try ActionIdPattern.idPatternContains(a0, a1)) }
            case "join": got = RefActions.v { try ActionEffective.join(a0 ?? .null, a1 ?? .null) }
            case "leq": got = RefActions.v { .bool(try ActionEffective.leq(a0 ?? .null, a1 ?? .null)) }
            case "profileEq": got = RefActions.v { .bool(try ActionEffective.profileEq(a0 ?? .null, a1 ?? .null)) }
            case "effective":
                let cf = a1 == .bool(true)
                got = RefActions.v { .object(try ActionEffective.effective(RefActions.obj(a0), core, cf ? { _ in true } : { _ in false })) }
            case "hintTraits": got = RefActions.v { RefActions.strs(try ActionEffective.hintTraits(RefActions.obj(a0))) }
            case "prulesViolations": got = RefActions.v { RefActions.strs(try ActionEffective.prulesViolations(RefActions.obj(a0))) }
            case "effWithTrait": got = RefActions.v { try ActionEffective.effWithTrait(RefActions.obj(a0), a1?.asString ?? "", core) }
            case "requiredPrulesViolated": got = RefActions.v { RefActions.strs(try ActionEffective.requiredPrulesViolated(RefActions.obj(a0), a1 ?? .null)) }
            case "diffDefs": got = RefActions.v { try ActionDiff.diffDefs(RefActions.obj(a0), RefActions.obj(a1), core, confirmed ? { _ in true } : { _ in false }) }
            case "diffIsFree": got = .value(.bool(ActionDiff.diffIsFree(a0?.asString ?? "")))
            case "diffDefsAuthoring": got = RefActions.v { try ActionDefDiff.diffDefs(RefActions.obj(a0), RefActions.obj(a1), core) }
            case "diffPacks": got = RefActions.v { .array(try ActionDefDiff.diffPacks(RefActions.list(a0), RefActions.list(a1), core)) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1200)
    }
}
