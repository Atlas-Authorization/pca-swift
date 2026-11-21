import XCTest
import Foundation
@testable import AtlasPCAVerify

extension RefActions {
    static func fixed(_ v: JSONValue?) -> (JObject) -> Bool { let c = v == .bool(true); return { _ in c } }
}

/// Differential replay of what an action def yields: params, effect class, schema, operation binding, risk, predicates, ontology, card.
final class RefActionsDeriveTests: XCTestCase {
    func testDerive() throws {
        try K042.requireCovers(["ActionDerive", "ActionEffective", "ActionIdPattern", "Actions"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each("ref-actions-derive.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let def = RefActions.obj(a0)
            let got: BaseGot
            switch c.fn {
            case "flattenParams": got = .value(.object(ActionDerive.flattenParams(def)))
            case "paramByRole": got = RefActions.v { .string(try ActionDerive.paramByRole(def, a1?.asString ?? "")) }
            case "effectClass": got = RefActions.v { .string(try ActionDerive.effectClass(def)) }
            case "resourceMatcher": got = .value(.string(ActionDerive.resourceMatcher(def)))
            case "toSchemaVerb": got = RefActions.v { try ActionDerive.toSchemaVerb(def, core, RefActions.fixed(a1)) }
            case "cardOf": got = RefActions.v { try ActionDerive.cardOf(def, try ActionEffective.effective(def, core, RefActions.fixed(a1)), core) }
            case "escalationOf": got = RefActions.v { try ActionDerive.escalationOf(try ActionEffective.effective(def, core, RefActions.fixed(a1))) }
            case "mcpAnnotationsOf": got = RefActions.v { ActionDerive.mcpAnnotationsOf(def, try ActionEffective.effective(def, core, RefActions.fixed(a1))) }
            case "explainDef": got = RefActions.v { .string(try ActionExplain.explainDef(def, core, RefActions.fixed(a1))) }
            case "operationOf": got = RefActions.v { try ActionDerive.operationOf(def, RefActions.obj(a1)) }
            case "riskOf":
                got = RefActions.v {
                    let eff = try ActionEffective.effective(def, core, RefActions.fixed(a1))
                    return try ActionDerive.riskOf(def, eff, c.arg(2)?.asObject, c.arg(3)?.asObject)
                }
            case "predicatesOf": got = RefActions.v { try ActionDerive.predicatesOf(def, c.args.count > 1 ? a1?.asObject : nil) }
            case "REVERSIBILITY_SCORE":
                got = .value(.object(Dictionary(uniqueKeysWithValues: ActionDerive.REVERSIBILITY_SCORE.map { (JKey($0.key), JSONValue.double($0.value)) })))
            case "toSchemaDoc":
                got = RefActions.v {
                    var reg = core
                    if let r = c.arg(3), r != .null { reg = try Actions.extendRegistry(core, RefActions.list(r)) }
                    return try ActionDerive.toSchemaDoc(RefActions.list(a0), reg, RefActions.obj(a1), RefActions.fixed(c.arg(2)))
                }
            case "toOntology": got = RefActions.v { try ActionDerive.toOntology(RefActions.list(a0), core, RefActions.fixed(a1)) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1700)
    }
}
