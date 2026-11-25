import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the built-in action data, the domain vocabularies and the starter templates.
final class RefActionsDataTests: XCTestCase {
    func testData() throws {
        try K042.requireCovers(["ActionBuiltin", "ActionTemplates", "ActionData"])
        let d = Base.Diffs()
        try Base.each("ref-actions-data.json.gz") { c in
            let a0 = c.arg(0)
            let got: BaseGot
            switch c.fn {
            case "builtinDefs": got = .value(.array(ActionBuiltin.builtinDefs()))
            case "domainDefs": got = .value(.array(ActionBuiltin.domainDefs()))
            case "corePackDefs": got = .value(.array(ActionBuiltin.corePackDefs()))
            case "legacyCatalog": got = .value(.object(ActionBuiltin.legacyCatalog()))
            case "legacyOntologyEffect": got = .value(.object(ActionBuiltin.legacyOntologyEffect()))
            case "resolutions": got = .value(.array(ActionBuiltin.resolutions()))
            case "domainBindings": got = .value(.object(ActionBuiltin.domainVerbBindings()))
            case "coreDigests":
                got = RefActions.v {
                    var rows: [JSONValue] = []
                    for def in ActionBuiltin.corePackDefs() { rows.append(.array([def.get("verb") ?? .null, .string(try Actions.defDigest(RefActions.obj(def)))])) }
                    return .array(rows)
                }
            case "domainVerbs": got = RefActions.v { try ActionBuiltin.domainVerbs(a0?.asString ?? "") }
            case "domainRoles": got = RefActions.v { .object(try ActionBuiltin.domainRoles(a0?.asString ?? "")) }
            case "releasedBuiltinDefs": got = .value(.bool(ActionBuiltin.releasedBuiltinDefs(nil) == ActionBuiltin.builtinDefs()))
            case "builtinConfirmed": got = .value(.bool(ActionBuiltin.builtinReviewOpts(nil) != nil))
            case "starterTemplates": got = .value(.array(ActionTemplates.starterTemplates()))
            case "starterTemplate": got = .value(ActionTemplates.starterTemplate(a0?.asString).map { .object($0) } ?? .null)
            case "templateYaml": got = RefActions.v { .string(try ActionTemplates.yaml(a0?.asString, c.arg(1))) }
            case "templateTraits": got = RefActions.v { .array(try ActionTemplates.traits(a0?.asString, c.arg(1))) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(162)
    }
}
