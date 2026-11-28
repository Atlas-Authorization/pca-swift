import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the lint rules, the findings output (text and SARIF) and the undo shape checks the linter uses.
final class RefActionsLintTests: XCTestCase {
    func testLint() throws {
        try K042.requireCovers(["ActionLint", "ActionUndo", "ActionEffective", "PolicyCi"])
        let d = Base.Diffs()
        try Base.each("ref-actions-lint.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "lintDefs":
                let opts = a1?.asObject
                let att = opts?["att"]
                got = RefActions.v { .array(try ActionLint.lintDefs(RefActions.list(a0), opts, att == nil || att == .null ? nil : RefActions.fixed(att))) }
            case "lintRulesDigest": got = RefActions.v { .string(try ActionLint.lintRulesDigest()) }
            case "LINT_RULES": got = .value(.array(PCAPolicyCi.LINT_RULES.map { RefActions.strs([$0.id, $0.severity, $0.title]) }))
            case "lintFails": got = .value(.bool(ActionLint.lintFails(RefActions.list(a0), a1 == .bool(true))))
            case "lintText": got = .value(.string(ActionLint.lintText(RefActions.list(a0))))
            case "toSarif": got = .value(ActionLint.toSarif(RefActions.list(a0), c.args.count > 1 ? a1?.asObject : nil))
            case "reversibilityFor": got = RefActions.v { .string(try ActionUndo.reversibilityFor(RefActions.obj(a0), RefActions.obj(a1))) }
            case "mayBeReversible": got = .value(.bool(ActionUndo.mayBeReversible(RefActions.obj(a0))))
            case "compensationShape": got = RefActions.v { try ActionUndo.compensationShape(RefActions.obj(a0), RefActions.obj(a1)) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(2100)
    }
}
