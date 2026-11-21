import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the approval rendering, the facade rows and the provenance facts of action defs.
final class RefActionsRenderTests: XCTestCase {
    func testRenderFacade() throws {
        try K042.requireCovers(["ActionApprovals", "ActionProvenance", "ActionDerive", "Approval"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each("ref-actions-render-facade.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
            let got: BaseGot
            switch c.fn {
            case "renderApproval": got = RefActions.v { try ActionApprovals.renderApproval(RefActions.obj(a0), a1, a2 == .bool(true)) }
            case "renderDigestForAction": got = RefActions.v { .string(try ActionApprovals.renderDigestForAction(RefActions.obj(a0), RefActions.obj(a1), RefActions.obj(a2), a3 == .bool(true))) }
            case "approverRenderCheck": got = RefActions.v { .string(try ActionApprovals.approverRenderCheck(RefActions.obj(a0), RefActions.obj(a1), a2?.asString, a3 == .bool(true))) }
            case "singleTapAllowed": got = .value(.bool(ActionApprovals.singleTapAllowed(RefActions.obj(a0))))
            case "renderersFromDefs": got = RefActions.v { try ActionApprovals.renderFromDefs(RefActions.list(a0), a1?.asString ?? "", a2?.asObject, a3 == .bool(true)) }
            case "specOfDef": got = RefActions.v { try ActionFacade.specOfDef(RefActions.obj(a0), core, reviewed: a1 == .bool(true), RefActions.fixed(a2)) }
            case "facadeSpecs": got = RefActions.v { .array(try ActionFacade.facadeSpecs(RefActions.list(a0), core, reviewed: a1 == .bool(true), RefActions.fixed(a2))) }
            case "provenanceInfoOf": got = RefActions.v { try ActionProvenance.provenanceInfoOf(RefActions.obj(a0), core, RefActions.fixed(a1)) }
            case "provenanceActions":
                got = RefActions.v {
                    let f = try ActionProvenance.provenanceActions(RefActions.list(a0), core, RefActions.fixed(a1))
                    return .array(RefActions.list(a2).map { f($0.asString ?? "") ?? .null })
                }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(800)
    }
}
