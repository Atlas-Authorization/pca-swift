import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the signed evolution records and the confirmation-gated undo planner against the reference.
final class RefActionsEvolveTests: XCTestCase {
    func testEvolve() throws {
        try K042.requireCovers(["ActionEvolve", "ActionDiff", "ActionsRegistry"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each("ref-actions-evolve.json.gz", seeds: true) { c in
            let got: BaseGot
            switch c.fn {
            case "evolutionRecords":
                let cf = c.arg(3) == .bool(true)
                got = RefActions.v { .array(try ActionEvolve.evolutionRecords(c.arg(0)?.asString ?? "", RefActions.list(c.arg(1)), RefActions.list(c.arg(2)), core, cf ? { _ in true } : { _ in false })) }
            case "signEvolution":
                got = RefActions.v {
                    guard let seed = Base.bytes(c.arg(2)) else { throw ActionKitError(code: "bad_seed", message: "seed") }
                    let key = PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: seed))
                    return .array(try ActionEvolve.signEvolution(RefActions.list(c.arg(0)), kid: c.arg(1)?.asString ?? "", key: key))
                }
            case "evolutionError":
                let cf = c.arg(5) == .bool(true)
                got = .value(Base.opt(ActionEvolve.evolutionError(c.arg(0)?.asString ?? "", RefActions.list(c.arg(1)), RefActions.list(c.arg(2)), RefActions.list(c.arg(3)), c.arg(4), core, cf ? { _ in true } : { _ in false })))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(120)
    }

    func testUndoEngine() throws {
        try K042.requireCovers(["ActionUndo", "ActionEffective", "Approval"])
        let d = Base.Diffs()
        try Base.each("ref-actions-undo-engine.json.gz") { c in
            let got: BaseGot
            switch c.fn {
            case "undoPlan":
                let e = ActionUndoEngine.undoEngine(defs: RefActions.list(c.arg(0)), pins: c.arg(1))
                got = .value(e.plan(RefActions.obj(c.arg(2))) ?? .null)
            case "attested":
                let ok = ActionUndoEngine.attestationVerifier(c.arg(1), Actions.coreRegistry)(RefActions.obj(c.arg(0)))
                got = .value(.bool(ok))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(200)
    }
}
