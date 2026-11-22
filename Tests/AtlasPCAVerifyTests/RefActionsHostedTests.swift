import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the hosted action registry (publish gate, rules documents, the verifier view) and the source sync.
final class RefActionsHostedTests: XCTestCase {
    func testHosted() throws {
        try K042.requireCovers(["ActionHosted", "ActionSync", "ActionBusinessRules"])
        let d = Base.Diffs()
        try Base.each("ref-actions-hosted.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            let got: BaseGot
            switch c.fn {
            case "publishGate": got = RefActions.v { .object(try ActionHosted.publishGate(RefActions.obj(a0))) }
            case "rulesDocError": got = .value(Base.opt(ActionHosted.rulesDocError(a0, "acme", RefActions.list(a1))))
            case "hostedVersionDigest": got = RefActions.v { .string(try ActionHosted.hostedVersionDigest(RefActions.obj(a0))) }
            case "viewLookup": got = .value(.object(ActionHosted.hostedView(RefActions.list(a0), a1).lookup(a2?.asString ?? "")))
            case "viewProvenance": got = .value(ActionHosted.hostedView(RefActions.list(a0), a1).provenance(a2?.asString ?? "") ?? .null)
            case "viewFloor": got = .value(.string(ActionHosted.hostedView(RefActions.list(a0), a1).floor(a2?.asString ?? "", RefActions.obj(c.arg(3)), RefActions.list(c.arg(4)))))
            case "viewUndo": got = .value(ActionHosted.hostedView(RefActions.list(a0), a1).undoPlan(RefActions.obj(a2)) ?? .null)
            case "hostedCallContext": got = RefActions.v { .array(try ActionHosted.hostedCallContext(lookup: a0, params: a1)) }
            case "rateKeysOf": got = .value(.array(ActionHosted.rateKeysOf(RefActions.obj(a0), RefActions.obj(a1))))
            case "grantFactsOf": got = .value(.object(ActionHosted.grantFactsOf(a0)))
            case "syncSource":
                let confirmed = c.arg(3) == .bool(true)
                got = RefActions.v { .object(try ActionSync.syncSource(RefActions.list(a0), RefActions.list(a1), String(repeating: "S", count: 43), a2?.asObject, .int(1_800_000_000), nil, { _ in confirmed })) }
            case "syncText": got = .value(.string(ActionSync.syncText(RefActions.obj(a0))))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(700)
    }
}
