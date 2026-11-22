import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the legacy-vocabulary shims, selector matching, the policy decision and the signed review confirmation.
final class RefActionsSelConfTests: XCTestCase {
    func testCompat() throws {
        try K042.requireCovers(["ActionCompat"])
        let d = Base.Diffs()
        try Base.each("ref-actions-compat.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "normalizeReversibility": got = .value(.string(ActionCompat.normalizeReversibility(a0)))
            case "legacyOperationsClass": got = .value(.string(ActionCompat.legacyOperationsClass(a0?.asString ?? "")))
            case "maxRevOf": got = .value(.string(ActionCompat.maxRevOf(a0?.asString ?? "", a1?.asString ?? "")))
            case "unitTagOf": got = .value(ActionCompat.unitTagOf(RefActions.obj(a0)) ?? .null)
            case "blastOfFloat": got = RefActions.v { guard let x = IV.num(a0) else { throw ActionKitError(code: "bad_arg", message: "num") }; return ActionCompat.blastOfFloat(x) }
            case "blastExactOfFloat": got = RefActions.v { guard let x = IV.num(a0) else { throw ActionKitError(code: "bad_arg", message: "num") }; return ActionCompat.blastExactOfFloat(x) }
            case "fromCatalogSpec": got = RefActions.v { try ActionCompat.fromCatalogSpec(RefActions.obj(a0), c.args.count > 1 ? a1?.asObject : nil) }
            case "fromCatalog": got = RefActions.v { .array(try ActionCompat.fromCatalog(RefActions.list(a0), c.args.count > 1 ? a1?.asObject : nil)) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(120)
    }

    func testSelectorsAndConfirmation() throws {
        try K042.requireCovers(["ActionSelectors", "ActionConfirmation"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each("ref-actions-sel-conf.json.gz", seeds: true) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "selectorMatches": got = RefActions.v { .bool(try ActionSelectors.selectorMatches(a0, RefActions.list(a1))) }
            case "selectorMatchesFor": got = RefActions.v { .bool(try ActionSelectors.selectorMatchesFor(a0, a1?.asString ?? "", RefActions.list(c.arg(2)), c.arg(3) == .bool(true))) }
            case "selectorHasNot": got = .value(.bool(ActionSelectors.selectorHasNot(a0)))
            case "allowSelectorError": got = .value(Base.opt(ActionSelectors.allowSelectorError(a0, a1 == .bool(true))))
            case "policyDecision": got = RefActions.v { .string(try ActionSelectors.policyDecision(RefActions.obj(a0), a1?.asString ?? "", RefActions.list(c.arg(2)), c.arg(3) == .bool(true))) }
            case "blankReason": got = .value(.bool(ActionConfirmation.blankReason(a0?.asString ?? "")))
            case "reviewMessage": got = RefActions.v { Base.bytesValue(try ActionConfirmation.reviewMessage(RefActions.obj(a0))) }
            case "signReview":
                got = RefActions.v {
                    guard let seed = Base.bytes(a1) else { throw ActionKitError(code: "bad_seed", message: "seed") }
                    return try ActionConfirmation.signReview(RefActions.obj(a0), try Ed25519Deterministic.key(seed: seed))
                }
            case "verbConfirmationError":
                var reg = core
                if let r = a1, r != .null { guard let x = try? Actions.extendRegistry(core, RefActions.list(r)) else { d.skip("registry"); return }; reg = x }
                got = .value(Base.opt(ActionConfirmation.verbConfirmationError(RefActions.obj(a0), reg, c.arg(2))))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1100)
    }
}
