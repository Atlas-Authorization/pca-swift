import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential test of Approval.swift against the TS reference (pca approval-render.ts, pca-actions approval-render.ts +
/// approval-profiles.ts): test-data/k05-approval.json.gz (4791 cases). A nil from the Swift API is the reference's throw; a
/// non-string digest cannot reach the String API (the reference throws for those).
final class K05ApprovalOracleTests: XCTestCase {
    static let file = "k05-approval.json.gz"
    static let covers = ["Approval", "Actions", "Merkle", "IntentValues", "StrictJSON", "Canonical", "Base64URLStrict", "JSONValue"]

    static func str(_ s: String?) -> K05Got { s.map { .value(.string($0)) } ?? .threw(nil) }
    static func kit(_ e: Error) -> String? { (e as? ActionKitError)?.code }

    /// A JSON integer as the typed port sees it (-0 is 0); nil for anything else.
    static func integer(_ v: JSONValue?) -> Int64? {
        guard let d = IV.num(v), d.isFinite, d.rounded(.towardZero) == d, abs(d) < 9.2e18 else { return nil }
        return Int64(d)
    }

    func testRenderShapeDigestChallengeWords() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["approvalRenderShapeError", "approvalRenderDigest", "approvalChallengeB64u", "bindingWords"]) { c in
            switch c.fn {
            case "approvalRenderShapeError":
                d.add(c, K05.diff(c, .value(K05.opt(Approval.renderShapeError(c.arg(0))))))
            case "approvalRenderDigest":
                d.add(c, K05.diff(c, Self.str(Approval.renderDigest(c.arg(0) ?? .null))))
            case "approvalChallengeB64u":
                guard let a = c.arg(0)?.asString, let r = c.arg(1)?.asString else { d.add(c, K05.diff(c, .threw(nil))); return }
                d.add(c, K05.diff(c, Self.str(Approval.challenge(actionDigest: a, renderDigest: r))))
            default:
                guard let r = c.arg(0)?.asString else { d.add(c, K05.diff(c, .threw(nil))); return }
                d.add(c, K05.diff(c, Self.str(Approval.bindingWords(r))))
            }
        }
        d.finish(2600)   // 2784 cases, 126 carry a lone surrogate (skipped)
    }

    func testRender() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["renderApproval", "validateDef"]) { c in
            if c.fn == "validateDef" { d.add(c, K05.diff(c, .value(K05.opt(Actions.validateDef(c.arg(0) ?? .null))))); return }
            // render takes a validated definition (every def here validates; the reference never renders an invalid one)
            guard let def = c.arg(0)?.asObject, Actions.validateDef(.object(def)) == nil else { d.skip("renderApproval: def does not validate"); return }
            d.add(c, K05.diff(c, K05.run(Self.kit) { try Approval.render(def: def, params: c.arg(1) ?? .null, confirmed: false) }))
        }
        d.finish(960)   // 1085 cases, 94 carry a lone surrogate (skipped)
    }

    func testPsd2MinorUnitsAndBatches() throws {
        try K042.requireCovers(Self.covers)
        let d = K05.Diffs()
        try K05.each(Self.file, ["psd2Linking", "minorToDecimal", "approvalBatch", "spcExpectation", "cibaApprovalDetails"]) { c in
            switch c.fn {
            case "psd2Linking":
                d.add(c, K05.diff(c, K05.run(Self.kit) { try Approval.psd2Linking(c.arg(0) ?? .null) }))
            case "minorToDecimal":
                // the typed (Int64, Int64) port: arguments that are not JSON integers cannot be passed (the reference refuses them all)
                guard let m = Self.integer(c.arg(0)), let e = Self.integer(c.arg(1)) else {
                    d.add(c, c.code == "psd2_unlinkable" ? nil : "\(c.name): a non-integer argument must be refused"); return
                }
                d.add(c, K05.diff(c, K05.run(Self.kit) { .string(try Approval.minorToDecimal(m, e)) }))
            case "approvalBatch":
                guard let items = c.arg(0)?.asArray else { d.skip("approvalBatch: items is not an array"); return }
                // the reference's challenge is the raw bytes ({$bytes}); Swift returns their base64url
                d.add(c, K05.diff(c, K05.run(Self.kit) {
                    var o = try Approval.batch(items).asObject ?? [:]
                    if let ch = o["challenge"]?.asString, let b = Base64URLStrict.decode(ch) { o["challenge"] = K05.bytesValue(b) }
                    return .object(o)
                }))
            default:
                d.skip("\(c.fn): the Swift SDK has no SPC / CIBA profile helpers")
            }
        }
        d.finish(870)
    }
}
