import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the importer pipeline, the eval harness, the review and confirmation flow, and the release signing of the built-ins.
final class RefActionsImportReviewTests: XCTestCase {
    static func seedKey(_ label: String) throws -> PCAEdKey { try Ed25519Deterministic.key(seed: Canonical.sha256(Array(("atlas-pca-conformance/" + label).utf8))) }

    private struct Adapter: ModelAdapter {
        let spec: JObject
        func id() -> String { spec[JKey("id")]?.asString ?? "" }
        func version() -> String? { spec[JKey("version")]?.asString }
        func complete(_ req: JObject) throws -> String? {
            if let t = spec[JKey("throws")]?.asString { throw JSError(t) }
            return spec[JKey("answer")]?.asString
        }
    }

    private static func suggestOpts(_ so: JObject) -> ImportPipeline.SuggestOpts {
        var o = ImportPipeline.SuggestOpts()
        o.mode = so[JKey("mode")]?.asString
        o.registry = Actions.coreRegistry
        if so[JKey("rules")] == .string("default") {
            var r = ImportRules.DEFAULT_RULES
            r[JKey("rules")] = .array(Array(RefActions.list(ImportRules.DEFAULT_RULES[JKey("rules")]).prefix(20)))
            o.rules = r
        }
        if let ms = so[JKey("models")]?.asArray { o.models = ms.map { Adapter(spec: RefActions.obj($0)) } }
        return o
    }

    func testImportReview() throws {
        try K042.requireCovers(["ImportReview", "ImportPipeline", "ImportEval", "ActionBuiltin"])
        let d = Base.Diffs()
        let core = Actions.coreRegistry
        try Base.each("ref-actions-import-review.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            func defs(_ x: JSONValue?) -> [JObject] { RefActions.list(x).map { RefActions.obj($0) } }
            let got: BaseGot
            switch c.fn {
            case "parseHandTsv": got = RefActions.v { .array(try ImportEval.parseHandTsv(a0?.asString ?? "")) }
            case "parseCorpusJsonl": got = RefActions.v { .array(try ImportEval.parseCorpusJsonl(a0?.asString ?? "")) }
            case "realSplit": got = .value(.string(ImportEval.realSplit(c.args.isEmpty ? nil : a0)))
            case "importCorpus": got = RefActions.v { .object(try ImportEval.importCorpus(RefActions.list(a0))) }
            case "evalSuggest":
                got = RefActions.v { .object(try ImportEval.evalSuggest(RefActions.list(a0), c.args.count > 1 && a1 != .string("default") ? RefActions.obj(a1) : nil, core, c.args.count > 2 ? IV.num(c.arg(2)) : nil)) }
            case "renderEvalMarkdown": got = .value(.string(ImportEval.renderEvalMarkdown(RefActions.obj(a0))))
            case "floorFailures": got = .value(RefActions.strs(ImportEval.floorFailures(RefActions.obj(a0), RefActions.obj(a1))))
            case "importActions": got = RefActions.v { .object(try ImportPipeline.importActions(a0?.asString, a1, RefActions.obj(c.arg(2)))) }
            case "IMPORTERS": got = RefActions.v { .object(try ImportPipeline.runImporter(a0?.asString ?? "", a1, RefActions.obj(c.arg(2)))) }
            case "suggestDefs": got = RefActions.v { try ImportPipeline.suggestDefs(defs(a0), c.args.count > 1 ? Self.suggestOpts(RefActions.obj(a1)) : nil).asJSON }
            case "importAndSuggest": got = RefActions.v { .object(try ImportPipeline.importAndSuggest(a0?.asString, a1, RefActions.obj(c.arg(2)), Self.suggestOpts(RefActions.obj(c.arg(3))))) }
            case "defsToJsonl": got = RefActions.v { .string(try ImportPipeline.defsToJsonl(defs(a0))) }
            case "jsonlToDefs": got = RefActions.v { .array(try ImportPipeline.jsonlToDefs(a0?.asString ?? "").map { .object($0) }) }
            case "verifyAttestation": got = .value(.object(ImportReview.verifyAttestation(RefActions.obj(a0), RefActions.obj(a1), core)))
            case "reviewStatus": got = RefActions.v { try ImportReview.reviewStatus(RefActions.obj(a0), RefActions.obj(a1), core) ?? .null }
            case "revertStale": got = RefActions.v { .object(try ImportReview.revertStale(RefActions.obj(a0), RefActions.obj(a1), core)) }
            case "reviewPriority": got = RefActions.v { .int(Int64(try ImportReview.reviewPriority(RefActions.obj(a0), core))) }
            case "reviewQueueOrder": got = RefActions.v { .array(try ImportReview.reviewQueueOrder(defs(a0), core).map { .object($0) }) }
            case "prepareReview": got = RefActions.v { .object(try ImportReview.prepareReview(RefActions.obj(a0), core, c.args.count > 1 ? RefActions.obj(a1) : nil)) }
            case "confirmDef":
                got = RefActions.v {
                    let cf = RefActions.obj(a1)
                    return .object(try ImportReview.confirmDef(RefActions.obj(a0), core, cf[JKey("kid")]?.asString ?? "", try Self.seedKey(cf[JKey("seed")]?.asString ?? ""),
                                                               cf[JKey("pins")] != nil ? RefActions.obj(cf[JKey("pins")]) : nil, RefActions.list(cf[JKey("finalTraits")]),
                                                               cf[JKey("dismissed")] != nil ? RefActions.list(cf[JKey("dismissed")]) : nil, cf[JKey("ts")]))
                }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(300)
    }

    func testSignBuiltins() throws {
        try K042.requireCovers(["ActionBuiltin", "ImportReview"])
        let d = Base.Diffs()
        try Base.each("ref-actions-signbuiltins-py.json.gz") { c in
            let cf = RefActions.obj(c.arg(0))
            let label = cf[JKey("secret")]?.get("$seed")?.asString ?? ""
            let all = ActionBuiltin.builtinDefs()
            let from = Int(IV.int(cf[JKey("from")]) ?? 0), to = Int(IV.int(cf[JKey("to")]) ?? 0)
            let got: BaseGot = RefActions.v {
                let signed = try ActionBuiltin.signBuiltins(nil, cf[JKey("kid")]?.asString ?? "", try Self.seedKey(label), cf[JKey("ts")], Array(all[from..<to]))
                return .array(signed.map { s in .array([s.get("verb") ?? .null, s.get("review")?.get("state") ?? .null, s.get("review")?.get("attestation") ?? .null]) })
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(3)
    }
}

private extension JObject {
    var asJSON: JSONValue { .object(self) }
}
