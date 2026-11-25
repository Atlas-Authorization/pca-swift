import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the importer helpers (naming, text hygiene, references, limits) and the four core importers.
final class RefActionsImportCoreTests: XCTestCase {
    func testImportCore() throws {
        try K042.requireCovers(["ImportCommon", "ImportLimits", "ImportersCore", "ImportSupport"])
        let d = Base.Diffs()
        try Base.each("ref-actions-import-core.json.gz") { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "tokensOf": got = .value(RefActions.strs(ImportCommon.tokensOf(a0)))
            case "humanize": got = .value(.string(ImportCommon.humanize(a0)))
            case "verbOf": got = .value(.string(ImportCommon.verbOf(a0?.asString ?? "", a1)))
            case "aliasOf": got = .value(Base.opt(ImportCommon.aliasOf(a0, a1?.asString)))
            case "paramSeg": got = .value(.string(ImportCommon.paramSeg(a0?.asString ?? "")))
            case "clip": got = .value(.string(ImportCommon.clip(a0, Int(IV.int(a1) ?? 0))))
            case "pointer": got = .value(ImportCommon.pointer(a0, a1) ?? .null)
            case "resolveLimits": got = RefActions.v { try ImportLimits.resolve(c.args.isEmpty ? nil : a0).json }
            case "checkParsed": got = RefActions.v { .int(try ImportLimits.resolve(a1).checkParsed(a0)) }
            case "textSizeCheck": got = RefActions.v { try ImportLimits.resolve(a1).textSizeCheck(a0?.asString ?? ""); return .null }
            case "importOpenApi": got = RefActions.v { .object(try OpenApiImporter.importOpenApi(a0, RefActions.obj(a1))) }
            case "importMcp": got = RefActions.v { .object(try McpImporter.importMcp(a0, RefActions.obj(a1))) }
            case "importJsonSchema": got = RefActions.v { .object(try JsonSchemaImporter.importJsonSchema(a0, RefActions.obj(a1))) }
            case "importAsyncApi": got = RefActions.v { .object(try AsyncApiImporter.importAsyncApi(a0, RefActions.obj(a1))) }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(900)
    }
}
