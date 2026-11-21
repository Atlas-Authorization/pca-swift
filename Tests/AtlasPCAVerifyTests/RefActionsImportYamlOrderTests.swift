import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The YAML an import writes lists the members of a def in the order the importer SET them (a JavaScript object's insertion order), not in
/// code-unit order. The reference output of every importer case carries that order as parsed text, so the YAML of the defs the Swift importers
/// BUILD must equal the YAML of the reference's defs, byte for byte.
final class RefActionsImportYamlOrderTests: XCTestCase {
    private static func defs(_ r: JObject) -> [JObject]? {
        guard case let .array(a)? = r[JKey("defs")] else { return nil }
        return a.compactMap { $0.asObject }
    }

    private func check(_ file: String, _ run: @escaping (String, JSONValue?, JSONValue?) throws -> JObject?) throws {
        var bad: [String] = []
        var compared = 0
        _ = try Base.each(file) { c in
            guard let want = c.out.asObject, let wd = Self.defs(want), !wd.isEmpty else { return }
            guard let got = try? run(c.fn, c.arg(0), c.arg(1)), let gd = Self.defs(got) else { return }
            compared += 1
            let w = try? ImportRegistry.defsToYaml("ns", wd), g = try? ImportRegistry.defsToYaml("ns", gd)
            if w == nil || w != g {
                // the first line where the two texts part (a log shows what differs, not only which case)
                let wl = (w ?? "<refused>").components(separatedBy: "\n"), gl = (g ?? "<refused>").components(separatedBy: "\n")
                let at = (0..<min(wl.count, gl.count)).first { wl[$0] != gl[$0] } ?? min(wl.count, gl.count)
                bad.append("\(c.name): line \(at + 1) want \(at < wl.count ? wl[at] : "<end>") got \(at < gl.count ? gl[at] : "<end>")")
            }
        }
        XCTAssertGreaterThan(compared, 50)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) case(s) emit another member order:\n" + bad.prefix(30).joined(separator: "\n"))
    }

    func testCoreImportersEmitInsertionOrder() throws {
        try K042.requireCovers(["ImportCommon", "YamlEmit", "ImportRegistry"])
        try check("ref-actions-import-core.json.gz") { fn, a0, a1 in
            switch fn {
            case "importOpenApi": return try OpenApiImporter.importOpenApi(a0, RefActions.obj(a1))
            case "importMcp": return try McpImporter.importMcp(a0, RefActions.obj(a1))
            case "importJsonSchema": return try JsonSchemaImporter.importJsonSchema(a0, RefActions.obj(a1))
            case "importAsyncApi": return try AsyncApiImporter.importAsyncApi(a0, RefActions.obj(a1))
            default: return nil
            }
        }
    }

    func testSdlImportersEmitInsertionOrder() throws {
        try K042.requireCovers(["ImportCommon", "YamlEmit", "ImportRegistry"])
        try check("ref-actions-import-sdl.json.gz") { fn, a0, a1 in
            switch fn {
            case "importGraphql": return try GraphqlImporter.importGraphql(a0, RefActions.obj(a1))
            default: return nil
            }
        }
    }

    func testBuiltObjectKeepsConstructionOrder() throws {
        var o: JObject = [:]
        o[o: "zeta"] = .int(1); o[o: "alpha"] = .int(2); o[o: "mid"] = .int(3); o[o: "alpha"] = .int(4)
        XCTAssertEqual(JS.keyOrder(o).map { $0.s }, ["zeta", "alpha", "mid"])
        XCTAssertEqual(try YamlEmit.stringify(.object(o)), "zeta: 1\nalpha: 4\nmid: 3\n")
        o[o: "alpha"] = nil
        XCTAssertEqual(JS.keyOrder(o).map { $0.s }, ["zeta", "mid"])
    }
}
