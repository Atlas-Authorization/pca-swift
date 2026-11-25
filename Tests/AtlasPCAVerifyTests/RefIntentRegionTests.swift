import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the typed region functions against the reference (@atlasauth/pca-intent region.ts), plus hand-derived
/// checks of the refusals the corpus does not pin. A reference throw requires a native refusal.
final class RefIntentRegionTests: XCTestCase {
    private static func idx(_ v: JSONValue?) throws -> [Int] {
        var out: [Int] = []
        for x in try PCAIntentOmega.arr(v) { out.append(PCAIntentOmega.toInt(try PCAIntentOmega.dbl(x))) }
        return out
    }

    func testRegionFunctionsAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["regionOfCell", "regionCells", "dimCellsIn", "restrictRegion", "valueInRegionDim"]
        try Base.each("ref-intent-omega.json.gz", fns) { c in
            let got = Base.run { () throws -> JSONValue in
                switch c.fn {
                case "regionOfCell":
                    return try PCAIntentRegion.regionOfCell(try PCAIntentOmega.verbSpaceFromJson(c.arg(0)), try Self.idx(c.arg(1))).toJson()
                case "regionCells":
                    let cells = try PCAIntentRegion.regionCells(try PCAIntentOmega.verbSpaceFromJson(c.arg(0)), try PCAIntentRegion.Region.fromJson(c.arg(1)), c.arg(2)?.asString == "inner")
                    return .array(cells.map { JSONValue.int($0) })
                case "dimCellsIn":
                    var rd: PCAIntentRegion.RegionDim? = nil
                    if let a1 = c.arg(1), !a1.isNull { rd = try PCAIntentRegion.RegionDim.fromJson(a1) }
                    let cells = try PCAIntentRegion.dimCellsIn(try PCAIntentOmega.dimFromJson(c.arg(0)), rd, c.arg(2)?.asString == "inner")
                    return .array(cells.map { JSONValue.int(Int64($0)) })
                case "restrictRegion":
                    let base = PCAIntentRegion.Region("v", [:])
                    return try PCAIntentRegion.restrictRegion(base, try PCAIntentOmega.dimFromJson(c.arg(0)), c.arg(1)).toJson()
                default:
                    guard let path = c.arg(0)?.asString else { throw JSError("bad path") }
                    return .bool(PCAIntentRegion.valueInRegionDim(path, try PCAIntentRegion.RegionDim.fromJson(c.arg(1)), c.arg(2)))
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1000)
    }

    func testRegionRefusals() throws {
        let vs = PCAIntentOmega.VerbSpace("v", "reversible", 1.0, [PCAIntentOmega.NumDim("a", 0, 10, [5], "uniform")])
        // a restriction on a dimension the space lacks is refused (dropping it would widen a narrow yes)
        let extra = PCAIntentRegion.Region("v", [JKey("zzz"): PCAIntentRegion.RegionDim.num(0, 1)])
        XCTAssertThrowsError(try PCAIntentRegion.regionCells(vs, extra, true))
        XCTAssertThrowsError(try PCAIntentRegion.regionCells(vs, PCAIntentRegion.Region("w", [:]), true))
        // a numeric part against a categorical dimension is refused
        let cat = PCAIntentOmega.CatDim("c", [PCAIntentOmega.CatValue("other", "\u{22A5}")])
        XCTAssertThrowsError(try PCAIntentRegion.restrictRegion(PCAIntentRegion.Region("v", [:]), cat, .object([JKey("lo"): .int(0), JKey("hi"): .int(1)])))
        XCTAssertThrowsError(try PCAIntentRegion.regionOfCell(vs, [99]))
        // an unrestricted region covers every cell
        let all = try PCAIntentRegion.regionCells(vs, PCAIntentRegion.Region("v", [:]), true)
        XCTAssertEqual(all.count, PCAIntentOmega.cellCount(vs.dims[0]))
    }
}
