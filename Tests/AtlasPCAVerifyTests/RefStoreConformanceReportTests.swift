import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the report side of pca-store-conformance (the recorder's history parser, the workload PRNG, folding and formatting a report, the report
/// JSON) against the TypeScript reference, and the exact `Number.prototype.toFixed(3)` the counterexample times use. A reference throw requires a native refusal.
final class RefStoreConformanceReportTests: XCTestCase {
    static let file = "ref-store-conformance.json.gz"

    func testReportSideAgainstTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each(Self.file, ["parseHistory", "prng", "overall", "formatReport", "reportJson"]) { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "parseHistory": return PCAStoreConformance.json(PCAStoreConformance.parseHistory(c.arg(0)?.asString ?? ""))
                case "prng":
                    guard let seed = IV.num(c.arg(0)) else { throw JSError("seed") }
                    let r = PCAStoreConformance.Prng(seed: seed)
                    return .array((c.arg(1)?.asArray ?? []).map { PCAStoreConformance.numValue(r.rand(IV.num($0) ?? Double.nan)) })
                case "overall":
                    guard let x = c.arg(0) else { throw JSError("tests") }
                    if let statuses = x.asArray { return .string(PCAStoreConformance.overall(statuses.map { .object(["status": $0]) })) }
                    return .string(PCAStoreConformance.overall(x.get("tests")?.asArray ?? []))
                case "formatReport": return .string(try PCAStoreConformance.formatReport(c.arg(0) ?? .null, maxKeys: Int(IV.num(c.arg(1)) ?? 3)))
                case "reportJson": return .string(PCAStoreConformance.reportJson(c.arg(0) ?? .null))
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertGreaterThan(n, 40)
        d.finish(40)
    }

    /// `toFixed(3)` rounds the EXACT binary value, a tie to the larger n, and keeps the sign of a magnitude that rounds to zero.
    func testToFixed3IsExact() {
        let cases: [(Double, String)] = [
            (1.0625, "1.063"), (0.0625, "0.063"), (0.1875, "0.188"), (2.5, "2.500"), (0, "0.000"), (-0.0, "0.000"), (0.0005, "0.001"), (1.0005, "1.000"),
            (1.0015, "1.002"), (0.0004999, "0.000"), (-0.0001, "-0.000"), (-1.0625, "-1.063"), (123.456, "123.456"), (5e-324, "0.000"), (1e20, "100000000000000000000.000"),
            (1e21, "1e+21"), (4503599627370496, "4503599627370496.000"), (9007199254740991, "9007199254740991.000"), (0.9995, "1.000"), (0.99951, "1.000"),
            (Double.infinity, "Infinity"), (-Double.infinity, "-Infinity"), (Double.nan, "NaN"),
        ]
        for (x, want) in cases { XCTAssertEqual(PCAStoreConformance.toFixed3(x), want, "\(x)") }
    }
}
