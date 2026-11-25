import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The action-schema shape checks (v1 and v2 documents, limits, paths, hostile inputs), the confirmation and floors declarations, the parameter value check over
/// every type and format, and the format predicates against the 16139-case shared base corpus: every case, every fn, with the fn set and the total asserted.
final class RefBaseActionSchemaTests: XCTestCase {
    typealias A = RefAnalyzer

    private static func opt(_ s: String?) -> JSONValue { s.map { .string($0) } ?? .null }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1)
        switch c.fn {
        case "shape": return .value(opt(ActionSchema.shapeError(a0 ?? .null)))
        case "shapeUnsigned": return .value(opt(ActionSchema.shapeError(a0 ?? .null, signed: false)))
        case "confirmation": return .value(opt(ActionSchema.confirmationShapeError(a0)))
        case "floors": return .value(opt(ActionSchema.floorsError(a0)))
        case "pvv":
            guard let d = a0?.asObject else { return .threw(nil) }
            guard let v = ActionSchema.valueViolation(d, a1 ?? .null) else { return .value(.null) }
            return .value(.object(["code": .string(v.0), "reason": .string(v.1)]))
        case "format":
            guard let f = a0?.asString else { return .threw(nil) }
            guard let check = ActionSchema.formatCheck(f) else { return .value(.string("unknown")) }
            return .value(.bool(check(a1?.asString ?? "")))
        default: return nil
        }
    }

    func testEveryCaseOfTheBaseCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("base-actionschema.json.gz") { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 16139)
        XCTAssertEqual(seen, ["shape": 10502, "pvv": 3027, "format": 1788, "confirmation": 425, "floors": 391, "shapeUnsigned": 6])
        d.finish(16139 - d.skipped.values.reduce(0, +))
    }
}
