import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The connector action catalog over JSON specs against the reference corpus: every case, every fn. A catalog is driven through its op script
/// (one result per op; an op that throws records `{"$err": true}`).
final class RefCatalogTests: XCTestCase {
    typealias A = RefAnalyzer
    private static let err: JSONValue = .object(["$err": .bool(true)])

    private static func op(_ cat: Catalog.ActionCatalog, _ op: [JSONValue]) throws -> JSONValue {
        func text(_ i: Int) -> String? { i < op.count ? op[i].asString : nil }
        switch text(0) {
        case "get": return text(1).flatMap { cat.get($0) } ?? .null
        case "forConnector": return .array(text(1).map { cat.forConnector($0) } ?? [])
        case "all": return .array(cat.all())
        case "resolve":
            guard let c = text(1), let a = text(2) else { return .null }
            return cat.resolve(connector: c, action: a) ?? .null
        case "resolveAction":
            guard let verb = text(1) else { throw PCAProducerError("verb") }
            let r = Catalog.resolveAction(cat, verb)
            return .object(["spec": r.spec, "catalogued": .bool(r.catalogued)])
        case "digest": return .string(try Catalog.catalogDigest(cat))
        case "assertPinned":
            guard let want = text(1) else { throw PCAProducerError("expected digest") }
            try Catalog.assertCatalogPinned(cat, want == "$self" ? try Catalog.catalogDigest(cat) : want)
            return .bool(true)
        case "extend":
            guard op.count > 1, case let .array(extra) = op[1] else { throw PCAProducerError("extra") }
            let e = try Catalog.extendCatalog(cat, extra)
            return .object(["all": .array(e.all()), "digest": .string(try Catalog.catalogDigest(e))])
        default: throw PCAProducerError("bad op")
        }
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1)
        switch c.fn {
        case "defineAction": return A.run { try Catalog.defineAction(a0 ?? .null) }
        case "uncataloguedSpec":
            guard let verb = a0?.asString else { return .threw(nil) }
            return .value(Catalog.uncataloguedSpec(verb))
        case "builtin":
            return A.run {
                var blast: JObject = [:]
                for (k, v) in Catalog.BLAST { blast[JKey(k)] = PD.num(v) }
                return .object(["actions": .array(Catalog.BUILTIN_ACTIONS), "digest": .string(try Catalog.catalogDigest(Catalog.DEFAULT_CATALOG)), "blast": .object(blast)])
            }
        case "catalog":
            let cat = a0?.asArray.map { Catalog.buildCatalog($0) } ?? Catalog.DEFAULT_CATALOG
            return .value(.array((a1?.asArray ?? []).map { o in (try? op(cat, o.asArray ?? [])) ?? err }))
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-catalog.json.gz") { c in
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 75)
        d.finish(75)
    }

    func testAnExtensionMayOnlyTighten() throws {
        let base = Catalog.DEFAULT_CATALOG
        XCTAssertEqual(base.all().count, 21)
        XCTAssertEqual(try Catalog.catalogDigest(base), "7pXXVTal7F5wMK-5cQUaN4e4zz0m3SF5wrv19iK6BBQ")
        let weaker = try Catalog.defineAction(K042.parse(#"{"connector":"gmail","action":"send","reversibility":"reversible","blastRadius":0.01,"description":"x"}"#))
        XCTAssertThrowsError(try Catalog.extendCatalog(base, [weaker]))
        let added = try Catalog.defineAction(K042.parse(#"{"connector":"acme","action":"ship","reversibility":"rate_limited","blastRadius":0.5,"description":"ships"}"#))
        let ext = try Catalog.extendCatalog(base, [added])
        XCTAssertEqual(ext.get("acme.ship")?.get("verb"), .string("acme.ship"))
        XCTAssertThrowsError(try Catalog.assertCatalogPinned(ext, try Catalog.catalogDigest(base)))
        XCTAssertFalse(Catalog.resolveAction(base, "acme.ship").catalogued)
    }
}
