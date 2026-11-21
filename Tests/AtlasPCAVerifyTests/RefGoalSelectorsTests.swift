import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the goal selector layer (catalog, class verbs, role resolution, expansion, typing, card, carrier form, catalog
/// tape) against the TypeScript reference (@atlasauth/pca-goal selectors.ts). A reference throw requires a native refusal.
///
/// A parsed object has no member order: the roles of a catalog verb are read in code-unit order by `encodeSelCatalog` (the corpus has no
/// verb with more than one role, so the order cannot differ here).
final class RefGoalSelectorsTests: XCTestCase {
    static let file = "ref-goal-selectors.json.gz"
    typealias S = PCAGoalSelectors

    static func must(_ v: JSONValue?) throws -> JSONValue {
        guard let x = v, x.isObject else { throw JSError("object expected") }
        return x
    }

    static func list(_ v: JSONValue?) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("array expected") }
        return a
    }

    static func text(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("string expected") }
        return s
    }

    /// A shipped domain stands for its IR ontology.
    static func ont(_ v: JSONValue?) throws -> JSONValue {
        if let name = v?.asString {
            guard let o = try PCAGoalOntologies.ontology(name) else { throw JSError("unknown domain") }
            return try PCAGoalOntology.toIrOntology(o, nil, nil)
        }
        return try must(v)
    }

    /// A shipped domain stands for its selector catalog.
    static func cat(_ v: JSONValue?) throws -> JSONValue {
        if let name = v?.asString {
            guard let c = try PCAGoalOntologies.selCatalog(name) else { throw JSError("unknown domain") }
            return c
        }
        return try must(v)
    }

    static func code(_ e: Error) -> String? {
        if let a = e as? ActionKitError { return a.code }
        if let j = e as? JSError { return j.code }
        return nil
    }

    func replay(_ fn: String, expected: Int, _ body: @escaping ([JSONValue]) throws -> JSONValue) throws {
        let d = Base.Diffs()
        let n = try Base.each(Self.file, [fn]) { c in
            d.add(c, Base.diff(c, Base.run(Self.code) { try body(c.args) }))
        }
        XCTAssertEqual(n, expected, "\(fn): cases in the corpus")
        d.finish(max(1, n - d.skipped.values.reduce(0, +)))
        print("goal selectors \(fn): \(n) cases, skipped \(d.skipped.values.reduce(0, +))")
    }

    func testSelCatalogDigest() throws {
        try replay("selCatalogDigest", expected: 9) { a in .string(try S.selCatalogDigest(try Self.cat(a[0]))) }
    }

    func testSelGoalDigest() throws {
        try replay("selGoalDigest", expected: 42) { a in .string(try S.selGoalDigest(try Self.must(a[0]))) }
    }

    func testEncodeSelCatalog() throws {
        try replay("encodeSelCatalog", expected: 9) { a in .array(try S.encodeSelCatalog(try Self.cat(a[0]))) }
    }

    func testCatalogOfDomain() throws {
        try replay("catalogOfDomain", expected: 5) { a in try S.selCatalogOfDomain(try Self.text(a[0])) ?? .null }
    }

    func testClassVerbs() throws {
        try replay("classVerbs", expected: 14) { a in .array(try S.classVerbs(try Self.cat(a[0]), try Self.list(a[1]), try Self.list(a[2]))) }
    }

    func testAllowClassVerbs() throws {
        try replay("allowClassVerbs", expected: 14) { a in .array(try S.allowClassVerbs(try Self.cat(a[0]), try Self.list(a[1]), try Self.list(a[2]))) }
    }

    func testFloatClassVerbs() throws {
        try replay("floatClassVerbs", expected: 14) { a in .array(try S.floatClassVerbs(try Self.cat(a[0]), try Self.list(a[1]), try Self.list(a[2]))) }
    }

    func testResolveRole() throws {
        try replay("resolveRole", expected: 32) { a in
            try S.resolveRole(try Self.ont(a[0]), try Self.cat(a[1]), try Self.text(a[2]), try Self.text(a[3])) ?? .null
        }
    }

    func testSelReasons() throws {
        try replay("selReasons", expected: 47) { a in .array(try S.selReasons(try Self.must(a[0]), try Self.ont(a[1]), try Self.cat(a[2]))) }
    }

    func testExpandSelGoal() throws {
        try replay("expandSelGoal", expected: 47) { a in try S.expandSelGoal(try Self.must(a[0]), try Self.ont(a[1]), try Self.cat(a[2])) }
    }

    func testSelCarrier() throws {
        try replay("selCarrier", expected: 42) { a in try S.selCarrier(try Self.must(a[0])) }
    }

    func testRenderSelCard() throws {
        try replay("renderSelCard", expected: 47) { a in try S.renderSelCard(try Self.must(a[0]), try Self.ont(a[1]), try Self.cat(a[2]), nil) }
    }

    func testWithRoleParams() throws {
        try replay("withRoleParams", expected: 9) { a in try S.withRoleParams(try Self.must(a[0]), try Self.cat(a[1])) }
    }

    func testTraitClosure() throws {
        try replay("traitClosure", expected: 6) { a in .array(try S.traitClosure(try Self.list(a[0]), nil).map { JSONValue.string($0) }) }
    }

    // only inputs the selector layer refuses: the proved compiler is not carried natively, so it must never be reached
    func testCompileSelGoal() throws {
        try replay("compileSelGoal", expected: 23) { a in
            try S.compileSelGoal(try Self.must(a[0]), try Self.ont(a[1]), try Self.cat(a[2])) { _, _ in throw JSError("compiler reached") }
        }
    }

    func testCatalogOfDefs() throws {
        try replay("catalogOfDefs", expected: 3) { a in try S.selCatalogOfDefs(try Self.list(a[0]), nil, nil) }
    }
}
