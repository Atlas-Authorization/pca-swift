import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the published wire schemas and the structural validator (PCASchema) against the reference
/// (@atlasauth/pca-schema), from the corrected corpus (validate takes (schemaOrName, value)). Every case is parsed with member order
/// kept, because the order of the reported errors follows the order of the schema's properties and of the value's members.
final class RefSchemaTests: XCTestCase {
    func testSchemaAgainstTheReference() throws {
        try K042.requireCovers(["Schema"])
        let text = String(decoding: try K042.bytes("ref-schema-dotnet.json.gz"), as: UTF8.self)
        var run = 0
        var lone = 0
        var bad: [String] = []
        for part in text.split(separator: "\n", omittingEmptySubsequences: true) {
            var line = String(part)
            guard line.hasPrefix(#"{"fn":"#) else { continue }
            if line.hasSuffix(",") { line.removeLast() }
            // a case whose text carries a lone UTF-16 unit cannot be read into a Swift String (the parser refuses it); it is counted, never silently dropped
            let parsed: PCASchema.Node
            do { parsed = try PCASchema.parse(line) } catch {
                if line.lowercased().contains("\\ud8") || line.lowercased().contains("\\udc") { lone += 1; continue }
                throw error
            }
            let c = parsed
            guard case let .str(fn)? = c.member("fn"), case let .str(name)? = c.member("name"), let out = c.member("out") else { bad.append("malformed case"); continue }
            run += 1
            if fn == "schemas" {
                if PCASchema.stringify(out) != PCASchema.stringify(PCASchema.all) { bad.append("\(name): the published schemas differ") }
                continue
            }
            guard fn == "validate", case let .arr(args)? = c.member("args"), args.count == 2 else { bad.append("\(name): bad case"); continue }
            let result: PCASchema.Result?
            if case let .str(n) = args[0] { result = try? PCASchema.validate(named: n, args[1]) } else { result = try? PCASchema.validate(args[0], args[1]) }
            if out.member("$throws") != nil {
                if result != nil { bad.append("\(name): want a refusal") }
                continue
            }
            guard let r = result else { bad.append("\(name): unexpected refusal"); continue }
            var want: [String] = []
            if case let .arr(es)? = out.member("errors") { for e in es { if case let .str(s) = e { want.append(s) } } }
            if out.member("valid") != .bool(r.valid) || want != r.errors { bad.append("\(name): want \(want) got \(r.errors)") }
        }
        print("schema: \(run) cases compared, \(lone) with a lone surrogate not comparable")
        K042.report(bad, run)
        XCTAssertGreaterThanOrEqual(run, 3000)
    }
}
