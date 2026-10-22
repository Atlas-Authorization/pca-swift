import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Intent Layer v2 differential test: `IntentV2.decide` against the TS reference decideIntentV2. test-data/
/// k042-intentv2-cases.json.gz is the shared oracle (tools/pca-audit/java-mutate/k042-intentv2-oracle.mts; every other native
/// suite runs the same file): every case pins the EXACT check list (name, ok, reason, in order). A thrown-internal-error
/// reason is compared up to its prefix "<check> error (fail closed): ". The reason TEXT is the reference's, character for
/// character; decisions must agree exactly.
final class IntentV2DiffTests: XCTestCase {
    static let failClosed = "(fail closed): "

    static func cases() throws -> [JSONValue] {
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/k042-intentv2-cases.json.gz").standardized.path
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["gzip", "-dc", path]
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let doc = try StrictJSON.parseLenient(String(decoding: data, as: UTF8.self))
        guard case let .array(a)? = doc.get("cases") else { throw XCTSkip("no cases") }
        return a
    }

    func testEveryDecisionMatchesTheReference() throws {
        let cases = try Self.cases()
        XCTAssertGreaterThan(cases.count, 1000)
        var bad: [String] = []
        let td = K042.TextDiffs()
        caseLoop: for cs in cases {
            let name = cs.get("name")?.asString ?? "?"
            guard case let .object(p)? = try? StrictJSON.parseLenient(cs.get("p")?.asString ?? ""),
                  let grant = try? StrictJSON.parseLenient(cs.get("grant")?.asString ?? "") else { bad.append("\(name): unparsable"); continue }
            var ctx: IntentV2Context? = nil
            if let t = cs.get("ctx")?.asString, let v = try? StrictJSON.parseLenient(t) {
                var cv = v
                if let wp = cs.get("wp")?.asString, let w = try? StrictJSON.parseLenient(wp), case var .object(o) = cv {
                    o[JKey("params")] = w
                    cv = .object(o)
                }
                ctx = IntentV2Context.fromJSON(cv)
            }
            let now: Int64
            switch cs.get("now") { case let .int(i)?: now = i; case let .double(d)?: now = Int64(d); default: now = 0 }
            let d = IntentV2.decide(p, grant: grant, ctx: ctx, now: now)
            guard case let .array(want)? = cs.get("checks") else { continue }
            var got: [String] = [], gotD: [String] = []
            for (i, c) in d.checks.enumerated() {
                var r = c.reason
                if r.contains("unsupported_suite") { continue caseLoop } // a PQ suite this host lacks: by design
                if i < want.count, case .bool(true)? = want[i].get("prefix"), let k = r.range(of: Self.failClosed) { r = String(r[..<k.upperBound]) }
                got.append("\(c.name)|\(c.ok)|\(r.isEmpty ? "null" : r)")
                gotD.append("\(c.name)|\(c.ok)")
            }
            let w = want.map { x -> String in
                let ok: Bool = { if case .bool(true)? = x.get("ok") { return true }; return false }()
                return "\(x.get("name")?.asString ?? "")|\(ok)|\(x.get("reason")?.asString ?? "null")"
            }
            let wD = w.map { $0.split(separator: "|", maxSplits: 2).prefix(2).joined(separator: "|") }
            if wD != gotD { bad.append("\(name):\n  want \(w)\n  got  \(got)") } else {
                for (a, b) in zip(w, got) where a != b { td.add(a, b, name) }
            }
        }
        td.finish("IntentV2Diff")
        XCTAssert(bad.isEmpty, "\(bad.count) cases differ:\n" + bad.prefix(12).joined(separator: "\n"))
    }
}
