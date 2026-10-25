import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Shared helpers of the K042 differential oracle tests: the golden files under test-data/ are produced by the TypeScript
/// reference (tools/pca-audit/java-mutate/k042-*-oracle.m(j|t)s, tools/pca-audit/kotlin-mutate/kill*-oracle-gen.mjs) and shared
/// by every native verifier suite.
enum K042 {
    static func dataURL(_ rel: String) -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/" + rel).standardized
    }

    /// The raw bytes of a golden file; `.gz` files are decompressed with the system gzip.
    static func bytes(_ rel: String) throws -> Data {
        let path = dataURL(rel).path
        if !rel.hasSuffix(".gz") { return try Data(contentsOf: URL(fileURLWithPath: path)) }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = ["gzip", "-dc", path]
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return data
    }

    /// A golden JSON document (lenient parse, lone surrogates substituted with the sentinel scalar, integer lexemes outside the
    /// safe range normalised to binary64 like JSON.parse).
    static func json(_ rel: String) throws -> JSONValue {
        let text = String(decoding: try bytes(rel), as: UTF8.self)
        return IV.normalized(try StrictJSON.parseLenient(ConformanceTests.sanitizeLoneSurrogates(text)))
    }

    /// A JSON text embedded in a golden case (an oracle input carried as text so both sides parse identical lexemes).
    static func parse(_ text: String) -> JSONValue {
        guard let v = try? StrictJSON.parseLenient(ConformanceTests.sanitizeLoneSurrogates(text)) else { return .null }
        return IV.normalized(v)
    }

    static func parseOrNil(_ text: String) -> JSONValue? {
        guard let v = try? StrictJSON.parseLenient(ConformanceTests.sanitizeLoneSurrogates(text)) else { return nil }
        return IV.normalized(v)
    }

    static func canon(_ v: JSONValue?) -> String {
        guard let v = v else { return "undefined" }
        return Canonical.canonicalize(v)
    }

    static func arr(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }
    static func obj(_ v: JSONValue?) -> JObject { v?.asObject ?? [:] }
    static func str(_ v: JSONValue?) -> String { v?.asString ?? "" }
    static func bool(_ v: JSONValue?) -> Bool { if case .bool(true)? = v { return true }; return false }
    static func num(_ v: JSONValue?) -> Double { IV.num(v) ?? .nan }
    static func isNull(_ v: JSONValue?) -> Bool { if case .null? = v { return true }; return v == nil }

    /// Fails with the first `limit` lines of `bad` (and the count) when it is not empty.
    static func report(_ bad: [String], _ of: Int, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssert(bad.isEmpty, "\(bad.count)/\(of) divergent:\n" + bad.prefix(30).joined(separator: "\n"), file: file, line: line)
    }

    /// The heavy oracles (hundreds of thousands of regex matches, 120k conditions) run on every ordinary `swift test`, but under
    /// mutation (tools/pca-audit/swift-mutate/mutate.mjs exports SWIFTMUT_FILE = the mutated source) only when they cover that
    /// file: a mutant is judged by a bounded oracle run, and a file the corpus never reaches cannot be killed by it.
    static func requireCovers(_ files: [String]) throws {
        guard let f = ProcessInfo.processInfo.environment["SWIFTMUT_FILE"], !f.isEmpty else { return }
        if !files.contains(where: { f.contains($0) }) { throw XCTSkip("this oracle does not cover \(f)") }
    }

    static func units(_ s: String) -> [UInt16] { Array(s.utf16) }

    static func hexUnits(_ h: String) -> [UInt16] {
        if h == "-" { return [] }
        let b = Array(h.utf8)
        var out: [UInt16] = []
        out.reserveCapacity(b.count / 4)
        var i = 0
        while i + 4 <= b.count {
            var v: UInt16 = 0
            for k in 0..<4 {
                let c = b[i + k]
                let d: UInt16 = c <= 57 ? UInt16(c) - 48 : UInt16(c) - 87
                v = (v << 4) | d
            }
            out.append(v)
            i += 4
        }
        return out
    }

    /// The places where a refusal reason TEXT differs from the TS reference. The reference wording is the contract: any
    /// difference fails the test. `PCA_TEXTDIFF_DUMP=<file>` appends the distinct pairs to the file instead of failing (a
    /// porting aid). A thrown internal error ("<check> error (fail closed): ") is compared up to that prefix.
    final class TextDiffs {
        private(set) var n = 0
        private var seen = Set<String>()
        private var list: [String] = []

        /// Records `want` vs `got` when they differ (both refusal reasons).
        func add(_ want: String?, _ got: String?, _ label: String = "") {
            if let w = want, let g = got, w.hasSuffix("(fail closed): "), g.hasPrefix(w) { return }
            if want == got { return }
            n += 1
            let k = "\(label)\n  want \(String(reflecting: want ?? "nil"))\n  got  \(String(reflecting: got ?? "nil"))"
            if seen.insert(k).inserted { list.append(k) }
        }

        func finish(_ name: String, file: StaticString = #filePath, line: UInt = #line) {
            if n == 0 { return }
            if let path = ProcessInfo.processInfo.environment["PCA_TEXTDIFF_DUMP"], !path.isEmpty {
                let text = "### \(name) \(n) diffs, \(list.count) distinct" + list.sorted().joined() + "\n"
                if !FileManager.default.fileExists(atPath: path) { FileManager.default.createFile(atPath: path, contents: nil) }
                if let h = FileHandle(forWritingAtPath: path) {
                    h.seekToEndOfFile()
                    h.write(Data(text.utf8))
                    h.closeFile()
                }
                return
            }
            XCTFail("\(n) reason texts differ from the reference (\(list.count) distinct)" + list.sorted().prefix(40).joined(), file: file, line: line)
        }
    }
}
