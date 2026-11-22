import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Shared helpers of the K042 differential oracle tests: the golden files under test-data/ are produced by the TypeScript
/// reference (tools/pca-audit/java-mutate/k042-*-oracle.m(j|t)s, tools/pca-audit/kotlin-mutate/kill*-oracle-gen.mjs) and shared
/// by every native verifier suite.
enum K042 {
    static func dataURL(_ rel: String) -> URL {
        if rel.hasPrefix("/") { return URL(fileURLWithPath: rel) }  // an absolute path (corpora CI generates outside the tree)
        return URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../test-data/" + rel).standardized
    }

    /// ref-<name>-gen.json.gz: the oracle cases that carry private keys, which CI generates with gen-secret-corpus.sh and never commits
    /// (next to the main corpus unless PCA_SECRET_CORPUS_DIR is set). nil when missing: a test failure under CI ("true"/"1"), else skipped.
    static func secretCorpusPath(_ file: String, in f: StaticString = #filePath, line l: UInt = #line) -> String? {
        let env = ProcessInfo.processInfo.environment
        let dir = env["PCA_SECRET_CORPUS_DIR"] ?? dataURL(file).deletingLastPathComponent().path
        let path = dir + "/" + URL(fileURLWithPath: file).lastPathComponent.replacingOccurrences(of: ".json.gz", with: "-gen.json.gz")
        if FileManager.default.fileExists(atPath: path) { return path }
        if env["CI"] == "true" || env["CI"] == "1" { XCTFail("secret corpus missing (\(path)): CI must generate it with gen-secret-corpus.sh", file: f, line: l) }
        else { print("skipping: secret corpus missing (\(path)); run gen-secret-corpus.sh") }
        return nil
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

    /// Replace each LONE surrogate `\uXXXX` escape (at the vectors.json level) with the sentinel scalar, so
    /// `JSONSerialization` can load the file; object-form vectors carrying the sentinel are treated as a
    /// `wire` failure. Valid surrogate PAIRS (astral chars) and escaped backslashes are left untouched.
    static func sanitizeLoneSurrogates(_ text: String) -> String {
        // Linear byte scan (UTF-8 multi-byte sequences never contain ASCII bytes, so the JSON syntax bytes are unambiguous).
        // The previous scalar-by-scalar `String.UnicodeScalarView` rebuild was effectively quadratic in debug builds: a 15 MB
        // corpus took minutes instead of seconds.
        let bs = Array(text.utf8)
        let sentinel = Array(String(Canonical.LONE_SURROGATE_SENTINEL).utf8)
        func hex(_ at: Int) -> UInt32? {
            guard at + 4 <= bs.count else { return nil }
            var v: UInt32 = 0
            for k in 0..<4 {
                let c = UInt32(bs[at + k])
                let d: UInt32
                switch c {
                case 48...57: d = c - 48
                case 97...102: d = c - 87
                case 65...70: d = c - 55
                default: return nil
                }
                v = (v << 4) | d
            }
            return v
        }
        var out = [UInt8](); out.reserveCapacity(bs.count)
        var i = 0
        var inStr = false
        while i < bs.count {
            let c = bs[i]
            if !inStr {
                inStr = (c == 0x22)
                out.append(c); i += 1
            } else if c == 0x22 {
                inStr = false; out.append(c); i += 1
            } else if c == 0x5c {
                if i + 1 < bs.count, bs[i + 1] == 0x75, let hi = hex(i + 2) {
                    if (0xD800...0xDBFF).contains(hi) {
                        let paired = i + 11 < bs.count && bs[i + 6] == 0x5c && bs[i + 7] == 0x75
                            && (hex(i + 8).map { (0xDC00...0xDFFF).contains($0) } ?? false)
                        if paired { out.append(contentsOf: bs[i..<(i + 12)]); i += 12 }
                        else { out.append(contentsOf: sentinel); i += 6 }
                    } else if (0xDC00...0xDFFF).contains(hi) {
                        out.append(contentsOf: sentinel); i += 6
                    } else {
                        out.append(contentsOf: bs[i..<min(i + 2, bs.count)]); i += 2
                    }
                } else {
                    out.append(contentsOf: bs[i..<min(i + 2, bs.count)]); i += 2
                }
            } else {
                out.append(c); i += 1
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// A golden JSON document (lenient parse, lone surrogates substituted with the sentinel scalar, integer lexemes outside the
    /// safe range normalised to binary64 like JSON.parse).
    static func json(_ rel: String) throws -> JSONValue {
        let text = String(decoding: try bytes(rel), as: UTF8.self)
        return IV.normalized(try StrictJSON.parseLenient(sanitizeLoneSurrogates(text)))
    }

    /// A JSON text embedded in a golden case (an oracle input carried as text so both sides parse identical lexemes).
    static func parse(_ text: String) -> JSONValue {
        guard let v = try? StrictJSON.parseLenient(sanitizeLoneSurrogates(text)) else { return .null }
        return IV.normalized(v)
    }

    static func parseOrNil(_ text: String) -> JSONValue? {
        guard let v = try? StrictJSON.parseLenient(sanitizeLoneSurrogates(text)) else { return nil }
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
