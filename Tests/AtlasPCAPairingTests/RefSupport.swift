import XCTest
import Foundation
@testable import AtlasPCAVerify

/// One case of a reference oracle corpus (test-data/ref-<pkg>.json.gz): `fn`, `name`, positional `args` and `out`
/// (exactly what the reference returned; a throw is {"$throws": ...}).
struct RefCase {
    let fn: String
    let name: String
    let args: [JSONValue]
    let out: JSONValue
    func arg(_ i: Int) -> JSONValue? { i < args.count ? args[i] : nil }
    var threw: Bool { out.get("$throws")?.asString != nil }
}

enum Ref {
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

    /// The raw bytes of a corpus file; `.gz` is decompressed with the system gzip.
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

    static func parse(_ text: String) -> JSONValue? { try? StrictJSON.parseLenient(text) }

    /// Lines the last `each` could not parse (a Swift String cannot hold a lone surrogate, so a case carrying one is not comparable).
    static var lastUnparsed = 0

    /// Calls `body` for every case (one per line, in file order) whose fn is in `fns` (nil = all); returns the count.
    @discardableResult
    static func each(_ file: String, _ fns: Set<String>? = nil, _ body: (RefCase) throws -> Void) throws -> Int {
        let text = String(decoding: try bytes(file), as: UTF8.self)
        var n = 0
        lastUnparsed = 0
        for var line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard line.hasPrefix(#"{"fn":"#) else { continue }
            if line.hasSuffix(",") { line = line.dropLast() }
            guard let v = parse(String(line)) else { lastUnparsed += 1; continue }
            let fn = v.get("fn")?.asString ?? ""
            if let f = fns, !f.contains(fn) { continue }
            n += 1
            try body(RefCase(fn: fn, name: v.get("name")?.asString ?? "?", args: v.get("args")?.asArray ?? [], out: v.get("out") ?? .null))
        }
        return n
    }

    static func canon(_ v: JSONValue?) -> String { v.map { Canonical.canonicalize($0) } ?? "undefined" }

    /// {"$bytes": b64url} -> the bytes (nil for anything else).
    static func bytes(_ v: JSONValue?) -> [UInt8]? {
        guard let o = v?.asObject, o.count == 1, let s = o["$bytes"]?.asString else { return nil }
        return Base64URLStrict.decode(s)
    }

    static func bytesValue(_ b: [UInt8]) -> JSONValue { .object(["$bytes": .string(Base64URLStrict.encode(b))]) }

    static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    static func unhex(_ s: String) -> [UInt8]? {
        let c = Array(s.utf8)
        guard c.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        func nib(_ x: UInt8) -> UInt8? { x >= 48 && x <= 57 ? x - 48 : x >= 97 && x <= 102 ? x - 87 : x >= 65 && x <= 70 ? x - 55 : nil }
        var i = 0
        while i < c.count { guard let a = nib(c[i]), let b = nib(c[i + 1]) else { return nil }; out.append(a << 4 | b); i += 2 }
        return out
    }

    static func sha256(_ b: [UInt8]) -> [UInt8] { Canonical.sha256(b) }

    /// A generic comparison of a native result with the reference output: a reference throw requires a native refusal.
    static func diff(_ c: RefCase, _ got: JSONValue?) -> String? {
        switch (c.threw, got) {
        case (true, nil): return nil
        case (true, let v?): return "\(c.name): want throw got \(canon(v).prefix(200))"
        case (false, nil): return "\(c.name): want \(canon(c.out).prefix(200)) got throw"
        case (false, let v?): return canon(v) == canon(c.out) ? nil : "\(c.name): want \(canon(c.out).prefix(300)) got \(canon(v).prefix(300))"
        }
    }

    /// Collects divergences and fails once at the end, with a floor on the number of cases that actually ran.
    final class Diffs {
        private(set) var bad: [String] = []
        private(set) var run = 0
        private(set) var skipped: [String: Int] = [:]
        func add(_ d: String?) { run += 1; if let d = d { bad.append(d) } }
        func skip(_ why: String) { skipped[why, default: 0] += 1 }
        func finish(_ min: Int, file: StaticString = #filePath, line: UInt = #line) {
            for (k, v) in skipped.sorted(by: { $0.key < $1.key }) { print("skipped \(v): \(k)") }
            XCTAssertGreaterThanOrEqual(run, min, "too few cases ran", file: file, line: line)
            XCTAssertTrue(bad.isEmpty, "\(bad.count) divergence(s):\n" + bad.prefix(15).joined(separator: "\n"), file: file, line: line)
        }
    }
}
