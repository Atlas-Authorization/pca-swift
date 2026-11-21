import XCTest
import Foundation
@testable import AtlasPCAVerify

/// One case of a k05 differential oracle: `fn` (the TS reference function, `@suspect` stripped), `args` (positional, parsed
/// with the lenient reader like every native), `out` (exactly what the reference returned; a throw is {$throws, code?}).
struct K05Case {
    let fn: String
    let name: String
    let args: [JSONValue]
    let out: JSONValue
    /// TS behaviour the generator flags as questionable: reported, never fails.
    let suspect: Bool
    let raw: JSONValue

    func arg(_ i: Int) -> JSONValue? { i < args.count ? args[i] : nil }
    /// The reference threw.
    var threw: Bool { out.get("$throws")?.asString != nil }
    /// The stable error code of a reference throw (when it carried one).
    var code: String? { threw ? out.get("code")?.asString : nil }
    /// A string member of the case record beyond fn/name/args/out (cmp, textPrefix, ...).
    func meta(_ k: String) -> String? { raw.get(k)?.asString }
}

/// What a native call produced, for the generic comparison.
enum K05Got {
    case value(JSONValue)
    /// A refusal; `code` = the native's stable error code when it has one.
    case threw(String?)
}

/// Loader + comparison helpers of the k05 differential oracles: test-data/k05-<module>.json.gz, produced by the TypeScript
/// reference (tools/pca-audit/k05-oracles in the flagship) and shared by every native verifier suite. The file holds one case
/// per line, so a case is parsed on its own (a 170 MB oracle never becomes one in-memory tree).
enum K05 {
    /// Calls `body` for every case (in file order) whose fn (`@suspect` stripped) is in `fns` (nil = all); returns the count.
    @discardableResult
    static func each(_ file: String, _ fns: Set<String>? = nil, _ body: (K05Case) throws -> Void) throws -> Int {
        let bs = [UInt8](try K042.bytes(file))
        let prefix = Array(#"{"fn":"#.utf8)
        var n = 0
        var lines: [Range<Int>] = []
        bs.withUnsafeBufferPointer { p in
            guard let base = p.baseAddress else { return }
            var at = 0
            while at < p.count {
                // memchr: a byte loop over 170 MB is seconds in a debug build
                let nl = memchr(base + at, 0x0A, p.count - at).map { UnsafeRawPointer($0) - UnsafeRawPointer(base) } ?? p.count
                lines.append(at..<nl)
                at = nl + 1
            }
        }
        // a fn filter is applied to the raw line first: only the wanted cases are parsed
        let wanted = fns.map { f in f.flatMap { [Array(#"{"fn":"\#($0)""#.utf8), Array(#"{"fn":"\#($0)@suspect""#.utf8)] } }
        for r in lines {
            var line = bs[r]
            guard line.starts(with: prefix) else { continue }
            if let w = wanted, !w.contains(where: { line.starts(with: $0) }) { continue }
            if line.last == UInt8(ascii: ",") { line = line.dropLast() }
            let v = K042.parse(String(decoding: line, as: UTF8.self))
            let full = v.get("fn")?.asString ?? ""
            let suspect = full.hasSuffix("@suspect")
            let fn = suspect ? String(full.dropLast("@suspect".count)) : full
            if let f = fns, !f.contains(fn) { continue }
            n += 1
            try body(K05Case(fn: fn, name: v.get("name")?.asString ?? "?", args: v.get("args")?.asArray ?? [], out: v.get("out") ?? .null,
                             suspect: suspect, raw: v))
        }
        return n
    }

    static func canon(_ v: JSONValue?) -> String { K042.canon(v) }

    /// A -0 anywhere in the value (TS Number.isSafeInteger / isInteger take -0 in a few checks the strict Swift profile refuses).
    static func negZero(_ v: JSONValue) -> Bool {
        switch v {
        case let .double(d): return d == 0 && d.sign == .minus
        case let .array(a): return a.contains(where: negZero)
        case let .object(o): return o.values.contains(where: negZero)
        default: return false
        }
    }

    /// {"$bytes": b64url} -> the bytes (nil for anything else).
    static func bytes(_ v: JSONValue?) -> [UInt8]? {
        guard let o = v?.asObject, o.count == 1, let s = o["$bytes"]?.asString else { return nil }
        return Base64URLStrict.decode(s)
    }

    /// The bytes as the {"$bytes": b64url} the reference writes for a Uint8Array.
    static func bytesValue(_ b: [UInt8]) -> JSONValue { .object(["$bytes": .string(Base64URLStrict.encode(b))]) }

    static func str(_ v: JSONValue?) -> JSONValue { v ?? .null }
    static func opt(_ s: String?) -> JSONValue { s.map { .string($0) } ?? .null }

    /// Runs a throwing native call; a thrown error becomes `.threw(code)` (code = `codeOf(error)`).
    static func run(_ codeOf: (Error) -> String? = { _ in nil }, _ f: () throws -> JSONValue) -> K05Got {
        do { return .value(try f()) } catch { return .threw(codeOf(error)) }
    }

    /// Generic comparison: a reference throw requires a native refusal (with the same code when the reference carried one);
    /// a reference value requires canonical-JSON equality. Returns nil when they agree, else the divergence text.
    static func diff(_ c: K05Case, _ got: K05Got) -> String? {
        switch (c.threw, got) {
        case (true, .threw(let code)):
            if let want = c.code, want != code { return "\(c.name): want throw code \(want) got \(code ?? "nil")" }
            return nil
        case (true, .value(let v)):
            return "\(c.name): want throw \(canon(c.out)) got \(canon(v).prefix(300))"
        case (false, .threw(let code)):
            return "\(c.name): want \(canon(c.out).prefix(300)) got throw \(code ?? "")"
        case (false, .value(let v)):
            return canon(v) == canon(c.out) ? nil : "\(c.name): want \(firstDiff(c.out, v, "@")) || want \(canon(c.out).prefix(300)) got \(canon(v).prefix(300))"
        }
    }

    /// The first place two values differ, as "<path> <want> got <got>" (a CI log shows what differs, not two truncated documents).
    static func firstDiff(_ a: JSONValue?, _ b: JSONValue?, _ at: String) -> String {
        switch (a, b) {
        case let (.object(x)?, .object(y)?):
            for k in Set(x.keys).union(y.keys).sorted() where canon(x[k]) != canon(y[k]) { return firstDiff(x[k], y[k], "\(at)/\(k.s)") }
        case let (.array(x)?, .array(y)?) where x.count == y.count:
            for i in x.indices where canon(x[i]) != canon(y[i]) { return firstDiff(x[i], y[i], "\(at)/\(i)") }
        default: break
        }
        return "\(at) \(canon(a).prefix(200)) got \(canon(b).prefix(200))"
    }

    /// Collects divergences; `@suspect` cases are printed, never failed.
    final class Diffs {
        private(set) var bad: [String] = []
        private(set) var suspect: [String] = []
        private(set) var run = 0
        private(set) var skipped: [String: Int] = [:]

        func add(_ c: K05Case, _ d: String?) {
            // a Swift String cannot hold a lone surrogate (the harness reads one as a sentinel scalar, and the strict parser refuses one on
            // the wire), so a case that carries one in its input or its reference output is not comparable (as in the Rust harness)
            if IV.hasSentinel(.array(c.args)) || IV.hasSentinel(c.out) { skip("lone surrogate: a Swift String cannot hold one"); return }
            // an OS without CryptoKit's ML-DSA (before macOS / iOS 26) refuses those suites as unsupported_suite (fail closed)
            if !MLDSA.available, let x = d, x.contains("unsupported_suite") { skip("ML-DSA is not available on this OS (unsupported_suite)"); return }
            run += 1
            guard let d = d else { return }
            if c.suspect { suspect.append(d) } else { bad.append(d) }
        }

        /// A case not compared, with the reason (summarised at the end).
        func skip(_ reason: String) { skipped[reason, default: 0] += 1 }

        func finish(_ min: Int, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertGreaterThanOrEqual(run, min, "too few k05 cases compared", file: file, line: line)
            for (r, n) in skipped.sorted(by: { $0.key < $1.key }) { print("k05 skipped \(n): \(r)") }
            if !bad.isEmpty {
                // the divergences grouped by what differs (the case name stripped), most frequent first, with one example each
                var groups: [String: (n: Int, example: String)] = [:]
                for b in bad {
                    var key = b.range(of: ": want ").map { String(b[$0.lowerBound...]) } ?? b
                    if let cut = key.range(of: " || ") { key = String(key[..<cut.lowerBound]) }
                    groups[String(key.prefix(400)), default: (0, b)].n += 1
                }
                for (k, g) in groups.sorted(by: { $0.value.n > $1.value.n }).prefix(150) { print("k05 divergence x\(g.n)\(k.prefix(400))\n    e.g. \(g.example.prefix(900))") }
            }
            if !suspect.isEmpty { print("k05 @suspect divergences (reported, not failed): \(suspect.count)\n" + suspect.prefix(10).joined(separator: "\n")) }
            K042.report(bad, run, file: file, line: line)
        }
    }
}
