import XCTest
import Foundation
@testable import AtlasPCAVerify

/// One case of a base differential oracle: `fn` (the TS reference function, `@suspect` stripped), `args` (positional, parsed
/// with the lenient reader like every native), `out` (exactly what the reference returned; a throw is {$throws, code?}).
struct BaseCase {
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
    /// The reference threw a raw JS-engine failure (see `Base.isEngineCrash`): the native only has to refuse.
    var engineCrash: Bool { out.get("$throws")?.asString.map(Base.isEngineCrash) ?? false }
    /// The stable error code of a reference throw (when it carried one).
    var code: String? { threw ? out.get("code")?.asString : nil }
    /// A string member of the case record beyond fn/name/args/out (cmp, textPrefix, ...).
    func meta(_ k: String) -> String? { raw.get(k)?.asString }
}

/// What a native call produced, for the generic comparison.
enum BaseGot {
    case value(JSONValue)
    /// A refusal; `code` = the native's stable error code when it has one.
    case threw(String?)
}

/// Loader + comparison helpers of the base differential oracles: test-data/base-<module>.json.gz, produced by the TypeScript
/// reference (tools/pca-audit/oracles-base in the flagship) and shared by every native verifier suite. The file holds one case
/// per line, so a case is parsed on its own (a 170 MB oracle never becomes one in-memory tree).
enum Base {
    /// Calls `body` for every case (in file order) whose fn (`@suspect` stripped) is in `fns` (nil = all); returns the count.
    @discardableResult
    static func each(_ file: String, _ fns: Set<String>? = nil, seeds: Bool = false, _ body: (BaseCase) throws -> Void) throws -> Int {
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
        var seen = Set<String>()
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
            seen.insert(fn)
            n += 1
            try body(BaseCase(fn: fn, name: v.get("name")?.asString ?? "?", args: (v.get("args")?.asArray ?? []).map { seeds ? resolveSeeds($0) : $0 }, out: v.get("out") ?? .null,
                             suspect: suspect, raw: v))
        }
        // a filter that names a fn the corpus does not hold (a renamed or mistyped fn) would silently replay nothing for it
        if let f = fns { XCTAssertTrue(f.subtracting(seen).isEmpty, "\(file): the fn filter names \(f.subtracting(seen).sorted()), which the corpus does not hold") }
        // every case of the corpus must be delivered: a replay never silently covers a part of its file (the header carries the total)
        if fns == nil, let m = String(decoding: bs.prefix(600), as: UTF8.self).range(of: #""count":\s*[0-9]+"#, options: .regularExpression),
           let want = Int(String(decoding: bs.prefix(600), as: UTF8.self)[m].drop(while: { $0 != ":" }).dropFirst().trimmingCharacters(in: .whitespaces)) {
            XCTAssertEqual(n, want, "\(file): the replay delivered \(n) cases, the corpus holds \(want)")
        }
        return n
    }

    /// The generator clock (epoch ms) of corpora committed before the header carried `clockMs`.
    static let fallbackClockMs: Double = 1_800_000_000_000

    /// The frozen clock a corpus header line records as `clockMs`, else `fallbackClockMs`. (A quote inside a header string is escaped, so the member text cannot hide in one.)
    static func clockOfHeader(_ header: String) -> Double {
        guard let r = header.range(of: #","clockMs":\s*-?[0-9]+(\.[0-9]+)?"#, options: .regularExpression) else { return fallbackClockMs }
        let member = header[r]
        guard let colon = member.firstIndex(of: ":"),
              let v = Double(member[member.index(after: colon)...].trimmingCharacters(in: .whitespaces)), v.isFinite else { return fallbackClockMs }
        return v
    }

    /// The one clock accessor of the replays: the frozen clock of the corpus `file` (its first line is the header).
    static func clockMs(_ file: String) -> Double {
        guard let data = try? K042.bytes(file) else { return fallbackClockMs }
        let bs = [UInt8](data)
        return clockOfHeader(String(decoding: bs.prefix(upTo: bs.firstIndex(of: 0x0A) ?? bs.count), as: UTF8.self))
    }

    static func canon(_ v: JSONValue?) -> String { K042.canon(v) }

    /// Every seed object (keys within {$seed, es256, ec, ed448}) -> its derived base64url key: plain SHA-256("atlas-pca-conformance/" + label)
    /// (top bit of byte 0 cleared when es256); ec P-384/P-521: first 48/66 bytes of SHA256(P+L)||SHA256(P+L+"/2")||SHA256(P+L+"/3"), byte0 &= 0x7F / 0x01;
    /// ed448: SHA256(P+L) || SHA256(P+L+"/2")[0..<25]. Other shapes are left alone (opt in per test with `each(seeds: true)`).
    static func resolveSeeds(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(resolveSeeds))
        case let .object(o):
            // {"$utf16": [code units]}: a string holding a lone surrogate; a Swift String cannot hold one, so it becomes the sentinel scalar
            if o.keys.count == 1, case let .array(u)? = o["$utf16"] {
                let units: [UInt16] = u.compactMap { if case let .int(n) = $0 { return UInt16(truncatingIfNeeded: n) } else if case let .double(d) = $0 { return UInt16(truncatingIfNeeded: Int(d)) } else { return nil } }
                var s = String.UnicodeScalarView()
                var it = units.makeIterator()
                var dec = UTF16()
                loop: while true {
                    switch dec.decode(&it) {
                    case let .scalarValue(sc): s.append(sc)
                    case .emptyInput: break loop
                    case .error: s.append(Canonical.LONE_SURROGATE_SENTINEL)
                    }
                }
                return .string(String(s))
            }
            if let label = o["$seed"]?.asString, o.keys.allSatisfy({ ["$seed", "es256", "ec", "ed448"].contains($0) }) {
                func h(_ sfx: String) -> [UInt8] { Canonical.sha256(Array("atlas-pca-conformance/\(label)\(sfx)".utf8)) }
                var raw = h("")
                if o["es256"] == .bool(true) { raw[0] &= 0x7F }
                if let ec = o["ec"]?.asString, ec == "P-384" || ec == "P-521" {
                    raw = h("") + h("/2") + h("/3")
                    if ec == "P-384" { raw = Array(raw.prefix(48)); raw[0] &= 0x7F } else { raw = Array(raw.prefix(66)); raw[0] &= 0x01 }
                }
                if o["ed448"] == .bool(true) { raw = h("") + Array(h("/2").prefix(25)) }
                return .string(Base64URLStrict.encode(raw))
            }
            return .object(o.mapValues(resolveSeeds))
        default: return v
        }
    }

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

    /// The message of the most recent refusal `run` caught, so a divergence line says why the native threw.
    nonisolated(unsafe) static var lastThrown = ""
    /// Runs a throwing native call; a thrown error becomes `.threw(code)` (code = `codeOf(error)`).
    static func run(_ codeOf: (Error) -> String? = { _ in nil }, _ f: () throws -> JSONValue) -> BaseGot {
        do { return .value(try f()) } catch { lastThrown = String(describing: error); return .threw(codeOf(error)) }
    }

    /// The JS-engine crash rule (one shared definition): a reference refusal whose message is a raw V8 failure on hostile input passes iff the
    /// native refuses; the message is never compared. Node error codes (ERR_*) are defined errors and never match.
    static func isEngineCrash(_ msg: String) -> Bool {
        msg.range(of: "Cannot read propert(y|ies) of (null|undefined)|is not a function|is not iterable|Cannot convert undefined or null to object|Cannot destructure|Cannot use 'in' operator|Cannot create property|Reduce of empty array|is not an object|Cannot mix BigInt|Do not know how to serialize a BigInt|Converting circular structure|Invalid array length|Maximum call stack", options: .regularExpression) != nil
    }

    /// Generic comparison: a reference throw requires a native refusal (with the same code when the reference carried one);
    /// a reference value requires canonical-JSON equality. Returns nil when they agree, else the divergence text.
    static func diff(_ c: BaseCase, _ got: BaseGot) -> String? {
        switch (c.threw, got) {
        case (true, .threw(let code)):
            if let want = c.code, want != code { return "\(c.name): want throw code \(want) got \(code ?? "nil")" }
            return nil
        case (true, .value(let v)):
            return "\(c.name): want throw \(canon(c.out)) got \(canon(v).prefix(300))"
        case (false, .threw(let code)):
            return "\(c.name): want \(canon(c.out).prefix(300)) got throw \(code ?? "") \(lastThrown.prefix(160))"
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
        /// A replay whose native code carries a lone surrogate as the library's sentinel scalar (and renders it as the reference does) compares those cases instead of skipping them.
        var acceptsLoneSurrogates = false
        private(set) var skipped: [String: Int] = [:]

        func add(_ c: BaseCase, _ d: String?) {
            // a Swift String cannot hold a lone surrogate (the harness reads one as a sentinel scalar, and the strict parser refuses one on
            // the wire), so a case that carries one in its input or its reference output is not comparable (as in the Rust harness)
            if !acceptsLoneSurrogates, IV.hasSentinel(.array(c.args)) || IV.hasSentinel(c.out) { skip("lone surrogate: a Swift String cannot hold one"); return }
            // an OS without CryptoKit's ML-DSA (before macOS / iOS 26) refuses those suites as unsupported_suite (fail closed)
            if !MLDSA.available, let x = d, x.contains("unsupported_suite") { if PqRequirement.mayLeaveOut("\(c.name)") { skip("ML-DSA is not available on this OS (unsupported_suite)") }; return }
            run += 1
            guard let d = d else { return }
            if c.suspect { suspect.append(d) } else { bad.append(d) }
        }

        /// A case not compared, with the reason (summarised at the end).
        func skip(_ reason: String) {
            skipped[reason, default: 0] += 1
            // a fn the replay has no mapping for is a coverage hole, never a skip
            if reason.contains(": not mapped") || reason.hasPrefix("function not replayed") || reason.hasPrefix("fn ") && reason.hasSuffix("not replayed") { unmapped.insert(reason) }
        }
        private(set) var unmapped: Set<String> = []

        func finish(_ min: Int, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertTrue(unmapped.isEmpty, "the replay has no mapping for: \(unmapped.sorted())", file: file, line: line)
            XCTAssertGreaterThanOrEqual(run, min, "too few base cases compared", file: file, line: line)
            for (r, n) in skipped.sorted(by: { $0.key < $1.key }) { print("base skipped \(n): \(r)") }
            if !bad.isEmpty {
                // the divergences grouped by what differs (the case name stripped), most frequent first, with one example each
                var groups: [String: (n: Int, example: String)] = [:]
                for b in bad {
                    var key = b.range(of: ": want ").map { String(b[$0.lowerBound...]) } ?? b
                    if let cut = key.range(of: " || ") { key = String(key[..<cut.lowerBound]) }
                    groups[String(key.prefix(400)), default: (0, b)].n += 1
                }
                for (k, g) in groups.sorted(by: { $0.value.n > $1.value.n }).prefix(150) { print("base divergence x\(g.n)\(k.prefix(400))\n    e.g. \(g.example.prefix(900))") }
            }
            if !suspect.isEmpty { print("base @suspect divergences (reported, not failed): \(suspect.count)\n" + suspect.prefix(10).joined(separator: "\n")) }
            K042.report(bad, run, file: file, line: line)
        }
    }
}
