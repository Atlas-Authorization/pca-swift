import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential kill tests of SafeRegex.swift against the TS reference (safe-regex.ts, predicates.ts isSafeRegexSource,
/// regex-budget.ts). (1) The shared k042 corpus (tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs): every pattern must
/// compile to the EXACT same NFA program (instruction for instruction) or be refused alike, get the same isSafeRegexSource
/// verdict and full-match every recorded subject alike. (2) killRegex (tools/pca-audit/kotlin-mutate/killRegex-oracle-gen.mjs):
/// compiled sizes, a pattern corpus crossed with boundary-probing subjects, the step boundary, the safe-source guard and the
/// per-document budget.
final class K042SafeRegexOracleTests: XCTestCase {
    static func dump(_ c: SafeRegex.Compiled) -> String {
        var parts: [String] = []
        parts.reserveCapacity(c.prog.count)
        for ins in c.prog {
            switch ins {
            case let .set(cs):
                let r = cs.ranges.isEmpty ? "E" : cs.ranges.map { "\($0.0)-\($0.1)" }.joined(separator: ":")
                parts.append("0,0,0,\(cs.negated ? 1 : 0),\(r)")
            case let .split(x, y): parts.append("1,\(x),\(y),-,-")
            case let .jmp(x): parts.append("2,\(x),0,-,-")
            case .bol: parts.append("3,0,0,-,-")
            case .eol: parts.append("4,0,0,-,-")
            case .match: parts.append("5,0,0,-,-")
            }
        }
        let s = parts.joined(separator: ";")
        if s.utf8.count > 1000 {
            return "H" + Canonical.sha256(Array(s.utf8)).map { String(format: "%02x", $0) }.joined()
        }
        return s
    }

    func testCorpusMatchesTheReference() throws {
        try K042.requireCovers(["SafeRegex"])
        let data = try K042.bytes("k042-saferegex.txt.gz")
        var fails: [String] = []
        var patterns = 0, compiled = 0, safe = 0, matches = 0
        var pat: [UInt16] = []
        var cur: SafeRegex.Compiled?
        var have = false
        data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            let bytes = raw.bindMemory(to: UInt8.self)
            var i = 0
            let n = bytes.count
            while i < n {
                var j = i
                while j < n && bytes[j] != 0x0a { j += 1 }
                let line = String(decoding: UnsafeBufferPointer(rebasing: bytes[i..<j]), as: UTF8.self)
                i = j + 1
                if line.isEmpty { continue }
                let f = line.split(separator: " ", omittingEmptySubsequences: false)
                if f[0] == "P" {
                    patterns += 1
                    pat = K042.hexUnits(String(f[1]))
                    let wantSafe = f[2] == "1"
                    cur = SafeRegex.compile(pat)
                    have = cur != nil
                    let got = cur.map { Self.dump($0) } ?? "N"
                    if have { compiled += 1 }
                    if got != String(f[3]) { fails.append("compile /\(f[1])/: want \(f[3].prefix(160)) got \(got.prefix(160))") }
                    let gs = SafeRegex.isSafeSource(pat)
                    if gs { safe += 1 }
                    if gs != wantSafe { fails.append("isSafeSource /\(f[1])/: want \(wantSafe) got \(gs)") }
                } else {
                    matches += 1
                    guard have, let re = cur else { fails.append("subject for a refused pattern \(f[1])"); continue }
                    let subj = K042.hexUnits(String(f[1]))
                    let want: Bool? = f[2] == "N" ? nil : (f[2] == "T")
                    let got = SafeRegex.run(re, subj)
                    if got != want { fails.append("run /\(pat.map { String(format: "%04x", $0) }.joined())/ on \(f[1]): want \(String(describing: want)) got \(String(describing: got))") }
                }
                if fails.count >= 3 { break }
            }
        }
        XCTAssert(fails.isEmpty, "\(fails.count) differences, first:\n" + fails.prefix(40).joined(separator: "\n"))
        XCTAssertEqual(patterns, 8648)
        XCTAssertEqual(compiled, 5267)
        XCTAssertEqual(safe, 3206)
        XCTAssertEqual(matches, 572525)
    }

    /// Group nesting depth of a pattern (escapes and classes ignored, enough to find the probes): the protocol caps a regex at
    /// 200 units, so a pattern nested deeper than ~100 groups is an engine probe; each verifier refuses it at a language-specific
    /// recursion depth (Swift: its own parse-depth bound), which is not part of the compared behaviour.
    static func nesting(_ p: String) -> Int {
        var d = 0, m = 0, esc = false, cls = false
        for c in p.unicodeScalars {
            if esc { esc = false; continue }
            if c == "\\" { esc = true } else if cls { if c == "]" { cls = false } } else if c == "[" { cls = true } else if c == "(" { d += 1; m = max(m, d) } else if c == ")" { d -= 1 }
        }
        return m
    }

    func testKillRegexFullMatchCorpus() throws {
        try K042.requireCovers(["SafeRegex"])
        let g = try K042.json("killRegex.json.gz")
        var bad: [String] = []
        var n = 0
        for eo in K042.arr(g.get("fm")) {
            let e = K042.arr(eo)
            if Self.nesting(K042.str(e[0])) > 100 { continue }
            let p = K042.units(K042.str(e[0]))
            let subs = K042.arr(e[1])
            let rs = Array(K042.str(e[2]).utf8)
            XCTAssertEqual(subs.count, rs.count)
            let prog = SafeRegex.compile(p)
            for (i, so) in subs.enumerated() {
                let want: Bool? = rs[i] == 0x31 ? true : (rs[i] == 0x30 ? false : nil)
                let got = prog.flatMap { SafeRegex.run($0, K042.units(K042.str(so))) }
                if got != want { bad.append("/\(K042.str(e[0]))/ on \(K042.units(K042.str(so))): want \(String(describing: want)) got \(String(describing: got))") }
                n += 1
            }
        }
        XCTAssertGreaterThan(n, 100_000)
        K042.report(bad, n)
    }

    func testKillRegexSizesStepsAndSafeSource() throws {
        let g = try K042.json("killRegex.json.gz")
        var bad: [String] = []
        for eo in K042.arr(g.get("size")) {
            let e = K042.arr(eo)
            if Self.nesting(K042.str(e[0])) > 100 { continue }
            let want = Int(IV.num(e[1]) ?? -1)
            let prog = SafeRegex.compile(K042.units(K042.str(e[0])))
            if want < 0 { if prog != nil { bad.append("size /\(K042.str(e[0]))/: want refused got \(prog!.prog.count)") } }
            else if prog?.prog.count != want { bad.append("size /\(K042.str(e[0]))/: want \(want) got \(String(describing: prog?.prog.count))") }
        }
        for eo in K042.arr(g.get("steps")) {
            let e = K042.arr(eo)
            let n = Int(IV.num(e[1]) ?? 0)
            let w = Int(IV.num(e[2]) ?? -1)
            let want: Bool? = w == 1 ? true : (w == 0 ? false : nil)
            let got = SafeRegex.compile(K042.units(K042.str(e[0]))).flatMap { SafeRegex.run($0, [UInt16](repeating: 0x61, count: n)) }
            if got != want { bad.append("steps /\(K042.str(e[0]).prefix(20))/ n=\(n): want \(String(describing: want)) got \(String(describing: got))") }
        }
        for eo in K042.arr(g.get("safe")) {
            let e = K042.arr(eo)
            if Self.nesting(K042.str(e[0])) > 100 { continue }
            let got = SafeRegex.isSafeSource(K042.units(K042.str(e[0])))
            if got != K042.bool(e[1]) { bad.append("safe /\(K042.str(e[0]))/: want \(K042.bool(e[1])) got \(got)") }
        }
        K042.report(bad, 0)
    }

    func testKillRegexBudgetSequences() throws {
        let g = try K042.json("killRegex.json.gz")
        var bad: [String] = []
        for (k, bo) in K042.arr(g.get("budgets")).enumerated() {
            let budget = SafeRegex.Budget()
            let ops = K042.arr(bo.get("ops")), res = K042.arr(bo.get("res"))
            for (i, oo) in ops.enumerated() {
                let op = K042.arr(oo)
                let src = K042.units(K042.str(op[0]))
                let subjectUnits = Int(IV.num(op[1]) ?? 0)
                var got = false
                if let re = SafeRegex.compile(src) { // chargeRegex compiles; the isSafeSource guard is a separate step
                    got = budget.charge(srcUnits: src.count, progLen: re.prog.count, subjectUnits: subjectUnits)
                }
                if got != K042.bool(res[i]) { bad.append("budget #\(k) op \(i): want \(K042.bool(res[i])) got \(got)") }
            }
            let fin = K042.arr(bo.get("fin"))
            // a refused charge poisons the budget differently from the reference's counters: totals compare only while nothing was refused
            if Int(IV.num(fin[3]) ?? -1) == 0 {
                if Double(budget.evaluations) != IV.num(fin[0]) || Double(budget.chars) != IV.num(fin[1]) || Double(budget.steps) != IV.num(fin[2]) {
                    bad.append("budget #\(k) totals: want \(fin.map { K042.canon($0) }) got \(budget.evaluations)/\(budget.chars)/\(budget.steps)")
                }
            }
        }
        K042.report(bad, 0)
    }
}
