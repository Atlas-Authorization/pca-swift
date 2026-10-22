import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The linear-time regex subset (`SafeRegex`) pinned construct by construct: the parser (escapes, classes, quantifiers, groups),
/// the NFA depth / size limits, the Pike simulation, the structural `isSafeSource` guard and its 22-bit cost budget, and the
/// per-document budget. Every expectation is the reference (JavaScript flagless `RegExp`) behaviour.
final class SafeRegexKillTests: XCTestCase {
    private func u(_ s: String) -> [UInt16] { Array(s.utf16) }
    private func compiled(_ re: String) -> SafeRegex.Compiled? { SafeRegex.compile(u(re)) }
    /// full match; nil when the source does not compile (or the budget refuses)
    private func m(_ re: String, _ subject: String) -> Bool? {
        guard let c = compiled(re) else { return nil }
        return SafeRegex.run(c, u(subject))
    }
    private func safe(_ src: String) -> Bool { SafeRegex.isSafeSource(u(src)) }
    private func rep(_ s: String, _ n: Int) -> String { String(repeating: s, count: n) }
    private func nest(_ n: Int, _ open: String, _ inner: String, _ close: String) -> String { rep(open, n) + inner + rep(close, n) }
    private func hex2(_ v: Int, upper: Bool) -> String {
        let s = String(v, radix: 16, uppercase: upper)
        return s.count < 2 ? "0" + s : s
    }
    private func hex4(_ v: Int, upper: Bool) -> String {
        let s = String(v, radix: 16, uppercase: upper)
        return String(repeating: "0", count: 4 - s.count) + s
    }
    private func matchesUnit(_ re: String, _ c: Int) -> Bool? {
        guard let comp = compiled(re) else { return nil }
        return SafeRegex.run(comp, [UInt16(c)])
    }

    // ---- character sets ----------------------------------------------------------------------------------------------

    func testClassEscapeSetsAgreeWithTheJavaScriptSets() {
        func word(_ c: Int) -> Bool { (0x30...0x39).contains(c) || (0x41...0x5a).contains(c) || c == 0x5f || (0x61...0x7a).contains(c) }
        func digit(_ c: Int) -> Bool { (0x30...0x39).contains(c) }
        func space(_ c: Int) -> Bool {
            (0x09...0x0d).contains(c) || c == 0x20 || c == 0xa0 || c == 0x1680 || (0x2000...0x200a).contains(c) || c == 0x2028 || c == 0x2029
                || c == 0x202f || c == 0x205f || c == 0x3000 || c == 0xfeff
        }
        func dot(_ c: Int) -> Bool { !(c == 0x0a || c == 0x0d || c == 0x2028 || c == 0x2029) }
        // every range boundary of the JavaScript sets (and one code unit either side), plus the ends of the code-unit space
        var probes = Array(0...0x80)
        for centre in [0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff] { probes += (centre - 2)...(centre + 2) }
        probes += [0x9f, 0xff, 0x100, 0xfffe, 0xffff]
        let cases: [(String, (Int) -> Bool)] = [
            (#"\w"#, word), (#"\W"#, { !word($0) }), (#"\d"#, digit), (#"\D"#, { !digit($0) }), (#"\s"#, space), (#"\S"#, { !space($0) }),
            (#"[\w]"#, word), (#"[\W]"#, { !word($0) }), (#"[\d]"#, digit), (#"[\D]"#, { !digit($0) }), (#"[\s]"#, space), (#"[\S]"#, { !space($0) }),
            (#"[^\W]"#, word), (#"[^\D]"#, digit), (#"[^\S]"#, space), (".", dot),
        ]
        for (re, oracle) in cases {
            guard let comp = compiled(re) else { XCTFail("\(re) does not compile"); continue }
            var bad: [Int] = []
            for c in probes where SafeRegex.run(comp, [UInt16(c)]) != oracle(c) { bad.append(c) }
            XCTAssertEqual(bad, [], "\(re) disagrees at \(bad.prefix(8))")
        }
    }

    func testComplementBoundaries() {
        // the \W complement ranges, one by one
        for (c, want) in [(0x00, true), (0x2f, true), (0x30, false), (0x31, false), (0x39, false), (0x3a, true), (0x40, true), (0x41, false), (0x5a, false),
                          (0x5b, true), (0x5e, true), (0x5f, false), (0x60, true), (0x61, false), (0x7a, false), (0x7b, true), (0xffff, true)] {
            XCTAssertEqual(matchesUnit(#"[\W]"#, c), want, "[\\W] at \(c)")
        }
        XCTAssertEqual(matchesUnit(#"[\D]"#, 0x00), true)
        XCTAssertEqual(matchesUnit(#"[\D]"#, 0x30), false)
        XCTAssertEqual(matchesUnit(#"[\D]"#, 0x31), false)
        XCTAssertEqual(matchesUnit(#"[\D]"#, 0x2f), true)
        XCTAssertEqual(matchesUnit(#"[\D]"#, 0x3a), true)
        XCTAssertEqual(matchesUnit(#"[\D]"#, 0xffff), true)
        XCTAssertEqual(matchesUnit(#"[\S]"#, 0x08), true)
        XCTAssertEqual(matchesUnit(#"[\S]"#, 0x09), false)
        XCTAssertEqual(matchesUnit(#"[\S]"#, 0x0e), true)
        XCTAssertEqual(matchesUnit(#"[\S]"#, 0xfeff), false)
        XCTAssertEqual(matchesUnit(#"[\S]"#, 0xff00), true)
    }

    func testRangeMergingAndLookup() {
        XCTAssertEqual(m("a", "b"), false)
        XCTAssertEqual(m("[a-cb-e]", "d"), true)
        XCTAssertEqual(m("[a-cb-e]", "c"), true)
        XCTAssertEqual(m("[a-cb-e]", "f"), false)
        XCTAssertEqual(m("[a-bd-e]", "c"), false, "a one-character gap is not merged")
        XCTAssertEqual(m("[a-bd-e]", "d"), true)
        XCTAssertEqual(m("[a-bc-e]", "c"), true)
        XCTAssertEqual(m("[ace]", "b"), false)
        XCTAssertEqual(m("[ace]", "e"), true)
        XCTAssertEqual(m("[a-z0-9_]", "_"), true)
        XCTAssertEqual(m("[a-z0-9_]", "A"), false)
        // overlapping, contained and out-of-order ranges still resolve by binary search
        for c in "abcdefghijklmnopqrstuvwxyz" {
            XCTAssertEqual(m("[x-zb-qk-ma-d]", String(c)), ("a"..."q").contains(c) || ("x"..."z").contains(c), String(c))
        }
    }

    // ---- escapes -----------------------------------------------------------------------------------------------------

    func testSingleCharacterEscapes() {
        for (re, code) in [(#"\t"#, 9), (#"\n"#, 10), (#"\v"#, 11), (#"\f"#, 12), (#"\r"#, 13), (#"\0"#, 0), (#"[\t]"#, 9), (#"[\n]"#, 10), (#"[\v]"#, 11),
                           (#"[\f]"#, 12), (#"[\r]"#, 13), (#"[\0]"#, 0), (#"[\b]"#, 8)] {
            for c in 0...20 { XCTAssertEqual(matchesUnit(re, c), c == code, "\(re) at \(c)") }
        }
        XCTAssertNil(compiled(#"\b"#))
        XCTAssertNil(compiled(#"a\b"#))
        // \0 followed by a digit is an octal escape: refused; followed by a non-digit it is NUL
        for d in ["0", "1", "7", "9"] { XCTAssertNil(compiled("\\0" + d), "\\0\(d)") }
        XCTAssertEqual(m(#"\0:"#, "\u{0}:"), true)
        XCTAssertEqual(m(#"\0/"#, "\u{0}/"), true)
        XCTAssertEqual(m(#"\0a"#, "\u{0}a"), true)
    }

    func testHexEscapes() {
        for v in 0...255 {
            XCTAssertEqual(matchesUnit("\\x" + hex2(v, upper: true), v), true, "\\x\(hex2(v, upper: true))")
            XCTAssertEqual(matchesUnit("\\x" + hex2(v, upper: false), v), true, "\\x\(hex2(v, upper: false))")
            XCTAssertEqual(matchesUnit("\\x" + hex2(v, upper: true), v ^ 1), false)
        }
        XCTAssertEqual(m(#"\x41b"#, "Ab"), true)
        for bad in ["G", "g", "@", "`", "/", ":", "-", ""] {
            XCTAssertNil(compiled("\\x4" + bad), "\\x4\(bad)")
            XCTAssertNil(compiled("\\x" + bad + "4"), "\\x\(bad)4")
            XCTAssertNil(compiled("\\u004" + bad), "\\u004\(bad)")
            XCTAssertNil(compiled("\\u00" + bad + "4"), "\\u00\(bad)4")
        }
        XCTAssertNil(compiled(#"\x"#))
        XCTAssertNil(compiled(#"\u"#))
        XCTAssertNil(compiled(#"\u004"#))
    }

    func testUnicodeEscapes() {
        for v in [0x0041, 0x00e9, 0x0100, 0x1000, 0x1234, 0xabcd, 0xd800, 0xffff, 0x0001, 0x0f0f, 0x8000] {
            XCTAssertEqual(matchesUnit("\\u" + hex4(v, upper: true), v), true, "\\u\(hex4(v, upper: true))")
            XCTAssertEqual(matchesUnit("\\u" + hex4(v, upper: false), v), true, "\\u\(hex4(v, upper: false))")
            XCTAssertEqual(matchesUnit("\\u" + hex4(v, upper: true), v ^ 1), false)
            XCTAssertEqual(matchesUnit("[\\u" + hex4(v, upper: true) + "]", v), true)
        }
        XCTAssertEqual(m(#"\u0041b"#, "Ab"), true)
        XCTAssertEqual(m(#"\u00411"#, "A1"), true)
    }

    func testControlEscapes() {
        let upper = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), lower = Array("abcdefghijklmnopqrstuvwxyz")
        for k in 0..<26 {
            XCTAssertEqual(matchesUnit("\\c" + String(upper[k]), k + 1), true, "\\c\(upper[k])")
            XCTAssertEqual(matchesUnit("\\c" + String(lower[k]), k + 1), true, "\\c\(lower[k])")
            XCTAssertEqual(matchesUnit("\\c" + String(upper[k]), k + 2), false)
        }
        XCTAssertEqual(m(#"\cAb"#, "\u{1}b"), true)
        for bad in ["1", "@", "[", "`", "{", "-", "_", "0", "9", ""] { XCTAssertNil(compiled("\\c" + bad), "\\c\(bad)") }
    }

    func testIdentityEscapesAndRefusedLetters() {
        for bad in ["A", "Z", "a", "z", "e", "g", "B", "k", "y", "Q", "1", "2", "8", "9", "_", "c", "x", "u"] {
            // c / x / u are escapes with a payload: bare, they are refused too
            XCTAssertNil(compiled("\\" + bad), "\\\(bad)")
        }
        for ok in ["@", "[", "`", "{", "}", "/", ":", "-", ".", "*", "+", "?", "(", ")", "|", "^", "$", "\\", "]"] {
            XCTAssertEqual(m("\\" + ok, ok), true, "\\\(ok)")
            XCTAssertEqual(m("\\" + ok, "q"), false)
        }
        XCTAssertNil(compiled("\\"))
    }

    // ---- classes -----------------------------------------------------------------------------------------------------

    func testClasses() {
        XCTAssertEqual(m("[^a]", "b"), true)
        XCTAssertEqual(m("[^a]", "a"), false)
        XCTAssertEqual(m("[^a]", "^"), true)
        XCTAssertEqual(m("[ab]", "["), false)
        XCTAssertEqual(m("[ab]", "b"), true)
        XCTAssertEqual(m("[a-c]", "b"), true)
        XCTAssertEqual(m("[a-c]", "d"), false)
        XCTAssertEqual(m("[a-c]", "-"), false)
        XCTAssertEqual(m("[a-]", "a"), true)
        XCTAssertEqual(m("[a-]", "-"), true)
        XCTAssertEqual(m("[a-]", "b"), false)
        XCTAssertEqual(m("[-a]", "-"), true)
        XCTAssertEqual(m("[a-a]", "a"), true)
        XCTAssertNil(compiled("[b-a]"))
        XCTAssertEqual(m("[]", "a"), false)
        XCTAssertEqual(m("[^]", "a"), true)
        XCTAssertEqual(m("[^]", "\n"), true)
        XCTAssertEqual(m(#"[a\]b]"#, "]"), true)
        XCTAssertEqual(m(#"[a\]b]"#, "b"), true)
        XCTAssertNil(compiled("["))
        XCTAssertNil(compiled("[a"))
        XCTAssertNil(compiled("[a-"))
        XCTAssertNil(compiled(#"[\"#))
        // an escape endpoint makes the '-' a literal (Annex B)
        for (re, ins, outs) in [(#"[\d-x]"#, ["-", "5", "x"], ["y", "a"]), (#"[x-\d]"#, ["-", "5", "x"], ["y", "a"]),
                                (#"[\w-x]"#, ["-", "a", "x", "_"], ["!", " "]), (#"[\s-x]"#, ["-", " ", "x"], ["y", "5"]),
                                (#"[\D-x]"#, ["-", "a", "x"], ["5"]), (#"[\W-x]"#, ["-", "!", "x"], ["y", "5"]),
                                (#"[\S-x]"#, ["-", "y", "x"], [" "])] {
            XCTAssertNotNil(compiled(re), re)
            for c in ins { XCTAssertEqual(m(re, c), true, "\(re) \(c)") }
            for c in outs { XCTAssertEqual(m(re, c), false, "\(re) \(c)") }
        }
        // escape-coded endpoints form a real range
        XCTAssertEqual(m(#"[\x41-\x43]"#, "B"), true)
        XCTAssertEqual(m(#"[\x41-\x43]"#, "D"), false)
        XCTAssertEqual(m(#"[\x41-\x43]"#, "-"), false)
        XCTAssertEqual(m(#"[\u0041-\u0043]"#, "C"), true)
        XCTAssertEqual(m(#"[\n-\r]"#, "\u{0b}"), true)
        XCTAssertEqual(m(#"[\n-\r]"#, "\u{0e}"), false)
        XCTAssertEqual(m(#"[\cA-\cC]"#, "\u{2}"), true)
    }

    // ---- quantifiers, groups, alternation, anchors -------------------------------------------------------------------

    func testQuantifierSemantics() {
        let table: [(String, [(String, Bool)])] = [
            ("a*", [("", true), ("a", true), ("aaa", true), ("b", false)]),
            ("a+", [("", false), ("a", true), ("aaa", true)]),
            ("a?", [("", true), ("a", true), ("aa", false)]),
            ("a?b", [("b", true), ("ab", true), ("aab", false)]),
            ("a{2}", [("a", false), ("aa", true), ("aaa", false)]),
            ("a{2,3}", [("a", false), ("aa", true), ("aaa", true), ("aaaa", false)]),
            ("a{2,}", [("a", false), ("aa", true), ("aaaaa", true)]),
            ("a{1,2}", [("", false), ("a", true), ("aa", true), ("aaa", false)]),
            ("a{0,2}", [("", true), ("aa", true), ("aaa", false)]),
            ("a{0,3}", [("", true), ("aaa", true), ("aaaa", false)]),
            ("a{1,3}b", [("b", false), ("ab", true), ("aaab", true), ("aaaab", false)]),
            ("a{12}", [(rep("a", 11), false), (rep("a", 12), true), (rep("a", 13), false)]),
            ("a{12,34}", [(rep("a", 11), false), (rep("a", 12), true), (rep("a", 34), true), (rep("a", 35), false)]),
            ("a{0064}", [(rep("a", 63), false), (rep("a", 64), true), (rep("a", 65), false)]),
            ("a{1,0064}", [(rep("a", 64), true), (rep("a", 65), false)]),
            ("a+?", [("aaa", true), ("", false)]),
            ("a*?b", [("aab", true), ("b", true), ("a", false)]),
            ("a??b", [("b", true), ("ab", true)]),
            ("a{2}?b", [("aab", true), ("ab", false)]),
            ("(ab)+", [("ababab", true), ("aba", false), ("", false)]),
            ("(?:ab)", [("ab", true), ("a", false), (":ab", false)]),
            ("(ab)c", [("abc", true), ("ac", false)]),
            ("(?:ab)*c", [("c", true), ("ababc", true), ("abac", false)]),
            ("(a|b)*c", [("ababc", true), ("c", true), ("abd", false)]),
            ("(a*)*", [("aaa", true), ("", true), ("b", false)]),
            ("a*a*a*", [("aaaa", true), ("", true), ("b", false)]),
        ]
        for (re, cases) in table {
            XCTAssertNotNil(compiled(re), re)
            for (s, want) in cases { XCTAssertEqual(m(re, s), want, "\(re) ~ \(s.count > 20 ? "\(s.count) chars" : s)") }
        }
        for bad in ["a{65}", "a{0,65}", "a{65,}", "a{00064}", "a{1,00064}", "a{3,2}", "a{,2}", "a{", "a{2", "a{2,3", "a{x}", "a{1,x}", "*a", "+a", "?a", "{1}a",
                    "^*", "$+", "^{2}", "$?", "(?=a)", "(?!a)", "(?<n>a)", "(?", "(?:", "(a", "a)", ")", "(", "(?:a"] {
            XCTAssertNil(compiled(bad), bad)
        }
        XCTAssertEqual(m("", ""), true)
        XCTAssertEqual(m("", "a"), false)
    }

    func testAlternation() {
        for (re, cases) in [("a|b|c", [("a", true), ("b", true), ("c", true), ("", false), ("ab", false), ("d", false)]),
                            ("a|bc", [("a", true), ("bc", true), ("b", false), ("c", false), ("abc", false)]),
                            ("ab|cd", [("ab", true), ("cd", true), ("ac", false), ("", false)]),
                            ("|a", [("", true), ("a", true), ("b", false)]),
                            ("a|", [("", true), ("a", true), ("b", false)]),
                            ("(a|b)(c|d)", [("ac", true), ("bd", true), ("ad", true), ("a", false), ("cd", false)]),
                            ("a|b|c|d|e", [("e", true), ("d", true), ("f", false), ("", false)])] as [(String, [(String, Bool)])] {
            for (s, want) in cases { XCTAssertEqual(m(re, s), want, "\(re) ~ \(s)") }
        }
    }

    func testAnchors() {
        for (re, cases) in [("^a", [("a", true), ("ab", false), ("ba", false), ("", false)]),
                            ("a$", [("a", true), ("ab", false), ("ba", false)]),
                            ("^a$", [("a", true), ("aa", false), ("", false)]),
                            ("^ab$", [("ab", true), ("xab", false), ("abx", false)]),
                            ("^", [("", true), ("a", false)]),
                            ("$", [("", true), ("a", false)]),
                            ("^$", [("", true), ("a", false)]),
                            ("^^a", [("a", true)]),
                            ("a$$", [("a", true)]),
                            ("a^b", [("ab", false), ("a", false), ("", false)]),
                            ("a$b", [("ab", false), ("a", false), ("", false)]),
                            ("a|^b", [("a", true), ("b", true), ("ab", false)]),
                            ("x$|bc", [("x", true), ("bc", true), ("b", false)]),
                            ("(^a|b$)", [("a", true), ("b", true), ("ab", false)]),
                            ("^ab", [("ab", true), ("b", false)]),
                            ("a$|bc", [("a", true), ("bc", true)])] as [(String, [(String, Bool)])] {
            for (s, want) in cases { XCTAssertEqual(m(re, s), want, "\(re) ~ \(s)") }
        }
    }

    // ---- nesting and size limits -------------------------------------------------------------------------------------

    func testParseDepthLimit() {
        XCTAssertEqual(m(nest(256, "(", "a", ")"), "a"), true)
        XCTAssertNil(compiled(nest(257, "(", "a", ")")))
        XCTAssertNil(compiled(nest(300, "(", "a", ")")))
        // sequential groups return the depth counter to zero
        XCTAssertEqual(m(rep("(a)", 300), rep("a", 300)), true)
        XCTAssertNotNil(compiled(rep("(a)", 10) + nest(256, "(", "a", ")")))
        XCTAssertNil(compiled(rep("(a)", 10) + nest(257, "(", "a", ")")))
    }

    func testEmitDepthLimit() {
        // each quantified group level costs two emit levels: 255 levels reach depth 511, 256 reach 513 (limit 512)
        for q in [")*", ")?", "){1}"] {
            XCTAssertNotNil(compiled(nest(255, "(", "a", q)), "255 x \(q)")
            XCTAssertNil(compiled(nest(256, "(", "a", q)), "256 x \(q)")
        }
        // wrapping in one more plain group lands exactly on depth 512, which is still allowed
        XCTAssertNotNil(compiled("(" + nest(255, "(", "a", ")*") + ")"))
        // alternation: two emit levels per level, whichever branch carries the nesting
        let lastNest: (Int) -> String = { self.rep("(a|", $0) + "b" + self.rep(")", $0) }
        let firstNest: (Int) -> String = { self.rep("(", $0) + "a" + self.rep("|b)", $0) }
        XCTAssertNotNil(compiled(lastNest(255)))
        XCTAssertNil(compiled(lastNest(256)))
        XCTAssertNotNil(compiled(firstNest(255)))
        XCTAssertNil(compiled(firstNest(256)))
        XCTAssertEqual(m(lastNest(20), "b"), true)
        XCTAssertEqual(m(firstNest(20), "a"), true)
    }

    func testInstructionLimit() {
        // n literals = n instructions, plus the final match
        XCTAssertNotNil(compiled(rep("a", 4095)))
        XCTAssertNil(compiled(rep("a", 4096)))
        XCTAssertNil(compiled(rep("a", 5000)))
    }

    func testRunStepBudget() {
        let a = compiled("a")!   // 2 instructions
        let ab = compiled("ab")! // 3 instructions
        XCTAssertEqual(a.prog.count, 2)
        XCTAssertEqual(ab.prog.count, 3)
        XCTAssertEqual(SafeRegex.run(a, [UInt16](repeating: 0x78, count: 999_999)), false)   // 2 * 1,000,000 = the cap exactly
        XCTAssertNil(SafeRegex.run(a, [UInt16](repeating: 0x78, count: 1_000_000)))          // 2,000,002
        XCTAssertEqual(SafeRegex.run(ab, [UInt16](repeating: 0x78, count: 666_665)), false)  // 1,999,998
        XCTAssertNil(SafeRegex.run(ab, [UInt16](repeating: 0x78, count: 666_666)))           // 2,000,001
    }

    // ---- isSafeSource ------------------------------------------------------------------------------------------------

    func testSafeSourceStructure() {
        for ok in ["a", "a|b", "(?:a)", "(a)", "()", "(a{2})", "(a?)", "(a*?)", "\\(", "\\)", "\\d", "\\d*", "[a]", "[\\]]", "[^]]", "[\\]a]", "a{2}b",
                   "a{1,2}b{1,2}c{1,2}", "a?b?c?", "a*b*", "a*?", "a+?b", "a{0,2}", "(a|b)", "(a*)", "(a)*", "(a)+", "a{2}?", "a{64}", "a{2,64}", "(|)", "(a|)",
                   "a{2}a{2}a{2}a{2}"] {
            XCTAssertTrue(safe(ok), ok)
        }
        for bad in ["(a*)*", "(a|b)*", "((a*))*", "((a|b))*", "((a)*)*", "*a", "a**", "a{3,2}", "a{", "a{x}", "a{1", "a{1,", "a{1,2", "[", "[abc", "a\\",
                    "\\1", "\\9", "\\k", "(", ")", "(?", "(?=a)", "(?:", "(a", "a)", "a|b)", "(?<n>a)", "a{65}", "a{0,65}", "a{2,1}", "a{2,3}{2}", "(a)|*"] {
            XCTAssertFalse(safe(bad), bad)
        }
        XCTAssertFalse(safe("a{99999999999999999999}"))
        XCTAssertFalse(safe("a{18446744073709551621}"))
    }

    func testSafeSourceCostBudget() {
        let p = "|"
        XCTAssertTrue(safe(rep(p, 22)))
        XCTAssertFalse(safe(rep(p, 23)))
        // '?' costs 1 bit, {0,2} and {0,3} cost 2, {0,16} costs 5, an unbounded quantifier costs 8
        XCTAssertTrue(safe(rep(p, 21) + "a?"))
        XCTAssertFalse(safe(rep(p, 22) + "a?"))
        XCTAssertTrue(safe(rep(p, 20) + "a{0,2}"))
        XCTAssertFalse(safe(rep(p, 21) + "a{0,2}"))
        XCTAssertTrue(safe(rep(p, 20) + "a{0,3}"))
        XCTAssertFalse(safe(rep(p, 21) + "a{0,3}"))
        XCTAssertTrue(safe(rep(p, 19) + "a{0,4}"))     // {0,4}: 5 options -> 3 bits
        XCTAssertFalse(safe(rep(p, 20) + "a{0,4}"))
        XCTAssertTrue(safe(rep(p, 17) + "a{0,16}"))
        XCTAssertFalse(safe(rep(p, 18) + "a{0,16}"))
        XCTAssertTrue(safe(rep(p, 22) + "a{2}"))        // a single option costs nothing
        XCTAssertTrue(safe(rep(p, 22) + "a{1}"))
        XCTAssertTrue(safe(rep(p, 20) + "a{1,2}"))      // {1,2}: 2 options -> 1 bit
        XCTAssertFalse(safe(rep(p, 22) + "a{1,2}"))
        XCTAssertTrue(safe("a*b*" + rep(p, 6)))
        XCTAssertFalse(safe("a*b*" + rep(p, 7)))
        XCTAssertTrue(safe(rep(p, 6) + "a*b*"))         // exactly 22 reached by a quantifier
        XCTAssertFalse(safe(rep(p, 7) + "a*b*"))
        XCTAssertFalse(safe("a*b*c*"))
        XCTAssertTrue(safe("a?b?c?"))
        XCTAssertFalse(safe("a{2,}b{2,}c{2,}"))
        XCTAssertTrue(safe("a{2}b{2}c{2}d{2}"))
        XCTAssertTrue(safe("a{1,2}b{1,2}c{1,2}"))
        // a lazy marker after a {n} quantifier is skipped, not counted as one more quantifier
        XCTAssertTrue(safe("a*b*" + rep(p, 6) + "c{2}?"))
        XCTAssertFalse(safe("a*b*" + rep(p, 6) + "c??"))   // the '?' quantifier is the 23rd bit; its lazy marker is skipped
        // characters that follow an escape / class / group opener are skipped exactly: the next '|' still counts
        XCTAssertFalse(safe(rep(p, 22) + "\\d|"))
        XCTAssertFalse(safe(rep(p, 22) + "[a]|"))
        XCTAssertFalse(safe(rep(p, 22) + "(?:|)"))
        XCTAssertTrue(safe(rep(p, 22) + "[\\]|]"))
        XCTAssertTrue(safe(rep(p, 22) + "[|]"))
        XCTAssertTrue(safe(rep(p, 22) + "\\|"))
        XCTAssertFalse(safe(rep(p, 22) + "()|"))
        XCTAssertFalse(safe(rep(p, 22) + "(a)|"))
        XCTAssertFalse(safe(rep(p, 22) + "a{2}|"))
        XCTAssertFalse(safe(rep(p, 22) + "a?|"))
        XCTAssertFalse(safe(rep(p, 22) + "a|"))
    }

    // ---- the per-document budget -------------------------------------------------------------------------------------

    func testDocumentBudgetEdges() {
        // source characters: 8192 allowed, 8193 not
        XCTAssertTrue(SafeRegex.Budget().charge(srcUnits: 8192, progLen: 1, subjectUnits: 0))
        XCTAssertFalse(SafeRegex.Budget().charge(srcUnits: 8193, progLen: 1, subjectUnits: 0))
        let c = SafeRegex.Budget()
        XCTAssertTrue(c.charge(srcUnits: 4096, progLen: 1, subjectUnits: 0))
        XCTAssertTrue(c.charge(srcUnits: 4096, progLen: 1, subjectUnits: 0))
        XCTAssertEqual(c.chars, 8192)
        XCTAssertFalse(c.charge(srcUnits: 1, progLen: 1, subjectUnits: 0))
        XCTAssertFalse(c.charge(srcUnits: 0, progLen: 1, subjectUnits: 0), "poisoned")
        // steps: 5,000,000 allowed, 5,000,001 not
        XCTAssertTrue(SafeRegex.Budget().charge(srcUnits: 1, progLen: 5_000_000, subjectUnits: 0))
        XCTAssertFalse(SafeRegex.Budget().charge(srcUnits: 1, progLen: 5_000_001, subjectUnits: 0))
        XCTAssertTrue(SafeRegex.Budget().charge(srcUnits: 1, progLen: 2_500_000, subjectUnits: 1))
        XCTAssertFalse(SafeRegex.Budget().charge(srcUnits: 1, progLen: 2_500_001, subjectUnits: 1))
        XCTAssertFalse(SafeRegex.Budget().charge(srcUnits: 1, progLen: 1, subjectUnits: 5_000_000))
        XCTAssertTrue(SafeRegex.Budget().charge(srcUnits: 1, progLen: 1, subjectUnits: 4_999_999))
        XCTAssertFalse(SafeRegex.Budget().charge(srcUnits: 1, progLen: 5_000_000, subjectUnits: 1))
        let s = SafeRegex.Budget()
        XCTAssertTrue(s.charge(srcUnits: 1, progLen: 2_500_000, subjectUnits: 0))
        XCTAssertTrue(s.charge(srcUnits: 1, progLen: 2_500_000, subjectUnits: 0))
        XCTAssertEqual(s.steps, 5_000_000)
        XCTAssertEqual(s.chars, 2)
        XCTAssertEqual(s.evaluations, 2)
        XCTAssertFalse(s.charge(srcUnits: 1, progLen: 1, subjectUnits: 0))
        XCTAssertFalse(s.charge(srcUnits: 1, progLen: 1, subjectUnits: 0), "poisoned")
        // evaluations: 64 allowed, the 65th refused, and the scope is then poisoned
        let e = SafeRegex.Budget()
        for _ in 0..<64 { XCTAssertTrue(e.charge(srcUnits: 1, progLen: 1, subjectUnits: 0)) }
        XCTAssertEqual(e.evaluations, 64)
        XCTAssertFalse(e.charge(srcUnits: 1, progLen: 1, subjectUnits: 0))
        XCTAssertFalse(e.charge(srcUnits: 0, progLen: 0, subjectUnits: 0))
        XCTAssertEqual(SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT, 64)
        XCTAssertEqual(SafeRegex.MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT, 8192)
        XCTAssertEqual(SafeRegex.MAX_REGEX_STEPS_PER_DOCUMENT, 5_000_000)
        // the counters accumulate source units and progLen * (subject + 1)
        let f = SafeRegex.Budget()
        XCTAssertTrue(f.charge(srcUnits: 3, progLen: 2, subjectUnits: 4))
        XCTAssertEqual(f.chars, 3)
        XCTAssertEqual(f.steps, 10)
    }

    func testConstantsArePinned() {
        XCTAssertEqual(SafeRegex.MAX_NFA_INSTRUCTIONS, 4096)
        XCTAssertEqual(SafeRegex.MAX_REPEAT, 64)
        XCTAssertEqual(SafeRegex.MAX_MATCH_STEPS, 2_000_000)
        XCTAssertEqual(SafeRegex.MAX_PARSE_DEPTH, 256)
        XCTAssertEqual(SafeRegex.MAX_BOUNDED_REPEAT, 64)
        XCTAssertEqual(SafeRegex.MAX_REGEX_COST_BITS, 22)
        XCTAssertEqual(SafeRegex.UNBOUNDED_QUANTIFIER_BITS, 8)
    }
}
