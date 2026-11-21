import Foundation

/// JavaScript text semantics for the interpreter's scanners, over UTF-16 code units: the regular expressions of the reference
/// (`\d` `\s` `\b` and the `i` flag are ASCII or the fixed JavaScript sets; lookbehind / lookahead; greedy backtracking) are
/// spelled out as scanners so no platform regex dialect decides what a candidate is. `toLowerCase` follows the ECMAScript full
/// case mapping including the final-sigma rule.
enum GoalInterpretText {
    typealias U = [UInt16]

    static func u(_ s: String) -> U { Array(s.utf16) }

    /// A UTF-16 slice back to a String (a lone surrogate, which a Swift String cannot hold, becomes U+FFFD).
    static func str<C: Collection>(_ x: C) -> String where C.Element == UInt16 { String(decoding: x, as: UTF16.self) }

    /// JavaScript `\s`.
    static func isWS(_ c: UInt16) -> Bool {
        switch c {
        case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF: return true
        default: return c >= 0x2000 && c <= 0x200A
        }
    }

    static func isDigit(_ c: UInt16) -> Bool { c >= 0x30 && c <= 0x39 }
    static func isAlpha(_ c: UInt16) -> Bool { (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) }
    static func isLowerAlpha(_ c: UInt16) -> Bool { c >= 0x61 && c <= 0x7A }
    /// JavaScript `\w` (ASCII, also under the `i` flag without `u`).
    static func isWord(_ c: UInt16) -> Bool { isDigit(c) || isAlpha(c) || c == 0x5F }
    /// `[A-Za-z0-9_-]`
    static func isIdChar(_ c: UInt16) -> Bool { isWord(c) || c == 0x2D }
    /// `[a-z0-9_]`
    static func isLowerWord(_ c: UInt16) -> Bool { isDigit(c) || isLowerAlpha(c) || c == 0x5F }

    static func fold(_ c: UInt16) -> UInt16 { (c >= 0x41 && c <= 0x5A) ? c + 32 : c }

    /// `\b` at position i (between i-1 and i).
    static func boundary(_ t: U, _ i: Int) -> Bool {
        let a = i > 0 && i - 1 < t.count && isWord(t[i - 1])
        let b = i >= 0 && i < t.count && isWord(t[i])
        return a != b
    }

    /// Case-insensitive (ASCII) match of the lowercase ASCII literal `lit` at i.
    static func startsCI(_ t: U, _ i: Int, _ lit: String) -> Bool {
        let l = Array(lit.utf16)
        if i < 0 || i + l.count > t.count { return false }
        var k = 0
        while k < l.count {
            if fold(t[i + k]) != l[k] { return false }
            k += 1
        }
        return true
    }

    /// Exact match of `p` at i.
    static func matches(_ t: U, _ i: Int, _ p: U) -> Bool {
        if i < 0 || i + p.count > t.count { return false }
        var k = 0
        while k < p.count {
            if t[i + k] != p[k] { return false }
            k += 1
        }
        return true
    }

    /// `hay.includes(needle)` over code units.
    static func includes(_ hay: U, _ needle: U) -> Bool {
        if needle.isEmpty { return true }
        if needle.count > hay.count { return false }
        var i = 0
        while i + needle.count <= hay.count {
            if matches(hay, i, needle) { return true }
            i += 1
        }
        return false
    }

    /// `s.slice(a, b)` for a, b >= 0 (clamped, empty when a >= b).
    static func slice(_ t: U, _ a0: Int, _ b0: Int) -> U {
        let a = max(0, min(a0, t.count))
        let b = max(0, min(b0, t.count))
        return a >= b ? [] : Array(t[a..<b])
    }

    /// `String.prototype.toLowerCase`: the full Unicode lower-case mapping per scalar, with the Final_Sigma context rule.
    static func lower(_ s: String) -> String {
        var ascii = true
        for b in s.utf8 where b >= 0x80 { ascii = false; break }
        if ascii { return s.lowercased() }
        let sc: [Unicode.Scalar] = Array(s.unicodeScalars)
        var out = String.UnicodeScalarView()
        var i = 0
        while i < sc.count {
            let c = sc[i]
            if c.value == 0x3A3 {
                var before = false
                var j = i - 1
                while j >= 0 {
                    let p = sc[j].properties
                    if p.isCaseIgnorable { j -= 1; continue }
                    before = p.isCased
                    break
                }
                var after = false
                var k = i + 1
                while k < sc.count {
                    let p = sc[k].properties
                    if p.isCaseIgnorable { k += 1; continue }
                    after = p.isCased
                    break
                }
                let sigma: UInt32 = (before && !after) ? 0x3C2 : 0x3C3
                out.append(Unicode.Scalar(sigma)!)
            } else {
                out.append(contentsOf: c.properties.lowercaseMapping.unicodeScalars)
            }
            i += 1
        }
        return String(out)
    }

    /// Distinct strings by code-unit equality, first occurrence order (`[...new Set(xs)]`).
    static func distinct(_ xs: [String]) -> [String] {
        var seen = Set<[UInt16]>()
        var out: [String] = []
        for x in xs {
            if seen.insert(u(x)).inserted { out.append(x) }
        }
        return out
    }

    static func same(_ a: String, _ b: String) -> Bool { a.unicodeScalars.elementsEqual(b.unicodeScalars) }

    // ---------------- id candidates ----------------

    /// `matchAll(/(?<![A-Za-z0-9_-])PREFIX[A-Za-z0-9_-]+/g)`: the matched texts in order.
    static func idMatches(_ t: U, _ prefix: U) -> [String] {
        var out: [String] = []
        var i = 0
        while i + prefix.count < t.count {
            if (i == 0 || !isIdChar(t[i - 1])) && matches(t, i, prefix) {
                var j = i + prefix.count
                while j < t.count && isIdChar(t[j]) { j += 1 }
                if j > i + prefix.count {
                    out.append(str(t[i..<j]))
                    i = j
                    continue
                }
            }
            i += 1
        }
        return out
    }

    // ---------------- amount candidates ----------------

    struct AmountMatch {
        let start: Int
        let end: Int
        let g1: (Int, Int)?
        let g2: (Int, Int)
        let g3: (Int, Int)?
    }

    private static func isSymbol(_ c: UInt16) -> Bool { c == 0x24 || c == 0x20AC || c == 0xA3 || c == 0xA5 }

    /// `\b(?:USD|EUR|GBP|JPY)\b` (case-insensitive) starting at p.
    private static func curWord(_ t: U, _ p: Int) -> Bool {
        if !boundary(t, p) { return false }
        let hit = startsCI(t, p, "usd") || startsCI(t, p, "eur") || startsCI(t, p, "gbp") || startsCI(t, p, "jpy")
        return hit && boundary(t, p + 3)
    }

    /// Group 3 of the amount pattern at p: `dollars?|euros?|pounds|yen|\bCUR\b`; the end position or nil.
    private static func group3End(_ t: U, _ p: Int) -> Int? {
        if startsCI(t, p, "dollar") { return (p + 6 < t.count && fold(t[p + 6]) == 0x73) ? p + 7 : p + 6 }
        if startsCI(t, p, "euro") { return (p + 4 < t.count && fold(t[p + 4]) == 0x73) ? p + 5 : p + 4 }
        if startsCI(t, p, "pounds") { return p + 6 }
        if startsCI(t, p, "yen") { return p + 3 }
        if curWord(t, p) { return p + 3 }
        return nil
    }

    /// The reference's amount pattern anchored at s, with its backtracking order.
    private static func amountAt(_ t: U, _ s: Int) -> AmountMatch? {
        var starts: [(Int, (Int, Int)?)] = []
        if s < t.count && isSymbol(t[s]) { starts.append((s + 1, (s, s + 1))) }
        else if curWord(t, s) { starts.append((s + 3, (s, s + 3))) }
        starts.append((s, nil))
        for (p, g1) in starts {
            var cands: [Int] = []
            if p < t.count && isWS(t[p]) { cands.append(p + 1) }
            cands.append(p)
            for q in cands {
                if q >= t.count || !isDigit(t[q]) { continue }
                var k = q
                var last = -1
                while k < t.count && (isDigit(t[k]) || t[k] == 0x2E || t[k] == 0x2C) {
                    if k > q && isDigit(t[k]) { last = k }
                    k += 1
                }
                let numEnd = last >= 0 ? last + 1 : q + 1
                var end = numEnd
                var gp = numEnd
                if end < t.count && isWS(t[end]) { gp = end + 1; end = end + 1 }
                var g3: (Int, Int)? = nil
                if let e3 = group3End(t, gp) { g3 = (gp, e3); end = e3 }
                return AmountMatch(start: s, end: end, g1: g1, g2: (q, numEnd), g3: g3)
            }
        }
        return nil
    }

    /// `matchAll(amt)` with the reference's pattern (see `extractCandidates`).
    static func amountMatches(_ t: U) -> [AmountMatch] {
        var out: [AmountMatch] = []
        var i = 0
        while i < t.count {
            var found: AmountMatch? = nil
            var s = i
            while s < t.count {
                if let m = amountAt(t, s) { found = m; break }
                s += 1
            }
            guard let m = found else { break }
            out.append(m)
            i = m.end > m.start ? m.end : m.start + 1
        }
        return out
    }

    // ---------------- count candidates ----------------

    struct CountMatch {
        let start: Int
        let end: Int
    }

    private static func currencyWordAhead(_ t: U, _ p: Int) -> Bool {
        return startsCI(t, p, "dollar") || startsCI(t, p, "euro") || startsCI(t, p, "pounds") || startsCI(t, p, "yen")
            || startsCI(t, p, "usd") || startsCI(t, p, "eur") || startsCI(t, p, "gbp") || startsCI(t, p, "jpy")
    }

    /// `\b(once|twice|one time|\d{1,6})\b(?!\s?[.,]\d)(?!\s?(?:dollars?|euros?|pounds|yen|usd|eur|gbp|jpy))` anchored at s.
    private static func countAt(_ t: U, _ s: Int) -> CountMatch? {
        if !boundary(t, s) { return nil }
        var ends: [Int] = []
        if startsCI(t, s, "once") { ends.append(s + 4) }
        if startsCI(t, s, "twice") { ends.append(s + 5) }
        if startsCI(t, s, "one time") { ends.append(s + 8) }
        var k = s
        while k < t.count && isDigit(t[k]) && k - s < 6 { k += 1 }
        var e = k
        while e > s { ends.append(e); e -= 1 }
        for end in ends {
            if !boundary(t, end) { continue }
            var p = end
            if p < t.count && isWS(t[p]) { p += 1 }
            if p + 1 < t.count && (t[p] == 0x2E || t[p] == 0x2C) && isDigit(t[p + 1]) { continue }
            if currencyWordAhead(t, p) { continue }
            return CountMatch(start: s, end: end)
        }
        return nil
    }

    static func countMatches(_ t: U) -> [CountMatch] {
        var out: [CountMatch] = []
        var i = 0
        while i < t.count {
            var found: CountMatch? = nil
            var s = i
            while s < t.count {
                if let m = countAt(t, s) { found = m; break }
                s += 1
            }
            guard let m = found else { break }
            out.append(m)
            i = m.end > m.start ? m.end : m.start + 1
        }
        return out
    }

    // ---------------- domain candidates ----------------

    private static func isDomainChar(_ c: UInt16) -> Bool { isLowerAlpha(c) || isDigit(c) || c == 0x2D }

    /// `matchAll(/(?<![A-Za-z0-9.-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?![A-Za-z0-9-])/g)`: the matched texts.
    static func domainMatches(_ t: U) -> [String] {
        var out: [String] = []
        var i = 0
        while i < t.count {
            var matched = -1
            let prev: UInt16 = i == 0 ? 0 : t[i - 1]
            let blocked: Bool = i > 0 && ((isIdChar(prev) && prev != 0x5F) || prev == 0x2E)
            if !blocked {
                // the segments `[a-z0-9-]+\.` as far as they go
                var ends: [Int] = []
                var p = i
                while true {
                    var j = p
                    while j < t.count && isDomainChar(t[j]) { j += 1 }
                    if j > p && j < t.count && t[j] == 0x2E { ends.append(j + 1); p = j + 1 } else { break }
                }
                var n = ends.count
                while n >= 1 {
                    let q = ends[n - 1]
                    var r = q
                    while r < t.count && isLowerAlpha(t[r]) { r += 1 }
                    if r - q >= 2 && (r == t.count || !(isAlpha(t[r]) || isDigit(t[r]) || t[r] == 0x2D)) {
                        matched = r
                        break
                    }
                    n -= 1
                }
            }
            if matched >= 0 {
                out.append(str(t[i..<matched]))
                i = matched
            } else {
                i += 1
            }
        }
        return out
    }
}
