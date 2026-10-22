import Foundation

/// The linear-time, budgeted matcher for `re:` resource patterns and the `matches` condition, a line-by-line port of
/// `packages/pca/src/safe-regex.ts` (parser, Thompson NFA, Pike simulation) and of `isSafeRegexSource` /
/// `chargeRegex` in `predicates.ts` / `regex-budget.ts`, so the predicate evaluator of the `layers` check (Intent Layer
/// v2) evaluates the SAME patterns with the SAME semantics as the reference: a flagless JavaScript `RegExp` subset over
/// UTF-16 code units (`.` excludes `\n \r U+2028 U+2029`; `\d \w \s` are the JavaScript sets; no `\b`, no backreferences,
/// no lookaround), at most 4096 NFA instructions, `{n,m}` bounds <= 64, and a refusal when
/// `instructions x (subject length + 1)` exceeds 2,000,000. Groups nest at most 256 deep (fail closed beyond).
enum SafeRegex {
    static let MAX_NFA_INSTRUCTIONS = 4096
    static let MAX_REPEAT: UInt64 = 64
    static let MAX_MATCH_STEPS = 2_000_000
    static let MAX_PARSE_DEPTH = 256
    static let MAX_BOUNDED_REPEAT: UInt64 = 64
    static let MAX_REGEX_COST_BITS = 22
    static let UNBOUNDED_QUANTIFIER_BITS = 8

    typealias Ranges = [(UInt32, UInt32)]

    static let DIGIT: Ranges = [(0x30, 0x39)]
    static let WORD: Ranges = [(0x30, 0x39), (0x41, 0x5a), (0x5f, 0x5f), (0x61, 0x7a)]
    static let SPACE: Ranges = [
        (0x09, 0x0d), (0x20, 0x20), (0xa0, 0xa0), (0x1680, 0x1680), (0x2000, 0x200a), (0x2028, 0x2029), (0x202f, 0x202f),
        (0x205f, 0x205f), (0x3000, 0x3000), (0xfeff, 0xfeff),
    ]
    static let LINE_TERMINATORS: Ranges = [(0x0a, 0x0a), (0x0d, 0x0d), (0x2028, 0x2029)]

    struct CharSet {
        var ranges: Ranges
        var negated: Bool
        static func single(_ c: UInt32) -> CharSet { CharSet(ranges: [(c, c)], negated: false) }
        func has(_ c: UInt32) -> Bool {
            var inside = false
            var lo = 0, hi = ranges.count - 1
            while lo <= hi {
                let mid = (lo + hi) >> 1
                let r = ranges[mid]
                if c < r.0 { hi = mid - 1 } else if c > r.1 { lo = mid + 1 } else { inside = true; break }
            }
            return inside != negated
        }
    }

    static func normalize(_ r: Ranges) -> Ranges {
        let s = r.sorted { $0.0 < $1.0 }
        var out: Ranges = []
        for x in s {
            if let last = out.last, x.0 <= last.1 + 1 { out[out.count - 1].1 = max(last.1, x.1) } else { out.append(x) }
        }
        return out
    }

    static func complement(_ r: Ranges) -> Ranges {
        var out: Ranges = []
        var next: UInt32 = 0
        for (a, b) in normalize(r) {
            if a > next { out.append((next, a - 1)) }
            next = b + 1
        }
        if next <= 0xffff { out.append((next, 0xffff)) }
        return out
    }

    indirect enum Node {
        case set(CharSet)
        case bol, eol
        case cat([Node])
        case alt([Node])
        case rep(Node, min: UInt64, max: UInt64?)
    }

    struct Refuse: Error {}

    static func isDigit(_ c: UInt16) -> Bool { c >= 0x30 && c <= 0x39 }
    static func isHex(_ c: UInt16) -> Bool { isDigit(c) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66) }
    static func isAsciiAlnum(_ c: UInt16) -> Bool { isDigit(c) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) }
    static func hexval(_ c: UInt16) -> UInt32 {
        if isDigit(c) { return UInt32(c - 0x30) }
        if c >= 0x41 && c <= 0x46 { return UInt32(c - 0x41 + 10) }
        return UInt32(c - 0x61 + 10)
    }

    struct Parser {
        let s: [UInt16]
        var i = 0
        var depth = 0

        func at(_ k: Int) -> UInt16? { k < s.count ? s[k] : nil }

        mutating func parse() throws -> Node {
            let n = try alt()
            if i < s.count { throw Refuse() } // unbalanced )
            return n
        }

        mutating func alt() throws -> Node {
            var items = [try cat()]
            while at(i) == 0x7c {
                i += 1
                items.append(try cat())
            }
            return items.count == 1 ? items[0] : .alt(items)
        }

        mutating func cat() throws -> Node {
            var items: [Node] = []
            while let c = at(i), c != 0x7c, c != 0x29 { items.append(try quantified()) }
            return .cat(items)
        }

        /// `{n}` `{n,}` `{n,m}` (1..4 digits each) at `i`: (min, max, length); nil when not well formed.
        func braceQuantifier() -> (UInt64, UInt64?, Int)? {
            var k = i + 1
            let d0 = k
            while k < s.count && k - d0 < 4 && isDigit(s[k]) { k += 1 }
            if k == d0 { return nil }
            func num(_ a: Int, _ b: Int) -> UInt64 { s[a..<b].reduce(0) { $0 * 10 + UInt64($1 - 0x30) } }
            let mn = num(d0, k)
            var mx: UInt64?
            if at(k) == 0x2c {
                k += 1
                let m0 = k
                while k < s.count && k - m0 < 4 && isDigit(s[k]) { k += 1 }
                mx = k == m0 ? nil : num(m0, k)
            } else {
                mx = mn
            }
            if at(k) != 0x7d { return nil }
            return (mn, mx, k + 1 - i)
        }

        mutating func quantified() throws -> Node {
            let atom = try self.atom()
            let mn: UInt64
            let mx: UInt64?
            switch at(i) {
            case 0x2a?: mn = 0; mx = nil; i += 1
            case 0x2b?: mn = 1; mx = nil; i += 1
            case 0x3f?: mn = 0; mx = 1; i += 1
            case 0x7b?:
                guard let (lo, hi, len) = braceQuantifier() else { throw Refuse() }
                if let h = hi, h < lo { throw Refuse() }
                mn = lo; mx = hi; i += len
            default:
                return atom
            }
            switch atom { case .bol, .eol: throw Refuse(); default: break }
            if let m = mx, m > MAX_REPEAT { throw Refuse() }
            if mn > MAX_REPEAT { throw Refuse() }
            if at(i) == 0x3f { i += 1 } // lazy: irrelevant to a full-match boolean
            return .rep(atom, min: mn, max: mx)
        }

        mutating func atom() throws -> Node {
            guard let c = at(i) else { throw Refuse() }
            switch c {
            case 0x28:
                i += 1
                if at(i) == 0x3f {
                    if at(i + 1) != 0x3a { throw Refuse() }
                    i += 2
                }
                depth += 1
                if depth > MAX_PARSE_DEPTH { throw Refuse() }
                let n = try alt()
                depth -= 1
                if at(i) != 0x29 { throw Refuse() }
                i += 1
                return n
            case 0x5b: return try cls()
            case 0x2e: i += 1; return .set(CharSet(ranges: LINE_TERMINATORS, negated: true))
            case 0x5e: i += 1; return .bol
            case 0x24: i += 1; return .eol
            case 0x5c: return .set(try escapeInner(inClass: false).0)
            case 0x2a, 0x2b, 0x3f, 0x7b: throw Refuse()
            default: i += 1; return .set(.single(UInt32(c)))
            }
        }

        /// After `\`: (set, is a class escape, single code).
        mutating func escapeInner(inClass: Bool) throws -> (CharSet, Bool, UInt32?) {
            i += 1
            guard let c = at(i) else { throw Refuse() }
            i += 1
            func single(_ code: UInt32) -> (CharSet, Bool, UInt32?) { (.single(code), false, code) }
            switch c {
            case 0x64: return (CharSet(ranges: DIGIT, negated: false), true, nil)
            case 0x44: return (CharSet(ranges: DIGIT, negated: true), true, nil)
            case 0x77: return (CharSet(ranges: WORD, negated: false), true, nil)
            case 0x57: return (CharSet(ranges: WORD, negated: true), true, nil)
            case 0x73: return (CharSet(ranges: SPACE, negated: false), true, nil)
            case 0x53: return (CharSet(ranges: SPACE, negated: true), true, nil)
            case 0x74: return single(9)
            case 0x6e: return single(10)
            case 0x76: return single(11)
            case 0x66: return single(12)
            case 0x72: return single(13)
            case 0x30:
                if let d = at(i), isDigit(d) { throw Refuse() } // octal escape
                return single(0)
            case 0x78:
                if let a = at(i), let b = at(i + 1), isHex(a), isHex(b) {
                    i += 2
                    return single(hexval(a) * 16 + hexval(b))
                }
                throw Refuse()
            case 0x75:
                var v: UInt32 = 0
                for k in 0..<4 {
                    guard let h = at(i + k), isHex(h) else { throw Refuse() }
                    v = v * 16 + hexval(h)
                }
                i += 4
                return single(v)
            case 0x63:
                if let l = at(i), (l >= 0x41 && l <= 0x5a) || (l >= 0x61 && l <= 0x7a) {
                    i += 1
                    return single(UInt32(l) % 32)
                }
                throw Refuse()
            case 0x62:
                if inClass { return single(8) }
                throw Refuse()
            default:
                if isAsciiAlnum(c) || c == 0x5f { throw Refuse() }
                return single(UInt32(c))
            }
        }

        mutating func readClassAtom() throws -> (Ranges, UInt32?, Bool) {
            guard let c = at(i) else { throw Refuse() }
            if c == 0x5c {
                let (set, isCls, ch) = try escapeInner(inClass: true)
                return (set.negated ? complement(set.ranges) : set.ranges, ch, isCls)
            }
            i += 1
            return ([(UInt32(c), UInt32(c))], UInt32(c), false)
        }

        mutating func cls() throws -> Node {
            i += 1
            var negated = false
            if at(i) == 0x5e { negated = true; i += 1 }
            var ranges: Ranges = []
            while true {
                guard let c = at(i) else { throw Refuse() }
                if c == 0x5d { i += 1; break }
                let a = try readClassAtom()
                let dash = at(i) == 0x2d
                let after = at(i + 1)
                if dash, let af = after, af != 0x5d {
                    i += 1
                    let b = try readClassAtom()
                    if a.2 || b.2 {
                        // Annex B: a class escape as a range endpoint makes the '-' a literal
                        ranges += a.0
                        ranges.append((0x2d, 0x2d))
                        ranges += b.0
                    } else {
                        guard let x = a.1, let y = b.1 else { throw Refuse() }
                        if x > y { throw Refuse() }
                        ranges.append((x, y))
                    }
                } else {
                    ranges += a.0
                }
            }
            return .set(CharSet(ranges: normalize(ranges), negated: negated))
        }
    }

    enum Inst {
        case set(CharSet)
        case split(Int, Int)
        case jmp(Int)
        case bol, eol, match
    }

    static func emit(_ node: Node, _ prog: inout [Inst], _ depth: Int) throws {
        if prog.count > MAX_NFA_INSTRUCTIONS || depth > MAX_PARSE_DEPTH * 2 { throw Refuse() }
        switch node {
        case let .set(s): prog.append(.set(s))
        case .bol: prog.append(.bol)
        case .eol: prog.append(.eol)
        case let .cat(items):
            for it in items { try emit(it, &prog, depth + 1) }
        case let .alt(items):
            var jmps: [Int] = []
            for (k, it) in items.enumerated() {
                if k < items.count - 1 {
                    let split = prog.count
                    prog.append(.split(split + 1, Int.max))
                    try emit(it, &prog, depth + 1)
                    jmps.append(prog.count)
                    prog.append(.jmp(Int.max))
                    prog[split] = .split(split + 1, prog.count)
                } else {
                    try emit(it, &prog, depth + 1)
                }
            }
            let end = prog.count
            for j in jmps { prog[j] = .jmp(end) }
        case let .rep(n, mn, mx):
            var k: UInt64 = 0
            while k < mn { try emit(n, &prog, depth + 1); k += 1 }
            if let m = mx {
                var splits: [Int] = []
                var r = mn
                while r < m {
                    let at = prog.count
                    splits.append(at)
                    prog.append(.split(at + 1, Int.max))
                    try emit(n, &prog, depth + 1)
                    r += 1
                }
                let end = prog.count
                for sp in splits { prog[sp] = .split(sp + 1, end) }
            } else {
                let split = prog.count
                prog.append(.split(split + 1, Int.max))
                try emit(n, &prog, depth + 1)
                prog.append(.jmp(split))
                prog[split] = .split(split + 1, prog.count)
            }
            if prog.count > MAX_NFA_INSTRUCTIONS { throw Refuse() }
        }
    }

    struct Compiled { let prog: [Inst] }

    /// `compileSafeRegex`: the NFA, or nil when the source is outside the subset or too large.
    static func compile(_ src: [UInt16]) -> Compiled? {
        var p = Parser(s: src)
        guard let ast = try? p.parse() else { return nil }
        var prog: [Inst] = []
        do { try emit(ast, &prog, 0) } catch { return nil }
        prog.append(.match)
        if prog.count > MAX_NFA_INSTRUCTIONS { return nil }
        return Compiled(prog: prog)
    }

    /// `runSafeRegex`: full match; nil when the work budget would be exceeded.
    static func run(_ re: Compiled, _ subject: [UInt16]) -> Bool? {
        let prog = re.prog
        let n = subject.count
        let (steps, over) = prog.count.multipliedReportingOverflow(by: n + 1)
        if over || steps > MAX_MATCH_STEPS { return nil }
        var mark = [Int](repeating: -1, count: prog.count)
        var epoch = 0
        var matched = false
        var stack: [Int] = []
        func add(_ list: inout [Int], _ pc0: Int, _ pos: Int) {
            stack.removeAll(keepingCapacity: true)
            stack.append(pc0)
            while let pc = stack.popLast() {
                if mark[pc] == epoch { continue }
                mark[pc] = epoch
                switch prog[pc] {
                case let .jmp(x): stack.append(x)
                case let .split(x, y): stack.append(y); stack.append(x)
                case .bol: if pos == 0 { stack.append(pc + 1) }
                case .eol: if pos == n { stack.append(pc + 1) }
                case .match: if pos == n { matched = true }
                case .set: list.append(pc)
                }
            }
        }
        var clist: [Int] = []
        var nlist: [Int] = []
        epoch += 1
        add(&clist, 0, 0)
        for pos in 0..<n {
            let c = UInt32(subject[pos])
            epoch += 1
            nlist.removeAll(keepingCapacity: true)
            for pc in clist {
                if case let .set(set) = prog[pc], set.has(c) { add(&nlist, pc + 1, pos + 1) }
            }
            swap(&clist, &nlist)
            if clist.isEmpty && !matched { return false }
        }
        return matched
    }

    /// `isSafeRegexSource` (predicates.ts): the structural guard (no backreferences, no lookaround, no quantified group
    /// holding a quantifier or an alternation, bounded repeats <= 64, a 22-bit backtracking-cost budget), and the source
    /// must ALSO compile.
    static func isSafeSource(_ src: [UInt16]) -> Bool {
        struct Frame { var hasQuant = false; var hasAlt = false }
        enum Prev { case none, atom, group(Frame) }
        var stack = [Frame()]
        var prev = Prev.none
        var bits = 0
        var i = 0
        let len = src.count
        while i < len {
            let ch = src[i]
            if ch == 0x5c {
                guard i + 1 < len else { return false }
                let n = src[i + 1]
                if (n >= 0x31 && n <= 0x39) || n == 0x6b { return false } // backreference
                i += 2
                prev = .atom
                continue
            }
            if ch == 0x5b {
                var j = i + 1
                if j < len && src[j] == 0x5e { j += 1 }
                while j < len && src[j] != 0x5d {
                    if src[j] == 0x5c { j += 1 }
                    j += 1
                }
                if j >= len { return false }
                i = j + 1
                prev = .atom
                continue
            }
            if ch == 0x28 {
                if i + 1 < len && src[i + 1] == 0x3f {
                    if !(i + 2 < len && src[i + 2] == 0x3a) { return false }
                    i += 3
                } else {
                    i += 1
                }
                stack.append(Frame())
                prev = .none
                continue
            }
            if ch == 0x29 {
                if stack.count < 2 { return false }
                let f = stack.removeLast()
                stack[stack.count - 1].hasQuant = stack[stack.count - 1].hasQuant || f.hasQuant
                stack[stack.count - 1].hasAlt = stack[stack.count - 1].hasAlt || f.hasAlt
                prev = .group(f)
                i += 1
                continue
            }
            if ch == 0x7c {
                bits += 1
                if bits > MAX_REGEX_COST_BITS { return false }
                stack[stack.count - 1].hasAlt = true
                prev = .none
                i += 1
                continue
            }
            // quantifier: (length, unbounded, max (nil = Infinity), options (nil = Infinity))
            var q: (Int, Bool, UInt64?, UInt64?)?
            if ch == 0x2a || ch == 0x2b {
                q = (1, true, nil, nil)
            } else if ch == 0x3f {
                q = (1, false, 1, 2)
            } else if ch == 0x7b {
                // /^\{(\d+)(?:(,)(\d*))?\}/ over the whole remaining source (saturating: a huge bound is just "too big")
                func sat(_ a: Int, _ b: Int) -> UInt64 {
                    src[a..<b].reduce(UInt64(0)) { acc, c in
                        let (m, o1) = acc.multipliedReportingOverflow(by: 10)
                        let (s, o2) = m.addingReportingOverflow(UInt64(c - 0x30))
                        return (o1 || o2) ? UInt64.max : s
                    }
                }
                var k = i + 1
                let d0 = k
                while k < len && isDigit(src[k]) { k += 1 }
                if k == d0 { return false }
                let lo = sat(d0, k)
                var hi: UInt64?
                if k < len && src[k] == 0x2c {
                    k += 1
                    let m0 = k
                    while k < len && isDigit(src[k]) { k += 1 }
                    hi = k == m0 ? nil : sat(m0, k)
                } else {
                    hi = lo
                }
                if !(k < len && src[k] == 0x7d) { return false }
                if let h = hi, h < lo { return false }
                q = (k + 1 - i, hi == nil, hi, hi.map { $0 &- lo &+ 1 })
            }
            if let (qlen, qunb, qmax, qopts) = q {
                switch prev {
                case .none: return false
                case let .group(f) where f.hasQuant || f.hasAlt: return false
                default: break
                }
                if !qunb, let m = qmax, m > MAX_BOUNDED_REPEAT { return false }
                if qunb {
                    bits += UNBOUNDED_QUANTIFIER_BITS
                } else if let o = qopts, o > 1 {
                    bits += 64 - (o - 1).leadingZeroBitCount // ceil(log2(o))
                }
                if bits > MAX_REGEX_COST_BITS { return false }
                stack[stack.count - 1].hasQuant = true
                i += qlen
                if i < len && src[i] == 0x3f { i += 1 }
                prev = .none
                continue
            }
            i += 1
            prev = .atom
        }
        return stack.count == 1 && compile(src) != nil
    }

    // ---- the per-DOCUMENT regex work budget (regex-budget.ts) ----

    static let MAX_REGEX_EVALUATIONS_PER_DOCUMENT = 64
    static let MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = 8192
    static let MAX_REGEX_STEPS_PER_DOCUMENT = 5_000_000

    /// One document scope (`withRegexBudget`): every regex evaluation in it is charged; once a cap would be exceeded the
    /// scope is poisoned and every later evaluation is refused (no match).
    final class Budget {
        var evaluations = 0
        var chars = 0
        var steps = 0
        func charge(srcUnits: Int, progLen: Int, subjectUnits: Int) -> Bool {
            let ev = evaluations + 1
            let ch = chars + srcUnits
            let st = steps + progLen * (subjectUnits + 1)
            if ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT || ch > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT || st > MAX_REGEX_STEPS_PER_DOCUMENT {
                evaluations = MAX_REGEX_EVALUATIONS_PER_DOCUMENT + 1
                return false
            }
            evaluations = ev
            chars = ch
            steps = st
            return true
        }
    }

    /// `isSafeRegexSource(src)`, then `chargeRegex(src, subject.length)`, then `safeRegexFullMatch(src, subject)`:
    /// nil = unknown (outside the subset, over the document budget, or the engine gave up).
    static func fullMatchTri(_ src: String, _ subject: String, _ budget: Budget) -> Bool? {
        let s = Array(src.utf16)
        if !isSafeSource(s) { return nil }
        guard let re = compile(s) else { return nil }
        let subj = Array(subject.utf16)
        if !budget.charge(srcUnits: s.count, progLen: re.prog.count, subjectUnits: subj.count) { return nil }
        return run(re, subj)
    }
}
