import Foundation

/// A YAML 1.2 emitter for parsed JSON trees that writes byte for byte what the `yaml` package's default `stringify` writes: block collections with
/// two-space indentation (sequences indented under their key), plain scalars unless they would read back as another type (then quoted), literal or folded
/// block scalars for multi-line text, double quotes with YAML escapes, and lines folded at 80 columns. A direct port of that library's string, number, pair
/// and collection stringifiers for the node kinds a JSON tree has.
///
/// A collection that appears more than once in a graph (the same `Node` instance) is written once with an anchor (`&a1`, numbered in the order the
/// repeats are met) and then as an alias (`*a1`), as the reference does. A `JSONValue` tree has no identity, so it never shares; build a `Node` graph to share.
/// A non-finite number or a number that is not a JSON value is refused. The members of an object a Swift program built are written in the order they were set when they were set through `o[o: name]`
/// (see JObjectOrder.swift; the importers do), else after the positioned members in code-unit order.
public enum YamlEmit {
    private static let LINE_WIDTH = 80, MIN_CONTENT_WIDTH = 20, DQ_MIN_MULTILINE = 40
    private enum Mode { case flow, block, quoted }

    /// A node of an emittable graph: scalars by value, collections by reference.
    public indirect enum Node {
        case null
        case bool(Bool)
        case number(Double)
        case string(String)
        case seq(Seq)
        case map(Map)
    }
    public final class Seq { public var items: [Node]; public init(_ items: [Node] = []) { self.items = items } }
    public final class Map { public var members: [(String, Node)]; public init(_ members: [(String, Node)] = []) { self.members = members } }

    /// The graph of a JSON value: every collection is a distinct instance.
    public static func node(_ v: JSONValue) throws -> Node {
        switch v {
        case .null: return .null
        case let .bool(b): return .bool(b)
        case let .int(i): return .number(Double(i))
        case let .double(d):
            if !d.isFinite { throw JSError("YAML: not a JSON number: \(d)") }
            return .number(d)
        case let .string(s): return .string(s)
        case let .array(a): return .seq(Seq(try a.map { try node($0) }))
        case let .object(o): return .map(Map(try JS.keyOrder(o).map { ($0.s, try node(o[$0]!)) }))
        }
    }

    /// The document text of `value`: the block-style YAML followed by a newline.
    public static func stringify(_ value: JSONValue) throws -> String { try stringify(node(value)) }

    public static func stringify(_ root: Node) throws -> String {
        let a = Anchors(root)
        return try stringifyNode(root, Ctx(a)) + "\n"
    }

    // ---- anchors ----

    private final class Anchors {
        var names: [ObjectIdentifier: String] = [:]
        var written = Set<ObjectIdentifier>()
        private var seen = Set<ObjectIdentifier>()
        private var count = 0
        init(_ root: Node) { walk(root) }

        static func id(_ n: Node) -> ObjectIdentifier? {
            switch n { case let .seq(s): return ObjectIdentifier(s); case let .map(m): return ObjectIdentifier(m); default: return nil }
        }

        private func walk(_ v: Node) {
            guard let id = Anchors.id(v) else { return }
            if !seen.insert(id).inserted {
                if names[id] == nil { count += 1; names[id] = "a\(count)" }
                return
            }
            switch v {
            case let .map(m): for k in jsKeys(m) { walk(m.members.last { $0.0 == k }!.1) }
            case let .seq(s): for x in s.items { walk(x) }
            default: break
            }
        }

        func isAlias(_ v: Node) -> Bool { Anchors.id(v).map { written.contains($0) } ?? false }
    }

    private final class Ctx {
        var anchors: Anchors
        var indent = "", indentStep = "  "
        var indentAtStart: Int? = nil
        var implicitKey = false, actualString = false, forceBlockIndent = false
        init(_ a: Anchors) { anchors = a }
        func copy() -> Ctx {
            let c = Ctx(anchors)
            c.indent = indent; c.indentStep = indentStep; c.indentAtStart = indentAtStart
            c.implicitKey = implicitKey; c.actualString = actualString; c.forceBlockIndent = forceBlockIndent
            return c
        }
    }

    // ---- nodes ----

    private static func stringifyNode(_ v: Node, _ ctx: Ctx) throws -> String {
        switch v {
        case .seq, .map:
            let id = Anchors.id(v)!
            let anchor = ctx.anchors.names[id]
            if let a = anchor, !ctx.anchors.written.insert(id).inserted { return "*" + a }
            let props = anchor.map { "&" + $0 }
            if let p = props { ctx.indentAtStart = (ctx.indentAtStart ?? 0) + p.utf16.count + 1 }
            let str: String
            if case let .map(m) = v { str = try stringifyMap(m, ctx) } else if case let .seq(s) = v { str = try stringifySeq(s, ctx) } else { str = "" }
            guard let p = props else { return str }
            let first = str.utf16.first
            return first == 0x7B || first == 0x5B ? p + " " + str : p + "\n" + ctx.indent + str
        case let .string(s): let c = ctx.copy(); c.actualString = true; return stringifyString(s, c)
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case let .number(d):
            if !d.isFinite { throw JSError("YAML: not a JSON number: \(d)") }
            if d == 0 && d.sign == .minus { return "-0" }
            return JS.number(d)
        }
    }

    private static func jsKeys(_ m: Map) -> [String] {
        var idx: [String] = [], rest: [String] = []
        for (k, _) in m.members { if JS.indexKey(k) != nil { idx.append(k) } else { rest.append(k) } }
        idx.sort { (JS.indexKey($0) ?? 0) < (JS.indexKey($1) ?? 0) }
        return idx + rest
    }

    private static func stringifyMap(_ m: Map, _ ctx: Ctx) throws -> String {
        let itemCtx = ctx.copy()
        itemCtx.indent = ctx.indent
        var lines: [String] = []
        for k in jsKeys(m) { lines.append(try stringifyPair(k, m.members.last { $0.0 == k }!.1, itemCtx)) }
        return join(lines, ctx.indent, "{}")
    }

    private static func stringifySeq(_ s: Seq, _ ctx: Ctx) throws -> String {
        let itemCtx = ctx.copy()
        itemCtx.indent = ctx.indent + "  "
        var lines: [String] = []
        for x in s.items { lines.append("- " + (try stringifyNode(x, itemCtx))) }
        return join(lines, ctx.indent, "[]")
    }

    private static func join(_ lines: [String], _ indent: String, _ empty: String) -> String {
        if lines.isEmpty { return empty }
        var b = lines[0]
        for line in lines.dropFirst() { b += line.isEmpty ? "\n" : "\n" + indent + line }
        return b
    }

    private static func stringifyPair(_ key: String, _ value: Node, _ ctx0: Ctx) throws -> String {
        let indent = ctx0.indent
        let ctx = ctx0.copy()
        ctx.indent = indent + ctx0.indentStep
        ctx.implicitKey = true
        var str = try stringifyNode(.string(key), ctx)
        let explicitKey = str.utf16.count > 1024
        str = explicitKey ? "? \(str)\n\(indent):" : "\(str):"
        ctx.implicitKey = false
        let alias = ctx.anchors.isAlias(value)
        var isColl = false, isEmpty = false
        switch value { case let .map(m): isColl = true; isEmpty = m.members.isEmpty; case let .seq(s): isColl = true; isEmpty = s.items.isEmpty; default: break }
        let collection = !alias && isColl
        if !explicitKey && !collection && !alias { ctx.indentAtStart = str.utf16.count + 1 }
        let valueStr = try stringifyNode(value, ctx)
        var ws = " "
        if !explicitKey && collection {
            let vu = Array(valueStr.utf16)
            let nl = vu.firstIndex(of: 0x0A)
            if nl != nil || !isEmpty {
                let sp0 = vu.firstIndex(of: 0x20)
                let propsLine = nl != nil && vu.first == 0x26 && (sp0 == nil || nl! < sp0!) // "&a1" alone on its line
                if !propsLine { ws = "\n" + ctx.indent }
            }
        } else if valueStr.isEmpty || valueStr.utf16.first == 0x0A { ws = "" }
        return str + ws + valueStr
    }

    // ---- strings ----

    private static func rx(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p) }
    private static let DOC_MARKER = rx("(?:^|[\\n\\r\\u2028\\u2029])(?:%|---|\\.\\.\\.)")
    private static let PLAIN_FORBIDDEN = rx("^[\\n\\t ,\\[\\]\\{\\}#&*!|>'\"%@`]|^[?\\-]\\z|^[?\\-][ \\t]|[\\n:][ \\t]|[ \\t]\\n|[\\n\\t ]#|[\\n\\t :]\\z")
    // the core schema's default tags that would read a plain scalar back as a non-string
    private static let NON_STRING: [NSRegularExpression] = [
        rx("^(?:~|[Nn]ull|NULL)?\\z"), rx("^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)\\z"), rx("^0o[0-7]+\\z"), rx("^[-+]?[0-9]+\\z"),
        rx("^0x[0-9a-fA-F]+\\z"), rx("^(?:[-+]?\\.(?:inf|Inf|INF)|\\.nan|\\.NaN|\\.NAN)\\z"), rx("^[-+]?(?:\\.[0-9]+|[0-9]+(?:\\.[0-9]*)?)[eE][-+]?[0-9]+\\z"),
        rx("^[-+]?(?:\\.[0-9]+|[0-9]+\\.[0-9]*)\\z"),
    ]
    private static let WS_AROUND_NL = rx("[ \\t]\\n|\\n[ \\t]")
    private static let NL_RUN = rx("\\n+")
    private static let BLOCK_END_NL = rx("(^|(?<!\\n))\\n+(?!\\n|\\z)")
    private static let TRAILING_WS_LINE = rx("\\n[\\t ]+\\z")
    private static let MORE_INDENTED = rx("(?:^|\\n)([\\t ].*)(?:([\\n\\t ]*)\\n(?![\\n\\t ]))?")

    private static func found(_ re: NSRegularExpression, _ s: String) -> Bool { re.firstMatch(in: s, range: NSRange(location: 0, length: s.utf16.count)) != nil }
    private static func sub(_ s: NSString, _ from: Int, _ to: Int) -> String { s.substring(with: NSRange(location: from, length: max(0, to - from))) }
    private static func containsDocumentMarker(_ s: String) -> Bool { found(DOC_MARKER, s) }

    /// `s.replace(/\n+/g, '$&' + suffix)`: every newline run followed by `suffix`.
    private static func afterNewlines(_ s: String, _ suffix: String) -> String {
        let ns = s as NSString
        var b = "", last = 0
        for m in NL_RUN.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            b += sub(ns, last, m.range.location + m.range.length) + suffix
            last = m.range.location + m.range.length
        }
        return b + sub(ns, last, ns.length)
    }

    /// The lone-surrogate scalar (`Canonical.LONE_SURROGATE_SENTINEL`) as a UTF-16 unit.
    private static let LONE = UInt16(Canonical.LONE_SURROGATE_SENTINEL.value)
    // shortcut: one scalar stands for every lone surrogate, so each is written as the high half `\ud800` (the reference writes the half it holds); upgrade when a value must keep which half it was
    private static let LONE_ESCAPE = Array("\\ud800".utf16)

    private static func forcesDoubleQuotes(_ s: String) -> Bool {
        let u = Array(s.utf16)
        var i = 0
        while i < u.count {
            let x = u[i]
            if x <= 0x08 || (x >= 0x0b && x <= 0x1f) || (x >= 0x7f && x <= 0x9f) { return true }
            if x == LONE { return true } // the scalar this library carries for a lone surrogate (a JavaScript string keeps the half itself)
            if x >= 0xD800 && x <= 0xDBFF { if i + 1 < u.count && u[i + 1] >= 0xDC00 && u[i + 1] <= 0xDFFF { i += 1 } else { return true } }
            else if x >= 0xDC00 && x <= 0xDFFF { return true }
            i += 1
        }
        return false
    }

    private static func stringifyString(_ value: String, _ ctx: Ctx) -> String { forcesDoubleQuotes(value) ? doubleQuotedString(value, ctx) : plainString(value, ctx) }

    private static func plainString(_ value: String, _ ctx: Ctx) -> String {
        let hasNl = value.contains("\n")
        if ctx.implicitKey && hasNl { return quotedString(value, ctx) }
        if found(PLAIN_FORBIDDEN, value) { return ctx.implicitKey || !hasNl ? quotedString(value, ctx) : blockString(value, ctx) }
        if !ctx.implicitKey && hasNl { return blockString(value, ctx) } // the string has no explicit type: block style is preferred where allowed
        if containsDocumentMarker(value) {
            if ctx.indent.isEmpty { ctx.forceBlockIndent = true; return blockString(value, ctx) }
            else if ctx.implicitKey && ctx.indent == ctx.indentStep { return quotedString(value, ctx) }
        }
        let str = afterNewlines(value, "\n" + ctx.indent)
        if ctx.actualString { for p in NON_STRING where found(p, str) { return quotedString(value, ctx) } }
        return ctx.implicitKey ? str : foldFlowLines(str, ctx.indent, .flow, ctx.indentAtStart, nil)
    }

    private static func quotedString(_ value: String, _ ctx: Ctx) -> String {
        let hasDouble = value.contains("\""), hasSingle = value.contains("'")
        return hasDouble && !hasSingle ? singleQuotedString(value, ctx) : doubleQuotedString(value, ctx)
    }

    private static func singleQuotedString(_ value: String, _ ctx: Ctx) -> String {
        if (ctx.implicitKey && value.contains("\n")) || found(WS_AROUND_NL, value) { return doubleQuotedString(value, ctx) }
        let indent = !ctx.indent.isEmpty ? ctx.indent : containsDocumentMarker(value) ? "  " : ""
        let res = "'" + afterNewlines(value.replacingOccurrences(of: "'", with: "''"), "\n" + indent) + "'"
        return ctx.implicitKey ? res : foldFlowLines(res, indent, .flow, ctx.indentAtStart, nil)
    }

    private static func at(_ s: [UInt16], _ i: Int) -> UInt16 { i >= 0 && i < s.count ? s[i] : 0 }
    private static func s16(_ u: ArraySlice<UInt16>) -> String { String(decoding: u, as: UTF16.self) }

    private static func doubleQuotedString(_ value: String, _ ctx: Ctx) -> String {
        let json = Array(JS.stringify(.string(value)).utf16).flatMap { $0 == LONE ? LONE_ESCAPE : [$0] }
        let indent = !ctx.indent.isEmpty ? ctx.indent : containsDocumentMarker(value) ? "  " : ""
        var str = [UInt16]()
        var start = 0, i = 0
        func app(_ s: String) { str += Array(s.utf16) }
        func app(_ a: Int, _ b: Int) { if a < b { str += json[a..<min(b, json.count)] } }
        while i < json.count {
            var ch = json[i]
            if ch == 0x20 && at(json, i + 1) == 0x5C && at(json, i + 2) == 0x6E {
                // a space before a newline is escaped so it is not folded
                app(start, i); app("\\ ")
                i += 1
                start = i
                ch = 0x5C
            }
            if ch == 0x5C {
                switch at(json, i + 1) {
                case 0x75: // u
                    app(start, i)
                    let code = s16(json[min(i + 2, json.count)..<min(i + 6, json.count)])
                    switch code {
                    case "0000": app("\\0")
                    case "0007": app("\\a")
                    case "000b": app("\\v")
                    case "001b": app("\\e")
                    case "0085": app("\\N")
                    case "00a0": app("\\_")
                    case "2028": app("\\L")
                    case "2029": app("\\P")
                    default: if code.hasPrefix("00") { app("\\x" + code.dropFirst(2)) } else { app(i, min(i + 6, json.count)) }
                    }
                    i += 5
                    start = i + 1
                case 0x6E: // n
                    if ctx.implicitKey || at(json, i + 2) == 0x22 || json.count < DQ_MIN_MULTILINE { i += 1 }
                    else {
                        // folding eats the first newline
                        app(start, i); app("\n\n")
                        while at(json, i + 2) == 0x5C && at(json, i + 3) == 0x6E && at(json, i + 4) != 0x22 { app("\n"); i += 2 }
                        app(indent)
                        // a space after a newline is escaped so it is not folded
                        if at(json, i + 2) == 0x20 { app("\\") }
                        i += 1
                        start = i + 1
                    }
                default: i += 1
                }
            }
            i += 1
        }
        let res: String
        if start != 0 { app(min(start, json.count), json.count); res = String(decoding: str, as: UTF16.self) } else { res = String(decoding: json, as: UTF16.self) }
        return ctx.implicitKey ? res : foldFlowLines(res, indent, .quoted, ctx.indentAtStart, nil)
    }

    private static func lineLengthOverLimit(_ str: String, _ lineWidth: Int, _ indentLength: Int) -> Bool {
        let u = Array(str.utf16)
        let limit = lineWidth - indentLength
        if u.count <= limit { return false }
        var start = 0
        for i in 0..<u.count where u[i] == 0x0A {
            if i - start > limit { return true }
            start = i + 1
            if u.count - start <= limit { return false }
        }
        return true
    }

    private static func blockString(_ value0: String, _ ctx: Ctx) -> String {
        var value = value0
        // a block cannot end in whitespace unless its last line is non-empty
        if found(TRAILING_WS_LINE, value) { return quotedString(value, ctx) }
        let indent = !ctx.indent.isEmpty ? ctx.indent : (ctx.forceBlockIndent || containsDocumentMarker(value)) ? "  " : ""
        let literal = !lineLengthOverLimit(value, LINE_WIDTH, indent.utf16.count)
        if value.isEmpty { return literal ? "|\n" : ">\n" }
        // chomping from the whitespace at the value's end
        var vu = Array(value.utf16)
        var endStart = vu.count
        while endStart > 0 { let ch = vu[endStart - 1]; if ch != 0x0A && ch != 0x09 && ch != 0x20 { break }; endStart -= 1 }
        var end = Array(vu[endStart...])
        let endNlPos = end.firstIndex(of: 0x0A)
        let chomp = endNlPos == nil ? "-" : (vu == end || endNlPos! != end.count - 1) ? "+" : ""
        var endS = s16(end[...])
        if !end.isEmpty {
            vu = Array(vu[0..<(vu.count - end.count)])
            if end[end.count - 1] == 0x0A { end.removeLast() }
            endS = replaceBlockEnd(s16(end[...]), indent)
        }
        value = String(decoding: vu, as: UTF16.self)
        // indent indicator from the whitespace at the value's start
        var startWithSpace = false
        var startEnd = 0, startNlPos = -1
        while startEnd < vu.count {
            let ch = vu[startEnd]
            if ch == 0x20 { startWithSpace = true } else if ch == 0x0A { startNlPos = startEnd } else { break }
            startEnd += 1
        }
        var start = s16(vu[0..<(startNlPos < startEnd ? startNlPos + 1 : startEnd)])
        if !start.isEmpty {
            value = String(decoding: vu[(start.utf16.count)...], as: UTF16.self)
            start = afterNewlines(start, indent)
        }
        let indentSize = !indent.isEmpty ? "2" : "1" // the root is at -1
        let header = (startWithSpace ? indentSize : "") + chomp
        if !literal {
            let foldedValue = afterNewlines(moreIndentedUnfolded(afterNewlinesPrefix(value)), indent)
            var overflow = false
            let body = withUnsafeMutablePointer(to: &overflow) { foldFlowLines(start + foldedValue + endS, indent, .block, ctx.indent.utf16.count, $0) }
            if !overflow { return ">\(header)\n\(indent)\(body)" }
        }
        value = afterNewlines(value, indent)
        return "|\(header)\n\(indent)\(start)\(value)\(endS)"
    }

    /// `end.replace(blockEndNewlines, '$&' + indent)`.
    private static func replaceBlockEnd(_ end: String, _ indent: String) -> String {
        let ns = end as NSString
        var b = "", last = 0
        for m in BLOCK_END_NL.matches(in: end, range: NSRange(location: 0, length: ns.length)) {
            b += sub(ns, last, m.range.location + m.range.length) + indent
            last = m.range.location + m.range.length
        }
        return b + sub(ns, last, ns.length)
    }

    /// `value.replace(/\n+/g, '\n$&')`.
    private static func afterNewlinesPrefix(_ s: String) -> String {
        let ns = s as NSString
        var b = "", last = 0
        for m in NL_RUN.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            b += sub(ns, last, m.range.location) + "\n" + sub(ns, m.range.location, m.range.location + m.range.length)
            last = m.range.location + m.range.length
        }
        return b + sub(ns, last, ns.length)
    }

    /// `s.replace(/(?:^|\n)([\t ].*)(?:([\n\t ]*)\n(?![\n\t ]))?/g, '$1$2')`: more-indented lines are not folded.
    private static func moreIndentedUnfolded(_ s: String) -> String {
        let ns = s as NSString
        var b = "", last = 0
        for m in MORE_INDENTED.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            b += sub(ns, last, m.range.location)
            b += sub(ns, m.range(at: 1).location, m.range(at: 1).location + m.range(at: 1).length)
            if m.range(at: 2).location != NSNotFound { b += sub(ns, m.range(at: 2).location, m.range(at: 2).location + m.range(at: 2).length) }
            last = m.range.location + m.range.length
        }
        return b + sub(ns, last, ns.length)
    }

    // ---- folding ----

    private static func consumeMoreIndentedLines(_ text: [UInt16], _ i0: Int, _ indent: Int) -> Int {
        var i = i0
        var end = i
        var start = i + 1
        var ch = at(text, start)
        while ch == 0x20 || ch == 0x09 {
            if i < start + indent { i += 1; ch = at(text, i) }
            else {
                repeat { i += 1; ch = at(text, i) } while ch != 0 && ch != 0x0A
                end = i
                start = i + 1
                ch = at(text, start)
            }
        }
        return end
    }

    /// Keeps text at up to the line width by splitting on spaces not followed by newlines or spaces (anywhere in quoted mode); lines end with a newline and
    /// start with `indent`. `indentAtStart` is where the first line already starts (nil = the indent).
    private static func foldFlowLines(_ textS: String, _ indentS: String, _ mode: Mode, _ indentAtStart: Int?, _ overflowOut: UnsafeMutablePointer<Bool>?) -> String {
        let text = Array(textS.utf16)
        let indent = indentS.utf16.count
        let lineWidth = LINE_WIDTH
        var minContentWidth = MIN_CONTENT_WIDTH
        if lineWidth < minContentWidth { minContentWidth = 0 }
        let endStep = max(1 + minContentWidth, 1 + lineWidth - indent)
        if text.count <= endStep { return textS }
        var folds: [Int] = []
        var escapedFolds = Set<Int>()
        var end = lineWidth - indent
        if let ias = indentAtStart {
            if ias > lineWidth - max(2, minContentWidth) { folds.append(0) } else { end = lineWidth - ias }
        }
        var split: Int? = nil
        var prev: UInt16 = 0
        var overflow = false
        var i = -1
        var escStart = -1, escEnd = -1
        if mode == .block {
            i = consumeMoreIndentedLines(text, i, indent)
            if i != -1 { end = i + endStep }
        }
        while true {
            i += 1
            var ch = at(text, i)
            if ch == 0 { break }
            if mode == .quoted && ch == 0x5C {
                escStart = i
                switch at(text, i + 1) { case 0x78: i += 3; case 0x75: i += 5; case 0x55: i += 9; default: i += 1 }
                escEnd = i
            }
            if ch == 0x0A {
                if mode == .block { i = consumeMoreIndentedLines(text, i, indent) }
                end = i + indent + endStep
                split = nil
            } else {
                if ch == 0x20 && prev != 0 && prev != 0x20 && prev != 0x0A && prev != 0x09 {
                    // a space surrounded by non-space can become a newline plus indent
                    let next = at(text, i + 1)
                    if next != 0 && next != 0x20 && next != 0x0A && next != 0x09 { split = i }
                }
                if i >= end {
                    if let sp = split {
                        folds.append(sp)
                        end = sp + endStep
                        split = nil
                    } else if mode == .quoted {
                        // white space collected at the end may stretch past the line width
                        while prev == 0x20 || prev == 0x09 {
                            prev = ch
                            i += 1
                            ch = at(text, i)
                            overflow = true
                        }
                        // account for the newline escape, but do not break a preceding escape
                        let j = i > escEnd + 1 ? i - 2 : escStart - 1
                        if escapedFolds.contains(j) { return textS }
                        folds.append(j)
                        escapedFolds.insert(j)
                        end = j + endStep
                        split = nil
                    } else {
                        overflow = true
                    }
                }
            }
            prev = ch
        }
        if let o = overflowOut, overflow { o.pointee = true }
        if folds.isEmpty { return textS }
        let ind = Array(indentS.utf16)
        var res = Array(text[0..<min(folds[0], text.count)])
        for k in folds.indices {
            let fold = folds[k]
            let e = k + 1 < folds.count && folds[k + 1] != 0 ? folds[k + 1] : text.count
            if fold == 0 {
                res = [0x0A] + ind + Array(text[0..<min(e, text.count)])
            } else {
                if mode == .quoted && escapedFolds.contains(fold) { res.append(text[fold]); res.append(0x5C) }
                res.append(0x0A); res += ind
                res += text[min(fold + 1, text.count)..<min(max(e, fold + 1), text.count)]
            }
        }
        return String(decoding: res, as: UTF16.self)
    }
}
