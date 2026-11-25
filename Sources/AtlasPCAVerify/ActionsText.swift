import Foundation
import CYaml

/// A syntax or policy refusal of the YAML front end (message plus 1-based position).
public struct YamlLoadError: Error {
    public let message: String
    public let line: Int
    public let column: Int
    public init(_ message: String, _ line: Int = 1, _ column: Int = 1) { self.message = message; self.line = line; self.column = column }
}

/// The authoring-file text loader: YAML 1.2 core schema or JSON text, with source positions. The syntax layer is libyaml (the C parser, vendored as
/// `CYaml`); only its EVENT stream is used. Everything the reference decides about meaning is done here, so the result does not depend on libyaml's
/// own resolver or alias handling: the tree is built from events, plain scalars are resolved with the YAML 1.2 core schema (null, bool, int, 0o / 0x,
/// float, .inf, .nan; everything else a string), mapping keys are stringified the way JavaScript does, aliases are refused, "<<" is an ordinary key,
/// and positions are the 1-based start of each action and each param key.
///
/// Where this differs from the reference it is STRICTER (it refuses): an explicit tag other than !!str / !!map / !!seq, a complex (non-scalar) mapping
/// key, two keys that are equal once stringified, a bare carriage return used as a line break, more than one document. Syntax error wording and the
/// line/column of a syntax error are the parser's own.
public enum ActionsText {
    private static let STR_TAG = "tag:yaml.org,2002:str"
    private static let MAP_TAG = "tag:yaml.org,2002:map"
    private static let SEQ_TAG = "tag:yaml.org,2002:seq"

    private final class N {
        let kind: String // scalar | map | seq
        let line: Int, col: Int
        var value: JSONValue = .null
        var seq: [N] = []
        var map: [(N, N)] = []
        init(_ kind: String, _ line: Int, _ col: Int) { self.kind = kind; self.line = line; self.col = col }
    }

    private struct Pos { let line: Int; let col: Int; let params: JObject }

    private static func jsNumber(_ d: Double) -> JSONValue { d.isNaN || d.isInfinite ? .double(d) : d == 0 ? .int(0) : Jx.num(d) }

    /// A non-negative integer given by digits in `radix`, as the nearest binary64 (BigInteger.toDouble).
    private static func bigToDouble(_ digits: String, _ radix: Int) -> Double {
        var acc = BigUInt()
        for u in digits.unicodeScalars { acc = acc * BigUInt(UInt64(radix)) + BigUInt(UInt64(Int(String(u), radix: radix) ?? 0)) }
        let l = acc.limbs
        guard let top = l.indices.last else { return 0 }
        if l.count <= 2 { return Double(UInt64(l[0]) | (l.count == 2 ? UInt64(l[1]) << 32 : 0)) }
        // the top 64 bits with a sticky bit for the rest: correct rounding to 53 bits
        let bits = (l.count - 1) * 32 + (32 - l[top].leadingZeroBitCount)
        let shift = bits - 64
        var v: UInt64 = 0
        var sticky = false
        for i in 0..<64 {
            let pos = shift + i
            if acc.bit(pos) == 1 { v |= UInt64(1) << UInt64(i) }
        }
        for pos in 0..<shift where acc.bit(pos) == 1 { sticky = true; break }
        if sticky { v |= 1 }
        return Double(v) * pow(2.0, Double(shift))
    }

    private static func jsInt(_ text: String, _ radix: Int) -> JSONValue {
        let neg = text.hasPrefix("-")
        let digits = String(text.drop { $0 == "+" || $0 == "-" })
        let d = radix == 10 ? (Double(digits) ?? bigToDouble(digits, radix)) : bigToDouble(digits, radix)
        if neg && d == 0 { return jsNumber(-0.0) }
        let v = neg ? -d : d
        if abs(v) <= 9007199254740992.0 { return Jx.num(v) }
        return jsNumber(v)
    }

    /// The YAML 1.2 core schema value of a plain scalar, as a JSON tree value (number, bool, null or string).
    public static func resolveCorePlain(_ text: String) -> JSONValue {
        if text == "" || text == "~" || text == "null" || text == "Null" || text == "NULL" { return .null }
        if text == "true" || text == "True" || text == "TRUE" { return .bool(true) }
        if text == "false" || text == "False" || text == "FALSE" { return .bool(false) }
        if Actions.fullMatch("[-+]?[0-9]+", text) { return jsInt(text, 10) }
        if Actions.fullMatch("0o[0-7]+", text) { return jsInt(String(text.dropFirst(2)), 8) }
        if Actions.fullMatch("0x[0-9a-fA-F]+", text) { return jsInt(String(text.dropFirst(2)), 16) }
        if Actions.fullMatch("[-+]?\\.(?:inf|Inf|INF)", text) { return .double(text.hasPrefix("-") ? -Double.infinity : Double.infinity) }
        if Actions.fullMatch("\\.(?:nan|NaN|NAN)", text) { return .double(Double.nan) }
        if Actions.fullMatch("[-+]?(?:\\.[0-9]+|[0-9]+(?:\\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?", text), let f = Double(text) {
            let negZero = f == 0 && text.drop { $0 == "+" }.hasPrefix("-")
            return f == f.rounded(.down) && abs(f) <= 9007199254740992.0 && !negZero ? .int(Int64(f)) : jsNumber(f)
        }
        return .string(text)
    }

    private static func jsKey(_ v: JSONValue) -> String {
        switch v {
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case let .int(i): return String(i)
        case let .double(d): return d.isNaN ? "NaN" : d.isInfinite ? (d > 0 ? "Infinity" : "-Infinity") : JS.number(d)
        case let .string(s): return s
        default: return ""
        }
    }

    // ---- libyaml events ----

    private enum Ev {
        case streamStart, streamEnd, docStart, docEnd
        case alias(Int, Int)
        case scalar(String, plain: Bool, tag: String?, Int, Int)
        case seqStart(tag: String?, Int, Int), seqEnd
        case mapStart(tag: String?, Int, Int), mapEnd
    }

    private static func cstr(_ p: UnsafePointer<yaml_char_t>?) -> String? {
        guard let p = p else { return nil }
        return String(cString: UnsafeRawPointer(p).assumingMemoryBound(to: CChar.self))
    }

    private static func tagOf(_ p: UnsafePointer<yaml_char_t>?) -> String? { cstr(p).flatMap { $0.isEmpty ? nil : $0 } }

    /// The parser's event stream of `text`, or a YamlLoadError at the position libyaml reports.
    private static func events(_ text: String, _ edits: [SurrogateEdit] = []) throws -> [Ev] {
        // a mark in the rewritten text, as a column of the text the author wrote (libyaml reads every other escape itself)
        func orig(_ line: Int, _ col: Int) -> Int { col + edits.reduce(0) { $0 + ($1.line == line && $1.endCol <= col ? $1.delta : 0) } }
        var parser = yaml_parser_t()
        guard yaml_parser_initialize(&parser) != 0 else { throw YamlLoadError("could not initialise the YAML parser") }
        defer { yaml_parser_delete(&parser) }
        let bytes = Array(text.utf8)
        var out: [Ev] = []
        var failure: YamlLoadError? = nil
        bytes.withUnsafeBufferPointer { buf in
            yaml_parser_set_input_string(&parser, buf.baseAddress, buf.count)
            var ev = yaml_event_t()
            while true {
                if yaml_parser_parse(&parser, &ev) == 0 {
                    let msg = cstr(UnsafeRawPointer(parser.problem)?.assumingMemoryBound(to: yaml_char_t.self)) ?? "syntax error"
                    failure = YamlLoadError(msg, Int(parser.problem_mark.line) + 1, orig(Int(parser.problem_mark.line) + 1, Int(parser.problem_mark.column) + 1))
                    return
                }
                let line = Int(ev.start_mark.line) + 1, col = orig(Int(ev.start_mark.line) + 1, Int(ev.start_mark.column) + 1)
                var done = false
                switch ev.type {
                case YAML_STREAM_START_EVENT: out.append(.streamStart)
                case YAML_STREAM_END_EVENT: out.append(.streamEnd); done = true
                case YAML_DOCUMENT_START_EVENT: out.append(.docStart)
                case YAML_DOCUMENT_END_EVENT: out.append(.docEnd)
                case YAML_ALIAS_EVENT: out.append(.alias(line, col))
                case YAML_SCALAR_EVENT:
                    let s = ev.data.scalar
                    let v = s.value.map { String(decoding: UnsafeBufferPointer(start: $0, count: Int(s.length)), as: UTF8.self) } ?? ""
                    out.append(.scalar(v, plain: s.style == YAML_PLAIN_SCALAR_STYLE, tag: tagOf(s.tag), line, col))
                case YAML_SEQUENCE_START_EVENT: out.append(.seqStart(tag: tagOf(ev.data.sequence_start.tag), line, col))
                case YAML_SEQUENCE_END_EVENT: out.append(.seqEnd)
                case YAML_MAPPING_START_EVENT: out.append(.mapStart(tag: tagOf(ev.data.mapping_start.tag), line, col))
                case YAML_MAPPING_END_EVENT: out.append(.mapEnd)
                default: break
                }
                yaml_event_delete(&ev)
                if done { return }
            }
        }
        if let f = failure { throw f }
        return out
    }

    struct SurrogateEdit { let line: Int; let endCol: Int; let delta: Int }

    /// `\uD83D\uDE00` inside a double-quoted scalar becomes `\U0001F600`; a lone `\uD800` (or a low half on its own) becomes the escape of the lone-surrogate
    /// scalar. Every edit records where it ends in the new text and how many columns it removed from the written one.
    static func rewriteSurrogateEscapes(_ text: String, json: Bool = false) -> (String, [SurrogateEdit]) {
        let b = Array(text.utf8)
        var out: [UInt8] = []
        var edits: [SurrogateEdit] = []
        var i = 0, line = 1, col = 1
        var dq = false, sq = false, comment = false
        func hex4(_ at: Int) -> UInt32? {
            guard at + 4 <= b.count else { return nil }
            var v: UInt32 = 0
            for k in 0..<4 {
                let c = b[at + k]
                let d: UInt32
                switch c { case 48...57: d = UInt32(c) - 48; case 97...102: d = UInt32(c) - 87; case 65...70: d = UInt32(c) - 55; default: return nil }
                v = v << 4 | d
            }
            return v
        }
        func emit(_ s: String) { out += Array(s.utf8) }
        func big(_ cp: UInt32) -> String { "\\U" + String(format: "%08X", cp) }
        while i < b.count {
            let c = b[i]
            if c == 0x0A { line += 1; col = 1; comment = false; out.append(c); i += 1; continue }
            if comment { if c & 0xC0 != 0x80 { col += 1 }; out.append(c); i += 1; continue }
            if dq {
                if c == 0x5C, i + 1 < b.count {
                    if b[i + 1] == 0x75, let hi = hex4(i + 2), (0xD800...0xDFFF).contains(hi) {
                        var used = 6
                        var cp = UInt32(Canonical.loneScalar(UInt16(hi)).value) // a lone half keeps its own unit
                        if (0xD800...0xDBFF).contains(hi), i + 12 <= b.count, b[i + 6] == 0x5C, b[i + 7] == 0x75, let lo = hex4(i + 8), (0xDC00...0xDFFF).contains(lo) {
                            used = 12; cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                        }
                        if json {
                            // JSON has no \U escape: a pair stays as written, a lone half becomes the BMP escape of the lone-surrogate scalar
                            if used == 12 { out += b[i..<(i + 12)]; col += 12 } else { out += Array(String(Canonical.loneScalar(UInt16(hi))).utf8); col += 1 }
                            i += used; continue
                        }
                        emit(big(cp))
                        col += 10
                        edits.append(SurrogateEdit(line: line, endCol: col, delta: used - 10))
                        i += used; continue
                    }
                    out.append(c); out.append(b[i + 1]); i += 2; col += 2; continue
                }
                if c == 0x22 { dq = false }
                if c & 0xC0 != 0x80 { col += 1 }
                out.append(c); i += 1; continue
            }
            if sq { if c == 0x27 { sq = false }; if c & 0xC0 != 0x80 { col += 1 }; out.append(c); i += 1; continue }
            if c == 0x22 { dq = true }
            else if c == 0x27 { sq = true }
            else if c == 0x23, i == 0 || b[i - 1] == 0x20 || b[i - 1] == 0x09 || b[i - 1] == 0x0A { comment = true }
            if c & 0xC0 != 0x80 { col += 1 }
            out.append(c); i += 1
        }
        return (String(decoding: out, as: UTF8.self), edits)
    }

    private static func parseDocument(_ text: String, _ strict: Bool) throws -> N? {
        let u8 = Array(text.utf8)
        if u8.indices.contains(where: { u8[$0] == 13 && ($0 + 1 == u8.count || u8[$0 + 1] != 10) }) {
            throw YamlLoadError("bare carriage return is not accepted as a line break")
        }
        let evs: [Ev]
        do { evs = try events(text) } catch let e as YamlLoadError where e.message.contains("Unicode character escape") {
            // libyaml refuses a surrogate half as an escape; JavaScript's parser combines a pair into one character and keeps a lone half. The text is rewritten so
            // each pair is the one character it denotes and each lone half the lone-surrogate scalar the library carries for it, the marks are mapped back.
            let (fixed, edits) = rewriteSurrogateEscapes(text)
            evs = try events(fixed, edits)
        }
        var pos = 0
        var docs = 0

        func isEnd(_ e: Ev, _ seq: Bool) -> Bool { if case .seqEnd = e { return seq }; if case .mapEnd = e { return !seq }; return false }

        func node() throws -> N {
            guard pos < evs.count else { throw YamlLoadError("unexpected end of the event stream") }
            let ev = evs[pos]
            pos += 1
            switch ev {
            case let .alias(l, c): throw YamlLoadError("Alias resolution is disabled", l, c)
            case let .scalar(v, plain, tag, l, c):
                if let t = tag, t != STR_TAG, t != MAP_TAG, t != SEQ_TAG { throw YamlLoadError("Unresolved or unsupported tag: \(t)", l, c) }
                let n = N("scalar", l, c)
                n.value = plain && tag == nil ? resolveCorePlain(v) : .string(v)
                return n
            case let .seqStart(tag, l, c):
                if let t = tag, t != STR_TAG, t != MAP_TAG, t != SEQ_TAG { throw YamlLoadError("Unresolved or unsupported tag: \(t)", l, c) }
                let n = N("seq", l, c)
                while pos < evs.count && !isEnd(evs[pos], true) { n.seq.append(try node()) }
                pos += 1
                return n
            case let .mapStart(tag, l, c):
                if let t = tag, t != STR_TAG, t != MAP_TAG, t != SEQ_TAG { throw YamlLoadError("Unresolved or unsupported tag: \(t)", l, c) }
                let n = N("map", l, c)
                var seen = Set<JKey>()
                while pos < evs.count && !isEnd(evs[pos], false) {
                    let key = try node()
                    let v = try node()
                    if strict {
                        if key.kind != "scalar" { throw YamlLoadError("complex mapping keys are not accepted", key.line, key.col) }
                        if !seen.insert(JKey(jsKey(key.value))).inserted { throw YamlLoadError("Map keys must be unique", key.line, key.col) }
                    }
                    n.map.append((key, v))
                }
                pos += 1
                return n
            default: throw YamlLoadError("unexpected parser event")
            }
        }

        var root: N? = nil
        while pos < evs.count {
            if case .docStart = evs[pos] {
                docs += 1
                if docs > 1 { throw YamlLoadError("Source contains multiple documents; please use YAML.parseAllDocuments()") }
                pos += 1
                if pos < evs.count { if case .docEnd = evs[pos] {} else { root = try node() } }
            } else { pos += 1 }
        }
        return root
    }

    private static func toValue(_ n: N?) throws -> JSONValue {
        guard let n = n else { return .null }
        if n.kind == "scalar" { return n.value }
        if n.kind == "seq" { return .array(try n.seq.map { try toValue($0) }) }
        var o: JObject = [:]
        var i: Int32 = 0
        for (k, v) in n.map {
            if k.kind != "scalar" { throw YamlLoadError("complex mapping keys are not accepted", k.line, k.col) }
            i += 1
            o[JKey(jsKey(k.value), ord: i)] = try toValue(v)
        }
        return .object(o)
    }

    // per-entry positions of an authoring document (actions items and their params keys), by entry index; nil when not a mapping
    private static func positionsOf(_ root: N?) -> [Pos]? {
        guard let root = root, root.kind == "map" else { return nil }
        var actions: N? = nil
        for (k, v) in root.map where k.kind == "scalar" && k.value == .string("actions") { actions = v }
        let items: [N] = actions?.kind == "seq" ? actions!.seq : [root]
        return items.map { it in
            var ps: JObject = [:]
            if it.kind == "map" {
                var pm: N? = nil
                for (k, v) in it.map where k.kind == "scalar" && k.value == .string("params") { pm = v }
                if let pm = pm, pm.kind == "map" {
                    for (k, _) in pm.map where k.kind == "scalar" { ps[JKey(k.value == .null ? "" : jsKey(k.value))] = AK.obj(["line": .int(Int64(k.line)), "column": .int(Int64(k.col))]) }
                }
            }
            return Pos(line: it.line, col: it.col, params: ps)
        }
    }

    private static func attachPositions(_ res: inout JObject, _ pos: [Pos]) {
        var errors = AK.arr(res[JKey("errors")])
        var failed = Set<Int64>()
        for e in errors { if let ix = e.get("index"), let i = IV.int(ix) { failed.insert(i) } }
        let order = (0..<pos.count).filter { !failed.contains(Int64($0)) }
        let defs = AK.arr(res[JKey("defs")])
        var locs = AK.o(res[JKey("locs")])
        for k in 0..<defs.count where k < order.count {
            let p = pos[order[k]]
            locs[JKey(JS.toString(defs[k].get("verb")))] = AK.obj(["line": .int(Int64(p.line)), "column": .int(Int64(p.col)), "params": .object(p.params)])
        }
        for i in errors.indices {
            var em = AK.o(errors[i])
            if let ix = IV.int(em[JKey("index")]) {
                if ix >= 0 && ix < Int64(pos.count) { em[JKey("line")] = .int(Int64(pos[Int(ix)].line)); em[JKey("column")] = .int(Int64(pos[Int(ix)].col)) }
            } else { em[JKey("line")] = .int(1); em[JKey("column")] = .int(1) }
            errors[i] = .object(em)
        }
        res[JKey("locs")] = .object(locs)
        res[JKey("errors")] = .array(errors)
    }

    private static func fail(_ message: String, _ line: Int = 1, _ column: Int = 1) -> JObject {
        Jx.obj(["defs": .array([]), "notes": .array([]), "errors": .array([AK.obj(["message": .string(message), "line": .int(Int64(line)), "column": .int(Int64(column))])]),
                "locs": .object([:]), "rules": .object([:])])
    }

    /// Load an authoring file (YAML 1.2 core or JSON, `fmt` "yaml" or "json") with source positions. Input above `ActionAuthor.MAX_AUTHOR_BYTES` is refused. Never throws.
    public static func loadActionsText(_ text: String, _ fmt: String = "yaml") -> JObject {
        if text.utf8.count > ActionAuthor.MAX_AUTHOR_BYTES { return fail("the file is larger than \(ActionAuthor.MAX_AUTHOR_BYTES) bytes") }
        var positions: [Pos]? = nil
        let value: JSONValue
        if fmt == "json" {
            do { value = try StrictJSON.parseLenient(text) } catch {
                let msg = (error as? JSError)?.message ?? "\(error)"
                // JavaScript keeps a lone surrogate escape as the lone code unit: here it is the lone-surrogate scalar the library carries for one
                if msg.contains("lone surrogate"), let v = try? StrictJSON.parseLenient(rewriteSurrogateEscapes(text, json: true).0) { value = v }
                else { return fail("not JSON: " + msg) }
            }
            // JSON is YAML: only the positions come from the YAML parse
            positions = (try? parseDocument(text, false)).flatMap { positionsOf($0) }
        } else {
            do {
                let root = try parseDocument(text, true)
                value = try toValue(root)
                positions = positionsOf(root)
            } catch let e as YamlLoadError { return fail("not YAML: " + e.message, e.line, e.column) }
            catch { return fail("not YAML: \(error)") }
        }
        var res = AK.o(ActionAuthor.loadActionsValue(value))
        if let p = positions { attachPositions(&res, p) }
        return res
    }

    /// The default YAML front end of `ActionTestRunner.runDefTests`: write the document as YAML text, read it back, load it.
    public static func roundTrip(_ doc: JSONValue) -> JSONValue {
        guard let text = try? YamlEmit.stringify(doc) else { return fail("YAML: the document could not be written") .asValue }
        return .object(loadActionsText(text, "yaml"))
    }
}

private extension JObject { var asValue: JSONValue { .object(self) } }
