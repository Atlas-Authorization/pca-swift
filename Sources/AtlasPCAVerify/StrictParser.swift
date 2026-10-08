import Foundation

/// STRICT JSON profile for signed bytes (wire v2), a hand-written RFC 8259 parser — deliberately
/// INDEPENDENT of `JSONSerialization` so every verifier reaches the same value from the same bytes.
/// Mirrors `strict-json.ts` / the Rust `strict_parse`. Rejects: comments, trailing commas, NaN/Infinity,
/// single quotes, a BOM, non-JSON whitespace; duplicate object keys (post-unescape); lone surrogates
/// (raw or escaped); raw control characters (< U+0020) in strings; unknown escapes; nesting deeper than
/// 32 containers; input longer than 2^20 UTF-8 bytes; and any number not in the canonical wire form.
enum StrictJSON {
    struct ParseError: Error { let message: String }

    static func parse(_ text: String) throws -> JSONValue {
        let bytes = Array(text.utf8)
        if bytes.count > Canonical.MAX_JSON_BYTES { throw ParseError(message: "strict JSON: input too large") }
        var p = Parser(b: bytes)
        let v = try p.value(1)
        p.ws()
        if p.i < p.b.count { throw p.err("trailing characters after the JSON value") }
        return v
    }

    /// A LENIENT RFC 8259 parse used only to load the conformance corpus itself (which is ordinary JSON, not
    /// the strict wire profile: it carries exponent numbers, deep nesting, etc.). Crucially it preserves
    /// string VALUES byte-for-byte — unlike `JSONSerialization`, which silently strips a leading U+FEFF from a
    /// string value and would corrupt the raw `pcactn_json` of the BOM vector. Numbers are classified by
    /// lexeme (integer → `.int`, fractional/exponent → `.double`), avoiding `NSNumber` int/double guesswork.
    static func parseLenient(_ text: String) throws -> JSONValue {
        var p = Parser(b: Array(text.utf8), lenient: true)
        let v = try p.value(1)
        p.ws()
        if p.i < p.b.count { throw p.err("trailing characters after the JSON value") }
        return v
    }

    private struct Parser {
        let b: [UInt8]
        var i = 0
        var lenient = false

        func err(_ m: String) -> ParseError { ParseError(message: "strict JSON: \(m) (at offset \(i))") }
        func peek() -> UInt8? { i < b.count ? b[i] : nil }

        mutating func ws() {
            while let c = peek(), c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d { i += 1 }
        }

        /// `i` points at `u`; reads 4 hex digits, leaves `i` on the last one.
        mutating func hex4() throws -> UInt32 {
            guard i + 4 < b.count else { throw err("bad \\u escape") }
            var v: UInt32 = 0
            for k in 1...4 {
                let c = b[i + k]
                let d: UInt32
                switch c {
                case 0x30...0x39: d = UInt32(c - 0x30)
                case 0x41...0x46: d = UInt32(c - 0x41 + 10)
                case 0x61...0x66: d = UInt32(c - 0x61 + 10)
                default: throw err("bad \\u escape")
                }
                v = (v << 4) | d
            }
            i += 4
            return v
        }

        mutating func string() throws -> String {
            i += 1 // opening quote
            var out = [UInt8]()
            loop: while true {
                guard let c = peek() else { throw err("unterminated string") }
                switch c {
                case 0x22:
                    i += 1
                    break loop
                case 0x00...0x1f:
                    throw err("raw control character in string")
                case 0x5c:
                    i += 1
                    guard let e = peek() else { throw err("unterminated string") }
                    switch e {
                    case 0x22: out.append(0x22)
                    case 0x5c: out.append(0x5c)
                    case 0x2f: out.append(0x2f)
                    case 0x62: out.append(0x08)
                    case 0x66: out.append(0x0c)
                    case 0x6e: out.append(0x0a)
                    case 0x72: out.append(0x0d)
                    case 0x74: out.append(0x09)
                    case 0x75:
                        let hi = try hex4()
                        let cp: UInt32
                        if (0xD800...0xDBFF).contains(hi) {
                            if i + 2 < b.count, b[i + 1] == 0x5c, b[i + 2] == 0x75 {
                                i += 2
                                let lo = try hex4()
                                if !(0xDC00...0xDFFF).contains(lo) { throw err("lone surrogate in string") }
                                cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                throw err("lone surrogate in string")
                            }
                        } else if (0xDC00...0xDFFF).contains(hi) {
                            throw err("lone surrogate in string")
                        } else {
                            cp = hi
                        }
                        guard let scalar = Unicode.Scalar(cp) else { throw err("bad code point") }
                        out.append(contentsOf: Array(String(scalar).utf8))
                    default:
                        throw err("unknown escape")
                    }
                    i += 1
                default:
                    out.append(c)
                    i += 1
                }
            }
            // NB: `String(bytes:encoding:.utf8)` (Foundation) strips a leading U+FEFF BOM from the value —
            // which would corrupt a string whose content legitimately begins with U+FEFF. Use the stdlib
            // UTF-8 decoder (no BOM handling) and validate by round-trip (invalid bytes become U+FFFD).
            let s = String(decoding: out, as: UTF8.self)
            if Array(s.utf8) != out { throw err("invalid UTF-8") }
            return s
        }

        mutating func numberLenient() throws -> JSONValue {
            let start = i
            if peek() == 0x2d { i += 1 }
            while let c = peek(), (0x30...0x39).contains(c) { i += 1 }
            var isFloat = false
            if peek() == 0x2e {
                isFloat = true; i += 1
                while let c = peek(), (0x30...0x39).contains(c) { i += 1 }
            }
            if let c = peek(), c == 0x65 || c == 0x45 {
                isFloat = true; i += 1
                if let s = peek(), s == 0x2b || s == 0x2d { i += 1 }
                while let c = peek(), (0x30...0x39).contains(c) { i += 1 }
            }
            let lex = String(decoding: b[start..<i], as: UTF8.self)
            if !isFloat, let n = Int64(lex) { return .int(n) }
            guard let d = Double(lex) else { throw err("bad number") }
            return .double(d)
        }

        mutating func number() throws -> JSONValue {
            if lenient { return try numberLenient() }
            let start = i
            if peek() == 0x2d { i += 1 } // '-'
            switch peek() {
            case .some(0x30): i += 1 // '0'
            case .some(0x31...0x39):
                while let c = peek(), (0x30...0x39).contains(c) { i += 1 }
            default:
                throw err("bad number")
            }
            var frac = false
            if peek() == 0x2e { // '.'
                i += 1
                guard let c = peek(), (0x30...0x39).contains(c) else { throw err("bad number") }
                while let d = peek(), (0x30...0x39).contains(d) { i += 1 }
                frac = true
            }
            if let c = peek(), c == 0x65 || c == 0x45 { // 'e'/'E'
                throw err("exponent form is not allowed (use a plain decimal)")
            }
            let lex = String(decoding: b[start..<i], as: UTF8.self)
            if lex == "-0" { throw err("negative zero is not allowed") }
            if frac {
                if lex.hasSuffix("0") { throw err("trailing fractional zero is not canonical") }
                let digits = lex.filter { $0 != "-" && $0 != "." }.drop(while: { $0 == "0" })
                if digits.count > Canonical.MAX_DECIMAL_DIGITS { throw err("more than 15 significant digits") }
                guard let v = Double(lex) else { throw err("bad number") }
                if v != 0.0 && abs(v) < 1e-6 { throw err("non-integer magnitude below 1e-6 is not allowed") }
                return .double(v)
            } else {
                let abs = lex.hasPrefix("-") ? String(lex.dropFirst()) : lex
                if abs.count > 16 { throw err("integer outside the safe range") }
                guard let mag = Int64(abs) else { throw err("bad number") }
                if mag > Canonical.MAX_SAFE { throw err("integer outside the safe range") }
                return .int(lex.hasPrefix("-") ? -mag : mag)
            }
        }

        mutating func value(_ depth: Int) throws -> JSONValue {
            ws()
            guard let ch = peek() else { throw err("unexpected end of input") }
            switch ch {
            case 0x7b: // '{'
                if !lenient && depth > Canonical.MAX_JSON_DEPTH { throw err("nesting too deep") }
                i += 1
                var o: [String: JSONValue] = [:]
                ws()
                if peek() == 0x7d { i += 1; return .object(o) }
                while true {
                    ws()
                    if peek() != 0x22 { throw err("expected a string key") }
                    let k = try string()
                    if o[k] != nil { throw err("duplicate key") }
                    ws()
                    if peek() != 0x3a { throw err("expected \":\"") }
                    i += 1
                    o[k] = try value(depth + 1)
                    ws()
                    switch peek() {
                    case 0x2c: i += 1
                    case 0x7d: i += 1; return .object(o)
                    default: throw err("expected \",\" or \"}\"")
                    }
                }
            case 0x5b: // '['
                if !lenient && depth > Canonical.MAX_JSON_DEPTH { throw err("nesting too deep") }
                i += 1
                var a: [JSONValue] = []
                ws()
                if peek() == 0x5d { i += 1; return .array(a) }
                while true {
                    a.append(try value(depth + 1))
                    ws()
                    switch peek() {
                    case 0x2c: i += 1
                    case 0x5d: i += 1; return .array(a)
                    default: throw err("expected \",\" or \"]\"")
                    }
                }
            case 0x22: // '"'
                return .string(try string())
            case 0x2d, 0x30...0x39: // '-' or digit
                return try number()
            default:
                if matches("true") { i += 4; return .bool(true) }
                if matches("false") { i += 5; return .bool(false) }
                if matches("null") { i += 4; return .null }
                throw err("unexpected token")
            }
        }

        func matches(_ kw: String) -> Bool {
            let k = Array(kw.utf8)
            guard i + k.count <= b.count else { return false }
            return Array(b[i..<(i + k.count)]) == k
        }
    }
}
