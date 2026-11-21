import Foundation

/// The few JavaScript value semantics the protocol bridges mirror from the TypeScript reference, over `JSONValue`: truthiness,
/// `String(x)`, `JSON.stringify` (keys in canonical order: a parsed object has no insertion order), array spread and
/// `encodeURIComponent`. A missing member and a JSON null are both "absent" (`?? default`).
public enum JS {
    static func truthy(_ v: JSONValue?) -> Bool {
        switch v {
        case nil, .null?: return false
        case let .bool(b)?: return b
        case let .int(i)?: return i != 0
        case let .double(d)?: return !(d == 0 || d.isNaN)
        case let .string(s)?: return !s.isEmpty
        default: return true
        }
    }

    /// `x ?? fallback`: nil for an absent or null member.
    static func present(_ v: JSONValue?) -> JSONValue? { (v == nil || v == .null) ? nil : v }

    /// `String(x)` (arrays join with ",", objects are "[object Object]").
    static func toString(_ v: JSONValue?) -> String {
        switch v {
        case nil: return "undefined"
        case .null?: return "null"
        case let .bool(b)?: return b ? "true" : "false"
        case let .int(i)?: return String(i)
        case let .double(d)?: return d.isNaN ? "NaN" : d.isInfinite ? (d < 0 ? "-Infinity" : "Infinity") : number(d)
        case let .string(s)?: return s
        case let .array(a)?: return a.map { ($0 == .null) ? "" : toString($0) }.joined(separator: ",")
        case .object?: return "[object Object]"
        }
    }

    /// ECMAScript Number::toString of a finite number (exponent form at >= 1e21 and below 1e-6).
    static func number(_ d: Double) -> String {
        if d == 0 { return "0" }
        let a = abs(d)
        if a >= 1e-6 && a < 1e21 { return Canonical.numberString(d) }
        // the shortest round-trip digits and the decimal exponent, from Swift's description ("1.5e-07", "1e+21")
        var t = "\(a)", exp = 0
        if let e = t.firstIndex(where: { $0 == "e" || $0 == "E" }) { exp = Int(t[t.index(after: e)...]) ?? 0; t = String(t[..<e]) }
        let parts = t.split(separator: ".", omittingEmptySubsequences: false)
        var digits = Array(parts[0] + (parts.count > 1 ? parts[1] : ""))
        exp += parts[0].count - 1
        while digits.count > 1 && digits.first == "0" { digits.removeFirst(); exp -= 1 }
        while digits.count > 1 && digits.last == "0" { digits.removeLast() }
        let mant = digits.count > 1 ? String(digits[0]) + "." + String(digits[1...]) : String(digits)
        return (d < 0 ? "-" : "") + mant + "e" + (exp >= 0 ? "+" : "-") + String(abs(exp))
    }

    /// An array-index key ("0" .. "4294967294" in canonical form): JS objects list these first, ascending.
    static func indexKey(_ k: String) -> UInt32? {
        guard let n = UInt32(k), n < UInt32.max, String(n) == k else { return nil }
        return n
    }

    /// The keys of an object in JavaScript `Object.keys` order: array-index keys ascending, then parser (insertion) order, then
    /// keys added after parsing (no position) in code-unit order.
    public static func keyOrder(_ o: JObject) -> [JKey] {
        let idx = o.keys.compactMap { k in indexKey(k.s).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        let rest = o.keys.filter { indexKey($0.s) == nil }
        let parsed = rest.filter { $0.ord > 0 }.sorted { $0.ord < $1.ord }
        let added = rest.filter { $0.ord == 0 }.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }
        return idx + parsed + added
    }

    /// `JSON.stringify(v)`: compact; a parsed object has no insertion order, so its keys are written index keys first (as JS
    /// does), then those named in `order` (the producer's order), then the rest in code-unit order. -0 is "0".
    public static func stringify(_ v: JSONValue, order: [String] = []) -> String {
        switch v {
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case let .int(i): return String(i)
        case let .double(d): return d.isFinite ? number(d) : "null"
        case .string: return Canonical.canonicalize(v)
        case let .array(a): return "[" + a.map { stringify($0, order: order) }.joined(separator: ",") + "]"
        case let .object(o):
            let ordered = keyOrder(o)
            let idx = ordered.filter { indexKey($0.s) != nil }
            // members of a parsed object keep the order of the text (JS insertion order); `order` ranks only the members added natively
            let parsed = ordered.filter { indexKey($0.s) == nil && $0.ord > 0 }
            let addedKeys = ordered.filter { indexKey($0.s) == nil && $0.ord == 0 }
            let named = order.map { JKey($0) }.filter { k in addedKeys.contains(k) }
            let rest = addedKeys.filter { !order.contains($0.s) }
            return "{" + (idx + parsed + named + rest).map { Canonical.canonicalize(.string($0.s)) + ":" + stringify(o[$0]!, order: order) }.joined(separator: ",") + "}"
        }
    }

    /// `[...v]`: an array is copied, a string spreads into its code points, anything else is not iterable (throws).
    static func spread(_ v: JSONValue?) throws -> [JSONValue] {
        switch v {
        case let .array(a)?: return a
        case let .string(s)?: return s.unicodeScalars.map { .string(String($0)) }
        default: throw JSError("not iterable")
        }
    }

    static func isStringArray(_ v: JSONValue?) -> Bool { v?.asArray?.allSatisfy { $0.asString != nil } ?? false }
    static func isNumberArray(_ v: JSONValue?) -> Bool { v?.asArray?.allSatisfy { $0.isNumber } ?? false }
    static func nonEmptyString(_ v: JSONValue?) -> String? { v?.asString.flatMap { $0.isEmpty ? nil : $0 } }

    /// `encodeURIComponent`: everything but A-Z a-z 0-9 - _ . ! ~ * ' ( ) is percent-encoded as UTF-8.
    static func encodeURIComponent(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            let c = Character(Unicode.Scalar(b))
            if (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || "-_.!~*'()".contains(c) { out.append(c) }
            else { out += String(format: "%%%02X", b) }
        }
        return out
    }

    /// The JS length of a string (UTF-16 code units).
    static func length(_ s: String) -> Int { s.utf16.count }

    /// `Number(x)` (ToNumber): undefined -> NaN, null -> 0, booleans 0 / 1, strings parsed as a JS numeric literal, an array through
    /// its string form, an object -> NaN.
    static func toNumber(_ v: JSONValue?) -> Double {
        switch v {
        case nil: return .nan
        case .null?: return 0
        case let .bool(b)?: return b ? 1 : 0
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        case let .string(s)?: return numberFromString(s)
        case .array?: return numberFromString(toString(v))
        case .object?: return .nan
        }
    }

    /// StringToNumber: trimmed; "" -> 0; [+-]Infinity; 0x / 0o / 0b integers; a decimal literal; anything else NaN.
    static func numberFromString(_ raw: String) -> Double {
        let s = Attest.jsTrim(raw)
        if s.isEmpty { return 0 }
        if s == "Infinity" || s == "+Infinity" { return .infinity }
        if s == "-Infinity" { return -.infinity }
        let b = Array(s.utf8)
        if b.count > 2, b[0] == 0x30 {
            let radixes: [UInt8: Double] = [0x78: 16, 0x58: 16, 0x6f: 8, 0x4f: 8, 0x62: 2, 0x42: 2]
            let radix = radixes[b[1]]
            if let r = radix {
                var n = 0.0
                for c in b[2...] {
                    guard let d = WhatwgURL.hexVal(c), Double(d) < r else { return .nan }
                    n = n * r + Double(d)
                }
                return n
            }
        }
        var i = 0
        if i < b.count, b[i] == 0x2b || b[i] == 0x2d { i += 1 }
        let digitsStart = i
        while i < b.count, b[i] >= 0x30 && b[i] <= 0x39 { i += 1 }
        var digits = i - digitsStart
        if i < b.count, b[i] == 0x2e {
            i += 1
            let f = i
            while i < b.count, b[i] >= 0x30 && b[i] <= 0x39 { i += 1 }
            digits += i - f
        }
        if digits == 0 { return .nan }
        if i < b.count, b[i] == 0x65 || b[i] == 0x45 {
            i += 1
            if i < b.count, b[i] == 0x2b || b[i] == 0x2d { i += 1 }
            let e = i
            while i < b.count, b[i] >= 0x30 && b[i] <= 0x39 { i += 1 }
            if i == e { return .nan }
        }
        return i == b.count ? (Double(s) ?? .nan) : .nan
    }
}

/// A refusal mirrored from a TypeScript `throw` (the message is informative; replay tests compare only that both sides refuse).
public struct JSError: Error, CustomStringConvertible {
    public let message: String
    /// The reference's stable error code where it has one (jose's ERR_*, a package's own codes).
    public let code: String?
    public init(_ message: String, code: String? = nil) { self.message = message; self.code = code }
    public var description: String { message }
}

/// `BigInt(x)` for the values the bridges convert: a string (trimmed; "" is 0; decimal with an optional sign, or 0x / 0o / 0b),
/// an integral number, a boolean, an array (through its string form). nil where the reference throws.
struct JSBigInt: Comparable {
    let neg: Bool
    let mag: BigUInt

    init(neg: Bool, mag: BigUInt) { self.neg = neg && !mag.isZero; self.mag = mag }

    static func of(_ v: JSONValue?) -> JSBigInt? {
        switch v {
        case let .bool(b)?: return JSBigInt(neg: false, mag: BigUInt(b ? 1 : 0))
        case let .int(i)?: return JSBigInt(neg: i < 0, mag: BigUInt(i.magnitude))
        case let .double(d)?:
            guard d.isFinite, d.rounded(.towardZero) == d else { return nil }
            return parse(Canonical.numberString(d))
        case let .string(s)?: return parse(s)
        case .array?: return parse(JS.toString(v))
        default: return nil
        }
    }

    static func parse(_ text: String) -> JSBigInt? {
        var s = Array(Attest.jsTrim(text).unicodeScalars)
        if s.isEmpty { return JSBigInt(neg: false, mag: BigUInt()) }
        var radix: UInt64 = 10, neg = false
        let prefixes: [Unicode.Scalar: UInt64] = ["x": 16, "X": 16, "o": 8, "O": 8, "b": 2, "B": 2]
        if s.count > 2, s[0] == "0", let r = prefixes[s[1]] {
            radix = r; s.removeFirst(2)
        } else if s[0] == "-" || s[0] == "+" {
            neg = s[0] == "-"; s.removeFirst()
            if s.isEmpty { return nil }
        }
        var acc = BigUInt()
        for c in s {
            guard c.isASCII, let d = WhatwgURL.hexVal(UInt8(c.value)), UInt64(d) < radix else { return nil }
            acc = acc * BigUInt(radix) + BigUInt(UInt64(d))
        }
        return JSBigInt(neg: neg, mag: acc)
    }

    static func < (a: JSBigInt, b: JSBigInt) -> Bool {
        if a.neg != b.neg { return a.neg }
        return a.neg ? b.mag < a.mag : a.mag < b.mag
    }

    /// `n.toString(16)` of a non-negative value.
    static func hex(_ n: BigUInt) -> String {
        if n.isZero { return "0" }
        let digits = Array("0123456789abcdef")
        var out = ""
        var i = (n.bitLength + 3) / 4 - 1
        while i >= 0 {
            let v = n.bit(4 * i) | n.bit(4 * i + 1) << 1 | n.bit(4 * i + 2) << 2 | n.bit(4 * i + 3) << 3
            out.append(digits[v]); i -= 1
        }
        return out
    }
}
