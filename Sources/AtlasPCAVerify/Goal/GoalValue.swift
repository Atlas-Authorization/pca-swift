import Foundation

/// A value that is not exactly a Goal IR value, or a malformed compiler tape.
public struct IrError: Error, CustomStringConvertible {
    public let message: String
    public init(_ m: String) { self.message = "pca-goal: " + m }
    public var description: String { message }
}

/// Small JSON-shaped value helpers shared by the goal modules (a Goal is a `JSONValue.object`, like the TypeScript objects).
/// A parsed object keeps no member order: where the reference's output order matters, a port carries an explicit key list
/// (see `JS.stringify(_:order:)`); `GV.stable` is the sorted-key form used for digests and comparison keys.
enum GV {
    static let MAX_SAFE: Int64 = 9007199254740991

    static func m(_ v: JSONValue?) -> JObject? { v?.asObject }
    static func l(_ v: JSONValue?) -> [JSONValue]? { v?.asArray }

    /// A required object member (IrError when the value is not an object).
    static func obj(_ v: JSONValue?, _ what: String) throws -> JObject {
        guard let o = v?.asObject else { throw IrError("\(what) expected an object") }
        return o
    }

    static func arr(_ v: JSONValue?, _ what: String = "") throws -> [JSONValue] {
        guard let a = v?.asArray else { throw IrError("array expected" + (what.isEmpty ? "" : " (\(what))")) }
        return a
    }

    static func get(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.asObject?[JKey(k)] }
    static func has(_ v: JSONValue?, _ k: String) -> Bool { v?.asObject?[JKey(k)] != nil }

    /// The string at `k`; IrError unless it is a string.
    static func str(_ v: JSONValue?, _ k: String) throws -> String {
        guard let s = get(v, k)?.asString else { throw IrError("string expected") }
        return s
    }

    /// The discriminant `k` of a value ("" when absent or not a string).
    static func kind(_ v: JSONValue?) -> String { get(v, "k")?.asString ?? "" }

    /// Safe-integer value of a JSON number (nil for -0, non-integers, beyond 2^53-1).
    static func safeInt(_ v: JSONValue?) -> Int64? { IV.int(v) }

    /// The number as a JavaScript double, or nil when it is not a number.
    static func dbl(_ v: JSONValue?) -> Double? { IV.num(v) }

    /// A number that is a JSON number (strict: strings and booleans are not numbers).
    static func strictNum(_ v: JSONValue?) -> Double? { IV.num(v) }

    static func num(_ i: Int) -> JSONValue { .int(Int64(i)) }
    static func num(_ i: Int64) -> JSONValue { .int(i) }

    static func obj(_ kv: [(String, JSONValue)]) -> JSONValue {
        var o = JObject()
        for (k, v) in kv { o[JKey(k)] = v }
        return .object(o)
    }

    static func strs(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }

    /// JSON.stringify of a string (the platform escaping: short forms, \u00XX below 0x20).
    static func q(_ s: String) -> String { Canonical.canonicalize(.string(s)) }

    /// JSON.stringify with every key in UTF-16 code-unit order (no index-key-first rule, no insertion order exists): the comparison-key form.
    static func stable(_ v: JSONValue?) -> String {
        return PCAGoalNormalize.stable(v)
    }

    /// The same, as a single-argument alias used where the reference calls JSON.stringify on a value.
    static func stringify(_ v: JSONValue?) -> String { stable(v) }

    /// JSON.stringify of a value used as a quoted label (strings quoted, everything else as its JSON text).
    static func quote(_ v: JSONValue?) -> String { stable(v) }

    /// UTF-16 code-unit ordering (JavaScript `<` on strings).
    static func less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }
    static func cmp(_ a: String, _ b: String) -> Int { IV.same(a, b) ? 0 : (less(a, b) ? -1 : 1) }

    static func truthy(_ v: JSONValue?) -> Bool { JS.truthy(v) }
    static func toNum(_ v: JSONValue?) -> Double { JS.toNumber(v) }
    /// JavaScript String(v) (template-literal interpolation).
    static func jsStr(_ v: JSONValue?) -> String { JS.toString(v) }
}
