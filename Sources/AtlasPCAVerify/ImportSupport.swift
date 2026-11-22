import Foundation

/// Small JSON-tree helpers shared by the importers (an absent member and a JSON null are both "not there").
public enum Jx {
    /// `text.split("\n")`: every line feed separates, also the one inside a CR LF pair (a Swift Character keeps CR LF as one, so Foundation's
    /// `components(separatedBy: "\n")` never splits there), leaving the CR on the end of the line as JavaScript does.
    public static func splitLF(_ s: String) -> [String] {
        var out: [String] = [], cur = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            if u == "\n" { out.append(String(cur)); cur = String.UnicodeScalarView() } else { cur.append(u) }
        }
        out.append(String(cur))
        return out
    }

    static func o(_ v: JSONValue?) -> JObject { v?.asObject ?? [:] }
    static func a(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }
    static func isObj(_ v: JSONValue?) -> Bool { v?.asObject != nil }
    static func isList(_ v: JSONValue?) -> Bool { v?.asArray != nil }
    static func has(_ v: JSONValue?, _ k: String) -> Bool { v?.asObject?[JKey(k)] != nil }
    static func get(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.asObject?[JKey(k)] }
    /// A member that is present and not JSON null (Kotlin's `map[k]` read as a nullable).
    static func nn(_ v: JSONValue?) -> JSONValue? { JS.present(v) }
    /// JavaScript `String(v)` with an absent value spelled "null" (the reference tree has no `undefined`).
    static func str(_ v: JSONValue?) -> String { JS.toString(v ?? .null) }
    static func num(_ v: JSONValue?) -> Double? { IV.num(v) }
    static func n(_ v: Int64) -> JSONValue { .int(v) }
    static func num(_ d: Double) -> JSONValue { d == d.rounded() && abs(d) <= 9007199254740991.0 ? .int(Int64(d)) : .double(d) }
    static func obj(_ kv: KeyValuePairs<String, JSONValue>) -> JObject { var m: JObject = [:]; for (k, v) in kv { m[o: k] = v }; return m }
    static func strs(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }
    static func truthy(_ v: JSONValue?) -> Bool { JS.truthy(v) }
    /// UTF-8 length as the reference measures it: a lone surrogate encodes as U+FFFD (3 bytes).
    static func u8(_ s: String) -> Int { s.unicodeScalars.reduce(0) { $0 + (Canonical.loneUnit($1) != nil ? 3 : UTF8.width($1)) } }
    static func u16(_ s: String) -> Int { s.unicodeScalars.reduce(0) { $0 + (Canonical.loneUnit($1) != nil ? 1 : UTF16.width($1)) } }
    static func utf8(_ s: String) -> [UInt8] { Array(s.utf8) }
    static func sha256(_ b: [UInt8]) -> [UInt8] { Canonical.sha256(b) }
    static func b64u(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }
    static func u16less(_ a: String, _ b: String) -> Bool { ActionBusinessRules.u16less(a, b) }
    public static func sortUniq(_ xs: [String]) -> [String] { Array(Set(xs)).sorted(by: u16less) }
    static func sortUniq(_ v: JSONValue?) -> [String] { sortUniq(a(v).compactMap { $0.asString }) }

    /// `Number.isSafeInteger(v) && !Object.is(v, -0)`.
    static func isInt(_ v: JSONValue?) -> Bool {
        guard let d = IV.num(v), d.isFinite, d == d.rounded(), abs(d) <= 9007199254740991.0 else { return false }
        return !(d == 0 && d.sign == .minus)
    }
    /// `Number.isSafeInteger(v)` (so -0 counts).
    static func isSafe(_ v: JSONValue?) -> Bool {
        guard let d = IV.num(v), d.isFinite, d == d.rounded(), abs(d) <= 9007199254740991.0 else { return false }
        return true
    }

    static func jsSpace(_ c: Unicode.Scalar) -> Bool { Attest.isJSSpace(c) }
    static func jsTrim(_ s: String) -> String { Attest.jsTrim(s) }

    static func sameJson(_ a: JSONValue?, _ b: JSONValue?) -> Bool { AK.sameJson(a, b) }

    /// `{...src}` into `dst`: an object copies its members, a string or array its indexed entries, anything else nothing.
    static func spread(_ dst: inout JObject, _ src: JSONValue?) {
        switch src {
        case let .object(o)?: for k in JS.keyOrder(o) { dst[o: k.s] = o[k] }
        case let .string(s)?: for (i, u) in s.utf16.enumerated() { dst[o: String(i)] = .string(String(decoding: [u], as: UTF16.self)) }
        case let .array(a)?: for (i, v) in a.enumerated() { dst[o: String(i)] = v }
        default: break
        }
    }

    /// `[...x]` of an array or a string (its code points); anything else throws as the engine does.
    static func spreadList(_ x: JSONValue?) throws -> [JSONValue] { try JS.spread(x) }

    /// decodeURIComponent; nil when the engine would throw URIError.
    static func decodeUriComponent(_ s: String) -> String? { s.removingPercentEncoding }
}
