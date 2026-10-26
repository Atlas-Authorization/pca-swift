import Foundation

/// An object key compared and hashed by its exact Unicode SCALARS. Swift's `String` ==/hash use canonical
/// equivalence (so "\u{e9}" == "e\u{301}"), which would silently MERGE two distinct JSON keys (NFC vs NFD) in a
/// `[String: _]` dictionary and mis-flag them as duplicates. JSON object keys are compared code point by code point.
public struct JKey: Hashable, ExpressibleByStringLiteral, Comparable, Sendable {
    public let s: String
    public init(_ s: String) { self.s = s }
    public init(stringLiteral v: String) { self.s = v }
    public static func == (a: JKey, b: JKey) -> Bool { a.s.unicodeScalars.elementsEqual(b.s.unicodeScalars) }
    public func hash(into h: inout Hasher) { for u in s.unicodeScalars { h.combine(u.value) } }
    public static func < (a: JKey, b: JKey) -> Bool { a.s.utf8.lexicographicallyPrecedes(b.s.utf8) }
}
public typealias JObject = [JKey: JSONValue]

/// A JSON value with the number split into `int` (integer lexeme) and `double` (fractional lexeme),
/// mirroring how the strict parser classifies numbers. Objects are stored as a dictionary; the strict
/// parser rejects duplicate keys before building one, and canonicalization sorts keys bytewise, so
/// insertion order is never relied upon.
public indirect enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object(JObject)

    var asString: String? { if case let .string(s) = self { return s } else { return nil } }
    var asObject: JObject? { if case let .object(o) = self { return o } else { return nil } }
    var asArray: [JSONValue]? { if case let .array(a) = self { return a } else { return nil } }
    var isObject: Bool { if case .object = self { return true } else { return false } }
    var isArray: Bool { if case .array = self { return true } else { return false } }
    var isNull: Bool { if case .null = self { return true } else { return false } }
    var isNumber: Bool {
        switch self { case .int, .double: return true; default: return false }
    }

    func get(_ key: String) -> JSONValue? { asObject?[JKey(key)] }

    /// A value that is a strictly-valid number AND integer-valued, as a safe Int64 (else nil).
    var safeInt: Int64? {
        switch self {
        case let .int(i):
            return (i >= -Canonical.MAX_SAFE && i <= Canonical.MAX_SAFE) ? i : nil // not abs(): abs(Int64.min) traps
        case let .double(d):
            guard d.isFinite, d.rounded() == d, abs(d) <= Double(Canonical.MAX_SAFE) else { return nil }
            return Int64(d)
        default:
            return nil
        }
    }
}
