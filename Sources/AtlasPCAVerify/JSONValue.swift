import Foundation
import CoreFoundation

/// A JSON value with the number split into `int` (integer lexeme) and `double` (fractional lexeme),
/// mirroring how the strict parser classifies numbers. Objects are stored as a dictionary; the strict
/// parser rejects duplicate keys before building one, and canonicalization sorts keys bytewise, so
/// insertion order is never relied upon.
public indirect enum JSONValue: Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    var asString: String? { if case let .string(s) = self { return s } else { return nil } }
    var asObject: [String: JSONValue]? { if case let .object(o) = self { return o } else { return nil } }
    var asArray: [JSONValue]? { if case let .array(a) = self { return a } else { return nil } }
    var isObject: Bool { if case .object = self { return true } else { return false } }
    var isArray: Bool { if case .array = self { return true } else { return false } }
    var isNull: Bool { if case .null = self { return true } else { return false } }
    var isNumber: Bool {
        switch self { case .int, .double: return true; default: return false }
    }

    func get(_ key: String) -> JSONValue? { asObject?[key] }

    /// A value that is a strictly-valid number AND integer-valued, as a safe Int64 (else nil).
    var safeInt: Int64? {
        switch self {
        case let .int(i):
            return abs(i) <= Canonical.MAX_SAFE ? i : nil
        case let .double(d):
            guard d.isFinite, d.rounded() == d, abs(d) <= Double(Canonical.MAX_SAFE) else { return nil }
            return Int64(d)
        default:
            return nil
        }
    }

    /// Convert a `JSONSerialization` object tree into a `JSONValue`. Integers vs. doubles are told apart by
    /// the `NSNumber` objCType ('q'/'i'/'l' → integer, 'd'/'f' → double); booleans by `CFBooleanGetTypeID`.
    static func from(foundation any: Any) -> JSONValue {
        if any is NSNull { return .null }
        if let num = any as? NSNumber {
            if CFGetTypeID(num) == CFBooleanGetTypeID() { return .bool(num.boolValue) }
            let t = String(cString: num.objCType)
            if t == "f" || t == "d" { return .double(num.doubleValue) }
            return .int(num.int64Value)
        }
        if let s = any as? String { return .string(s) }
        if let a = any as? [Any] { return .array(a.map { from(foundation: $0) }) }
        if let o = any as? [String: Any] {
            var out: [String: JSONValue] = [:]
            for (k, v) in o { out[k] = from(foundation: v) }
            return .object(out)
        }
        return .null
    }
}
