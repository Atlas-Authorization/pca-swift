import Foundation

/// JavaScript property-access and comparison semantics over `JSONValue`, for the ports whose reference runs over hostile
/// (untyped) input: a property read on any value, `Object.keys` order, relational comparison, a stable `Array.prototype.sort`
/// whose comparator may throw. `nil` is `undefined`; `.null` is `null`.
///
/// shortcut: a parsed object keeps no insertion order, so `keys` lists the array-index keys ascending (as JS does) and the other
/// keys in UTF-16 code-unit order; a hostile object with two non-index unknown members may name the other one first.
enum JSLoose {
    /// `o[k]` without throwing: nil for an absent member or a value without members.
    static func get(_ o: JSONValue?, _ k: String) -> JSONValue? {
        switch o {
        case let .object(d)?: return d[JKey(k)]
        case let .array(a)?:
            if k == "length" { return .int(Int64(a.count)) }
            if let i = JS.indexKey(k), Int(i) < a.count { return a[Int(i)] }
            return nil
        case let .string(s)?:
            let u = Array(s.utf16)
            if k == "length" { return .int(Int64(u.count)) }
            if let i = JS.indexKey(k), Int(i) < u.count { return .string(String(utf16CodeUnits: [u[Int(i)]], count: 1)) }
            return nil
        default: return nil
        }
    }

    /// `o[k]` where `o` must not be null or undefined (a TypeError otherwise).
    static func rd(_ o: JSONValue?, _ k: String) throws -> JSONValue? {
        guard let o = o, o != .null else { throw JSError("cannot read '\(k)' of \(o == nil ? "undefined" : "null")") }
        return get(o, k)
    }

    /// `Object.keys(o)`: array-index keys ascending first, then the members in insertion order.
    static func keys(_ o: JSONValue?) -> [String] {
        switch o {
        case let .object(d)?:
            return JS.keyOrder(d).map { $0.s } // index keys ascending, then the written (insertion) order, then members added in code
            
        case let .array(a)?: return a.indices.map { String($0) }
        case let .string(s)?: return (0..<s.utf16.count).map { String($0) }
        default: return []
        }
    }

    /// A plain object (not an array, not null).
    static func isObj(_ v: JSONValue?) -> Bool { v?.isObject ?? false }

    /// `typeof v === 'number'` (any JSON number).
    static func isNum(_ v: JSONValue?) -> Bool { v?.isNumber ?? false }

    /// `Number.isSafeInteger(v) && !Object.is(v, -0)`.
    static func isInt(_ v: JSONValue?) -> Bool {
        switch v {
        case let .int(i)?: return i >= -Canonical.MAX_SAFE && i <= Canonical.MAX_SAFE
        case let .double(d)?: return d.isFinite && d.rounded() == d && abs(d) <= Double(Canonical.MAX_SAFE) && !(d == 0 && d.sign == .minus)
        default: return false
        }
    }

    /// `v === 1` for a number.
    static func isOne(_ v: JSONValue?) -> Bool { IV.num(v) == 1 }

    /// ToPrimitive of a JSON value: an array through its string form, an object as "[object Object]".
    static func prim(_ v: JSONValue?) -> JSONValue? {
        switch v {
        case .array?, .object?: return .string(JS.toString(v))
        default: return v
        }
    }

    /// JS `a < b` (false when either side is NaN).
    static func lt(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        let x = prim(a), y = prim(b)
        if case let .string(s)? = x, case let .string(t)? = y { return s.utf16.lexicographicallyPrecedes(t.utf16) }
        return JS.toNumber(x) < JS.toNumber(y)
    }

    static func gt(_ a: JSONValue?, _ b: JSONValue?) -> Bool { lt(b, a) }

    /// JS `a <= b` (false when either side is NaN).
    static func le(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        let x = prim(a), y = prim(b)
        if case .string? = x, case .string? = y { return !lt(y, x) }
        return JS.toNumber(x) <= JS.toNumber(y)
    }

    /// `a < b ? -1 : a > b ? 1 : 0`.
    static func cmp(_ a: JSONValue?, _ b: JSONValue?) -> Double { lt(a, b) ? -1 : gt(a, b) ? 1 : 0 }

    /// `a - b` (ToNumber on both sides).
    static func sub(_ a: JSONValue?, _ b: JSONValue?) -> Double { JS.toNumber(a) - JS.toNumber(b) }

    /// `first || rest()` for numbers: zero and NaN are falsy.
    static func or(_ first: Double, _ rest: () throws -> Double) rethrows -> Double { (first != 0 && !first.isNaN) ? first : try rest() }

    /// `{...v}`: an object's own members, an array's or a string's indices, nothing for any other value (never throws).
    static func spread(_ v: JSONValue?) -> JObject {
        switch v {
        case let .object(d)?: return d
        case let .array(a)?: return Dictionary(uniqueKeysWithValues: a.enumerated().map { (JKey(String($0.offset)), $0.element) })
        case let .string(s)?: return Dictionary(uniqueKeysWithValues: s.unicodeScalars.enumerated().map { (JKey(String($0.offset)), JSONValue.string(String($0.element))) })
        default: return [:]
        }
    }

    /// `const {a, ...rest} = v`: the rest members; null and undefined throw.
    static func rest(_ v: JSONValue?, without k: String) throws -> JObject {
        guard let v = v, v != .null else { throw JSError("cannot destructure") }
        var m = spread(v)
        m[JKey(k)] = nil
        return m
    }

    /// A stable `Array.prototype.sort`: the comparator's sign decides (> 0 swaps); it is never called for fewer than two items.
    static func sort(_ a: [JSONValue], _ cmp: (JSONValue, JSONValue) throws -> Double) throws -> [JSONValue] {
        if a.count < 2 { return a }
        let mid = a.count / 2
        let l = try sort(Array(a[..<mid]), cmp), r = try sort(Array(a[mid...]), cmp)
        var out: [JSONValue] = []
        out.reserveCapacity(a.count)
        var i = 0, j = 0
        while i < l.count && j < r.count {
            if try cmp(l[i], r[j]) > 0 { out.append(r[j]); j += 1 } else { out.append(l[i]); i += 1 }
        }
        out += l[i...]
        out += r[j...]
        return out
    }

    /// `x.sort(cmp)` on a member that must be an array (anything else is "sort is not a function").
    static func sortMember(_ x: JSONValue?, _ cmp: (JSONValue, JSONValue) throws -> Double) throws -> JSONValue {
        guard case let .array(a)? = x else { throw JSError("sort is not a function") }
        return .array(try sort(a, cmp))
    }

    /// `JSON.parse(JSON.stringify(v))`: a deep copy in which -0 becomes 0.
    static func plain(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .double(d): return d == 0 ? .int(0) : v
        case let .array(a): return .array(a.map(plain))
        case let .object(o): return .object(o.mapValues(plain))
        default: return v
        }
    }
}
