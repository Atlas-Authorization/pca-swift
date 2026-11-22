import Foundation

/// Small JSON-tree helpers shared by the action-toolkit ports (a JSON null and an absent member are both "not there", like `??`).
enum AK {
    static func o(_ v: JSONValue?) -> JObject { v?.asObject ?? [:] }
    static func arr(_ v: JSONValue?) -> [JSONValue] { v?.asArray ?? [] }
    static func nz(_ v: JSONValue?, _ d: Double) -> Double { IV.num(v) ?? d }
    static func strs(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }
    static func obj(_ kv: KeyValuePairs<String, JSONValue>) -> JSONValue {
        var m: JObject = [:]
        for (k, v) in kv { m[o: k] = v }
        return .object(m)
    }
    /// A member, JSON null counted as absent.
    static func pres(_ o: JObject, _ k: String) -> JSONValue? { JS.present(o[JKey(k)]) }
    /// `JSON.stringify(a.k) === JSON.stringify(b.k)` where a missing member is `undefined`.
    static func sameMember(_ a: JObject, _ b: JObject, _ k: String) -> Bool {
        switch (a[JKey(k)], b[JKey(k)]) {
        case (nil, nil): return true
        case let (x?, y?): return JS.stringify(x) == JS.stringify(y)
        default: return false
        }
    }
    static func sameJson(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?): return JS.stringify(x) == JS.stringify(y)
        default: return false
        }
    }
    /// The reference's `sortKeys`: every object rebuilt with its keys in code-unit order (arrays keep their order), so the compared text does
    /// not depend on the order the members were written in. The rebuilt keys carry no parse position, so `JS.stringify` orders them as JS does.
    static func sortKeysDeep(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .array(a): return .array(a.map(sortKeysDeep))
        case let .object(o):
            var out: JObject = [:]
            for k in o.keys { out[JKey(k.s)] = sortKeysDeep(o[k]!) }
            return .object(out)
        default: return v
        }
    }
    /// `JSON.stringify(sortKeys(a)) === JSON.stringify(sortKeys(b))`: the version diff's comparison of definitions, independent of key order.
    static func sameJsonSorted(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?): return JS.stringify(sortKeysDeep(x)) == JS.stringify(sortKeysDeep(y))
        default: return false
        }
    }
    static func fail(_ code: String, _ msg: String) -> ActionKitError { ActionKitError(code: code, message: msg) }
    static func sortedKeys(_ o: JObject) -> [String] { o.keys.map { $0.s }.sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) } }
}
