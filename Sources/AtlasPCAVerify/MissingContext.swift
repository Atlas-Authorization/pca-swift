import Foundation

/// TYPED MISSING CONTEXT and the STORED-WINS merge: when a permit condition cannot be decided because a value is absent, the decision
/// names what is missing and who may supply it (escalate), or denies when only the agent could say it. Request-supplied context never
/// replaces a value bound by the grant or chain. Port of packages/pca/src/missing-context.ts; replays
/// packages/pca/conformance/missing-context-vectors.json. Everything is total: any failure is a deny.
public enum MissingContext {
    public static let SUPPLIERS = ["principal", "discharge_issuer", "rs_observation", "agent_declared_untrusted"]

    public struct Missing: Equatable {
        public var path: String
        public var supplier: String
    }

    /// `context` is the merged context; `conflicts` and `dropped` are sorted by path.
    public struct Bound: Equatable {
        public var context: JSONValue
        public var conflicts: [String]
        public var dropped: [String]
    }

    public struct Typed: Equatable {
        public var decision: String
        public var reason: String? = nil
        public var missing: [Missing] = []
    }

    static func u16Less(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    /// The longest table key equal to `path` or a prefix of it at a segment boundary; none is `principal`.
    public static func supplierOf(_ path: String, table: JObject) -> String {
        var best: String? = nil
        for k in table.keys {
            let matches = IV.same(path, k.s) || IV.startsWith(path, k.s + ".")
            if matches, best == nil || k.s.utf16.count > (best ?? "").utf16.count { best = k.s }
        }
        guard let b = best else { return "principal" }
        return table[JKey(b)]?.asString ?? "principal"
    }

    private static func identOK(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard let f = u.first, (f >= 65 && f <= 90) || (f >= 97 && f <= 122) || f == 95 else { return false }
        return u.allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 95 }
    }

    /// `^(action\.params|subject|env)(\.[A-Za-z_][A-Za-z0-9_]*)*$` and no forbidden segment.
    private static func pathOK(_ k: String) -> Bool {
        let segs = IV.split(k, ".")
        var rest = segs.dropFirst()
        if segs.count >= 2 && segs[0] == "action" && segs[1] == "params" { rest = segs.dropFirst(2) } else if !(segs[0] == "subject" || segs[0] == "env") { return false }
        return rest.allSatisfy { identOK($0) && !IV.FORBIDDEN_SEGMENTS.contains($0) }
    }

    /// nil = a well-formed table.
    public static func supplierTableError(_ t: JSONValue?) -> String? {
        guard let m = t?.asObject else { return "the supplier table must be an object" }
        for k in m.keys.sorted() {
            if !pathOK(k.s) { return "bad supplier path '\(k.s)'" }
            guard let v = m[k]?.asString, SUPPLIERS.contains(v) else { return "bad supplier for '\(k.s)'" }
        }
        return nil
    }

    /// Flatten a plain-object tree into dotted leaf paths. Arrays and non-objects are leaves.
    private static func leaves(_ v: JSONValue, _ prefix: String, _ out: inout [String: JSONValue], _ depth: Int = 0) {
        if depth > 16 { out[prefix] = v; return }
        if let o = v.asObject, !o.isEmpty {
            for k in o.keys.map({ $0.s }).sorted(by: u16Less) where !IV.FORBIDDEN_SEGMENTS.contains(k) {
                leaves(o[JKey(k)] ?? .null, prefix + "." + k, &out, depth + 1)
            }
        } else {
            out[prefix] = v
        }
    }

    private static func setPath(_ node: JSONValue, _ segs: ArraySlice<String>, _ value: JSONValue) -> JSONValue {
        var o = node.asObject ?? [:]
        guard let head = segs.first else { return value }
        let key = JKey(head)
        if segs.count == 1 {
            o[key] = value
        } else {
            let child = o[key]
            o[key] = setPath(child?.isObject == true ? (child ?? .null) : .object([:]), segs.dropFirst(), value)
        }
        return .object(o)
    }

    /// Merge `supplied` into `bound`. Bound wins. nil where the reference throws (callers fail closed).
    public static func bindContext(_ bound: JSONValue, supplied: JSONValue?, table: JObject = [:]) -> Bound? {
        guard var root = bound.asObject else { return nil }
        var conflicts: [String] = []
        var dropped: [String] = []
        guard let sup = supplied?.asObject else { return Bound(context: .object(root), conflicts: conflicts, dropped: dropped) }
        var flat: [String: JSONValue] = [:]
        if let ap = sup[JKey("action")]?.get("params"), ap.isObject { leaves(ap, "action.params", &flat) }
        if let s = sup[JKey("subject")], s.isObject { leaves(s, "subject", &flat) }
        if let e = sup[JKey("env")], e.isObject { leaves(e, "env", &flat) }
        for path in flat.keys.sorted(by: u16Less) {
            let value = flat[path] ?? .null
            if supplierOf(path, table: table) == "agent_declared_untrusted" { dropped.append(path); continue }
            if let cur = Predicates.resolve(.object(root), path) {
                guard let x = IV.strictHash(.object([JKey("v"): cur])), let y = IV.strictHash(.object([JKey("v"): value])) else { return nil }
                if x != y { conflicts.append(path) }
                continue
            }
            let segs = IV.split(path, ".")
            var blocked = false
            if segs.count > 2 {
                for i in 2..<segs.count {
                    if let above = Predicates.resolve(.object(root), segs[0..<i].joined(separator: ".")), !above.isObject { blocked = true }
                }
            }
            if blocked { conflicts.append(path); continue }
            if IV.startsWith(path, "action.params") {
                var action = root[JKey("action")] ?? .null
                if action.isNull { action = .object([JKey("verb"): .string(""), JKey("resource"): .string("")]) }
                guard var am = action.asObject else { return nil }
                if am[JKey("params")]?.isObject != true { am[JKey("params")] = .object([:]) }
                root[JKey("action")] = .object(am)
            }
            guard let next = setPath(.object(root), segs[...], value).asObject else { return nil }
            root = next
        }
        return Bound(context: .object(root), conflicts: conflicts, dropped: dropped)
    }

    private static func collect(_ c: JSONValue, _ ctx: JSONValue, _ out: inout Set<String>, _ ill: inout Bool, _ budget: SafeRegex.Budget, _ depth: Int = 0) {
        guard depth <= 64, c.isObject || c.isArray else { ill = true; return }
        if let o = c.asObject, Predicates.isGroup(o) {
            let kids: JSONValue = o[JKey("all_of")] ?? o[JKey("any_of")] ?? .array([o[JKey("not")] ?? .null])
            guard let kl = kids.asArray, !kl.isEmpty else { ill = true; return }
            for k in kl { collect(k, ctx, &out, &ill, budget, depth + 1) }
            return
        }
        if Predicates.conditionTri(c, ctx, budget) != .u { return }
        var absent = false
        if let o = c.asObject {
            for key in ["field", "ref"] {
                if let p = o[JKey(key)]?.asString, !p.isEmpty, Predicates.resolve(ctx, p) == nil { out.insert(p); absent = true }
            }
            if let f = o[JKey("field")]?.asString, IV.same(f, "action.params") || IV.startsWith(f, "action.params."), !Predicates.paramsPresent(ctx) {
                out.insert(f)
                absent = true
            }
        }
        if !absent { ill = true }
    }

    /// Decide a permit condition list (implicit AND) over the bound context plus whatever the request supplied.
    public static func decideWithMissing(where conditions: JSONValue?, bound: JSONValue?, supplied: JSONValue? = nil, suppliers: JSONValue? = nil) -> Typed {
        func deny(_ reason: String, _ missing: [Missing] = []) -> Typed { Typed(decision: "deny", reason: reason, missing: missing) }
        guard let bm = bound?.asObject, bm[JKey("action")]?.isObject == true else { return deny("bad_context") }
        let tableValue: JSONValue = (suppliers == nil || suppliers == .null) ? .object([:]) : (suppliers ?? .null)
        if let te = supplierTableError(tableValue) { return deny("bad supplier table: \(te)") }
        let table = tableValue.asObject ?? [:]
        guard case let .array(wl)? = conditions, !wl.isEmpty else { return deny("condition_false") }
        guard let b = bindContext(.object(bm), supplied: supplied, table: table) else { return deny("evaluation error (fail closed)") }
        if !b.conflicts.isEmpty { return deny("context_shadow: " + b.conflicts.joined(separator: ",")) }
        let budget = SafeRegex.Budget()
        switch Predicates.conditionTri(.object([JKey("all_of"): .array(wl)]), b.context, budget) {
        case .t: return Typed(decision: "allow")
        case .f: return deny("condition_false")
        case .u: break
        }
        var paths = Set<String>()
        var ill = false
        for c in wl { collect(c, b.context, &paths, &ill, budget) }
        if paths.isEmpty || ill { return deny("ill_typed_context") }
        let missing = paths.sorted(by: u16Less).map { Missing(path: $0, supplier: supplierOf($0, table: table)) }
        let untrusted = missing.filter { $0.supplier == "agent_declared_untrusted" }
        if !untrusted.isEmpty { return deny("missing_context_untrusted: " + untrusted.map { $0.path }.joined(separator: ","), missing) }
        return Typed(decision: "escalate", reason: "escalate: missing_context " + missing.map { $0.supplier + ":" + $0.path }.joined(separator: ","), missing: missing)
    }
}
