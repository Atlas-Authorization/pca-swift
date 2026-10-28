import Foundation

/// The semantic firewall: `tool_schema` caveats (`evaluateToolSchema` of the TypeScript reference, agent-native.ts).
///
/// A `tool_schema` caveat is `{type: "tool_schema", tool, signature_digest?, schema: {props, required?}, schema_digest,
/// binding_digest}`. The argument schema is CLOSED (unknown keys refuse), bounded (depth 8, 256 nodes, 64 properties, 256
/// enum values) and self-consistent (`schema_digest` and `binding_digest` are recomputed). Values follow JavaScript:
/// string lengths count UTF-16 code units, an integer is a finite number without a fraction (3.0 is an integer), `enum` /
/// `const` compare with `===` (a boolean is never a number, numbers compare as doubles). Key presence (not null) decides
/// optional members.
enum ToolSchema {
    static let MAX_SCHEMA_DEPTH = 8
    static let MAX_SCHEMA_NODES = 256
    static let MAX_OBJECT_PROPS = 64
    static let MAX_ENUM_VALUES = 256
    static let DEFAULT_MAX_ARRAY_ITEMS = 256.0
    static let ABSOLUTE_MAX_ARRAY_ITEMS = 4096.0
    static let DEFAULT_MAX_STRING_LEN = 65_536.0
    static let ABSOLUTE_MAX_STRING_LEN = 1_048_576.0
    static let MAX_VALUE_NODES = 10_000

    static let SPEC_KEYS: [(String, [String])] = [
        ("string", ["type", "enum", "const", "minLength", "maxLength", "prefix"]),
        ("number", ["type", "enum", "const", "min", "max"]),
        ("integer", ["type", "enum", "const", "min", "max"]),
        ("boolean", ["type", "enum", "const"]),
        ("object", ["type", "props", "required"]),
        ("array", ["type", "items", "minItems", "maxItems"]),
    ]

    final class Counter { var n = 0 }

    // ---- JavaScript value rules ----

    /// A finite JSON number as a double (never a boolean or a string).
    static func fin(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d.isFinite ? d : nil
        default: return nil
        }
    }

    static func isInt(_ v: JSONValue?) -> Bool { fin(v).map { $0.rounded(.towardZero) == $0 } ?? false }

    static func nonNegInt(_ v: JSONValue?, _ mx: Double) -> Bool {
        guard let f = fin(v) else { return false }
        return f.rounded(.towardZero) == f && f >= 0 && f <= mx
    }

    /// Exact code-point equality of a JSON string member with `s`.
    static func eqs(_ v: JSONValue?, _ s: String) -> Bool {
        if case let .string(x)? = v { return IV.same(x, s) }
        return false
    }

    /// JavaScript `===` on the scalars a schema can hold.
    static func jsEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        let fa = fin(a), fb = fin(b)
        if fa != nil || fb != nil { return fa != nil && fb != nil && fa! == fb! }
        switch (a, b) {
        case let (.bool(x)?, .bool(y)?): return x == y
        case (.bool?, _), (_, .bool?): return false
        case let (.string(x)?, .string(y)?): return IV.same(x, y)
        default: return false
        }
    }

    /// JavaScript `string.length`.
    static func jslen(_ s: String) -> Int { s.utf16.count }

    /// `/^[A-Za-z0-9_]{1,64}$/`
    static func safeName(_ n: String) -> Bool {
        let u = n.unicodeScalars
        guard u.count >= 1 && u.count <= 64 else { return false }
        return u.allSatisfy { c in
            (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5a) || (c.value >= 0x61 && c.value <= 0x7a) || c.value == 0x5f
        }
    }

    /// `JSON.stringify(k)` of a key cut to 48 characters (with an ellipsis), for reasons.
    static func show(_ k: String) -> String {
        let cut = jslen(k) > 48 ? IV.text(k.unicodeScalars.prefix(48)) + "\u{2026}" : k
        return Canonical.canonicalize(.string(cut))
    }

    /// Object keys in a deterministic order (UTF-8 byte order). JSON objects here carry no member order, so when a value
    /// breaks several rules the one reported may differ from the reference's (which follows insertion order); the verdict
    /// never does.
    static func keys(_ o: JObject) -> [JKey] { o.keys.sorted() }

    static func allowedKeys(_ t: String) -> [String]? { SPEC_KEYS.first { IV.same($0.0, t) }?.1 }

    // ---- schema validation ----

    /// Validate a `tool_schema` argument schema; nil when valid, else the reason.
    static func validateArgSchema(_ schema: JSONValue?) -> String? {
        guard case let .object(o)? = schema else { return "schema must be an object" }
        if !o.keys.allSatisfy({ $0 == "props" || $0 == "required" }) { return "unknown schema key" }
        return objectSchemaError(o["props"], o["required"], 1, Counter())
    }

    static func objectSchemaError(_ props: JSONValue?, _ required: JSONValue?, _ depth: Int, _ budget: Counter) -> String? {
        if depth > MAX_SCHEMA_DEPTH { return "schema too deep" }
        budget.n += 1
        if budget.n > MAX_SCHEMA_NODES { return "schema too large" }
        guard case let .object(ps)? = props else { return "props must be an object" }
        if ps.count > MAX_OBJECT_PROPS { return "too many props" }
        for k in keys(ps) {
            if !safeName(k.s) { return "invalid property name '\(IV.text(k.s.unicodeScalars.prefix(32)))'" }
            if let e = specError(ps[k], depth + 1, budget) { return "\(k.s): \(e)" }
        }
        if let r = required {
            guard case let .array(rs) = r, rs.count <= MAX_OBJECT_PROPS else { return "required must be a short array" }
            for x in rs {
                guard case let .string(name) = x, ps[JKey(name)] != nil else { return "required names an undeclared property" }
            }
        }
        return nil
    }

    static func specError(_ specV: JSONValue?, _ depth: Int, _ budget: Counter) -> String? {
        if depth > MAX_SCHEMA_DEPTH { return "schema too deep" }
        budget.n += 1
        if budget.n > MAX_SCHEMA_NODES { return "schema too large" }
        guard case let .object(spec)? = specV, case let .string(t)? = spec["type"], let allowed = allowedKeys(t) else { return "unknown type" }
        if !spec.keys.allSatisfy({ k in allowed.contains { IV.same($0, k.s) } }) { return "unknown spec key" }
        if IV.same(t, "object") {
            budget.n -= 1 // counted once by objectSchemaError
            return objectSchemaError(spec["props"], spec["required"], depth, budget)
        }
        if IV.same(t, "array") {
            if let v = spec["minItems"], !nonNegInt(v, ABSOLUTE_MAX_ARRAY_ITEMS) { return "bad minItems" }
            if let v = spec["maxItems"], !nonNegInt(v, ABSOLUTE_MAX_ARRAY_ITEMS) { return "bad maxItems" }
            if let lo = fin(spec["minItems"]), let hi = fin(spec["maxItems"]), lo > hi { return "minItems > maxItems" }
            return specError(spec["items"], depth + 1, budget)
        }
        func ok(_ v: JSONValue) -> Bool {
            if IV.same(t, "string") { if case let .string(s) = v { return jslen(s) <= 1024 }; return false }
            if IV.same(t, "boolean") { if case .bool = v { return true }; return false }
            return fin(v) != nil && (IV.same(t, "number") || isInt(v))
        }
        if let c = spec["const"], !ok(c) { return "bad const" }
        if let en = spec["enum"] {
            guard case let .array(a) = en, !a.isEmpty, a.count <= MAX_ENUM_VALUES, a.allSatisfy(ok) else { return "bad enum" }
        }
        if IV.same(t, "string") {
            if let v = spec["minLength"], !nonNegInt(v, ABSOLUTE_MAX_STRING_LEN) { return "bad minLength" }
            if let v = spec["maxLength"], !nonNegInt(v, ABSOLUTE_MAX_STRING_LEN) { return "bad maxLength" }
            if let lo = fin(spec["minLength"]), let hi = fin(spec["maxLength"]), lo > hi { return "minLength > maxLength" }
            if let p = spec["prefix"] {
                guard case let .string(ps) = p, jslen(ps) <= 512 else { return "bad prefix" }
            }
        } else if IV.same(t, "number") || IV.same(t, "integer") {
            if let v = spec["min"], fin(v) == nil { return "bad min" }
            if let v = spec["max"], fin(v) == nil { return "bad max" }
            if let lo = fin(spec["min"]), let hi = fin(spec["max"]), lo > hi { return "min > max" }
        }
        return nil
    }

    // ---- value checking ----

    static func checkValue(_ spec: JObject, _ v: JSONValue, _ path: String, _ depth: Int, _ budget: Counter) -> String? {
        if depth > MAX_SCHEMA_DEPTH + 1 { return "\(path): too deep" }
        budget.n += 1
        if budget.n > MAX_VALUE_NODES { return "\(path): too many values" }
        let t = spec["type"]?.asString ?? ""
        if IV.same(t, "object") {
            guard case let .object(o) = v else { return "\(path): expected object" }
            return checkObject(spec["props"]?.asObject ?? [:], spec["required"], o, path, depth, budget)
        }
        if IV.same(t, "array") {
            guard case let .array(a) = v else { return "\(path): expected array" }
            let mx = min(fin(spec["maxItems"]) ?? DEFAULT_MAX_ARRAY_ITEMS, ABSOLUTE_MAX_ARRAY_ITEMS)
            if Double(a.count) > mx { return "\(path): exceeds maxItems" }
            if let lo = fin(spec["minItems"]), Double(a.count) < lo { return "\(path): below minItems" }
            let items = spec["items"]?.asObject ?? [:]
            for (i, x) in a.enumerated() {
                if let e = checkValue(items, x, "\(path)[\(i)]", depth + 1, budget) { return e }
            }
            return nil
        }
        if IV.same(t, "string") {
            guard case let .string(s) = v else { return "\(path): wrong type (expected string)" }
            let n = Double(jslen(s))
            if n > min(fin(spec["maxLength"]) ?? DEFAULT_MAX_STRING_LEN, ABSOLUTE_MAX_STRING_LEN) { return "\(path): exceeds maxLength" }
            if let lo = fin(spec["minLength"]), n < lo { return "\(path): below minLength" }
            if case let .string(p)? = spec["prefix"], !s.unicodeScalars.starts(with: p.unicodeScalars) { return "\(path): violates prefix" }
        } else if IV.same(t, "number") || IV.same(t, "integer") {
            guard let f = fin(v), !(IV.same(t, "integer") && f.rounded(.towardZero) != f) else { return "\(path): wrong type (expected \(t))" }
            if let lo = fin(spec["min"]), f < lo { return "\(path): below min" }
            if let hi = fin(spec["max"]), f > hi { return "\(path): above max" }
        } else if IV.same(t, "boolean") {
            guard case .bool = v else { return "\(path): wrong type (expected boolean)" }
        } else {
            return "\(path): unknown type"
        }
        if let c = spec["const"], !jsEq(c, v) { return "\(path): violates const" }
        if let en = spec["enum"], !(en.asArray ?? []).contains(where: { jsEq($0, v) }) { return "\(path): violates enum" }
        return nil
    }

    static func checkObject(_ props: JObject, _ required: JSONValue?, _ obj: JObject, _ path: String, _ depth: Int, _ budget: Counter) -> String? {
        let ks = keys(obj)
        for k in ks where props[k] == nil { return "\(path): unexpected argument \(show(k.s))" }
        for r in required?.asArray ?? [] {
            if case let .string(name) = r, obj[JKey(name)] == nil { return "\(path): missing required argument '\(name)'" }
        }
        for k in ks {
            if let e = checkValue(props[k]?.asObject ?? [:], obj[k] ?? .null, "\(path).\(k.s)", depth + 1, budget) { return e }
        }
        return nil
    }

    static func evaluate(_ caveat: JSONValue?, _ call: PCA.ToolCall?) -> (ok: Bool, reason: String?) {
        guard case let .object(c)? = caveat, eqs(c["type"], "tool_schema"), case let .string(tool)? = c["tool"], !tool.isEmpty else {
            return (false, "malformed tool_schema caveat")
        }
        if let e = validateArgSchema(c["schema"]) { return (false, "malformed tool_schema caveat: \(e)") }
        guard let schema = c["schema"], case let .object(so) = schema, let sd = IV.strictHash(schema) else {
            return (false, "evaluation error (fail closed)")
        }
        if !eqs(c["schema_digest"], sd) { return (false, "schema digest mismatch") }
        let sig = c["signature_digest"].map { IntentV2.jsString($0) } ?? "undefined"
        guard let bd = IV.strictHash(.object(["tool": .string(tool), "signature_digest": .string(sig), "schema": schema])) else {
            return (false, "evaluation error (fail closed)")
        }
        if !eqs(c["binding_digest"], bd) { return (false, "binding digest mismatch") }
        guard let call = call, case let .object(args) = call.args else { return (false, "malformed call") }
        if !IV.same(call.tool, tool) { return (false, "tool \(show(call.tool)) not authorized") }
        if let d = call.toolSignatureDigest, !eqs(c["signature_digest"], d) {
            return (false, "signed tool_binding differs from the authorized tool signature")
        }
        if let e = checkObject(so["props"]?.asObject ?? [:], so["required"], args, "args", 1, Counter()) { return (false, e) }
        return (true, nil)
    }
}
