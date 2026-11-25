import Foundation

/// Starter packs a platform can begin from: typical actions of five business types in the authoring YAML form, with custom traits and business rules (and
/// their examples). Every action is an AUTHORED draft: a template never confirms anything. The namespace is the platform's choice (verbs, resource types
/// and custom trait ids are derived from it). The text is the reference's, embedded verbatim with the namespace substituted.
public enum ActionTemplates {
    private static let all: [JSONValue] = AK.arr((try? StrictJSON.parseLenient(ActionData.TEMPLATES)) ?? .null)

    /// The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`.
    private static func checkNs(_ ns: JSONValue?) throws -> String {
        guard let s = ns?.asString, Actions.fullMatch("[a-z][a-z0-9_]{0,31}", s) else { throw ActionKitError(code: "bad_ns", message: "ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)") }
        if s == "pca" { throw ActionKitError(code: "bad_ns", message: "the namespace 'pca' is reserved for core traits") }
        return s
    }

    private static func subst(_ v: JSONValue, _ ns: String) -> JSONValue {
        switch v {
        case let .string(s): return .string(s.replacingOccurrences(of: ActionData.PLACEHOLDER_NS, with: ns))
        case let .array(a): return .array(a.map { subst($0, ns) })
        case let .object(o): return .object(o.mapValues { subst($0, ns) })
        default: return v
        }
    }

    /// The starter templates, as `{id, title, description, ns}` (use `traits` and `yaml` for the namespace-bound parts).
    public static func starterTemplates() -> [JSONValue] {
        all.map { t in AK.obj(["id": t.get("id") ?? .null, "title": t.get("title") ?? .null, "description": t.get("description") ?? .null, "ns": t.get("ns") ?? .null]) }
    }

    /// The starter template with this id, or nil.
    public static func starterTemplate(_ id: String?) -> JObject? {
        starterTemplates().first { $0.get("id") == id.map { .string($0) } }.map { AK.o($0) }
    }

    private static func raw(_ id: String?) throws -> JSONValue {
        if let t = all.first(where: { $0.get("id") == id.map { .string($0) } }) { return t }
        throw ActionKitError(code: "unknown_template", message: "no starter template '\(id ?? "null")'")
    }

    /// The pack's custom traits under namespace `ns` (ids `<ns>.<name>`).
    public static func traits(_ id: String?, _ ns: JSONValue?) throws -> [JSONValue] {
        let n = try checkNs(ns)
        return AK.arr(subst(try raw(id).get("traits") ?? .null, n))
    }

    /// The authoring YAML under namespace `ns`, with `rules:` blocks and their examples.
    public static func yaml(_ id: String?, _ ns: JSONValue?) throws -> String {
        let n = try checkNs(ns)
        return JS.toString(try raw(id).get("yaml")).replacingOccurrences(of: ActionData.PLACEHOLDER_NS, with: n)
    }
}
