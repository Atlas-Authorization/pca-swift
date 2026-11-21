import Foundation

/// The import registry's output side: the YAML an `import` writes.
public enum ImportRegistry {
    /// The YAML an import writes: `{ns, actions: [def...]}` with each def written in full form. `rules` (verb to a business-rules value; may be nil)
    /// re-attaches each action's rules block (the loader keeps rules apart from the def), so a rewrite (confirm, sync) never drops them. The text is byte for
    /// byte what the reference's YAML writer produces (see `YamlEmit`), ending in a newline.
    public static func defsToYaml(_ ns: String, _ defs: [JObject], _ rules: JObject? = nil) throws -> String {
        var rn: [String: YamlEmit.Node] = [:]
        for (k, v) in rules ?? [:] { rn[k.s] = try YamlEmit.node(v) }
        return try defsToYaml(ns, try defs.map { d in
            guard case let .map(m) = try YamlEmit.node(.object(d)) else { throw JSError("a def is an object") }
            return m
        }, rn)
    }

    /// The same over `YamlEmit.Node` graphs, where a container that two places hold is one instance (written once with an anchor, then as an alias).
    public static func defsToYaml(_ ns: String, _ defs: [YamlEmit.Map], _ rules: [String: YamlEmit.Node]?) throws -> String {
        var actions: [YamlEmit.Node] = []
        for d in defs {
            var verb: String? = nil
            for (k, v) in d.members where k == "verb" { if case let .string(s) = v { verb = s } else { verb = nil } }
            if let r = rules, let v = verb, let rv = r[v] {
                var members = d.members
                if let at = members.firstIndex(where: { $0.0 == "rules" }) { members[at] = ("rules", rv) } else { members.append(("rules", rv)) }
                actions.append(.map(YamlEmit.Map(members)))
            } else { actions.append(.map(d)) }
        }
        return try YamlEmit.stringify(.map(YamlEmit.Map([("ns", .string(ns)), ("actions", .seq(YamlEmit.Seq(actions)))])))
    }
}
