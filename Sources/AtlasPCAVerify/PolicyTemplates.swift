import Foundation

/// Policy templates and a fluent authoring builder: the deterministic backbone of "natural language to policy". A request maps onto a named ROLE
/// template (read-only, support agent, finance bot, dev assistant) or is composed with the typed builder; both compile through the facade's
/// `compilePolicy`, so what you author is exactly what the verifier enforces. Pure.
public enum PCAPolicyTemplates {
    /// A named role template: permissions (connector to actions, in order), optional limits and risk-policy members.
    public struct Template {
        public let name: String
        public let description: String
        public let permissions: [(String, [String])]
        public let limits: [String: String]?
        public let riskPolicy: JObject?
    }

    /// The built-in role templates: conservative starting points, meant to be narrowed, not widened.
    public static let templates: [Template] = [
        Template(name: "read-only", description: "Read access only \u{2014} no side effects anywhere.",
                 permissions: [("github", ["read"]), ("slack", ["read"]), ("files", ["read"]), ("http", ["get"])], limits: nil, riskPolicy: nil),
        Template(name: "support-agent", description: "Draft + send customer email and post to Slack, rate-limited.",
                 permissions: [("gmail", ["draft", "send"]), ("slack", ["post_message"])], limits: ["send": "50/day", "post_message": "100/day"], riskPolicy: nil),
        Template(name: "finance-bot", description: "Issue reversible refunds within a daily cap; no payouts.",
                 permissions: [("stripe", ["refund"])], limits: ["refund": "$500/day"], riskPolicy: nil),
        Template(name: "dev-assistant", description: "Read repos, open PRs and comment \u{2014} never merge or delete.",
                 permissions: [("github", ["read", "create_pr", "comment"])], limits: ["create_pr": "20/day"], riskPolicy: nil),
    ]

    public static func listTemplates() -> [Template] { templates }

    static func template(_ name: String) -> Template? { templates.first { IV.same($0.name, name) } }

    /// Inputs of `fromTemplate`; the override members (permissions, limits, riskPolicy, agentBinding, budgetModel) replace the template's.
    public struct FromTemplateOptions {
        public var principal: PCASuiteKey
        public var goal: String
        public var aud: String?
        public var holder: PCASuiteKey?
        public var now: Int64?
        public var permissions: [(String, [String])]?
        public var limits: [String: String]?
        public var riskPolicy: JObject?
        public var agentBinding: JObject?
        public var budgetModel: String?
        public init(principal: PCASuiteKey, goal: String, aud: String? = nil, holder: PCASuiteKey? = nil, now: Int64? = nil) {
            self.principal = principal; self.goal = goal; self.aud = aud; self.holder = holder; self.now = now
        }
    }

    /// Mint an agent from a named template. Throws on an unknown template.
    public static func fromTemplate(_ name: String, _ o: FromTemplateOptions) throws -> PCAFacadeAgent {
        guard let t = template(name) else { throw JSError("fromTemplate: unknown template '\(name)' (have: \(templates.map { $0.name }.joined(separator: ", ")))") }
        return try PCAAgent.fromPrincipal(PCAAgentOptions(
            principal: o.principal, goal: o.goal, permissions: o.permissions ?? t.permissions, limits: o.limits ?? t.limits, holder: o.holder,
            agentBinding: o.agentBinding, riskPolicy: o.riskPolicy ?? t.riskPolicy, budgetModel: o.budgetModel, aud: o.aud, now: o.now))
    }

    /// The output of `PolicyBuilder.build`: permissions, limits and an optional risk-policy override.
    public struct BuiltPolicy {
        public let permissions: [(String, [String])]
        public let limits: [String: String]
        public let riskPolicy: JObject?
    }

    /// A typed, chainable policy builder: `PCAPolicyTemplates.policy().allow("stripe", ["refund"]).limit("refund", "$500/day")`.
    public struct PolicyBuilder {
        private var perms: [(String, [String])] = []
        private var lims: [String: String] = [:]
        private var riskOverride: JObject?

        public init() {}

        /// Start from a named template (its permissions, limits and risk seed the builder).
        public static func from(_ name: String) throws -> PolicyBuilder {
            guard let t = template(name) else { throw JSError("PolicyBuilder.from: unknown template '\(name)'") }
            var b = PolicyBuilder()
            for (c, acts) in t.permissions { b = b.allow(c, acts) }
            for (k, v) in t.limits ?? [:] { b = b.limit(k, v) }
            if let r = t.riskPolicy { b = b.risk(r) }
            return b
        }

        /// Allow `actions` on a connector (the union with what was allowed before, first-seen order).
        public func allow(_ connector: String, _ actions: [String]) -> PolicyBuilder {
            var b = self
            var merged = perms.first { IV.same($0.0, connector) }?.1 ?? []
            for a in actions where !merged.contains(where: { IV.same($0, a) }) { merged.append(a) }
            if let i = b.perms.firstIndex(where: { IV.same($0.0, connector) }) { b.perms[i].1 = merged } else { b.perms.append((connector, merged)) }
            return b
        }

        public func limit(_ verbOrAction: String, _ spec: String) -> PolicyBuilder {
            var b = self
            b.lims[verbOrAction] = spec
            return b
        }

        /// Merge risk-policy members over the earlier ones.
        public func risk(_ partial: JObject) -> PolicyBuilder {
            var b = self
            var m = riskOverride ?? [:]
            for (k, v) in partial { m[k] = v }
            b.riskOverride = m
            return b
        }

        /// The built policy. Throws when no permission was added.
        public func build() throws -> BuiltPolicy {
            if perms.isEmpty { throw JSError("PolicyBuilder: no permissions added") }
            return BuiltPolicy(permissions: perms, limits: lims, riskPolicy: riskOverride)
        }

        /// Mint an agent directly from the built policy.
        public func agent(principal: PCASuiteKey, goal: String, aud: String? = nil, holder: PCASuiteKey? = nil, now: Int64? = nil) throws -> PCAFacadeAgent {
            let b = try build()
            return try PCAAgent.fromPrincipal(PCAAgentOptions(principal: principal, goal: goal, permissions: b.permissions, limits: b.limits, holder: holder, riskPolicy: b.riskPolicy, aud: aud, now: now))
        }
    }

    /// Entry point for the fluent builder.
    public static func policy() -> PolicyBuilder { PolicyBuilder() }
}
