import Foundation

extension PCAWalletDelivery {
    /// Fans a notice out to every enabled channel (disabled channels are skipped): the reference's `createQuestionDispatcher`.
    public struct QuestionDispatcher {
        public let channels: [QuestionChannel]
        public func notifyAll(_ notice: JSONValue) -> [JSONValue] { PCAWalletDelivery.notifyAll(channels, notice) }
    }

    public static func createQuestionDispatcher(_ channels: [QuestionChannel]) -> QuestionDispatcher { QuestionDispatcher(channels: channels) }
}

extension PCAMcp {
    /// Import an MCP tool list as ActionDefs (typed params with roles, nested bodies flattened, annotations kept as untrusted hints, every def `unreviewed`
    /// until a pinned reviewer signs it), then run the deterministic trait suggestions unless `suggest` is `"none"`. `source` is the tool array or a
    /// `tools/list` result. Returns `{defs, todo, source}`.
    public static func importActionDefsFromMcp(_ source: JSONValue, ns: String, uri: String? = nil, licence: String? = nil, now: Double? = nil, suggest: String? = nil) throws -> JObject {
        var opts: JObject = ["ns": .string(ns)]
        if let u = uri { opts["uri"] = .string(u) }
        if let l = licence { opts["licence"] = .string(l) }
        if let n = now { opts["now"] = n.rounded() == n && abs(n) < 9_007_199_254_740_992 ? .int(Int64(n)) : .double(n) }
        let r = try McpImporter.importMcp(source, opts)
        var so = ImportPipeline.SuggestOpts()
        so.mode = suggest ?? "rules"
        let s = try ImportPipeline.suggestDefs((r[JKey("defs")]?.asArray ?? []).compactMap { $0.asObject }, so)
        return ["defs": s[JKey("defs")] ?? .array([]), "todo": r[JKey("todo")] ?? .array([]), "source": r[JKey("source")] ?? .null]
    }
}

extension PCATesting {
    /// A REAL agent with test defaults (a signed grant and the genuine `act` / `dryRun`), so a PCActn it builds verifies against `fakeVerify` out of the box.
    /// Defaults: permissions `stripe: [refund]`, limits `refund: $500/day`, goal `test`, audience `ins_test`; fresh principal and holder keys when omitted.
    public static func testAgent(permissions: [(String, [String])]? = nil, limits: [String: String]? = nil, goal: String = "test", aud: String = "ins_test",
                                 principal: PCASuiteKey? = nil, holder: PCASuiteKey? = nil) throws -> PCAFacadeAgent {
        try PCAAgent.fromPrincipal(PCAAgentOptions(principal: try principal ?? .ed25519(try PCAEdKey.generate()), goal: goal, permissions: permissions ?? [("stripe", ["refund"])],
                                                   limits: limits ?? ["refund": "$500/day"], holder: holder, aud: aud))
    }

    /// A PCActn from `a` for one action (a thin wrapper over `a.act`): the `pcactn` and its wire `encoded` form. The counter auto-increments per holder when
    /// omitted; `now` pins the issue time (epoch ms) of this call.
    public static func makePCActn(_ a: PCAFacadeAgent, _ verb: String, _ resource: String, params: JSONValue? = nil, counter: Int64? = nil, now: Int64? = nil) throws -> (pcactn: JSONValue, encoded: String) {
        let r = try a.act(verb: verb, resource: resource, params: params, options: PCAActOptions(counter: counter, now: now))
        return (r.pcactn, r.encoded)
    }
}
