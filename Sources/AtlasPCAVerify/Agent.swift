import Foundation

/// An agent that acts under a grant: it owns the leaf signing key, the capability chain and the monotonic counter, stamps a fresh nonce
/// on every action, and encodes the PCActn the way the native middleware expects (the `PCA-Action` header, unpadded base64url of the JSON).
/// No TypeScript process is needed.
///
///     let me = PCASuiteKey.ed25519(try PCAEdKey.generate())
///     let agent = try PCAAgent(signer: me, aud: "ins_123", grant: grant)          // the chain defaults to [grant]
///     let pcactn = try agent.act(verb: "pay", resource: "invoice/7", params: .object(["amount": .int(1200)]))
///     request.setValue(PCAAgent.headerValue(pcactn), forHTTPHeaderField: PCAAgent.HEADER)
///
/// A reference type, not thread-safe: counters are handed out in order, so use one agent per task or serialise around `act`.
public final class PCAAgent {
    public static let HEADER = "PCA-Action"

    public let signer: PCASuiteKey
    public let aud: String
    public let grant: JSONValue
    public let chain: [JSONValue]
    /// The last counter used; the next action uses `counter + 1`.
    public var counter: Int64
    public var ttlMs: Int64 = PCAIssue.DEFAULT_TTL_MS
    public var clock: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }
    public var nonces = true
    private var plan: PCAIssue.Plan?

    public init(signer: PCASuiteKey, aud: String, grant: JSONValue, chain: [JSONValue]? = nil, counter: Int64 = 0) throws {
        if aud.isEmpty { throw PCAProducerError("Agent: aud (the resource server / instance id) is required") }
        self.signer = signer; self.aud = aud; self.grant = grant; self.chain = chain ?? [grant]; self.counter = counter
    }

    /// Commit a plan locally; the returned root is what a server must echo if the plan is registered with it.
    @discardableResult public func commitPlan(_ nodes: [JObject]) throws -> PCAIssue.Plan {
        let p = try PCAIssue.commitPlan(nodes)
        plan = p
        return p
    }

    private func build(_ p: PCAIssue.Plan, _ nodeId: String, _ params: JSONValue?, _ slots: JObject) throws -> JSONValue {
        var extras = slots
        if extras["nonce"] == nil && nonces { extras["nonce"] = .string(PCAIssue.random(16)) }
        let next = counter + 1
        let out = try PCAIssue.buildPCActn(.init(grant: grant, chain: chain, plan: p, nodeId: nodeId, params: params, counter: next, signer: signer, aud: aud,
                                                 iat: clock(), ttlMs: ttlMs, extras: extras))
        counter = next // monotonic: a counter is never reused, even if the call later fails
        return out
    }

    /// Act on a node of the committed plan. `slots` carries the optional signed members (caution, intent, fresh_at, ...).
    public func actNode(_ nodeId: String, params: JSONValue? = nil, slots: JObject = [:]) throws -> JSONValue {
        guard let p = plan else { throw PCAProducerError("commitPlan() first") }
        return try build(p, nodeId, params, slots)
    }

    /// Act on one verb and resource with an ad-hoc single-node plan.
    public func act(verb: String, resource: String, params: JSONValue? = nil, slots: JObject = [:]) throws -> JSONValue {
        let id = "n\(counter + 1)"
        let node: JObject = ["id": .string(id), "verb": .string(verb), "resource": .string(resource)]
        return try build(try PCAIssue.commitPlan([node]), id, params, slots)
    }

    /// Delegate a narrower authority to a sub-agent; the returned agent signs with `child` over the extended chain (its counter starts at 0).
    public func delegate(to child: PCASuiteKey, addedCaveats: [JSONValue] = []) throws -> PCAAgent {
        guard let cid = child.id, let leaf = chain.last else { throw PCAProducerError("a delegate holder needs an Ed25519 identity") }
        let hop = try PCAIssue.delegate(parent: leaf, toHolder: cid, added: addedCaveats, signer: signer, holderPqPk: child.pqPk)
        let a = try PCAAgent(signer: child, aud: aud, grant: grant, chain: chain + [hop], counter: 0)
        a.ttlMs = ttlMs; a.clock = clock; a.nonces = nonces
        return a
    }

    /// The header value for a PCActn.
    public static func headerValue(_ pcactn: JSONValue) -> String { PCAIssue.header(pcactn) }

    /// The JSON body `{"pcactn": ...}` that the Atlas `POST /v1/pca/actions` endpoint takes.
    public static func actionsBody(_ pcactn: JSONValue) -> String { Canonical.canonicalize(.object(["pcactn": pcactn])) }
}
