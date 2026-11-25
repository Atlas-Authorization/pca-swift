import Foundation

/// A failure of the agent client (`PcaAgentError` of pca-agent): `no_plan`, `unknown_node`, `no_secret`, `network`, `bad_response` or `build_failed`.
public struct PCAAgentError: Error, Equatable, CustomStringConvertible {
    public let code: String
    public let message: String
    public let httpStatus: Int?
    public init(_ code: String, _ message: String, httpStatus: Int? = nil) { self.code = code; self.message = message; self.httpStatus = httpStatus }
    public var description: String { "PcaAgentError(\(code)): \(message)" }
}

/// The networked agent client of pca-agent (`createAgent`): commits a plan to the resource server, acts on its nodes (a PCActn per action, a
/// monotonic counter that is never reused), follows a step-up to its outcome and verifies the ledger receipt of every allow. The transport is an
/// injected blocking `fetch`, so the client runs under any HTTP stack (and in tests without one).
public final class PCAAgentClient: @unchecked Sendable {
    public struct FetchResponse {
        public var status: Int
        public var json: JSONValue?
        public init(status: Int, json: JSONValue?) { self.status = status; self.json = json }
    }

    /// `(method, url, headers, body)` -> the status and the parsed JSON body (nil for a body that is not JSON).
    public typealias Fetch = (_ method: String, _ url: String, _ headers: [String: String], _ body: String?) throws -> FetchResponse

    public struct TrustBudget: Equatable { public var B: Double; public var tau: Double; public var asOf: Double }

    public enum ActResult {
        case allowed(verdict: JSONValue, receipt: JSONValue, pcactn: JSONValue)
        case denied(verdict: JSONValue, httpStatus: Int, pcactn: JSONValue)
        case stepUp(stepupId: String, requiredT: Double, pcactn: JSONValue)
        case error(PCAAgentError)
    }

    public enum StepUpOutcome: Equatable {
        case approved(JSONValue), denied(JSONValue), expired(JSONValue)
        case timeout
    }

    public let grant: JSONValue
    public let chain: [JSONValue]
    public let agentPublic: String?
    public private(set) var counter: Int64
    public private(set) var budget: TrustBudget?
    public private(set) var planRoot: String?
    private let signer: PCASuiteKey?
    private let base: String
    private let audience: String
    private let fetch: Fetch
    private let verifyReceipts: Bool
    private let provenance: ProvenanceRecorder?
    private let ttlMs: Int64?
    private let now: () -> Int64
    private let nonce: Bool
    private var plan: [JObject]?
    private var agent: PCAAgent?

    /// `audience` is REQUIRED (the resource server / instance id PCActns are for; a PCActn only verifies there). `rsBaseUrl` must be an absolute
    /// http(s) URL. `verifyReceipts` (default true): an allow whose receipt does not verify is an error, never an allow.
    public init(grant: JSONValue, chain: [JSONValue]? = nil, signer: PCASuiteKey? = nil, agentPublic: String? = nil, rsBaseUrl: String, audience: String,
                ttlMs: Int64? = nil, now: (() -> Int64)? = nil, nonce: Bool = true, fetch: @escaping Fetch, verifyReceipts: Bool = true, counter: Int64 = 0,
                budget: TrustBudget? = nil, provenance: ProvenanceRecorder? = nil) throws {
        if audience.isEmpty { throw PCAAgentError("build_failed", "createAgent: `audience` is required (the resource-server / Atlas instance id PCActns are for)") }
        guard let u = URL(string: rsBaseUrl), let scheme = u.scheme?.lowercased(), scheme == "https" || scheme == "http", u.host != nil else {
            throw PCAAgentError("build_failed", "createAgent: `rsBaseUrl` must be an absolute http(s) URL")
        }
        var b = rsBaseUrl
        while b.hasSuffix("/") { b.removeLast() }
        self.base = b
        self.grant = grant; self.chain = chain ?? [grant]; self.signer = signer; self.agentPublic = agentPublic; self.audience = audience
        self.ttlMs = ttlMs; self.now = now ?? { Int64(Date().timeIntervalSince1970 * 1000) }; self.nonce = nonce; self.fetch = fetch
        self.verifyReceipts = verifyReceipts; self.counter = counter; self.budget = budget; self.provenance = provenance
    }

    private func call(_ method: String, _ path: String, _ body: JSONValue? = nil) throws -> FetchResponse {
        try fetch(method, base + path, ["content-type": "application/json", "accept": "application/json"], body.map { Canonical.canonicalize($0) })
    }

    /// Commit the plan to the server; the server must echo the locally computed root.
    @discardableResult
    public func commitPlan(_ nodes: [JObject]) throws -> String {
        let local = try PCAIssue.commitPlan(nodes).root
        let res = try call("POST", "/v1/pca/plans", .object(["grant_ref": grant.get("id") ?? .null, "nodes": .array(nodes.map { .object($0) })]))
        if res.status < 200 || res.status >= 300 { throw PCAAgentError("bad_response", "plan commit failed (\(res.status))", httpStatus: res.status) }
        // a missing root cannot be told apart from a server that stored another plan
        guard res.json?.get("plan_root")?.asString == local else {
            throw PCAAgentError("bad_response", "server plan_root is missing or differs from the locally computed root", httpStatus: res.status)
        }
        plan = nodes
        planRoot = local
        return local
    }

    private static func isBudget(_ v: JSONValue?) -> TrustBudget? {
        guard let o = v?.asObject, let b = IV.num(o["B"]), let t = IV.num(o["tau"]), let a = IV.num(o["asOf"]), b.isFinite, t.isFinite, a.isFinite else { return nil }
        return TrustBudget(B: b, tau: t, asOf: a)
    }

    private static func entryBinds(_ receipt: JObject, _ pcactn: JSONValue) -> Bool {
        guard let salt = receipt["salt"]?.asString, let d = IV.strictHash(pcactn),
              let c = IV.strictHash(.object(["salt": .string(salt), "pcactn_digest": .string(d)])) else { return false }
        return c == receipt["commit"]?.asString
    }

    public func verifyReceipt(_ r: JSONValue) -> Bool {
        guard let root = r.get("root")?.asString else { return false }
        return Ledger.verifyInclusion(root, r.get("inclusion_proof"), r.get("commit"))
    }

    /// Act on a plan node: build and sign a PCActn (the counter moves even if the call fails), POST it and classify the answer.
    public func act(_ nodeId: String, params: JSONValue? = nil, slots: JObject = [:]) -> ActResult {
        guard let nodes = plan else { return .error(PCAAgentError("no_plan", "commitPlan() first")) }
        guard let key = signer else { return .error(PCAAgentError("no_secret", "no agentSecret for this client")) }
        guard let node = nodes.first(where: { $0["id"]?.asString == nodeId }) else { return .error(PCAAgentError("unknown_node", "unknown plan node \(nodeId)")) }
        let pcactn: JSONValue
        do {
            let a = try PCAAgent(signer: key, aud: audience, grant: grant, chain: chain, counter: counter)
            a.clock = now
            a.nonces = nonce
            if let t = ttlMs { a.ttlMs = t }
            try a.commitPlan(nodes)
            pcactn = try a.actNode(nodeId, params: params, slots: slots)
            counter = a.counter // monotonic: never reuse a counter, even if the call fails
        } catch {
            return .error(PCAAgentError("build_failed", "\(error)"))
        }
        var body: JObject = ["pcactn": pcactn]
        if let rec = provenance {
            do { body["pca_provenance"] = try rec.forAction(PCA.Operation(verb: node["verb"]?.asString ?? "", resource: node["resource"]?.asString ?? "", params: params ?? .object([:]))) }
            catch { return .error(PCAAgentError("build_failed", "\(error)")) }
        }
        let res: FetchResponse
        do { res = try call("POST", "/v1/pca/actions", .object(body)) } catch { return .error(PCAAgentError("network", "\(error)")) }
        let j = res.json?.asObject ?? [:]
        if res.status == 202 || j["status"]?.asString == "step_up_required" || j["step_up_required"] == .bool(true) {
            guard let id = (j["stepup_id"] ?? j["stepupId"] ?? j["id"])?.asString else {
                return .error(PCAAgentError("bad_response", "step-up response missing stepup_id", httpStatus: res.status))
            }
            let t = IV.num(j["required_t"] ?? j["requiredT"] ?? j["t"]) ?? 2
            return .stepUp(stepupId: id, requiredT: t, pcactn: pcactn)
        }
        let verdictV: JSONValue = (j["verdict"]?.isObject == true) ? j["verdict"]! : .object(["allow": .bool(j["allow"] == .bool(true))])
        // allow only on an explicit boolean true from every place the server states it (a truthy string or a contradiction is a deny)
        let allowed = res.status >= 200 && res.status < 300 && verdictV.get("allow") == .bool(true) && (j["allow"] == nil || j["allow"] == .bool(true))
        if let b = Self.isBudget(verdictV.get("budget")) { budget = b }
        if allowed {
            guard let receipt = j["receipt"], receipt.isObject else { return .error(PCAAgentError("bad_response", "allow without receipt", httpStatus: res.status)) }
            if verifyReceipts {
                if !verifyReceipt(receipt) { return .error(PCAAgentError("bad_response", "allow receipt inclusion proof does not verify", httpStatus: res.status)) }
                if receipt.get("salt") != nil, !Self.entryBinds(receipt.asObject!, pcactn) {
                    return .error(PCAAgentError("bad_response", "allow receipt does not commit to this action", httpStatus: res.status))
                }
            }
            return .allowed(verdict: verdictV, receipt: receipt, pcactn: pcactn)
        }
        return .denied(verdict: verdictV, httpStatus: res.status, pcactn: pcactn)
    }

    /// Poll a step-up to its outcome. Only a 2xx answer can approve; a 4xx other than 429 is final (never an approval).
    public func awaitStepUp(_ stepupId: String, pollMs: Int64 = 1000, timeoutMs: Int64 = 5 * 60_000, sleep: (Int64) -> Void = { Thread.sleep(forTimeInterval: Double($0) / 1000) }) throws -> StepUpOutcome {
        let deadline = now() + timeoutMs
        let enc = stepupId.addingPercentEncoding(withAllowedCharacters: CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()")) ?? stepupId
        while true {
            let wait = Swift.min(25, (deadline - now()) / 1000)
            let res: FetchResponse
            do { res = try call("GET", "/v1/pca/stepups/\(enc)" + (wait > 0 ? "?wait=\(wait)" : "")) } catch { throw PCAAgentError("network", "\(error)") }
            let s = res.json?.get("status")?.asString
            let ok = res.status >= 200 && res.status < 300
            if ok, let st = s, st == "approved" || st == "denied" || st == "expired" {
                var o = res.json?.asObject ?? [:]
                o["status"] = .string(st)
                switch st { case "approved": return .approved(.object(o)); case "denied": return .denied(.object(o)); default: return .expired(.object(o)) }
            }
            if res.status >= 400 && res.status < 500 && res.status != 429 { return .denied(.object(["status": .string("denied"), "httpStatus": .int(Int64(res.status))])) }
            if now() + pollMs > deadline { return .timeout }
            sleep(pollMs)
        }
    }

    /// A sub-agent over the extended chain (a fresh counter, the same transport, audience and provenance session).
    public func delegate(toPublic: String, addedCaveats: [JSONValue] = [], signer childSigner: PCASuiteKey? = nil) throws -> PCAAgentClient {
        guard let key = signer else { throw PCAAgentError("no_secret", "cannot delegate without agentSecret") }
        guard let leaf = chain.last else { throw PCAAgentError("build_failed", "empty chain") }
        let hop = try PCAIssue.delegate(parent: leaf, toHolder: toPublic, added: addedCaveats, signer: key, holderPqPk: childSigner?.pqPk)
        return try PCAAgentClient(grant: grant, chain: chain + [hop], signer: childSigner, agentPublic: toPublic, rsBaseUrl: base, audience: audience, ttlMs: ttlMs,
                                  now: now, nonce: nonce, fetch: fetch, verifyReceipts: verifyReceipts, counter: 0, budget: nil, provenance: provenance)
    }
}
