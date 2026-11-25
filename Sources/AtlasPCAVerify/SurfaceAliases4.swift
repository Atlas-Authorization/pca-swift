import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// TypeScript exports of the connector registry, the hybrid threshold verifier, the passport registry and the directory push clients.
extension PCAConnectors {
    /// Validate and register a custom manifest onto the process-wide default registry (refuses to replace a registered provider unless `replace`).
    @discardableResult
    public static func registerProvider(_ manifest: JSONValue, replace: Bool = false, expectedDigest: String? = nil) throws -> ProviderManifest {
        try defaultRegistry.register(manifest, replace: replace, expectedDigest: expectedDigest)
    }

    /// The manifest of `id` in the default registry, or nil.
    public static func getProvider(_ id: String) -> ProviderManifest? { defaultRegistry.get(id) }

    /// Every provider of the default registry, in ascending id order.
    public static func listProviders() -> [ProviderManifest] { defaultRegistry.list() }
}

extension PCAPqThreshold {
    /// A threshold hook for the core verifier enforcing the HYBRID step-up (the FROST aggregate under the trusted group key AND the ML-DSA quorum): the
    /// reference's `createHybridThresholdVerifier`. See `thresholdHook`.
    public static func createHybridThresholdVerifier(_ opts: HybridOpts, pqBlock: JSONValue?) throws -> (_ pcactn: JSONValue) -> (enforced: Bool, ok: Bool, reason: String?) {
        try thresholdHook(opts, pqBlock: pqBlock)
    }
}

/// A passport without its id: the identity fields `passportFingerprint` hashes.
public typealias PassportIdentity = JObject

/// Passports by id (a later passport with the same id replaces the earlier one in place): the reference's `PassportRegistry`.
public final class PassportRegistry: @unchecked Sendable {
    private var order: [String] = []
    private var byId: [String: JObject] = [:]
    public init(_ passports: [JObject] = []) {
        for p in passports {
            let id = JS.toString(p["id"])
            if byId[id] == nil { order.append(id) }
            byId[id] = p
        }
    }
    public func get(_ id: String) -> JObject? { byId[id] }
    public func has(_ id: String) -> Bool { byId[id] != nil }
    public func all() -> [JObject] { order.compactMap { byId[$0] } }
}

extension PCAScim {
    /// Where and how to push an outbound provisioning body. `fetch(url, headers, body)` returns the status and the response text; the default is a
    /// blocking POST over URLSession.
    public struct PushTarget {
        public var endpoint: String
        public var token: String
        public var fetch: ((_ url: String, _ headers: [String: String], _ body: String) throws -> (status: Int, body: String))?
        public init(endpoint: String, token: String, fetch: ((String, [String: String], String) throws -> (status: Int, body: String))? = nil) {
            self.endpoint = endpoint; self.token = token; self.fetch = fetch
        }
    }

    /// The outcome of a push-provision call: `ok` is a 2xx status; `body` is the response parsed as JSON, or null.
    public struct PushResult: Equatable {
        public var ok: Bool
        public var status: Int
        public var body: JSONValue
    }

    private final class Reply: @unchecked Sendable { var status = 0; var body = ""; var err: Error? }

    private static func urlSessionPost(_ url: String, _ headers: [String: String], _ body: String) throws -> (status: Int, body: String) {
        guard let u = URL(string: url) else { throw JSError("pushProvision: bad endpoint") }
        var req = URLRequest(url: u)
        req.httpMethod = "POST"
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = Data(body.utf8)
        let box = Reply(), sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { d, r, e in
            box.status = (r as? HTTPURLResponse)?.statusCode ?? 0
            box.body = d.flatMap { String(data: $0, encoding: .utf8) } ?? ""
            box.err = e
            sem.signal()
        }.resume()
        sem.wait()
        if let e = box.err { throw e }
        return (box.status, box.body)
    }

    /// POST an already-shaped provisioning payload to a directory endpoint (injectable transport).
    public static func pushProvision(_ payload: JSONValue, _ target: PushTarget) throws -> PushResult {
        let f = target.fetch ?? urlSessionPost
        let r = try f(target.endpoint, ["authorization": "Bearer \(target.token)", "content-type": SCIM_CONTENT_TYPE], JS.stringify(payload))
        return PushResult(ok: (200..<300).contains(r.status), status: r.status, body: (try? StrictJSON.parseLenient(r.body)) ?? .null)
    }

    /// Shape a PCA agent for Entra and push it.
    public static func pushToEntra(_ agent: JObject, _ target: PushTarget) throws -> PushResult { try pushProvision(toEntraAgentPayload(agent), target) }

    /// Shape a PCA agent for Okta and push it.
    public static func pushToOkta(_ agent: JObject, _ target: PushTarget) throws -> PushResult { try pushProvision(toOktaScimPayload(agent), target) }
}
