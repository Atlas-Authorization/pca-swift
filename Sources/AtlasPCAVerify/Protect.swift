import Foundation

/// A revocation list shared between the guard's `isRevoked` hook and `Protected.revoke`.
final class RevokedSet: @unchecked Sendable {
    private let lock = NSLock()
    private var ids = Set<String>()
    func insert(_ id: String) { lock.lock(); ids.insert(id); lock.unlock() }
    func contains(_ id: String?) -> Bool { guard let id = id else { return false }; lock.lock(); defer { lock.unlock() }; return ids.contains(id) }
}

/// What `protect(...)` returns: a ready `PcaGuardConfig` (hand it to `PcaGuard`, `PcaMiddleware` or the Hummingbird middleware) and the
/// revoke handle.
public struct Protected {
    public var config: PcaGuardConfig
    let revoked: RevokedSet

    /// Refuse every further action under this grant id.
    public func revoke(_ grantId: String) { revoked.insert(grantId) }
}

/// `protect(...)`: the secure defaults for a resource server, in one call.
///
///     let p = protect(audience: "ins_acme", grants: [grant], operation: { req in PCA.Operation(verb: "stripe.refund", resource: "charge:1", params: ...) })
///     app.middleware.use(try p.middleware())      // Vapor, from AtlasPCAVapor
///     p.revoke("grant-id")                        // later: every action under that grant is refused
///
/// It fills in what every server otherwise wires by hand: the grant lookup (your own list or closure, never the request), an in-memory
/// replay store, a revocation source and the single-step plan (the grant alone limits what runs). Everything is still `PCA.authorize`:
/// bound to the operation your route executes, default-deny. Any option you pass wins over the default; `configure` edits the whole
/// config last. Not included: server-side risk from the connector catalog (the TypeScript `protect()` prices risk with `catalogRisk`;
/// this port has no catalog, so a step-up threshold needs your own `PCA.AuthorizeContext`). The in-memory store is per process: pass a
/// durable `stateStore` (for example the SQLite one) when you run more than one instance.
public func protect(audience: String, operation: @escaping (PcaGuardRequest) throws -> PCA.Operation?, grants: [JSONValue] = [],
                    resolveGrant: ((String) throws -> JSONValue?)? = nil, isRevoked: ((JSONValue, JSONValue) throws -> Bool?)? = nil,
                    stateStore: (any PCAStateStore)? = nil, plan: String? = nil, now: (() -> Int64)? = nil,
                    executor: PcaGuardExecutorConfig? = nil, configure: ((inout PcaGuardConfig) -> Void)? = nil) -> Protected {
    let revoked = RevokedSet()
    var byId: [String: JSONValue] = [:]
    for g in grants { if let id = g.get("id")?.asString { byId[id] = g } }
    let table = byId
    let resolve: (String) throws -> JSONValue? = resolveGrant ?? { table[$0] }
    // the revocation hook stays unless you replace it; a throw from yours refuses (only `false` passes)
    let revocation: (JSONValue, JSONValue) throws -> Bool? = { pcactn, grant in
        if revoked.contains(grant.get("id")?.asString) { return true }
        if let extra = isRevoked { return try extra(pcactn, grant) }
        return false
    }
    let store: any PCAStateStore = stateStore ?? MemoryStateStore()
    let az = PcaAuthorizeConfig(stateStore: store, isRevoked: revocation, plan: plan, operation: operation)
    var config = PcaGuardConfig(audience: audience, resolveGrant: resolve, now: now, authorize: az, executor: executor)
    configure?(&config)
    return Protected(config: config, revoked: revoked)
}
