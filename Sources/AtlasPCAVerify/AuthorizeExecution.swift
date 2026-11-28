import Foundation

/// `authorizeExecution`: the full-policy check for one local execution (an agent framework tool call, a gateway request), for verifiers that have the PCActn in
/// hand rather than an HTTP request. The core verifier alone checks that a proof is genuine (signatures, chain, plan, audience, validity, counter format); it
/// does not read the grant's limits, so a validly signed $400 payment under a $100 grant passes it. This runs, in order: (1) the configuration (the audience, a
/// grant source, the replay / budget store and the revocation check are REQUIRED; a missing one denies every call, never a downgrade to signature-only);
/// (2) the operation binding (the PCActn's signed verb, and resource when named, must be the operation about to execute); (3) the full server pipeline
/// (`PCA.authorize`): the grant from the caller's store, the operation's params against the signed params digest, the grant's predicates, limits and caveats,
/// revocation, the replay counter and the trust budget, with risk priced from server-side inputs.
extension PCA {
    /// The operation that is about to execute: what the PCActn must have been signed for.
    public struct ExecutionOperation {
        /// The PCA verb of this operation (e.g. `stripe.refund`). Must equal the signed `action.verb`.
        public var verb: String
        /// The PCA resource of this operation. When given it must equal the signed `action.resource`.
        public var resource: String?
        /// The parameters the operation will execute with. They must hash to the signed `action.params_digest`.
        public var params: JSONValue
        /// The provenance bundle the agent presented with this call (absent = unlabelled).
        public var provenance: JSONValue?
        public init(verb: String, resource: String? = nil, params: JSONValue, provenance: JSONValue? = nil) { self.verb = verb; self.resource = resource; self.params = params; self.provenance = provenance }
    }

    public struct AuthorizeExecutionOptions {
        /// REQUIRED: this verifier's audience id. A PCActn whose signed `aud` differs is denied.
        public var audience: String?
        /// The grant the PCActn must chain to. Give this or `resolveGrant` (one is required).
        public var grant: JSONValue?
        /// Look the grant up in YOUR store by the PCActn's signed `grant_ref`. Never return a grant taken from the call.
        public var resolveGrant: ((_ grantRef: String, _ pcactn: JSONValue) throws -> JSONValue?)?
        /// REQUIRED: replay counters and trust budgets per agent. Share one store across processes.
        public var state: (any PCAStateStore)?
        /// REQUIRED: is this grant revoked? A verifier that cannot answer this must not authorize.
        public var isRevoked: ((_ grant: JSONValue, _ pcactn: JSONValue) throws -> Bool)?
        /// Has the principal authorized this plan root for this grant? Default: a one-step plan is authorized when it is exactly the step that was signed.
        public var isPlanAuthorized: ((_ grantRef: String, _ planRoot: String) throws -> Bool)?
        /// Server-side risk inputs for this operation (default `PCA.amountRisk`: `blastRadius = amount / kappa`). Inputs not supplied are priced at the worst case.
        public var risk: ((_ grant: JSONValue, _ params: JSONValue, _ pcactn: JSONValue) -> JObject?)?
        /// The threshold (attestation / quorum) hook forwarded to the verifier.
        public var thresholdHook: ((JSONValue) throws -> ThresholdOutcome)?
        /// Further checks that must report `pass`, on top of the full-mode defaults.
        public var require: [String] = []
        public var k1: K1Input?
        /// The consume-once store `max_uses` caveats spend from.
        public var usesStore: (any PCAStateStore)?
        /// Accepted signature suites. Default `["ed25519"]`.
        public var allowedSuites: [String]?
        /// Server-side PQ pins `issuer -> pq_pk`, needed only if a post-quantum suite is accepted.
        public var pqPins: [String: String]?
        /// Verifier clock (epoch ms). Default the wall clock.
        public var now: (() -> Int64)?
        public var requireAssurance: AssuranceRequirement?
        /// The provenance gate's configuration (pinned mediators, the `actions` facts of your action definitions, server `observed` content).
        public var provenance: ArgProvenanceOptions?
        public init() {}
    }

    /// Why a full-policy check refused.
    public enum ExecutionDenialKind: String { case config, binding, authn, policy, replay, revoked }

    public struct ExecutionDecision {
        public let allow: Bool
        /// The denial kind (nil on an allow).
        public let kind: ExecutionDenialKind?
        public let status: Int
        /// The decisive reason, in the verifier's words (nil on an allow).
        public let reason: String?
        public let pcactn: JSONValue?
        public let grant: JSONValue?
        public let checks: [String: CheckStatus]
        public let result: AuthorizeResult?

        static func deny(_ kind: ExecutionDenialKind, _ status: Int, _ reason: String, result: AuthorizeResult? = nil) -> ExecutionDecision {
            ExecutionDecision(allow: false, kind: kind, status: status, reason: reason, pcactn: nil, grant: nil, checks: result?.checks ?? [:], result: result)
        }
    }


    /// The required components that `opts` lacks (empty when the configuration is complete).
    public static func missingExecutionComponents(_ o: AuthorizeExecutionOptions) -> [String] {
        var missing: [String] = []
        if (o.audience ?? "").isEmpty { missing.append("audience") }
        if o.grant == nil && o.resolveGrant == nil { missing.append("grant or resolveGrant") }
        if o.state == nil { missing.append("state") }
        if o.isRevoked == nil { missing.append("isRevoked") }
        return missing
    }

    /// The reason of the first failing check (the verifier also lists context such as worst-case risk inputs). A failing `operation` check is a params mismatch
    /// that `params_digest` already reports, so it is ranked last and the reason stays the established `params_digest` one.
    static func decisiveExecutionReason(_ r: AuthorizeResult) -> String {
        let noise: (String) -> Bool = { $0.contains("risk input(s) missing") }
        let names = r.checkNames.filter { $0 != "operation" } + r.checkNames.filter { $0 == "operation" }
        for n in names where r.checks[n] == .fail {
            if let hit = r.reasons.first(where: { $0.hasPrefix(n + ":") && !noise($0) }) { return hit }
        }
        return r.reasons.first(where: { !noise($0) }) ?? r.reasons.first ?? "denied"
    }

    /// Authorize one execution completely: configuration, binding to the operation, and the full verifier. Never throws: every failure is a denial.
    /// Not carried from the reference: the opt-in `enforce` gates, `multiInstance`, `replayScope` and `claimRetries` (use `PCA.authorize` directly for those).
    public static func authorizeExecution(_ pcactn: JSONValue, _ operation: ExecutionOperation, _ opts: AuthorizeExecutionOptions) -> ExecutionDecision {
        let missing = missingExecutionComponents(opts)
        if !missing.isEmpty { return .deny(.config, 403, "full policy mode is missing \(missing.joined(separator: ", ")) (fail closed)") }
        let action = pcactn.get("action")
        let signedVerb = action?.get("verb"), signedResource = action?.get("resource")
        if signedVerb != .string(operation.verb) || (operation.resource != nil && signedResource != .string(operation.resource!)) {
            let want = operation.resource.map { "\(operation.verb) on \($0)" } ?? operation.verb
            return .deny(.binding, 403, "the proof is for \(signedVerb.map { JS.toString($0) } ?? "undefined") on \(signedResource.map { JS.toString($0) } ?? "undefined"), but this call is \(want)")
        }
        do {
            var grant = opts.grant
            if grant == nil, let ref = pcactn.get("grant_ref")?.asString { grant = try opts.resolveGrant?(ref, pcactn) }
            guard let g = grant, !g.isNull else { return .deny(.authn, 401, "unknown grant_ref") }
            let params = operation.params
            let op = Operation(verb: operation.verb, resource: operation.resource ?? signedResource?.asString ?? "", params: params)
            var input = AuthorizeInput(operation: op, audience: opts.audience, resolveGrant: { _ in g }, stateStore: opts.state, isRevoked: { p, gr in try opts.isRevoked!(gr, p) },
                                       now: opts.now?(), plan: nil, context: { pc in
                let node: JSONValue = .object(["id": pc.get("plan")?.get("node_id") ?? .null, "verb": action?.get("verb") ?? .null, "resource": signedResource ?? .null,
                                               "params_digest": action?.get("params_digest") ?? .null, "reversibility_class": action?.get("reversibility_class") ?? .null])
                let consistent = PCA.knownPlanRoot([node]).map { $0 == pc.get("plan")?.get("root")?.asString } ?? false // the leaf carries the node's own conditions, as planNodeLeaf does
                var approved = true
                if let f = opts.isPlanAuthorized { approved = (try? f(pc.get("grant_ref")?.asString ?? "", pc.get("plan")?.get("root")?.asString ?? "")) == true }
                return AuthorizeContext(plan: [node], planAuthorized: consistent && approved)
            }, allowedSuites: opts.allowedSuites ?? ["ed25519"], require: opts.require, requireAssurance: opts.requireAssurance, k1: opts.k1, usesStore: opts.usesStore,
                                       argProvenance: opts.provenance ?? ArgProvenanceOptions(), provenance: operation.provenance,
                                       riskSource: { o, gr, pc in
                if let f = opts.risk { return f(gr, params, pc) }
                return try amountRisk(o, gr, pc)
            })
            input.pqPins = opts.pqPins
            input.thresholdHook = opts.thresholdHook
            let r = authorize(pcactn: pcactn, input)
            if r.allow { return ExecutionDecision(allow: true, kind: nil, status: r.status, reason: nil, pcactn: r.pcactn ?? pcactn, grant: g, checks: r.checks, result: r) }
            let kind: ExecutionDenialKind = r.status == 401 ? .authn : r.checks["revocation"] == .fail ? .revoked : r.checks["replay"] == .fail ? .replay : .policy
            return .deny(kind, r.status, decisiveExecutionReason(r), result: r)
        } catch {
            return .deny(.policy, 403, "authorization error (fail closed): \((error as? JSError)?.message ?? "unknown")")
        }
    }
}
