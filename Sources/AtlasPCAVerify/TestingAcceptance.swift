import Foundation

/// The shared acceptance matrix for resource-server adapters, run for real: every adapter drives the SAME scenarios through its own request
/// and response plumbing with the options of the `authorize` pipeline, and must produce `PCATesting.ADAPTER_ACCEPTANCE_EXPECTED` exactly.
///
/// The routes: `POST /payments` executes `payments.send`, `POST /refunds` executes `payments.refund`, both on resource `payments` with the JSON
/// body as params. The grant permits both verbs up to $100 per call; the operation mapping reads the request's method and URL. Scenarios (each
/// on a fresh adapter unless noted): `over_limit_predicate` (a validly signed $400 payment under a `where amount <= 100` grant),
/// `over_limit_max_spend` (the same under a `max_spend: 100` caveat), `body_differs` (a proof signed for $50, a body that says $400),
/// `other_operation` (a `payments.send` proof presented to `POST /refunds`), `escalate_unanswered` (a payment the grant's `tighten[]`
/// escalates, with no principal answer), `missing_revocation` / `missing_store` (no revocation source / no state store), and `valid_first`
/// then `replay_second` on one adapter (a $50 payment runs once, the same request again is refused). Every refusal must happen before the
/// handler runs; an allowed call must carry the bound operation.
extension PCATesting {
    /// One request as the adapter's framework would receive it.
    public struct AcceptanceRequest {
        public var method = "POST"
        /// Path only (`/payments`); adapters that need an absolute URL prefix an origin.
        public var path: String
        public var headers: [String: String]
        public var body: JObject
        public init(method: String = "POST", path: String, headers: [String: String], body: JObject) {
            self.method = method
            self.path = path
            self.headers = headers
            self.body = body
        }
    }

    /// What the harness observed for one request.
    public struct AcceptanceObservation {
        public var status: Int
        public var handlerRan: Bool
        /// The operation the adapter attached for the handler (allowed calls only).
        public var operation: PCA.AuthorizedOperation?
        public init(status: Int, handlerRan: Bool, operation: PCA.AuthorizedOperation? = nil) {
            self.status = status
            self.handlerRan = handlerRan
            self.operation = operation
        }
    }

    /// What the adapter is built from: the `PCA.authorize` template (audience, grant lookup, state store and revocation source, which a
    /// scenario leaves out, the risk source and the pinned provenance mediator; `operation` is left nil) and the server's mapping from a request
    /// to its operation. Pass them to the adapter unchanged.
    public struct AcceptanceOptions {
        public var input: PCA.AuthorizeInput
        public var operation: (AcceptanceRequest) throws -> PCA.Operation?
        public init(input: PCA.AuthorizeInput, operation: @escaping (AcceptanceRequest) throws -> PCA.Operation?) {
            self.input = input
            self.operation = operation
        }
    }

    /// Adapter-specific plumbing: build the adapter once from `options` with a handler spy, and return a function that sends one request
    /// through it. An adapter whose configuration is refused at construction (the options of a scenario lack a required component) may throw
    /// from the builder: the matrix reads that as a refusal (403, the handler never ran), never as an allow.
    public typealias AcceptanceHarness = (AcceptanceOptions) throws -> (AcceptanceRequest) throws -> AcceptanceObservation

    private static let acceptanceProvenanceKey = [UInt8](repeating: 3, count: 32)

    private static func acceptanceMap(_ req: AcceptanceRequest) throws -> PCA.Operation? {
        guard let op = try acceptanceOperation(.object(["method": .string(req.method), "url": .string(req.path), "body": .object(req.body)])),
              let verb = op.get("verb")?.asString, let resource = op.get("resource")?.asString, let params = op.get("params") else { return nil }
        return PCA.Operation(verb: verb, resource: resource, params: params)
    }

    private struct AcceptanceFixture {
        let grant: JSONValue
        let holder: PCASuiteKey
        var counter: Int64 = 0
        let provenancePin: JSONValue

        mutating func request(signedVerb: String, signedAmount: Int64, sentPath: String, sentAmount: Int64) throws -> AcceptanceRequest {
            let params: JSONValue = .object(["payee": .string("acme"), "amount": .int(signedAmount)])
            let node: JObject = ["id": .string("n1"), "verb": .string(signedVerb), "resource": .string("payments"), "params_digest": .string(Merkle.paramsDigest(params)),
                                 "reversibility_class": .string("irreversible")]
            counter += 1
            let p = try PCAIssue.buildPCActn(.init(grant: grant, chain: [grant], plan: try PCAIssue.commitPlan([node]), nodeId: "n1", params: params, counter: counter, signer: holder,
                                                    aud: PCATesting.ADAPTER_ACCEPTANCE_AUDIENCE, iat: Int64(Date().timeIntervalSince1970 * 1000), extras: ["nonce": .string(PCAIssue.random(16))]))
            // provenance by default: the agent presents a principal-direct bundle from a recorder the server pins (the matrix is about limits,
            // binding, replay and configuration, not prompt injection)
            let recorder = try ProvenanceRecorder(mediator: "adapter-acceptance", kid: "k1", signer: .ed25519(try PCAEdKey(seed: PCATesting.acceptanceProvenanceKey)))
            let bundle = try PCA.principalDirectProvenance(recorder, PCA.Operation(verb: signedVerb, resource: "payments", params: params))
            var headers = PCAIssue.headers(p, provenance: bundle)
            headers["content-type"] = "application/json"
            return AcceptanceRequest(path: sentPath, headers: headers, body: ["payee": .string("acme"), "amount": .int(sentAmount)])
        }

        func options(store: Bool = true, revocation: Bool = true) -> AcceptanceOptions {
            let g = grant
            let stateStore: (any PCAStateStore)? = store ? AtlasPCAVerify.MemoryStateStore() : nil
            let isRevoked: ((JSONValue, JSONValue) throws -> Bool?)? = revocation ? { _, _ in false } : nil
            var input = PCA.AuthorizeInput(audience: PCATesting.ADAPTER_ACCEPTANCE_AUDIENCE, resolveGrant: { ref in IV.same(ref, g.get("id")?.asString ?? "") ? g : nil },
                                           stateStore: stateStore, isRevoked: isRevoked, plan: PCA.SINGLE_STEP,
                                           riskSource: { op, _, _ in
                                               // "spend = risk": each call is priced at amount / 100 and debits the amount from a far-away budget
                                               let amt = PCAFacade.jsToNumber(op.params.get("amount")) / 100
                                               return ["blastRadius": PCAFacade.jsNum(amt.isNaN ? amt : min(1, amt)), "semanticDistance": .int(0), "reversibility": .int(0), "taint": .int(0), "confidence": .int(1)]
                                           })
            input.argProvenance = ArgProvenanceOptions(mediators: [provenancePin])
            return AcceptanceOptions(input: input, operation: PCATesting.acceptanceMap)
        }
    }

    private enum Limit { case predicate, maxSpend, escalate }

    private static func acceptanceFixture(_ limit: Limit) throws -> AcceptanceFixture {
        let principal = PCASuiteKey.ed25519(try PCAEdKey.generate())
        let holder = PCASuiteKey.ed25519(try PCAEdKey.generate())
        let recorder = try ProvenanceRecorder(mediator: "adapter-acceptance", kid: "k1", signer: .ed25519(try PCAEdKey(seed: acceptanceProvenanceKey)))
        let amountField: JSONValue = .string("action.params.amount")
        let whereLte: JSONValue = .array([.object(["field": amountField, "op": .string("lte"), "value": .int(100)])])
        var envelope: JObject = [
            "predicates": .array([.object(["verb": .array([.string("payments.send"), .string("payments.refund")]), "resource": .string("payments"),
                                           "where": limit == .maxSpend ? .array([]) : whereLte])]),
            "caveats": .array([]), "agent_binding": .object([:]),
            "risk_policy": .object(["weights": .object(["alpha": .int(0), "beta": .int(0), "gamma": .int(1), "delta": .int(0), "epsilon": .int(0), "zeta": .int(0)]),
                                    "theta1": .int(1), "theta2": .int(1), "kappa": .int(100), "lambda": .int(0), "rho": .double(0.5), "bMax": .int(1_000_000)]),
        ]
        // `escalate`: a payment over 50 asks the principal (decision escalate); with no answer it is refused
        if limit == .escalate {
            envelope["tighten"] = .array([.object(["id": .string("big_payment"), "when": .object(["field": amountField, "op": .string("gt"), "value": .int(50)]), "signal": .string("escalate")])])
        }
        let minted = try PCAIssue.mintGrant(principal: principal, holder: holder.id!, envelope: envelope, goal: "pay invoices").grant
        // max_spend as a ROOT caveat (outside the envelope): enforced like a delegated one
        let grant = limit == .maxSpend
            ? try PCAIssue.mintRoot(principal: principal, holder: holder.id!, caveats: (minted.get("caveats")?.asArray ?? []) + [.object(["type": .string("max_spend"), "usd": .int(100)])])
            : minted
        return AcceptanceFixture(grant: grant, holder: holder, provenancePin: recorder.pin)
    }

    /// Run the matrix through `harness`; compare the result with `ADAPTER_ACCEPTANCE_EXPECTED` (the same names, in the same order).
    public static func runAdapterAcceptance(_ harness: AcceptanceHarness) throws -> [(name: String, outcome: AcceptanceOutcome)] {
        var out: [(name: String, outcome: AcceptanceOutcome)] = []
        func settle(_ req: AcceptanceRequest, _ o: AcceptanceObservation) throws -> AcceptanceOutcome {
            let ran = try acceptanceMap(req)
            let bound = o.operation != nil && ran != nil && PCA.isAuthorizedFor(allow: true, bound: o.operation, operation: ran!)
            return AcceptanceOutcome(status: o.status, handlerRan: o.handlerRan, bound: bound)
        }
        /// A fresh adapter per call; one refused at construction is a refusal.
        func once(_ name: String, _ f: AcceptanceFixture, _ req: AcceptanceRequest, store: Bool = true, revocation: Bool = true) throws {
            let obs: AcceptanceObservation
            do { obs = try harness(f.options(store: store, revocation: revocation))(req) } catch { obs = AcceptanceObservation(status: 403, handlerRan: false) }
            out.append((name, try settle(req, obs)))
        }

        var pred = try acceptanceFixture(.predicate)
        try once("over_limit_predicate", pred, try pred.request(signedVerb: "payments.send", signedAmount: 400, sentPath: "/payments", sentAmount: 400))
        var spend = try acceptanceFixture(.maxSpend)
        try once("over_limit_max_spend", spend, try spend.request(signedVerb: "payments.send", signedAmount: 400, sentPath: "/payments", sentAmount: 400))
        try once("body_differs", pred, try pred.request(signedVerb: "payments.send", signedAmount: 50, sentPath: "/payments", sentAmount: 400))
        try once("other_operation", pred, try pred.request(signedVerb: "payments.send", signedAmount: 50, sentPath: "/refunds", sentAmount: 50))
        var esc = try acceptanceFixture(.escalate)
        try once("escalate_unanswered", esc, try esc.request(signedVerb: "payments.send", signedAmount: 70, sentPath: "/payments", sentAmount: 70))
        try once("missing_revocation", pred, try pred.request(signedVerb: "payments.send", signedAmount: 50, sentPath: "/payments", sentAmount: 50), revocation: false)
        try once("missing_store", pred, try pred.request(signedVerb: "payments.send", signedAmount: 50, sentPath: "/payments", sentAmount: 50), store: false)

        let valid = try pred.request(signedVerb: "payments.send", signedAmount: 50, sentPath: "/payments", sentAmount: 50)
        var send: ((AcceptanceRequest) throws -> AcceptanceObservation)?
        do { send = try harness(pred.options()) } catch { send = nil }
        for name in ["valid_first", "replay_second"] {
            let obs = (try send?(valid)) ?? AcceptanceObservation(status: 403, handlerRan: false)
            out.append((name, try settle(valid, obs)))
        }
        return out
    }
}
