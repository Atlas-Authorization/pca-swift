import Foundation

/// The rail side of the payments package (rails.ts, network-token.ts, testing.ts): the real-time authorization callback that answers from
/// `authorizeChargeAtomic` inside a latency budget, the generic partner token providers (NO network calls: a `PartnerTransport` is the caller's),
/// token issuance behind the binding gate, suspension on revoke, and the single-process reference budget store.
extension PCAPayments {

    /// The trait pattern of the action-kit convention (`mcc.c5734`: the verb may spend in MCC 5734), as a regular expression source.
    public static let MCC_TRAIT_RE = "^mcc\\.c(\\d{4})$"

    // MARK: network token providers

    /// A card network's token surface: issue a token whose own controls equal `controls`, and suspend it (idempotent).
    public struct NetworkTokenProvider {
        public var id: String
        /// `{controls, agentId}` in, `{token_ref}` out.
        public var issue: (JSONValue) throws -> JSONValue
        public var suspend: (_ tokenRef: String, _ reason: String) throws -> Void
        public init(id: String, issue: @escaping (JSONValue) throws -> JSONValue, suspend: @escaping (String, String) throws -> Void) {
            self.id = id; self.issue = issue; self.suspend = suspend
        }
    }

    /// The transport of a partner adapter: `post(path, body)` returns the response object.
    public struct PartnerTransport {
        public var post: (_ path: String, _ body: JSONValue) throws -> JSONValue
        public init(post: @escaping (String, JSONValue) throws -> JSONValue) { self.post = post }
    }

    private static func encodeURIComponent(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.!~*'()")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    /// GENERIC MAPPING, NOT THE PARTNER WIRE FORMAT: the path and body names are placeholders; the control values are exact copies of PCA's limits.
    private static func partnerAdapter(_ id: String, _ scopeKey: String, _ t: PartnerTransport) -> NetworkTokenProvider {
        NetworkTokenProvider(id: id, issue: { req in
            let r: JSONValue? = req
            let controls = try P.prop(r, "controls")
            let c: JSONValue? = controls
            var scope: JObject = [:]
            scope["currency"] = try P.prop(c, "currency") ?? .null
            scope["per_authorization_max"] = try P.prop(c, "perAuthorizationMax") ?? .null
            scope["total_max"] = try P.prop(c, "totalMax") ?? .null
            scope["merchant_categories"] = try P.prop(c, "categories") ?? .null
            scope["merchants"] = try P.prop(c, "merchants") ?? .null
            if let e = try P.prop(c, "expiresAt") { scope["expires_at"] = e }
            let resp = try t.post("/tokens", .object(["agent_id": try P.prop(r, "agentId") ?? .null, JKey(scopeKey): .object(scope), "metadata": try P.prop(c, "metadata") ?? .null]))
            let ref = try P.prop(resp, "token_ref")
            if let e = tokenRefError(ref) { throw JSError("\(id): provider returned \(e)") }
            return .object(["token_ref": ref ?? .null])
        }, suspend: { tokenRef, reason in
            _ = try t.post("/tokens/\(encodeURIComponent(tokenRef))/suspend", .object(["reason": .string(reason)]))
        })
    }

    /// Visa Intelligent Commerce, generic mapping (partner-gated; unverified field names).
    public static func visaIntelligentCommerceAdapter(_ transport: PartnerTransport) -> NetworkTokenProvider { partnerAdapter("visa_ic", "instructions", transport) }
    /// Mastercard Agent Pay (agentic tokens over MDES), generic mapping (partner-gated; unverified field names).
    public static func mastercardAgentPayAdapter(_ transport: PartnerTransport) -> NetworkTokenProvider { partnerAdapter("mastercard_agent_pay", "session_scope", transport) }

    /// Issuance gate: the token is requested with controls no wider than the rail limits, a provider answer whose reference is malformed or PAN-shaped is
    /// refused (by `bindNetworkToken`), and the holder binds the reference to the grant. Returns `{binding, controls}`.
    public static func issueBoundNetworkToken(provider: NetworkTokenProvider, limits: JSONValue, grant: JSONValue, agentId: String, holder: PCAEdKey, holderPublic: [UInt8],
                                              issuerNonce: String) throws -> JSONValue {
        let controls = try controlsFromLimits(limits, grant)
        let issued = try provider.issue(.object(["controls": controls, "agentId": .string(agentId)]))
        let binding = try bindNetworkToken(.object(["provider": .string(provider.id), "tokenRef": try P.prop(issued, "token_ref") ?? .null, "grant": grant,
                                                    "issuerNonce": .string(issuerNonce)]), holder: holder, holderPublic: holderPublic)
        return .object(["binding": binding, "controls": controls])
    }

    /// Grant revoked => suspend. Provider errors propagate (the caller must retry; a failed suspend is not a success).
    public static func suspendOnRevoke(_ provider: NetworkTokenProvider, _ binding: JSONValue) throws {
        guard let ref = try P.prop(binding, "token_ref")?.asString else { throw JSError("suspendOnRevoke: the binding has no token_ref") }
        try provider.suspend(ref, "grant_revoked")
    }

    // MARK: the real-time authorization callback

    /// The instrument a rail authorization is for: its mandate, the grant the caller verified or loaded from its own store, and the budget key (default the grant hash).
    public struct InstrumentBinding {
        public var mandate: JSONValue
        public var grant: JSONValue
        public var budgetKey: String?
        public init(mandate: JSONValue, grant: JSONValue, budgetKey: String? = nil) { self.mandate = mandate; self.grant = grant; self.budgetKey = budgetKey }
    }

    public struct RailAuthorizerOptions {
        public var instruments: (_ instrumentId: String) throws -> InstrumentBinding?
        public var store: BudgetStore
        /// Answer by this many ms or decline. Stripe waits 2000 ms; the default 1500 leaves room for the network.
        public var latencyBudgetMs: Double?
        public var now: (() -> Double)?
        /// A step-up cannot wait at a card terminal: it is declined here, and this hook may notify the principal.
        public var onStepUp: ((_ authorization: JSONValue, _ decision: JSONValue) throws -> Void)?
        public init(instruments: @escaping (String) throws -> InstrumentBinding?, store: BudgetStore, latencyBudgetMs: Double? = nil, now: (() -> Double)? = nil,
                    onStepUp: ((JSONValue, JSONValue) throws -> Void)? = nil) {
            self.instruments = instruments; self.store = store; self.latencyBudgetMs = latencyBudgetMs; self.now = now; self.onStepUp = onStepUp
        }
    }

    private static func decline(_ reasons: [String], _ decision: JSONValue? = nil) -> JSONValue {
        var v: JObject = ["approved": .bool(false), "reasons": .array(reasons.map { .string($0) })]
        if let d = decision { v["decision"] = d }
        return .object(v)
    }

    private static func railDecide(_ a: JSONValue, _ o: RailAuthorizerOptions, _ decide: Decide) -> JSONValue {
        guard a.isObject, let id = a.get("id")?.asString, !id.isEmpty, let instrumentId = a.get("instrumentId")?.asString else { return decline(["malformed_authorization"]) }
        guard let amount = P.numOf(a.get("amount")), P.safeF(amount), amount > 0 else { return decline(["amount_not_positive_minor_units"]) }
        guard let currency = a.get("currency")?.asString, !currency.isEmpty else { return decline(["currency_missing"]) }
        guard let merchant = a.get("merchantId")?.asString, !merchant.isEmpty else { return decline(["merchant_unknown"]) }
        do {
            guard let inst = try o.instruments(instrumentId) else { return decline(["instrument_unknown"]) }
            var charge: JObject = ["merchant": .string(merchant), "amount": a.get("amount") ?? .null, "currency": .string(P.jsUpper(currency)),
                                   "now": P.num((o.now ?? { P.nowMs() })())]
            if let c = a.get("mcc"), c != .null { charge["category"] = c }
            let d = try authorizeChargeAtomic(inst.mandate, .object(charge), inst.grant, store: o.store, decide: decide, key: inst.budgetKey)
            let reasons = (d.get("reasons")?.asArray ?? []).map { P.tostr($0) }
            switch d.get("outcome")?.asString {
            case "auto": return .object(["approved": .bool(true), "reasons": .array([]), "decision": d])
            case "step_up":
                do { try o.onStepUp?(a, d) } catch { /* a failing notifier must not change the answer */ }
                return decline(["step_up_required"] + reasons, d)
            default: return decline(reasons.isEmpty ? ["denied"] : reasons, d)
            }
        } catch {
            return decline(["authorizer_error"])
        }
    }

    /// The single code path from a rail request `{id, instrumentId, amount, currency, merchantId?, mcc?}` to a verdict `{approved, reasons, decision?}`.
    /// Total: every failure, a step-up, an unknown card and a timeout are declines; an approval is only ever PCA's own `auto`. A decision that finishes
    /// after the timeout may still have debited the budget with no approval sent (budget under-spend, the safe direction).
    public static func createRailAuthorizer(_ opts: RailAuthorizerOptions, decide: @escaping Decide = { try PCAPolicyVm.decide($0) }) throws -> (JSONValue) -> JSONValue {
        let budgetMs = opts.latencyBudgetMs ?? 1500
        guard budgetMs.isFinite, budgetMs > 0 else { throw JSError("createRailAuthorizer: latencyBudgetMs must be positive") }
        return { a in
            final class Box: @unchecked Sendable { var v: JSONValue? }
            let box = Box()
            let sem = DispatchSemaphore(value: 0)
            let lock = NSLock()
            Thread {
                let r = railDecide(a, opts, decide)
                lock.lock(); box.v = r; lock.unlock()
                sem.signal()
            }.start()
            if sem.wait(timeout: .now() + .milliseconds(Int(budgetMs.rounded(.up)))) == .timedOut { return decline(["latency_budget_exceeded"]) }
            lock.lock(); defer { lock.unlock() }
            return box.v ?? decline(["authorizer_error"])
        }
    }

    // MARK: testing

    /// Single-process reference budget store for tests; production needs a durable store with a conditional write.
    public static func memoryChargeBudgetStore() -> BudgetStore {
        final class Mem: @unchecked Sendable {
            let lock = NSLock()
            var m: [String: (budget: JSONValue, version: Int64)] = [:]
        }
        let mem = Mem()
        return BudgetStore(get: { k in
            mem.lock.lock(); defer { mem.lock.unlock() }
            return mem.m[k].map { .object(["budget": $0.budget, "version": .int($0.version)]) }
        }, compareAndSet: { k, expected, budget in
            mem.lock.lock(); defer { mem.lock.unlock() }
            guard mem.m[k]?.version == expected else { return false }
            mem.m[k] = (budget, (expected ?? 0) + 1)
            return true
        })
    }
}
