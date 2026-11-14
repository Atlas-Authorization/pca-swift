import Foundation

// The facade: `PCAAgent.fromPrincipal` compiles human-level inputs (permissions, limits) into the real primitives (a policy envelope, a
// risk policy, a signed root intent grant naming the harness's provenance recorder) and returns a handle that builds one proof-carrying
// action per tool call. Nothing here authorizes anything: the resource server's verifier decides, and every field the facade emits is
// covered by a signature. Same compile-down and wire as the TypeScript reference's `agent()`, byte for byte.
//
//     let a = try PCAAgent.fromPrincipal(PCAAgentOptions(principal: principal, goal: "refund order 1",
//                                                        permissions: [("stripe", ["refund"])], limits: ["refund": "$500/day"], aud: "ins_123"))
//     let r = try a.act(verb: "stripe.refund", resource: "charge:ch_1", params: .object(["amount": .int(42), "currency": .string("usd")]))
//     for (k, v) in r.headers { request.setValue(v, forHTTPHeaderField: k) }   // PCA-Action (+ PCA-Provenance)
//
// Keep the provenance recorder in the harness, out of the model's reach (never expose `provenance` as a tool).

/// One action definition: the verb `connector.action`, its reversibility class (reversible < rate_limited < irreversible), a blast-radius
/// preset in [0, 1], and for a money-moving action the params field that carries the amount.
public struct PCACatalogAction: Equatable, Sendable {
    public var connector: String
    public var action: String
    public var verb: String
    public var reversibility: String
    public var blastRadius: Double
    public var amountField: String?
    public var description: String
    public var aliases: [String]
    public var traits: [String]
    public var resource: String?
    public init(connector: String, action: String, verb: String, reversibility: String, blastRadius: Double, amountField: String?, description: String,
                aliases: [String] = [], traits: [String] = [], resource: String? = nil) {
        self.connector = connector; self.action = action; self.verb = verb; self.reversibility = reversibility; self.blastRadius = blastRadius
        self.amountField = amountField; self.description = description; self.aliases = aliases; self.traits = traits; self.resource = resource
    }
}

/// Resolves verbs (and aliases) to action definitions; a later definition of a verb replaces an earlier one.
public struct PCACatalog: Sendable {
    private var byVerb: [JKey: PCACatalogAction] = [:]
    private var order: [JKey] = []

    public init(_ actions: [PCACatalogAction]) {
        for a in actions {
            if byVerb[JKey(a.verb)] == nil { order.append(JKey(a.verb)) }
            byVerb[JKey(a.verb)] = a
        }
    }

    /// The catalog of the built-in actions.
    public static var `default`: PCACatalog { PCACatalog(builtin) }

    public func get(_ verb: String) -> PCACatalogAction? { byVerb[JKey(verb)] }

    /// `connector.action`, else the ONE action of the connector that has `action` as an alias (never a guess).
    public func resolve(connector: String, action: String) -> PCACatalogAction? {
        if let a = get(connector + "." + action) { return a }
        let hits = order.compactMap { byVerb[$0] }.filter { IV.same($0.connector, connector) && IV.contains($0.aliases, action) }
        return hits.count == 1 ? hits[0] : nil
    }

    /// The definition of a verb; an uncatalogued verb counts as irreversible with blast radius 0.8.
    public func specFor(_ verb: String) -> PCACatalogAction {
        if let s = get(verb) { return s }
        let parts = verb.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if parts.count > 1, !parts[0].isEmpty, let via = resolve(connector: parts[0], action: parts.dropFirst().joined(separator: ".")) { return via }
        let action = parts.dropFirst().joined(separator: ".")
        return PCACatalogAction(connector: parts[0], action: action.isEmpty ? verb : action, verb: verb, reversibility: "irreversible", blastRadius: 0.8,
                                amountField: nil, description: "(uncatalogued) \(verb)")
    }
}

/// A parsed limit: `unit` "usd" (`$N`) or "count" (`N`), and the window it names in ms (nil: none).
public struct PCAParsedLimit: Equatable, Sendable {
    public var amount: Double
    public var unit: String
    public var periodMs: Int64?

    /// The reference's ParsedLimit object: `{amount, unit, periodMs?}`.
    public var json: JSONValue {
        var o: JObject = ["amount": PCAFacade.jsNum(amount), "unit": .string(unit)]
        if let p = periodMs { o["periodMs"] = .int(p) }
        return .object(o)
    }
}

/// The policy envelope material `PCAFacade.compilePolicy` derives.
public struct PCACompiledPolicy: Sendable {
    public var predicates: [JSONValue]
    public var caveats: [JSONValue]
    public var riskPolicy: JObject
    public var actions: [PCACatalogAction]
    /// "dollars" or "risk".
    public var budgetModel: String
    /// Per verb, in first-seen order, the limits that matched a granted action.
    public var limits: [(verb: String, limit: PCAParsedLimit)]
    public var inputLimits: [String: String]
    /// Limits this offline compiler only approximates (a `$N/period` is a per-call ceiling plus a one-period lifetime).
    public var approximations: [String]

    /// The reference's CompiledPolicy object without its action specs and raw inputs:
    /// `{predicates, caveats, riskPolicy, budgetModel, limits, approximations}`.
    public var json: JSONValue {
        var lim: JObject = [:]
        for (v, l) in limits { lim[JKey(v)] = l.json }
        return .object(["predicates": .array(predicates), "caveats": .array(caveats), "riskPolicy": .object(riskPolicy), "budgetModel": .string(budgetModel),
                        "limits": .object(lim), "approximations": .array(approximations.map { .string($0) })])
    }
}

public enum PCAFacade {
    /// The longest limit string accepted, in UTF-16 code units.
    public static let MAX_LIMIT_LENGTH = 64

    /// The reference's default risk policy.
    public static let DEFAULT_RISK_POLICY: JObject = [
        "weights": .object(["alpha": .double(0.25), "beta": .double(0.2), "gamma": .double(0.2), "delta": .double(0.2), "epsilon": .double(0.1), "zeta": .double(0.05)]),
        "theta1": .double(0.25), "theta2": .double(0.6), "kappa": .int(1), "lambda": .double(0.0005), "rho": .double(0.5), "bMax": .int(1),
    ]

    static let PERIODS: [String: Int64] = [
        "s": 1000, "sec": 1000, "second": 1000, "seconds": 1000,
        "m": 60_000, "min": 60_000, "minute": 60_000, "minutes": 60_000,
        "h": 3_600_000, "hr": 3_600_000, "hour": 3_600_000, "hours": 3_600_000,
        "d": 86_400_000, "day": 86_400_000, "days": 86_400_000,
        "w": 604_800_000, "week": 604_800_000, "weeks": 604_800_000,
        "mo": 2_592_000_000, "month": 2_592_000_000, "months": 2_592_000_000,
    ]

    static let REVERSIBILITY_ORDER = ["reversible", "rate_limited", "irreversible"]

    /// A JSON number for a binary64 value: an integer when it is a safe integer, else the double.
    static func jsNum(_ d: Double) -> JSONValue { IV.isSafeDouble(d) && !IV.isNegZero(d) ? .int(Int64(d)) : .double(d) }

    /// JavaScript's `String(number)` (exponent form at or above 1e21 and below 1e-6, as `Number.prototype.toString`).
    static func jsNumberText(_ d: Double) -> String {
        let a = abs(d)
        guard d.isFinite, a != 0, a >= 1e21 || a < 1e-6 else { return Canonical.numberString(d) }
        let t = "\(d)" // Swift's shortest round trip, e.g. "1.5e+21" or "1e-07" (a one-digit mantissa has no ".0")
        guard let e = t.firstIndex(where: { $0 == "e" || $0 == "E" }), let x = Int(t[t.index(after: e)...]) else { return t }
        let m = String(t[..<e])
        return "\(m)e\(x < 0 ? "-" : "+")\(abs(x))"
    }

    /// Parse `"$500/day"`, `"$500"`, `"10/hour"` or `"10"` (periods s, m, h, d, w, mo and their long forms).
    public static func parseLimit(_ s: String) throws -> PCAParsedLimit {
        let t = Array(Attest.jsTrim(s).unicodeScalars)
        if t.isEmpty { throw PCAProducerError("parseLimit: empty limit") }
        if s.utf16.count > MAX_LIMIT_LENGTH { throw PCAProducerError("parseLimit: limit is longer than \(MAX_LIMIT_LENGTH) characters") }
        let bad = PCAProducerError("parseLimit: cannot parse limit '\(s)'")
        func digit(_ c: Unicode.Scalar) -> Bool { c.value >= 48 && c.value <= 57 }
        func letter(_ c: Unicode.Scalar) -> Bool { (c.value >= 65 && c.value <= 90) || (c.value >= 97 && c.value <= 122) }
        var i = 0
        func ws() { while i < t.count, Attest.isJSSpace(t[i]) { i += 1 } }
        let usd = t[0] == "$"
        if usd { i = 1 }
        ws()
        let numStart = i
        while i < t.count, digit(t[i]) { i += 1 }
        if i == numStart { throw bad }
        if i < t.count, t[i] == "." {
            i += 1
            let fracStart = i
            while i < t.count, digit(t[i]) { i += 1 }
            if i == fracStart { throw bad }
        }
        let numText = String(String.UnicodeScalarView(t[numStart..<i]))
        ws()
        var period: String?
        if i < t.count {
            guard t[i] == "/" else { throw bad }
            i += 1
            ws()
            let pStart = i
            while i < t.count, letter(t[i]) { i += 1 }
            if i == pStart || i != t.count { throw bad }
            period = String(String.UnicodeScalarView(t[pStart..<i]))
        }
        guard let amount = Double(numText), amount.isFinite else { throw PCAProducerError("parseLimit: bad amount in '\(s)'") }
        var periodMs: Int64?
        if let p = period {
            guard let ms = PERIODS[p.lowercased()] else { throw PCAProducerError("parseLimit: unknown period '\(p)' in '\(s)'") }
            periodMs = ms
        }
        return PCAParsedLimit(amount: amount, unit: usd ? "usd" : "count", periodMs: periodMs)
    }

    /// Compile permissions and limits into predicates, caveats and a risk policy. Pure: no keys, no signing. `permissions` lists each
    /// connector with its granted actions, in order (it fixes the order of the predicates); `limits` are keyed by full verb
    /// (`stripe.refund`), bare action (`refund`) or alias, the verb winning. A `$N` limit becomes a per-call ceiling on the action's amount
    /// field (refused on a verb with none); the strictest reversibility class becomes a `reversibility_max` caveat, the shortest limit
    /// period the grant lifetime, and every `N/period` limit one rate caveat. `budgetModel`: "auto" (or nil), "dollars" or "risk";
    /// `riskPolicy` members override the derived policy (weights merge member by member). `now`: epoch ms of the limit windows.
    public static func compilePolicy(permissions: [(String, [String])], limits: [String: String]? = nil, catalog: PCACatalog = .default,
                                     budgetModel: String? = nil, riskPolicy: JObject? = nil, now: Int64? = nil) throws -> PCACompiledPolicy {
        let at = now ?? Int64(Date().timeIntervalSince1970 * 1000)
        var actions: [PCACatalogAction] = []
        for (connector, acts) in permissions { for a in acts { actions.append(catalog.specFor("\(connector).\(a)")) } }
        if actions.isEmpty { throw PCAProducerError("compilePolicy: no permissions granted") }

        let raw = limits ?? [:]
        var parsed: [(verb: String, limit: PCAParsedLimit)] = []
        func limitFor(_ s: PCACatalogAction) throws -> PCAParsedLimit? {
            var text: String?
            for k in [s.verb, s.action] + s.aliases where text == nil { text = raw[k] }
            guard let t = text else { return nil }
            let pl = try parseLimit(t)
            if let i = parsed.firstIndex(where: { IV.same($0.verb, s.verb) }) { parsed[i].limit = pl } else { parsed.append((s.verb, pl)) }
            return pl
        }

        var predicates: [JSONValue] = []
        for s in actions {
            let lim = try limitFor(s)
            var pred: JObject = ["verb": .string(s.verb), "resource": .string(s.resource ?? "*")]
            if let l = lim, l.unit == "usd" {
                guard let f = s.amountField else {
                    throw PCAProducerError("compilePolicy: '$' limit on '\(s.verb)' but the catalog gives that verb no amount field, so the limit could not be enforced")
                }
                let field = JSONValue.string("action.params.\(f)")
                pred["where"] = .array([.object(["field": field, "op": .string("lte"), "value": jsNum(l.amount)]),
                                        .object(["field": field, "op": .string("gte"), "value": .int(0)])])
            }
            predicates.append(.object(pred))
        }

        func sev(_ c: String) -> Int { REVERSIBILITY_ORDER.firstIndex(of: c) ?? -1 }
        var strictest = "reversible"
        for s in actions where sev(s.reversibility) > sev(strictest) { strictest = s.reversibility }
        var caveats: [JSONValue] = [.object(["type": .string("reversibility_max"), "class": .string(strictest)])]
        let periods = parsed.compactMap { $0.limit.periodMs }
        if let p = periods.min() { caveats.append(.object(["type": .string("expires"), "at": .int(at + p)])) }
        for (_, l) in parsed where l.unit == "count" {
            if let p = l.periodMs { caveats.append(.object(["type": .string("rate"), "max": jsNum(l.amount), "per_secs": .int(max(1, (p + 500) / 1000))])) }
        }

        let dollars = parsed.filter { $0.limit.unit == "usd" }.map { $0.limit.amount }
        let model = budgetModel == "dollars" || budgetModel == "risk" ? budgetModel! : (dollars.isEmpty ? "risk" : "dollars")
        let irreversible = actions.contains { $0.reversibility == "irreversible" }
        var rp = DEFAULT_RISK_POLICY
        if model == "dollars", let kappa = dollars.max() {
            let bMax = dollars.reduce(0, +) // in order, as the reference sums
            rp = ["weights": .object(["alpha": .int(0), "beta": .int(0), "gamma": .int(1), "delta": .int(0), "epsilon": .int(0), "zeta": .int(0)]),
                  // within-cap actions auto-approve only when nothing granted is irreversible; otherwise the default co-sign tiers stay
                  "theta1": irreversible ? DEFAULT_RISK_POLICY["theta1"]! : .int(1), "theta2": irreversible ? DEFAULT_RISK_POLICY["theta2"]! : .int(1),
                  "kappa": jsNum(kappa > 0 ? kappa : 1), "lambda": .int(0), "rho": DEFAULT_RISK_POLICY["rho"]!, "bMax": jsNum(bMax > 0 ? bMax : 1)]
        }
        if let o = riskPolicy {
            var w = rp["weights"]?.asObject ?? [:]
            if case let .object(ow)? = o["weights"] { for (k, v) in ow { w[k] = v } }
            for (k, v) in o { rp[k] = v }
            rp["weights"] = .object(w)
        }
        guard case let .object(rpN) = try PCAIssue.norm(.object(rp)) else { throw PCAProducerError("compilePolicy: derived risk policy invalid") }
        if let bad = PCA.validateRiskPolicy(.object(rpN)) { throw PCAProducerError("compilePolicy: derived risk policy invalid: \(bad)") }
        let approx = parsed.filter { $0.limit.unit == "usd" && $0.limit.periodMs != nil }.map {
            "\($0.verb): $\(jsNumberText($0.limit.amount))/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap"
        }
        guard case let .array(predsN) = try PCAIssue.norm(.array(predicates)), case let .array(cavN) = try PCAIssue.norm(.array(caveats)) else {
            throw PCAProducerError("compilePolicy: predicates")
        }
        return PCACompiledPolicy(predicates: predsN, caveats: cavN, riskPolicy: rpN, actions: actions, budgetModel: model, limits: parsed,
                                 inputLimits: raw, approximations: approx)
    }

    /// JavaScript's `Number(v)` for a params member (NaN when absent or for an object).
    static func jsToNumber(_ v: JSONValue?) -> Double {
        switch v {
        case nil: return .nan
        case .null?: return 0
        case let .bool(b)?: return b ? 1 : 0
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        case let .string(s)?: return IV.jsNumber(s)
        case let .array(a)?:
            // Number([x]) is Number(String(x)): [] and [null] are 0, [n], ["n"] and [[n]] the number, anything else NaN
            if a.isEmpty { return 0 }
            guard a.count == 1, let x = a.first else { return .nan }
            switch x {
            case .null: return 0
            case .int, .double, .string, .array: return jsToNumber(x)
            default: return .nan
            }
        case .object?: return .nan
        }
    }
}

/// The provenance recorder options of `PCAAgentOptions` (mediator "agent-harness", kid "k1", a fresh key and session by default).
public struct PCAProvenanceOptions {
    public var mediator = "agent-harness"
    public var kid = "k1"
    /// The mediator key; generated when nil. Keep it out of the model's reach: the grant names it.
    public var signer: PCASuiteKey?
    /// Canonical base64url of 32 bytes; random when nil.
    public var session: String?
    public var now: (() -> Int64)?
    public init(mediator: String = "agent-harness", kid: String = "k1", signer: PCASuiteKey? = nil, session: String? = nil, now: (() -> Int64)? = nil) {
        self.mediator = mediator; self.kid = kid; self.signer = signer; self.session = session; self.now = now
    }
}

/// What `PCAAgent.fromPrincipal` builds an agent from. `principal`, `goal` and `permissions` are required.
public struct PCAAgentOptions {
    /// The human's key: signs and roots the grant.
    public var principal: PCASuiteKey
    /// The plaintext goal; only its salted commitment goes in the grant.
    public var goal: String
    /// Each connector with its granted actions, in order, e.g. `[("stripe", ["refund"])]`.
    public var permissions: [(String, [String])]
    public var limits: [String: String]?
    /// The agent key that signs actions (a generated Ed25519 key when nil). Under a post-quantum or hybrid suite its PQ key is committed
    /// in the grant as `holder_pq`.
    public var holder: PCASuiteKey?
    public var agentBinding: JObject?
    public var riskPolicy: JObject?
    public var budgetModel: String?
    public var catalog: PCACatalog?
    /// The default audience of `act`.
    public var aud: String?
    /// Epoch ms of minting and of the limit windows; nil: the wall clock.
    public var now: Int64?
    public var provenance: PCAProvenanceOptions?
    /// base64url salt of the goal commitment; nil draws one (set it only to reproduce a grant).
    public var goalSalt: String?

    public init(principal: PCASuiteKey, goal: String, permissions: [(String, [String])], limits: [String: String]? = nil, holder: PCASuiteKey? = nil,
                agentBinding: JObject? = nil, riskPolicy: JObject? = nil, budgetModel: String? = nil, catalog: PCACatalog? = nil, aud: String? = nil,
                now: Int64? = nil, provenance: PCAProvenanceOptions? = nil, goalSalt: String? = nil) {
        self.principal = principal; self.goal = goal; self.permissions = permissions; self.limits = limits; self.holder = holder
        self.agentBinding = agentBinding; self.riskPolicy = riskPolicy; self.budgetModel = budgetModel; self.catalog = catalog; self.aud = aud
        self.now = now; self.provenance = provenance; self.goalSalt = goalSalt
    }
}

/// Per-call options of `PCAFacadeAgent.act`.
public struct PCAActOptions {
    /// The replay counter; nil: one more than the highest so far.
    public var counter: Int64?
    public var aud: String?
    /// Issued-at in epoch ms; nil: the wall clock.
    public var now: Int64?
    public var ttlMs: Int64?
    /// Signed when given (no nonce by default).
    public var nonce: String?
    /// The agent's own uncertainty in [0, 1]: it can only raise the server's risk.
    public var caution: Double?
    /// Overrides the claimed risk (else from the amount or the blast radius).
    public var risk: Double?
    public init(counter: Int64? = nil, aud: String? = nil, now: Int64? = nil, ttlMs: Int64? = nil, nonce: String? = nil, caution: Double? = nil, risk: Double? = nil) {
        self.counter = counter; self.aud = aud; self.now = now; self.ttlMs = ttlMs; self.nonce = nonce; self.caution = caution; self.risk = risk
    }
}

/// A local, NON-authoritative check of the grant's own predicates and caveats; `t` is the risk tier the policy would assign (1 automatic,
/// 2 guardian co-sign, 3 human).
public struct PCADryRun: Equatable, Sendable {
    public var allowed: Bool
    public var reason: String?
    public var t: Int?
}

/// One built action: the PCActn, its encoded JSON, the headers to send (`PCA-Action`, and `PCA-Provenance` when the bundle fits a header;
/// else send `provenance` as the body member `pca_provenance`), the local dry run and the provenance bundle.
public struct PCAActResult {
    public let pcactn: JSONValue
    public let encoded: String
    public let headers: [String: String]
    public let dryRun: PCADryRun
    public let provenance: JSONValue
}

extension PCAAgent {
    /// Build an agent from the principal's inputs: compile the policy, create the provenance recorder (its key is pinned in the grant
    /// envelope), mint the root intent grant and return the handle that builds one proof-carrying action per tool call.
    public static func fromPrincipal(_ o: PCAAgentOptions) throws -> PCAFacadeAgent { try PCAFacadeAgent.create(o) }
}

/// What `PCAAgent.fromPrincipal` returns: the signed grant and chain, the compiled policy, the holder key, the starting trust budget, and
/// `act` / `dryRun` / `subAgent`. `provenance` is the session's recorder: record the principal's message and every tool, retrieval or
/// web result entering the model's context; `act` appends the action. Safe for concurrent use.
public final class PCAFacadeAgent: @unchecked Sendable {
    public let grant: JSONValue
    public let chain: [JSONValue]
    public let goalSalt: String
    public let goalCommit: String
    public let policy: PCACompiledPolicy
    public let holder: PCASuiteKey
    public let principalPublic: String
    /// The starting trust budget (B = bMax); the server meters it.
    public let budget: Risk.Budget
    /// The most this agent can do between human co-signs.
    public let autonomyBound: Double
    public let provenance: ProvenanceRecorder

    private let catalog: PCACatalog
    private let aud: String?
    private let startNow: Int64
    let lock = PCALock()
    private var counter: Int64 = 0

    init(grant: JSONValue, chain: [JSONValue], goalSalt: String, goalCommit: String, policy: PCACompiledPolicy, holder: PCASuiteKey, principal: String,
         catalog: PCACatalog, aud: String?, startNow: Int64, recorder: ProvenanceRecorder) {
        self.grant = grant; self.chain = chain; self.goalSalt = goalSalt; self.goalCommit = goalCommit; self.policy = policy; self.holder = holder
        self.principalPublic = principal; self.catalog = catalog; self.aud = aud; self.startNow = startNow; self.provenance = recorder
        let bMax = IV.num(policy.riskPolicy["bMax"]) ?? 0
        let kappa = IV.num(policy.riskPolicy["kappa"]) ?? 0
        budget = Risk.Budget(b: bMax, tau: Double(startNow), asOf: Double(startNow))
        autonomyBound = (kappa > 0 ? max(0, bMax) / kappa : 0) * kappa
    }

    static func create(_ o: PCAAgentOptions) throws -> PCAFacadeAgent {
        guard let principal = o.principal.id else { throw PCAProducerError("agent: the principal needs an Ed25519 identity") }
        let catalog = o.catalog ?? .default
        let now = o.now ?? Int64(Date().timeIntervalSince1970 * 1000)
        let holder = try o.holder ?? .ed25519(PCAEdKey.generate())
        guard let hid = holder.id else { throw PCAProducerError("agent: the holder needs an Ed25519 identity") }
        let policy = try PCAFacade.compilePolicy(permissions: o.permissions, limits: o.limits, catalog: catalog, budgetModel: o.budgetModel,
                                                 riskPolicy: o.riskPolicy, now: now)
        let po = o.provenance ?? PCAProvenanceOptions()
        let rec = try ProvenanceRecorder(mediator: po.mediator, kid: po.kid, signer: try po.signer ?? .ed25519(PCAEdKey.generate()), session: po.session, now: po.now)
        let env: JObject = ["predicates": .array(policy.predicates), "caveats": .array(policy.caveats), "agent_binding": .object(o.agentBinding ?? [:]),
                            "risk_policy": .object(policy.riskPolicy),
                            // the principal designates the harness's mediator key: a verifier trusts its labels with no extra configuration
                            "provenance": .object(["mediators": .array([rec.pin])])]
        let g = try PCAIssue.mintGrant(principal: o.principal, holder: hid, holderPqPk: holder.pqPk, envelope: env, goal: o.goal, salt: o.goalSalt)
        return PCAFacadeAgent(grant: g.grant, chain: [g.grant], goalSalt: g.goalSalt, goalCommit: g.goalCommit, policy: policy, holder: holder, principal: principal,
                              catalog: catalog, aud: o.aud, startNow: now, recorder: rec)
    }

    /// The override clamped to [0, 1], else amount / kappa in the dollars model, else the catalog's blast radius.
    func riskFor(_ spec: PCACatalogAction, _ params: JSONValue?, _ override: Double?) -> Double {
        func clamp(_ x: Double) -> Double { max(0, min(1, x)) }
        if let r = override { return clamp(r) }
        if policy.budgetModel == "dollars", let f = spec.amountField {
            let amt = PCAFacade.jsToNumber(params?.get(f))
            if let kappa = IV.num(policy.riskPolicy["kappa"]), amt.isFinite, kappa > 0 { return clamp(amt / kappa) }
        }
        return clamp(spec.blastRadius)
    }

    /// Check the grant's own predicates and caveats for an action, locally and without authority (the server decides).
    public func dryRun(verb: String, resource: String, params: JSONValue? = nil, now: Int64? = nil) -> PCADryRun {
        let spec = catalog.specFor(verb)
        let at = now ?? Int64(Date().timeIntervalSince1970 * 1000)
        let p = (try? PCAIssue.norm(params ?? .object([:]))) ?? .object([:])
        let ctx: JSONValue = .object(["action": .object(["verb": .string(verb), "resource": .string(resource), "params": p,
                                                         "reversibility_class": .string(spec.reversibility)])])
        if let why = PCA.envelopePredicatesError(.array(policy.predicates), ctx, SafeRegex.Budget()) { return PCADryRun(allowed: false, reason: why, t: nil) }
        let cav = PCA.evaluateCaveats(.array(policy.caveats), context: .object([
            "now": .int(at), "blast_radius": PCAFacade.jsNum(spec.blastRadius), "reversibility_class": .string(spec.reversibility),
            "delegation_depth": .int(Int64(chain.count - 1)),
            // the local handle has no admitted-action history (the server meters it), so a rate caveat can hold
            "recent_action_times": .array([]),
        ]))
        if !cav.ok { return PCADryRun(allowed: false, reason: "caveat(s) failed: " + cav.failed.joined(separator: ", "), t: nil) }
        let r = riskFor(spec, p, nil)
        let th = Risk.requiredThreshold(r, theta1: IV.num(policy.riskPolicy["theta1"]) ?? 0, theta2: IV.num(policy.riskPolicy["theta2"]) ?? 0)
        let covers = budget.b >= Risk.cost(r, kappa: IV.num(policy.riskPolicy["kappa"]) ?? 0)
        return PCADryRun(allowed: true, reason: nil, t: Risk.admit(t: th.t, covers: covers).t)
    }

    /// Build the proof-carrying action for one tool call (it does NOT authorize): a one-node plan (node `n0`, the catalog's reversibility
    /// class, the params digest) signed by the holder with a risk claim, and the provenance bundle of the action. No nonce unless given.
    public func act(verb: String, resource: String, params: JSONValue? = nil, options o: PCAActOptions = PCAActOptions()) throws -> PCAActResult {
        guard let a = o.aud ?? aud, !a.isEmpty else {
            throw PCAProducerError("act: aud (resource-server / instance id) is required (pass PCAActOptions.aud or PCAAgentOptions.aud)")
        }
        let spec = catalog.specFor(verb)
        // the node commits the SAME params digest the action carries, else plan inclusion fails
        let node: JObject = ["id": .string("n0"), "verb": .string(verb), "resource": .string(resource), "reversibility_class": .string(spec.reversibility),
                             "params_digest": .string(Merkle.paramsDigest(params))]
        let r = PCAFacade.jsNum(riskFor(spec, params, o.risk))
        lock.lock()
        let useCounter: Int64
        if let c = o.counter { useCounter = c; counter = max(counter, c) } else { counter += 1; useCounter = counter }
        lock.unlock()
        var extras: JObject = ["risk_claim": .object(["r": r, "inputs": .object(["blastRadius": r])])]
        if let n = o.nonce { extras["nonce"] = .string(n) }
        if let c = o.caution { extras["caution"] = PCAFacade.jsNum(c) }
        let pcactn = try PCAIssue.buildPCActn(.init(grant: grant, chain: chain, plan: try PCAIssue.commitPlan([node]), nodeId: "n0", params: params, counter: useCounter,
                                                    signer: holder, aud: a, iat: o.now ?? Int64(Date().timeIntervalSince1970 * 1000), ttlMs: o.ttlMs, extras: extras))
        let bundle = try provenance.forAction(PCA.Operation(verb: verb, resource: resource, params: params ?? .object([:])))
        return PCAActResult(pcactn: pcactn, encoded: PCAIssue.encode(pcactn), headers: PCAIssue.headers(pcactn, provenance: bundle),
                            dryRun: dryRun(verb: verb, resource: resource, params: params, now: o.now), provenance: bundle)
    }

    /// An agent one hop down: the hop (signed by this agent) rebinds the chain to `holder` (a fresh key when nil) with the added caveats,
    /// sharing the policy, catalog and provenance recorder. Under a post-quantum suite the sub-agent gets its own PQ key (generated when no
    /// holder is given), committed in the hop; it never signs with this agent's PQ key.
    public func subAgent(holder h: PCASuiteKey? = nil, addedCaveats: [JSONValue] = []) throws -> PCAFacadeAgent {
        let sub: PCASuiteKey
        if let given = h {
            sub = given
        } else if let pq = holder.pq, holder.alg != "ed25519" {
            sub = try PCASuiteKey(alg: holder.alg, ed: try PCAEdKey.generate(), pq: try PCAPQKey.generate(pq.level))
        } else {
            sub = .ed25519(try PCAEdKey.generate())
        }
        guard let sid = sub.id else { throw PCAProducerError("subAgent: the sub-agent needs an Ed25519 identity") }
        if sub.alg != holder.alg { throw PCAProducerError("subAgent: the sub-agent's key does not match the suite \(holder.alg)") }
        guard let leaf = chain.last else { throw PCAProducerError("subAgent: empty chain") }
        let hop = try PCAIssue.delegate(parent: leaf, toHolder: sid, added: addedCaveats, signer: holder, holderPqPk: sub.pqPk)
        return PCAFacadeAgent(grant: grant, chain: chain + [hop], goalSalt: goalSalt, goalCommit: goalCommit, policy: policy, holder: sub,
                              principal: principalPublic, catalog: catalog, aud: aud, startNow: startNow, recorder: provenance)
    }

    /// The grant's canonical JSON (for transport or inspection).
    public func encodeGrant() -> String { Canonical.canonicalize(grant) }
}
