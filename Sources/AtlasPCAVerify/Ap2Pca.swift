import Foundation
import CryptoKit

/// Binding AP2 mandates to a PCA grant and to the PCA proof of each action, and the settlement payloads a verified mandate feeds.
///
/// AP2 decides what a mandate may say; PCA decides whether the agent may act. The two are tied together by a namespaced `x_pca` claim that
/// lives INSIDE the mandate object (so it is covered by the issuer's / agent's signature and by the next hop's `sd_hash`):
///
///   open mandate   `x_pca = { v, grant, terms }`       the PCA grant (principal-signed) and the terms it was minted from
///   closed payment `x_pca = { v, charge, pcactn }`     the PCActn (agent-signed) that authorises exactly this charge
///
/// The PCActn's signed `nonce` commits to the AP2 side: the transaction id, payee, amount, instrument, the open mandate's `sd_hash` and the
/// thumbprint of the agent's AP2 key. Swapping any of those, or replaying the PCActn under another mandate or another AP2 agent key, breaks
/// the binding.
extension PCAAp2 {
    /// A PCA term as integer minor units; anything else (a major-unit float from an older mandate) is refused.
    static func minorTerm(_ v: V, _ name: String) throws -> JSONValue {
        guard isNonNegInt(v), let x = v else { throw JSError("PCA term \(name) must be a non-negative integer in minor units, got \(P.tostr(v))") }
        return x
    }

    /// `JSON.parse(JSON.stringify(v))`: undefined is refused, a non-finite number becomes null, -0 becomes 0.
    static func toJson(_ v: V) throws -> JSONValue {
        guard let x = v else { throw JSError("\"undefined\" is not valid JSON") }
        func walk(_ y: JSONValue) -> JSONValue {
            switch y {
            case let .double(d): return d.isFinite ? P.num(d) : .null
            case let .array(a): return .array(a.map(walk))
            case let .object(o): return .object(o.mapValues(walk))
            default: return y
            }
        }
        return walk(x)
    }

    // ---- PCA terms -> AP2 open mandates ----

    /// The `x_pca` claim of an open mandate: the principal-signed grant and the terms it was minted from.
    public static func pcaOpenClaim(_ mandate: JSONValue?) throws -> JSONValue {
        .object(["v": .int(Int64(PCA_BINDING_VERSION)), "grant": try toJson(try P.prop(mandate, "grant")), "terms": try toJson(try P.prop(mandate, "terms"))])
    }

    /// The `exp` of an open mandate minted from `terms`: the caller's, or the PCA period end; never past the period end.
    static func openExpiry(_ terms: V, _ o: V) throws -> JSONValue {
        let pe = try P.prop(terms, "periodEnd")
        let periodEnd: Double? = pe == nil ? nil : (P.toNumber(pe) / 1000).rounded(.down)
        let exp = coalesce(try P.prop(o, "exp"), { periodEnd.map { numV($0) } })
        guard let e = exp else { throw JSError("exp is required when the PCA terms have no period end") }
        if let p = periodEnd, !jsLe(e, numV(p)) { throw JSError("exp must not exceed the PCA period end") }
        return e
    }

    static func merchantsFor(_ terms: V, _ merchants: V) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for id in try listOf(try P.prop(terms, "merchants"), "terms.merchants.map") {
            var found: V = nil
            for x in try listOf(merchants, "merchants.find") where found == nil {
                if P.seq(try P.prop(x, "id"), id) { found = x }
            }
            guard let m = found, JS.truthy(m) else { throw JSError("no merchant descriptor supplied for PCA merchant \(P.tostr(id))") }
            out.append(m)
        }
        return out
    }

    /// The value of AP2 `payment.budget.max` for a PCA cap in integer minor units. The official AP2 SDK reads it as `int(max * 100)` whatever
    /// the currency, while the schema calls it an amount, so two readers exist: the SDK (hundredths) and a major-unit reader (`max * 10^exponent`).
    /// The value emitted never lets EITHER read more than the cap, nudged up by at most a few ulps when `cap / divisor` falls just under the exact
    /// decimal so that the SDK's `int(max * 100)` is exact.
    public static func ap2BudgetMax(_ capMinor: JSONValue?, _ currency: JSONValue?) throws -> JSONValue {
        let capV = try minorTerm(capMinor, "cumulativeCap")
        let cap = P.numOf(capV) ?? 0
        let e = try currencyExponent(currency)
        let sdkTarget = e <= 2 ? cap : (cap / pow(10.0, Double(e - 2))).rounded(.down)
        var d = cap / pow(10.0, Double(max(e, 2)))
        for _ in 0..<8 {
            if !(d > 0 && (d * 100).rounded(.towardZero) < sdkTarget) { break }
            d = d.nextUp
        }
        if (d * 100).rounded(.towardZero) != sdkTarget || P.jsRound(d * pow(10.0, Double(e))) > cap {
            throw JSError("cumulativeCap \(P.tostr(capV)) \(P.tostr(currency)) has no exact AP2 budget.max representation")
        }
        return P.num(d)
    }

    /// What the two readers of an AP2 `budget.max` read, in minor units of `currency`: `{ sdk, major }`.
    public static func ap2BudgetReads(_ max: JSONValue?, _ currency: JSONValue?) throws -> JSONValue {
        let e = try currencyExponent(currency)
        guard let m = P.numOf(max), m.isFinite, m >= 0 else { throw JSError("budget.max must be a finite non-negative number, got \(P.tostr(max))") }
        return .object(["sdk": P.num((m * 100).rounded(.towardZero)), "major": P.num(P.jsRound(m * pow(10.0, Double(e))))])
    }

    /// The AP2 open payment constraints a set of PCA terms denotes. PCA terms are INTEGER MINOR UNITS of the mandate currency (ISO 4217 exponent
    /// per currency); `amount_range` is in the same minor units and `budget.max` is derived exactly by `ap2BudgetMax`.
    public static func paymentConstraintsFromTerms(_ terms: JSONValue?, _ merchants: JSONValue?, _ checkoutReference: JSONValue?) throws -> [JSONValue] {
        let cur = try P.prop(terms, "currency")
        let perTx = try minorTerm(try P.prop(terms, "perTransactionCap"), "perTransactionCap")
        let budgetMax = try ap2BudgetMax(try P.prop(terms, "cumulativeCap"), cur)
        func with(_ o: JObject, _ k: String, _ v: V) -> JObject { var r = o; if let x = v { r[o: k] = x }; return r }
        var rec: JObject = ["type": .string("payment.agent_recurrence"), "frequency": .string("ON_DEMAND")]
        if let mt = try P.prop(terms, "maxTransactionsPerPeriod") { rec["max_occurrences"] = mt }
        return [
            .object(with(["type": .string("payment.amount_range"), "min": .int(0), "max": perTx], "currency", cur)),
            .object(["type": .string("payment.allowed_payees"), "allowed": .array(try merchantsFor(terms, merchants))]),
            .object(with(["type": .string("payment.reference")], "conditional_transaction_id", checkoutReference)),
            .object(with(["type": .string("payment.budget"), "max": budgetMax], "currency", cur)),
            .object(rec),
        ]
    }

    static func fromPcaInput(_ mandate: V, _ o: V, _ constraints: () throws -> JSONValue) throws -> JSONValue {
        var out: JObject = [:]
        if let a = try P.prop(o, "agentJwk") { out["agentJwk"] = a }
        if let i = try P.prop(o, "iat") { out["iat"] = i }
        out["exp"] = try openExpiry(try P.prop(mandate, "terms"), o)
        out["pca"] = try pcaOpenClaim(mandate)
        out["constraints"] = try constraints()
        return .object(out)
    }

    /// Issue the open payment mandate for a PCA mandate (grant + terms), chained to `o.checkoutReference`. `o`: `agentJwk`, `merchants`, `iat`,
    /// `exp?` (never past the PCA period end), `checkoutReference`.
    public static func openPaymentMandateFromPca(_ mandate: JSONValue?, _ o: JSONValue, issuer: MandateIssuer, salt: (() -> String)? = nil) throws -> String {
        let ov: JSONValue? = o
        let input = try fromPcaInput(mandate, ov) {
            .array(try paymentConstraintsFromTerms(try P.prop(mandate, "terms"), try P.prop(ov, "merchants"), try P.prop(ov, "checkoutReference")))
        }
        return try issueOpenPaymentMandate(input, issuer: issuer, salt: salt)
    }

    /// Issue the open checkout mandate for a PCA mandate: the merchant allowlist and the acceptable line items (`o.lineItems`).
    public static func openCheckoutMandateFromPca(_ mandate: JSONValue?, _ o: JSONValue, issuer: MandateIssuer, salt: (() -> String)? = nil) throws -> String {
        let ov: JSONValue? = o
        let input = try fromPcaInput(mandate, ov) {
            var items: JObject = ["type": .string("checkout.line_items")]
            if let li = try P.prop(ov, "lineItems") { items["items"] = li }
            return .array([.object(items), .object(["type": .string("checkout.allowed_merchants"), "allowed": .array(try merchantsFor(try P.prop(mandate, "terms"), try P.prop(ov, "merchants")))])])
        }
        return try issueOpenCheckoutMandate(input, issuer: issuer, salt: salt)
    }

    // ---- the closed payment: PCActn bound to the AP2 mandate ----

    /// The value the PCActn's signed `nonce` must equal for these AP2 facts (`transactionId`, `payeeId`, `amount`, `currency`, `instrumentId`,
    /// `openHash`, `agentJkt`).
    public static func pcaBindingNonce(_ f: JSONValue?) throws -> String {
        var o: JObject = ["v": .int(Int64(PCA_BINDING_VERSION))]
        for (k, v) in P.spreadObj(f) { o[k] = v }
        return "ap2:" + (try P.hashStrict(.object(o)))
    }

    /// amount / cap, clamped to [0, 1] and rounded UP to 12 decimals (PCA's canonical encoding refuses numbers with more than 15 significant
    /// digits, so 100/300 cannot be signed as-is; rounding up can only raise the risk the threshold policy sees, never lower it).
    public static func riskRatio(_ amount: JSONValue?, _ cap: JSONValue?) -> JSONValue {
        let c = P.toNumber(cap)
        let r = c > 0 ? P.toNumber(amount) / c : 1
        return P.num(riskRatioValue(r))
    }

    static func riskRatioValue(_ r: Double) -> Double {
        let t = (r * 1e12 - 1e-6).rounded(.up) / 1e12
        return P.jsMin(1, P.jsMax(0, t))
    }

    /// Build the `x_pca` claim of a closed payment mandate: a PCActn authorising exactly this charge. `i`: `mandate` (the PCA mandate: grant +
    /// terms), `open` (the open payment mandate token), `agentJwk`, `audience`, `counter`, `transactionId`, `payee`, `amount` (`{ amount, currency }`),
    /// `instrumentId`, optional `category`, `now` (epoch ms). `agentKey` is the grant holder's signing key; `cosign` returns the threshold shares
    /// over the built PCActn for a charge that needs a human co-sign.
    public static func buildPcaPaymentBinding(_ input: JSONValue, agentKey: PCASuiteKey, cosign: ((JSONValue) throws -> JSONValue)? = nil) throws -> JSONValue {
        let i: JSONValue? = input
        let amount = try P.prop(i, "amount")
        let major = try minorTerm(try P.prop(amount, "amount"), "amount") // the charge amount is integer minor units, as in the mandate
        let payee = try P.prop(i, "payee")
        let category = try P.prop(i, "category")
        var charge: JObject = ["amount": major]
        if let m = try P.prop(payee, "id") { charge["merchant"] = m }
        if let c = try P.prop(amount, "currency") { charge["currency"] = c }
        if let c = category { charge["category"] = c }
        guard let txId = try P.prop(i, "transactionId"), let payeeId = try P.prop(payee, "id"), let cur = try P.prop(amount, "currency"),
              let instr = try P.prop(i, "instrumentId") else { throw JSError("canonicalize: unsupported type undefined") }
        let openHash = try sdHashOf(try parseSdJwtHop(try P.prop(i, "open")))
        let facts: JSONValue = .object(["transactionId": txId, "payeeId": payeeId, "amount": try P.prop(amount, "amount")!, "currency": cur, "instrumentId": instr,
                                        "openHash": .string(openHash), "agentJkt": .string(try jwkThumbprint(try P.prop(i, "agentJwk")))])
        let mandate = try P.prop(i, "mandate")
        let risk = riskRatioValue(riskRatioRaw(major, try P.prop(try P.prop(mandate, "terms"), "perTransactionCap")))
        let nodeId = "ap2:\(P.tostr(txId))"
        let chargeV: JSONValue = .object(charge)
        let mv = mandate ?? .null
        let node = try PCAPayments.chargePlanNode(mv, chargeV, nodeId)
        let params = try PCAPayments.chargeParams(mv, chargeV)
        guard case let .object(grant)? = try P.prop(mandate, "grant") else { throw JSError("buildPCActn: the grant is not a capability") }
        let counterV = try P.prop(i, "counter")
        guard let cf = P.numOf(counterV), cf.rounded() == cf, abs(cf) <= P.MAX_SAFE else { throw JSError("build_pcactn: counter must be an integer") }
        let nowV = try P.prop(i, "now")
        let iat: Int64 = P.isFinite(nowV) ? Int64(P.numOf(nowV) ?? 0) : Int64(P.nowMs())
        var inputs = params.asObject ?? [:]
        inputs["blastRadius"] = P.num(risk)
        let built: JSONValue
        do {
            let plan = try PCAIssue.commitPlan([node.asObject ?? [:]])
            built = try PCAIssue.buildPCActn(.init(grant: .object(grant), chain: [.object(grant)], plan: plan, nodeId: nodeId, params: params, counter: Int64(cf), signer: agentKey,
                                                   aud: (try P.prop(i, "audience"))?.asString ?? "", iat: iat,
                                                   extras: ["nonce": .string(try pcaBindingNonce(facts)), "risk_claim": .object(["r": P.num(risk), "inputs": .object(inputs)])]))
        } catch let e as PCAProducerError { throw JSError(e.description) }
        var pcactn = built
        if let cs = cosign, case var .object(b) = built {
            b["threshold"] = try cs(built)
            pcactn = .object(b)
        }
        var claimCharge: JObject = ["amount": major]
        if let c = try P.prop(amount, "currency") { claimCharge["currency"] = c }
        if let c = category { claimCharge["category"] = c }
        return .object(["v": .int(Int64(PCA_BINDING_VERSION)), "charge": .object(claimCharge), "pcactn": try toJson(pcactn)])
    }

    static func riskRatioRaw(_ amount: V, _ cap: V) -> Double {
        let c = P.toNumber(cap)
        return c > 0 ? P.toNumber(amount) / c : 1
    }

    // ---- settlement backends (structural only, no network) ----

    /// Convert integer minor units to an integer string of atomic units: scales by `10 ** (decimals - exponent)` exactly; when the asset has fewer
    /// decimals than the currency the division must be exact. Refused otherwise (fail closed).
    public static func toAtomicUnits(_ amount: JSONValue?, _ decimals: JSONValue?) throws -> String {
        guard P.isInteger(decimals), let dec = P.numOf(decimals), dec >= 0, dec <= 18 else { throw JSError("x402: decimals must be an integer in 0..18, got \(P.tostr(decimals))") }
        let amt = try P.prop(amount, "amount")
        guard isNonNegInt(amt), let a = P.numOf(amt) else { throw JSError("x402: amount \(P.tostr(amt)) cannot be expressed in atomic units with \(P.tostr(decimals)) decimals") }
        let exp = try currencyExponent(try P.prop(amount, "currency"))
        let minor = Int64(a), d = Int(dec)
        if d >= exp { return minor == 0 ? "0" : String(minor) + String(repeating: "0", count: d - exp) }
        var div: Int64 = 1
        for _ in 0..<(exp - d) { div *= 10 }
        if minor % div != 0 { throw JSError("x402: amount \(P.tostr(amt)) cannot be expressed in atomic units with \(P.tostr(decimals)) decimals") }
        return String(minor / div)
    }

    static func ctxGet(_ ctx: V, _ k: String) -> V {
        if case let .object(o)? = ctx { return o[JKey(k)] }
        return nil
    }

    static func withoutNil(_ pairs: [(String, V)]) -> JSONValue {
        var o: JObject = [:]
        for (k, v) in pairs { if let x = v { o[o: k] = x } }
        return .object(o)
    }

    /// Coinbase x402 adapter: the HTTP 402 `Payment Required` challenge (`accepts`) plus the `X-PAYMENT` request header (standard base64 of the
    /// JSON payment payload). The payload is a placeholder envelope, not a signed authorization: the real rail settles on-chain. `payment` is a
    /// closed Payment Mandate that has ALREADY been verified; `ctx`: `resourceUrl`, `payTo`, `network`, `asset`, `decimals` (default 6),
    /// `maxTimeoutSeconds` (default 60).
    public static func x402Settlement(_ payment: JSONValue?, _ ctx: JSONValue? = nil) throws -> JSONValue {
        let network = coalesce(ctxGet(ctx, "network"), { JSONValue.string("base-sepolia") })
        let amt = try P.prop(payment, "payment_amount")
        let atomic = try toAtomicUnits(amt, coalesce(ctxGet(ctx, "decimals"), { JSONValue.int(6) }))
        let payTo = try coalesce(ctxGet(ctx, "payTo"), { try P.prop(try P.prop(payment, "payee"), "id") })
        let asset = try coalesce(ctxGet(ctx, "asset"), { try P.prop(amt, "currency") })
        let txId = try P.prop(payment, "transaction_id")
        let requirement = withoutNil([
            ("scheme", .string("exact")), ("network", network), ("maxAmountRequired", .string(atomic)),
            ("resource", coalesce(ctxGet(ctx, "resourceUrl"), { JSONValue.string("") })),
            ("description", .string("AP2 payment mandate \(P.tostr(txId))")),
            ("payTo", payTo), ("asset", asset), ("mimeType", .string("application/json")),
            ("maxTimeoutSeconds", coalesce(ctxGet(ctx, "maxTimeoutSeconds"), { JSONValue.int(60) })),
        ])
        let amtAmount = try P.prop(amt, "amount"), amtCur = try P.prop(amt, "currency")
        let envelope = withoutNil([
            ("x402Version", .int(1)), ("scheme", .string("exact")), ("network", network),
            ("payload", withoutNil([("transactionId", txId), ("amount", amtAmount), ("currency", amtCur)])),
        ])
        let text = JS.stringify(envelope, order: ["x402Version", "scheme", "network", "payload", "transactionId", "amount", "currency"])
        let xPayment = Data(text.utf8).base64EncodedString()
        let merchant = try P.prop(try P.prop(payment, "payee"), "id")
        return withoutNil([
            ("rail", .string("x402")), ("amount", amt), ("merchant", merchant),
            ("payload", withoutNil([("httpStatus", .int(402)), ("x402Version", .int(1)), ("error", .string("X-PAYMENT header is required")),
                                    ("accepts", .array([requirement])), ("header", .object(["X-PAYMENT": .string(xPayment)]))])),
        ])
    }

    /// Stripe Shared Payment Token adapter: a shared token the buyer's agent grants the merchant to pull a bounded amount. The mandate amount is
    /// already in minor units, which is what Stripe takes. The token is the mandate's payment instrument id, never a raw PAN.
    public static func stripeSptSettlement(_ payment: JSONValue?, _ ctx: JSONValue? = nil) throws -> JSONValue {
        let inst = try P.prop(payment, "payment_instrument")
        let type = try P.prop(inst, "type")
        if !P.seq(type, .string("shared_payment_token")) {
            throw JSError("stripe-spt: the payment instrument must be of type shared_payment_token, got \(P.tostr(type))")
        }
        let amt = try P.prop(payment, "payment_amount")
        guard let cur = try P.prop(amt, "currency")?.asString else { throw JSError("payment.payment_amount.currency.toLowerCase is not a function") }
        var payload: [(String, V)] = [("shared_payment_token", try P.prop(inst, "id")), ("amount", try P.prop(amt, "amount")), ("currency", .string(cur.lowercased()))]
        if let pt = ctxGet(ctx, "payTo"), JS.truthy(pt) { payload.append(("on_behalf_of", pt)) }
        return withoutNil([("rail", .string("stripe-spt")), ("amount", amt), ("merchant", try P.prop(try P.prop(payment, "payee"), "id")), ("payload", withoutNil(payload))])
    }
}
