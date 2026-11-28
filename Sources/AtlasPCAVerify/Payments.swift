import Foundation
import CryptoKit

/// The JavaScript value semantics the payments, AP2 and ACP bridges mirror over `JSONValue?` (nil is `undefined`): a property read
/// is a TypeError on null / undefined, arithmetic coerces, `===` is identity for primitives. Internal to the module.
enum PayJS {
    typealias V = JSONValue?
    static let MAX_SAFE: Double = 9_007_199_254_740_991

    /// `o.k`: a TypeError for null / undefined, `undefined` for a missing member or a primitive.
    static func prop(_ o: V, _ k: String) throws -> V {
        switch o {
        case nil: throw JSError("Cannot read properties of undefined (reading '\(k)')")
        case .null?: throw JSError("Cannot read properties of null (reading '\(k)')")
        case let .object(m)?: return m[JKey(k)]
        default: return nil
        }
    }

    /// `o?.k`.
    static func optprop(_ o: V, _ k: String) throws -> V { nullish(o) ? nil : try prop(o, k) }

    static func nullish(_ v: V) -> Bool { v == nil || v == .null }
    static func numOf(_ v: V) -> Double? { IV.num(v) }
    static func isFinite(_ v: V) -> Bool { numOf(v)?.isFinite ?? false }
    static func safeF(_ f: Double) -> Bool { f.isFinite && f.rounded() == f && abs(f) <= MAX_SAFE }
    static func safeInt(_ v: V) -> Bool { numOf(v).map(safeF) ?? false }
    /// `Number.isInteger`.
    static func isInteger(_ v: V) -> Bool { numOf(v).map { $0.isFinite && $0.rounded() == $0 } ?? false }
    static func isStr(_ v: V) -> String? { v?.asString }
    static func obj(_ v: V) -> JObject? { v?.asObject }

    /// A JS number as JSON: a whole number is an integer, NaN / Infinity (not JSON) become null.
    static func num(_ f: Double) -> JSONValue {
        if f.isFinite && f.rounded() == f && abs(f) < 9.0e15 { return .int(Int64(f)) }
        return f.isFinite ? .double(f) : .null
    }

    static func toNumber(_ v: V) -> Double { JS.toNumber(v) }
    static func tostr(_ v: V) -> String { JS.toString(v) }
    static func gt0(_ v: V) -> Bool { toNumber(v) > 0 }

    /// `a === b` for JSON values (an object or array is never identical to another).
    static func seq(_ a: V, _ b: V) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?):
            if x.isNumber && y.isNumber { return IV.num(x) == IV.num(y) }
            if x.isObject || x.isArray || y.isObject || y.isArray { return false }
            return x == y
        default: return false
        }
    }

    /// `v.length`: a TypeError for null / undefined; a string's UTF-16 length, an array's length, an object's `length` member.
    static func length(_ v: V) throws -> JSONValue? {
        switch v {
        case nil: throw JSError("Cannot read properties of undefined (reading 'length')")
        case .null?: throw JSError("Cannot read properties of null (reading 'length')")
        case let .string(s)?: return .int(Int64(s.utf16.count))
        case let .array(a)?: return .int(Int64(a.count))
        case let .object(o)?: return o[JKey("length")]
        default: return nil
        }
    }

    static func jsMax(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : max(a, b) }
    static func jsMin(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : min(a, b) }

    /// `Math.round`.
    static func jsRound(_ x: Double) -> Double {
        if !x.isFinite { return x }
        let r = x.rounded(.down)
        return x - r >= 0.5 ? r + 1 : r
    }

    /// `a > b` for two JSON values (two strings compare by UTF-16 code unit, anything else as numbers).
    static func jsGt(_ a: V, _ b: V) -> Bool {
        if let x = a?.asString, let y = b?.asString { return y.utf16.lexicographicallyPrecedes(x.utf16) }
        return toNumber(a) > toNumber(b)
    }

    /// `{...v}` members.
    static func spreadObj(_ v: V) -> JObject {
        switch v {
        case let .object(m)?: return m
        case let .array(a)?:
            var o: JObject = [:]
            for (i, x) in a.enumerated() { o[JKey(String(i))] = x }
            return o
        case let .string(s)?:
            var o: JObject = [:]
            for (i, u) in s.utf16.enumerated() { o[JKey(String(i))] = .string(String(decoding: [u], as: UTF16.self)) }
            return o
        default: return [:]
        }
    }

    /// `[...v]`.
    static func spreadArr(_ v: V) throws -> [JSONValue] { try JS.spread(v) }

    /// base64url(sha256(strict canonical(v))); an `undefined` or out-of-profile value is a TypeError.
    static func hashStrict(_ v: V) throws -> String {
        guard let x = v else { throw JSError("canonicalize: unsupported type undefined") }
        do { return Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(x))) }
        catch let e as Canonical.CanonicalError { throw JSError(e.message) }
    }

    static func nowMs() -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
    static func jsLower(_ s: String) -> String { s.lowercased() }
    static func jsUpper(_ s: String) -> String { s.uppercased() }

    /// The default `Array.prototype.sort` over strings or anything stringified: by UTF-16 code unit, stable.
    static func jsSorted(_ v: [JSONValue]) -> [JSONValue] {
        v.enumerated().sorted { a, b in
            let x = tostr(a.element), y = tostr(b.element)
            if x.utf16.elementsEqual(y.utf16) { return a.offset < b.offset }
            return x.utf16.lexicographicallyPrecedes(y.utf16)
        }.map { $0.element }
    }

    static func keypairId(_ k: PCASuiteKey) -> String { k.id ?? "" }

    /// `s.split(sep)` over UTF-16 code units (here: scalars, a Swift String holds no lone surrogate): empty pieces kept.
    static func splitScalars(_ s: String, _ sep: Unicode.Scalar) -> [[Unicode.Scalar]] {
        var out: [[Unicode.Scalar]] = [[]]
        for u in s.unicodeScalars { if u == sep { out.append([]) } else { out[out.count - 1].append(u) } }
        return out
    }

    static func isJSSpace(_ c: Character) -> Bool { c.unicodeScalars.count == 1 && Attest.isJSSpace(c.unicodeScalars.first!) }
}

/// Payments for PCA: a payment mandate as a Root Intent Grant, the charge decision, the charge PCActn, Shared Payment Token limits,
/// spend rails (card limits, settlement reconciliation), the Stripe Issuing adapter and agent network tokens.
///
/// Values are the reference's JSON shapes (camelCase members). Inputs follow JavaScript semantics where the reference does (missing
/// members, truthiness, coercing arithmetic), so a hostile mandate or charge is refused or priced exactly as the reference does; a
/// JavaScript TypeError is a thrown `JSError`. This package carries no policy engine: the charge decision takes the PCA decision
/// function as an injected closure. Signing keys are `PCASuiteKey` values (the reference takes raw secrets inside the options).
public enum PCAPayments {
    public static let CHARGE_REVERSIBILITY_CLASS = "reversible"
    public static let CHARGE_VERB = "charge"
    public static let AMOUNT_NOT_MINOR_UNITS = "amount_not_integer_minor_units"
    public static let MERCHANT_INVALID = "merchant_invalid"
    public static let STRIPE_WEBHOOK_TOLERANCE_SEC: Double = 300
    public static let STRIPE_API_VERSION = "2025-03-31.basil"
    public static let NETWORK_TOKEN_BINDING_KIND = "pca.network_token_binding"

    /// The PCA policy decision (`decide`), supplied by the caller: decide input in, decision out.
    public typealias Decide = (JSONValue) throws -> JSONValue

    typealias P = PayJS

    static func grantErr(_ code: String, _ message: String) -> JSError { JSError(message, code: code) }

    // ---- mandate ----

    /// A merchant id that cannot act as a resource pattern: a non-empty string with no `*` and no control characters.
    public static func isPlainId(_ x: JSONValue?) -> Bool {
        guard let s = x?.asString, !s.isEmpty else { return false }
        return !s.unicodeScalars.contains { $0 == "*" || $0.value < 0x20 || $0.value == 0x7f }
    }

    /// A non-negative safe integer (amounts are integer minor units); `-0` is not one.
    public static func isMinorUnits(_ x: JSONValue?) -> Bool {
        guard let f = P.numOf(x), P.safeF(f), f >= 0 else { return false }
        return !(f == 0 && f.sign == .minus)
    }

    static func validate(_ p: JSONValue) throws {
        let pv: JSONValue? = p
        func g(_ k: String) throws -> JSONValue? { try P.prop(pv, k) }
        // -0 is a number the strict canonicalizer refuses (the grant digest): refuse it here too instead of signing it
        for k in ["perTransactionCap", "autoApproveThreshold", "cumulativeCap", "replenishPerCosign", "periodMs", "maxTransactionsPerPeriod", "periodStart", "now"] {
            if let f = P.numOf(try g(k)), f == 0, f.sign == .minus { throw JSError("buildPaymentMandate: \(k) must not be negative zero") }
        }
        let strict = (try g("strictMinorUnits")) != .bool(false)
        if strict {
            let rep = try g("replenishPerCosign")
            let reps: JSONValue? = P.nullish(rep) ? .int(0) : rep
            let items: [(String, JSONValue?)] = [("perTransactionCap", try g("perTransactionCap")), ("autoApproveThreshold", try g("autoApproveThreshold")),
                                                 ("cumulativeCap", try g("cumulativeCap")), ("replenishPerCosign", reps)]
            for (k, v) in items where !P.safeInt(v) {
                throw JSError("buildPaymentMandate: \(k) must be a safe integer in minor units (strictMinorUnits)")
            }
        }
        guard case let .array(ms)? = try g("merchants"), !ms.isEmpty else {
            throw JSError("buildPaymentMandate: at least one allowlisted merchant is required")
        }
        if ms.contains(where: { ($0.asString ?? "").isEmpty }) { throw JSError("buildPaymentMandate: merchant ids must be non-empty strings") }
        if ms.contains(where: { !isPlainId($0) }) { throw JSError("buildPaymentMandate: merchant ids must not contain `*` or control characters") }
        if (try g("currency"))?.asString.map({ $0.isEmpty }) ?? true { throw JSError("buildPaymentMandate: currency is required") }
        func fin(_ v: JSONValue?) -> Double? { P.numOf(v).flatMap { $0.isFinite ? $0 : nil } }
        let xf = fin(try g("perTransactionCap"))
        if xf == nil || xf! <= 0 { throw JSError("buildPaymentMandate: perTransactionCap (X) must be a finite number > 0") }
        let x = xf!
        if let y = fin(try g("autoApproveThreshold")), y >= 0, y <= x {} else {
            throw JSError("buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 \u{2264} Y \u{2264} X")
        }
        if let c = fin(try g("cumulativeCap")), c >= x {} else {
            throw JSError("buildPaymentMandate: cumulativeCap must be a finite number \u{2265} perTransactionCap (X)")
        }
        if let pm = try g("periodMs") {
            if let f = fin(pm), f > 0 {} else { throw JSError("buildPaymentMandate: periodMs must be a finite number > 0 when given") }
        }
        if let mx = try g("maxTransactionsPerPeriod") {
            if P.isInteger(mx), let f = P.numOf(mx), f > 0 {} else { throw JSError("buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given") }
        }
        if let r = try g("replenishPerCosign") {
            if let f = fin(r), f >= 0 {} else { throw JSError("buildPaymentMandate: replenishPerCosign must be a finite number \u{2265} 0 when given") }
        }
    }

    static func cond(_ field: String, _ op: String, _ value: JSONValue?) -> JSONValue {
        var m: JObject = ["field": .string(field), "op": .string(op)]
        if let v = value { m["value"] = v }
        return .object(m)
    }

    /// The predicates plus whether the reference's objects carry an `undefined` member (a hash of them is a TypeError there).
    static func predicatesRaw(_ terms: JSONValue) throws -> (preds: [JSONValue], undef: Bool) {
        let t: JSONValue? = terms
        guard case let .array(ms)? = try P.prop(t, "merchants") else { throw JSError("terms.merchants.map is not a function") }
        let cap = try P.prop(t, "perTransactionCap"), cur = try P.prop(t, "currency")
        var out: [JSONValue] = []
        var undef = false
        for m in ms {
            let cats = try P.prop(t, "categories")
            let n = try P.length(cats)
            var conds: [JSONValue] = [cond("action.params.amount", "lte", cap), cond("action.params.currency", "eq", cur), cond("action.params.amount", "gte", .int(0))]
            if P.gt0(n) { conds.append(cond("action.params.category", "in", cats)) }
            undef = undef || cap == nil || cur == nil
            out.append(.object(["verb": .string("charge"), "resource": .string("merchant:" + P.tostr(m)), "where": .array(conds)]))
        }
        return (out, undef)
    }

    /// One predicate per merchant, each carrying the currency, category and hard-ceiling guards.
    public static func mandatePredicates(_ terms: JSONValue) throws -> JSONValue { .array(try predicatesRaw(terms).preds) }

    /// The envelope caveats: period window, velocity cap, and the bonded / refundable reversibility floor.
    public static func mandateCaveats(_ terms: JSONValue) throws -> JSONValue {
        let t: JSONValue? = terms
        var cv: [JSONValue] = []
        let ps = try P.prop(t, "periodStart")
        if P.gt0(ps) { cv.append(.object(["type": .string("not_before"), "at": ps!])) }
        let pe = try P.prop(t, "periodEnd")
        if let pe = pe { cv.append(.object(["type": .string("expires"), "at": pe])) }
        if let mx = try P.prop(t, "maxTransactionsPerPeriod"), let pe = pe {
            let per = P.jsMax(1, P.jsRound((P.toNumber(pe) - P.toNumber(ps)) / 1000))
            cv.append(.object(["type": .string("rate"), "max": mx, "per_secs": P.num(per)]))
        }
        cv.append(.object(["type": .string("reversibility_max"), "class": .string("reversible")]))
        return .array(cv)
    }

    /// The risk policy that makes "spend = risk" exact: only blast radius weighs, theta1 = theta2 = Y/X, kappa = X, bMax = the cap.
    public static func mandateRiskPolicy(_ terms: JSONValue, _ replenishPerCosign: JSONValue) throws -> JSONValue {
        let t: JSONValue? = terms
        let a = try P.prop(t, "autoApproveThreshold"), x = try P.prop(t, "perTransactionCap")
        let th = P.num(P.toNumber(a) / P.toNumber(x))
        var m: JObject = [
            "weights": .object(["alpha": .int(0), "beta": .int(0), "gamma": .int(1), "delta": .int(0), "epsilon": .int(0), "zeta": .int(0)]),
            "theta1": th, "theta2": th, "lambda": .int(0), "rho": replenishPerCosign,
        ]
        if let x = x { m["kappa"] = x }
        if let c = try P.prop(t, "cumulativeCap") { m["bMax"] = c }
        return .object(m)
    }

    /// The most an agent can spend autonomously between two human co-signs: `safetyBound * kappa` (equals the cumulative cap).
    public static func autoSpendBound(_ mandate: JSONValue) throws -> JSONValue {
        let p = try P.prop(mandate, "policy")
        let kappa = try P.prop(p, "kappa"), bMax = try P.prop(p, "bMax")
        let k = P.toNumber(kappa)
        let bound = k > 0 ? P.jsMax(0, P.toNumber(bMax)) / k : 0
        return P.num(bound * k)
    }

    /// Encode the params as a PCA Root Intent Grant envelope plus the initial trust budget. `principal` signs the grant (the reference's
    /// `principalSecret`); `principalPublic` must be its public key (stricter: the reference signs with the secret and names whatever
    /// public key it was given).
    public static func buildPaymentMandate(_ params: JSONValue, principal: PCASuiteKey) throws -> JSONValue {
        try validate(params)
        let p: JSONValue? = params
        func g(_ k: String) throws -> JSONValue? { try P.prop(p, k) }
        let nowRaw = try g("now"), psRaw = try g("periodStart")
        let nowV: JSONValue = P.isFinite(nowRaw) ? nowRaw! : P.num(P.nowMs())
        let psV: JSONValue = P.isFinite(psRaw) ? psRaw! : nowV
        let cats = try g("categories")
        var terms: JObject = [:]
        terms["merchants"] = try g("merchants") ?? .null
        if JS.truthy(cats) { terms["categories"] = .array(try P.spreadArr(cats)) } else { terms["categories"] = .array([]) }
        for k in ["currency", "perTransactionCap", "autoApproveThreshold", "cumulativeCap"] { terms[JKey(k)] = try g(k) ?? .null }
        terms["periodStart"] = psV
        if let pm = try g("periodMs") { terms["periodEnd"] = P.num(P.toNumber(psV) + P.toNumber(pm)) }
        if let mx = try g("maxTransactionsPerPeriod") { terms["maxTransactionsPerPeriod"] = mx }
        let termsV = JSONValue.object(terms)
        let rep = try g("replenishPerCosign")
        let cap = terms["cumulativeCap"] ?? .null
        let policy = try mandateRiskPolicy(termsV, P.nullish(rep) ? cap : rep!)
        let goal: String
        switch try g("goal") {
        case nil, .null?:
            let ms = (terms["merchants"]?.asArray ?? []).compactMap { $0.asString }
            goal = "spend \u{2264} \(P.tostr(terms["autoApproveThreshold"])) \(terms["currency"]?.asString ?? "") autonomously / \u{2264} \(P.tostr(terms["perTransactionCap"])) with co-sign, \u{2264} \(P.tostr(terms["cumulativeCap"])) cumulative, at [\(ms.joined(separator: ", "))]"
        case let .string(s)? where !s.isEmpty: goal = s
        default: throw JSError("mintGrant: goal required")
        }
        if (try g("principalPublic"))?.asString != principal.id {
            throw JSError("buildPaymentMandate: principalPublic is not the public key of principalSecret")
        }
        let salt: String?
        switch try g("goalSalt") {
        case nil: salt = nil
        case let .string(s)?: salt = s
        default: throw JSError("mintGrant: salt must be a string")
        }
        guard let holder = (try g("agentPublic"))?.asString else { throw JSError("mintGrant: holder must be a string") }
        let envelope: JObject = ["predicates": try mandatePredicates(termsV), "caveats": try mandateCaveats(termsV), "agent_binding": .object([:]), "risk_policy": policy]
        let minted: (grant: JSONValue, goalCommit: String, goalSalt: String)
        do { minted = try PCAIssue.mintGrant(principal: principal, holder: holder, envelope: envelope, goal: goal, salt: salt) }
        catch let e as PCAProducerError { throw JSError(e.description) }
        return .object(["grant": minted.grant, "policy": policy, "budget": .object(["B": cap, "tau": nowV, "asOf": nowV]), "terms": termsV,
                        "goalCommit": .string(minted.goalCommit), "goalSalt": .string(minted.goalSalt)])
    }

    // ---- charge decision ----

    /// The charge params (and whether the reference's object would carry an `undefined` member): the amount, the currency (only an
    /// ABSENT currency defaults to the mandate's) and the category when present.
    static func chargeParamsRaw(_ mandate: JSONValue, _ charge: JSONValue) throws -> (params: JObject, undef: Bool) {
        let c: JSONValue? = charge
        let amount = try P.prop(c, "amount")
        var cur = try P.prop(c, "currency")
        if cur == nil { cur = try P.prop(try P.prop(mandate, "terms"), "currency") }
        var p: JObject = [:]
        if let a = amount { p["amount"] = a }
        if let cu = cur { p["currency"] = cu }
        if let cat = try P.prop(c, "category") { p["category"] = cat }
        return (p, amount == nil || cur == nil)
    }

    /// The charge params committed in both the plan node and the PCActn action (they must reconcile).
    public static func chargeParams(_ mandate: JSONValue, _ charge: JSONValue) throws -> JSONValue { .object(try chargeParamsRaw(mandate, charge).params) }

    /// The action a charge denotes: the verb / resource / params the predicates and risk read.
    public static func chargeActionContext(_ mandate: JSONValue, _ charge: JSONValue) throws -> JSONValue {
        let params = try chargeParams(mandate, charge)
        return .object(["action": .object(["verb": .string(CHARGE_VERB), "resource": .string("merchant:" + P.tostr(try P.prop(charge, "merchant"))),
                                           "params": params, "reversibility_class": .string(CHARGE_REVERSIBILITY_CLASS)])])
    }

    static func same(_ a: JSONValue, _ b: JSONValue) throws -> Bool { try P.hashStrict(a) == P.hashStrict(b) }

    static func isObj(_ v: JSONValue) -> Bool { v.isObject || v.isArray }

    /// Bind a mandate to the grant the caller VERIFIED: the mandate's grant must be that grant and its terms / policy the ones signed
    /// into the envelope. Returns the mandate with its budget clamped to the signed `bMax`.
    static func bindToVerifiedGrant(_ mandate: JSONValue, _ verifiedGrant: JSONValue) throws -> JSONValue {
        if !isObj(verifiedGrant) {
            throw grantErr("verified_grant_required", "a verified (or stored) grant is required; the mandate's own grant is never the authority")
        }
        let m: JSONValue? = mandate
        if try !isObj(mandate) || (P.hashStrict(P.prop(m, "grant")) != P.hashStrict(verifiedGrant)) {
            throw grantErr("mandate_grant_mismatch", "the mandate grant is not the verified grant")
        }
        let mismatch = grantErr("mandate_terms_mismatch", "the mandate terms / policy are not the ones signed into the verified grant")
        guard let env = PCA.readEnvelope(verifiedGrant) else { throw mismatch }
        let terms = try P.prop(m, "terms"), policy = try P.prop(m, "policy")
        if !JS.truthy(terms) || !JS.truthy(policy) { throw mismatch }
        let (preds, undef) = try predicatesRaw(terms ?? .null)
        if undef { throw JSError("canonicalize: unsupported type undefined") }
        let okPreds = try same(env.get("predicates") ?? .null, .array(preds))
        if !okPreds { throw mismatch }
        let okCaveats = try same(env.get("caveats") ?? .null, try mandateCaveats(terms ?? .null))
        if !okCaveats { throw mismatch }
        let okPolicy = try same(env.get("risk_policy") ?? .null, policy ?? .null)
        if !okPolicy { throw mismatch }
        let bMax = P.numOf(env.get("risk_policy")?.get("bMax")) ?? .nan
        let budget = try P.prop(m, "budget")
        let b = try P.optprop(budget, "B")
        let bb: Double = P.isFinite(b) ? P.jsMax(0, P.jsMin(P.toNumber(b), bMax)) : 0
        var out = P.spreadObj(m)
        out["grant"] = verifiedGrant
        var nb = P.spreadObj(budget)
        nb["B"] = P.num(bb)
        out["budget"] = .object(nb)
        return .object(out)
    }

    /// The decide input for a charge: risk collapses to the normalised amount (spend = risk). A mandate whose grant, terms or policy
    /// differ from `verifiedGrant` is refused (code `verified_grant_required` / `mandate_grant_mismatch` / `mandate_terms_mismatch`).
    public static func chargeDecideInput(_ mandate0: JSONValue, _ charge: JSONValue, _ now: JSONValue, _ verifiedGrant: JSONValue) throws -> JSONValue {
        let mandate = try bindToVerifiedGrant(mandate0, verifiedGrant)
        let x = try P.prop(try P.prop(mandate, "terms"), "perTransactionCap")
        let amountV = try P.prop(charge, "amount")
        let amount: Double = P.isFinite(amountV) ? P.toNumber(amountV) : .infinity
        let xf = P.toNumber(x)
        let blast = xf > 0 ? amount / xf : 1
        var ctx: JObject = ["reversibilityClass": .string(CHARGE_REVERSIBILITY_CLASS)]
        if let r = try P.prop(charge, "recentChargeTimes") { ctx["recentActionTimes"] = r }
        var out: JObject = ["grant": verifiedGrant, "action": try chargeActionContext(mandate, charge),
                            "risk": .object(["semanticDistance": .int(0), "reversibility": .int(1), "blastRadius": P.num(blast), "taint": .int(0), "confidence": .int(1), "age": .int(0)]),
                            "now": now, "caveatContext": .object(ctx)]
        if let b = mandate.get("budget") { out["budget"] = b }
        return .object(out)
    }

    /// Run a charge through the PCA decision against the grant you VERIFIED. Pure: reads the mandate budget (clamped to the signed
    /// bMax) and returns the next one in `budgetAfter`. `decide` is the PCA policy engine.
    public static func authorizeCharge(_ mandate0: JSONValue, _ charge: JSONValue, _ verifiedGrant: JSONValue, decide: Decide) throws -> JSONValue {
        let mandate = try bindToVerifiedGrant(mandate0, verifiedGrant)
        let now = try P.prop(charge, "now")
        let nowV: JSONValue = P.isFinite(now) ? now! : P.num(P.nowMs())
        let raw = try decide(try chargeDecideInput(mandate, charge, nowV, verifiedGrant))
        let amount = try P.prop(charge, "amount"), merchant = try P.prop(charge, "merchant")
        let refusal: String? = !isMinorUnits(amount) ? AMOUNT_NOT_MINOR_UNITS : (!isPlainId(merchant) ? MERCHANT_INVALID : nil)
        let decision: JSONValue
        if let r = refusal {
            guard case var .object(d) = raw else { throw JSError("Cannot read properties of undefined (reading 'reasons')") }
            guard case let .array(rs)? = d["reasons"] else { throw JSError("raw.reasons is not iterable") }
            d["admit"] = .bool(false)
            d["releaseGuardianShare"] = .bool(false)
            d["reasons"] = .array([.string(r)] + rs)
            d["budget"] = mandate.get("budget") ?? .null
            decision = .object(d)
        } else { decision = raw }
        let outcome: String = !JS.truthy(decision.get("releaseGuardianShare")) ? "deny" : (JS.truthy(decision.get("admit")) ? "auto" : "step_up")
        let policy: JSONValue? = mandate.get("policy"), terms: JSONValue? = mandate.get("terms")
        let budget: JSONValue = mandate.get("budget") ?? .null
        let kappa = try P.prop(policy, "kappa")
        let exact = try outcome == "auto" && isMinorUnits(amount) && P.seq(kappa, P.prop(terms, "perTransactionCap")) && P.safeInt(budget.get("B"))
        let required = try P.prop(decision, "requiredThreshold")
        let t = try P.prop(required, "t")
        let r = decision.get("r")
        let cost: JSONValue
        if outcome != "auto" { cost = .int(0) }
        else if exact { cost = amount ?? .null }
        else { cost = P.num(Risk.cost(P.numOf(r) ?? .nan, kappa: P.toNumber(kappa))) }
        let after: JSONValue
        if exact {
            var b = P.spreadObj(decision.get("budget"))
            b["B"] = P.num(P.toNumber(budget.get("B")) - P.toNumber(amount))
            after = .object(b)
        } else { after = decision.get("budget") ?? .null }
        return .object(["outcome": .string(outcome), "t": t ?? .null, "r": r ?? .null, "requiredThreshold": required ?? .null, "cost": cost, "budgetBefore": budget,
                        "budgetAfter": after, "reasons": decision.get("reasons") ?? .null, "decision": decision])
    }

    /// Advance the mandate's budget after a decision (functional).
    public static func settleCharge(_ mandate: JSONValue, _ decision: JSONValue) throws -> JSONValue {
        var m = P.spreadObj(mandate)
        m["budget"] = try P.prop(decision, "budgetAfter")
        return .object(m)
    }

    static func nz(_ v: JSONValue?) -> Double { P.numOf(v).flatMap { $0.isFinite && $0 > 0 ? $0 : nil } ?? 0 }

    public static func recharge(_ b: JSONValue?, _ rho: JSONValue?, _ bMax: JSONValue?, _ now: JSONValue) throws -> JSONValue {
        let bb = try P.prop(b, "B")
        let r = nz(rho)
        let total: Double
        switch bb {
        // `B + nz(rho)` concatenates when B is a string, an array or an object
        case .string?, .array?, .object?: total = JS.numberFromString(P.tostr(bb) + JS.number(r))
        default: total = P.toNumber(bb) + r
        }
        return .object(["B": P.num(P.jsMin(nz(bMax), total)), "tau": now, "asOf": now])
    }

    /// Apply a human co-sign: restore autonomous budget by `rho`, or fully re-confirm to `bMax` with `{"full": true}`. The only way
    /// the budget goes up. `opts` nil is `undefined` (defaults to `{}`); `.null` is a TypeError, as in the reference.
    public static func applyHumanCosign(_ mandate: JSONValue, _ now: JSONValue, _ opts: JSONValue? = nil) throws -> JSONValue {
        let full = JS.truthy(try P.prop(opts ?? .object([:]), "full"))
        let m: JSONValue? = mandate
        let budget: JSONValue
        if full {
            budget = .object(["B": P.num(nz(try P.prop(try P.prop(m, "policy"), "bMax"))), "tau": now, "asOf": now])
        } else {
            let policy = try P.prop(m, "policy")
            budget = try recharge(try P.prop(m, "budget"), try P.prop(policy, "rho"), try P.prop(policy, "bMax"), now)
        }
        var out = P.spreadObj(m)
        out["budget"] = budget
        return .object(out)
    }

    /// Durable cumulative-budget state with an atomic compare-and-set (the reference's `ChargeBudgetStore`).
    public struct BudgetStore {
        /// The record of `key`: `{budget, version}`, or nil when there is none yet.
        public var get: (String) throws -> JSONValue?
        /// Commit `budget` only while the stored version still equals `expected` (nil = no record yet).
        public var compareAndSet: (String, Int64?, JSONValue) throws -> Bool
        public init(get: @escaping (String) throws -> JSONValue?, compareAndSet: @escaping (String, Int64?, JSONValue) throws -> Bool) {
            self.get = get; self.compareAndSet = compareAndSet
        }
    }

    static let MAX_CAS_ATTEMPTS = 8

    static func validRecord(_ r: JSONValue) -> Bool {
        let v = r.get("version"), b = r.get("budget")
        guard P.safeInt(v), let f = P.numOf(v), !(f == 0 && f.sign == .minus), let bo = b, bo.isObject else { return false }
        return ["B", "tau", "asOf"].allSatisfy { P.isFinite(bo.get($0)) }
    }

    static func recordOf(_ store: BudgetStore, _ key: String) throws -> JSONValue? {
        let rec = try store.get(key)
        if let r = rec, !validRecord(r) { throw JSError("the store returned a malformed budget record") }
        return rec
    }

    /// `authorizeCharge` against the DURABLE cumulative budget in `store`. An auto debit is committed with a compare-and-set before it
    /// is returned; losing the race re-reads and re-decides; persistent contention returns a deny.
    public static func authorizeChargeAtomic(_ mandate: JSONValue, _ charge: JSONValue, _ verifiedGrant: JSONValue, store: BudgetStore, decide: Decide, key: String? = nil) throws -> JSONValue {
        let k = try key ?? P.hashStrict(verifiedGrant)
        for _ in 0..<MAX_CAS_ATTEMPTS {
            let rec = try recordOf(store, k)
            var m = mandate
            if let r = rec { var o = P.spreadObj(mandate); o["budget"] = r.get("budget") ?? .null; m = .object(o) }
            let d = try authorizeCharge(m, charge, verifiedGrant, decide: decide)
            if d.get("outcome")?.asString != "auto" { return d }
            if try store.compareAndSet(k, rec?.get("version").flatMap { $0.safeInt }, d.get("budgetAfter") ?? .null) { return d }
        }
        let d = try authorizeCharge(mandate, charge, verifiedGrant, decide: decide)
        var o = d.asObject ?? [:]
        o["outcome"] = .string("deny"); o["t"] = .int(3); o["cost"] = .int(0)
        o["budgetAfter"] = d.get("budgetBefore") ?? .null
        o["reasons"] = .array([.string("budget_store_conflict")] + (d.get("reasons")?.asArray ?? []))
        return .object(o)
    }

    /// `applyHumanCosign` against the DURABLE budget, committed with a compare-and-set so a co-sign racing a charge is never lost or
    /// applied twice. Call it only after verifying the human co-sign; persistent contention is an error.
    public static func applyHumanCosignAtomic(_ mandate: JSONValue, _ verifiedGrant: JSONValue, store: BudgetStore, now: JSONValue, full: Bool = false, key: String? = nil) throws -> JSONValue {
        let k = try key ?? P.hashStrict(verifiedGrant)
        for _ in 0..<MAX_CAS_ATTEMPTS {
            let rec = try recordOf(store, k)
            var base = mandate
            if let r = rec { var o = P.spreadObj(mandate); o["budget"] = r.get("budget") ?? .null; base = .object(o) }
            let bound = try bindToVerifiedGrant(base, verifiedGrant)
            let next = try applyHumanCosign(bound, now, .object(["full": .bool(full)])).get("budget") ?? .null
            if try store.compareAndSet(k, rec?.get("version").flatMap { $0.safeInt }, next) { return next }
        }
        throw JSError("could not commit the co-sign: the budget record kept changing")
    }

    // ---- charge as a proof-carrying action ----

    /// The committed plan node for a charge; `params_digest` is pinned to the charge params so the leaf reconciles with the PCActn.
    public static func chargePlanNode(_ mandate: JSONValue, _ charge: JSONValue, _ id: String) throws -> JSONValue {
        let (params, undef) = try chargeParamsRaw(mandate, charge)
        if undef { throw JSError("canonicalize: unsupported type undefined") }
        return .object(["id": .string(id), "verb": .string(CHARGE_VERB), "resource": .string("merchant:" + P.tostr(try P.prop(charge, "merchant"))),
                        "reversibility_class": .string(CHARGE_REVERSIBILITY_CLASS), "params_digest": .string(try P.hashStrict(.object(params)))])
    }

    /// A signed PCActn for a charge: `{pcactn, node}`. `opts`: `aud`, `counter`, optional `chain`, `nodeId`, `now`. `signer` is the leaf
    /// holder's key (the reference's `opts.signerSecret`).
    public static func chargeToPCActn(_ mandate: JSONValue, _ charge: JSONValue, _ opts: JSONValue, signer: PCASuiteKey) throws -> JSONValue {
        let c: JSONValue? = charge, o: JSONValue? = opts
        if !isMinorUnits(try P.prop(c, "amount")) { throw JSError("chargeToPCActn: amount must be a non-negative integer in minor units") }
        let counterV = try P.prop(o, "counter")
        let nodeId: String
        switch try P.prop(o, "nodeId") {
        case nil, .null?: nodeId = "charge:\(P.tostr(try P.prop(c, "merchant"))):\(P.tostr(counterV))"
        case let .string(s)?: nodeId = s
        default: throw JSError("chargeToPCActn: nodeId must be a string")
        }
        let node = try chargePlanNode(mandate, charge, nodeId)
        let x = try P.prop(try P.prop(mandate, "terms"), "perTransactionCap")
        let amountV = try P.prop(c, "amount")
        let amount = P.toNumber(P.isFinite(amountV) ? amountV : x)
        let xf = P.toNumber(x)
        var r = xf > 0 ? amount / xf : 1
        r = r < 0 ? 0 : (r > 1 ? 1 : r)
        let params = try chargeParams(mandate, charge)
        let chain: [JSONValue]
        switch try P.prop(o, "chain") {
        case nil, .null?: chain = [mandate.get("grant") ?? .null]
        case let .array(a)? where !a.isEmpty: chain = a
        default: throw JSError("chain[0] is not a capability")
        }
        guard chain[0].isObject else { throw JSError("buildPCActn: the grant is not a capability") }
        guard let cf = P.numOf(counterV), cf.rounded() == cf, abs(cf) <= P.MAX_SAFE else { throw JSError("build_pcactn: counter must be an integer") }
        let aud = (try P.prop(o, "aud"))?.asString ?? ""
        let nowV = try P.prop(o, "now")
        let iat: Int64 = P.isFinite(nowV) ? Int64(P.numOf(nowV) ?? 0) : Int64(P.nowMs())
        var inputs = params.asObject ?? [:]
        inputs["blastRadius"] = P.num(r)
        let pcactn: JSONValue
        do {
            let plan = try PCAIssue.commitPlan([node.asObject ?? [:]])
            pcactn = try PCAIssue.buildPCActn(.init(grant: chain[0], chain: chain, plan: plan, nodeId: nodeId, params: params, counter: Int64(cf), signer: signer, aud: aud, iat: iat,
                                                    extras: ["risk_claim": .object(["r": P.num(r), "inputs": .object(inputs)])]))
        } catch let e as PCAProducerError { throw JSError(e.description) }
        return .object(["pcactn": pcactn, "node": node])
    }

    // ---- Shared Payment Token limits, rails ----

    /// The `usage_limits` of a Stripe Shared Payment Token that fits what the mandate lets an agent spend WITHOUT a co-sign: at most the
    /// auto-approve threshold and the remaining autonomous budget, lowercase currency, expiring with the mandate period.
    public static func sharedPaymentTokenLimits(_ mandate: JSONValue, _ now: JSONValue) throws -> JSONValue {
        if !P.isFinite(now) { throw JSError("sharedPaymentTokenLimits: now must be an epoch-ms time") }
        let t = try P.prop(mandate, "terms")
        let budget = P.toNumber(try P.prop(try P.prop(mandate, "budget"), "B")).rounded(.down)
        let mx = P.jsMin(P.toNumber(try P.prop(t, "autoApproveThreshold")), budget)
        if !P.safeF(mx) || mx <= 0 { throw JSError("sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed") }
        let pe = try P.prop(t, "periodEnd")
        // an infinite period end would serialize as expires_at: null, read as no expiry
        if pe != nil && !P.isFinite(pe) { throw JSError("sharedPaymentTokenLimits: periodEnd must be an epoch-ms time") }
        if pe != nil && !(P.toNumber(now) < P.toNumber(pe)) { throw JSError("sharedPaymentTokenLimits: the mandate period has ended") }
        guard let cur = (try P.prop(t, "currency"))?.asString else { throw JSError("t.currency.toLowerCase is not a function") }
        var out: JObject = ["currency": .string(P.jsLower(cur)), "max_amount": P.num(mx)]
        if pe != nil { out["expires_at"] = P.num((P.toNumber(pe) / 1000).rounded(.down)) }
        return .object(out)
    }

    static func iterValues(_ v: JSONValue) throws -> [JSONValue] {
        switch v {
        case let .array(a): return a
        case let .string(s): return s.unicodeScalars.map { .string(String($0)) }
        default: throw JSError("traits is not iterable")
        }
    }

    /// Action-kit convention: a trait `mcc.c5734` says the verb may spend in MCC 5734. Traits only narrow.
    public static func categoriesFromTraits(_ traits: JSONValue) throws -> JSONValue {
        var out = Set<String>()
        for t in try iterValues(traits) {
            let s = P.tostr(t)
            guard s.hasPrefix("mcc.c") else { continue }
            let d = String(s.dropFirst(5))
            if d.utf8.count == 4 && d.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) { out.insert(d) }
        }
        return .array(out.sorted().map { .string($0) })
    }

    /// The limits an instrument for this mandate may carry (amounts from `sharedPaymentTokenLimits`; categories are the mandate's
    /// allowlist narrowed by the action's mcc traits). `opts`: `actionTraits`, `allowAnyCategory`.
    public static func railLimits(_ mandate: JSONValue, _ now: JSONValue, _ opts: JSONValue? = nil) throws -> JSONValue {
        let o: JSONValue? = opts ?? .object([:])
        let spt = try sharedPaymentTokenLimits(mandate, now)
        let total = P.num(P.toNumber(try P.prop(try P.prop(mandate, "budget"), "B")).rounded(.down))
        let t = try P.prop(mandate, "terms")
        let fromMandate = try P.spreadArr(try P.prop(t, "categories") ?? .null)
        let traits = try P.prop(o, "actionTraits")
        let fromTraits = try categoriesFromTraits(P.nullish(traits) ? .array([]) : traits!).asArray ?? []
        let cats: [JSONValue]
        if !fromMandate.isEmpty && !fromTraits.isEmpty {
            cats = P.jsSorted(fromMandate.filter { c in fromTraits.contains(c) })
            if cats.isEmpty { throw JSError("railLimits: the action traits and the mandate categories do not intersect; nothing may be spent") }
        } else if !fromMandate.isEmpty { cats = P.jsSorted(fromMandate) }
        else { cats = P.jsSorted(fromTraits) }
        if cats.isEmpty, try P.prop(o, "allowAnyCategory") != .bool(true) {
            throw JSError("railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category")
        }
        guard let cur = (try P.prop(t, "currency"))?.asString else { throw JSError("t.currency.toUpperCase is not a function") }
        var out: JObject = ["currency": .string(P.jsUpper(cur)), "perAuthorizationMax": spt.get("max_amount") ?? .null, "totalMax": total, "categories": .array(cats),
                            "merchants": .array(try P.spreadArr(try P.prop(t, "merchants") ?? .null))]
        if let e = spt.get("expires_at") { out["expiresAt"] = P.num(P.toNumber(e) * 1000) }
        return .object(out)
    }

    /// Compare what settled with what PCA approved: commit only on an exact fit; anything else says freeze the grant.
    public static func reconcileSettlement(_ approved: JSONValue, _ s: JSONValue) throws -> JSONValue {
        let a: JSONValue? = approved, sv: JSONValue? = s
        var reasons: [String] = []
        if !P.seq(try P.prop(sv, "authorizationId"), try P.prop(a, "id")) { reasons.append("authorization_id_mismatch") }
        if P.jsGt(try P.prop(sv, "amount"), try P.prop(a, "amount")) { reasons.append("settled_more_than_approved") }
        guard let sc = (try P.prop(sv, "currency"))?.asString else { throw JSError("s.currency.toUpperCase is not a function") }
        guard let ac = (try P.prop(a, "currency"))?.asString else { throw JSError("approved.currency.toUpperCase is not a function") }
        if P.jsUpper(sc) != P.jsUpper(ac) { reasons.append("currency_mismatch") }
        if !P.seq(try P.prop(sv, "merchantId"), try P.prop(a, "merchantId")) { reasons.append("merchant_mismatch") }
        if P.jsGt(try P.prop(sv, "captures"), .int(1)) { reasons.append("second_capture") }
        return reasons.isEmpty ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reasons": .array(reasons.map { .string($0) }), "action": .string("freeze_grant")])
    }

    // ---- Stripe Issuing adapter ----

    /// The form parameters for `POST /v1/issuing/cards` (virtual, active) that carry the rail limits. Fails when an MCC has no Stripe
    /// category name. `metadata` is the optional `{k: v}` object.
    public static func stripeCardParams(_ limits: JSONValue, _ categoryNames: JSONValue, _ cardholder: JSONValue, _ metadata: JSONValue? = nil) throws -> JSONValue {
        let l: JSONValue? = limits
        guard let cur = (try P.prop(l, "currency"))?.asString else { throw JSError("limits.currency.toLowerCase is not a function") }
        var p: JObject = [
            "cardholder": cardholder, "type": .string("virtual"), "status": .string("active"), "currency": .string(P.jsLower(cur)),
            "spending_controls[spending_limits][0][amount]": .string(P.tostr(try P.prop(l, "perAuthorizationMax"))),
            "spending_controls[spending_limits][0][interval]": .string("per_authorization"),
            "spending_controls[spending_limits][1][amount]": .string(P.tostr(try P.prop(l, "totalMax"))),
            "spending_controls[spending_limits][1][interval]": .string("all_time"),
        ]
        guard case let .array(cats)? = try P.prop(l, "categories") else { throw JSError("limits.categories.forEach is not a function") }
        for (i, mcc) in cats.enumerated() {
            guard let name = try P.prop(categoryNames, P.tostr(mcc)) else { throw JSError("stripeCardParams: no Stripe category name for MCC \(P.tostr(mcc))") }
            p[JKey("spending_controls[allowed_categories][\(i)]")] = name
        }
        if case let .object(md)? = metadata { for (k, v) in md { p[JKey("metadata[\(k.s)]")] = v } }
        return .object(p)
    }

    static func hmacStripe(_ secret: String, _ t: String, _ rawBody: String) -> (key: SymmetricKey, data: Data) {
        (SymmetricKey(data: Data(secret.utf8)), Data((t + "." + rawBody).utf8))
    }

    /// `t=<t>,v1=<hex>` over `<t>.<rawBody>` with the endpoint secret.
    public static func signStripePayload(_ rawBody: String, _ secret: String, _ tSec: Double) -> String {
        let t = JS.toString(.double(tSec))
        let (k, d) = hmacStripe(secret, t, rawBody)
        return "t=\(t),v1=" + HMAC<SHA256>.authenticationCode(for: d, using: k).map { String(format: "%02x", $0) }.joined()
    }

    /// Verify a `Stripe-Signature` header over the RAW body. Total: false on anything malformed, stale or mismatched. A NaN clock is
    /// refused (the reference's `abs(NaN) > tolerance` is false, so it goes on to compare the signature).
    public static func verifyStripeSignature(_ rawBody: String, _ header: String?, _ secret: String?, nowSec: Double, toleranceSec: Double = STRIPE_WEBHOOK_TOLERANCE_SEC) -> Bool {
        guard let header = header, let secret = secret, !secret.isEmpty, toleranceSec.isFinite, toleranceSec > 0 else { return false }
        var t: String?
        var v1: [String] = []
        for part in PayJS.splitScalars(header, ",") {
            guard let eq = part.firstIndex(of: "=") else { continue }
            let k = Attest.jsTrim(String(String.UnicodeScalarView(part[..<eq]))), v = Attest.jsTrim(String(String.UnicodeScalarView(part[(eq + 1)...])))
            if k == "t" { t = v } else if k == "v1" { v1.append(v) }
        }
        guard let tt = t, !tt.isEmpty, tt.utf8.count <= 12, tt.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), !v1.isEmpty, let tv = Double(tt) else { return false }
        let diff = nowSec - tv
        if !(abs(diff) <= toleranceSec) { return false }
        let (k, d) = hmacStripe(secret, tt, rawBody)
        return v1.contains { sig in
            guard sig.utf8.count == 64, sig.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else { return false }
            let u = Array(sig.utf8)
            var bytes: [UInt8] = []
            for i in 0..<32 {
                guard let h = WhatwgURL.hexVal(u[2 * i]), let l = WhatwgURL.hexVal(u[2 * i + 1]) else { return false }
                bytes.append(UInt8(h * 16 + l))
            }
            return HMAC<SHA256>.isValidAuthenticationCode(Data(bytes), authenticating: d, using: k)
        }
    }

    /// Normalise an `issuing_authorization.request` event; nil when it is not a well-formed request with a pending amount.
    public static func stripeAuthorizationFromEvent(_ event: JSONValue) -> JSONValue? {
        guard let e = event.asObject, e["type"]?.asString == "issuing_authorization.request",
              let a = e["data"]?.asObject.flatMap({ $0["object"] })?.asObject, let pending = a["pending_request"]?.asObject,
              let id = a["id"]?.asString, let cardId = a["card"]?.asObject?["id"]?.asString,
              let amount = pending["amount"], amount.isNumber, let currency = pending["currency"]?.asString else { return nil }
        let merchant = a["merchant_data"]?.asObject
        var out: JObject = ["id": .string(id), "instrumentId": .string(cardId), "amount": amount, "currency": .string(currency)]
        if let n = merchant?["network_id"]?.asString, !n.isEmpty { out["merchantId"] = .string(n) }
        if let c = merchant?["category_code"]?.asString { out["mcc"] = .string(c) }
        return .object(out)
    }

    static func reply(_ status: Int64, _ body: String, _ version: String) -> JSONValue {
        .object(["status": .int(status), "headers": .object(["Stripe-Version": .string(version), "Content-Type": .string("application/json")]), "body": .string(body)])
    }

    /// The HTTP handler body for the `issuing_authorization.request` endpoint. A bad signature is 400 (nothing is decided); a request
    /// event gets 200 `{approved}` from the PCA decision; any other event type gets 200 `{}`. `amount` is never sent. `authorize` is the
    /// verdict function (`{approved, reasons}`). REQUIRED OPERATOR SETTING: set the Issuing authorization timeout response to DECLINE
    /// and turn Autopilot off.
    public static func stripeIssuingWebhook(_ rawBody: String, signature: String?, secret: String?, nowSec: Double, toleranceSec: Double? = nil, stripeVersion: String? = nil,
                                            authorize: (JSONValue) -> JSONValue) -> JSONValue {
        let version = stripeVersion ?? STRIPE_API_VERSION
        if !verifyStripeSignature(rawBody, signature, secret, nowSec: nowSec, toleranceSec: toleranceSec ?? STRIPE_WEBHOOK_TOLERANCE_SEC) {
            return reply(400, "{\"error\":\"bad_signature\"}", version)
        }
        // a repeated member is refused (JSON.parse keeps the last: the signer and this reader could see different events)
        guard let parsed = try? NoDuplicateKeys.parse(rawBody) else { return reply(400, "{\"error\":\"bad_json\"}", version) }
        let event = IV.normalized(parsed)
        if event.asObject?["type"]?.asString != "issuing_authorization.request" { return reply(200, "{}", version) }
        guard let auth = stripeAuthorizationFromEvent(event) else { return reply(200, "{\"approved\":false}", version) }
        let v = authorize(auth)
        return reply(200, v.get("approved") == .bool(true) ? "{\"approved\":true}" : "{\"approved\":false}", version)
    }

    /// Normalise an `issuing_transaction.created` capture into a settlement (a capture's amount is negative in Stripe's ledger).
    public static func stripeSettlementFromTransaction(_ txn: JSONValue) -> JSONValue? {
        guard let t = txn.asObject, t["type"]?.asString == "capture", let auth = t["authorization"]?.asString,
              let amount = t["amount"], amount.isNumber, let af = IV.num(amount), let currency = t["currency"]?.asString else { return nil }
        var out: JObject = ["authorizationId": .string(auth), "amount": P.num(-af), "currency": .string(currency), "captures": .int(1)]
        if let n = t["merchant_data"]?.asObject?["network_id"]?.asString { out["merchantId"] = .string(n) }
        return .object(out)
    }

    // ---- agent network tokens ----

    static func luhn(_ d: [UInt8]) -> Bool {
        var total = 0, dbl = false
        for c in d.reversed() {
            var n = Int(c) - 48
            if dbl { n *= 2; if n > 9 { n -= 9 } }
            total += n
            dbl.toggle()
        }
        return total % 10 == 0
    }

    /// True when a maximal digit run (whitespace and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only.
    public static func looksLikePan(_ s: String) -> Bool {
        var run: [UInt8] = []
        var hit = false
        func flush() { if run.count >= 13 && run.count <= 19 && luhn(run) { hit = true }; run = [] }
        for u in s.unicodeScalars {
            if Attest.isJSSpace(u) || u == "-" { continue }
            if u.value >= 0x30 && u.value <= 0x39 { run.append(UInt8(u.value)) } else { flush() }
        }
        flush()
        return hit
    }

    /// Why a token reference is refused (`token_ref_malformed`, `token_ref_looks_like_pan`), or nil.
    public static func tokenRefError(_ r: JSONValue?) -> String? {
        guard let s = r?.asString, (8...128).contains(s.utf8.count),
              s.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x5f || $0 == 0x2e || $0 == 0x3a || $0 == 0x2d }) else {
            return "token_ref_malformed"
        }
        return looksLikePan(s) ? "token_ref_looks_like_pan" : nil
    }

    static func bodyOf(_ b: JSONValue) throws -> JSONValue {
        let m: JSONValue? = b
        var body: JObject = ["kind": .string(NETWORK_TOKEN_BINDING_KIND), "v": .int(1)]
        for k in ["provider", "token_ref", "grant_digest", "issuer_nonce", "holder"] {
            guard let v = try P.prop(m, k) else { throw JSError("canonicalize: unsupported type undefined") }
            body[JKey(k)] = v
        }
        return .object(body)
    }

    /// The exact bytes the holder signs: UTF-8 of the canonical-JSON digest of the binding body.
    public static func bindingMessage(_ b: JSONValue) throws -> [UInt8] { Array(try P.hashStrict(try bodyOf(b)).utf8) }

    /// Tie a grant holder to an OPAQUE network-token reference (never a PAN). `opts`: `provider`, `tokenRef`, `grant`, `issuerNonce`.
    /// `holder` signs (the reference's `holderSecret`); `holderPublic` is its public key bytes.
    public static func bindNetworkToken(_ opts: JSONValue, holder: PCAEdKey, holderPublic: [UInt8]) throws -> JSONValue {
        let o: JSONValue? = opts
        if let e = tokenRefError(try P.prop(o, "tokenRef")) { throw JSError("bindNetworkToken: \(e)") }
        let nonce = try P.prop(o, "issuerNonce")
        if let n = try P.length(nonce), P.toNumber(n) < 16 { throw JSError("bindNetworkToken: issuer nonce must be at least 16 chars") }
        var core: JObject = [:]
        if let p = try P.prop(o, "provider") { core["provider"] = p }
        core["token_ref"] = try P.prop(o, "tokenRef") ?? .null
        core["grant_digest"] = .string(try P.hashStrict(try P.prop(o, "grant")))
        core["issuer_nonce"] = nonce ?? .null
        core["holder"] = .string(Base64URLStrict.encode(holderPublic))
        let proof: [UInt8]
        do { proof = try holder.sign(try bindingMessage(.object(core))) } catch let e as PCAProducerError { throw JSError(e.description) }
        var out: JObject = ["kind": .string(NETWORK_TOKEN_BINDING_KIND)]
        for (k, v) in core { out[k] = v }
        out["binding_proof"] = .string(Base64URLStrict.encode(proof))
        return .object(out)
    }

    static func verifyBinding(_ b: JSONValue, _ expect: JSONValue) throws -> String? {
        let x: JSONValue? = b, e: JSONValue? = expect
        if try !isObj(b) || (P.prop(x, "kind"))?.asString != NETWORK_TOKEN_BINDING_KIND { return "binding_malformed" }
        if let err = tokenRefError(try P.prop(x, "token_ref")) { return err }
        let prov = try P.prop(x, "provider"), expProv = try P.prop(e, "provider")
        if (prov?.asString ?? "").isEmpty || (expProv != nil && !P.seq(prov, expProv)) { return "provider_mismatch" }
        if !P.seq(try P.prop(x, "grant_digest"), .string(try P.hashStrict(try P.prop(e, "grant")))) { return "grant_digest_mismatch" }
        if !P.seq(try P.prop(x, "holder"), try P.prop(e, "holder")) { return "holder_mismatch" }
        if !P.seq(try P.prop(x, "issuer_nonce"), try P.prop(e, "issuerNonce")) { return "issuer_nonce_mismatch" }
        guard let hs = (try P.prop(x, "holder"))?.asString, let pk = Base64URLStrict.decode(hs),
              let ps = (try P.prop(x, "binding_proof"))?.asString, let sg = Base64URLStrict.decode(ps) else { return "binding_malformed" }
        guard pk.count == 32, sg.count == 64 else { return "binding_proof_invalid" }
        return Ed25519Strict.verify(publicKey: pk, message: try bindingMessage(b), signature: sg) ? nil : "binding_proof_invalid"
    }

    /// Total. nil = valid, else the refusal reason. `expect`: `grant` (the one the caller verified), `holder` (b64u), `issuerNonce`,
    /// optional `provider`.
    public static func verifyNetworkTokenBinding(_ b: JSONValue, _ expect: JSONValue) -> String? {
        // not `try?` + `??`: verifyBinding returns nil for a VALID binding, and `try?` flattens that nil into the failure default
        do { return try verifyBinding(b, expect) } catch { return "binding_malformed" }
    }

    /// The network-side controls: always an upper-bounded copy of the rail limits.
    public static func controlsFromLimits(_ limits: JSONValue, _ grant: JSONValue) throws -> JSONValue {
        let l: JSONValue? = limits
        var c: JObject = [:]
        for k in ["currency", "perAuthorizationMax", "totalMax"] { if let v = try P.prop(l, k) { c[JKey(k)] = v } }
        c["categories"] = .array(try P.spreadArr(try P.prop(l, "categories") ?? .null))
        c["merchants"] = .array(try P.spreadArr(try P.prop(l, "merchants") ?? .null))
        if let e = try P.prop(l, "expiresAt") { c["expiresAt"] = e }
        c["metadata"] = .object(["grant_digest": .string(try P.hashStrict(grant))])
        return .object(c)
    }

    /// The metadata echoed on the network settlement.
    public static func settlementMetadata(_ b: JSONValue, _ pcactnDigest: JSONValue) throws -> JSONValue {
        var m: JObject = [:]
        if let g = try P.prop(b, "grant_digest") { m["pca_grant"] = g }
        m["pca_pcactn"] = pcactnDigest
        if let r = try P.prop(b, "token_ref") { m["pca_token_ref"] = r }
        return .object(m)
    }

    /// A network settlement record joins the ledger entry only if all three echoed values match exactly.
    public static func reconcileNetworkSettlement(_ expected: JSONValue, _ record: JSONValue) throws -> JSONValue {
        let md = try P.optprop(record, "metadata")
        let m: JSONValue? = P.nullish(md) ? .object([:]) : md
        let ex: JSONValue? = expected
        var reasons: [String] = []
        let ped = try P.prop(m, "pca_pcactn")
        var missing = true
        if let s = ped?.asString, !s.isEmpty {
            if let n = try P.length(try P.prop(ex, "pcactnDigest")), P.toNumber(n) == 0 { missing = true } else { missing = false }
        }
        if missing { reasons.append("pcactn_digest_missing") }
        if !P.seq(try P.prop(m, "pca_grant"), try P.prop(ex, "grantDigest")) { reasons.append("grant_digest_mismatch") }
        if !P.seq(ped, try P.prop(ex, "pcactnDigest")) { reasons.append("pcactn_digest_mismatch") }
        if !P.seq(try P.prop(m, "pca_token_ref"), try P.prop(ex, "tokenRef")) { reasons.append("token_ref_mismatch") }
        return reasons.isEmpty ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reasons": .array(reasons.map { .string($0) })])
    }

    /// Build the PCActn for the charge and return the metadata for the network request, derived from THAT PCActn's digest: there is no
    /// way to carry a digest that is not of a PCActn this call built.
    public static func chargeWithNetworkToken(_ binding: JSONValue, _ mandate: JSONValue, _ charge: JSONValue, _ opts: JSONValue, signer: PCASuiteKey) throws -> JSONValue {
        if tokenRefError(try P.prop(binding, "token_ref")) != nil { throw JSError("chargeWithNetworkToken: bad binding") }
        if !P.seq(try P.prop(binding, "grant_digest"), .string(try P.hashStrict(try P.prop(mandate, "grant")))) {
            throw JSError("chargeWithNetworkToken: binding is for another grant")
        }
        let built = try chargeToPCActn(mandate, charge, opts, signer: signer)
        let pcactn = built.get("pcactn") ?? .null
        let digest = try P.hashStrict(pcactn)
        return .object(["pcactn": pcactn, "node": built.get("node") ?? .null, "metadata": try settlementMetadata(binding, .string(digest)), "pcactnDigest": .string(digest)])
    }
}
