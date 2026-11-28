import Foundation

/// Explainable reputation over observed outcomes (deny rate, step-up rate, slashed disputes), coverage pricing from it, the signed coverage
/// quote, the capital-constrained insurance pool and the derivation of disputes from guardian-signed settlement records. Reputation is a
/// read of history, never an authorization: nothing here admits an action.
public enum Reputation {
    public static let MAX_REPUTATION_RECORDS = 100_000
    /// Domain separation of the underwriter's signature over a coverage quote.
    public static let COVERAGE_QUOTE_DOMAIN = "atlas-pca/coverage-quote/v1\0"
    static let OUTCOMES = ["auto", "step_up", "deny", "executed"]

    private static func unit(_ x: Double) -> Double { x.isNaN ? x : (x > 0 ? min(1, x) : 0) }

    /// Nil when the input `{subject, events?, disputes?}` is well formed, else the first problem.
    public static func validateReputationInput(_ input: JSONValue?) -> String? {
        guard let subject = input?.get("subject")?.asString, !subject.isEmpty else { return "subject must be a non-empty string" }
        // an absent member is an empty list; null is not
        guard case let .array(events) = input?.get("events") ?? .array([]), case let .array(disputes) = input?.get("disputes") ?? .array([]) else {
            return "events and disputes must be arrays"
        }
        if events.count > MAX_REPUTATION_RECORDS || disputes.count > MAX_REPUTATION_RECORDS { return "too many records" }
        if events.contains(where: { e in !OUTCOMES.contains { IV.same($0, e.get("outcome")?.asString) } }) { return "event with an unknown outcome" }
        for d in disputes {
            guard let id = d.get("id")?.asString, !id.isEmpty else { return "dispute without an id" }
            if !IV.same(d.get("subject")?.asString, subject) { return "dispute for another subject" }
            guard case .bool? = d.get("slashed") else { return "dispute.slashed must be a boolean" }
            guard let at = IV.num(d.get("at")), at.isFinite, at >= 0 else { return "dispute.at must be finite and >= 0" }
            if let amount = d.get("amount") {
                guard let a = IV.num(amount), a.isFinite, a >= 0 else { return "dispute.amount must be finite and >= 0" }
            }
        }
        return nil
    }

    private static func row(_ subject: String, _ actions: Int, _ autos: Int, _ stepUps: Int, _ denies: Int, _ slashes: Int, _ disputes: Int, _ score: Double,
                            _ factors: [String]) -> JSONValue {
        var o: JObject = [:]
        o[o: "subject"] = .string(subject)
        o[o: "actions"] = .int(Int64(actions))
        o[o: "autos"] = .int(Int64(autos))
        o[o: "stepUps"] = .int(Int64(stepUps))
        o[o: "denies"] = .int(Int64(denies))
        o[o: "slashes"] = .int(Int64(slashes))
        o[o: "disputes"] = .int(Int64(disputes))
        o[o: "score"] = PD.num(score)
        o[o: "factors"] = .array(factors.map { .string($0) })
        return .object(o)
    }

    /// The reputation of a subject: `{subject, actions, autos, stepUps, denies, slashes, disputes, score, factors}` with score in [0, 1].
    /// Never throws: an invalid input scores 0 with the factor `invalid input: <reason>`. Disputes are de-duplicated by id before scoring.
    public static func reputation(_ input: JSONValue?) -> JSONValue {
        if let bad = validateReputationInput(input) {
            let subject = JS.present(input?.get("subject")).map { JS.toString($0) } ?? ""
            return row(subject, 0, 0, 0, 0, 0, 0, 0, ["invalid input: \(bad)"])
        }
        let subject = input?.get("subject")?.asString ?? ""
        let events = input?.get("events")?.asArray ?? []
        var seen = Set<JKey>()
        let disputes = (input?.get("disputes")?.asArray ?? []).filter { seen.insert(JKey($0.get("id")?.asString ?? "")).inserted }
        func count(_ outcome: String) -> Int { events.filter { IV.same($0.get("outcome")?.asString, outcome) }.count }
        let actions = events.count, autos = count("auto"), stepUps = count("step_up"), denies = count("deny")
        let slashes = disputes.filter { $0.get("slashed") == .bool(true) }.count
        if actions == 0 && disputes.isEmpty { return row(subject, actions, autos, stepUps, denies, slashes, 0, 0.5, ["unproven (no history)"]) }

        var factors: [String] = []
        var score = 1.0
        if actions > 0 {
            let denyRate = Double(denies) / Double(actions), stepUpRate = Double(stepUps) / Double(actions)
            if denyRate > 0 {
                score -= 0.6 * denyRate
                factors.append("deny rate \(PCAImmune.toFixed(denyRate * 100, 0))%")
            }
            if stepUpRate > 0 {
                score -= 0.15 * stepUpRate
                factors.append("step-up rate \(PCAImmune.toFixed(stepUpRate * 100, 0))%")
            }
        }
        if slashes > 0 {
            score -= min(0.8, 0.3 * Double(slashes))
            factors.append("\(slashes) slashed dispute\(slashes > 1 ? "s" : "")")
        }
        if factors.isEmpty { factors.append("clean history") }
        return row(subject, actions, autos, stepUps, denies, slashes, disputes.count, unit(score), factors)
    }

    /// Underwriting parameters: the base premium rate (default 0.01), the load on a low score (default 4) and the score below which
    /// coverage is declined (default 0.25).
    public struct PricingOptions: Equatable, Sendable {
        public var baseRate: Double?
        public var riskLoad: Double?
        public var minScore: Double?
        public init(baseRate: Double? = nil, riskLoad: Double? = nil, minScore: Double? = nil) {
            self.baseRate = baseRate; self.riskLoad = riskLoad; self.minScore = minScore
        }
    }

    public struct InsurancePricing: Equatable, Sendable {
        public var declined: Bool
        public var premium: Double
        public var coverage: Double
        public var rationale: String

        public var json: JSONValue {
            var o: JObject = [:]
            o[o: "declined"] = .bool(declined)
            o[o: "premium"] = PD.num(premium)
            o[o: "coverage"] = PD.num(coverage)
            o[o: "rationale"] = .string(rationale)
            return .object(o)
        }
    }

    /// Prices coverage of `exposure` for a reputation score: `baseRate * exposure * (1 + riskLoad * (1 - score))`. Declined (premium and
    /// coverage 0) when the score is not a number in [0, 1] or is below `minScore`. A negative or non-finite exposure counts as 0.
    public static func priceCoverage(score: Double, exposure: Double, _ opts: PricingOptions = PricingOptions()) -> InsurancePricing {
        let baseRate = opts.baseRate ?? 0.01, riskLoad = opts.riskLoad ?? 4, minScore = opts.minScore ?? 0.25
        if !score.isFinite || score < 0 || score > 1 { return InsurancePricing(declined: true, premium: 0, coverage: 0, rationale: "invalid reputation score") }
        let exp = exposure.isFinite && exposure > 0 ? exposure : 0
        func text(_ d: Double) -> String { JS.toString(.double(d)) }
        if score < minScore {
            return InsurancePricing(declined: true, premium: 0, coverage: 0, rationale: "reputation \(PCAImmune.toFixed(score, 2)) below underwriting floor \(text(minScore))")
        }
        let load = 1 + riskLoad * (1 - score)
        return InsurancePricing(declined: false, premium: baseRate * exp * load, coverage: exp,
                                rationale: "base \(text(baseRate)) × exposure \(text(exp)) × load \(PCAImmune.toFixed(load, 2)) (score \(PCAImmune.toFixed(score, 2)))")
    }

    private static func quoteMessage(_ claim: JObject) throws -> [UInt8] {
        Array(COVERAGE_QUOTE_DOMAIN.utf8) + Array(try SafetyCertificate.canonical(.object(claim)).utf8)
    }

    /// Issues a signed coverage quote for a reputation (`rep` is the object `reputation` returns): the pricing inputs, the price, a
    /// validity window `[now, now + ttlMs)` and the underwriter's Ed25519 signature. Throws on a non-finite or negative exposure, a
    /// non-finite time, a ttl that is not positive, and a score outside [0, 1].
    public static func issueCoverageQuote(rep: JSONValue, exposure: Double, underwriter: PCAEdKey, now: Double, ttlMs: Double,
                                          _ opts: PricingOptions = PricingOptions()) throws -> JSONValue {
        if !exposure.isFinite || exposure < 0 { throw JSError("issueCoverageQuote: exposure must be finite and >= 0") }
        if !now.isFinite || !(ttlMs > 0) || !ttlMs.isFinite { throw JSError("issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0") }
        guard let score = IV.num(rep.get("score")), score.isFinite, score >= 0, score <= 1 else { throw JSError("issueCoverageQuote: invalid reputation score") }
        // a reputation without a subject cannot be encoded in the signed claim
        guard let subject = rep.get("subject") else { throw JSError("canonicalize: unsupported type undefined") }
        let baseRate = opts.baseRate ?? 0.01, riskLoad = opts.riskLoad ?? 4, minScore = opts.minScore ?? 0.25
        let p = priceCoverage(score: score, exposure: exposure, PricingOptions(baseRate: baseRate, riskLoad: riskLoad, minScore: minScore))
        var claim: JObject = [:]
        claim[o: "v"] = .int(1)
        claim[o: "subject"] = subject
        claim[o: "score"] = PD.num(score)
        claim[o: "exposure"] = PD.num(exposure)
        claim[o: "baseRate"] = PD.num(baseRate)
        claim[o: "riskLoad"] = PD.num(riskLoad)
        claim[o: "minScore"] = PD.num(minScore)
        claim[o: "declined"] = .bool(p.declined)
        claim[o: "premium"] = PD.num(p.premium)
        claim[o: "coverage"] = PD.num(p.coverage)
        claim[o: "issued_at"] = PD.num(now)
        claim[o: "expires_at"] = PD.num(now + ttlMs)
        claim[o: "underwriter"] = .string(Base64URLStrict.encode(underwriter.pub))
        claim[o: "sig"] = .string(Base64URLStrict.encode(try underwriter.sign(try quoteMessage(claim))))
        return .object(claim)
    }

    /// Verifies a coverage quote against the pinned `underwriter` key at `now`. Never throws. `{ok: true}` or `{ok: false, reason}` with
    /// reason `malformed`, `underwriter`, `signature`, `not-yet-valid`, `expired` or `price-mismatch` (the price is recomputed from the
    /// signed inputs).
    public static func verifyCoverageQuote(_ quote: JSONValue?, underwriter: String, now: Double) -> JSONValue {
        func no(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }
        guard case let .object(q)? = quote, IV.num(q["v"]) == 1, let sig = q["sig"]?.asString else { return no("malformed") }
        var n: [Double] = []
        for k in ["score", "exposure", "baseRate", "riskLoad", "minScore", "premium", "coverage", "issued_at", "expires_at"] {
            guard let v = IV.num(q[JKey(k)]), v.isFinite else { return no("malformed") }
            n.append(v)
        }
        guard case let .bool(declined)? = q["declined"], q["subject"]?.asString != nil else { return no("malformed") }
        guard let named = q["underwriter"]?.asString, IV.same(named, underwriter) else { return no("underwriter") }
        var claim = q
        claim["sig"] = nil
        guard let msg = try? quoteMessage(claim) else { return no("malformed") }
        if !Ed25519Strict.verifyB64u(named, msg, sig) { return no("signature") }
        if !now.isFinite || now < n[7] { return no("not-yet-valid") }
        if now >= n[8] { return no("expired") }
        let p = priceCoverage(score: n[0], exposure: n[1], PricingOptions(baseRate: n[2], riskLoad: n[3], minScore: n[4]))
        if p.declined != declined || p.premium != n[5] || p.coverage != n[6] { return no("price-mismatch") }
        return .object(["ok": .bool(true)])
    }

    /// Derives dispute records from settlement records, counting only those the guardian signed and whose bond maps to a known subject
    /// (`subjectOf` returns nil for an unknown claim: the record is rejected). An `open` record is not an outcome. Each dispute is
    /// `{id (the record digest), subject, slashed, at, amount}`.
    public static func disputesFromSettlements(_ records: [JSONValue], guardianPublicKey: String, subjectOf: (String) -> String?,
                                               pins: [String: String]? = nil) -> (disputes: [JSONValue], rejected: Int) {
        var disputes: [JSONValue] = []
        var rejected = 0
        for r in records {
            guard let claim = r.get("claimId")?.asString, let subject = subjectOf(claim),
                  PCABondSettlement.verifySettlement(r, guardianPublic: guardianPublicKey, pins: pins) else { rejected += 1; continue }
            let action = r.get("action")?.asString
            if action == "open" { continue }
            var d: JObject = [:]
            d[o: "id"] = .string(PCABondSettlement.settlementRecordDigest(r))
            d[o: "subject"] = .string(subject)
            d[o: "slashed"] = .bool(action == "slash")
            d[o: "at"] = r.get("at")
            d[o: "amount"] = r.get("amount")
            disputes.append(.object(d))
        }
        return (disputes, rejected)
    }
}

/// An insurance capital pool: premiums accumulate finite capital and victim payouts draw it down. The pool can only ever pay what it
/// holds (coverage is capital-constrained, fail closed). Premiums are priced by `Reputation.priceCoverage`. Pure accounting, not thread
/// safe: guard it like any other mutable value.
public final class InsuranceCapitalPool {
    public let initial: Double
    public private(set) var premiumsIn = 0.0
    public private(set) var payoutsOut = 0.0

    public init(initial: Double = 0) throws {
        if !initial.isFinite || initial < 0 { throw JSError("InsuranceCapitalPool: initial capital must be a non-negative finite number") }
        self.initial = initial
    }

    public var balance: Double { initial + premiumsIn - payoutsOut }

    /// `{initial, premiumsIn, payoutsOut, balance}`.
    public func state() -> JSONValue {
        var o: JObject = [:]
        o[o: "initial"] = PD.num(initial)
        o[o: "premiumsIn"] = PD.num(premiumsIn)
        o[o: "payoutsOut"] = PD.num(payoutsOut)
        o[o: "balance"] = PD.num(balance)
        return .object(o)
    }

    public func quote(score: Double, exposure: Double, _ opts: Reputation.PricingOptions = Reputation.PricingOptions()) -> Reputation.InsurancePricing {
        Reputation.priceCoverage(score: score, exposure: exposure, opts)
    }

    /// Prices the coverage and, unless declined, adds the premium to the pool. Returns the pricing and the state after it.
    public func collectPremium(score: Double, exposure: Double, _ opts: Reputation.PricingOptions = Reputation.PricingOptions()) throws
        -> (pricing: Reputation.InsurancePricing, state: JSONValue) {
        let pricing = quote(score: score, exposure: exposure, opts)
        if !pricing.declined && pricing.premium > 0 {
            if !pricing.premium.isFinite { throw JSError("collectPremium: priced premium is not a non-negative finite number") }
            premiumsIn += pricing.premium
        }
        return (pricing, state())
    }

    public func canCover(_ amount: Double) -> Bool { amount.isFinite && amount >= 0 && balance >= amount }

    /// Pays a claim out of the pool. Throws on an amount that is not positive and finite, and when the pool does not hold it.
    public func payClaim(_ amount: Double) throws -> JSONValue {
        if !amount.isFinite || amount <= 0 { throw JSError("payClaim: amount must be a positive finite number") }
        if !(balance.isFinite && amount <= balance) { throw JSError("payClaim: insufficient pool capital (need \(JS.toString(.double(amount))), have \(JS.toString(.double(balance))))") }
        payoutsOut += amount
        return state()
    }
}
