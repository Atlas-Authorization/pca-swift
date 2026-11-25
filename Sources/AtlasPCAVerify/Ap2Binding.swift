import Foundation
import CryptoKit

/// Verification of the PCA side of a verified AP2 payment chain: the grant in the open mandate (signed by the expected principal, consistent
/// with the terms it claims and with the open constraints), and the closed mandate's PCActn (valid under that grant, for this audience,
/// committing to exactly this AP2 charge). Run it AFTER `verifyPaymentChain`, which establishes the AP2 signatures.
///
/// The PCA policy decision (cumulative budget, charge-count rate limit, caveats) always runs on the verifier's OWN mandate state: the PCA
/// policy engine is injected as `decide`, as in `PCAPayments.authorizeCharge`. Core gates beyond the PCActn's own checks (freshness, taint,
/// forbid clauses) belong to the authorize pipeline and are not part of this entry.
extension PCAAp2 {
    /// A verification hook's answer (`attestation`, `threshold` or `revocation`): when `enforced` and not `ok` the binding is refused; a
    /// threshold hook reports the `t` it enforced.
    public struct HookResult {
        public var enforced: Bool
        public var ok: Bool
        public var reason: String?
        public var t: Double?
        public init(enforced: Bool, ok: Bool, reason: String? = nil, t: Double? = nil) { self.enforced = enforced; self.ok = ok; self.reason = reason; self.t = t }
    }

    public struct BindingHooks {
        public var attestation: ((JSONValue) -> HookResult)?
        public var threshold: ((JSONValue) -> HookResult)?
        public var revocation: ((JSONValue) -> HookResult)?
        public init(attestation: ((JSONValue) -> HookResult)? = nil, threshold: ((JSONValue) -> HookResult)? = nil, revocation: ((JSONValue) -> HookResult)? = nil) {
            self.attestation = attestation; self.threshold = threshold; self.revocation = revocation
        }
    }

    /// Thrown when `verifyPcaBinding` lacks the server-held state the policy decision needs (`code`: `mandate_required` or `charge_history_required`).
    public struct PcaBindingError: Error, CustomStringConvertible {
        public let code: String
        public let message: String
        public var description: String { message }
    }

    /// The input of `verifyPcaBinding`.
    public struct VerifyPcaBindingInput {
        public var open: JSONValue?
        public var closed: JSONValue?
        /// `sd_hash` of the open payment mandate hop (from `verifyPaymentChain().openHash`).
        public var openHash: JSONValue?
        /// The Ed25519 key (base64url) of the principal who must have signed the grant. Required.
        public var expectedPrincipal: String?
        /// Verifier-side PQ pins by Ed25519 identity.
        public var pqPins: [String: String]?
        /// This verifier's PCA audience; the PCActn's signed `aud` must equal it.
        public var audience: String
        /// Verification time, epoch ms (default: the wall clock).
        public var now: Int64?
        /// REQUIRED: the PCA mandate state THIS verifier holds (its live budget).
        public var mandate: JSONValue?
        /// Epoch-ms times of this holder's earlier admitted charges, from the verifier's own records. REQUIRED when the mandate limits the charge count.
        public var recentChargeTimes: JSONValue?
        public var hooks: BindingHooks?
        public init(open: JSONValue?, closed: JSONValue?, openHash: JSONValue?, expectedPrincipal: String?, audience: String, mandate: JSONValue?, pqPins: [String: String]? = nil,
                    now: Int64? = nil, recentChargeTimes: JSONValue? = nil, hooks: BindingHooks? = nil) {
            self.open = open; self.closed = closed; self.openHash = openHash; self.expectedPrincipal = expectedPrincipal; self.audience = audience
            self.mandate = mandate; self.pqPins = pqPins; self.now = now; self.recentChargeTimes = recentChargeTimes; self.hooks = hooks
        }
    }

    static func includes(_ list: V, _ v: V) -> Bool {
        if case let .array(a)? = list { return a.contains { P.seq($0, v) } }
        if let s = list?.asString, let x = v?.asString { return s.contains(x) }
        return false
    }

    static func findType(_ constraints: V, _ t: String) throws -> V {
        for c in try listOf(constraints, "constraints.find") {
            if P.seq(try P.prop(c, "type"), .string(t)) { return c }
        }
        return nil
    }

    /// Check the open mandate's constraints never exceed the PCA terms (the AP2 side only narrows the grant).
    static func constraintsWithinTerms(_ open: V, _ terms: V) throws -> String? {
        let cur = try P.prop(terms, "currency")
        let perTx = try minorTerm(try P.prop(terms, "perTransactionCap"), "perTransactionCap")
        let constraints = try P.prop(open, "constraints")
        guard let range = try findType(constraints, "payment.amount_range") else { return "open mandate has no amount_range to compare with the PCA per-transaction cap" }
        if !P.seq(try P.prop(range, "currency"), cur) { return "amount_range currency differs from the PCA terms" }
        let rmax = try P.prop(range, "max")
        if !jsLe(rmax, perTx) { return "amount_range.max \(P.tostr(rmax)) exceeds the PCA per-transaction cap \(P.tostr(perTx))" }
        let payees = try findType(constraints, "payment.allowed_payees")
        if let p = payees {
            for m in try listOf(try P.prop(p, "allowed"), "payees.allowed.some") {
                if !includes(try P.prop(terms, "merchants"), try P.prop(m, "id")) { return "allowed_payees names a merchant outside the PCA allowlist" }
            }
        } else { return "open mandate has no allowed_payees; the PCA allowlist would not be enforced on the AP2 side" }
        guard let budget = try findType(constraints, "payment.budget") else { return "open mandate has no budget to compare with the PCA cumulative cap" }
        if !P.seq(try P.prop(budget, "currency"), cur) { return "budget exceeds the PCA cumulative cap" }
        let reads = try ap2BudgetReads(try P.prop(budget, "max"), cur)
        let capMinor = try minorTerm(try P.prop(terms, "cumulativeCap"), "cumulativeCap")
        if jsGtV(reads.get("sdk"), capMinor) || jsGtV(reads.get("major"), capMinor) { return "budget exceeds the PCA cumulative cap" }
        let rec = try findType(constraints, "payment.agent_recurrence")
        let maxTx = try P.prop(terms, "maxTransactionsPerPeriod")
        if let mt = maxTx {
            if rec == nil { return "max_occurrences is missing or exceeds the PCA transaction limit" }
            let mo = try P.prop(rec, "max_occurrences")
            if mo == nil || !jsLe(mo, mt) { return "max_occurrences is missing or exceeds the PCA transaction limit" }
        }
        if let pe = try P.prop(terms, "periodEnd") {
            let exp = try P.prop(open, "exp")
            if exp == nil || !jsLe(exp, numV((P.toNumber(pe) / 1000).rounded(.down))) { return "open mandate outlives the PCA period" }
        }
        return nil
    }

    /// Verify the PCA side of a verified AP2 payment chain. Returns `{ ok: true, pcactn, grant, terms }` or `{ ok: false, reason }`; throws
    /// `PcaBindingError` when the server-held mandate or the charge history is missing (the policy decision is never skipped).
    public static func verifyPcaBinding(_ i: VerifyPcaBindingInput, decide: @escaping PCAPayments.Decide) throws -> JSONValue {
        guard case .object? = i.mandate else {
            throw PcaBindingError(code: "mandate_required", message: "verifyPcaBinding needs the server-held PCA mandate (its live budget); the policy decision is never skipped")
        }
        let maxTxM = try P.prop(try P.prop(i.mandate, "terms"), "maxTransactionsPerPeriod")
        if maxTxM != nil {
            guard case let .array(times)? = i.recentChargeTimes, times.allSatisfy({ P.isFinite($0) }) else {
                throw PcaBindingError(code: "charge_history_required", message: "the mandate limits the charge count: pass recentChargeTimes from your own records")
            }
        }
        func fail(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }
        do {
            let oc = try P.prop(i.open, "x_pca")
            let one = Int64(PCA_BINDING_VERSION)
            guard case let .object(ocO)? = oc, P.seq(get(ocO, "v"), .int(one)), case .object? = get(ocO, "grant"), case .object? = get(ocO, "terms") else {
                return fail("open mandate carries no x_pca grant")
            }
            let grant = get(ocO, "grant")!, terms = get(ocO, "terms")!
            if let why = Capability.verifyChain([grant], expectedRootIssuer: i.expectedPrincipal, pqPins: i.pqPins) { return fail("PCA grant: \(why)") }
            guard let env = PCA.readEnvelope(grant) else { return fail("PCA grant has no envelope") }
            let envPred = try P.hashStrict(env.get("predicates")), envCav = try P.hashStrict(env.get("caveats"))
            let termPred = try P.hashStrict(try PCAPayments.mandatePredicates(terms)), termCav = try P.hashStrict(try PCAPayments.mandateCaveats(terms))
            if envPred != termPred || envCav != termCav { return fail("x_pca terms do not match the grant envelope") }
            let rp = env.get("risk_policy")
            if try !P.seq(try P.prop(rp, "kappa"), try P.prop(terms, "perTransactionCap")) || !P.seq(try P.prop(rp, "bMax"), try P.prop(terms, "cumulativeCap")) {
                return fail("x_pca terms do not match the grant risk policy")
            }
            if let within = try constraintsWithinTerms(i.open, terms) { return fail(within) }

            let cc = try P.prop(i.closed, "x_pca")
            guard case let .object(ccO)? = cc, P.seq(get(ccO, "v"), .int(one)), case .object? = get(ccO, "pcactn"), case .object? = get(ccO, "charge") else {
                return fail("closed mandate carries no x_pca PCActn")
            }
            let pcactn = get(ccO, "pcactn")!, charge = get(ccO, "charge")
            let amt = try P.prop(i.closed, "payment_amount"), payee = try P.prop(i.closed, "payee")
            if try !P.seq(try P.prop(charge, "currency"), try P.prop(amt, "currency")) || !P.seq(try P.prop(charge, "amount"), try P.prop(amt, "amount")) {
                return fail("x_pca charge differs from the mandate payment_amount")
            }
            let cats = try P.prop(terms, "categories")
            let catLen = try P.length(cats)
            let category = try P.prop(charge, "category")
            if P.toNumber(catLen) > 0, category?.asString == nil || !includes(cats, category) { return fail("x_pca charge lacks an allowed category") }

            var enforcedT: Double?
            let now = i.now ?? Int64(P.nowMs())
            let core = PCA.verify(pcactn: pcactn, grant: grant, now: now, audience: i.audience, insecureSkipPlanRootCheck: true)
            if !core.allow { return fail("PCActn: \(core.reason.isEmpty ? "rejected" : core.reason)") }
            let hookCtx: JSONValue = .object(["pcactn": pcactn, "grant": grant, "nowEpoch": .int(now)])
            for (name, hook) in [("attestation", i.hooks?.attestation), ("threshold", i.hooks?.threshold), ("revocation", i.hooks?.revocation)] {
                guard let h = hook else { continue }
                let res = h(hookCtx)
                if name == "threshold", res.enforced, res.ok, let t = res.t, t.isFinite { enforcedT = t }
                if res.enforced && !res.ok { return fail("PCActn: \(name): \(res.reason ?? "rejected")") }
            }

            let action = try P.prop(pcactn, "action")
            if try !P.seq(try P.prop(action, "verb"), .string("charge")) || !P.seq(try P.prop(action, "resource"), .string("merchant:\(P.tostr(try P.prop(payee, "id")))")) {
                return fail("PCActn action is not a charge at this payee")
            }
            var params: JObject = [:]
            if let a = try P.prop(charge, "amount") { params["amount"] = a }
            if let c = try P.prop(charge, "currency") { params["currency"] = c }
            if let c = category, c.asString != nil { params["category"] = c }
            if params["amount"] == nil || params["currency"] == nil { throw JSError("canonical JSON cannot encode an undefined charge member") }
            if !P.seq(try P.prop(action, "params_digest"), .string(Merkle.paramsDigest(.object(params)))) { return fail("PCActn params do not commit to the x_pca charge") }
            let jwkV = try P.prop(try P.prop(i.open, "cnf"), "jwk")
            var facts: [(String, V)] = [("transactionId", try P.prop(i.closed, "transaction_id")), ("payeeId", try P.prop(payee, "id")), ("amount", try P.prop(amt, "amount")),
                                        ("currency", try P.prop(amt, "currency")), ("instrumentId", try P.prop(try P.prop(i.closed, "payment_instrument"), "id")), ("openHash", i.openHash)]
            facts.append(("agentJkt", .string(try jwkThumbprint(jwkV))))
            if facts.contains(where: { $0.1 == nil }) { throw JSError("canonical JSON cannot encode an undefined binding fact") }
            if !P.seq(try P.prop(pcactn, "nonce"), .string(try pcaBindingNonce(withoutNil(facts)))) {
                return fail("PCActn nonce does not bind this AP2 transaction, open mandate and agent key")
            }
            let perTx = try minorTerm(try P.prop(terms, "perTransactionCap"), "perTransactionCap")
            let chargeAmount = try P.prop(amt, "amount")
            if !(P.isFinite(chargeAmount) && jsLe(chargeAmount, perTx)) { return fail("payment exceeds the PCA per-transaction cap") }
            // The agent may not understate the risk of its own charge, and a charge whose risk needs a human co-sign (t > 1) is only accepted
            // when the verifier supplies a threshold verifier to check it.
            let recomputed = riskRatioRaw(try P.prop(amt, "amount"), try P.prop(terms, "perTransactionCap"))
            let recomputedClamped = riskRatioValue(recomputed)
            let claimedV = try P.prop(try P.prop(pcactn, "risk_claim"), "r")
            guard let claimed = P.numOf(claimedV), claimed >= recomputedClamped - 1e-9 else { return fail("PCActn understates the risk of this charge") }
            let theta1 = P.toNumber(try P.prop(rp, "theta1")), theta2 = P.toNumber(try P.prop(rp, "theta2"))
            let need = Risk.requiredThreshold(claimed, theta1: theta1, theta2: theta2).t
            if need > 1 && i.hooks?.threshold == nil { return fail("this charge needs a threshold of \(need) (human co-sign); supply hooks.threshold to verify it") }
            if need > 1 && !(enforcedT.map { $0 >= Double(need) } ?? false) {
                return fail("this charge needs a threshold of \(need) but the threshold hook enforced t=\(enforcedT.map { JS.toString(P.num($0)) } ?? "unreported"); build it with createThresholdVerifier({ t: \(need) })")
            }
            if try !P.seq(try P.prop(amt, "currency"), try P.prop(terms, "currency")) || !includes(try P.prop(terms, "merchants"), try P.prop(payee, "id")) {
                return fail("payment currency or payee is outside the PCA terms")
            }

            let heldGrant = try P.hashStrict(try P.prop(i.mandate, "grant")), openGrant = try P.hashStrict(grant)
            if heldGrant != openGrant { return fail("the supplied PCA mandate is not the one in the open mandate") }
            // `grant` was verified above under the caller-pinned principal; the decision is bound to it.
            var spend: JObject = [:]
            if let m = try P.prop(payee, "id") { spend["merchant"] = m }
            if let a = try P.prop(amt, "amount") { spend["amount"] = a }
            if let c = try P.prop(amt, "currency") { spend["currency"] = c }
            if let c = category, c.asString != nil { spend["category"] = c }
            spend["recentChargeTimes"] = i.recentChargeTimes ?? .array([])
            if let n = i.now { spend["now"] = .int(n) }
            let decision = try PCAPayments.authorizeCharge(i.mandate ?? .null, .object(spend), grant, decide: decide)
            let outcome = decision.get("outcome")?.asString
            if outcome == "deny" {
                let reasons = (decision.get("reasons")?.asArray ?? []).map { JS.toString($0) }
                return fail("PCA denies this charge: \(reasons.joined(separator: "; "))")
            }
            if outcome == "step_up" && !(enforcedT.map { $0 >= 2 } ?? false) {
                return fail("PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced")
            }
            return .object(["ok": .bool(true), "pcactn": pcactn, "grant": grant, "terms": terms])
        } catch { return fail(reasonOf(error)) }
    }
}
