import Foundation

/// Risk-priced escalation of the wallet: ask a human iff pBadUpper * loss > interruptionCost, in integer arithmetic (probabilities in
/// ppm, money in minor units; no floats, no randomness, no clock). Every input is explicit and comes from a principal-SIGNED
/// configuration; anything missing, out of range or unsigned means ASK. The only learned component is a per-principal multiplier that
/// scales P(bad) UP, so it can only add asks; asking less needs a principal-signed autonomy raise. A port of the TypeScript reference
/// (@atlasauth/pca-wallet, escalation-pricing). Signing needs the principal's 32-byte Ed25519 seed.
public enum PCAWalletPricing {
    public static let PPM = 1_000_000
    public static let MAX_MULTIPLIER_PPM = 100 * PPM

    /// A safe integer >= 0 (a minor-unit amount).
    static func isMinor(_ v: JSONValue?) -> Bool { IV.safe(v).map { $0 >= 0 } ?? false }

    static func msg(_ kind: String, _ body: JSONValue) throws -> [UInt8] {
        Canonical.utf8(try WJ.hash(WJ.obj([("kind", .string(kind)), ("body", body)])))
    }

    static func sig(_ seed: [UInt8], _ kind: String, _ body: JSONValue) throws -> String {
        Base64URLStrict.encode(Ed25519Deterministic.sign(seed: seed, try msg(kind, body)))
    }

    /// `verify(decodeKey(principal), msg, decodeKey(sig))`: a key or signature that is not canonical base64url throws (malformed).
    static func verify(_ principal: String, _ kind: String, _ body: JSONValue, _ sig: String) throws -> Bool {
        let m = try msg(kind, body)
        guard let pk = Base64URLStrict.decode(principal), let sg = Base64URLStrict.decode(sig) else { throw JSError("bad base64url") }
        return Ed25519Strict.verify(publicKey: pk, message: m, signature: sg)
    }

    static func without(_ o: JObject, _ k: String) -> JSONValue {
        var b = o
        b[JKey(k)] = nil
        return .object(b)
    }

    static func signed(_ body: JSONValue?, _ seed: [UInt8], _ kind: String) throws -> JSONValue {
        guard case var .object(o)? = body else { throw JSError("not an object") }
        o["sig"] = .string(try sig(seed, kind, body!))
        return .object(o)
    }

    public static func signPricingConfig(_ body: JSONValue?, seed: [UInt8]) throws -> JSONValue { try signed(body, seed, "pca.escalation_pricing") }

    /// Why a signed pricing configuration is refused, or nil (a pure function of its content).
    public static func pricingConfigError(_ c: JSONValue?) -> String? {
        guard case let .object(x)? = c else { return "config_malformed" }
        guard WJ.numEq(x["v"], 1), let principal = x["principal"]?.asString, x["currency"]?.asString != nil, let sg = x["sig"]?.asString else { return "config_malformed" }
        guard isMinor(x["interruptionCost"]), isMinor(x["maxInterruptionCost"]), isMinor(x["hardCeilingLoss"]), isMinor(x["epoch"]) else { return "config_amounts_invalid" }
        if IV.num(x["interruptionCost"])! > IV.num(x["maxInterruptionCost"])! { return "config_cost_above_max" }
        guard let step = IV.safe(x["tightenStepPpm"]), step >= 0, step <= Double(MAX_MULTIPLIER_PPM) else { return "config_step_invalid" }
        do { return try verify(principal, "pca.escalation_pricing", without(x, "sig"), sg) ? nil : "config_signature_invalid" } catch { return "config_malformed" }
    }

    public static func freshCalibration() -> JSONValue { WJ.obj([("multiplierPpm", WJ.i(PPM)), ("seen", .array([]))]) }

    static func decision(_ ask: Bool, _ reason: String) -> JSONValue { WJ.obj([("ask", .bool(ask)), ("reason", .string(reason))]) }

    /// Pure and total: {ask, reason}. Anything unverifiable or out of range asks.
    public static func decideEscalation(_ config: JSONValue?, _ cal: JSONValue?, _ a: JSONValue?) -> JSONValue {
        if let e = pricingConfigError(config) { return decision(true, e) }
        guard let a = a, a.isObject || a.isArray, let cfg = config?.asObject, IV.same(a.get("currency")?.asString, cfg["currency"]?.asString) else {
            return decision(true, "currency_mismatch")
        }
        guard isMinor(a.get("loss")), !WJ.negZero(a.get("loss")), let p = IV.safe(a.get("pBadUpperPpm")), p >= 0, !IV.isNegZero(p), p <= Double(PPM) else {
            return decision(true, "risk_input_invalid")
        }
        guard let mult = IV.safe(cal?.get("multiplierPpm")), mult >= Double(PPM), mult <= Double(MAX_MULTIPLIER_PPM) else { return decision(true, "calibration_invalid") }
        let loss = IV.num(a.get("loss"))!
        if loss > IV.num(cfg["hardCeilingLoss"])! { return decision(true, "above_hard_ceiling") }
        let pe = BigUInt(UInt64(p)) * BigUInt(UInt64(mult))
        let cap = BigUInt(UInt64(PPM)) * BigUInt(UInt64(PPM))
        let capped = cap < pe ? cap : pe
        let lhs = capped * BigUInt(UInt64(loss))
        let rhs = BigUInt(UInt64(IV.num(cfg["interruptionCost"])!)) * cap
        return rhs < lhs ? decision(true, "expected_loss_exceeds_interruption_cost") : decision(false, "expected_loss_within_interruption_cost")
    }

    public static func signAnswer(_ body: JSONValue?, seed: [UInt8]) throws -> JSONValue { try signed(body, seed, "pca.escalation_answer") }

    static func answerOk(_ a: JSONValue?, _ principal: String) -> Bool {
        guard case let .object(o)? = a, WJ.numEq(o["v"], 1), IV.same(o["principal"]?.asString, principal), let nonce = o["nonce"]?.asString, nonce.utf16.count >= 8,
              o["action_digest"]?.asString != nil, WJ.isStr(o["answer"], "approve") || WJ.isStr(o["answer"], "deny"), let sg = o["sig"]?.asString else { return false }
        return (try? verify(principal, "pca.escalation_answer", without(o, "sig"), sg)) ?? false
    }

    /// Fold signed answers into the calibration. A DENY the principal gave to an action that the CURRENT pricing would have
    /// auto-approved is a miss and adds `tightenStepPpm` (capped); anything else changes nothing. The multiplier never decreases.
    /// `risks` maps an action digest to its risk.
    public static func updateCalibration(_ config: JSONValue?, _ cal: JSONValue?, _ answers: JSONValue?, _ risks: JSONValue?) throws -> JSONValue {
        if pricingConfigError(config) != nil { return cal ?? .null }
        guard let cfg = config?.asObject, let principal = cfg["principal"]?.asString else { throw JSError("config") }
        guard var mult = IV.num(cal?.get("multiplierPpm")) else { throw JSError("Cannot read properties of undefined (reading 'multiplierPpm')") }
        let start = mult
        var seen = Set<JKey>()
        var order: [JSONValue] = []
        for s in try seenList(cal?.get("seen")) { seen.insert(JKey(s.asString ?? "")); order.append(s) }
        for a in try JS.spread(answers) {
            guard answerOk(a, principal), let nonce = a.get("nonce")?.asString, !seen.contains(JKey(nonce)) else { continue }
            seen.insert(JKey(nonce))
            order.append(.string(nonce))
            guard WJ.isStr(a.get("answer"), "deny"), let digest = a.get("action_digest")?.asString, let risk = risks?.get(digest) else { continue }
            let probe = WJ.obj([("multiplierPpm", .double(mult)), ("seen", .array([]))])
            if decideEscalation(config, probe, risk).get("ask") == .bool(false) {
                mult = min(Double(MAX_MULTIPLIER_PPM), mult + (IV.num(cfg["tightenStepPpm"]) ?? .nan))
            }
        }
        return WJ.obj([("multiplierPpm", .double(max(mult, start))), ("seen", .array(order))])
    }

    static func seenList(_ v: JSONValue?) throws -> [JSONValue] {
        guard let v = v else { throw JSError("cal.seen is not iterable") }
        return try JS.spread(v)
    }

    public static func signAutonomyRaise(_ body: JSONValue?, seed: [UInt8]) throws -> JSONValue { try signed(body, seed, "pca.autonomy_raise") }

    /// A higher interruption cost means fewer asks. Needs the principal's signature, a strictly newer epoch and a cost within
    /// `maxInterruptionCost`; throws otherwise.
    public static func applyAutonomyRaise(_ config: JSONValue?, _ raise: JSONValue?, seed: [UInt8]) throws -> JSONValue {
        guard case let .object(r)? = raise else { throw JSError("Cannot destructure undefined") }
        guard case let .object(cfg)? = config else { throw JSError("Cannot read properties of undefined (reading 'principal')") }
        var ok = false
        if WJ.numEq(r["v"], 1), IV.same(r["principal"]?.asString, cfg["principal"]?.asString), let p = cfg["principal"]?.asString, let sg = r["sig"]?.asString {
            ok = (try? verify(p, "pca.autonomy_raise", without(r, "sig"), sg)) ?? false
        }
        if !ok { throw JSError("applyAutonomyRaise: signature or principal invalid") }
        guard let re = IV.num(r["epoch"]), let ce = IV.num(cfg["epoch"]), re > ce else { throw JSError("applyAutonomyRaise: epoch must advance") }
        guard isMinor(r["newInterruptionCost"]), let cost = IV.num(r["newInterruptionCost"]), let mx = IV.num(cfg["maxInterruptionCost"]), cost <= mx else {
            throw JSError("applyAutonomyRaise: above the configured maximum")
        }
        guard case var .object(body) = without(cfg, "sig") else { throw JSError("config") }
        body["interruptionCost"] = r["newInterruptionCost"]!
        body["epoch"] = r["epoch"]!
        return try signed(.object(body), seed, "pca.escalation_pricing")
    }
}
