import Foundation

/// K4 (verification side): risk-priced escalation (pricing config, decision, calibration from signed answers), the network-token
/// binding and the ERC-7715 granted-permission check. Replays packages/pca/conformance/k4-vectors.json.
/// Signatures are Ed25519 (strict) over the UTF-8 bytes of hashCanonical({"kind": kind, "body": body}) (the digest string); body is the
/// signed object without its `sig`. Escalation is integer-only (64x64-bit full-width products). Total: never traps.
public enum K4 {
    public static let PPM: Int64 = 1_000_000
    public static let MAX_MULTIPLIER_PPM: Int64 = 100 * PPM
    public static let BINDING_KIND = "pca.network_token_binding"

    private static func int(_ v: JSONValue?) -> Int64? { IV.safe(v).map { Int64($0) } }
    private static func minor(_ v: JSONValue?) -> Int64? { K3Sig.safeInt(v) }
    private static func isHex(_ s: Substring) -> Bool { !s.isEmpty && s.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102) } }

    /// nil when the key or signature does not decode; else the strict verification result.
    private static func sigOk(_ pub: String?, _ kind: String, _ o: JObject) -> Bool? {
        guard let pub = pub, let sig = o[JKey("sig")]?.asString, Base64URLStrict.decode(pub) != nil, Base64URLStrict.decode(sig) != nil,
              let digest = IV.strictHash(.object([JKey("kind"): .string(kind), JKey("body"): .object(K3Sig.without(o, "sig"))])) else { return nil }
        return Ed25519Strict.verifyB64u(pub, Array(digest.utf8), sig)
    }

    // ---- network-token binding ----

    private static func luhn(_ d: [UInt8]) -> Bool {
        var sum = 0
        var dbl = false
        for c in d.reversed() {
            var n = Int(c) - 48
            if dbl { n *= 2; if n > 9 { n -= 9 } }
            sum += n
            dbl.toggle()
        }
        return sum % 10 == 0
    }

    /// A maximal digit run (spaces and hyphens removed) of 13..19 digits that passes Luhn.
    public static func looksLikePan(_ s: String) -> Bool {
        var run: [UInt8] = []
        func check() -> Bool { (13...19).contains(run.count) && luhn(run) }
        for u in s.utf8 where !(u == 45 || u == 32 || (u >= 9 && u <= 13)) {
            if u >= 48 && u <= 57 { run.append(u) } else { if check() { return true }; run = [] }
        }
        return check()
    }

    public static func tokenRefError(_ ref: JSONValue?) -> String? {
        guard let s = ref?.asString, (8...128).contains(s.utf8.count),
              s.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 95 || $0 == 46 || $0 == 58 || $0 == 45 }) else { return "token_ref_malformed" }
        return looksLikePan(s) ? "token_ref_looks_like_pan" : nil
    }

    /// nil = valid, else the reason. provider nil = any.
    public static func verifyBinding(_ bo: JSONValue?, grant: JSONValue, holder: String, issuerNonce: String, provider: String?) -> String? {
        guard let b = bo?.asObject, b[JKey("kind")]?.asString == BINDING_KIND else { return "binding_malformed" }
        if let e = tokenRefError(b[JKey("token_ref")]) { return e }
        guard let p = b[JKey("provider")]?.asString, !p.isEmpty, provider == nil || IV.same(p, provider!) else { return "provider_mismatch" }
        guard let gd = IV.strictHash(grant), b[JKey("grant_digest")]?.asString == gd else { return "grant_digest_mismatch" }
        if b[JKey("holder")]?.asString != holder { return "holder_mismatch" }
        if b[JKey("issuer_nonce")]?.asString != issuerNonce { return "issuer_nonce_mismatch" }
        guard Base64URLStrict.decode(holder) != nil, let proof = b[JKey("binding_proof")]?.asString, Base64URLStrict.decode(proof) != nil else { return "binding_malformed" }
        let body: JSONValue = .object([JKey("kind"): .string(BINDING_KIND), JKey("v"): .int(1), JKey("provider"): .string(p), JKey("token_ref"): b[JKey("token_ref")]!,
                                       JKey("grant_digest"): b[JKey("grant_digest")]!, JKey("issuer_nonce"): b[JKey("issuer_nonce")]!, JKey("holder"): b[JKey("holder")]!])
        guard let digest = IV.strictHash(body) else { return "binding_malformed" }
        return Ed25519Strict.verifyB64u(holder, Array(digest.utf8), proof) ? nil : "binding_proof_invalid"
    }

    // ---- risk-priced escalation ----

    public static func pricingConfigError(_ co: JSONValue?) -> String? {
        guard let c = co?.asObject, c[JKey("v")]?.safeInt == 1, c[JKey("principal")]?.asString != nil, c[JKey("currency")]?.asString != nil, c[JKey("sig")]?.asString != nil else { return "config_malformed" }
        guard let cost = minor(c[JKey("interruptionCost")]), let mx = minor(c[JKey("maxInterruptionCost")]), minor(c[JKey("hardCeilingLoss")]) != nil, minor(c[JKey("epoch")]) != nil else { return "config_amounts_invalid" }
        if cost > mx { return "config_cost_above_max" }
        guard let st = int(c[JKey("tightenStepPpm")]), st >= 0, st <= MAX_MULTIPLIER_PPM else { return "config_step_invalid" }
        guard let r = sigOk(c[JKey("principal")]?.asString, "pca.escalation_pricing", c) else { return "config_malformed" }
        return r ? nil : "config_signature_invalid"
    }

    public struct Verdict: Equatable { public let ask: Bool; public let reason: String }
    private static func ask(_ r: String) -> Verdict { Verdict(ask: true, reason: r) }

    /// Ask a person iff min(p * multiplier, 1e12) * loss > interruptionCost * 1e12; anything unexpected asks.
    public static func decide(config: JSONValue?, calibration cal: JSONValue?, risk ao: JSONValue?) -> Verdict {
        if let e = pricingConfigError(config) { return ask(e) }
        let cfg = config!.asObject!
        guard let a = ao?.asObject, a[JKey("currency")]?.asString == cfg[JKey("currency")]?.asString else { return ask("currency_mismatch") }
        guard let loss = minor(a[JKey("loss")]), let p = int(a[JKey("pBadUpperPpm")]), p >= 0, p <= PPM else { return ask("risk_input_invalid") }
        guard let m = int(cal?.get("multiplierPpm")), m >= PPM, m <= MAX_MULTIPLIER_PPM else { return ask("calibration_invalid") }
        if loss > (minor(cfg[JKey("hardCeilingLoss")]) ?? 0) { return ask("above_hard_ceiling") }
        let one = UInt64(PPM) * UInt64(PPM)
        let capped = min(UInt64(p) * UInt64(m), one)
        let lhs = capped.multipliedFullWidth(by: UInt64(loss))
        let rhs = one.multipliedFullWidth(by: UInt64(minor(cfg[JKey("interruptionCost")]) ?? 0))
        let greater = lhs.high != rhs.high ? lhs.high > rhs.high : lhs.low > rhs.low
        return greater ? ask("expected_loss_exceeds_interruption_cost") : Verdict(ask: false, reason: "expected_loss_within_interruption_cost")
    }

    private static func answerOk(_ ao: JSONValue, _ principal: String) -> Bool {
        guard let a = ao.asObject, a[JKey("v")]?.safeInt == 1, a[JKey("principal")]?.asString == principal,
              let n = a[JKey("nonce")]?.asString, IV.u16(n) >= 8, a[JKey("action_digest")]?.asString != nil,
              let ans = a[JKey("answer")]?.asString, ans == "approve" || ans == "deny" else { return false }
        return sigOk(principal, "pca.escalation_answer", a) == true
    }

    /// Fold principal-signed answers into the calibration; the multiplier can only rise. risks: action digest to risk object.
    public static func updateCalibration(config: JSONValue?, mult startMult: Int64, seen startSeen: [String], answers: [JSONValue], risks: [String: JSONValue]) -> (multiplierPpm: Int64, seen: [String]) {
        var order = startSeen
        if pricingConfigError(config) != nil { return (startMult, order) }
        let cfg = config!.asObject!
        let principal = cfg[JKey("principal")]!.asString!
        let step = int(cfg[JKey("tightenStepPpm")]) ?? 0
        var mult = startMult
        for ao in answers {
            guard answerOk(ao, principal), let a = ao.asObject, let nonce = a[JKey("nonce")]?.asString, !order.contains(nonce) else { continue }
            order.append(nonce)
            guard a[JKey("answer")]?.asString == "deny", let digest = a[JKey("action_digest")]?.asString, let risk = risks[digest] else { continue }
            if !decide(config: config, calibration: .object([JKey("multiplierPpm"): .int(mult)]), risk: risk).ask { mult = min(MAX_MULTIPLIER_PPM, mult + step) }
        }
        return (max(mult, startMult), order)
    }

    // ---- ERC-7715 granted-permission check ----

    private static func lower(_ v: JSONValue?) -> String { v?.asString.map { $0.lowercased() } ?? "\u{0}" }

    /// Numeric compare of normalised hex quantities (no leading zeros): longer is larger, else lexicographic.
    private static func hexGreater(_ a: Substring, _ b: Substring) -> Bool {
        let (x, y) = (a.lowercased(), b.lowercased())
        return x.count != y.count ? x.count > y.count : x > y
    }

    /// nil when what the wallet granted is within the request and the grant. g = {grantDigest, expiresAtSec}.
    public static func verifyGranted(g: JSONValue, sent: JSONValue, got: JSONValue?, allowedManagers: [String], contextOwner: ((String) -> String?)?) -> String? {
        guard let r = got?.asObject, let perm = r[JKey("permission")]?.asObject else { return "response_malformed" }
        guard let ctx = r[JKey("context")]?.asString, ctx.hasPrefix("0x"), isHex(ctx.dropFirst(2)) else { return "context_malformed" }
        if let owner = contextOwner?(ctx), owner != g.get("grantDigest")?.asString { return "context_bound_to_other_grant" }
        guard let m = r[JKey("delegationManager")]?.asString, m.hasPrefix("0x"), m.utf8.count == 42, isHex(m.dropFirst(2)),
              allowedManagers.contains(where: { $0.lowercased() == m.lowercased() }) else { return "delegation_manager_not_allowed" }
        if lower(r[JKey("chainId")]) != lower(sent.get("chainId")) { return "chain_mismatch" }
        if lower(r[JKey("to")]) != lower(sent.get("to")) { return "recipient_mismatch" }
        if let f = sent.get("from"), !f.isNull, lower(r[JKey("from")]) != lower(f) { return "from_mismatch" }
        guard let sperm = sent.get("permission") else { return "response_malformed" }
        guard let pt = perm[JKey("type")]?.asString, pt == sperm.get("type")?.asString, pt == "native-token-allowance" || pt == "erc20-token-allowance" else { return "permission_type_mismatch" }
        guard let d = perm[JKey("data")]?.asObject else { return "response_malformed" }
        let sd = sperm.get("data")
        if (d[JKey("tokenAddress")]?.asString?.lowercased() ?? "") != (sd?.get("tokenAddress")?.asString?.lowercased() ?? "") { return "token_mismatch" }
        guard let al = d[JKey("allowance")]?.asString, al.hasPrefix("0x"), isHex(al.dropFirst(2)),
              al.dropFirst(2) == "0" || !al.dropFirst(2).hasPrefix("0") else { return "amount_malformed" }
        if hexGreater(al.dropFirst(2), (sd?.get("allowance")?.asString ?? "0x0").dropFirst(2)) { return "amount_widened" }
        if perm[JKey("isAdjustmentAllowed")] != sperm.get("isAdjustmentAllowed"), perm[JKey("isAdjustmentAllowed")] == .bool(true) { return "adjustment_widened" }
        guard let rules = r[JKey("rules")]?.asArray else { return "expiry_missing" }
        var expiry: Int64?
        for rule in rules {
            guard rule.get("type")?.asString == "expiry" else { return "unknown_rule_type" }
            if expiry != nil { return "duplicate_expiry" }
            guard let ts = int(rule.get("data")?.get("timestamp")) else { return "expiry_malformed" }
            expiry = ts
        }
        guard let e = expiry else { return "expiry_missing" }
        return e > (int(g.get("expiresAtSec")) ?? 0) ? "expiry_extended" : nil
    }
}
