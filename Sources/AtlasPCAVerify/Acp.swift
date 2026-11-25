import Foundation

/// The Agentic Commerce Protocol (ACP) and x402 for PCA: one-time delegated payment tokens minted FROM a PCActn (the proof's spend cap,
/// merchant and category allowlists and human-present requirement gate issuance), their settlement-time verification, the x402 v1
/// challenge, the injectable settle flow and the ACP `allowance`. x402 v2, its HTTP transport and Stripe Shared Payment Granted Tokens
/// are in `AcpX402.swift`. No network is performed: the verifier, the settle step and the single-use store are injected.
///
/// Values are the reference's JSON shapes and inputs follow JavaScript value semantics (a property read on null is a TypeError,
/// `x ?? default`, `String(x)`), so a hostile input reaches the same verdict as the reference. A token is a compact EdDSA JWS; the
/// signing and verification keys are Ed25519 JWKs (other algorithms are refused). The members of an object written to the wire
/// (claims, headers, x402 bodies) follow the reference's member order.
public enum PCAAcp {
    typealias V = JSONValue?
    typealias P = PayJS

    public static let ACP_DELEGATED_TOKEN_VERSION = 1
    public static let ACP_DELEGATED_TOKEN_TYPE = "acp-delegated-payment"
    public static let SPEND_CAP_CAVEAT = "max_amount"
    public static let MERCHANT_ALLOW_CAVEAT = "merchant_allow"
    public static let MERCHANT_CATEGORY_CAVEAT = "merchant_category"
    public static let HUMAN_PRESENT_CAVEAT = "human_present"
    public static let X402_VERSION_1 = 1
    public static let X402_VERSION_2 = 2
    public static let X402_SUPPORTED_VERSIONS: [Int] = [2, 1]
    public static let X402_V2_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
    public static let X402_PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
    public static let X402_PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"
    public static let X402_HTTP_STATUS: [String: Int] = ["payment_required": 402, "malformed": 400, "failed": 402, "internal_error": 500, "settled": 200]
    public static let STRIPE_SPT_OBJECT = "shared_payment.granted_token"

    /// The member order of every object this module writes as JSON (the reference's source order): claims, JWS header, x402 bodies.
    static let ORDER: [String] = [
        "alg", "typ", "kid", "ver", "jti", "session", "merchant", "success", "errorReason", "transaction", "scheme", "network", "payer", "amount",
        "asset", "payTo", "maxTimeoutSeconds", "extra", "currency", "iat", "exp", "paymentMethod", "humanPresent", "category", "iss", "pca",
        "type", "display", "token", "digest", "aud", "grant_ref", "leaf_holder", "verb", "x402Version", "error", "resource", "params_digest",
        "accepts", "accepted", "payload", "extensions", "url", "description", "mimeType", "serviceName", "tags", "iconUrl",
    ]

    /// A refusal because the request exceeds the proof's authority (or the input is malformed).
    static func authErr(_ m: String) -> JSError { JSError(m, code: "AcpAuthorityError") }

    // ---- small JS helpers ----

    static func isObj(_ v: V) -> Bool { v?.isObject ?? false }
    static func isBool(_ v: V) -> Bool {
        guard let x = v else { return false }
        if case .bool = x { return true }
        return false
    }
    static func nonEmptyStr(_ v: V) -> Bool { v?.asString?.isEmpty == false }
    /// Integer minor units: floats, NaN, zero, negatives and unsafe integers are refused.
    static func isAmount(_ v: V) -> Bool { P.safeInt(v) && (P.numOf(v) ?? 0) > 0 }
    /// A safe integer that is not -0.
    static func isInt(_ v: V) -> Bool {
        guard P.safeInt(v), let d = P.numOf(v) else { return false }
        return !(d == 0 && d.sign == .minus)
    }
    static func no(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }

    /// `String.prototype.includes` over UTF-16 code units.
    static func strContains(_ s: String, _ sub: String) -> Bool {
        let a = Array(s.utf16), b = Array(sub.utf16)
        if b.isEmpty { return true }
        if b.count > a.count { return false }
        for i in 0...(a.count - b.count) where a[i] == b[0] {
            if Array(a[i..<(i + b.count)]) == b { return true }
        }
        return false
    }

    /// `coll.includes(item)`: an array (SameValueZero) or a string (substring of String(item)); anything else is a TypeError.
    static func includes(_ coll: V, _ item: V) throws -> Bool {
        switch coll {
        case let .array(a)?: return a.contains { P.seq($0, item) }
        case let .string(s)?: return strContains(s, P.tostr(item))
        default: throw JSError("includes is not a function")
        }
    }

    static func dedupe(_ l: [JSONValue]) -> [JSONValue] {
        var out: [JSONValue] = []
        for x in l where !out.contains(x) { out.append(x) }
        return out
    }

    // ---- caveat vocabulary ----

    public static func spendCapCaveat(_ max: JSONValue?, _ currency: JSONValue? = nil) -> JSONValue {
        var o: JObject = ["type": .string(SPEND_CAP_CAVEAT)]
        if let m = max { o["max"] = m }
        if let c = currency { o["currency"] = c }
        return .object(o)
    }

    public static func merchantAllowCaveat(_ merchants: JSONValue?) throws -> JSONValue {
        .object(["type": .string(MERCHANT_ALLOW_CAVEAT), "merchants": .array(try P.spreadArr(merchants))])
    }

    public static func merchantCategoryCaveat(_ categories: JSONValue?) throws -> JSONValue {
        .object(["type": .string(MERCHANT_CATEGORY_CAVEAT), "categories": .array(try P.spreadArr(categories))])
    }

    /// `humanPresentCaveat(required = true)`.
    public static func humanPresentCaveat(_ required: JSONValue? = nil) -> JSONValue {
        .object(["type": .string(HUMAN_PRESENT_CAVEAT), "required": required ?? .bool(true)])
    }

    static func stringArray(_ v: V, _ label: String) throws -> [JSONValue] {
        guard let a = v?.asArray, a.allSatisfy({ $0.asString != nil }) else { throw authErr("malformed \(label) caveat: expected a string[] (fail closed)") }
        return a
    }

    /// Collapse a leaf capability's cumulative caveats into its effective payment authority: the tightest cap, intersected allowlists, a
    /// sticky human-present requirement. A malformed PAYMENT caveat throws (fail closed); other caveat types are ignored.
    public static func extractPaymentAuthority(_ caveats: JSONValue?) throws -> JSONValue {
        let items: [JSONValue]
        switch caveats {
        case let .array(a)?: items = a
        case let .string(s)?: items = s.unicodeScalars.map { JSONValue.string(String($0)) }
        default: throw JSError("caveats is not iterable")
        }
        var maxAmount: JSONValue? = nil
        var currency: JSONValue? = nil
        var merchants: [JSONValue]? = nil
        var categories: [JSONValue]? = nil
        var human = false
        for c in items {
            guard let t = try P.prop(c, "type")?.asString else { continue }
            if t == SPEND_CAP_CAVEAT {
                let mx = try P.prop(c, "max")
                guard P.safeInt(mx), let m = P.numOf(mx), m >= 0, !(m == 0 && m.sign == .minus) else {
                    throw authErr("malformed max_amount caveat: max must be an integer >= 0 in minor units (fail closed)")
                }
                if let have = maxAmount, let hm = P.numOf(have) { if m < hm { maxAmount = mx } } else { maxAmount = mx }
                if let cur = try P.prop(c, "currency") {
                    guard let cs = cur.asString, !cs.isEmpty else { throw authErr("malformed max_amount caveat: currency must be a non-empty string (fail closed)") }
                    if let have = currency, have != cur { throw authErr("conflicting spend-cap currencies \"\(P.tostr(have))\" vs \"\(cs)\" (fail closed)") }
                    currency = cur
                }
            } else if t == MERCHANT_ALLOW_CAVEAT {
                let list = try stringArray(try P.prop(c, "merchants"), "merchant_allow")
                if let cur = merchants { merchants = cur.filter { list.contains($0) } } else { merchants = dedupe(list) }
            } else if t == MERCHANT_CATEGORY_CAVEAT {
                let list = try stringArray(try P.prop(c, "categories"), "merchant_category")
                if let cur = categories { categories = cur.filter { list.contains($0) } } else { categories = dedupe(list) }
            } else if t == HUMAN_PRESENT_CAVEAT {
                guard case let .bool(b)? = try P.prop(c, "required") else { throw authErr("malformed human_present caveat: required must be a boolean (fail closed)") }
                human = human || b
            }
        }
        var out: JObject = [:]
        if let m = maxAmount { out["maxAmount"] = m }
        if let c = currency { out["currency"] = c }
        out["merchants"] = merchants.map { JSONValue.array($0) } ?? JSONValue.null
        out["categories"] = categories.map { JSONValue.array($0) } ?? JSONValue.null
        out["humanPresentRequired"] = .bool(human)
        return .object(out)
    }

    /// Check a concrete purchase request against a payment authority. Pure and fail-closed.
    public static func checkPaymentAuthority(_ authority: JSONValue?, _ request: JSONValue?) throws -> JSONValue {
        let amount = try P.prop(request, "amount")
        let currency = try P.prop(request, "currency")
        let merchant = try P.prop(request, "merchant")
        if !isAmount(amount) { return no("amount must be a positive integer in minor units") }
        guard let cur = currency?.asString, !cur.isEmpty else { return no("currency must be a non-empty string") }
        guard let mer = merchant?.asString, !mer.isEmpty else { return no("merchant must be a non-empty string") }
        _ = mer
        if let ac = try P.prop(authority, "currency"), !P.seq(ac, currency) {
            return no("currency \"\(cur)\" is not the authorized currency \"\(P.tostr(ac))\"")
        }
        let capV = try P.prop(authority, "maxAmount")
        if let cap = capV {
            // a present cap must be a non-negative safe integer; absent is the way to say unbounded
            guard let c = P.numOf(cap), P.safeF(c), c >= 0, !IV.isNegZero(c) else { return no("authorized spend cap is not a non-negative integer (fail closed)") }
        }
        if let cap = capV, P.jsGt(amount, cap) || P.numOf(cap)?.isNaN == true {
            return no("amount \(P.tostr(amount)) exceeds the authorized spend cap \(P.tostr(cap))")
        }
        let ms = try P.prop(authority, "merchants")
        if ms != .null {
            if !(try includes(ms, merchant)) { return no("merchant \"\(mer)\" is not in the authorized allowlist") }
        }
        let cs = try P.prop(authority, "categories")
        if cs != .null {
            let category = try P.prop(request, "category")
            if category == nil { return no("the proof constrains merchant categories but no category was supplied") }
            if !(try includes(cs, category)) { return no("category \"\(P.tostr(category))\" is not in the authorized allowlist") }
        }
        if JS.truthy(try P.prop(authority, "humanPresentRequired")), try P.prop(request, "humanPresent") != .bool(true) {
            return no("the proof requires a human-present charge but humanPresent was not asserted")
        }
        return .object(["ok": .bool(true)])
    }

    // ---- delegated payment token ----

    /// The leaf (acting) capability of a proof's chain.
    static func leaf(_ pca: V) throws -> JSONValue {
        guard case let .array(chain)? = try P.prop(pca, "cap_chain"), !chain.isEmpty else { throw authErr("PCActn carries no capability chain (fail closed)") }
        return chain[chain.count - 1]
    }

    /// How a token points back at the PCActn that authorized it: the digest and the proof's audience, grant, leaf holder and action.
    static func authorityRef(_ pca: V) throws -> JObject {
        let lf = try leaf(pca)
        var r: JObject = [:]
        r["digest"] = .string(try P.hashStrict(pca))
        let aud = try P.prop(pca, "aud"), grant = try P.prop(pca, "grant_ref"), holder = try P.prop(lf, "holder")
        let action = try P.prop(pca, "action")
        let verb = try P.prop(action, "verb"), resource = try P.prop(action, "resource"), pd = try P.prop(action, "params_digest")
        if let v = aud { r["aud"] = v }
        if let v = grant { r["grant_ref"] = v }
        if let v = holder { r["leaf_holder"] = v }
        if let v = verb { r["verb"] = v }
        if let v = resource { r["resource"] = v }
        if let v = pd { r["params_digest"] = v }
        return r
    }

    /// Mint a one-time ACP delegated payment token (a compact EdDSA JWS) FROM a PCActn, bound to session, merchant, amount, currency and
    /// expiry, carrying the proof's authority BY REFERENCE (`pca.digest`). The proof's caveats gate issuance: an over-authority request,
    /// an expiry in the past or one that would outlive the proof throws. `opts`: amount, currency, merchant, session, expiresAt,
    /// paymentMethod, signingKey (a private Ed25519 JWK), alg ("EdDSA"), category, humanPresent, issuer, kid, jti, now.
    public static func mintDelegatedPaymentToken(_ pca: JSONValue?, _ opts: JSONValue?) throws -> String {
        let nowOpt = try P.prop(opts, "now")
        let now: Double = P.isFinite(nowOpt) ? (P.numOf(nowOpt) ?? 0) : P.nowMs()
        let nowJSON: JSONValue = P.isFinite(nowOpt) ? (nowOpt ?? .null) : P.num(now)

        let authority = try extractPaymentAuthority(try P.prop(try leaf(pca), "caveats"))
        var req: JObject = [:]
        for k in ["amount", "currency", "merchant", "category", "humanPresent"] {
            if let v = try P.prop(opts, k) { req[JKey(k)] = v }
        }
        let check = try checkPaymentAuthority(authority, .object(req))
        if check.get("ok") != .bool(true) { throw authErr("refused: \(check.get("reason")?.asString ?? "request exceeds the proof authority")") }

        let expV = try P.prop(opts, "expiresAt")
        guard P.isFinite(expV), let exp = P.numOf(expV) else { throw authErr("refused: expiresAt must be a finite epoch-ms timestamp") }
        if exp <= now { throw authErr("refused: expiresAt is not in the future") }
        let proofExp = try P.prop(pca, "exp")
        if !P.isFinite(proofExp) || P.jsGt(expV, proofExp) { throw authErr("refused: token expiry \(P.tostr(expV)) would outlive the proof's exp \(P.tostr(proofExp))") }
        let session = try P.prop(opts, "session")
        if !JS.truthy(session) { throw authErr("refused: a session id is required") }

        let ref = try authorityRef(pca)
        let merchant = try P.prop(opts, "merchant"), amount = try P.prop(opts, "amount"), currency = try P.prop(opts, "currency")
        var jti: JSONValue
        if let j = JS.present(try P.prop(opts, "jti")) {
            jti = j
        } else {
            var seed = P.spreadObj(pca)
            let digest = ref["digest"]?.asString ?? ""
            seed["nonce"] = .string("acp:\(P.tostr(session)):\(P.tostr(merchant)):\(P.tostr(amount)):\(P.tostr(currency)):\(P.tostr(expV)):\(digest)")
            jti = .string(try P.hashStrict(JSONValue.object(seed)))
        }

        var claims: JObject = ["typ": .string(ACP_DELEGATED_TOKEN_TYPE), "ver": .int(Int64(ACP_DELEGATED_TOKEN_VERSION)), "jti": jti]
        if let v = session { claims["session"] = v }
        if let v = merchant { claims["merchant"] = v }
        if let v = amount { claims["amount"] = v }
        if let v = currency { claims["currency"] = v }
        claims["iat"] = nowJSON
        claims["exp"] = expV ?? .null
        claims["paymentMethod"] = .object(P.spreadObj(try P.prop(opts, "paymentMethod")))
        claims["humanPresent"] = .bool(try P.prop(opts, "humanPresent") == .bool(true))
        if let v = try P.prop(opts, "category") { claims["category"] = v }
        if let v = try P.prop(opts, "issuer") { claims["iss"] = v }
        claims["pca"] = .object(ref)

        // the signing key: a private Ed25519 JWK ('kty' in key); anything else is not a usable key
        let algV = JS.present(try P.prop(opts, "alg")) ?? .string("EdDSA")
        guard let jwk = try P.prop(opts, "signingKey")?.asObject, jwk["kty"] != nil else { throw JSError("Key must be a JWK with a kty member") }
        guard algV == .string("EdDSA") else { throw JSError("Invalid key for this operation, its asymmetricKeyType must be ec") }
        guard jwk["kty"] == .string("OKP"), jwk["crv"] == .string("Ed25519") else { throw JSError("Invalid or unsupported JWK for EdDSA") }
        guard let d = jwk["d"] else { throw JSError("KeyObject instances for asymmetric algorithm signing must be of type \"private\"") }
        guard let seedBytes = d.asString.flatMap({ Base64URLStrict.decode($0) }), seedBytes.count == 32 else {
            throw JSError("Invalid JWK OKP key", code: "ERR_CRYPTO_INVALID_JWK")
        }
        var header: JObject = ["alg": algV, "typ": .string(ACP_DELEGATED_TOKEN_TYPE)]
        if let kid = try P.prop(opts, "kid") { header["kid"] = kid }
        return try Jose.sign(header: .object(header), headerOrder: ORDER, payload: .object(claims), payloadOrder: ORDER,
                             signer: { Ed25519Deterministic.sign(seed: seedBytes, $0) })
    }

    /// An atomic first-use claim: `claim(jti, expiresAtMs)` answers exactly `true` once per `jti` (a conditional insert). Any other answer
    /// is a refusal; a thrown error is an unavailable store (fail closed).
    public struct SingleUseStore {
        public let claim: (_ jti: String, _ expiresAtMs: Double) throws -> JSONValue
        public init(claim: @escaping (_ jti: String, _ expiresAtMs: Double) throws -> JSONValue) { self.claim = claim }
    }

    /// The `singleUse` option: nothing (undefined), a store, or any other value (which is not a store).
    public enum SingleUse {
        case absent
        case store(SingleUseStore)
        case other
    }

    /// The claims object when the delegated payment token shape is well formed.
    static func parseClaims(_ c: JObject) -> JSONValue? {
        guard c["typ"] == .string(ACP_DELEGATED_TOKEN_TYPE), P.numOf(c["ver"]) == Double(ACP_DELEGATED_TOKEN_VERSION) else { return nil }
        guard nonEmptyStr(c["jti"]), nonEmptyStr(c["session"]), nonEmptyStr(c["merchant"]), nonEmptyStr(c["currency"]), isAmount(c["amount"]),
              P.isFinite(c["iat"]), P.isFinite(c["exp"]), isBool(c["humanPresent"]) else { return nil }
        guard let pm = c["paymentMethod"]?.asObject, pm["type"]?.asString != nil else { return nil }
        guard let p = c["pca"]?.asObject else { return nil }
        for k in ["digest", "aud", "grant_ref", "leaf_holder", "verb", "resource", "params_digest"] where p[JKey(k)]?.asString == nil { return nil }
        return .object(c)
    }

    /// Node's `Buffer.from(s, 'base64')` as jose's JWK import uses it: characters outside the base64 / base64url alphabets are skipped (a stray space, a newline).
    static func nodeBase64Lenient(_ s: String) -> [UInt8]? {
        let kept = s.unicodeScalars.filter { ($0.value >= 0x41 && $0.value <= 0x5a) || ($0.value >= 0x61 && $0.value <= 0x7a) || ($0.value >= 0x30 && $0.value <= 0x39) || $0 == "-" || $0 == "_" || $0 == "+" || $0 == "/" }
        var t = String.UnicodeScalarView(); t.append(contentsOf: kept)
        let std = String(t).replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        return Base64URLStrict.decode(std)
    }

    /// jose's compactVerify over a canonical compact JWS: header rules (crit / b64), the allowed algorithm, the Ed25519 signature. Returns
    /// the payload object, or nil when the header unencodes the payload (the raw text is never a JSON object).
    static func compactVerify(_ token: V, _ opts: V, _ alg: JSONValue) throws -> JObject? {
        let c = try Jose.assertCanonicalCompactJws(token)
        let h = c.header
        var b64 = true
        if let crit = h["crit"] {
            guard let list = crit.asArray, !list.isEmpty, list.allSatisfy({ ($0.asString ?? "").isEmpty == false }) else {
                throw JSError("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present")
            }
            for p in list.compactMap({ $0.asString }) {
                if p != "b64" { throw JSError("Extension Header Parameter \"\(p)\" is not recognized") }
                if h["b64"] == nil { throw JSError("Extension Header Parameter \"b64\" is missing") }
            }
            guard case let .bool(b)? = h["b64"] else { throw JSError("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean") }
            b64 = b
        }
        guard let headerAlg = JS.nonEmptyString(h["alg"]) else { throw JSError("JWS \"alg\" (Algorithm) Header Parameter missing or invalid") }
        guard alg == .string(headerAlg) else { throw JSError("\"alg\" (Algorithm) Header Parameter value not allowed") }
        guard headerAlg == "EdDSA" else { throw JSError("unsupported algorithm") }
        // importJWK: an Ed25519 public key (a private JWK verifies with its public part)
        guard let jwk = try P.prop(opts, "verifyKey")?.asObject, jwk["kty"] != nil else { throw JSError("Invalid key for this operation") }
        guard jwk["kty"] == .string("OKP"), jwk["crv"] == .string("Ed25519"), let x = jwk["x"]?.asString.flatMap({ nodeBase64Lenient($0) }), x.count == 32 else {
            throw JSError("Invalid JWK OKP key")
        }
        let sig = try Jose.decodeCanonicalBase64url(c.segments[2])
        guard Jose.verifySignature(alg: "EdDSA", key: .ed25519(x), input: Array((c.segments[0] + "." + c.segments[1]).utf8), sig: sig) else {
            throw JSError("signature verification failed")
        }
        return b64 ? c.payload : nil
    }

    static func refused(_ reason: String, _ claims: JSONValue? = nil) -> JSONValue {
        var o: JObject = ["ok": .bool(false), "reason": .string(reason)]
        if let c = claims { o["claims"] = c }
        return .object(o)
    }

    static func verifyBinding(_ token: V, _ opts: V) throws -> JSONValue {
        let algV = JS.present(try P.prop(opts, "alg")) ?? .string("EdDSA")
        let nowOpt = try P.prop(opts, "now")
        let now: Double = P.isFinite(nowOpt) ? (P.numOf(nowOpt) ?? 0) : P.nowMs()

        // 1. the JWS signature
        var payload: JObject? = nil
        do { payload = try compactVerify(token, opts, algV) } catch { return refused("token signature did not verify: \(error)") }
        guard let pl = payload, let claims = parseClaims(pl), let co = claims.asObject else {
            return refused("token payload is not a well-formed delegated payment token")
        }
        let cMerchant = co["merchant"]?.asString ?? "", cSession = co["session"]?.asString ?? "", cCurrency = co["currency"]?.asString ?? ""
        let cAmount = P.numOf(co["amount"]) ?? 0, cExp = P.numOf(co["exp"]) ?? 0

        // 2. binding checks (fail closed)
        let em = try P.prop(opts, "expectedMerchant")
        if em != .string(cMerchant) { return refused("token merchant \"\(cMerchant)\" does not match expected \"\(P.tostr(em))\"", claims) }
        let amountV = try P.prop(opts, "amount")
        if !isAmount(amountV) { return refused("settlement amount must be a positive integer in minor units", claims) }
        if (P.numOf(amountV) ?? 0) > cAmount {
            return refused("settlement amount \(P.tostr(amountV)) exceeds the token's authorized amount \(P.tostr(co["amount"]))", claims)
        }
        if now > cExp { return refused("the delegated payment token has expired", claims) }
        if let es = try P.prop(opts, "expectedSession"), es != .string(cSession) {
            return refused("token session \"\(cSession)\" does not match expected \"\(P.tostr(es))\"", claims)
        }
        if let ec = try P.prop(opts, "expectedCurrency"), ec != .string(cCurrency) {
            return refused("token currency \"\(cCurrency)\" does not match expected \"\(P.tostr(ec))\"", claims)
        }

        // 3. proof binding (optional); a grant with no PCActn would silently skip the re-verification it asked for
        let grant = try P.prop(opts, "grant"), pcaOpt = try P.prop(opts, "pcActn")
        if grant != nil && pcaOpt == nil { return refused("a grant was supplied without the pcActn to re-verify (fail closed)", claims) }
        if let pa = pcaOpt {
            let digest = JSONValue.string(try P.hashStrict(pa))
            if co["pca"]?.get("digest") != digest {
                return refused("pcactn_digest mismatch: the supplied proof is not the one that minted this token", claims)
            }
            if let g = grant {
                let aud: PCA.Audience
                switch try P.prop(opts, "audience") {
                case nil: aud = .unset
                case .null?: aud = .any
                case let .string(s)?: aud = .id(s)
                default: aud = .id("\u{0}not-a-string-audience")
                }
                var roots: [String]? = nil
                if let r = try P.prop(opts, "authorizedPlanRoots") { roots = r.asArray?.compactMap { $0.asString } ?? [] }
                let skip = try P.prop(opts, "insecureSkipPlanRootCheck") == .bool(true)
                let nowI: Int64 = now.isFinite && abs(now) < 9.0e15 ? Int64(now.rounded(.down)) : 0
                let v = PCA.verify(pcactn: pa, grant: g, now: nowI, audience: aud, authorizedPlanRoots: roots, insecureSkipPlanRootCheck: skip)
                var checks: JObject = [:]
                for (k, b) in v.checks { checks[JKey(k)] = .bool(b) }
                let result: JSONValue = .object(["allow": .bool(v.allow), "checks": .object(checks), "reason": .string(v.reason)])
                if !v.allow {
                    var o: JObject = ["ok": .bool(false), "reason": .string("bound proof failed to verify: \(v.reason.isEmpty ? "denied" : v.reason)")]
                    o["claims"] = claims
                    o["pcaResult"] = result
                    return .object(o)
                }
                return .object(["ok": .bool(true), "claims": claims, "pcaResult": result])
            }
        }
        return .object(["ok": .bool(true), "claims": claims])
    }

    /// Verify a delegated payment token at settlement: the signature, then the merchant, amount, expiry, session and currency bindings and,
    /// with a `pcActn`, the proof's digest (end to end with a `grant`). Strict by default: a single-use store and `expectedCurrency` are
    /// required, and after every other check the token's `jti` is claimed once. Fails CLOSED on every mismatch, an already redeemed token
    /// or an unavailable store.
    public static func verifyDelegatedPaymentToken(_ token: JSONValue?, _ opts: JSONValue?, singleUse: SingleUse = .absent) throws -> JSONValue {
        if try P.prop(opts, "strict") != .bool(false) {
            guard case .store = singleUse else { return refused("strict settlement requires a singleUse store (fail closed)") }
            guard try nonEmptyStr(P.prop(opts, "expectedCurrency")) else { return refused("strict settlement requires expectedCurrency (fail closed)") }
        }
        let res = try verifyBinding(token, opts)
        guard res.get("ok") == .bool(true), let claims = res.get("claims") else { return res }
        let unavailable = refused("single-use store unavailable (fail closed)", claims)
        switch singleUse {
        case .absent: return res
        case .other: return unavailable
        case let .store(s):
            let first: Bool
            do { first = try s.claim(claims.get("jti")?.asString ?? "", P.numOf(claims.get("exp")) ?? 0) == .bool(true) } catch { return unavailable }
            return first ? res : refused("the delegated payment token was already redeemed", claims)
        }
    }

    // ---- x402 v1 ----

    /// The HTTP 402 challenge for a protected resource (the x402 v1 `accepts` entry and body). Throws on anything the v1 wire would make
    /// invalid: a non-positive-integer amount, no payTo or asset, a bad timeout.
    public static func x402Challenge(_ resource: JSONValue?, _ opts: JSONValue?) throws -> JSONValue {
        let amount = try P.prop(opts, "amount")
        if !isAmount(amount) { throw JSError("x402Challenge: amount must be a positive integer in atomic/minor units") }
        guard let payTo = try P.prop(opts, "payTo")?.asString, !payTo.isEmpty else { throw JSError("x402Challenge: payTo is required") }
        guard let currency = try P.prop(opts, "currency")?.asString, !currency.isEmpty else { throw JSError("x402Challenge: currency (the x402 asset) is required") }
        let timeout = JS.present(try P.prop(opts, "maxTimeoutSeconds")) ?? .int(60)
        guard P.safeInt(timeout), (P.numOf(timeout) ?? 0) > 0 else { throw JSError("x402Challenge: maxTimeoutSeconds must be a positive integer") }
        var r: JObject = ["maxTimeoutSeconds": timeout]
        r["scheme"] = JS.present(try P.prop(opts, "scheme")) ?? .string("exact")
        r["network"] = JS.present(try P.prop(opts, "network")) ?? .string("base-sepolia")
        r["maxAmountRequired"] = .string(P.tostr(amount))
        if let res = resource { r["resource"] = res }
        r["description"] = JS.present(try P.prop(opts, "description")) ?? .string("Payment required for \(P.tostr(resource))")
        r["payTo"] = .string(payTo)
        r["asset"] = .string(currency)
        r["mimeType"] = JS.present(try P.prop(opts, "mimeType")) ?? .string("application/json")
        let errV = JS.present(try P.prop(opts, "error")) ?? JSONValue.string("X-PAYMENT header is required")
        let body: JSONValue = .object(["x402Version": .int(1), "error": errV, "accepts": .array([.object(r)])])
        return .object(["status": .int(402), "headers": .object(["Content-Type": .string("application/json")]), "body": body])
    }

    /// An injectable function that verifies an x402 payment payload; it answers `{ok, reason?, claims?}`.
    public typealias Verify = (JSONValue?) throws -> JSONValue
    /// An injectable settlement step run once payment is verified; its return value (when not nil) becomes the receipt.
    public typealias Settle = (JSONValue?, JSONValue) throws -> JSONValue?

    /// Gate an x402 settlement on a verified, PCActn-bound payment: a refusal is a fresh 402 (fail closed); on success the optional
    /// settle step runs and its return value becomes the `receipt`.
    public static func x402Settle(_ payload: JSONValue?, verify: Verify, settle: Settle? = nil) throws -> JSONValue {
        func fail(_ r: JSONValue) -> JSONValue { .object(["settled": .bool(false), "status": .int(402), "reason": r]) }
        let norm = normalizeX402Payload(payload)
        if norm.get("ok") != .bool(true) { return fail(norm.get("reason") ?? .null) }
        let v = try verify(payload)
        if !JS.truthy(try P.prop(v, "ok")) {
            var out = fail(JS.present(try P.prop(v, "reason")) ?? .string("payment verification failed"))
            if let c = try P.prop(v, "claims"), JS.truthy(c), case var .object(o) = out { o["claims"] = c; out = .object(o) }
            return out
        }
        guard let claims = try P.prop(v, "claims") else { return fail(.string("verifier admitted the payment but returned no claims (fail closed)")) }
        var receipt: JSONValue? = nil
        if let s = settle { receipt = try s(payload, claims) }
        var out: JObject = ["settled": .bool(true), "status": .int(200), "claims": claims]
        if let r = receipt { out["receipt"] = r }
        return .object(out)
    }

    /// Adapt `verifyDelegatedPaymentToken` into the verify step of `x402Settle`: it reads the token from the payload of either version and
    /// verifies its binding and bound proof. Strict by default: `expectedMerchant` and `amount` must come from the server (the payload's
    /// own are never read) and a store and currency are required.
    public static func acpX402Verifier(_ opts: JSONValue?, singleUse: SingleUse = .absent) -> Verify {
        return { payload in
            let norm = normalizeX402Payload(payload)
            if norm.get("ok") != .bool(true) { return .object(["ok": .bool(false), "reason": norm.get("reason") ?? .null]) }
            if norm.get("version") == .int(2), let offered = try P.prop(opts, "offered"), !(try x402AcceptedMatches(offered, norm.get("accepted"))) {
                return .object(["ok": .bool(false), "reason": .string("x402 v2 payload.accepted is not one of the requirements this server offered")])
            }
            let em = try P.prop(opts, "expectedMerchant"), amt = try P.prop(opts, "amount")
            if try P.prop(opts, "strict") != .bool(false), em == nil || amt == nil {
                return .object(["ok": .bool(false), "reason": .string("strict settlement requires the server to supply expectedMerchant and amount (fail closed)")])
            }
            guard let merchant = (JS.present(em) ?? norm.get("merchant")), nonEmptyStr(merchant) else {
                return .object(["ok": .bool(false), "reason": .string("x402 payload has no merchant to check the token against")])
            }
            guard let amount = (JS.present(amt) ?? norm.get("amount")), amount.isNumber, isAmount(amount) else {
                return .object(["ok": .bool(false), "reason": .string("x402 payload has no amount to check the token against")])
            }
            var o2: JObject = ["expectedMerchant": merchant, "amount": amount]
            if let vk = try P.prop(opts, "verifyKey") { o2["verifyKey"] = vk }
            for k in ["alg", "now", "expectedSession", "expectedCurrency", "pcActn", "grant", "audience", "authorizedPlanRoots", "insecureSkipPlanRootCheck", "strict"] {
                if let v = try P.prop(opts, k) { o2[JKey(k)] = v }
            }
            let res = try verifyDelegatedPaymentToken(norm.get("token"), .object(o2), singleUse: singleUse)
            var out: JObject = ["ok": res.get("ok") ?? .bool(false)]
            if let r = JS.present(res.get("reason")) { out["reason"] = r }
            if let c = res.get("claims"), JS.truthy(c) { out["claims"] = c }
            return .object(out)
        }
    }

    // ---- ACP delegate_payment allowance ----

    /// Map VERIFIED token claims to the ACP delegate_payment `allowance`; throws when a claim cannot be expressed in the ACP shape
    /// (currency not three letters, merchant over 256 characters, expiry not a date).
    public static func toAcpAllowance(_ claims: JSONValue?) throws -> JSONValue {
        let amount = try P.prop(claims, "amount")
        if !isAmount(amount) { throw authErr("allowance: amount must be a positive integer in minor units") }
        let currency = (try P.prop(claims, "currency")?.asString)?.lowercased() ?? ""
        let cb = Array(currency.utf8)
        guard cb.count == 3, cb.allSatisfy({ $0 >= 0x61 && $0 <= 0x7a }) else { throw authErr("allowance: currency must be a three-letter ISO-4217 code") }
        guard let merchant = try P.prop(claims, "merchant")?.asString, !merchant.isEmpty, JS.length(merchant) <= 256 else {
            throw authErr("allowance: merchant_id must be 1 to 256 characters")
        }
        guard let session = try P.prop(claims, "session")?.asString, !session.isEmpty else { throw authErr("allowance: checkout_session_id is required") }
        let exp = try P.prop(claims, "exp")
        guard P.isFinite(exp), let ms = P.numOf(exp), let at = try? PCAScim.isoString(ms) else { throw authErr("allowance: expiry is not a valid time") }
        return .object(["reason": .string("one_time"), "max_amount": amount ?? .null, "currency": .string(currency), "checkout_session_id": .string(session),
                        "merchant_id": .string(merchant), "expires_at": .string(at)])
    }
}
