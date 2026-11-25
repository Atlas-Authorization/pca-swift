import Foundation
import CryptoKit

/// AP2 mandate issuance, presentation and verification.
///
/// Wire format: a mandate is the single object in an SD-JWT's `delegate_payload` array, itself an array-element disclosure. An OPEN mandate is
/// signed by the issuer (the user's trusted surface / agent provider) and names the agent's key in `cnf.jwk`. A CLOSED mandate is a KB-SD-JWT
/// hop (`typ: kb+sd-jwt`) signed by that agent key, carrying `iat`, `aud`, `nonce` and an `sd_hash` over the preceding hop. Hops are joined by
/// `~~`. That hop is AP2's key-binding mechanism; no trailing RFC 9901 KB-JWT is used or accepted.
///
/// Inputs are JSON objects in the reference's member names (`agentJwk`, `iat`, `exp`, `constraints`, ...); the signing keys, the salt source
/// and the key resolvers are native values next to them.
extension PCAAp2 {
    /// A P-256 key pair: the private key and its public JWK (which never carries `d`).
    public struct KeyPair {
        public let privateKey: PrivateKey
        public let publicJwk: JObject
    }

    /// A fresh ES256 key pair.
    public static func generateAp2KeyPair(kid: String? = nil) -> KeyPair {
        let k = PrivateKey()
        return KeyPair(privateKey: k, publicJwk: publicJwk(k, kid: kid))
    }

    /// Rebuild a key pair from a private JWK (`d` present). Refused (code `ERR_CRYPTO_INVALID_JWK`) unless it is a consistent EC P-256 key.
    public static func ap2KeyPairFromPrivateJwk(_ jwk: JSONValue?) throws -> KeyPair {
        func bad(_ kty: String) -> JSError { JSError("Invalid JWK \(kty) key", code: "ERR_CRYPTO_INVALID_JWK") }
        guard case let .object(o)? = jwk else { throw bad("EC") }
        guard seq(get(o, "kty"), "EC"), seq(get(o, "crv"), "P-256") else { throw bad(get(o, "kty")?.asString ?? "EC") }
        func segment(_ k: String) throws -> [UInt8] {
            guard let s = get(o, k)?.asString, s.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x2d || $0 == 0x5f }) else { throw bad("EC") }
            return lenientB64u(s)
        }
        let d = try segment("d"), x = try segment("x"), y = try segment("y")
        guard d.count == 32, x.count == 32, y.count == 32, let key = try? PrivateKey(rawRepresentation: Data(d)) else { throw bad("EC") }
        let raw = Array(key.publicKey.x963Representation)
        guard Array(raw[1..<33]) == x, Array(raw[33..<65]) == y else { throw bad("EC") }
        return KeyPair(privateKey: key, publicJwk: publicJwk(key, kid: get(o, "kid")?.asString))
    }

    // ---- issuing open mandates ----

    /// The signer of an open mandate: the user's trusted surface or agent provider (an ES256 key).
    public struct MandateIssuer {
        public var privateKey: PrivateKey
        /// `kid` header; a verifier's key resolver maps it to the public key.
        public var kid: JSONValue?
        /// Optional `x5c` header (base64 DER certificates); chain validation is the resolver's job.
        public var x5c: JSONValue?
        public init(privateKey: PrivateKey, kid: JSONValue? = nil, x5c: JSONValue? = nil) { self.privateKey = privateKey; self.kid = kid; self.x5c = x5c }
    }

    static func signRoot(_ c: JSONValue?, _ issuer: MandateIssuer, _ mandate: JSONValue, _ b: DisclosureBuilder) throws -> String {
        let element = try b.element(mandate)
        var header: JObject = ["typ": coalesce(try P.prop(c, "typ"), { JSONValue.string(ROOT_TYP) })!]
        if let kid = issuer.kid { header["kid"] = kid }
        if let x5c = issuer.x5c, JS.truthy(x5c) { header["x5c"] = x5c }
        let alg = coalesce(try P.prop(c, "sdAlg"), { JSONValue.string("sha-256") })!
        return try signSdJwt(header: .object(header), payload: .object(["delegate_payload": .array([element]), "_sd_alg": alg]), disclosures: b.disclosures, privateKey: issuer.privateKey)
    }

    static func commonClaims(_ c: JSONValue?) throws -> JObject {
        let jwk = try assertP256Jwk(try P.prop(c, "agentJwk"), "agentJwk")
        let iat = try P.prop(c, "iat"), exp = try P.prop(c, "exp")
        guard P.safeInt(iat), P.safeInt(exp), (P.numOf(exp) ?? 0) > (P.numOf(iat) ?? 0) else { throw JSError("open mandate: need integer iat < exp (epoch seconds)") }
        var out: JObject = ["cnf": .object(["jwk": .object(["crv": .string("P-256"), "kty": .string("EC"), "x": get(jwk, "x")!, "y": get(jwk, "y")!])]), "iat": iat!, "exp": exp!]
        if let pca = try P.prop(c, "pca"), JS.truthy(pca) { out[o: PCA_CLAIM] = pca }
        return out
    }

    static func sdPaymentConstraint(_ c: JSONValue?, _ b: DisclosureBuilder) throws -> JSONValue {
        let t = try P.prop(c, "type")
        if seq(t, "payment.allowed_payees") || seq(t, "payment.allowed_payment_instruments") {
            return .object(["type": t!, "allowed": .array(try listOf(try P.prop(c, "allowed"), "c.allowed.map").map { try b.element($0) })])
        }
        return c ?? .null
    }

    static func sdCheckoutConstraint(_ c: JSONValue?, _ b: DisclosureBuilder) throws -> JSONValue {
        let t = try P.prop(c, "type")
        if seq(t, "checkout.allowed_merchants") { return .object(["type": t!, "allowed": .array(try listOf(try P.prop(c, "allowed"), "c.allowed.map").map { try b.element($0) })]) }
        var items: [JSONValue] = []
        for it in try listOf(try P.prop(c, "items"), "c.items.map") {
            var o: JObject = [:]
            if let id = try P.prop(it, "id") { o["id"] = id }
            o["acceptable_items"] = .array(try listOf(try P.prop(it, "acceptable_items"), "it.acceptable_items.map").map { try b.element($0) })
            if let q = try P.prop(it, "quantity") { o["quantity"] = q }
            items.append(.object(o))
        }
        var out: JObject = ["items": .array(items)]
        if let t = t { out["type"] = t }
        return .object(out)
    }

    /// Validate the PLAIN claims (before selective-disclosure wrapping) so a bad input fails at issuance.
    static func assertWellFormed(_ wrapped: JObject, _ problems: (JSONValue?) -> [String], _ what: String, _ plainConstraints: JSONValue?) throws {
        var plain = wrapped
        if let pc = plainConstraints { plain["constraints"] = pc } else { plain["constraints"] = nil }
        let p = problems(.object(plain))
        if !p.isEmpty { throw JSError("\(what): \(p.joined(separator: "; "))") }
    }

    /// Issue an open Payment Mandate (`mandate.payment.open.1`) as a signed SD-JWT. `input`: `agentJwk`, `iat`, `exp`, `constraints`, optional
    /// `payee`, `paymentAmount`, `paymentInstrument`, `pisp`, `executionDate`, `pca` (the `x_pca` claim), `sdAlg`, `typ`.
    public static func issueOpenPaymentMandate(_ input: JSONValue, issuer: MandateIssuer, salt: (() -> String)? = nil) throws -> String {
        let inp: JSONValue? = input
        let b = disclosureBuilder(try P.prop(inp, "sdAlg"), salt: salt)
        let cons = try P.prop(inp, "constraints")
        var mandate: JObject = ["vct": .string(VCT_PAYMENT_OPEN), "constraints": .array(try listOf(cons, "input.constraints.map").map { try sdPaymentConstraint($0, b) })]
        for (member, key) in [("payee", "payee"), ("payment_amount", "paymentAmount"), ("payment_instrument", "paymentInstrument"), ("pisp", "pisp")] {
            if let v = try P.prop(inp, key), JS.truthy(v) { mandate[o: member] = v }
        }
        if let ed = try P.prop(inp, "executionDate") { mandate["execution_date"] = ed }
        for (k, v) in try commonClaims(inp) { mandate[k] = v }
        try assertWellFormed(mandate, openPaymentMandateProblems, "open payment mandate", cons)
        return try signRoot(inp, issuer, .object(mandate), b)
    }

    /// Issue an open Checkout Mandate (`mandate.checkout.open.1`) as a signed SD-JWT (`input` as the payment form; `constraints` are checkout constraints).
    public static func issueOpenCheckoutMandate(_ input: JSONValue, issuer: MandateIssuer, salt: (() -> String)? = nil) throws -> String {
        let inp: JSONValue? = input
        let b = disclosureBuilder(try P.prop(inp, "sdAlg"), salt: salt)
        let cons = try P.prop(inp, "constraints")
        var mandate: JObject = ["vct": .string(VCT_CHECKOUT_OPEN), "constraints": .array(try listOf(cons, "input.constraints.map").map { try sdCheckoutConstraint($0, b) })]
        for (k, v) in try commonClaims(inp) { mandate[k] = v }
        try assertWellFormed(mandate, openCheckoutMandateProblems, "open checkout mandate", cons)
        return try signRoot(inp, issuer, .object(mandate), b)
    }

    // ---- presenting closed mandates (KB-SD-JWT hops) ----

    static func presentHop(_ c: JSONValue?, agentKey: PrivateKey, salt: (() -> String)?, _ build: (DisclosureBuilder) throws -> JObject) throws -> String {
        let aud = try P.prop(c, "aud"), nonce = try P.prop(c, "nonce"), iat = try P.prop(c, "iat")
        if !JS.truthy(aud) || !JS.truthy(nonce) { throw JSError("closed mandate: aud and nonce are required") }
        if !P.safeInt(iat) { throw JSError("closed mandate: iat must be an integer") }
        let open = try P.prop(c, "open")
        let prev = try parseSdJwtHop(open)
        let b = disclosureBuilder(.string(prev.sdAlg), salt: salt)
        let mandate = try build(b)
        let element = try b.element(.object(mandate))
        let mode = coalesce(try P.prop(c, "hashMode"), { JSONValue.string("sd_hash") })!
        var payload: JObject = ["delegate_payload": .array([element]), "iat": iat!, "aud": aud!, "nonce": nonce!]
        payload[o: mode.asString ?? JS.toString(mode)] = .string(seq(mode, "sd_hash") ? try sdHashOf(prev) : try issuerJwtHashOf(prev))
        payload["_sd_alg"] = .string(prev.sdAlg)
        let hop = try signSdJwt(header: .object(["typ": .string("kb+sd-jwt")]), payload: .object(payload), disclosures: b.disclosures, privateKey: agentKey)
        // Hops are joined by "~~": the preceding token's own trailing "~" plus one separator "~".
        return "\(open?.asString ?? "")~\(hop)"
    }

    /// Present a closed Payment Mandate (`mandate.payment.1`) on top of an open payment mandate. `input`: `open`, `aud`, `nonce`, `iat`,
    /// `transactionId`, `payee`, `paymentAmount`, `paymentInstrument`, optional `pisp`, `executionDate`, `riskData`, `exp`, `pca`, `hashMode`.
    /// `agentKey` is the agent's private key (its public key must be the open mandate's `cnf.jwk`).
    public static func presentClosedPayment(_ input: JSONValue, agentKey: PrivateKey, salt: (() -> String)? = nil) throws -> String {
        let inp: JSONValue? = input
        return try presentHop(inp, agentKey: agentKey, salt: salt) { _ in
            var mandate: JObject = ["vct": .string(VCT_PAYMENT)]
            for (member, key) in [("transaction_id", "transactionId"), ("payee", "payee"), ("payment_amount", "paymentAmount"), ("payment_instrument", "paymentInstrument")] {
                if let v = try P.prop(inp, key) { mandate[o: member] = v }
            }
            for (member, key) in [("pisp", "pisp"), ("risk_data", "riskData")] {
                if let v = try P.prop(inp, key), JS.truthy(v) { mandate[o: member] = v }
            }
            if let ed = try P.prop(inp, "executionDate") { mandate["execution_date"] = ed }
            if let e = try P.prop(inp, "exp") { mandate["exp"] = e }
            if let pca = try P.prop(inp, "pca"), JS.truthy(pca) { mandate[o: PCA_CLAIM] = pca }
            let p = paymentMandateProblems(.object(mandate))
            if !p.isEmpty { throw JSError("closed payment mandate: \(p.joined(separator: "; "))") }
            return mandate
        }
    }

    /// Present a closed Checkout Mandate (`mandate.checkout.1`) on top of an open checkout mandate (`input` as above with `checkoutJwt`).
    public static func presentClosedCheckout(_ input: JSONValue, agentKey: PrivateKey, salt: (() -> String)? = nil) throws -> String {
        let inp: JSONValue? = input
        return try presentHop(inp, agentKey: agentKey, salt: salt) { b in
            let prevAlg = try parseSdJwtHop(try P.prop(inp, "open")).sdAlg
            let jwt = try P.prop(inp, "checkoutJwt")
            var mandate: JObject = ["_sd": .array([try b.property("checkout_jwt", jwt)]), "vct": .string(VCT_CHECKOUT), "checkout_hash": .string(try sdDigest(jwt, .string(prevAlg)))]
            if let e = try P.prop(inp, "exp") { mandate["exp"] = e }
            if let pca = try P.prop(inp, "pca"), JS.truthy(pca) { mandate[o: PCA_CLAIM] = pca }
            var withJwt = mandate
            if let j = jwt { withJwt["checkout_jwt"] = j }
            let p = checkoutMandateProblems(.object(withJwt))
            if !p.isEmpty { throw JSError("closed checkout mandate: \(p.joined(separator: "; "))") }
            return mandate
        }
    }

    // ---- verifying a delegation chain ----

    /// Resolves a public JWK from a JWT header (`kid` / `x5c`); nil refuses.
    public typealias KeyResolver = (JObject) -> JSONValue?

    public struct VerifiedHop {
        public let index: Int
        /// `root`, `intermediate` or `terminal`.
        public let kind: String
        public let hop: Hop
        /// Hop-level claims after disclosure processing.
        public let claims: JSONValue
        /// The single mandate object disclosed in `delegate_payload`.
        public let mandate: JObject
        public func with(index: Int) -> VerifiedHop { VerifiedHop(index: index, kind: kind, hop: hop, claims: claims, mandate: mandate) }
        public var json: JSONValue { .object(["index": .int(Int64(index)), "kind": .string(kind), "claims": claims, "mandate": .object(mandate)]) }
    }

    /// Options of a chain verification. `expectedAudience` and `expectedNonce` are REQUIRED (a verifier that does not name itself cannot detect
    /// redirection; the nonce is the replay defence). `now` is epoch seconds (default: the wall clock), `clockSkewSeconds` defaults to 60.
    public struct ChainOptions {
        public var resolveIssuerKey: KeyResolver
        public var expectedAudience: JSONValue?
        public var expectedNonce: JSONValue?
        public var now: Double?
        public var clockSkewSeconds: Double?
        public init(resolveIssuerKey: @escaping KeyResolver, expectedAudience: JSONValue?, expectedNonce: JSONValue?, now: Double? = nil, clockSkewSeconds: Double? = nil) {
            self.resolveIssuerKey = resolveIssuerKey; self.expectedAudience = expectedAudience; self.expectedNonce = expectedNonce; self.now = now; self.clockSkewSeconds = clockSkewSeconds
        }
    }

    /// The outcome of a chain, checkout, payment or purchase verification: `ok`, or `reason` (and, for a constraint failure, `violations`).
    public struct ChainOutcome {
        public var ok: Bool
        public var reason: String
        public var violations: [String]?
        public var hops: [VerifiedHop]
        public var open: JSONValue?
        public var closed: JSONValue?
        public var checkoutJwt: String?
        public var checkout: JSONValue?
        public var openHash: String?
        static func fail(_ reason: String, violations: [String]? = nil) -> ChainOutcome {
            ChainOutcome(ok: false, reason: reason, violations: violations, hops: [], open: nil, closed: nil, checkoutJwt: nil, checkout: nil, openHash: nil)
        }
    }

    /// Split a `~~`-joined chain into hops, each restored to `<jwt>~<d>...~`.
    public static func splitChain(_ token: JSONValue?) throws -> [String] {
        guard let t = token?.asString, !t.isEmpty else { throw JSError("chain: empty") }
        // `t.split("~~")`: left to right, non-overlapping
        var hops: [[Unicode.Scalar]] = [[]]
        let us = Array(t.unicodeScalars)
        var i = 0
        while i < us.count {
            if us[i] == "~", i + 1 < us.count, us[i + 1] == "~" { hops.append([]); i += 2 } else { hops[hops.count - 1].append(us[i]); i += 1 }
        }
        if hops.count > MAX_HOPS { throw JSError("chain: more than \(MAX_HOPS) hops") }
        return hops.enumerated().map { (k, p) in
            let s = String(String.UnicodeScalarView(p))
            return k == hops.count - 1 ? s : s + "~"
        }
    }

    static func checkTimes(_ label: String, _ o: JObject, _ now: Double, _ skew: Double) throws {
        if let exp = get(o, "exp") {
            if !isInt(exp) { throw JSError("\(label): exp must be an integer") }
            if !(now.isFinite && skew.isFinite && now <= (P.numOf(exp) ?? 0) + skew) { throw JSError("\(label): expired at \(JS.toString(exp))") }
        }
        if let iat = get(o, "iat") {
            if !isInt(iat) { throw JSError("\(label): iat must be an integer") }
            if !(now.isFinite && skew.isFinite && (P.numOf(iat) ?? 0) <= now + skew) { throw JSError("\(label): iat is in the future") }
        }
    }

    static func delegateMandate(_ claims: JSONValue, _ label: String) throws -> JObject {
        guard case let .array(dp)? = claims.get("delegate_payload") else { throw JSError("\(label): delegate_payload missing") }
        guard dp.count == 1, case let .object(m) = dp[0] else { throw JSError("\(label): delegate_payload must disclose exactly one mandate (got \(dp.count))") }
        return m
    }

    static func cnfJwk(_ mandate: JObject, _ label: String) throws -> JObject {
        guard case let .object(cnf)? = get(mandate, "cnf"), case .object? = get(cnf, "jwk") else { throw JSError("\(label): no cnf.jwk to delegate to") }
        return try assertP256Jwk(get(cnf, "jwk"), "\(label) cnf.jwk")
    }

    /// Verify one key-binding hop against its predecessor (signature, typ, binding hash, times, aud/nonce).
    public static func verifyKbHop(_ hop: Hop, prev: (hop: Hop, mandate: JObject), terminal: Bool, expectedAudience: JSONValue?, expectedNonce: JSONValue?,
                                   now: Double, skew: Double, label: String) throws -> VerifiedHop {
        let allowed = terminal ? TYP_TERMINAL : TYP_INTERMEDIATE
        guard let typ = get(hop.header, "typ")?.asString, allowed.contains(where: { $0.unicodeScalars.elementsEqual(typ.unicodeScalars) }) else {
            throw JSError("\(label): typ must be one of \(allowed.joined(separator: ", "))")
        }
        if get(hop.header, "crit") != nil { throw JSError("\(label): crit headers are not supported") }
        let key = try cnfJwk(prev.mandate, "preceding mandate")
        if !(try verifyHopSignature(hop, .object(key))) { throw JSError("\(label): signature does not verify under the preceding mandate's cnf.jwk") }
        let claims = try processDisclosures(.object(hop.payload), hop.disclosures, hop.sdAlg)
        guard case let .object(co) = claims else { throw JSError("\(label): claims must be an object") }
        let hasSd = get(co, "sd_hash") != nil, hasIss = get(co, "issuer_jwt_hash") != nil
        if hasSd == hasIss { throw JSError("\(label): exactly one of sd_hash / issuer_jwt_hash is required") }
        let expected: JSONValue = .string(hasSd ? try sdHashOf(prev.hop) : try issuerJwtHashOf(prev.hop))
        if !P.seq(hasSd ? get(co, "sd_hash") : get(co, "issuer_jwt_hash"), expected) { throw JSError("\(label): \(hasSd ? "sd_hash" : "issuer_jwt_hash") does not match the preceding hop") }
        if get(co, "iat") == nil { throw JSError("\(label): iat is required") }
        try checkTimes(label, co, now, skew)
        let mandate = try delegateMandate(claims, label)
        try checkTimes("\(label) mandate", mandate, now, skew)
        let hasCnf = get(mandate, "cnf")?.isObject ?? false
        if terminal && hasCnf { throw JSError("\(label): a terminal hop must not carry cnf") }
        if !terminal && !hasCnf { throw JSError("\(label): an intermediate hop requires cnf") }
        if terminal {
            if expectedAudience == nil || !P.seq(get(co, "aud"), expectedAudience) { throw JSError("\(label): aud mismatch") }
            if expectedNonce == nil || !P.seq(get(co, "nonce"), expectedNonce) { throw JSError("\(label): nonce mismatch") }
        }
        return VerifiedHop(index: -1, kind: terminal ? "terminal" : "intermediate", hop: hop, claims: claims, mandate: mandate)
    }

    static func reasonOf(_ e: Error) -> String { (e as? JSError)?.message ?? "\(e)" }

    static func nowSeconds() -> Double { Double(Int((Date().timeIntervalSince1970).rounded(.down))) }

    /// Verify a whole chain: root signature, then every hop in order. Never throws; reports the reason.
    public static func verifyDelegationChain(_ token: String, _ o: ChainOptions) -> ChainOutcome {
        do {
            if !JS.truthy(o.expectedAudience) || !JS.truthy(o.expectedNonce) { throw JSError("verify: expectedAudience and expectedNonce are required") }
            let now = o.now ?? nowSeconds()
            let skew = o.clockSkewSeconds ?? 60
            let segments = try splitChain(.string(token)).map { try parseSdJwtHop(.string($0)) }
            let root = segments[0]
            if get(root.header, "crit") != nil { throw JSError("root: crit headers are not supported") }
            guard let issuerKey = o.resolveIssuerKey(root.header), JS.truthy(issuerKey) else { throw JSError("root: no issuer key for this header") }
            if !(try verifyHopSignature(root, issuerKey)) { throw JSError("root: signature does not verify under the issuer key") }
            let rootClaims = try processDisclosures(.object(root.payload), root.disclosures, root.sdAlg)
            guard case let .object(rc) = rootClaims else { throw JSError("root: claims must be an object") }
            try checkTimes("root", rc, now, skew)
            let rootMandate = try delegateMandate(rootClaims, "root")
            try checkTimes("root mandate", rootMandate, now, skew)
            var hops = [VerifiedHop(index: 0, kind: "root", hop: root, claims: rootClaims, mandate: rootMandate)]
            for i in 1..<max(segments.count, 1) {
                let v = try verifyKbHop(segments[i], prev: (hops[i - 1].hop, hops[i - 1].mandate), terminal: i == segments.count - 1, expectedAudience: o.expectedAudience,
                                        expectedNonce: o.expectedNonce, now: now, skew: skew, label: "hop \(i)")
                hops.append(v.with(index: i))
            }
            var out = ChainOutcome.fail("")
            out.ok = true
            out.hops = hops
            return out
        } catch {
            return ChainOutcome.fail(reasonOf(error))
        }
    }

    static func pair(_ r: ChainOutcome) throws -> (VerifiedHop, VerifiedHop) {
        if r.hops.count != 2 { throw JSError("expected an open mandate followed by one closed mandate, got \(r.hops.count) hop(s)") }
        return (r.hops[0], r.hops[1])
    }

    static func requireOpenExpiry(_ m: JObject, _ label: String) throws {
        if !P.safeInt(get(m, "exp")) { throw JSError("\(label): an open mandate must carry exp") }
    }

    /// Verify an open+closed checkout chain, the merchant-signed checkout, its hash, and the open constraints.
    public static func verifyCheckoutChain(_ token: String, _ o: ChainOptions, resolveMerchantKey: KeyResolver) -> ChainOutcome {
        var r = verifyDelegationChain(token, o)
        if !r.ok { return r }
        do {
            let (openHop, closedHop) = try pair(r)
            let open = JSONValue.object(openHop.mandate), closed = JSONValue.object(closedHop.mandate)
            let op = openCheckoutMandateProblems(open)
            if !op.isEmpty { throw JSError("open checkout mandate: \(op.joined(separator: "; "))") }
            try requireOpenExpiry(openHop.mandate, "open checkout mandate")
            let cp = checkoutMandateProblems(closed)
            if !cp.isEmpty { throw JSError("closed checkout mandate: \(cp.joined(separator: "; "))") }
            let cj = closed.get("checkout_jwt")
            if !P.seq(.string(try sdDigest(cj, .string(closedHop.hop.sdAlg))), closed.get("checkout_hash")) { throw JSError("checkout_hash does not match checkout_jwt") }
            let jwt = try parseJwt(cj, "checkout_jwt")
            guard let key = resolveMerchantKey(jwt.header), JS.truthy(key) else { throw JSError("checkout_jwt: no merchant key for this header") }
            if !(try verifyJwtEs256(jwt, key)) { throw JSError("checkout_jwt: merchant signature does not verify") }
            let checkout = try projectCheckout(.object(jwt.payload))
            let violations = try checkCheckoutConstraints(open, checkout)
            if !violations.isEmpty { return ChainOutcome.fail("open checkout constraints violated: \(violations.joined(separator: "; "))", violations: violations) }
            r.open = open
            r.closed = closed
            r.checkoutJwt = cj?.asString
            r.checkout = checkout
            r.openHash = try sdHashOf(openHop.hop)
            return r
        } catch {
            return ChainOutcome.fail(reasonOf(error))
        }
    }

    /// Verify an open+closed payment chain and every open payment constraint. `openCheckoutHash` is the open checkout mandate's `sd_hash`,
    /// `context` the usage state under this open mandate (needed for `payment.budget` and recurrence), `expectedTransactionId` the closed
    /// checkout's `checkout_hash`.
    public static func verifyPaymentChain(_ token: String, _ o: ChainOptions, openCheckoutHash: JSONValue?, context: JSONValue? = nil, expectedTransactionId: JSONValue? = nil) -> ChainOutcome {
        var r = verifyDelegationChain(token, o)
        if !r.ok { return r }
        do {
            let (openHop, closedHop) = try pair(r)
            let open = JSONValue.object(openHop.mandate), closed = JSONValue.object(closedHop.mandate)
            let op = openPaymentMandateProblems(open)
            if !op.isEmpty { throw JSError("open payment mandate: \(op.joined(separator: "; "))") }
            try requireOpenExpiry(openHop.mandate, "open payment mandate")
            let cp = paymentMandateProblems(closed)
            if !cp.isEmpty { throw JSError("closed payment mandate: \(cp.joined(separator: "; "))") }
            if let want = expectedTransactionId, !P.seq(closed.get("transaction_id"), want) { throw JSError("transaction_id does not match the checkout being settled") }
            var opts: JObject = ["now": P.num(o.now ?? nowSeconds())]
            if let h = openCheckoutHash { opts["openCheckoutHash"] = h }
            if let c = context, JS.truthy(c) { opts["context"] = c }
            let violations = try checkPaymentConstraints(open, closed, .object(opts))
            if !violations.isEmpty { return ChainOutcome.fail("open payment constraints violated: \(violations.joined(separator: "; "))", violations: violations) }
            r.open = open
            r.closed = closed
            r.openHash = try sdHashOf(openHop.hop)
            return r
        } catch {
            return ChainOutcome.fail(reasonOf(error))
        }
    }

    /// What a verifier names for one chain: its audience and its nonce.
    public struct ChainExpect {
        public var expectedAudience: JSONValue?
        public var expectedNonce: JSONValue?
        public init(expectedAudience: JSONValue?, expectedNonce: JSONValue?) { self.expectedAudience = expectedAudience; self.expectedNonce = expectedNonce }
    }

    public struct PurchaseOptions {
        public var resolveIssuerKey: KeyResolver
        public var resolveMerchantKey: KeyResolver
        public var checkout: ChainExpect
        public var payment: ChainExpect
        public var context: JSONValue?
        public var now: Double?
        public var clockSkewSeconds: Double?
        public init(resolveIssuerKey: @escaping KeyResolver, resolveMerchantKey: @escaping KeyResolver, checkout: ChainExpect, payment: ChainExpect, context: JSONValue? = nil,
                    now: Double? = nil, clockSkewSeconds: Double? = nil) {
            self.resolveIssuerKey = resolveIssuerKey; self.resolveMerchantKey = resolveMerchantKey; self.checkout = checkout; self.payment = payment
            self.context = context; self.now = now; self.clockSkewSeconds = clockSkewSeconds
        }
    }

    /// The outcome of `verifyPurchase` / `redeemPurchase`: `ok` with both chains, or a `reason` (for the redeem ledger also `replayed`,
    /// `ledger_unavailable`, `ledger_required`).
    public struct PurchaseOutcome {
        public var ok: Bool
        public var reason: String
        public var checkout: ChainOutcome?
        public var payment: ChainOutcome?
        static func fail(_ r: String) -> PurchaseOutcome { PurchaseOutcome(ok: false, reason: r, checkout: nil, payment: nil) }
    }

    /// Verify a complete purchase: the checkout chain, then the payment chain bound to it (the payment's `payment.reference` is the open checkout
    /// hash; its `transaction_id` is the closed checkout's `checkout_hash`), and that the payment settles what the merchant quoted (payee,
    /// currency, total).
    public static func verifyPurchase(_ checkoutToken: String, _ paymentToken: String, _ o: PurchaseOptions) -> PurchaseOutcome {
        let co = verifyCheckoutChain(checkoutToken, ChainOptions(resolveIssuerKey: o.resolveIssuerKey, expectedAudience: o.checkout.expectedAudience, expectedNonce: o.checkout.expectedNonce,
                                                                 now: o.now, clockSkewSeconds: o.clockSkewSeconds), resolveMerchantKey: o.resolveMerchantKey)
        if !co.ok { return .fail("checkout: \(co.reason)") }
        let pay = verifyPaymentChain(paymentToken, ChainOptions(resolveIssuerKey: o.resolveIssuerKey, expectedAudience: o.payment.expectedAudience, expectedNonce: o.payment.expectedNonce,
                                                                now: o.now, clockSkewSeconds: o.clockSkewSeconds), openCheckoutHash: co.openHash.map { JSONValue.string($0) },
                                     context: o.context, expectedTransactionId: co.closed?.get("checkout_hash"))
        if !pay.ok { return .fail("payment: \(pay.reason)") }
        guard let total = try? checkoutTotal(co.checkout) else { return .fail("checkout: needs exactly one total entry") }
        let amt = pay.closed?.get("payment_amount")
        if !P.seq(amt?.get("currency"), co.checkout?.get("currency")) { return .fail("payment currency differs from the checkout currency") }
        if !P.seq(amt?.get("amount"), total) { return .fail("payment amount \(P.tostr(amt?.get("amount"))) differs from the checkout total \(P.tostr(total))") }
        guard let merchant = co.checkout?.get("merchant") else { return .fail("checkout: no merchant to compare the payee with") }
        if !P.seq(merchant.get("id"), pay.closed?.get("payee")?.get("id")) { return .fail("payee differs from the checkout merchant") }
        return PurchaseOutcome(ok: true, reason: "", checkout: co, payment: pay)
    }

    // ---- the redeem ledger ----

    /// `verifyPurchase` plus single use and server-owned cumulative state. The usage context comes from `ledger`, never from the caller, and the
    /// purchase's transaction id can be redeemed once. A missing or failing ledger denies. (Synchronous: wrap an asynchronous store in a blocking
    /// adapter, or call `reserve` / `release` yourself around `verifyPurchase`.)
    public static func redeemPurchase(_ checkoutToken: String, _ paymentToken: String, _ o: PurchaseOptions, ledger: PCAAp2PurchaseLedger?) -> PurchaseOutcome {
        guard let ledger = ledger else { return .fail("ledger_required") }
        // A zero context is the most permissive one for budget and recurrence, so a failure here is final.
        var first = o
        first.context = .object(["totalAmount": .int(0), "totalUses": .int(0)])
        let f = verifyPurchase(checkoutToken, paymentToken, first)
        if !f.ok { return f }
        let openHash = f.payment?.openHash ?? ""
        let closed = f.payment?.closed
        let txId = closed?.get("transaction_id")?.asString ?? ""
        let amount = closed?.get("payment_amount")?.get("amount") ?? .null
        let ctx: JSONValue?
        do { ctx = try ledger.reserve(openHash, txId, amount) } catch { return .fail("ledger_unavailable") }
        if ctx?.asString == "replayed" { return .fail("replayed") }
        var second = o
        second.context = ctx
        let final = verifyPurchase(checkoutToken, paymentToken, second)
        if !final.ok {
            do { try ledger.release(openHash, txId) } catch { /* the reservation stays: a failed release only ever over-counts spend */ }
        }
        return final
    }
}

/// Durable, serialised purchase state for open mandates. `reserve` is ONE atomic step: it refuses a transaction id that was already reserved
/// under this open mandate (answer the string `replayed`), otherwise records it with its amount and returns the usage of every EARLIER
/// reservation as `{ totalAmount, totalUses, lastUsedDate? }` (so two concurrent purchases see each other and cannot share one budget).
/// Back it with a unique key on (openMandateHash, transactionId) and a serialised sum. `release` undoes a reservation whose purchase then
/// failed verification. A throw from either is a ledger failure; a missing context (`nil`) denies at the budget check.
public protocol PCAAp2PurchaseLedger {
    func reserve(_ openMandateHash: String, _ transactionId: String, _ amountMinor: JSONValue) throws -> JSONValue?
    func release(_ openMandateHash: String, _ transactionId: String) throws
}
