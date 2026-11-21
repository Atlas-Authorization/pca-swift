import Foundation

/// OAuth Transaction Tokens for PCA: the capability chain as an RFC 8693 sub/act custody chain, issuing an EdDSA transaction
/// token (draft-11 profile `txntoken+jwt` by default: tctx, txn, scope, req_wl, aud = the trust domain; or the legacy
/// `txn_token+jwt` with a jti), and verifying one. Verification is fail closed: the canonical-spelling gate, EdDSA only, the
/// profile's typ and required claims, and a replay check (`seenTxn`) unless the caller explicitly opts out.
public enum TxnTokens {
    public static let TXN_TOKEN_TYP = "txn_token+jwt"
    public static let TXN_TOKEN_TYP_DRAFT_11 = "txntoken+jwt"
    public static let MAX_TOKEN_CHARS = 16384
    static let DEFAULT_TTL_SEC: Double = 120

    static func nonEmpty(_ v: JSONValue?) -> String? { JS.nonEmptyString(v) }

    /// The custody chain of a capability chain (root first): {sub: root issuer, act: {sub: holder 0, act: {...}}}.
    public static func subActChain(_ chain: JSONValue?) throws -> JSONValue {
        guard let hops = chain?.asArray, !hops.isEmpty else { throw JSError("subActChain: chain must be a non-empty CapabilityChain") }
        var act: JSONValue? = nil
        for i in stride(from: hops.count - 1, through: 0, by: -1) {
            guard hops[i] != .null else { throw JSError("subActChain: hop \(i) is null") }
            guard let holder = nonEmpty(hops[i].get("holder")) else { throw JSError("subActChain: hop \(i) has no holder") }
            act = .object(act.map { ["sub": .string(holder), "act": $0] } ?? ["sub": .string(holder)])
        }
        guard let root = nonEmpty(hops[0].get("issuer")) else { throw JSError("subActChain: root hop has no issuer (principal)") }
        return .object(["sub": .string(root), "act": act!])
    }

    /// The number of `act` levels under a claim.
    public static func actDepth(_ claim: JSONValue?) throws -> Int {
        guard let c = claim, c.isObject || c.isArray else { throw JSError("actDepth: expected a sub/act claim object") }
        var depth = 0
        var cur = c.get("act")
        while JS.truthy(cur) { depth += 1; cur = cur?.get("act") }
        return depth
    }

    /// The reference's toRfc8693Act: the actors re-nested in reverse order of the chain (an absent `sub` stays absent).
    public static func toRfc8693Act(_ claim: JSONValue?) throws -> JSONValue {
        guard let c = claim, c != .null else { throw JSError("toRfc8693Act: claim must not be null") }
        var actors: [JSONValue?] = []
        var cur = c.get("act")
        while JS.truthy(cur) { actors.append(cur?.get("sub")); cur = cur?.get("act") }
        func node(_ sub: JSONValue?, _ act: JSONValue?) -> JSONValue {
            var o: JObject = [:]
            if let s = sub { o["sub"] = s }
            if let a = act { o["act"] = a }
            return .object(o)
        }
        var act: JSONValue? = nil
        for s in actors { act = node(s, act) }
        return node(c.get("sub"), act)
    }

    static func uuid() -> String { UUID().uuidString.lowercased() }

    /// Issue a transaction token. `args`: chain, action {verb, resource, aud}, issuer, profile? ('draft-11' | 'legacy'), scope / reqWl
    /// (draft-11, required), txn?, trustDomain? (default action.aud), ttlSec? (default 120). `seed` = the issuer's Ed25519 seed.
    public static func toTransactionToken(_ args: JObject, seed: [UInt8], nowSec: Double? = nil) throws -> String {
        guard let issuer = nonEmpty(args["issuer"]) else { throw JSError("toTransactionToken: `issuer` is required") }
        guard let action = args["action"]?.asObject, let verb = action["verb"]?.asString, let resource = action["resource"]?.asString,
              let aud = action["aud"]?.asString else { throw JSError("toTransactionToken: `action` must have string verb, resource and aud") }
        let custody = try subActChain(args["chain"])
        let ttlV = JS.present(args["ttlSec"]) ?? .double(DEFAULT_TTL_SEC)
        guard let ttl = IV.num(ttlV), ttl.isFinite, ttl > 0 else { throw JSError("toTransactionToken: ttlSec must be > 0") }
        let now = nowSec ?? Date().timeIntervalSince1970.rounded(.down)
        guard seed.count == 32 else { throw JSError("toTransactionToken: a raw Ed25519 secret key must be 32 bytes") }
        let key = try Ed25519Deterministic.key(seed: seed)
        let profile = args["profile"]
        let draft = (JS.present(profile) ?? .string("draft-11")) == .string("draft-11")
        if profile != nil && profile != .string("legacy") && !draft { throw JSError("toTransactionToken: profile must be legacy or draft-11") }
        let tctx: JSONValue = .object(["verb": .string(verb), "resource": .string(resource), "aud": .string(aud)])
        let exp = now + ttl
        let expV: JSONValue = exp.rounded() == exp ? .int(Int64(exp)) : .double(exp)
        if draft {
            guard let scope = nonEmpty(args["scope"]) else { throw JSError("toTransactionToken: draft-11 requires `scope`") }
            guard let reqWl = nonEmpty(args["reqWl"]) else { throw JSError("toTransactionToken: draft-11 requires `reqWl`") }
            guard let td = nonEmpty(JS.present(args["trustDomain"]) ?? .string(aud)) else { throw JSError("toTransactionToken: draft-11 requires a non-empty trust domain (aud)") }
            var c: JObject = ["tctx": tctx, "txn": JS.present(args["txn"]) ?? .string(uuid()), "scope": .string(scope), "req_wl": .string(reqWl),
                              "iat": .int(Int64(now)), "iss": .string(issuer), "sub": custody.get("sub")!, "aud": .string(td), "exp": expV]
            if let a = custody.get("act") { c["act"] = a }
            return try Jose.sign(header: .object(["alg": .string("EdDSA"), "typ": .string(TXN_TOKEN_TYP_DRAFT_11)]), headerOrder: ["alg", "typ"],
                                 payload: .object(c), payloadOrder: ["tctx", "act", "txn", "scope", "req_wl", "iat", "iss", "sub", "aud", "exp"], signer: key.sign)
        }
        var c: JObject = ["tctx": tctx, "iat": .int(Int64(now)), "iss": .string(issuer), "sub": custody.get("sub")!, "aud": .string(aud), "exp": expV, "jti": .string(uuid())]
        if let a = custody.get("act") { c["act"] = a }
        return try Jose.sign(header: .object(["alg": .string("EdDSA"), "typ": .string(TXN_TOKEN_TYP)]), headerOrder: ["alg", "typ"],
                             payload: .object(c), payloadOrder: ["tctx", "act", "iat", "iss", "sub", "aud", "exp", "jti"], signer: key.sign)
    }

    static func normalizeAct(_ node: JSONValue?) throws -> JSONValue? {
        guard let n = node else { return nil }
        guard let o = n.asObject else { throw JSError("transaction token: malformed `act` claim") }
        guard let sub = nonEmpty(o["sub"]) else { throw JSError("transaction token: `act.sub` must be a non-empty string") }
        let inner = try normalizeAct(o["act"])
        return .object(inner.map { ["sub": .string(sub), "act": $0] } ?? ["sub": .string(sub)])
    }

    public struct VerifyOptions {
        /// "draft-11" (default) or "legacy".
        public var profile: String? = nil
        /// The trust domain this verifier serves (required for draft-11).
        public var audience: String? = nil
        public var clockToleranceSec: Double? = nil
        /// Unix milliseconds; nil = the system clock.
        public var nowMs: Double? = nil
        /// Returns true when the transaction id was already seen (it records it). Required unless `replayUnchecked`.
        public var seenTxn: ((String, JSONValue?) throws -> Bool)? = nil
        public var replayUnchecked = false
        public init() {}
    }

    /// Verify a transaction token under the issuer's raw Ed25519 public key: {chain, action, tctx, claims}.
    public static func fromTransactionToken(_ jwt: JSONValue?, verifyKey: [UInt8], _ o: VerifyOptions) throws -> JSONValue {
        let draft = (o.profile ?? "draft-11") == "draft-11"
        if let p = o.profile, p != "legacy", !draft { throw JSError("fromTransactionToken: profile must be legacy or draft-11") }
        if draft && (o.audience ?? "").isEmpty {
            throw JSError("fromTransactionToken: draft-11 requires opts.audience (the trust domain this verifier serves)")
        }
        if o.seenTxn == nil && !o.replayUnchecked {
            throw JSError("fromTransactionToken: supply opts.seenTxn (a replay store) or set opts.replayCheck to 'unchecked'", code: "replay_store_required")
        }
        if let s = jwt?.asString, JS.length(s) > MAX_TOKEN_CHARS { throw JSError("transaction token: token exceeds the size limit") }
        _ = try Jose.assertCanonicalCompactJws(jwt)
        // a non-finite tolerance or an invalid clock makes every exp/nbf comparison pass
        if let t = o.clockToleranceSec, !(t.isFinite && t >= 0) { throw JSError("fromTransactionToken: clockToleranceSec must be a finite number >= 0") }
        if let n = o.nowMs, !n.isFinite { throw JSError("fromTransactionToken: now must be a valid Date") }
        guard verifyKey.count == 32 else { throw JSError("fromTransactionToken: a raw Ed25519 public key must be 32 bytes") }
        var vo = Jose.VerifyOptions()
        vo.algorithms = ["EdDSA"]
        vo.typ = draft ? TXN_TOKEN_TYP_DRAFT_11 : TXN_TOKEN_TYP
        vo.requiredClaims = draft ? ["iat", "exp", "aud", "sub", "txn", "scope", "req_wl"] : ["exp"]
        vo.audience = o.audience.map { [$0] }
        vo.clockTolerance = o.clockToleranceSec ?? 0
        vo.now = o.nowMs.map { ($0 / 1000).rounded(.down) }
        let payload = try Jose.jwtVerify(jwt, key: .ed25519(verifyKey), vo).payload
        if draft {
            for k in ["txn", "scope", "req_wl"] where nonEmpty(payload[JKey(k)]) == nil { throw JSError("transaction token: `\(k)` must be a non-empty string") }
        }
        guard let sub = nonEmpty(payload["sub"]) else { throw JSError("transaction token: missing `sub` (root principal)") }
        guard let tctx = payload["tctx"], let t = tctx.asObject else { throw JSError("transaction token: missing or malformed `tctx`") }
        var action: JSONValue = .null
        if !draft || t["verb"] != nil || t["resource"] != nil || t["aud"] != nil {
            guard let v = t["verb"]?.asString, let r = t["resource"]?.asString, let a = t["aud"]?.asString else {
                throw JSError("transaction token: missing or malformed `tctx`")
            }
            action = .object(["verb": .string(v), "resource": .string(r), "aud": .string(a)])
        }
        if draft, let r = payload["rctx"], r.asObject == nil { throw JSError("transaction token: malformed `rctx`") }
        let act = try normalizeAct(payload["act"])
        if let seen = o.seenTxn {
            guard let id = nonEmpty(payload[draft ? "txn" : "jti"]) else { throw JSError("transaction token: no transaction identifier to check for replay") }
            if try seen(id, payload["exp"]) { throw JSError("transaction token: replayed (transaction identifier already seen)") }
        }
        let chain: JSONValue = .object(act.map { ["sub": .string(sub), "act": $0] } ?? ["sub": .string(sub)])
        var out: JObject = ["chain": chain, "tctx": tctx, "claims": .object(payload)]
        if action != .null { out["action"] = action }
        return .object(out)
    }
}
