import Foundation

/// Identity Assertion JWT Authorization Grants (ID-JAG, the cross-app access flow) for PCA: verify an ID-JAG on top of the OIDC
/// ID-token checks (exactly one audience, an `act` agent claim, scopes; in the default strict-draft mode also typ
/// `oauth-id-jag+jwt`, the authenticated client_id and a single-use jti), project it to a PCA principal and a root capability with
/// authority / provenance caveats, and build the token-exchange and jwt-bearer requests.
public enum PCAIdJag {
    public static let MAX_ID_JAG_CHARS = 16384
    public static let IDJAG_AUTHORITY_CAVEAT = "idjag_authority"
    public static let IDJAG_PROVENANCE_CAVEAT = "idjag_provenance"
    public static let GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
    public static let GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    public static let TOKEN_TYPE_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
    public static let TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    public static let TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    public static let TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
    public static let CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    static func fail(_ code: String, _ m: String) -> JSError { JSError(m, code: code) }

    /// Split on JavaScript whitespace (`/\s+/`), empty parts dropped.
    static func words(_ s: String) -> [String] {
        var out: [String] = [], cur = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            if Attest.isJSSpace(u) { if !cur.isEmpty { out.append(String(cur)); cur = String.UnicodeScalarView() } } else { cur.append(u) }
        }
        if !cur.isEmpty { out.append(String(cur)) }
        return out
    }

    static func parseScopes(_ scope: JSONValue?, _ scopes: JSONValue?) -> [String]? {
        if let s = scope?.asString { return words(s) }
        if let a = scope?.asArray { return a.compactMap { JS.nonEmptyString($0) } }
        if let a = scopes?.asArray { return a.compactMap { JS.nonEmptyString($0) } }
        return nil
    }

    /// Verify an ID-JAG. `opts` uses the reference's names (issuer, audience, clientId, nonce?, requiredScopes?, strictDraft?,
    /// clockToleranceSec?, maxTokenAgeSec?, algorithms?, jwksUri?, discover?); the key, the fetch and the single-use jti store
    /// (`consumeJti(jti, exp)`: true iff first use) are passed natively. Returns the grant.
    public static func verifyIdJag(_ jwt: JSONValue?, _ opts: JSONValue?, key: OidcKey? = nil, fetch: OidcFetch? = nil,
                                   consumeJti: ((String, JSONValue) throws -> Bool)? = nil) throws -> JSONValue {
        guard let t = jwt?.asString, !t.isEmpty else { throw fail("invalid_token", "verifyIdJag: jwt must be a non-empty string") }
        if JS.length(t) > MAX_ID_JAG_CHARS { throw fail("invalid_token", "verifyIdJag: jwt exceeds the size limit") }
        guard let o = opts?.asObject ?? (opts?.asArray != nil ? [:] : nil) else { throw fail("config", "verifyIdJag: opts is required") }
        guard JS.nonEmptyString(o["issuer"]) != nil else { throw fail("config", "verifyIdJag: opts.issuer is required") }
        guard let audience = JS.nonEmptyString(o["audience"]) else { throw fail("config", "verifyIdJag: opts.audience is required (ID-JAG is single-audience)") }
        let strict = o["strictDraft"] != .bool(false)
        if strict && consumeJti == nil { throw fail("config", "verifyIdJag: strictDraft requires opts.consumeJti (single-use store)") }
        if strict && JS.nonEmptyString(o["clientId"]) == nil {
            throw fail("config", "verifyIdJag: strictDraft requires opts.clientId (the client authenticated at the token endpoint)")
        }
        var vo: JObject = [:]
        for k in ["issuer", "audience", "nonce", "clockToleranceSec", "maxTokenAgeSec", "algorithms", "jwksUri", "discover"] {
            if let v = o[JKey(k)] { vo[JKey(k)] = v }
        }
        let baseV: JSONValue
        do { baseV = try PCAOidc.verifyIdToken(jwt, .object(vo), key: key, fetch: fetch) } catch {
            if let j = error as? JSError, let c = j.code, PCAOidc.CODES.contains(c) { throw j }
            throw fail("invalid_token", "ID-JAG verification failed")
        }
        let base = baseV.asObject!
        let audList = base["aud"]?.asArray ?? [base["aud"] ?? .null]
        if audList.count != 1 || audList[0] != .string(audience) {
            throw fail("audience", "ID-JAG must carry exactly one audience equal to the resource app (single-audience grant)")
        }
        let jws = try Jose.assertCanonicalCompactJws(jwt)
        let raw = jws.payload ?? [:]
        guard let act = raw["act"]?.asObject, let agent = JS.nonEmptyString(act["sub"]) else {
            throw fail("actor", "ID-JAG is missing a well-formed \"act\" (agent) claim with a string \"sub\"")
        }
        guard let scopes = parseScopes(raw["scope"], raw["scopes"]) else { throw fail("scope", "ID-JAG is missing the \"scope\" (or \"scopes\") claim") }
        if let req = o["requiredScopes"]?.asArray {
            for r in req where !(r.asString.map { scopes.contains($0) } ?? false) {
                throw fail("scope", "ID-JAG does not grant the required scope \"\(JS.toString(r))\"")
            }
        }
        let jti = JS.nonEmptyString(raw["jti"])
        if strict {
            if jws.header["typ"] != .string("oauth-id-jag+jwt") { throw fail("grant", "ID-JAG header typ must be \"oauth-id-jag+jwt\"") }
            guard JS.nonEmptyString(raw["client_id"]) != nil else { throw fail("grant", "ID-JAG is missing \"client_id\"") }
            if raw["client_id"] != o["clientId"] { throw fail("grant", "ID-JAG client_id does not match the expected client") }
            guard let j = jti else { throw fail("grant", "ID-JAG is missing \"jti\"") }
            let fresh = (try? consumeJti!(j, base["exp"] ?? .null)) ?? false
            if !fresh { throw fail("grant", "ID-JAG jti was already used or the single-use store failed") }
        }
        var g: JObject = ["iss": base["iss"]!, "sub": base["sub"]!, "actor": .object(act), "agent": .string(agent), "audience": .string(audience),
                          "scopes": .array(scopes.map { .string($0) }), "iat": base["iat"]!, "exp": base["exp"]!, "oidcClaims": baseV]
        if let j = jti { g["jti"] = .string(j) }
        if let n = base["nonce"] { g["nonce"] = n }
        if let c = base["cnf"] { g["cnf"] = c }
        return .object(g)
    }

    /// The PCA principal of a grant (its OIDC claims, an optional opts.principalPublic that must agree with a cnf-bound key).
    public static func idJagToPcaPrincipal(_ grant: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        guard let g = grant?.asObject ?? (grant?.asArray != nil ? [:] : nil) else { throw JSError("idJagToPcaPrincipal: grant is required") }
        return try PCAOidc.oidcPrincipal(g["oidcClaims"], opts)
    }

    /// A root capability for the grant, signed by the principal (`principalSecret` = its Ed25519 seed, whose public key must be
    /// `opts.principalPublic`), with the idjag_authority, idjag_provenance and oidc_subject caveats then `opts.extraCaveats`.
    public static func idJagToCapability(_ grant: JSONValue?, _ opts: JSONValue?, principalSecret: [UInt8]?) throws -> JSONValue {
        guard let g = grant?.asObject ?? (grant?.asArray != nil ? [:] : nil) else { throw JSError("idJagToCapability: grant is required") }
        guard let o = opts?.asObject ?? (opts?.asArray != nil ? [:] : nil) else { throw JSError("idJagToCapability: opts is required") }
        guard let secret = principalSecret else { throw JSError("idJagToCapability: opts.principalSecret must be a Uint8Array") }
        guard let pub = JS.nonEmptyString(o["principalPublic"]) else { throw JSError("idJagToCapability: opts.principalPublic is required") }
        guard let holder = JS.nonEmptyString(o["holder"]) else { throw JSError("idJagToCapability: opts.holder (the agent key) is required") }
        let principal = try idJagToPcaPrincipal(grant, .object(["principalPublic": .string(pub)]))
        guard let scopes = g["scopes"]?.asArray else { throw JSError("grant.scopes is not iterable") }
        var authority: JObject = ["type": .string(IDJAG_AUTHORITY_CAVEAT), "scopes": .array(scopes)]
        if let a = g["audience"] { authority["aud"] = a }
        var provenance: JObject = ["type": .string(IDJAG_PROVENANCE_CAVEAT)]
        for (k, from) in [("iss", "iss"), ("sub", "sub"), ("agent", "agent"), ("aud", "audience"), ("iat", "iat"), ("exp", "exp"), ("jti", "jti")] {
            if let v = g[JKey(from)] { provenance[JKey(k)] = v }
        }
        var caveats: [JSONValue] = [.object(authority), .object(provenance), principal.get("subjectCaveat")!]
        if let extra = JS.present(o["extraCaveats"]) { caveats += try JS.spread(extra) }
        guard secret.count == 32 else { throw JSError("idJagToCapability: principalSecret must be a 32-byte Ed25519 seed") }
        let key = try Ed25519Deterministic.key(seed: secret)
        guard key.id == pub else { throw JSError("idJagToCapability: principalSecret does not match opts.principalPublic") }
        let cap = try PCAIssue.mintRoot(principal: .ed25519(key), holder: holder, caveats: caveats)
        return .object(["capability": cap, "principal": principal, "scopes": .array(scopes)])
    }

    public static func isIdJagAuthorityCaveat(_ cv: JSONValue?) -> Bool {
        guard let o = cv?.asObject else { return false }
        return o["type"] == .string(IDJAG_AUTHORITY_CAVEAT) && JS.isStringArray(o["scopes"]) && JS.nonEmptyString(o["aud"]) != nil
    }

    public static func isIdJagProvenanceCaveat(_ cv: JSONValue?) -> Bool {
        guard let o = cv?.asObject else { return false }
        return o["type"] == .string(IDJAG_PROVENANCE_CAVEAT) && ["iss", "sub", "agent", "aud"].allSatisfy { o[JKey($0)]?.asString != nil }
            && (o["iat"]?.isNumber ?? false) && (o["exp"]?.isNumber ?? false)
    }

    /// The first caveat of `type` (nil when absent or malformed); a `caveats` member that is not a list throws, as the reference does.
    static func read(_ cap: JSONValue?, _ type: String, _ check: (JSONValue) -> Bool) throws -> JSONValue {
        guard let caveats = JS.present(cap?.asObject?["caveats"]) else { return .null }
        guard let list = caveats.asArray else { throw JSError("cap.caveats.find is not a function") }
        guard let cv = list.first(where: { $0.asObject?["type"] == .string(type) }) else { return .null }
        return check(cv) ? cv : .null
    }

    public static func readIdJagAuthority(_ cap: JSONValue?) throws -> JSONValue { try read(cap, IDJAG_AUTHORITY_CAVEAT, isIdJagAuthorityCaveat) }
    public static func readIdJagProvenance(_ cap: JSONValue?) throws -> JSONValue { try read(cap, IDJAG_PROVENANCE_CAVEAT, isIdJagProvenanceCaveat) }

    // ---- request shapes ----

    /// application/x-www-form-urlencoded (URLSearchParams): [A-Za-z0-9*-._] kept, space as '+', the rest %XX of the UTF-8 bytes.
    static func formEncode(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            switch b {
            case 0x41...0x5A, 0x61...0x7A, 0x30...0x39, 0x2A, 0x2D, 0x2E, 0x5F: out.unicodeScalars.append(Unicode.Scalar(b))
            case 0x20: out += "+"
            default: out += String(format: "%%%02X", b)
            }
        }
        return out
    }

    /// The members of `{...extra}`: an object's members (string keys in code-unit order: a JSON object carries no member order),
    /// an array's / a string's index entries; anything else spreads to nothing.
    static func spreadEntries(_ v: JSONValue?) -> [(String, JSONValue)] {
        switch JS.present(v) {
        case let .object(o)?: return o.keys.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }.map { ($0.s, o[$0]!) }
        case let .array(a)?: return a.enumerated().map { (String($0.offset), $0.element) }
        case let .string(s)?: return s.utf16.enumerated().map { (String($0.offset), .string(String(decoding: [$0.element], as: UTF16.self))) }
        default: return []
        }
    }

    static func formRequest(_ url: String, _ entries: [(String, JSONValue)]) -> JSONValue {
        var keys: [String] = [], vals: [String: JSONValue] = [:]
        for (k, v) in entries { if vals[k] == nil { keys.append(k) }; vals[k] = v }
        // object key order: array-index keys ascending first, then insertion order
        let idx = keys.compactMap { k in JS.indexKey(k).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        let ordered = idx + keys.filter { JS.indexKey($0) == nil }
        var params: JObject = [:], parts: [String] = []
        for k in ordered {
            guard let s = JS.nonEmptyString(vals[k]) else { continue }
            params[JKey(k)] = .string(s)
            parts.append(formEncode(k) + "=" + formEncode(s))
        }
        return .object(["url": .string(url), "method": .string("POST"),
                        "headers": .object(["content-type": .string("application/x-www-form-urlencoded"), "accept": .string("application/json")]),
                        "params": .object(params), "body": .string(parts.joined(separator: "&"))])
    }

    static func scopeParam(_ scope: JSONValue?) throws -> String? {
        guard let s = scope else { return nil }
        let parts: [String]
        if let a = s.asArray { parts = a.compactMap { JS.nonEmptyString($0) } }
        else if let str = s.asString { parts = words(str) }
        else { throw JSError("scope.split is not a function") }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }

    static func optsObject(_ opts: JSONValue?, _ fn: String) throws -> JObject {
        guard let o = opts?.asObject ?? (opts?.asArray != nil ? [:] : nil) else { throw JSError("\(fn): opts is required") }
        return o
    }

    /// The RFC 8693 token-exchange request for an ID-JAG (subject = the ID token by default).
    public static func tokenExchangeRequest(_ opts: JSONValue?) throws -> JSONValue {
        let o = try optsObject(opts, "tokenExchangeRequest")
        guard let te = JS.nonEmptyString(o["tokenEndpoint"]) else { throw JSError("tokenExchangeRequest: opts.tokenEndpoint is required") }
        guard let st = JS.nonEmptyString(o["subjectToken"]) else { throw JSError("tokenExchangeRequest: opts.subjectToken is required") }
        var e: [(String, JSONValue)] = [("grant_type", .string(GRANT_TYPE_TOKEN_EXCHANGE)), ("subject_token", .string(st)),
                                        ("subject_token_type", JS.present(o["subjectTokenType"]) ?? .string(TOKEN_TYPE_ID_TOKEN)),
                                        ("requested_token_type", JS.present(o["requestedTokenType"]) ?? .string(TOKEN_TYPE_ID_JAG))]
        if let a = o["audience"] { e.append(("audience", a)) }
        if let r = o["resource"] { e.append(("resource", r)) }
        if let s = try scopeParam(o["scope"]) { e.append(("scope", .string(s))) }
        if let at = JS.nonEmptyString(o["actorToken"]) {
            e.append(("actor_token", .string(at)))
            e.append(("actor_token_type", JS.present(o["actorTokenType"]) ?? .string(TOKEN_TYPE_JWT)))
        }
        if let c = o["clientId"] { e.append(("client_id", c)) }
        return formRequest(te, e + spreadEntries(o["extra"]))
    }

    /// The RFC 7523 jwt-bearer request presenting an ID-JAG to the resource app's token endpoint.
    public static func jwtBearerAssertion(_ opts: JSONValue?) throws -> JSONValue {
        let o = try optsObject(opts, "jwtBearerAssertion")
        guard let te = JS.nonEmptyString(o["tokenEndpoint"]) else { throw JSError("jwtBearerAssertion: opts.tokenEndpoint is required") }
        guard let assertion = JS.nonEmptyString(o["assertion"]) else { throw JSError("jwtBearerAssertion: opts.assertion is required") }
        let scope = try scopeParam(o["scope"])
        var e: [(String, JSONValue)] = [("grant_type", .string(GRANT_TYPE_JWT_BEARER)), ("assertion", .string(assertion))]
        if let s = scope { e.append(("scope", .string(s))) }
        if let c = o["clientId"] { e.append(("client_id", c)) }
        if let ca = JS.nonEmptyString(o["clientAssertion"]) {
            e.append(("client_assertion_type", .string(CLIENT_ASSERTION_TYPE_JWT_BEARER)))
            e.append(("client_assertion", .string(ca)))
        }
        var out: JObject = ["grantType": .string(GRANT_TYPE_JWT_BEARER), "assertion": .string(assertion), "request": formRequest(te, e + spreadEntries(o["extra"]))]
        if let s = scope { out["scope"] = .string(s) }
        return .object(out)
    }
}
