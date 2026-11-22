import Foundation

/// One HTTP reply to a discovery / JWKS request.
public struct OidcFetchResponse {
    public var status: Int
    public var body: String
    public var headers: [String: String]
    public init(status: Int, body: String, headers: [String: String] = [:]) { self.status = status; self.body = body; self.headers = headers }
    var ok: Bool { status >= 200 && status <= 299 }
    func header(_ name: String) -> String? { headers.first { $0.key.lowercased() == name.lowercased() }?.value }
}

/// GET `url` (accept: application/json); throws on a transport failure.
public typealias OidcFetch = (String) throws -> OidcFetchResponse

/// The key an ID token is verified under.
public enum OidcKey {
    /// One JWK (any JSON: a value that is not a usable JWK is refused).
    case jwk(JSONValue)
    /// An HMAC secret (HS256 / HS384 / HS512 only).
    case secret([UInt8])
    /// A local JWK Set.
    case set(OidcLocalJwks)
    /// A remote JWK Set with caching.
    case resolver(OidcJwks)
}

/// A local JWK Set with the reference's key selection: the key type of the alg, the kid when the header has a string kid, a
/// member `alg` / `use` / `key_ops` that must agree, the curve of the alg; no match or more than one match is refused.
public struct OidcLocalJwks {
    let keys: [JObject]

    public init(_ jwks: JSONValue?) throws {
        guard let list = jwks?.get("keys")?.asArray, list.allSatisfy({ $0.asObject != nil }) else {
            throw JSError("JSON Web Key Set malformed", code: "ERR_JWKS_INVALID")
        }
        keys = list.compactMap { $0.asObject }
    }

    var kids: Set<String> { Set(keys.compactMap { $0["kid"]?.asString }) }

    /// The one member for this header, imported for its alg.
    func select(_ header: JObject) throws -> (jwk: JObject, key: Jose.Key) {
        let alg = header["alg"]?.asString ?? ""
        let kty: String
        switch alg.prefix(2) {
        case "RS", "PS": kty = "RSA"
        case "ES": kty = "EC"
        case "Ed": kty = "OKP"
        default: throw JSError("Unsupported \"alg\" value for a JSON Web Key Set", code: "ERR_JOSE_NOT_SUPPORTED")
        }
        let kid = header["kid"]?.asString
        let candidates = keys.filter { j in
            guard j["kty"] == .string(kty) else { return false }
            if let k = kid, j["kid"] != .string(k) { return false }
            if let a = j["alg"]?.asString, a != alg { return false }
            if let u = j["use"]?.asString, u != "sig" { return false }
            if let ops = j["key_ops"]?.asArray, !ops.contains(.string("verify")) { return false }
            switch alg {
            case "ES256": return j["crv"] == .string("P-256")
            case "ES256K": return j["crv"] == .string("secp256k1")
            case "ES384": return j["crv"] == .string("P-384")
            case "ES512": return j["crv"] == .string("P-521")
            case "Ed25519": return j["crv"] == .string("Ed25519")
            case "EdDSA": return j["crv"] == .string("Ed25519") || j["crv"] == .string("Ed448")
            default: return true
            }
        }
        if candidates.isEmpty { throw JSError("no applicable key found in the JSON Web Key Set", code: "ERR_JWKS_NO_MATCHING_KEY") }
        if candidates.count > 1 { throw JSError("multiple matching keys found in the JSON Web Key Set", code: "ERR_JWKS_MULTIPLE_MATCHING_KEYS") }
        let key = try PCAOidc.importJwk(.object(candidates[0]), alg: alg, fromSet: true)
        return (candidates[0], key)
    }
}

/// A remote JWK Set (https only unless `requireHttps: false`): cached for `cacheMaxAgeSec` (default 600; a stale set is never
/// served, even when the refetch fails), refetched for an unknown kid at most once per `cooldownSec` (default 30), bodies over
/// `maxBytes` (default 1 MiB) refused. Every fetch / parse failure is code `keys`.
public final class OidcJwks {
    let uri: String
    let fetch: OidcFetch?
    let now: () -> Double
    let maxAgeMs: Double, cooldownMs: Double, maxBytes: Double
    var cache: (at: Double, set: OidcLocalJwks, kids: Set<String>)? = nil
    var lastFetch = -Double.infinity
    let lock = NSLock()

    /// `opts`: jwksUri, requireHttps?, cacheMaxAgeSec?, cooldownSec?, maxBytes?, timeoutMs? (the reference's names). `now` = ms.
    public init(_ opts: JObject, fetch: OidcFetch?, now: (() -> Double)? = nil) throws {
        guard let u = JS.nonEmptyString(opts["jwksUri"]) else { throw JSError("createOidcJwks: jwksUri is required") }
        if JS.truthy(JS.present(opts["requireHttps"]) ?? .bool(true)) && !u.lowercased().hasPrefix("https://") {
            throw JSError("createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)")
        }
        for name in ["cacheMaxAgeSec", "cooldownSec", "maxBytes", "timeoutMs"] {
            if let v = opts[JKey(name)] {
                guard v.isNumber, let n = IV.num(v), n.isFinite, n >= 0 else { throw JSError("createOidcJwks: \(name) must be a finite number >= 0") }
            }
        }
        uri = u
        self.fetch = fetch
        self.now = now ?? { Date().timeIntervalSince1970 * 1000 }
        maxAgeMs = (IV.num(opts["cacheMaxAgeSec"]) ?? 600) * 1000
        cooldownMs = (IV.num(opts["cooldownSec"]) ?? 30) * 1000
        maxBytes = IV.num(opts["maxBytes"]) ?? 1024 * 1024
        // AbortSignal.timeout(ms) throws for a non-integer or a value above 2^32-1 (Node's validateUint32): that is a refused fetch, never a call to it
        let t = IV.num(opts["timeoutMs"]) ?? 10_000
        timeoutInvalid = t != t.rounded() || t > 4_294_967_295
    }
    let timeoutInvalid: Bool

    static func keysError(_ m: String) -> JSError { JSError(m, code: "keys") }

    func refetch() throws {
        lastFetch = now()
        let set: OidcLocalJwks
        do {
            guard let f = fetch else { throw JSError("no fetch implementation") }
            if timeoutInvalid { throw JSError("The \"delay\" argument must be an unsigned 32-bit integer") }
            let res = try f(uri)
            if !res.ok { throw JSError("HTTP \(res.status)") }
            if Double(res.body.utf8.count) > maxBytes { throw JSError("response exceeds \(JS.number(maxBytes)) bytes") }
            let jwks = try StrictJSON.parseLenient(res.body)
            guard jwks.asObject?["keys"]?.asArray != nil else { throw JSError("not a JWK Set") }
            set = try OidcLocalJwks(jwks)
        } catch {
            throw Self.keysError("could not fetch the issuer signing keys from \(uri)")
        }
        let storedAt = now()
        if !storedAt.isFinite { throw Self.keysError("the clock returned a non-finite time") }
        cache = (storedAt, set, set.kids)
    }

    /// The member for this header (and its imported key), fetching / refetching as needed.
    func resolve(_ header: JObject) throws -> (jwk: JObject, key: Jose.Key) {
        lock.lock(); defer { lock.unlock() }
        let t = now()
        if !t.isFinite { throw Self.keysError("the clock returned a non-finite time") }
        if cache == nil || t - cache!.at >= maxAgeMs {
            cache = nil
            try refetch()
        } else if let kid = header["kid"]?.asString, !cache!.kids.contains(kid), t - lastFetch >= cooldownMs {
            try refetch()
        }
        return try cache!.set.select(header)
    }

    /// The selected member (public parts) for a header.
    public func resolveJwk(_ header: JObject) throws -> JObject { try resolve(header).jwk }
}

/// OpenID Connect for PCA: discovery (issuer equality, https, size caps), ID-token verification (the canonical-spelling gate,
/// an alg allow-list, jose-compatible key selection and claim checks, azp / nonce / at_hash / c_hash) with the reference's
/// stable error codes, and the principal mapping (iss#sub, an optional cnf-bound Ed25519 key).
public enum PCAOidc {
    public static let DEFAULT_ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"]
    public static let DEFAULT_MAX_DISCOVERY_BYTES = 1024 * 1024
    public static let DEFAULT_JWKS_TIMEOUT_MS = 5000
    public static let OIDC_SUBJECT_CAVEAT = "oidc_subject"
    static let CODES: Set<String> = ["config", "invalid_token", "signature", "issuer", "audience", "expired", "issued_at", "not_before",
                                     "nonce", "azp", "at_hash", "c_hash", "keys", "claims"]

    static func fail(_ code: String, _ m: String) -> JSError { JSError(m, code: code) }
    static func typeError(_ m: String) -> JSError { JSError(m) }

    // ---- discovery ----

    static func isHttps(_ u: String) -> Bool { WhatwgURL.parse(u)?.scheme == "https" }

    public static func discoveryUrl(_ issuer: JSONValue?) throws -> String {
        guard let s = issuer?.asString else { throw typeError("issuer.endsWith is not a function") }
        return (s.hasSuffix("/") ? String(s.dropLast()) : s) + "/.well-known/openid-configuration"
    }

    /// The provider metadata of `issuer` (its `issuer` member must equal it exactly). `opts`: requireHttps? (only false waives
    /// https), maxBytes? (default 1 MiB, compared as the reference does). Errors carry no code.
    public static func discoverOidc(_ issuer: JSONValue?, _ opts: JSONValue? = nil, fetch: OidcFetch?) throws -> JSONValue {
        guard let iss = JS.nonEmptyString(issuer) else { throw JSError("discoverOidc: issuer must be a non-empty string") }
        if opts == .null { throw typeError("Cannot read properties of null (reading 'requireHttps')") }
        let o = opts?.asObject ?? [:]
        let requireHttps = o["requireHttps"] != .bool(false)
        if requireHttps && !isHttps(iss) { throw JSError("discoverOidc: issuer '\(iss)' is not an https URL") }
        guard let f = fetch else { throw JSError("discoverOidc: no fetch implementation available (pass opts.fetch)") }
        let url = try discoveryUrl(.string(iss))
        let res: OidcFetchResponse
        do { res = try f(url) } catch { throw JSError("discoverOidc: fetch of \(url) failed") }
        if !res.ok { throw JSError("discoverOidc: \(url) returned HTTP \(res.status)") }
        let maxV = JS.present(o["maxBytes"]) ?? .int(Int64(DEFAULT_MAX_DISCOVERY_BYTES))
        let maxN = JS.toNumber(maxV)
        let declared = res.header("content-length").map { JS.numberFromString($0) } ?? 0
        if declared.isFinite && declared > maxN { throw JSError("discoverOidc: \(url) response exceeds \(JS.toString(maxV)) bytes") }
        if Double(res.body.utf8.count) > maxN { throw JSError("discoverOidc: \(url) response exceeds \(JS.toString(maxV)) bytes") }
        let body: JSONValue
        do { body = try StrictJSON.parseLenient(res.body) } catch { throw JSError("discoverOidc: \(url) did not return valid JSON") }
        guard let meta = body.asObject else { throw JSError("discoverOidc: metadata is not a JSON object") }
        guard let mi = JS.nonEmptyString(meta["issuer"]) else { throw JSError("discoverOidc: metadata is missing a string \"issuer\"") }
        guard let jw = JS.nonEmptyString(meta["jwks_uri"]) else { throw JSError("discoverOidc: metadata is missing a string \"jwks_uri\"") }
        if mi != iss { throw JSError("discoverOidc: metadata issuer '\(mi)' does not match requested '\(iss)'") }
        if requireHttps && !isHttps(jw) { throw JSError("discoverOidc: jwks_uri '\(jw)' is not an https URL") }
        return body
    }

    /// Discovery, then a remote JWK Set at the metadata's jwks_uri (the options reach the resolver).
    public static func createOidcJwksFromIssuer(_ issuer: JSONValue?, _ opts: JObject = [:], fetch: OidcFetch?, now: (() -> Double)? = nil) throws -> OidcJwks {
        var d: JObject = [:]
        if let r = opts["requireHttps"] { d["requireHttps"] = r }
        let meta = try discoverOidc(issuer, .object(d), fetch: fetch)
        var o = opts
        o["jwksUri"] = meta.get("jwks_uri")
        return try OidcJwks(o, fetch: fetch, now: now)
    }

    // ---- keys ----

    static let HS = ["HS256", "HS384", "HS512"], RSA = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
    static func b64(_ v: JSONValue?) -> [UInt8]? { v?.asString.flatMap { Base64URLStrict.decode($0) } }

    /// A JWK as a verification key for `alg`, refusing what the reference's importJWK / key-type check refuses (a key of another
    /// type or curve, a member `alg` that differs, private material, an Ed25519 x that is not 32 bytes, RSA under 2048 bits).
    static func importJwk(_ jwk: JSONValue, alg: String, fromSet: Bool = false) throws -> Jose.Key {
        guard let j = jwk.asObject, let kty = j["kty"]?.asString else {
            throw typeError("Key must be one of type KeyObject, CryptoKey, or Uint8Array")
        }
        if let a = j["alg"]?.asString, a != alg { throw typeError("Invalid key for this operation, its alg does not match") }
        if j["d"] != nil { throw JSError("JSON Web Key Set members must be public keys", code: "ERR_JWKS_INVALID") }
        if let u = j["use"], u != .string("sig") { throw typeError("Invalid key for this operation, its \"use\" must be \"sig\"") }
        if let ops = j["key_ops"], !(ops.asArray?.contains(.string("verify")) ?? false) {
            throw typeError("Invalid key for this operation, its \"key_ops\" must include \"verify\"")
        }
        let wrong = typeError("Invalid key for this operation (\(kty) key, alg \(alg))")
        switch kty {
        case "oct":
            guard HS.contains(alg), let k = b64(j["k"]) else { throw wrong }
            return .hmac(k)
        case "OKP":
            guard alg == "EdDSA" || alg == "Ed25519" else { throw wrong }
            if j["crv"] == .string("Ed448") && alg == "EdDSA" {
                // Ed448 verifies only when AtlasPCAOpenSSL registered a verifier; otherwise the key never verifies (the token is refused as a bad signature)
                guard PCAExtraCrypto.ed448Verify != nil else { return .hmac([]) }
                guard let x = b64(j["x"]), x.count == 57 else {
                    if fromSet { throw typeError("Invalid JWK OKP key") }
                    return .hmac([])
                }
                return .ed448(x)
            }
            guard j["crv"] == .string("Ed25519") else { throw wrong }
            guard let x = b64(j["x"]), x.count == 32 else {
                // a set member that does not import is refused; a lone key of the wrong size never verifies (as the reference)
                if fromSet { throw typeError("Invalid JWK OKP key") }
                return .hmac([])
            }
            return .ed25519(x)
        case "EC":
            let curves = ["ES256": "P-256", "ES384": "P-384", "ES512": "P-521"]
            guard let curve = curves[alg] else {
                if alg == "ES256K" { throw JSError("Unsupported key curve for this operation", code: "ERR_JOSE_NOT_SUPPORTED") }
                throw wrong
            }
            guard j["crv"] == .string(curve) else { throw wrong }
            // a coordinate that does not decode or is off the curve never verifies
            return .ec(curve: curve, point: [0x04] + (b64(j["x"]) ?? []) + (b64(j["y"]) ?? []))
        case "RSA":
            guard RSA.contains(alg) else { throw wrong }
            if j["oth"] != nil { throw JSError("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported", code: "ERR_JOSE_NOT_SUPPORTED") }
            guard let n = b64(j["n"]) else { throw typeError("Invalid JWK RSA key") }
            if BigNat(bytes: n).bitLength < 2048 { throw typeError("\(alg) requires key modulusLength to be 2048 bits or larger") }
            return .rsa(n: n, e: b64(j["e"]) ?? [])
        default:
            throw JSError("Invalid or unsupported JWK \"kty\" (Key Type) Parameter value", code: "ERR_JOSE_NOT_SUPPORTED")
        }
    }

    static func keyFor(_ source: OidcKey, header: JObject, alg: String) throws -> Jose.Key {
        switch source {
        case let .jwk(j): return try importJwk(j, alg: alg)
        case let .secret(s):
            guard HS.contains(alg) else { throw typeError("Key for the \(alg) algorithm must be of type KeyObject") }
            return .hmac(s)
        case let .set(s): return try s.select(header).key
        case let .resolver(r): return try r.resolve(header).key
        }
    }

    // ---- verify ----

    static func mapJose(_ e: Error) -> JSError {
        guard let j = e as? JSError else { return fail("invalid_token", "id token verification failed") }
        if let c = j.code, CODES.contains(c) { return j }
        switch j.code {
        case "ERR_JWT_EXPIRED"?:
            return Jose.claimOf(j) == "iat" ? fail("issued_at", "id token is older than the maximum accepted age") : fail("expired", "id token has expired")
        case "ERR_JWT_CLAIM_VALIDATION_FAILED"?:
            let code = ["iss": "issuer", "aud": "audience", "iat": "issued_at", "nbf": "not_before"][Jose.claimOf(j) ?? ""] ?? "claims"
            return fail(code, j.message)
        case "ERR_JWS_SIGNATURE_VERIFICATION_FAILED"?: return fail("signature", "id token signature verification failed")
        case let c? where c.hasPrefix("ERR_"): return fail("invalid_token", j.message)
        default: return fail("invalid_token", "id token verification failed")
        }
    }

    static func resolveSource(_ o: JObject, key: OidcKey?, fetch: OidcFetch?) throws -> OidcKey {
        if let k = key { return k }
        var uri = o["jwksUri"]
        if uri == nil && o["discover"] == .bool(true) {
            var d: JObject = [:]
            if let r = o["requireHttps"] { d["requireHttps"] = r }
            uri = try discoverOidc(o["issuer"], .object(d), fetch: fetch).get("jwks_uri")
        }
        guard let u = uri else { throw fail("config", "verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)") }
        var r: JObject = ["jwksUri": u]
        if let h = o["requireHttps"] { r["requireHttps"] = h }
        do {
            // the reference's resolver here uses the global fetch; this one has none, so every key fetch fails closed (`keys`)
            return .resolver(try OidcJwks(r, fetch: nil))
        } catch {
            throw fail("config", "verifyIdToken: \((error as? JSError)?.message ?? "\(error)")")
        }
    }

    static func halfHash(_ name: String, _ actual: String?, _ value: JSONValue, alg: String?) throws {
        guard let a = actual else { throw fail(name, "id token is missing the expected \(name)") }
        let bits: String?
        if alg == "EdDSA" { bits = "512" } else if let g = alg, let b = ["256", "384", "512"].first(where: { g.hasSuffix($0) }) { bits = b } else { bits = nil }
        guard let b = bits else { throw fail(name, "cannot compute \(name) for alg \(alg ?? "undefined")") }
        guard let v = value.asString else { throw JSError("The \"data\" argument must be of type string", code: "ERR_INVALID_ARG_TYPE") }
        let bytes = v.utf16.map { UInt8($0 & 0xff) } // Node's 'ascii' encoding keeps the low byte of each code unit
        let hash: AHash = b == "256" ? .sha256 : b == "384" ? .sha384 : .sha512
        let d = hash.digest(bytes)
        if a != Base64URLStrict.encode(Array(d[0..<(d.count / 2)])) { throw fail(name, "id token \(name) does not match the supplied value") }
    }

    static func str(_ v: JSONValue?) -> String? { JS.nonEmptyString(v) }
    static func finite(_ v: JSONValue?) -> JSONValue? { (v?.isNumber ?? false) && (IV.num(v!)?.isFinite ?? false) ? v : nil }

    static func projectClaims(_ p: JObject, _ o: JObject) throws -> JObject {
        guard let iss = str(p["iss"]) else { throw fail("issuer", "id token is missing the \"iss\" claim") }
        guard let sub = str(p["sub"]) else { throw fail("claims", "id token is missing the \"sub\" claim") }
        guard let aud = p["aud"] else { throw fail("audience", "id token is missing the \"aud\" claim") }
        guard let iat = finite(p["iat"]) else { throw fail("issued_at", "id token is missing a numeric \"iat\" claim") }
        guard let exp = finite(p["exp"]) else { throw fail("expired", "id token is missing a numeric \"exp\" claim") }
        let nonce = str(p["nonce"]), azp = str(p["azp"])
        if let want = o["nonce"], nonce.map({ JSONValue.string($0) }) != want {
            throw fail("nonce", nonce == nil ? "id token is missing the expected nonce" : "id token nonce does not match the expected value")
        }
        let audCount = aud.asArray?.count ?? 1
        let expectedAzp: JSONValue? = JS.present(o["authorizedParty"]) ?? (o["audience"]?.asString != nil ? o["audience"] : nil)
        if audCount > 1 && azp == nil { throw fail("azp", "id token has multiple audiences but no azp (authorized party)") }
        if let a = azp, let e = expectedAzp, e != .string(a) { throw fail("azp", "id token azp does not match the authorized party") }
        var c: JObject = ["iss": .string(iss), "sub": .string(sub), "aud": aud, "iat": iat, "exp": exp]
        if let n = nonce { c["nonce"] = .string(n) }
        if let a = azp { c["azp"] = .string(a) }
        for (k, out) in [("at_hash", "at_hash"), ("c_hash", "c_hash"), ("email", "email"), ("name", "name"), ("preferred_username", "preferred_username"),
                         ("given_name", "given_name"), ("family_name", "family_name"), ("picture", "picture")] {
            if let s = str(p[JKey(k)]) { c[JKey(out)] = .string(s) }
        }
        if let t = finite(p["auth_time"]) { c["auth_time"] = t }
        if case let .bool(b)? = p["email_verified"] { c["email_verified"] = .bool(b) }
        if let cnf = p["cnf"], cnf.asObject != nil { c["cnf"] = cnf }
        return c
    }

    /// Verify an ID token. `opts` uses the reference's option names (issuer, audience, nonce?, authorizedParty?, accessToken?,
    /// code?, clockToleranceSec?, maxTokenAgeSec?, algorithms?, jwksUri?, discover?, requireHttps?); the key and the fetch are
    /// passed natively. Returns the projected claims; throws JSError with the reference's code.
    public static func verifyIdToken(_ token: JSONValue?, _ opts: JSONValue?, key: OidcKey? = nil, fetch: OidcFetch? = nil) throws -> JSONValue {
        guard let t = token?.asString, !t.isEmpty else { throw fail("invalid_token", "verifyIdToken: idToken must be a non-empty string") }
        guard let o = opts?.asObject ?? (opts?.asArray != nil ? [:] : nil) else { throw fail("config", "verifyIdToken: opts is required") }
        guard JS.nonEmptyString(o["issuer"]) != nil else { throw fail("config", "verifyIdToken: opts.issuer is required") }
        let audience: [String]?
        var audPresence = false
        switch o["audience"] {
        case let .string(s)?: audience = s.isEmpty ? nil : [s]; audPresence = s.isEmpty
        case let .array(a)?: audience = a.compactMap { $0.asString }
        default: throw fail("config", "verifyIdToken: opts.audience is required")
        }
        // a non-finite skew tolerance would make every expiry comparison pass; a NaN age limit would disable the age check
        // (anything that is not a finite number is refused for the tolerance; the age limit is compared with JavaScript's coercion, so only a value that is not >= 0 is refused)
        if let v = o["clockToleranceSec"], !(v.isNumber && (IV.num(v).map { $0.isFinite && $0 >= 0 } ?? false)) { throw fail("config", "verifyIdToken: clockToleranceSec must be a finite number >= 0") }
        if let v = o["maxTokenAgeSec"], !(JS.toNumber(v) >= 0) { throw fail("config", "verifyIdToken: maxTokenAgeSec must be a number >= 0") }
        let c: Jose.CanonicalJws
        do { c = try Jose.assertCanonicalCompactJws(token) } catch { throw fail("invalid_token", (error as? JSError)?.message ?? "\(error)") }
        let source = try resolveSource(o, key: key, fetch: fetch)
        var algs: [JSONValue]
        switch JS.present(o["algorithms"]) {
        case nil: algs = DEFAULT_ID_TOKEN_ALGS.map { .string($0) }
        case let .array(a)?: algs = a
        case let .string(s)?: algs = s.unicodeScalars.map { .string(String($0)) }
        default: throw typeError("opts.algorithms is not iterable")
        }
        let payload: JObject
        do {
            guard algs.allSatisfy({ $0.asString != nil }) else { throw typeError("\"algorithms\" option must be an array of strings") }
            let alg = try Jose.checkProtectedHeader(c.header, algorithms: algs.compactMap { $0.asString })
            let k = try keyFor(source, header: c.header, alg: alg)
            let sig = try Jose.decodeCanonicalBase64url(c.segments[2])
            if !Jose.verifySignature(alg: alg, key: k, input: Array((c.segments[0] + "." + c.segments[1]).utf8), sig: sig) {
                throw JSError("signature verification failed", code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED")
            }
            try Jose.rejectUnencodedPayload(c.header)
            var vo = Jose.VerifyOptions()
            vo.issuer = [o["issuer"]!.asString!]
            vo.audience = audience
            if audPresence { vo.requiredClaims = ["aud"] }
            var deferred: JSError? = nil
            switch o["clockToleranceSec"] {
            case nil: break
            case let v? where v.isNumber: vo.clockTolerance = IV.num(v) ?? 0
            default: deferred = typeError("Invalid clockTolerance option type")
            }
            var ageTypeError = false
            switch o["maxTokenAgeSec"] {
            case nil: break
            case let v? where v.isNumber: vo.maxTokenAge = IV.num(v)
            case let v?: vo.maxTokenAge = 0; ageTypeError = JS.truthy(v)
            }
            if let d = deferred {
                // the reference checks presence / iss / sub / aud, then refuses the tolerance option
                do { try Jose.validateClaims(header: c.header, payload: c.payload!, vo) } catch let e as JSError {
                    let claim = Jose.claimOf(e)
                    if e.message.hasPrefix("missing required") || ["typ", "iss", "sub", "aud"].contains(claim ?? "") { throw e }
                }
                throw d
            }
            try Jose.validateClaims(header: c.header, payload: c.payload!, vo)
            if ageTypeError { throw typeError("Invalid time period format") }
            payload = c.payload!
        } catch {
            throw mapJose(error)
        }
        let claims = try projectClaims(payload, o)
        let alg = c.header["alg"]?.asString
        if let v = o["accessToken"] { try halfHash("at_hash", claims["at_hash"]?.asString, v, alg: alg) }
        if let v = o["code"] { try halfHash("c_hash", claims["c_hash"]?.asString, v, alg: alg) }
        return .object(claims)
    }

    // ---- principal ----

    static func canonicalEd25519(_ v: JSONValue?) -> String? {
        guard let s = v?.asString, !s.isEmpty, let raw = Base64URLStrict.decode(s), raw.count == 32, Base64URLStrict.encode(raw) == s else { return nil }
        return s
    }

    /// {iss, sub, principalId: "iss#sub", subjectCaveat, claims, principalPublic? (cnf-bound Ed25519 key or opts.principalPublic,
    /// which must agree), email?, emailVerified?, name?, preferredUsername?, authTime?}.
    public static func oidcPrincipal(_ claims: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        if claims == nil || claims == .null { throw typeError("Cannot read properties of \(claims == nil ? "undefined" : "null") (reading 'iss')") }
        let c = claims!.asObject ?? [:]
        guard let iss = JS.nonEmptyString(c["iss"]) else { throw typeError("oidcPrincipal: claims.iss is required") }
        guard let sub = JS.nonEmptyString(c["sub"]) else { throw typeError("oidcPrincipal: claims.sub is required") }
        var fromToken: String? = nil
        if let cnf = c["cnf"] {
            if cnf == .null { throw typeError("Cannot read properties of null (reading 'jwk')") }
            if let jwk = cnf.asObject?["jwk"], jwk.get("kty") == .string("OKP"), jwk.get("crv") == .string("Ed25519") {
                fromToken = canonicalEd25519(jwk.get("x"))
            }
        }
        if opts == .null { throw typeError("Cannot read properties of null (reading 'principalPublic')") }
        var principalPublic = fromToken
        if let pp = opts?.asObject?["principalPublic"] {
            guard let provided = canonicalEd25519(pp) else {
                throw typeError("oidcPrincipal: opts.principalPublic is not a canonical base64url Ed25519 public key")
            }
            if let t = fromToken, t != provided { throw JSError("oidcPrincipal: opts.principalPublic does not match the cnf-bound key in the ID token") }
            principalPublic = provided
        }
        var out: JObject = ["iss": .string(iss), "sub": .string(sub), "principalId": .string("\(iss)#\(sub)"),
                            "subjectCaveat": .object(["type": .string(OIDC_SUBJECT_CAVEAT), "iss": .string(iss), "sub": .string(sub)]),
                            "claims": claims!]
        if let p = principalPublic { out["principalPublic"] = .string(p) }
        for (k, n) in [("email", "email"), ("email_verified", "emailVerified"), ("name", "name"), ("preferred_username", "preferredUsername"), ("auth_time", "authTime")] {
            if let v = c[JKey(k)] { out[JKey(n)] = v }
        }
        return .object(out)
    }

    public static func isOidcSubjectCaveat(_ cv: JSONValue?) -> Bool {
        guard let o = cv?.asObject else { return false }
        return o["type"] == .string(OIDC_SUBJECT_CAVEAT) && JS.nonEmptyString(o["iss"]) != nil && JS.nonEmptyString(o["sub"]) != nil
    }
}
