import Foundation

/// GNAP (RFC 9635) bridge, the Agent-GNAP profile (mirrors `@atlasauth/pca-gnap`): GNAP access rights map onto policy-envelope
/// predicates (namespace `gnap:<type>:<location>`), a grant request becomes a root grant (no parent) or an attenuated delegated hop
/// recording its clamped rights as an append-only `gnap_access` caveat, the effective authority of a chain is the root envelope
/// intersected with every hop's recorded rights, access tokens carry the chain itself, `jwsd` detached-JWS proofs bind requests to
/// the holder key, and a continuation resolves through a threshold co-signature folded into the action's PCActn. Every verify path
/// fails closed; the issuance paths throw on a malformed request. Values are `JSONValue`s read with JavaScript member semantics
/// (a member of a non-object is absent; reading a member of null throws, as in the reference).
public enum PCAGnap {
    public static let GNAP_GRANT_CAVEAT = "gnap_grant"
    public static let GNAP_ACCESS_CAVEAT = "gnap_access"
    /// Upper bound on an accepted detached JWS (UTF-16 code units).
    public static let MAX_DETACHED_JWS_CHARS = 8192
    static let JWSD_TYP = "gnap-binding-jwsd"
    static let REQUEST_DOMAIN = "atlas-pca/gnap/request/v1"

    static func s(_ v: String) -> JSONValue { .string(v) }

    /// `v.k` in JavaScript: nil when absent or when `v` is not an object; reading a member of null / undefined throws.
    static func member(_ v: JSONValue?, _ k: String) throws -> JSONValue? {
        guard let v = v else { throw JSError("Cannot read properties of undefined (reading '\(k)')") }
        if v.isNull { throw JSError("Cannot read properties of null (reading '\(k)')") }
        return v.get(k)
    }

    static func strArr(_ u: JSONValue?) -> [JSONValue]? {
        guard case let .array(a)? = u else { return nil }
        return a.filter { $0.asString != nil }
    }

    static func asEd25519(_ x: JSONValue?) -> String? {
        guard let s = x?.asString, Base64URLStrict.decode(s, length: 32) != nil else { return nil }
        return s
    }

    public static func gnapActionResource(_ type: String, _ location: String) -> String { "gnap:\(type):\(location)" }

    // ---- access rights ----

    static func tryNormalizeAccessItem(_ item: JSONValue) -> JSONValue? {
        if case let .string(t) = item { return t.isEmpty ? nil : .object(["type": s(t)]) }
        guard case let .object(o) = item, let t = o["type"]?.asString, !t.isEmpty else { return nil }
        var out: JObject = ["type": s(t)]
        for k in ["actions", "locations", "datatypes", "privileges"] {
            if let l = strArr(o[JKey(k)]), !l.isEmpty { out[JKey(k)] = .array(l) }
        }
        if case .string? = o["identifier"] { out["identifier"] = o["identifier"] }
        return .object(out)
    }

    /// Normalize an access array for issuance, refusing any malformed entry.
    public static func normalizeAccess(_ items: JSONValue?) throws -> [JSONValue] {
        guard case let .array(l)? = items else { throw JSError("access must be an array") }
        return try l.map {
            guard let n = tryNormalizeAccessItem($0) else { throw JSError("malformed access item (needs a non-empty string `type`)") }
            return n
        }
    }

    /// A stored (signed) access array, malformed entries skipped.
    static func readAccessArray(_ u: JSONValue?) -> [JSONValue] { (u?.asArray ?? []).compactMap(tryNormalizeAccessItem) }

    static func nonEmptyList(_ v: JSONValue?) -> [JSONValue]? {
        guard case let .array(a)? = v, !a.isEmpty else { return nil }
        return a
    }

    /// One predicate per location: actions -> verb (absent: `*`), locations -> resource (absent: `*`), datatypes / identifier ->
    /// `where` conditions on `action.params`.
    public static func accessToPredicates(_ access: JObject) -> [JSONValue] {
        let verb: JSONValue = nonEmptyList(access["actions"]).map { .array($0) } ?? s("*")
        let locations = nonEmptyList(access["locations"]) ?? [s("*")]
        var whereC: [JSONValue] = []
        if let d = nonEmptyList(access["datatypes"]) {
            whereC.append(.object(["field": s("action.params.datatype"), "op": s("in"), "value": .array(d)]))
        }
        if case let .string(id)? = access["identifier"] {
            whereC.append(.object(["field": s("action.params.identifier"), "op": s("eq"), "value": s(id)]))
        }
        let type = JS.toString(access["type"])
        return locations.map { loc in
            var p: JObject = ["verb": verb, "resource": s(gnapActionResource(type, JS.toString(loc)))]
            if !whereC.isEmpty { p["where"] = .array(whereC) }
            return .object(p)
        }
    }

    static func accessArrayToPredicates(_ access: [JSONValue]) -> [JSONValue] { access.flatMap { accessToPredicates($0.asObject ?? [:]) } }

    static func includes(_ l: [JSONValue], _ x: JSONValue) -> Bool { l.contains { PCASdJwt.strictEq($0, x) } }

    static func coversStrings(_ g: JObject, _ r: JObject, _ k: JKey) -> Bool {
        guard let sup = g[k] else { return true } // the issuer allows all
        guard let sub = r[k] else { return false } // the request wants all, the issuer has a concrete set
        let supL = sup.asArray ?? []
        return (sub.asArray ?? []).allSatisfy { includes(supL, $0) }
    }

    static func coversLocations(_ g: JObject, _ r: JObject) -> Bool {
        guard let sup = g["locations"] else { return true }
        let supL = sup.asArray ?? []
        guard let sub = r["locations"] else { return includes(supL, s("*")) }
        return (sub.asArray ?? []).allSatisfy { sv in
            let su = Array((sv.asString ?? "").utf16)
            return supL.contains { gv in
                if PCASdJwt.strictEq(gv, sv) || gv.asString == "*" { return true }
                guard sv.asString != nil, let gs = gv.asString else { return false }
                let gu = Array(gs.utf16)
                return gu.last == 0x2a && su.starts(with: gu.dropLast())
            }
        }
    }

    /// Does the issuer's granted right `g` fully contain the requested right `r`?
    public static func accessContains(_ g: JObject, _ r: JObject) -> Bool {
        if !PCASdJwt.strictEq(g["type"], r["type"]) { return false }
        if !coversStrings(g, r, "actions") || !coversLocations(g, r) || !coversStrings(g, r, "datatypes") { return false }
        if let ri = r["identifier"], let gi = g["identifier"], !PCASdJwt.strictEq(gi, ri) { return false }
        return true
    }

    public static func accessWithin(_ granted: [JSONValue], _ r: JObject) -> Bool { granted.contains { accessContains($0.asObject ?? [:], r) } }

    /// Split a requested access array into the part within the issuer's authority and the rest.
    public static func clampAccess(_ issuerGranted: [JSONValue], _ requested: [JSONValue]) -> (granted: [JSONValue], dropped: [JSONValue]) {
        var g: [JSONValue] = [], d: [JSONValue] = []
        for r in requested { if accessWithin(issuerGranted, r.asObject ?? [:]) { g.append(r) } else { d.append(r) } }
        return (g, d)
    }

    // ---- provenance + granted access ----

    static func readGrantedAccessOfRoot(_ root: JSONValue) -> [JSONValue]? {
        guard let env = PCA.readEnvelope(root),
              let cv = (env.get("caveats")?.asArray ?? []).first(where: { $0.get("type") == s(GNAP_GRANT_CAVEAT) }) else { return nil }
        guard cv.get("client_id")?.asString != nil, cv.get("request_digest")?.asString != nil else { return nil }
        return readAccessArray(cv.get("granted_access"))
    }

    /// The effective granted access of a chain: the leaf's most recent `gnap_access` caveat, or (root only) the root grant's recorded rights.
    public static func grantedAccessOf(_ chain: JSONValue?) throws -> [JSONValue] {
        guard case let .array(l)? = chain, let leaf = l.last else { return [] }
        let caveats = try member(leaf, "caveats")?.asArray ?? []
        for c in caveats.reversed() where c.get("type") == s(GNAP_ACCESS_CAVEAT) { return readAccessArray(c.get("access")) }
        return readGrantedAccessOfRoot(l[0]) ?? []
    }

    // ---- holders ----

    /// The base64url Ed25519 holder key from the request's client key, or `holderOverride` when one is passed (`.null` is an explicit
    /// override and is refused). A declared key proof method other than `jwsd` is refused even with an override.
    public static func resolveHolder(_ req: JSONValue?, override holderOverride: JSONValue? = nil) throws -> String {
        let client = try member(req, "client")
        let declared = client?.asObject?["key"]
        if let d = declared, d.isObject || d.asArray != nil {
            let proof = d.get("proof")
            let method = proof?.asString != nil ? proof : proof?.asObject?["method"]
            if method?.asString != "jwsd" {
                throw JSError("unsupported client key proof method: \(method?.asString ?? "none") (only jwsd is supported)")
            }
        }
        if let o = holderOverride {
            guard let h = asEd25519(o) else { throw JSError("holder override is not a canonical base64url Ed25519 public key") }
            return h
        }
        if let jwk = declared?.asObject?["jwk"]?.asObject, jwk["kty"] == s("OKP"), jwk["crv"] == s("Ed25519"), let x = asEd25519(jwk["x"]) { return x }
        throw JSError("cannot resolve holder: supply client.key.jwk (OKP/Ed25519) or a holder override")
    }

    /// The holder key as a GNAP JWK.
    public static func holderJwk(_ holder: String) -> JSONValue {
        .object(["kty": s("OKP"), "crv": s("Ed25519"), "x": s(holder), "use": s("sig"), "alg": s("EdDSA")])
    }

    static func accessOf(_ req: JSONValue?) throws -> JSONValue {
        let at = try member(req, "access_token")
        if let a = at?.asObject?["access"], a.asArray != nil { return a }
        throw JSError("grant request must carry access_token.access (single-token request)")
    }

    static func requestDigest(_ holder: String, _ granted: [JSONValue], _ interact: JSONValue?) throws -> String {
        let v: JSONValue = .object(["d": s(REQUEST_DOMAIN), "client_id": s(holder), "access": .array(granted), "interact": interact ?? .null])
        return Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v)))
    }

    static func edKey(_ seed: [UInt8]?) throws -> PCAEdKey {
        guard let sd = seed else { throw JSError("signWithSuite: 'ed25519' requires edSecret") }
        guard sd.count == 32 else { throw JSError("private key of length 32 expected, got \(sd.count)") }
        return try Ed25519Deterministic.key(seed: sd)
    }

    // ---- grant request -> capability ----

    /// Options of `grantRequestToCapability`. A truthy `parent` delegates a hop from it (signed by `issuerSeed`, the parent holder's
    /// key); otherwise a root grant is minted by the principal (`issuerSeed`, whose public key `issuerPublic` must be).
    public struct GrantOptions {
        public var issuerSeed: [UInt8]?
        public var issuerPublic: String?
        public var parent: JSONValue?
        /// The issuer chain the clamp reads (default `[parent]`).
        public var issuerChain: [JSONValue]?
        /// Drop requested rights beyond the issuer's authority (default true).
        public var clampToIssuer = true
        /// An explicit holder override (`.null` is refused).
        public var holder: JSONValue?
        public var interacted = false
        /// Epoch ms (default now); floored.
        public var now: Double?
        public var goal: String?
        public var riskPolicy: JSONValue?
        public var agentBinding: JSONValue?
        public var salt: String?
        public init() {}
    }

    /// A GNAP grant request as a capability bound to the client key, never wider than the issuer: `{grant, chain, holder,
    /// grantedAccess, droppedAccess, provenance}`.
    public static func grantRequestToCapability(_ req: JSONValue?, _ o: GrantOptions) throws -> JSONValue {
        let holder = try resolveHolder(req, override: o.holder)
        let requested = try normalizeAccess(try accessOf(req))
        let now = Int64(((o.now ?? Date().timeIntervalSince1970 * 1000)).rounded(.down))
        let delegated = JS.truthy(o.parent)
        let issuerChain = o.issuerChain ?? (o.parent.map { [$0] } ?? [])
        var granted = requested, dropped: [JSONValue] = []
        if delegated && o.clampToIssuer {
            (granted, dropped) = clampAccess(try grantedAccessOf(.array(issuerChain)), requested)
        }
        let digest = try requestDigest(holder, granted, try member(req, "interact"))
        func result(_ grant: JSONValue, _ chain: [JSONValue], _ prov: JObject) -> JSONValue {
            .object(["grant": grant, "chain": .array(chain), "holder": s(holder), "grantedAccess": .array(granted),
                     "droppedAccess": .array(dropped), "provenance": .object(prov)])
        }
        if delegated {
            let prov: JObject = ["type": s(GNAP_ACCESS_CAVEAT), "access": .array(granted), "predicates": .array(accessArrayToPredicates(granted)),
                                 "request_digest": s(digest), "client_id": s(holder), "ts": .int(now)]
            let key = try edKey(o.issuerSeed)
            guard let parent = o.parent, parent.isObject else { throw JSError("canonicalize: unsupported type undefined") }
            let child = try PCAIssue.delegate(parent: parent, toHolder: holder, added: [.object(prov)], signer: .ed25519(key))
            return result(child, issuerChain + [child], prov)
        }
        let prov: JObject = ["type": s(GNAP_GRANT_CAVEAT), "client_id": s(holder), "granted_access": .array(granted), "request_digest": s(digest),
                             "interacted": .bool(o.interacted), "ts": .int(now)]
        let key = try edKey(o.issuerSeed)
        guard let pub = o.issuerPublic else { throw JSError("canonicalize: unsupported type undefined") }
        if pub != key.id { throw JSError("issuerPublic is not the public key of issuerSecret") } // the reference would sign an unverifiable root
        let env: JObject = ["predicates": .array(accessArrayToPredicates(granted)), "caveats": .array([.object(prov)]),
                            "agent_binding": o.agentBinding ?? .object([:]), "risk_policy": o.riskPolicy ?? .object(PCAFacade.DEFAULT_RISK_POLICY)]
        let m = try PCAIssue.mintGrant(principal: .ed25519(key), holder: holder, envelope: env, goal: o.goal ?? "gnap:grant:\(holder)", salt: o.salt)
        return result(m.grant, [m.grant], prov)
    }

    // ---- action authorization ----

    /// The chain-root pins: `expectedRootIssuer` (nil: any root) and the verifier-side PQ pins by Ed25519 identity.
    public struct ChainPins {
        public var expectedRootIssuer: String?
        public var pqPins: [String: String]?
        public init(expectedRootIssuer: String? = nil, pqPins: [String: String]? = nil) { self.expectedRootIssuer = expectedRootIssuer; self.pqPins = pqPins }
    }

    static func chainError(_ chain: [JSONValue], _ p: ChainPins) -> String? {
        Capability.verifyChain(chain, expectedRootIssuer: p.expectedRootIssuer, pqPins: p.pqPins)
    }

    /// Is `action` ({verb, resource, params?, reversibility_class?}) authorized by a GNAP-issued chain? The chain verifies, the root
    /// envelope permits the action, and every `gnap_access` caveat of the leaf permits it too. `{allowed, reason?}`; fails closed.
    public static func authorizeGnapAction(_ chain: JSONValue?, _ action: JSONValue?, _ pins: ChainPins = ChainPins()) throws -> JSONValue {
        func deny(_ r: String) -> JSONValue { .object(["allowed": .bool(false), "reason": s(r)]) }
        guard case let .array(l)? = chain, !l.isEmpty else { return deny("empty chain") }
        if let why = chainError(l, pins) { return deny("capability chain invalid: \(why)") }
        guard let env = PCA.readEnvelope(l[0]) else { return deny("root grant carries no policy envelope") }
        var a: JObject = [:]
        for k in ["verb", "resource"] { if let v = try member(action, k) { a[JKey(k)] = v } }
        for k in ["params", "reversibility_class"] { if let v = action?.get(k) { a[JKey(k)] = v } }
        let ctx: JSONValue = .object(["action": .object(a)])
        if let why = PCA.envelopePredicatesError(env.get("predicates"), ctx, SafeRegex.Budget()) { return deny("root authority denies: \(why)") }
        for c in l[l.count - 1].get("caveats")?.asArray ?? [] where c.get("type") == s(GNAP_ACCESS_CAVEAT) {
            let preds = JSONValue.array(accessArrayToPredicates(readAccessArray(c.get("access"))))
            if let why = PCA.envelopePredicatesError(preds, ctx, SafeRegex.Budget()) { return deny("delegated hop denies: \(why)") }
        }
        return .object(["allowed": .bool(true)])
    }

    // ---- bound token ----

    /// A capability's members in the order the reference creates them (an object has no insertion order here; nested objects are canonical).
    static let CAP_ORDER = ["id", "issuer", "holder", "caveats", "body_digest", "sig", "parent", "holder_pq", "alg", "pq_pk", "pq_sig"]

    /// A capability chain as a GNAP access-token value: base64url(JSON of the chain).
    /// shortcut: a non-capability object member order is canonical (JSONValue keeps none); a hand-built chain with unsorted plain
    /// objects encodes differently from the reference. Chains this bridge issues are exact.
    public static func encodeBoundToken(_ chain: [JSONValue]) -> String {
        Base64URLStrict.encode(Canonical.utf8("[" + chain.map(stringifyHop).joined(separator: ",") + "]"))
    }

    /// JSON.stringify of one hop: the capability members in CAP_ORDER, any other member after (code-unit order), nested values canonical.
    static func stringifyHop(_ v: JSONValue) -> String {
        guard case let .object(o) = v else { return JS.stringify(v) }
        let named = CAP_ORDER.map { JKey($0) }.filter { o[$0] != nil }
        let rest = o.keys.filter { !CAP_ORDER.contains($0.s) }.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }
        return "{" + (named + rest).map { Canonical.canonicalize(.string($0.s)) + ":" + JS.stringify(o[$0]!) }.joined(separator: ",") + "}"
    }

    static func isCapabilityShape(_ x: JSONValue) -> Bool {
        guard case let .object(o) = x else { return false }
        for k in ["id", "issuer", "holder", "body_digest", "sig"] where o[JKey(k)]?.asString == nil { return false }
        guard o["caveats"]?.asArray != nil else { return false }
        for k in ["parent", "alg", "pq_pk", "pq_sig"] { if let v = o[JKey(k)], v.asString == nil { return false } }
        return true
    }

    static func decodeBoundToken(_ value: String) -> [JSONValue]? {
        guard var raw = Base64URLStrict.decode(value) else { return nil }
        if raw.starts(with: [0xEF, 0xBB, 0xBF]) { raw.removeFirst(3) } // a UTF-8 decoder drops a leading BOM
        let text = String(decoding: raw, as: UTF8.self)
        guard Array(text.utf8) == raw, case let .array(l)? = try? StrictJSON.parse(text), l.allSatisfy(isCapabilityShape) else { return nil }
        return l
    }

    /// A capability chain as a GNAP grant response with a bound access token. `opts` members (JSON): expiresIn, bearer, instanceId,
    /// manageUri, continue; a present member (null included) is carried, as in the reference.
    public static func capabilityToGrantResponse(_ chain: JSONValue?, _ opts: JObject = [:]) throws -> JSONValue {
        guard case let .array(l)? = chain, let leaf = l.last else { throw JSError("capabilityToGrantResponse: empty chain") }
        var token: JObject = ["value": s(encodeBoundToken(l)), "access": .array(try grantedAccessOf(chain))]
        token["key"] = opts["bearer"] == .bool(true) ? .bool(false) : holderJwk(JS.toString(try member(leaf, "holder")))
        if let e = opts["expiresIn"] { token["expires_in"] = e }
        if let m = opts["manageUri"] { token["manage"] = .object(["uri": m]) }
        var out: JObject = ["access_token": .object(token)]
        if let c = opts["continue"] { out["continue"] = c }
        if let i = opts["instanceId"] { out["instance_id"] = i }
        return .object(out)
    }

    /// Verify an incoming bound token: `{ok:true, principal, capability, chain, access}` or `{ok:false, reason}`.
    public static func verifyGnapToken(_ value: JSONValue?, _ pins: ChainPins = ChainPins()) -> JSONValue {
        func fail(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": s(r)]) }
        guard let v = value?.asString, !v.isEmpty else { return fail("token value is empty") }
        guard let chain = decodeBoundToken(v), let root = chain.first, let leaf = chain.last else { return fail("token is not a decodable PCA capability chain") }
        if let why = chainError(chain, pins) { return fail("capability chain invalid: \(why)") }
        let access = (try? grantedAccessOf(.array(chain))) ?? []
        return .object(["ok": .bool(true), "principal": root.get("issuer") ?? .null, "capability": leaf, "chain": .array(chain), "access": .array(access)])
    }

    // ---- jwsd detached-JWS proofs ----

    /// The content a jwsd proof covers: none (empty payload), exact text or bytes (hashed as sent), or a JSON value (hashed as its
    /// strict canonical JSON, which is then the content the sender transmits).
    public enum Content {
        case none
        case text(String)
        case bytes([UInt8])
        case json(JSONValue)
    }

    /// JSON.parse(JSON.stringify(v)): -0 becomes 0.
    static func toPlain(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .double(d) where d == 0: return .int(0)
        case let .array(a): return .array(a.map(toPlain))
        case let .object(o): return .object(o.mapValues(toPlain))
        default: return v
        }
    }

    /// The jwsd payload (RFC 9635 7.3.3): the SHA-256 of the content, or nothing for no content.
    public static func gnapContentDigest(_ body: Content) throws -> [UInt8] {
        switch body {
        case .none: return []
        case let .text(t): return Canonical.sha256(Canonical.utf8(t))
        case let .bytes(b): return Canonical.sha256(b)
        case let .json(v): return Canonical.sha256(try Canonical.canonicalBytes(toPlain(v)))
        }
    }

    static func ath(_ v: String) -> String { Base64URLStrict.encode(Canonical.sha256(Canonical.utf8(v))) }

    /// A jwsd proof request: `created` (epoch seconds, default now), `kid` and `accessTokenValue` absent when nil.
    public struct SignArgs {
        public var body: Content
        public var seed: [UInt8]
        /// The key pair's public half when the caller holds it (it must be the seed's).
        public var publicKey: [UInt8]?
        public var htm: String
        public var uri: JSONValue
        public var created: JSONValue?
        public var kid: JSONValue?
        public var accessTokenValue: String?
        public init(body: Content, seed: [UInt8], htm: String, uri: JSONValue) { self.body = body; self.seed = seed; self.htm = htm; self.uri = uri }
    }

    /// A jwsd detached-JWS proof over the body, signed by the client key: `{detachedJws, header, holder}`.
    public static func signGnapRequest(_ a: SignArgs) throws -> JSONValue {
        guard a.seed.count == 32 else { throw JSError("Invalid JWK OKP key", code: "ERR_CRYPTO_INVALID_JWK") }
        let key = try Ed25519Deterministic.key(seed: a.seed)
        if let p = a.publicKey, p != key.pub { throw JSError("Invalid JWK OKP key", code: "ERR_CRYPTO_INVALID_JWK") }
        var h: JObject = ["alg": s("EdDSA"), "typ": s(JWSD_TYP), "htm": s(a.htm.uppercased()), "uri": a.uri,
                          "created": a.created ?? PCASdJwt.jnum((Date().timeIntervalSince1970).rounded(.down))]
        if let k = a.kid { h["kid"] = k }
        if let t = a.accessTokenValue { h["ath"] = s(ath(t)) }
        let payload = try gnapContentDigest(a.body)
        let prot = Base64URLStrict.encode(Canonical.utf8(JS.stringify(.object(h), order: ["alg", "typ", "htm", "uri", "created", "kid", "ath"])))
        let sig = try key.sign(Canonical.utf8(prot + "." + Base64URLStrict.encode(payload)))
        return .object(["detachedJws": s("\(prot)..\(Base64URLStrict.encode(sig))"), "header": .object(h), "holder": s(key.id)])
    }

    /// A jwsd proof to verify. `seenProof` is the replay store: called once per otherwise valid proof with sha256(detachedJws) and the
    /// proof's expiry (epoch seconds); true, nil (no answer) or a throw means replayed. Without a store, `replayUnchecked` must be set
    /// explicitly, or the call throws.
    public struct VerifyArgs {
        public var detachedJws: JSONValue?
        public var body: Content
        public var holder: JSONValue?
        public var htm: JSONValue?
        public var uri: JSONValue?
        /// Max accepted age of `created` in seconds (default 300).
        public var maxAgeSec: Double?
        /// Epoch ms (default now).
        public var now: Double?
        public var accessTokenValue: String?
        public var seenProof: ((String, Double) throws -> Bool?)?
        public var replayUnchecked = false
        public init(detachedJws: JSONValue?, body: Content, holder: JSONValue?, htm: JSONValue?, uri: JSONValue?) {
            self.detachedJws = detachedJws; self.body = body; self.holder = holder; self.htm = htm; self.uri = uri
        }
    }

    /// The reference JOSE library's protected-header gate for an Ed25519 key: `crit` a non-empty array naming only `b64` (present,
    /// boolean), alg EdDSA.
    static func joseAccepts(_ h: JObject) -> Bool {
        if let c = h["crit"] {
            guard let l = c.asArray, !l.isEmpty, l.allSatisfy({ $0.asString == "b64" }) else { return false }
            guard case .bool? = h["b64"] else { return false }
        }
        return h["alg"] == s("EdDSA")
    }

    /// Verify a jwsd proof and bind the request to the holder key: `{ok:true, holder, header}` or `{ok:false, reason}`.
    public static func verifyGnapRequest(_ a: VerifyArgs) throws -> JSONValue {
        if a.seenProof == nil && !a.replayUnchecked {
            throw JSError("verifyGnapRequest: supply args.seenProof (a replay store) or set args.replayCheck to 'unchecked'")
        }
        func fail(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": s(r)]) }
        guard let jws = a.detachedJws?.asString else { return fail("malformed jwsd request") }
        if JS.length(jws) > MAX_DETACHED_JWS_CHARS { return fail("detached JWS exceeds the size limit") }
        let parts = jws.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if parts.count != 3 { return fail("not a compact JWS (expected three dot-separated parts)") }
        let (prot, mid, sigSeg) = (parts[0], parts[1], parts[2])
        guard let holder = asEd25519(a.holder) else { return fail("holder is not a canonical base64url Ed25519 public key") }
        guard let digest = try? gnapContentDigest(a.body) else { return fail("malformed jwsd request") }
        let payload = Base64URLStrict.encode(digest)
        if mid != "" && mid != payload { return fail("not a DETACHED compact JWS") }
        let header: JObject, sig: [UInt8]
        do {
            if JS.length(prot) + JS.length(sigSeg) > Jose.DEFAULT_MAX_JWS_BYTES { throw Jose.canonicalError("too-long") }
            if prot.isEmpty || sigSeg.isEmpty { throw Jose.canonicalError("empty-segment") }
            guard let hv = try Jose.parseJSONBytes(try Jose.decodeCanonicalBase64url(prot)).asObject else { throw Jose.canonicalError("not-an-object") }
            header = hv
            sig = try Jose.decodeCanonicalBase64url(sigSeg)
        } catch {
            return fail("non-canonical detached JWS: \((error as? JSError)?.message ?? "malformed")")
        }
        guard joseAccepts(header), sig.count == 64, let pk = Base64URLStrict.decode(holder, length: 32),
              Ed25519Strict.verify(publicKey: pk, message: Canonical.utf8(prot + "." + payload), signature: sig) else {
            return fail("jwsd signature does not verify under the holder key (or body was tampered)")
        }
        if header["typ"] != s(JWSD_TYP) { return fail("unexpected typ (not gnap-binding-jwsd)") }
        guard let htm = header["htm"]?.asString else { return fail("htm does not match the request method") }
        guard let want = a.htm?.asString else { return fail("malformed jwsd request") }
        if htm.uppercased() != want.uppercased() { return fail("htm does not match the request method") }
        guard let uri = header["uri"]?.asString, a.uri?.asString == uri else { return fail("uri does not match the request target") }
        guard let createdV = header["created"], createdV.isNumber, let created = IV.num(createdV), created.isFinite else { return fail("missing or malformed created") }
        let nowSec = ((a.now ?? Date().timeIntervalSince1970 * 1000) / 1000).rounded(.down)
        let maxAge = a.maxAgeSec ?? 300
        if !(nowSec.isFinite && created <= nowSec + 60) { return fail("created is in the future") }
        if !(maxAge.isFinite && nowSec - created <= maxAge) { return fail("jwsd proof is stale") }
        let athV = header["ath"]?.asString
        if let t = a.accessTokenValue, athV != ath(t) { return fail("ath does not bind the named access token") }
        if let seen = a.seenProof {
            let replayed: Bool
            do { replayed = try seen(ath(jws), created + maxAge) != false } catch { replayed = true }
            if replayed { return fail("jwsd proof replayed (or the replay store failed)") }
        }
        var out: JObject = ["alg": s("EdDSA"), "typ": s(JWSD_TYP), "htm": s(htm), "uri": s(uri), "created": createdV]
        if case .string? = header["kid"] { out["kid"] = header["kid"] }
        if let t = athV { out["ath"] = s(t) }
        return .object(["ok": .bool(true), "holder": s(holder), "header": .object(out)])
    }

    // ---- continuation -> step-up ----

    /// Does a grant request need a continuation? Interaction requested, an explicit tier above 1, or (given the issuer's chain) rights
    /// beyond the issuer's authority. `tier` nil = derived (3 with rights beyond, else 2). `{required, reason, beyond, tier}`.
    public static func gnapRequestRequiresStepUp(_ req: JSONValue?, issuerChain: [JSONValue]? = nil, tier: JSONValue? = nil) throws -> JSONValue {
        var beyond: [JSONValue] = []
        if let ch = issuerChain {
            let g = try grantedAccessOf(.array(ch))
            for r in try normalizeAccess(try accessOf(req)) where !accessWithin(g, r.asObject ?? [:]) { beyond.append(r) }
        }
        var interactRequested = false
        if let it = try member(req, "interact") {
            if case let .array(st)? = try member(it, "start") { interactRequested = !st.isEmpty }
        }
        let tierGt1 = tier.map { JS.toNumber($0) > 1 } ?? false
        let required = interactRequested || !beyond.isEmpty || tierGt1
        let t: JSONValue = JS.present(tier) ?? .int(beyond.isEmpty ? 2 : 3)
        let reason = !required ? "no step-up required"
            : !beyond.isEmpty ? "requested rights exceed the issuer's authority (\(beyond.count) right(s) beyond)"
            : interactRequested ? "GNAP interaction requested" : "tier \(JS.toString(t)) step-up required"
        return .object(["required": .bool(required), "reason": s(reason), "beyond": .array(beyond), "tier": t])
    }

    /// Emit the `continue` handle (a grant response with no token yet) and the step-up it resolves through. `args`: signerSet, t,
    /// tier, continueUri, continueToken, wait?, reason?.
    public static func beginGnapContinuation(_ args: JObject) -> JSONValue {
        var cont: JObject = ["uri": args["continueUri"] ?? .null, "access_token": .object(["value": args["continueToken"] ?? .null, "bound": .bool(true)])]
        if let w = args["wait"] { cont["wait"] = w }
        let reason = JS.present(args["reason"]) ?? s("tier \(JS.toString(args["tier"])) co-signature required to continue")
        var step: JObject = ["reason": reason]
        for k in ["tier", "t", "signerSet", "continueToken"] { if let v = args[JKey(k)] { step[JKey(k)] = v } }
        return .object(["response": .object(["continue": .object(cont)]), "stepUp": .object(step)])
    }

    static let ROLES: Set<String> = ["agent", "guardian", "principal"]

    /// A threshold `t`: exactly 1, 2 or 3.
    static func thresholdT(_ t: JSONValue?) -> Int? {
        guard let v = t, v.isNumber, let d = IV.num(v), d == 1 || d == 2 || d == 3 else { return nil }
        return Int(d)
    }

    /// The reference signerSetHash over whatever is there: rows {publicKey: String(x), role: String(x), pq_pk if a string}, stably
    /// sorted by the UTF-8 bytes of (role, publicKey); a non-array set hashes as empty.
    public static func signerSetHash(_ set: JSONValue?) throws -> [UInt8] {
        var rows: [(role: String, pk: String, pq: String?)] = []
        for e in set?.asArray ?? [] {
            rows.append((JS.toString(e.get("role")), JS.toString(e.get("publicKey")), e.get("pq_pk")?.asString))
        }
        let sorted = rows.enumerated().sorted { x, y in
            let c = Canonical.compareUtf8(x.element.role, y.element.role)
            if c != 0 { return c < 0 }
            let d = Canonical.compareUtf8(x.element.pk, y.element.pk)
            return d != 0 ? d < 0 : x.offset < y.offset
        }.map { r -> JSONValue in
            var row: JObject = ["publicKey": s(r.element.pk), "role": s(r.element.role)]
            if let q = r.element.pq { row["pq_pk"] = s(q) }
            return .object(row)
        }
        return Canonical.sha256(Threshold.SIGNER_SET_DOMAIN + (try Canonical.canonicalBytes(.array(sorted))))
    }

    static func shareMessage(_ role: String, _ message: [UInt8], _ set: JSONValue?, _ t: JSONValue?) throws -> [UInt8] {
        guard let tt = thresholdT(t) else { throw JSError("shareMessage: t must be 1, 2 or 3") }
        return Canonical.utf8("atlas-pca/share/\(role)") + [0] + Canonical.sha256(message) + (try signerSetHash(set)) + [UInt8(tt)]
    }

    public static func signShare(_ role: String, _ seed: [UInt8], _ message: [UInt8], _ set: JSONValue?, _ t: JSONValue?) throws -> JObject {
        let m = try shareMessage(role, message, set, t)
        let key = try edKey(seed)
        return ["role": s(role), "publicKey": s(key.id), "sig": s(Base64URLStrict.encode(try key.sign(m)))]
    }

    /// One role's step-up co-signature share over a PCActn body, bound to the signer set and t.
    public static func gnapStepUpShare(_ body: JObject, role: String, seed: [UInt8], signerSet: JSONValue?, t: JSONValue?) throws -> JSONValue {
        .object(try signShare(role, seed, try PCA.thresholdMessage(body), signerSet, t))
    }

    static func show(_ v: JSONValue?) -> String {
        switch v {
        case .array?: return "<array>"
        case .object?: return "<object>"
        default: return JS.toString(v)
        }
    }

    /// The reference verifyThreshold (no leaf baseline) over Ed25519 shares: the signer set is validated first (known roles, a canonical
    /// key per entry, a well-formed pq_pk, one key per role, one role per key), then the DISTINCT registered keys with a valid role / set /
    /// t-bound share are counted. A role that registers a pq_pk is never satisfied by an Ed25519 share. `{ok, count, roles, reason?}`.
    public static func verifyThreshold(_ shares: [JObject], _ message: [UInt8], _ set: JSONValue?, _ t: JSONValue?) -> JSONValue {
        func verdict(_ roles: [String], _ reason: String?) -> JSONValue {
            var v: JObject = ["ok": .bool(reason == nil), "count": .int(Int64(roles.count)), "roles": .array(roles.map { s($0) })]
            if let r = reason { v["reason"] = s(r) }
            return .object(v)
        }
        guard let tt = thresholdT(t) else { return verdict([], "invalid threshold t=\(show(t)) (must be 1, 2 or 3)") }
        var reg: [String: String] = [:], pqOf: [String: String] = [:], seen: [String: String?] = [:]
        for e in set?.asArray ?? [] {
            let o = e.asObject
            let role = o?["role"]?.asString.flatMap { ROLES.contains($0) ? $0 : nil }
            let pk = o?["publicKey"]?.asString ?? ""
            let keyOK = o?["publicKey"]?.asString != nil && Base64URLStrict.decode(pk, length: 32) != nil
            var pqOK = true
            var pq: String? = nil
            if let pv = o?["pq_pk"] {
                if let ps = pv.asString, let b = Base64URLStrict.decode(ps), Threshold.PQ_PK_LENGTHS.contains(b.count) { pq = ps } else { pqOK = false }
            }
            guard let r = role, keyOK else { return verdict([], "malformed signer set") }
            let id = r + "\u{0}" + pk
            if pqOK, let prev = seen[id], prev != pq { pqOK = false } else if pqOK { seen[id] = pq }
            if !pqOK { return verdict([], "malformed signer set (pq_pk)") }
            if let k = reg[r], k != pk { return verdict([], "signer set registers more than one key for role \(r)") }
            if reg.contains(where: { $0.value == pk && $0.key != r }) { return verdict([], "signer set registers one key under two roles") }
            if reg[r] == nil { reg[r] = pk; if let q = pq { pqOf[r] = q } }
        }
        var keys = Set<String>(), roles: [String] = [], reason: String? = nil
        func note(_ r: String) { if reason == nil { reason = r } }
        for sh in shares {
            guard let role = sh["role"]?.asString, let pk = sh["publicKey"]?.asString else { note("malformed share"); continue }
            if keys.contains(pk) { continue }
            guard let want = reg[role] else { note("role \(role) is not in the signer set"); continue }
            if want != pk { note("share for role \(role) uses a key not registered for that role"); continue }
            guard pqOf[role] == nil, let m = try? shareMessage(role, message, set, t), let sig = sh["sig"]?.asString,
                  Ed25519Strict.verifyB64u(pk, m, sig) else { note("invalid signature for role \(role)"); continue }
            keys.insert(pk)
            roles.append(role)
        }
        if roles.count >= tt { return verdict(roles, nil) }
        return verdict(roles, reason ?? "only \(roles.count) distinct valid key(s), need \(show(t))")
    }

    /// Resolve a continuation: build the action's PCActn (signed by the agent leaf key), fold the agent share and the step-up
    /// co-signatures into its threshold and verify that `t` is reached: `{pcactn, threshold, verdict}`.
    public struct ContinuationArgs {
        public var grant: JSONValue
        public var chain: [JSONValue]
        public var plan: [JObject]
        public var nodeId: String
        public var params: JSONValue?
        public var counter: Int64
        public var aud: String
        /// Epoch ms (default now).
        public var now: Int64?
        public var ttlMs: Int64?
        public var agentLeafSeed: [UInt8]
        public var signerSet: JSONValue?
        public var t: JSONValue?
        public var cosigns: [(role: String, seed: [UInt8])]
        public init(grant: JSONValue, chain: [JSONValue], plan: [JObject], nodeId: String, counter: Int64, aud: String, agentLeafSeed: [UInt8],
                    signerSet: JSONValue?, t: JSONValue?, cosigns: [(role: String, seed: [UInt8])]) {
            self.grant = grant; self.chain = chain; self.plan = plan; self.nodeId = nodeId; self.counter = counter; self.aud = aud
            self.agentLeafSeed = agentLeafSeed; self.signerSet = signerSet; self.t = t; self.cosigns = cosigns
        }
    }

    public static func completeGnapContinuation(_ a: ContinuationArgs) throws -> JSONValue {
        if a.chain.isEmpty { throw JSError("completeGnapContinuation: empty chain") }
        let key = try edKey(a.agentLeafSeed)
        let spec = PCAIssue.ActSpec(grant: a.grant, chain: a.chain, plan: try PCAIssue.commitPlan(a.plan), nodeId: a.nodeId, params: a.params,
                                    counter: a.counter, signer: .ed25519(key), aud: a.aud,
                                    iat: a.now ?? Int64(Date().timeIntervalSince1970 * 1000), ttlMs: a.ttlMs)
        guard case var .object(p) = try PCAIssue.buildPCActn(spec) else { throw JSError("buildPCActn") }
        let msg = try PCA.thresholdMessage(p)
        var shares = [try signShare("agent", a.agentLeafSeed, msg, a.signerSet, a.t)]
        for c in a.cosigns { shares.append(try signShare(c.role, c.seed, msg, a.signerSet, a.t)) }
        let threshold: JSONValue = .object(["shares": .array(shares.map { .object($0) })])
        let verdict = verifyThreshold(shares, msg, a.signerSet, a.t)
        p["threshold"] = threshold
        return .object(["pcactn": .object(p), "threshold": threshold, "verdict": verdict])
    }

    // ---- the profile ----

    public static let AGENT_GNAP_PROFILE: JSONValue = {
        func mp(_ g: String, _ p: String, _ n: String) -> JSONValue { .object(["gnap": .string(g), "pca": .string(p), "note": .string(n)]) }
        return .object([
            "name": .string("agent-gnap"), "version": .string("1.0"), "rfc": .string("RFC 9635"),
            "summary": .string("A GNAP profile for autonomous-agent delegation: each A2A hop is a GNAP grant whose authority is "
                + "issued as an attenuated, key-bound PCA capability, never wider than the issuing agent."),
            "mapping": .array([
                mp("access[].type", "predicate resource namespace gnap:<type>:<location>", "the resource family the rights live in"),
                mp("access[].actions", "predicate.verb (list, or * for any)", "the operations permitted"),
                mp("access[].locations", "predicate.resource (exact or trailing-* prefix)", "the resource targets"),
                mp("access[].datatypes / identifier", "predicate.where on action.params.*", "value-level constraints"),
                mp("client.key.jwk (OKP/Ed25519)", "capability.holder (cnf-bound key)", "the proof-of-possession key"),
                mp("grant request (no prior grant)", "mintGrant → root capability", "envelope predicates = requested access"),
                mp("grant request (delegated hop)", "delegate → child capability + gnap_access caveat", "append-only attenuation"),
                mp("access_token (§3.2)", "a verifiable PCA capability chain (encodeBoundToken)", "bound, self-verifying token"),
                mp("continue (§3.1) + interact (§3.3)", "PCA step-up: FROST/threshold co-signature folded into a PCActn", "tier-2/3 escalation"),
                mp("jwsd detached JWS (§7.3.4)", "request proof binding the body to capability.holder", "verified with jose"),
            ]),
            "proofMethods": .array([.string("jwsd")]),
            "multiHop": .string("An A2A task is a chain of GNAP grants. Each hop delegates from the issuing agent to the next, "
                + "recording its (clamped) rights as an append-only gnap_access caveat. Effective authority is the "
                + "intersection of the root policy envelope and every hop; PCA caveats are conjunctive and "
                + "append-only, so no hop can widen — \"never wider than the issuer\" holds across any depth."),
            "stepUp": .string("A request for authority beyond the issuer (or an explicit interaction) returns a GNAP continue "
                + "handle instead of a token. The client returns with the action PCActn plus a guardian/principal "
                + "co-signature, which is folded into the PCActn threshold and verified at tier 2/3 (FROST or "
                + "multi-signature) before the action is admitted."),
            "security": .array([
                .string("Attenuation is structural and append-only: a delegated hop can only ever narrow authority."),
                .string("Every grant is key-bound (cnf): the holder key must prove possession via a jwsd detached JWS."),
                .string("All verification fails closed: bad token, broken chain, bad proof, stale request, or out-of-scope action denies."),
                .string("Rights beyond the issuer are clamped at issue time and denied at action time (defense in depth)."),
                .string("Elevation beyond the agent requires a human/guardian co-signature, not a self-minted grant."),
            ]),
        ])
    }()
}
