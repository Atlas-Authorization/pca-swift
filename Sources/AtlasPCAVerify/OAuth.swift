import Foundation

/// The OAuth 2.1 / MCP-authorization bridge: RFC 9728 Protected Resource Metadata (build, parse, well-known path), the RFC 6750 /
/// RFC 7235 `WWW-Authenticate` challenge (the MCP `Bearer resource_metadata` challenge plus the PCA one), RFC 8707 resource
/// indicators and token-audience binding, the 401 / discovery glue, and the `pca_grant` (RFC 9396) builder and token gate.
/// The bridge is the envelope around the proof: a verified per-action PCActn stays the credential. Pure, no I/O.
/// Options are JSON objects keyed with the reference's option names (`authorizationServers`, `errorDescription`, `pcaChallenge`, ...).
public enum PCAOAuth {
    public static let WELL_KNOWN_OAUTH_PRM = "/.well-known/oauth-protected-resource"
    public static let WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration"
    public static let DEFAULT_PCA_HINT = "send PCA-Action: <base64url PCActn> or JSON body {pcactn}"
    static let DEFAULT_SUITES = ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"]
    static let DEFAULT_REQUIRED = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]

    static func strs(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }

    /// RFC 9728 section 1.2: why `resource` is not an https URL without a fragment, or nil when it is one.
    public static func resourceIdentifierProblem(_ resource: JSONValue?) -> String? {
        guard let r = JS.nonEmptyString(resource) else { return "resource identifier must be a non-empty string" }
        guard let u = WhatwgURL.parse(r) else { return "resource identifier is not an absolute URL" }
        if u.scheme != "https" { return "resource identifier must use the https scheme" }
        if r.contains("#") { return "resource identifier must not contain a fragment" }
        return nil
    }

    /// RFC 9728 section 3.1: the well-known suffix goes between the host and the path/query. Throws on an invalid identifier.
    public static func prmPathForResource(_ resource: String) throws -> String {
        if let p = resourceIdentifierProblem(.string(resource)) { throw JSError("prmPathForResource: \(p)") }
        let u = WhatwgURL.parse(resource)!
        return WELL_KNOWN_OAUTH_PRM + (u.pathname == "/" ? "" : u.pathname) + (u.search ?? "")
    }

    /// The absolute metadata URL (the `resource_metadata` value).
    public static func prmUrlForResource(_ resource: String) throws -> String {
        guard let origin = WhatwgURL.parse(resource)?.origin else { throw JSError("prmUrlForResource: invalid resource identifier") }
        let path = try prmPathForResource(resource)
        return origin + path
    }

    /// The core discovery document (buildDiscoveryDocument).
    static func discoveryDocument(_ o: JObject) throws -> JObject {
        guard let aud = JS.nonEmptyString(o["audience"]) else { throw JSError("buildDiscoveryDocument: audience is required") }
        var d: JObject = [
            "audience": .string(aud),
            "pca_versions": JS.present(o["pcaVersions"]) ?? .array([.int(2)]),
            "signature_suites": JS.present(o["signatureSuites"]) ?? strs(DEFAULT_SUITES),
            "action_header": JS.present(o["actionHeader"]) ?? .string("PCA-Action"),
            "required_checks": JS.present(o["requiredChecks"]) ?? strs(DEFAULT_REQUIRED),
        ]
        for (k, w) in [("endpoints", "endpoints"), ("trustedRoots", "trusted_roots"), ("metadata", "metadata")] where JS.truthy(o[JKey(k)]) {
            d[JKey(w)] = o[JKey(k)]!
        }
        return d
    }

    /// RFC 9728 Protected Resource Metadata with the PCA block (the discovery document embedded; its `audience` IS `resource`).
    public static func protectedResourceMetadata(_ o: JObject) throws -> JSONValue {
        guard let resource = JS.nonEmptyString(o["resource"]) else {
            throw JSError("protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required")
        }
        if o["strict"] != .bool(false), let p = resourceIdentifierProblem(.string(resource)) { throw JSError("protectedResourceMetadata: \(p)") }
        var dopts: JObject = ["audience": .string(resource)]
        for k in ["signatureSuites", "pcaVersions", "actionHeader", "requiredChecks", "endpoints", "trustedRoots", "metadata"] { dopts[JKey(k)] = o[JKey(k)] }
        let discovery = try discoveryDocument(dopts)
        var base = String(resource.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)[0])
        while base.hasSuffix("/") { base.removeLast() }
        let cfg = JS.present(o["pcaConfigurationEndpoint"]) ?? .string(base + WELL_KNOWN_PCA_PATH)
        var doc: JObject = [
            "resource": .string(resource),
            "bearer_methods_supported": JS.present(o["bearerMethodsSupported"]) ?? strs(["header"]),
            "pca_action_header": discovery["action_header"]!,
            "pca_signature_suites": .array(try JS.spread(discovery["signature_suites"])),
            "pca_versions": .array(try JS.spread(discovery["pca_versions"])),
            "pca_configuration_endpoint": cfg,
            "pca": .object(discovery),
        ]
        if JS.truthy(o["authorizationServers"]) { doc["authorization_servers"] = .array(try JS.spread(o["authorizationServers"])) }
        if JS.truthy(o["resourceDocumentation"]) { doc["resource_documentation"] = o["resourceDocumentation"]! }
        if JS.truthy(o["scopesSupported"]) { doc["scopes_supported"] = .array(try JS.spread(o["scopesSupported"])) }
        if JS.truthy(o["resourceName"]) { doc["resource_name"] = o["resourceName"]! }
        if JS.truthy(o["resourceSigningAlgValuesSupported"]) {
            doc["resource_signing_alg_values_supported"] = .array(try JS.spread(o["resourceSigningAlgValuesSupported"]))
        }
        if JS.truthy(o["authorizationDetailsTypesSupported"]) {
            doc["authorization_details_types_supported"] = .array(try JS.spread(o["authorizationDetailsTypesSupported"]))
        }
        return .object(doc)
    }

    /// Validate and narrow an untrusted PRM document (fail closed). Strict by default: `expectedResource` is required (RFC 9728
    /// section 3.3) and must equal both `resource` and the embedded `pca.audience`.
    public static func parseProtectedResourceMetadata(_ value: JSONValue?, _ opts: JObject = [:]) throws -> JSONValue {
        let p = "parseProtectedResourceMetadata: "
        guard let v = value?.asObject else { throw JSError(p + "not an object") }
        guard let resource = JS.nonEmptyString(v["resource"]) else { throw JSError(p + "missing `resource`") }
        guard JS.isStringArray(v["bearer_methods_supported"]) else { throw JSError(p + "bearer_methods_supported must be a string[]") }
        guard JS.nonEmptyString(v["pca_action_header"]) != nil else { throw JSError(p + "missing pca_action_header") }
        guard JS.isStringArray(v["pca_signature_suites"]) else { throw JSError(p + "pca_signature_suites must be a string[]") }
        guard JS.isNumberArray(v["pca_versions"]) else { throw JSError(p + "pca_versions must be a number[]") }
        guard let pca = v["pca"]?.asObject else { throw JSError(p + "missing embedded `pca` discovery document") }
        guard let audience = JS.nonEmptyString(pca["audience"]) else { throw JSError(p + "embedded pca.audience is required") }
        // a member present with null is not `undefined`: it must match too (and never does)
        if let expected = opts["expectedResource"] {
            if expected != .string(resource) { throw JSError(p + "`resource` does not match the expected resource identifier") }
            if expected != .string(audience) { throw JSError(p + "embedded pca.audience does not match the expected resource identifier") }
        }
        if opts["strict"] != .bool(false) {
            if opts["expectedResource"] == nil { throw JSError(p + "expectedResource is required (RFC 9728 section 3.3); pass strict: false to skip") }
            if let problem = resourceIdentifierProblem(.string(resource)) { throw JSError(p + problem) }
            if !(v["bearer_methods_supported"]!.asArray!.allSatisfy { ["header", "body", "query"].contains($0.asString!) }) {
                throw JSError(p + "bearer_methods_supported has a value outside header/body/query")
            }
        }
        var doc: JObject = [
            "resource": .string(resource), "bearer_methods_supported": v["bearer_methods_supported"]!, "pca_action_header": v["pca_action_header"]!,
            "pca_signature_suites": v["pca_signature_suites"]!, "pca_versions": v["pca_versions"]!, "pca": .object(pca),
        ]
        for k in ["pca_configuration_endpoint", "resource_documentation", "resource_name"] where v[JKey(k)]?.asString != nil { doc[JKey(k)] = v[JKey(k)]! }
        for k in ["authorization_servers", "scopes_supported", "resource_signing_alg_values_supported"] where JS.isStringArray(v[JKey(k)]) { doc[JKey(k)] = v[JKey(k)]! }
        return .object(doc)
    }

    /// A value for a quoted auth-param: a quote, backslash or control character would inject into the header, so it is refused.
    static func quotedParam(_ v: JSONValue?) throws -> String {
        let s = JS.toString(v)
        if s.unicodeScalars.contains(where: { $0 == "\"" || $0 == "\\" || $0.value < 0x20 || $0.value == 0x7F }) {
            throw JSError("pca-oauth: WWW-Authenticate parameter value may not contain a quote or newline")
        }
        return s
    }

    /// encodePcaNeed: the canonical need, base64url, at most 2048 characters.
    static func encodePcaNeed(_ need: JSONValue) throws -> String {
        if let code = A2a.needError(need) { throw JSError("encodePcaNeed: malformed need (\(code))") }
        let enc = Base64URLStrict.encode(try Canonical.canonicalBytes(need))
        if enc.utf8.count > 2048 { throw JSError("encodePcaNeed: the need is too large for a header") }
        return enc
    }

    /// The `WWW-Authenticate` value of a 401: `Bearer resource_metadata="<prmUrl>"` (MCP) and, by default, the PCA challenge.
    public static func wwwAuthenticate(_ prmUrl: JSONValue?, _ o: JObject = [:]) throws -> String {
        guard JS.nonEmptyString(prmUrl) != nil else { throw JSError("wwwAuthenticate: prmUrl is required") }
        func param(_ name: String, _ v: JSONValue?) throws -> String { let q = try quotedParam(v); return "\(name)=\"\(q)\"" }
        var params = [try param("resource_metadata", prmUrl)]
        if JS.truthy(o["error"]) { params.append(try param("error", o["error"])) }
        if JS.truthy(o["errorDescription"]) { params.append(try param("error_description", o["errorDescription"])) }
        if JS.truthy(o["scope"]) { params.append(try param("scope", o["scope"])) }
        if JS.truthy(o["pcaNeed"]) {
            let enc = try encodePcaNeed(o["pcaNeed"]!)
            params.append(try param("pca_need", .string(enc)))
        }
        var challenges = ["Bearer " + params.joined(separator: ", ")]
        let includePca = JS.present(o["includePca"]).map { JS.truthy($0) } ?? true
        if JS.truthy(o["pcaChallenge"]) {
            let pc = JS.toString(o["pcaChallenge"])
            if pc.unicodeScalars.contains(where: { ($0.value < 0x20 && $0 != "\t") || $0.value == 0x7F }) {
                throw JSError("pca-oauth: pcaChallenge may not contain control characters or newlines")
            }
            challenges.append(pc)
        } else if includePca {
            let realm = JS.present(o["realm"]) ?? .string("pca")
            let hint = JS.present(o["hint"]) ?? .string(DEFAULT_PCA_HINT)
            var pca = "PCA " + (try param("realm", realm))
            if JS.truthy(hint) { pca += ", " + (try param("hint", hint)) }
            challenges.append(pca)
        }
        return challenges.joined(separator: ", ")
    }

    static func indicator(ok: Bool, matched: JSONValue? = nil, reason: String? = nil) -> JSONValue {
        var r: JObject = ["ok": .bool(ok)]
        if let m = matched { r["matched"] = m }
        if let s = reason { r["reason"] = .string(s) }
        return .object(r)
    }

    /// RFC 8707: does an incoming `resource` indicator (one value or several) name this audience? The OAuth-layer echo only:
    /// an early reject, never the security boundary (the PCActn's signed `aud` is).
    public static func checkResourceIndicator(_ param: JSONValue?, _ expectedAudience: JSONValue?) throws -> JSONValue {
        guard let expected = JS.nonEmptyString(expectedAudience) else { throw JSError("checkResourceIndicator: expectedAudience is required") }
        guard let param = JS.present(param) else { return indicator(ok: false, reason: "no resource indicator presented") }
        let values = param.asArray ?? [param]
        if values.isEmpty { return indicator(ok: false, reason: "empty resource indicator") }
        for r in values {
            guard let s = JS.nonEmptyString(r) else { continue }
            if IV.same(s, expected) { return indicator(ok: true, matched: .string(s)) }
        }
        return indicator(ok: false, reason: "resource indicator \(JS.stringify(.array(values))) does not match audience \(JS.stringify(.string(expected)))")
    }

    /// The `aud` of an already verified token must be, or contain, exactly this resource identifier (no prefix, case or slash tolerance).
    public static func checkTokenAudience(_ aud: JSONValue?, _ expectedResource: JSONValue?) throws -> JSONValue {
        guard let expected = JS.nonEmptyString(expectedResource) else { throw JSError("checkTokenAudience: expectedResource is required") }
        guard let aud = JS.present(aud) else { return indicator(ok: false, reason: "token has no audience") }
        let values = aud.asArray ?? [aud]
        if values.isEmpty { return indicator(ok: false, reason: "token has an empty audience") }
        if values.contains(where: { $0.asString.map { IV.same($0, expected) } ?? false }) { return indicator(ok: true, matched: .string(expected)) }
        return indicator(ok: false, reason: "token audience \(JS.stringify(aud)) does not include resource \(JS.stringify(.string(expected)))")
    }

    /// The path and body to serve the RFC 9728 document (`rfcPath` is an alias of `path`).
    public static func oauthDiscoveryHandler(_ o: JObject) throws -> JSONValue {
        let body = try protectedResourceMetadata(o)
        let resource = o["resource"]!.asString!
        let path = try resourceIdentifierProblem(.string(resource)) == nil ? prmPathForResource(resource) : WELL_KNOWN_OAUTH_PRM
        return .object(["path": .string(path), "body": body, "rfcPath": .string(path)])
    }

    /// The complete MCP/OAuth 401: status, `WWW-Authenticate` and a small JSON body pointing at the PRM document.
    public static func mcpUnauthorized(_ prmUrl: JSONValue?, _ o: JObject = [:]) throws -> JSONValue {
        var body: JObject = ["error": JS.present(o["error"]) ?? .string("invalid_request"), "resource_metadata": prmUrl ?? .null]
        if JS.truthy(o["errorDescription"]) { body["error_description"] = o["errorDescription"]! }
        let header = try wwwAuthenticate(prmUrl, o)
        return .object(["status": .int(401), "headers": .object(["WWW-Authenticate": .string(header)]), "body": .object(body)])
    }

    /// Prepend the MCP `resource_metadata` challenge to a deny result's own PCA challenge (kept verbatim); other members are kept.
    public static func upgradeUnauthorizedChallenge(_ result: JSONValue?, _ prmUrl: JSONValue?, _ o: JObject = [:]) throws -> JSONValue {
        guard var r = result?.asObject else { throw JSError("upgradeUnauthorizedChallenge: result must be an object") }
        var merged = o
        if JS.truthy(r["wwwAuthenticate"]) { merged["pcaChallenge"] = r["wwwAuthenticate"]! }
        r["wwwAuthenticate"] = .string(try wwwAuthenticate(prmUrl, merged))
        return .object(r)
    }

    // ---- pca_grant (RFC 9396) ----

    /// A validated `pca_grant` detail over the chain (root first). Throws on anything the profile refuses.
    public static func buildPcaGrantDetail(chainIds: [String], chainRef: JSONValue? = nil, bundleRevision: JSONValue? = nil, locations: JSONValue? = nil) throws -> JSONValue {
        var d: JObject = ["type": .string(PcaGrant.TYPE), "chain_digest": .string(PcaGrant.chainDigest(chainIds)), "chain_len": .int(Int64(chainIds.count))]
        if let r = chainRef { d["chain_ref"] = r }
        if let b = bundleRevision { d["bundle_revision"] = b }
        if let l = locations { d["locations"] = .array(try JS.spread(l)) }
        if let code = PcaGrant.validate(.object(d)) { throw JSError("buildPcaGrantDetail: refused (\(code))") }
        return .object(d)
    }

    /// The form-encoded `authorization_details` request parameter (RFC 9396 section 3). Members of a detail are written in the
    /// profile's order (type, chain_digest, chain_len, chain_ref, bundle_revision, locations), the order the builder produces.
    public static func pcaGrantRequestParam(_ details: [JSONValue]) -> String {
        let order = ["type", "chain_digest", "chain_len", "chain_ref", "bundle_revision", "locations"]
        let parts = details.map { d -> String in
            guard let o = d.asObject else { return JS.stringify(d) }
            let keys = order.map { JKey($0) }.filter { o[$0] != nil } + o.keys.filter { !order.contains($0.s) }.sorted()
            return "{" + keys.map { JS.stringify(.string($0.s)) + ":" + JS.stringify(o[$0]!) }.joined(separator: ",") + "}"
        }
        return JS.encodeURIComponent("[" + parts.joined(separator: ",") + "]")
    }

    /// Gate an OAuth access token carrying `pca_grant` details (already authenticated by the caller). Allow only with well-formed
    /// details naming a prefix of the presented chain and this resource AND a verified per-action proof; another location is a 403
    /// `insufficient_scope`, everything else a 401 `invalid_token`.
    public static func authorizePcaGrantToken(authorizationDetails: JSONValue?, resource: String, chainIds: [String], proofVerified: Bool) -> JSONValue {
        let parsed = PcaGrant.parse(authorizationDetails)
        if let code = parsed.code { return .object(["allow": .bool(false), "status": .int(401), "error": .string("invalid_token"), "code": .string(code)]) }
        let r = PcaGrant.check(details: parsed.details, resource: resource, chainIds: chainIds, proofVerified: proofVerified)
        if let i = r.index { return .object(["allow": .bool(true), "detail": parsed.details[i]]) }
        let loc = r.code == "wrong_location"
        return .object(["allow": .bool(false), "status": .int(loc ? 403 : 401), "error": .string(loc ? "insufficient_scope" : "invalid_token"), "code": .string(r.code ?? "chain_mismatch")])
    }

    /// deriveActionScopes: the confirmed action's `upstream.scopes_min` (deduplicated, sorted), within `granted` when given.
    public static func deriveActionScopes(_ action: JSONValue?, provider: JSONValue? = nil, granted: JSONValue? = nil) -> (scopes: [String], code: String?) {
        guard let a = action?.asObject else { return ([], "unknown_action") }
        guard a["confirmed"] == .bool(true) else { return ([], "unconfirmed") }
        let up = a["upstream"]?.asObject
        if let p = provider, up?["provider"] != p { return ([], "provider_mismatch") }
        guard let min = up?["scopes_min"]?.asArray, !min.isEmpty else { return ([], "no_scopes") }
        let ok = min.allSatisfy { v in
            guard let s = v.asString, s.utf16.count <= 256, !s.isEmpty else { return false }
            return s.unicodeScalars.allSatisfy { $0.value == 0x21 || ($0.value >= 0x23 && $0.value <= 0x5B) || ($0.value >= 0x5D && $0.value <= 0x7E) }
        }
        if !ok { return ([], "bad_scope") }
        // the scope tokens are ASCII, so a UTF-16 sort is a byte sort
        let scopes = Array(Set(min.compactMap { $0.asString })).sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        if let g = granted {
            let allowed = Set((g.asArray ?? []).compactMap { $0.asString })
            if !scopes.allSatisfy(allowed.contains) { return ([], "exceeds_grant") }
        }
        return (scopes, nil)
    }

    /// The `scope` (and RFC 8707 `resource`) to request for one confirmed action; a refusal requests nothing.
    public static func oauthScopeForAction(_ action: JSONValue?, provider: JSONValue?, granted: JSONValue? = nil, resource: JSONValue? = nil) -> JSONValue {
        let d = deriveActionScopes(action, provider: provider, granted: granted)
        if let c = d.code { return .object(["ok": .bool(false), "code": .string(c)]) }
        var r: JObject = ["ok": .bool(true), "scope": .string(d.scopes.joined(separator: " ")), "scopes": strs(d.scopes)]
        if let res = resource { r["resource"] = res }
        return .object(r)
    }
}
