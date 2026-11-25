import Foundation

/// The connector catalog: declarative provider manifests (pure data, no secrets), their validation and digest, the provider registry, the
/// authorize URL / PKCE builders, access-token placement, and the authorization-code exchange and refresh that store the connection in the
/// `PCAConnect` vault. Token requests go through an injected synchronous transport.
public enum PCAConnectors {
    public enum TokenPlacement: String { case bearer, header, query }
    public enum RefreshMode: String { case refresh_token, none }
    public enum ClientAuth: String { case post, basic }

    public struct RefreshSpec {
        public var mode: RefreshMode
        /// Token endpoint used for refresh; defaults to the manifest's `tokenUrl`.
        public var tokenEndpoint: String?
        public var supportsScopeNarrowing: Bool?
        /// Extra static form parameters merged into every refresh request (in this order).
        public var extraParams: [(String, String)]?
        public init(mode: RefreshMode, tokenEndpoint: String? = nil, supportsScopeNarrowing: Bool? = nil, extraParams: [(String, String)]? = nil) {
            self.mode = mode
            self.tokenEndpoint = tokenEndpoint
            self.supportsScopeNarrowing = supportsScopeNarrowing
            self.extraParams = extraParams
        }
    }

    /// A declarative outbound-provider definition.
    public struct ProviderManifest {
        /// Stable, lowercase, globally-unique registry id.
        public var id: String
        public var displayName: String
        /// May carry `{var}` placeholders (see `requiredVars`).
        public var authorizeUrl: String
        public var tokenUrl: String
        public var scopesAvailable: [String]
        /// The least-privilege default requested when a caller names no scopes; inside `scopesAvailable`.
        public var defaultScopes: [String]
        public var refresh: RefreshSpec
        public var tokenPlacement: TokenPlacement
        public var pkce: Bool?
        /// Scope delimiter in the authorize request; default a space.
        public var scopeSeparator: String?
        /// Static extra parameters added to the authorize URL, in this order.
        public var authParams: [(String, String)]?
        public var clientAuth: ClientAuth?
        public var headerName: String?
        public var queryParam: String?
        public var requiredVars: [String]?
        public var docsUrl: String?

        public init(id: String, displayName: String, authorizeUrl: String, tokenUrl: String, scopesAvailable: [String], defaultScopes: [String], refresh: RefreshSpec,
                    tokenPlacement: TokenPlacement, pkce: Bool? = nil, scopeSeparator: String? = nil, authParams: [(String, String)]? = nil, clientAuth: ClientAuth? = nil,
                    headerName: String? = nil, queryParam: String? = nil, requiredVars: [String]? = nil, docsUrl: String? = nil) {
            self.id = id
            self.displayName = displayName
            self.authorizeUrl = authorizeUrl
            self.tokenUrl = tokenUrl
            self.scopesAvailable = scopesAvailable
            self.defaultScopes = defaultScopes
            self.refresh = refresh
            self.tokenPlacement = tokenPlacement
            self.pkce = pkce
            self.scopeSeparator = scopeSeparator
            self.authParams = authParams
            self.clientAuth = clientAuth
            self.headerName = headerName
            self.queryParam = queryParam
            self.requiredVars = requiredVars
            self.docsUrl = docsUrl
        }

        /// The manifest as the JSON document its digest is taken over.
        public var json: JSONValue {
            func strs(_ a: [String]) -> JSONValue { .array(a.map { .string($0) }) }
            func map(_ p: [(String, String)]) -> JSONValue {
                var o = JObject()
                for (k, v) in p { o[JKey(k)] = .string(v) }
                return .object(o)
            }
            var r: JObject = ["mode": .string(refresh.mode.rawValue)]
            if let t = refresh.tokenEndpoint { r["tokenEndpoint"] = .string(t) }
            if let s = refresh.supportsScopeNarrowing { r["supportsScopeNarrowing"] = .bool(s) }
            if let e = refresh.extraParams { r["extraParams"] = map(e) }
            var o: JObject = ["id": .string(id), "displayName": .string(displayName), "authorizeUrl": .string(authorizeUrl), "tokenUrl": .string(tokenUrl),
                              "scopesAvailable": strs(scopesAvailable), "defaultScopes": strs(defaultScopes), "refresh": .object(r), "tokenPlacement": .string(tokenPlacement.rawValue)]
            if let p = pkce { o["pkce"] = .bool(p) }
            if let s = scopeSeparator { o["scopeSeparator"] = .string(s) }
            if let a = authParams { o["authParams"] = map(a) }
            if let c = clientAuth { o["clientAuth"] = .string(c.rawValue) }
            if let h = headerName { o["headerName"] = .string(h) }
            if let q = queryParam { o["queryParam"] = .string(q) }
            if let v = requiredVars { o["requiredVars"] = strs(v) }
            if let d = docsUrl { o["docsUrl"] = .string(d) }
            return .object(o)
        }
    }

    // MARK: errors

    /// A refusal of this package: `name` is ConnectorError, ManifestValidationError (with `issues`) or UnknownProviderError.
    public struct ConnectorError: Error, CustomStringConvertible {
        public let name: String
        public let message: String
        public var issues: [String]?
        public var description: String { "\(name): \(message)" }
        init(_ message: String, name: String = "ConnectorError", issues: [String]? = nil) {
            self.name = name
            self.message = message
            self.issues = issues
        }
        static func validation(_ issues: [String]) -> ConnectorError {
            ConnectorError("invalid provider manifest: \(issues.joined(separator: "; "))", name: "ManifestValidationError", issues: issues)
        }
        static func unknownProvider(_ id: String) -> ConnectorError { ConnectorError("no connector registered for provider '\(id)'", name: "UnknownProviderError") }
    }

    // MARK: validation

    /// OAuth request parameters a manifest or a caller must not set through `authParams` / `extraParams`: the request builders own them.
    public static let RESERVED_AUTHORIZE_PARAMS: Set<String> = ["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"]
    public static let RESERVED_TOKEN_PARAMS: Set<String> = ["grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier", "refresh_token"]
    private static let FORBIDDEN_HEADERS: Set<String> = ["host", "content-length", "content-type", "transfer-encoding", "connection", "cookie", "set-cookie"]

    public enum Validation {
        case valid(ProviderManifest)
        case invalid([String])
    }

    static func isWord(_ c: Unicode.Scalar) -> Bool { (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A) || c == "_" }
    private static func isAlnum(_ c: Unicode.Scalar) -> Bool { isWord(c) && c != "_" }

    /// The `{name}` placeholders of a URL in order (name = `\w+`), each with its scalar range; text that is not a placeholder is literal.
    static func placeholders(_ s: [Unicode.Scalar]) -> [(name: String, range: Range<Int>)] {
        var out: [(String, Range<Int>)] = []
        var i = 0
        while i < s.count {
            if s[i] == "{" {
                var j = i + 1
                while j < s.count, isWord(s[j]) { j += 1 }
                if j > i + 1, j < s.count, s[j] == "}" {
                    out.append((String(String.UnicodeScalarView(s[(i + 1)..<j])), i..<(j + 1)))
                    i = j + 1
                    continue
                }
            }
            i += 1
        }
        return out
    }

    /// `u.replace(/\{\w+\}/g, 'x')`.
    static func fillPlaceholders(_ u: String, with fill: String = "x") -> String {
        let s = Array(u.unicodeScalars)
        var out = String.UnicodeScalarView(), at = 0
        for p in placeholders(s) {
            out.append(contentsOf: s[at..<p.range.lowerBound])
            out.append(contentsOf: fill.unicodeScalars)
            at = p.range.upperBound
        }
        out.append(contentsOf: s[at...])
        return String(out)
    }

    /// An https URL whose host may carry `{var}` placeholders: no credentials (a manifest is data with no secrets), no fragment, and the
    /// placeholder is never the whole host (the caller would then choose where tokens go).
    static func isHttpsUrl(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString, IV.startsWith(s, "https://") else { return false }
        let filled = fillPlaceholders(s)
        guard let u = WhatwgURL.parse(filled), u.scheme == "https" else { return false }
        let x = WhatwgURL.userinfoAndFragment(filled)
        if x.userinfo || x.fragment { return false }
        let rest = Array(s.unicodeScalars.dropFirst(8))
        let rawHost = Array(rest.prefix { $0 != "/" && $0 != "?" && $0 != "#" })
        // ^\{\w+\}(:\d+)?$
        if let p = placeholders(rawHost).first, p.range.lowerBound == 0 {
            let tail = rawHost[p.range.upperBound...]
            if tail.isEmpty || (tail.first == ":" && tail.count > 1 && tail.dropFirst().allSatisfy { $0.value >= 0x30 && $0.value <= 0x39 }) { return false }
        }
        return true
    }

    private static func isRecord(_ v: JSONValue?) -> JObject? { v?.asObject }
    private static func stringRecord(_ v: JSONValue?) -> [(String, String)]? {
        guard let o = v?.asObject, o.values.allSatisfy({ $0.asString != nil }) else { return nil }
        return o.keys.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }.map { ($0.s, o[$0]!.asString!) }
    }
    private static func stringArray(_ v: JSONValue?) -> [String]? {
        guard let a = v?.asArray, a.allSatisfy({ $0.asString != nil }) else { return nil }
        return a.compactMap { $0.asString }
    }
    private static func nonEmpty(_ v: JSONValue?) -> String? { v?.asString.flatMap { $0.isEmpty ? nil : $0 } }
    private static func matches(_ s: String, first: (Unicode.Scalar) -> Bool, rest: (Unicode.Scalar) -> Bool) -> Bool {
        guard let f = s.unicodeScalars.first, first(f) else { return false }
        return s.unicodeScalars.dropFirst().allSatisfy(rest)
    }

    /// Structurally validate an untrusted value as a manifest. Pure; collects every issue rather than failing on the first. Issues about
    /// a map's keys (reserved parameter names) are listed in code-unit order of the key (a JSON object has no member order).
    public static func validateManifest(_ input: JSONValue?) -> Validation {
        var issues: [String] = []
        guard let obj = input?.asObject else { return .invalid(["manifest must be an object"]) }
        func prop(_ k: String) -> JSONValue? { obj[JKey(k)] }

        let id = prop("id")
        if nonEmpty(id) == nil { issues.append("id must be a non-empty string") }
        else if !matches(id!.asString!, first: { isAlnum($0) && !($0.value >= 0x41 && $0.value <= 0x5A) }, rest: { (isAlnum($0) && !($0.value >= 0x41 && $0.value <= 0x5A)) || $0 == "." || $0 == "_" || $0 == "-" }) {
            issues.append("id '\(id!.asString!)' must be lowercase and match ^[a-z0-9][a-z0-9._-]*$")
        }
        if nonEmpty(prop("displayName")) == nil { issues.append("displayName must be a non-empty string") }

        let authorizeUrl = prop("authorizeUrl"), tokenUrl = prop("tokenUrl")
        if !isHttpsUrl(authorizeUrl) { issues.append("authorizeUrl must be an https:// URL") }
        if !isHttpsUrl(tokenUrl) { issues.append("tokenUrl must be an https:// URL") }

        let scopesAvailable = stringArray(prop("scopesAvailable")), defaultScopes = stringArray(prop("defaultScopes"))
        if scopesAvailable == nil { issues.append("scopesAvailable must be an array of strings") }
        if defaultScopes == nil { issues.append("defaultScopes must be an array of strings") }
        for (name, list) in [("scopesAvailable", scopesAvailable), ("defaultScopes", defaultScopes)] {
            guard let l = list else { continue }
            if l.contains(where: { $0.isEmpty || $0.unicodeScalars.contains(where: { Attest.isJSSpace($0) || $0 == "," }) }) {
                issues.append("\(name) entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)")
            }
            if !IV.distinct(l) { issues.append("\(name) must not contain duplicates") }
        }
        if let av = scopesAvailable, let df = defaultScopes, !av.isEmpty {
            let missing = df.filter { !IV.contains(av, $0) }
            if !missing.isEmpty { issues.append("defaultScopes must be a subset of scopesAvailable (unknown: \(missing.joined(separator: ", ")))") }
        }

        let refresh = prop("refresh")
        if let r = refresh?.asObject {
            let mode = r[JKey("mode")]?.asString
            if mode != "refresh_token" && mode != "none" { issues.append("refresh.mode must be one of refresh_token | none") }
            if let te = r[JKey("tokenEndpoint")], !isHttpsUrl(te) { issues.append("refresh.tokenEndpoint, when present, must be an https:// URL") }
            if let sn = r[JKey("supportsScopeNarrowing")], case .bool = sn {} else if r[JKey("supportsScopeNarrowing")] != nil { issues.append("refresh.supportsScopeNarrowing must be a boolean") }
            if let ep = r[JKey("extraParams")] {
                if let pairs = stringRecord(ep) {
                    for (k, _) in pairs where RESERVED_TOKEN_PARAMS.contains(k) { issues.append("refresh.extraParams may not set '\(k)': the request builder owns it") }
                } else { issues.append("refresh.extraParams must be a string→string map") }
            }
        } else {
            issues.append("refresh must be an object")
        }

        let placement = prop("tokenPlacement")?.asString
        if placement != "bearer" && placement != "header" && placement != "query" {
            issues.append("tokenPlacement must be one of bearer | header | query")
        } else if placement == "header", nonEmpty(prop("headerName")) == nil {
            issues.append("tokenPlacement 'header' requires a non-empty headerName")
        } else if placement == "query", nonEmpty(prop("queryParam")) == nil {
            issues.append("tokenPlacement 'query' requires a non-empty queryParam")
        }
        if let h = prop("headerName")?.asString {
            let ok = matches(h, first: { isAlnum($0) }, rest: { isAlnum($0) || $0 == "-" })
            if !ok || FORBIDDEN_HEADERS.contains(h.lowercased()) { issues.append("headerName '\(h)' must be an HTTP token and not a protocol header") }
        }
        if let q = prop("queryParam")?.asString, !matches(q, first: { (isAlnum($0) && !($0.value >= 0x30 && $0.value <= 0x39)) || $0 == "_" }, rest: { isWord($0) || $0 == "." || $0 == "-" }) {
            issues.append("queryParam '\(q)' must be a plain parameter name")
        }
        if let s = prop("scopeSeparator")?.asString, s.isEmpty { issues.append("scopeSeparator must not be empty") }

        if let p = prop("pkce") { if case .bool = p {} else { issues.append("pkce must be a boolean") } }
        if let s = prop("scopeSeparator"), s.asString == nil { issues.append("scopeSeparator must be a string") }
        let authParamsV = prop("authParams")
        if let ap = authParamsV {
            if let pairs = stringRecord(ap) {
                for (k, _) in pairs where RESERVED_AUTHORIZE_PARAMS.contains(k) { issues.append("authParams may not set '\(k)': the request builder owns it") }
            } else { issues.append("authParams must be a string→string map") }
        }
        if let c = prop("clientAuth"), c.asString != "post", c.asString != "basic" { issues.append("clientAuth must be one of post | basic") }

        let requiredVarsV = prop("requiredVars")
        if requiredVarsV != nil, stringArray(requiredVarsV) == nil { issues.append("requiredVars must be an array of strings") }
        // Every `{var}` that appears in a URL must be declared, and vice-versa, so substitution can never leave a placeholder in a live request.
        if isHttpsUrl(authorizeUrl), isHttpsUrl(tokenUrl) {
            let declared = stringArray(requiredVarsV) ?? []
            var used: [String] = []
            for u in [authorizeUrl!.asString!, tokenUrl!.asString!] { for p in placeholders(Array(u.unicodeScalars)) where !IV.contains(used, p.name) { used.append(p.name) } }
            for v in used where !IV.contains(declared, v) { issues.append("url uses '{\(v)}' but requiredVars does not declare it") }
            var seen: [String] = []
            for v in declared where !IV.contains(seen, v) {
                seen.append(v)
                if !IV.contains(used, v) { issues.append("requiredVars declares '\(v)' but no URL uses '{\(v)}'") }
            }
        }
        if let d = prop("docsUrl"), d.asString == nil { issues.append("docsUrl must be a string") }

        if !issues.isEmpty { return .invalid(issues) }
        // rebuild a clean manifest from the validated values so it carries only known keys
        let r = refresh!.asObject!
        var spec = RefreshSpec(mode: r[JKey("mode")]?.asString == "none" ? .none : .refresh_token)
        spec.tokenEndpoint = r[JKey("tokenEndpoint")]?.asString
        if case let .bool(b)? = r[JKey("supportsScopeNarrowing")] { spec.supportsScopeNarrowing = b }
        spec.extraParams = stringRecord(r[JKey("extraParams")])
        var m = ProviderManifest(id: id!.asString!, displayName: prop("displayName")!.asString!, authorizeUrl: authorizeUrl!.asString!, tokenUrl: tokenUrl!.asString!,
                                 scopesAvailable: scopesAvailable!, defaultScopes: defaultScopes!, refresh: spec,
                                 tokenPlacement: placement == "header" ? .header : placement == "query" ? .query : .bearer)
        if case let .bool(b)? = prop("pkce") { m.pkce = b }
        m.scopeSeparator = prop("scopeSeparator")?.asString
        m.authParams = stringRecord(authParamsV)
        m.clientAuth = prop("clientAuth")?.asString == "post" ? .post : prop("clientAuth")?.asString == "basic" ? .basic : nil
        m.headerName = prop("headerName")?.asString
        m.queryParam = prop("queryParam")?.asString
        m.requiredVars = stringArray(requiredVarsV)
        m.docsUrl = prop("docsUrl")?.asString
        return .valid(m)
    }

    /// Validate `input`, returning the manifest or throwing a `ManifestValidationError`.
    public static func assertManifest(_ input: JSONValue?) throws -> ProviderManifest {
        switch validateManifest(input) {
        case let .valid(m): return m
        case let .invalid(i): throw ConnectorError.validation(i)
        }
    }

    /// A digest of a manifest (SHA-256 over canonical JSON). Pin the digest of a manifest you reviewed: a registry given the digest refuses
    /// a manifest that has since changed.
    public static func manifestDigest(_ m: ProviderManifest) -> String { IV.strictHash(m.json) ?? "" }

    // MARK: registry

    public final class ProviderRegistry {
        private var byId: [JKey: ProviderManifest] = [:]
        public init() {}

        /// Validate and register a manifest. Throws if it is invalid, does not match `expectedDigest`, or the id is taken (unless `replace`).
        @discardableResult
        public func register(_ manifest: JSONValue, replace: Bool = false, expectedDigest: String? = nil) throws -> ProviderManifest {
            let valid = try assertManifest(manifest)
            if let d = expectedDigest, !IV.same(manifestDigest(valid), d) { throw ConnectorError("manifest '\(valid.id)' does not match the pinned digest") }
            if byId[JKey(valid.id)] != nil, !replace {
                throw ConnectorError("provider '\(valid.id)' is already registered; pass { replace: true } to replace it deliberately")
            }
            byId[JKey(valid.id)] = valid
            return valid
        }

        @discardableResult
        public func register(_ manifest: ProviderManifest, replace: Bool = false, expectedDigest: String? = nil) throws -> ProviderManifest {
            try register(manifest.json, replace: replace, expectedDigest: expectedDigest)
        }

        public func get(_ id: String) -> ProviderManifest? { byId[JKey(id)] }

        public func require(_ id: String) throws -> ProviderManifest {
            guard let m = byId[JKey(id)] else { throw ConnectorError.unknownProvider(id) }
            return m
        }

        public func has(_ id: String) -> Bool { byId[JKey(id)] != nil }

        /// Sorted by id (code-unit order).
        public func list() -> [ProviderManifest] { byId.values.sorted { $0.id.utf16.lexicographicallyPrecedes($1.id.utf16) } }
        public func ids() -> [String] { list().map { $0.id } }
    }

    public static func createDefaultRegistry() -> ProviderRegistry {
        let r = ProviderRegistry()
        for m in Providers.BUILTIN_MANIFESTS { _ = try? r.register(m) }
        return r
    }

    public static let defaultRegistry = createDefaultRegistry()

    /// A digest of the whole catalog: the sorted `[id, manifestDigest]` pairs.
    public static func catalogDigest(_ registry: ProviderRegistry = defaultRegistry) -> String {
        IV.strictHash(.array(registry.list().map { .array([.string($0.id), .string(manifestDigest($0))]) })) ?? ""
    }
}
