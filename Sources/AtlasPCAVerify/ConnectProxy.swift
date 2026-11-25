import Foundation

/// Proxy mode: the vault makes the outbound call, so the agent never holds the credential. The extractor maps an outbound request back
/// to the action's parameters (which must hash to the PCActn's signed `params_digest`); the release receipt links the credential's use
/// to the effect.
extension PCAConnect {
    public struct ProxyRequest {
        public var method: String
        /// Absolute https URL.
        public var url: String
        /// In the order the caller gave them (lookup is case-insensitive; the first match wins).
        public var headers: [(String, String)]
        /// The request body as text (JSON or form encoded); nil = none.
        public var body: String?
        public init(method: String, url: String, headers: [(String, String)] = [], body: String? = nil) {
            self.method = method
            self.url = url
            self.headers = headers
            self.body = body
        }
    }

    public struct ProxyResponse {
        public var status: Int
        public var headers: [(String, String)]
        public var body: String
        public init(status: Int, headers: [(String, String)] = [], body: String) {
            self.status = status
            self.headers = headers
            self.body = body
        }
    }

    /// The outbound request the vault hands the injected transport. The transport MUST NOT follow redirects (a redirect would send the
    /// credential to a host the extractor never saw): a 3xx goes back to the caller as is.
    public struct ProxyFetchRequest {
        public var method: String
        public var url: String
        public var headers: [String: String]
        public var body: String?
    }
    public typealias ProxyFetch = (ProxyFetchRequest) throws -> ProxyResponse

    public struct HttpRequestSpec {
        /// Exact method, upper case.
        public var method: String
        /// `https://host/path/{param}/more`: literal text matches exactly; each `{name}` is one path segment and becomes the string parameter `name`. No query, no fragment.
        public var url: String
        /// Query keys that may appear; each present key becomes the string parameter of that name.
        public var query: [String]
        /// "json": a strict-JSON object body whose members are parameters. "form": urlencoded, string parameters. nil: no body.
        public var body: String?
        /// Body members the request always carries with exactly these values (not parameters).
        public var fixed: JObject
        public init(method: String, url: String, query: [String] = [], body: String? = nil, fixed: JObject = [:]) {
            self.method = method
            self.url = url
            self.query = query
            self.body = body
            self.fixed = fixed
        }
    }

    /// The extractor could not map the request to parameters for a reason other than a mismatch (a fixed member that is not canonicalizable).
    struct ExtractFailure: Error {}

    // MARK: JS URL helpers

    /// `decodeURIComponent`: nil is the reference's URIError (a bad escape, or a decoded sequence that is not UTF-8).
    static func decodeURIComponent(_ s: String) -> String? {
        let b = Array(s.utf8)
        var out: [UInt8] = []
        var i = 0
        func pct(_ k: Int) -> UInt8? {
            guard k + 2 < b.count, b[k] == 0x25, let h = WhatwgURL.hexVal(b[k + 1]), let l = WhatwgURL.hexVal(b[k + 2]) else { return nil }
            return h << 4 | l
        }
        while i < b.count {
            if b[i] != 0x25 { out.append(b[i]); i += 1; continue }
            guard let first = pct(i) else { return nil }
            i += 3
            if first < 0x80 { out.append(first); continue }
            let n = first >= 0xF8 ? 0 : first >= 0xF0 ? 4 : first >= 0xE0 ? 3 : first >= 0xC0 ? 2 : 0
            guard n >= 2 else { return nil }
            var seq = [first]
            for _ in 1..<n {
                guard let c = pct(i), c & 0xC0 == 0x80 else { return nil }
                seq.append(c)
                i += 3
            }
            // a replacement character would change the bytes: the sequence is not well-formed UTF-8 (overlong, surrogate, > U+10FFFF)
            guard Array(String(decoding: seq, as: UTF8.self).utf8) == seq else { return nil }
            out += seq
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// `new URLSearchParams(text)` entries (`stripQuestionMark`: the string constructor drops one leading `?`).
    static func formEntries(_ text: String, stripQuestionMark: Bool) -> [(String, String)] {
        var b = Array(text.utf8)
        if stripQuestionMark, b.first == 0x3F { b.removeFirst() }
        func dec(_ part: ArraySlice<UInt8>) -> String {
            let plus = part.map { $0 == 0x2B ? 0x20 : $0 }
            return String(decoding: WhatwgURL.pctDecode(plus.map { Unicode.Scalar($0) }), as: UTF8.self)
        }
        var out: [(String, String)] = []
        for seq in b.split(separator: 0x26, omittingEmptySubsequences: true) {
            if let eq = seq.firstIndex(of: 0x3D) { out.append((dec(seq[..<eq]), dec(seq[(eq + 1)...]))) } else { out.append((dec(seq), "")) }
        }
        return out
    }

    private static func isParamChar(_ c: Unicode.Scalar) -> Bool {
        (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A) || "._~%-".unicodeScalars.contains(c)
    }

    private enum PathToken {
        case literal([Unicode.Scalar])
        case param(String)
    }

    /// `pathTemplate.split(/\{([A-Za-z0-9_]+)\}/)`: literal text and `{name}` placeholders.
    private static func tokens(_ template: String) -> [PathToken] {
        let s = Array(template.unicodeScalars)
        var out: [PathToken] = [], lit: [Unicode.Scalar] = [], i = 0
        func word(_ c: Unicode.Scalar) -> Bool { (c.value >= 0x30 && c.value <= 0x39) || (c.value >= 0x41 && c.value <= 0x5A) || (c.value >= 0x61 && c.value <= 0x7A) || c == "_" }
        while i < s.count {
            if s[i] == "{" {
                var j = i + 1
                while j < s.count, word(s[j]) { j += 1 }
                if j > i + 1, j < s.count, s[j] == "}" {
                    out.append(.literal(lit)); lit = []
                    out.append(.param(String(String.UnicodeScalarView(s[(i + 1)..<j]))))
                    i = j + 1
                    continue
                }
            }
            lit.append(s[i]); i += 1
        }
        out.append(.literal(lit))
        return out
    }

    /// A greedy backtracking match of `^lit0 (cap0) lit1 ... $` where each capture is one or more of `[A-Za-z0-9._~%-]`, as the regex does.
    private static func matchPath(_ toks: [PathToken], _ i: Int, _ path: [Unicode.Scalar], _ pos: Int) -> [String]? {
        if i == toks.count { return pos == path.count ? [] : nil }
        switch toks[i] {
        case let .literal(l):
            guard pos + l.count <= path.count, path[pos..<(pos + l.count)].elementsEqual(l) else { return nil }
            return matchPath(toks, i + 1, path, pos + l.count)
        case .param:
            var maxLen = 0
            while pos + maxLen < path.count, isParamChar(path[pos + maxLen]) { maxLen += 1 }
            var len = maxLen
            while len >= 1 {
                if let rest = matchPath(toks, i + 1, path, pos + len) { return [String(String.UnicodeScalarView(path[pos..<(pos + len)]))] + rest }
                len -= 1
            }
            return nil
        }
    }

    private static func mismatch(_ m: String) -> VaultError { VaultError.requestMismatch("outbound request refused: \(m)") }

    /// The extractor for one operation. Throws on a malformed spec (at configuration time, not at call time).
    public static func httpExtractor(_ spec: HttpRequestSpec) throws -> (ProxyRequest) throws -> JObject {
        // spec.url.replace(PLACEHOLDER, 'x')
        let replaced = String(String.UnicodeScalarView(tokens(spec.url).flatMap { t -> [Unicode.Scalar] in
            switch t { case let .literal(l): return l; case .param: return ["x"] }
        }))
        // `new URL(...)` refuses a text that is not a URL with Node's own error, before any rule of the extractor is checked
        guard let u = WhatwgURL.parse(replaced) else { throw JSError("Invalid URL", code: "ERR_INVALID_URL") }
        guard u.scheme == "https", (u.search ?? "").isEmpty else { throw ConnectError("httpExtractor: url must be https without query, fragment or userinfo") }
        let extras = WhatwgURL.userinfoAndFragment(replaced)
        guard !extras.userinfo, !extras.fragment else { throw ConnectError("httpExtractor: url must be https without query, fragment or userinfo") }
        guard IV.same(spec.method, spec.method.uppercased()) else { throw ConnectError("httpExtractor: method must be upper case") }
        let origin = u.origin ?? "null"
        let pathTemplate = String(decoding: Array(spec.url.utf16.dropFirst(origin.utf16.count)), as: UTF16.self)
        let toks = tokens(pathTemplate)
        let names: [String] = toks.compactMap { if case let .param(n) = $0 { return n } else { return nil } }
        let ctype = spec.body == "json" ? "application/json" : spec.body == "form" ? "application/x-www-form-urlencoded" : nil
        let specBody = spec.body

        return { req in
            guard IV.same(req.method, spec.method) else { throw mismatch("method \(req.method) is not \(spec.method)") }
            guard let r = WhatwgURL.parse(req.url) else { throw mismatch("the url does not parse") }
            let rx = WhatwgURL.userinfoAndFragment(req.url)
            guard let ro = r.origin, IV.same(ro, origin), !rx.userinfo, !rx.fragment else { throw mismatch("the url is not on the pinned origin") }
            guard let caps = matchPath(toks, 0, Array(r.pathname.unicodeScalars), 0) else { throw mismatch("the path does not match the pinned template") }
            var params = JObject()
            func put(_ k: String, _ v: JSONValue) throws {
                if params[JKey(k)] != nil { throw mismatch("parameter '\(k)' is carried twice") }
                params[JKey(k)] = v
            }
            for (n, c) in zip(names, caps) {
                guard let d = decodeURIComponent(c) else { throw mismatch("a path segment is not valid percent-encoding") }
                try put(n, .string(d))
            }
            var seen: [String] = []
            let q = r.search.map { $0.hasPrefix("?") ? String($0.dropFirst()) : $0 } ?? ""
            for (k, v) in formEntries(q, stripQuestionMark: false) {
                if !IV.contains(spec.query, k) { throw mismatch("query key '\(k)' is not allowed") }
                if IV.contains(seen, k) { throw mismatch("query key '\(k)' is repeated") }
                seen.append(k)
                try put(k, .string(v))
            }
            let ct = req.headers.first { $0.0.lowercased() == "content-type" }?.1
            guard let kind = specBody else {
                if let b = req.body, !b.isEmpty { throw mismatch("this operation carries no body") }
                return params
            }
            guard let body = req.body, !body.isEmpty else { throw mismatch("the body is missing") }
            guard let c = ct, let first = c.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first,
                  IV.same(Attest.jsTrim(String(first)).lowercased(), ctype!) else { throw mismatch("content-type must be \(ctype!)") }
            var fixed = spec.fixed
            if kind == "json" {
                guard let parsed = try? StrictJSON.parse(body) else { throw mismatch("the body is not strict JSON") }
                guard let obj = parsed.asObject else { throw mismatch("the body must be a JSON object") }
                for (k, v) in obj {
                    if let f = fixed[k] {
                        guard let a = IV.strictHash(v), let b = IV.strictHash(f) else { throw ExtractFailure() }
                        if a != b { throw mismatch("fixed member '\(k.s)' has another value") }
                        fixed[k] = nil
                    } else { try put(k.s, v) }
                }
            } else {
                var keys: [String] = []
                for (k, v) in formEntries(body, stripQuestionMark: true) {
                    if IV.contains(keys, k) { throw mismatch("form key '\(k)' is repeated") }
                    keys.append(k)
                    if let f = fixed[JKey(k)] {
                        guard case let .string(fs) = f, IV.same(v, fs) else { throw mismatch("fixed member '\(k)' has another value") }
                        fixed[JKey(k)] = nil
                    } else { try put(k, .string(v)) }
                }
            }
            if !fixed.isEmpty { throw mismatch("fixed member(s) \(fixed.keys.map { $0.s }.sorted().joined(separator: ", ")) missing") }
            return params
        }
    }

    /// Request headers the agent may set; the vault sets Authorization itself. Anything else is refused (Host, Cookie, X-HTTP-Method-Override, ...).
    public static let DEFAULT_PROXY_HEADERS = ["content-type", "accept", "idempotency-key"]

    /// The headers the vault will send: lower-cased names, each allowed, none repeated, no CR / LF / NUL in a value.
    public static func checkProxyHeaders(_ headers: [(String, String)], _ allow: [String]) throws -> [String: String] {
        var out: [String: String] = [:]
        for (k, v) in headers {
            let n = k.lowercased()
            if !IV.contains(allow, n) { throw mismatch("header '\(k)' is not allowed") }
            if out[n] != nil { throw mismatch("header '\(k)' is repeated") }
            if v.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" || $0 == "\u{0}" }) { throw mismatch("header '\(k)' has an invalid value") }
            out[n] = v
        }
        return out
    }

    // MARK: release receipts

    public static let RELEASE_RECEIPT_DOMAIN = "atlas-pca/connect-release-receipt/v1\u{0}"

    /// base64url(sha256(strictCanonical({d, method, url, headers, body}))) of the outbound request as made.
    public static func outboundRequestDigest(method: String, url: String, headers: [String: String], body: String?) -> String? {
        var h = JObject()
        for (k, v) in headers { h[JKey(k)] = .string(v) }
        return IV.strictHash(.object(["d": .string("atlas-pca/connect-request/v1"), "method": .string(method), "url": .string(url), "headers": .object(h), "body": body.map { .string($0) } ?? .null]))
    }

    /// Sign a release receipt body `{v: 1, kind: 'pca-release-receipt', action_digest, provider, connection_id, mode, scopes_released,
    /// request_digest, http_status, outcome, ts}` with the vault key (Ed25519 seed).
    public static func signReleaseReceipt(_ body: JSONValue, seed: [UInt8]) throws -> JSONValue {
        let key = PCASuiteKey.ed25519(try Ed25519Deterministic.key(seed: seed))
        return .object(try PCAIssue.signArtifact(domain: RELEASE_RECEIPT_DOMAIN, body: body, signer: key))
    }

    /// True iff the receipt is signed by the pinned vault key.
    public static func verifyReleaseReceipt(_ r: JSONValue?, vaultPk: String) -> Bool {
        guard let o = r?.asObject else { return false }
        return IntentWB.verifyArtifactSig(RELEASE_RECEIPT_DOMAIN, o, vaultPk)
    }

    /// The digest of the exact PCActn that authorized a release (`escalationActionDigest`).
    public static func receiptActionDigest(_ pcactn: JSONValue) -> String? { PCA.escalationActionDigest(pcactn: pcactn) }
}
