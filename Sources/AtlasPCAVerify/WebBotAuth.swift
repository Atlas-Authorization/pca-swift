import Foundation
import CryptoKit

/// Single-use store for accepted signatures (`replayCache` of `verifySignedRequest`). `claim` is true when the key is claimed for the first time
/// (until its expiry); an implementation that cannot decide must throw (the verification then fails closed).
public protocol WebBotAuthReplayCache: AnyObject {
    func claim(_ key: String, _ expiresAtSec: Double, _ nowSec: Double) throws -> Bool
}

/// In-process replay cache: fails CLOSED (throws) when `maxEntries` unexpired claims are held.
public final class WebBotAuthMemoryReplayCache: WebBotAuthReplayCache {
    private var seen: [JKey: Double] = [:]
    private let maxEntries: Double

    public init(maxEntries: Double = 100_000) { self.maxEntries = maxEntries }

    public func claim(_ key: String, _ expiresAtSec: Double, _ nowSec: Double) throws -> Bool {
        if !nowSec.isFinite || !expiresAtSec.isFinite { return false }
        if Double(seen.count) >= maxEntries {
            seen = seen.filter { !(nowSec.isFinite && $0.value < nowSec) }
            if Double(seen.count) >= maxEntries { throw JSError("replay cache full") }
        }
        if let existing = seen[JKey(key)], !(nowSec.isFinite && existing < nowSec) { return false }
        seen[JKey(key)] = expiresAtSec
        return true
    }
}

/// A resolved verification key: the raw 32 Ed25519 bytes or a public OKP / Ed25519 JWK.
public enum WebBotAuthKey {
    case raw([UInt8])
    case jwk(JSONValue)
}

/// A key to publish in a directory: `keyid` defaults to the RFC 7638 thumbprint.
public struct WebBotAuthDirectoryKey {
    public var publicKey: [UInt8]
    public var keyid: String?
    public var use: JSONValue?
    public var nbf: JSONValue?
    public var exp: JSONValue?
    public init(publicKey: [UInt8], keyid: String? = nil, use: JSONValue? = nil, nbf: JSONValue? = nil, exp: JSONValue? = nil) {
        self.publicKey = publicKey; self.keyid = keyid; self.use = use; self.nbf = nbf; self.exp = exp
    }
}

/// Web Bot Auth for Proof-Carrying Authority: RFC 9421 HTTP Message Signatures over outbound agent requests in the "web-bot-auth" profile (so
/// a PCA agent passes automated-traffic bot verification AND carries its per-action proof in the SAME request), the signed key directory,
/// RFC 9530 Content-Digest and the PCA proof binding. The signature base is built byte for byte as the reference does.
/// `verifySignedRequest` FAILS CLOSED (a parse error, a stale window, a wrong tag, an unknown key or a bad signature returns
/// {valid: false, reason}); a valid signature proves the key holder signed THIS request's covered components inside the window, not that the
/// action is authorized (the PCActn verifier's job).
///
/// Values are the parsed-JSON model (`JSONValue`); input and option bags are objects keyed by the reference's names. A signing key is an object
/// with a base64url `secretKey` (the 32-byte seed).
/// shortcut: request URLs must be http(s) / ws(s) / ftp (other schemes are refused where the reference would accept them), a `@target-uri`
/// covering a URL with credentials or a fragment is refused, and an IDN host is refused unless AtlasPCAAda registered an IDNA mapping; header objects arrive without
/// insertion order, so two header names that differ only in case are joined in code-unit order. Upgrade when a non-HTTP target is signed.
public enum PCAWebBotAuth {
    public static let WEB_BOT_AUTH_TAG = "web-bot-auth"
    public static let WEB_BOT_AUTH_ALG = "ed25519"
    public static let WELL_KNOWN_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
    public static let DIRECTORY_CONTENT_TYPE = "application/http-message-signatures-directory+json"
    public static let DEFAULT_SIGNATURE_LABEL = "sig1"
    public static let DEFAULT_EXPIRES_SEC = 300.0
    public static let SIGNATURE_AGENT_HEADER = "Signature-Agent"
    public static let PCA_HEADER = "PCA-Action"
    public static let PCA_PROOF_COMPONENT = "pca-action"
    public static let CONTENT_DIGEST_HEADER = "Content-Digest"
    public static let CONTENT_DIGEST_ALGS = ["sha-256", "sha-512"]
    public static let DIRECTORY_SIGNATURE_TAG = "http-message-signatures-directory"
    static let DEFAULT_DIRECTORY_LIFETIME_SEC = 86_400.0

    /// A refusal while parsing a signature header (its message is part of the verification reason).
    struct ParseError: Error { let message: String }
    static func pe(_ m: String) -> ParseError { ParseError(message: m) }
    static func typeError(_ m: String) -> JSError { JSError("TypeError: \(m)") }
    static func text(_ e: Error) -> String { (e as? ParseError)?.message ?? (e as? JSError)?.message ?? "\(e)" }

    // ---- small JS helpers ----

    static func eq(_ a: String, _ b: String) -> Bool { a.unicodeScalars.elementsEqual(b.unicodeScalars) }
    static func str(_ b: ArraySlice<UInt8>) -> String { String(decoding: b, as: UTF8.self) }
    static func str(_ b: [UInt8]) -> String { String(decoding: b, as: UTF8.self) }
    static func trim(_ b: [UInt8]) -> [UInt8] { Array(Attest.jsTrim(str(b)).utf8) }
    static func has(_ v: JSONValue?, _ k: String) -> Bool { v?.asObject?[JKey(k)] != nil }
    /// `v[k] ?? undefined`: a missing member and a JSON null are both absent.
    static func opt(_ v: JSONValue?, _ k: String) -> JSONValue? { JS.present(v?.get(k)) }
    static func nowSec() -> Double { Date().timeIntervalSince1970.rounded(.down) }
    static func b64url(_ b: [UInt8]) -> String { Base64URLStrict.encode(b) }
    static func b64(_ b: [UInt8]) -> String { Data(b).base64EncodedString() }
    static func numOr(_ o: JSONValue?, _ k: String, _ d: Double) -> Double { opt(o, k).map { JS.toNumber($0) } ?? d }
    static func isNum(_ v: JSONValue?) -> Double? {
        switch v { case let .int(i)?: return Double(i); case let .double(d)?: return d; default: return nil }
    }

    /// `===` over parsed JSON scalars (strings by code points, numbers by value).
    static func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.string(x)?, .string(y)?): return eq(x, y)
        case let (.bool(x)?, .bool(y)?): return x == y
        case (.null?, .null?): return true
        default:
            if let x = isNum(a), let y = isNum(b) { return x == y }
            return false
        }
    }

    /// RFC 8941 sf-string (quoted, `\` and `"` escaped); a non-string is a TypeError like `s.replace`.
    static func sf(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw typeError("value is not a string") }
        return sf(s)
    }
    static func sf(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            if u == "\\" || u == "\"" { out.unicodeScalars.append("\\") }
            out.unicodeScalars.append(u)
        }
        return out + "\""
    }

    static func thumbprintOfX(_ x: String) -> String {
        b64url(Canonical.sha256(Array("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"\(x)\"}".utf8)))
    }

    /// RFC 7638 JWK thumbprint of an Ed25519 public key (base64url of SHA-256 over the canonical JWK).
    public static func jwkThumbprint(_ publicKey: [UInt8]) -> String { thumbprintOfX(b64url(publicKey)) }

    /// An Ed25519 signing identity from `{secretKey: base64url seed}`: the seed.
    static func signingSeed(_ k: JSONValue?) throws -> [UInt8] {
        guard let sk = opt(k, "secretKey")?.asString, let seed = Base64URLStrict.decode(sk, length: 32) else { throw JSError("key must carry a secretKey") }
        return seed
    }

    // ---- structured-field helpers (targeted to the RFC 9421 grammars; byte level, every delimiter is ASCII) ----

    static func splitTop(_ s: [UInt8], _ sep: UInt8) -> [[UInt8]] {
        var out: [[UInt8]] = []
        var depth = 0, start = 0, i = 0
        var inStr = false
        while i < s.count {
            let c = s[i]
            if inStr {
                if c == 0x5c { i += 1 } else if c == 0x22 { inStr = false }
                i += 1; continue
            }
            if c == 0x22 { inStr = true }
            else if c == 0x28 { depth += 1 }
            else if c == 0x29 { depth = max(0, depth - 1) }
            else if c == sep && depth == 0 { out.append(Array(s[start..<i])); start = i + 1 }
            i += 1
        }
        out.append(Array(s[min(start, s.count)...]))
        return out
    }

    static func indexTop(_ s: [UInt8], _ ch: UInt8) -> Int {
        var depth = 0, i = 0
        var inStr = false
        while i < s.count {
            let c = s[i]
            if inStr {
                if c == 0x5c { i += 1 } else if c == 0x22 { inStr = false }
                i += 1; continue
            }
            if c == 0x22 { inStr = true }
            else if c == 0x28 { depth += 1 }
            else if c == 0x29 { depth = max(0, depth - 1) }
            else if c == ch && depth == 0 { return i }
            i += 1
        }
        return -1
    }

    static func matchingParen(_ s: [UInt8], _ open: Int) -> Int {
        guard open < s.count, s[open] == 0x28 else { return -1 }
        var depth = 0, i = open
        var inStr = false
        while i < s.count {
            let c = s[i]
            if inStr {
                if c == 0x5c { i += 1 } else if c == 0x22 { inStr = false }
                i += 1; continue
            }
            if c == 0x22 { inStr = true }
            else if c == 0x28 { depth += 1 }
            else if c == 0x29 { depth -= 1; if depth == 0 { return i } }
            i += 1
        }
        return -1
    }

    /// The decoded sf-string at `s[i]` and the offset after its closing quote.
    static func readSf(_ s: [UInt8], _ i: Int) throws -> ([UInt8], Int) {
        guard i < s.count, s[i] == 0x22 else { throw pe("expected a quoted string") }
        var out: [UInt8] = []
        var j = i + 1
        while j < s.count {
            let c = s[j]
            if c == 0x5c {
                guard j + 1 < s.count, s[j + 1] == 0x22 || s[j + 1] == 0x5c else { throw pe("invalid escape in string") }
                out.append(s[j + 1]); j += 2
            } else if c == 0x22 {
                return (out, j + 1)
            } else {
                out.append(c); j += 1
            }
        }
        throw pe("unterminated string")
    }

    static func isDigits(_ b: ArraySlice<UInt8>) -> Bool { !b.isEmpty && b.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }

    /// A parameter value: string / integer / decimal / boolean / token (as the reference reads it).
    static func parseParamValue(_ raw: [UInt8]) throws -> JSONValue {
        let s = trim(raw)
        if s.isEmpty { return .bool(true) }
        if s[0] == 0x22 {
            let (v, next) = try readSf(s, 0)
            guard next == s.count else { throw pe("trailing characters after string parameter") }
            return .string(str(v))
        }
        if s == Array("?1".utf8) { return .bool(true) }
        if s == Array("?0".utf8) { return .bool(false) }
        let body = s[0] == 0x2d ? s[1...] : s[...]
        if isDigits(body) { return .double(Double(str(s)) ?? .infinity) }
        if let dot = body.firstIndex(of: 0x2e), isDigits(body[..<dot]), isDigits(body[(dot + 1)...]) { return .double(Double(str(s)) ?? .infinity) }
        return .string(str(s))
    }

    static func parseParams(_ paramStr: [UInt8]) throws -> [JKey: JSONValue] {
        var params: [JKey: JSONValue] = [:]
        let t = trim(paramStr)
        if t.isEmpty { return params }
        guard t[0] == 0x3b else { throw pe("expected parameters to start with \";\"") }
        for part in splitTop(Array(t[1...]), 0x3b) {
            let seg = trim(part)
            if seg.isEmpty { continue }
            let eqAt = indexTop(seg, 0x3d)
            if eqAt == -1 { params[JKey(str(seg))] = .bool(true) }
            else { params[JKey(str(trim(Array(seg[..<eqAt]))))] = try parseParamValue(Array(seg[(eqAt + 1)...])) }
        }
        return params
    }

    static func isLineTerminator(_ u: Unicode.Scalar) -> Bool { u == "\n" || u == "\r" || u == "\u{2028}" || u == "\u{2029}" }

    /// The index after the quoted string `"(?:[^"\\]|\\.)*"` starting at `u[i]`, or nil.
    static func quotedEnd(_ u: [Unicode.Scalar], _ i: Int) -> Int? {
        guard i < u.count, u[i] == "\"" else { return nil }
        var j = i + 1
        while j < u.count {
            if u[j] == "\"" { return j + 1 }
            if u[j] == "\\" {
                guard j + 1 < u.count, !isLineTerminator(u[j + 1]) else { return nil }
                j += 2
            } else { j += 1 }
        }
        return nil
    }

    /// `^;key=("...")$`: the quoted token, or nil.
    static func keyParam(_ rest: [UInt8]) -> [UInt8]? {
        let u = Array(str(rest).unicodeScalars)
        let pre = Array(";key=".unicodeScalars)
        guard u.count > pre.count, Array(u[0..<pre.count]) == pre, let end = quotedEnd(u, pre.count), end == u.count else { return nil }
        return Array(String(String.UnicodeScalarView(u[pre.count...])).utf8)
    }

    static func isLowerAscii(_ c: Unicode.Scalar) -> Bool { c.value >= 0x61 && c.value <= 0x7a }
    static func isDigitAscii(_ c: Unicode.Scalar) -> Bool { c.value >= 0x30 && c.value <= 0x39 }
    static func isAlnumAscii(_ c: Unicode.Scalar) -> Bool { isLowerAscii(c) || isDigitAscii(c) || (c.value >= 0x41 && c.value <= 0x5a) }

    /// `^(;[a-z*][a-z0-9_.*-]*(=("..."|[A-Za-z0-9_.:/*+%-]+))?)*$`
    static func canonicalParamTail(_ u: [Unicode.Scalar]) -> Bool {
        var i = 0
        while i < u.count {
            guard u[i] == ";" else { return false }
            i += 1
            guard i < u.count, isLowerAscii(u[i]) || u[i] == "*" else { return false }
            i += 1
            while i < u.count, isLowerAscii(u[i]) || isDigitAscii(u[i]) || "_.*-".unicodeScalars.contains(u[i]) { i += 1 }
            if i < u.count, u[i] == "=" {
                i += 1
                if i < u.count, u[i] == "\"" {
                    guard let e = quotedEnd(u, i) else { return false }
                    i = e
                } else {
                    let s = i
                    while i < u.count, isAlnumAscii(u[i]) || "_.:/*+%-".unicodeScalars.contains(u[i]) { i += 1 }
                    if i == s { return false }
                }
            }
        }
        return true
    }

    struct Comp { let id: String; let raw: String; let key: String? }
    struct SigInput { let label: String; let comps: [Comp]; let paramsRaw: String; let params: [JKey: JSONValue] }

    static func comp(_ id: String, key: String? = nil) -> Comp {
        Comp(id: id, raw: key.map { "\"\(id)\";key=\(sf($0))" } ?? "\"\(id)\"", key: key)
    }

    static func parseSignatureInput(_ value: String) throws -> [SigInput] {
        var entries: [SigInput] = []
        for memberRaw in splitTop(Array(value.utf8), 0x2c) {
            let member = trim(memberRaw)
            if member.isEmpty { continue }
            let eqAt = indexTop(member, 0x3d)
            if eqAt == -1 { throw pe("malformed Signature-Input member") }
            let label = str(trim(Array(member[..<eqAt])))
            let paramsRaw = trim(Array(member[(eqAt + 1)...]))
            guard paramsRaw.first == 0x28 else { throw pe("Signature-Input value must be an inner list") }
            let close = matchingParen(paramsRaw, 0)
            if close == -1 { throw pe("unterminated inner list") }
            var comps: [Comp] = []
            for chunkRaw in splitTop(Array(paramsRaw[1..<close]), 0x20) {
                let chunk = trim(chunkRaw)
                if chunk.isEmpty { continue }
                let (nameB, next) = try readSf(chunk, 0)
                let id = str(nameB)
                let lowered = id.lowercased()
                let rest = trim(Array(chunk[next...]))
                if rest.isEmpty { comps.append(comp(lowered)); continue }
                // the only component parameter supported is `key` (dictionary member), on header components
                guard let q = keyParam(rest), !lowered.hasPrefix("@") else { throw pe("unsupported component parameters on \"\(id)\"") }
                comps.append(comp(lowered, key: str(try readSf(q, 0).0)))
            }
            entries.append(SigInput(label: label, comps: comps, paramsRaw: str(paramsRaw), params: try parseParams(Array(paramsRaw[(close + 1)...]))))
        }
        return entries
    }

    /// label -> raw signature bytes (a later label wins).
    static func parseSignature(_ value: String) throws -> [JKey: [UInt8]] {
        var out: [JKey: [UInt8]] = [:]
        for memberRaw in splitTop(Array(value.utf8), 0x2c) {
            let member = trim(memberRaw)
            if member.isEmpty { continue }
            let eqAt = indexTop(member, 0x3d)
            if eqAt == -1 { throw pe("malformed Signature member") }
            let label = str(trim(Array(member[..<eqAt])))
            let v = trim(Array(member[(eqAt + 1)...]))
            guard v.count >= 2, v.first == 0x3a, v.last == 0x3a else { throw pe("Signature value must be a byte sequence (:base64:)") }
            out[JKey(label)] = Attest.nodeB64(str(v[1..<(v.count - 1)]))
        }
        return out
    }

    // ---- signature base (RFC 9421 section 2.5) ----

    struct Context {
        let method: String, authority: String, path: String, scheme: String, query: String, requestTarget: String
        let targetUri: String?
        let headers: [JKey: String]
    }

    /// Lower-cased name -> value (list values trimmed and joined; repeats joined, in code-unit order of the names).
    static func normalizeHeaders(_ h: JSONValue?) throws -> [JKey: String] {
        var m: [JKey: String] = [:]
        guard let o = h?.asObject else { return m }
        // JS own-key order (the text order, then keys added by the code): names differing only in case join in that order, `a, b`
        for k in JS.keyOrder(o) {
            let value: String
            switch o[k]! {
            case let .array(a):
                var parts: [String] = []
                for x in a {
                    guard let s = x.asString else { throw typeError("x.trim is not a function") }
                    parts.append(Attest.jsTrim(s))
                }
                value = parts.joined(separator: ", ")
            case let .string(s): value = Attest.jsTrim(s)
            default: throw typeError("v.trim is not a function")
            }
            let name = JKey(k.s.lowercased())
            m[name] = m[name].map { $0 + ", " + value } ?? value
        }
        return m
    }

    static let httpSchemes: Set<String> = ["http", "https", "ws", "wss", "ftp"]

    static func noFragment(_ url: String) -> String { url.firstIndex(of: "#").map { String(url[..<$0]) } ?? url }

    /// Whether the authority of `url` (fragment already cut) carries credentials.
    static func hasCredentials(_ noFrag: String) -> Bool {
        let b = Array(noFrag.utf8)
        guard let s = (0..<max(0, b.count - 1)).first(where: { b[$0] == 0x2f && b[$0 + 1] == 0x2f }) else { return false }
        var end = b.count
        var k = s + 2
        while k < b.count { if b[k] == 0x2f || b[k] == 0x5c || b[k] == 0x3f { end = k; break }; k += 1 }
        return b[(s + 2)..<end].contains(0x40)
    }

    /// Whether `@target-uri` can be derived: the platform URL keeps credentials and a fragment in its href, which this port does not carry.
    static func plainUrl(_ url: String) -> Bool { !url.contains("#") && !hasCredentials(url) }

    static func buildContext(_ method: JSONValue?, _ url: JSONValue?, _ headers: [JKey: String]) throws -> Context {
        guard let us = url?.asString, let u = WhatwgURL.parse(us) else { throw JSError("Invalid URL") }
        guard httpSchemes.contains(u.scheme) else { throw JSError("unsupported URL scheme") }
        guard let m = method?.asString else { throw typeError("method.toUpperCase is not a function") }
        let search = u.search ?? ""
        let path = u.pathname.isEmpty ? "/" : u.pathname
        var target: String?
        if plainUrl(us) { target = u.scheme + "://" + u.host + u.pathname + search + (search.isEmpty && us.contains("?") ? "?" : "") }
        return Context(method: m.uppercased(), authority: u.host.lowercased(), path: path, scheme: u.scheme, query: search.isEmpty ? "?" : search,
                       requestTarget: path + search, targetUri: target, headers: headers)
    }

    static func derive(_ c: Comp, _ ctx: Context) throws -> String {
        switch c.id {
        case "@method": return ctx.method
        case "@authority": return ctx.authority
        case "@path": return ctx.path
        case "@target-uri":
            guard let t = ctx.targetUri else { throw pe("@target-uri is not supported for a URL with credentials or a fragment") }
            return t
        case "@scheme": return ctx.scheme
        case "@query": return ctx.query
        case "@request-target": return ctx.requestTarget
        default:
            if c.id.hasPrefix("@") { throw pe("unsupported derived component \"\(c.id)\"") }
            guard let v = ctx.headers[JKey(c.id)] else { throw pe("covered header \"\(c.id)\" is absent from the request") }
            if let k = c.key { return try dictionaryMember(v, k, c.id) }
            return v
        }
    }

    /// RFC 9421 section 2.1.2: the serialized value of dictionary member `key` (string members only; anything else fails closed).
    static func dictionaryMember(_ header: String, _ key: String, _ name: String) throws -> String {
        for memberRaw in splitTop(Array(header.utf8), 0x2c) {
            let member = trim(memberRaw)
            let eqAt = indexTop(member, 0x3d)
            if eqAt == -1 || !eq(str(trim(Array(member[..<eqAt]))), key) { continue }
            let value = trim(Array(member[(eqAt + 1)...]))
            let (_, next) = try readSf(value, 0)
            // parameters are allowed only in compact canonical form, so the verbatim text IS the serialization
            guard canonicalParamTail(Array(str(value[next...]).unicodeScalars)) else { throw pe("member \"\(key)\" of \"\(name)\" is not in canonical form") }
            return str(value)
        }
        throw pe("\"\(name)\" has no dictionary member \"\(key)\"")
    }

    static func signatureBase(_ comps: [Comp], _ paramsRaw: String, _ ctx: Context) throws -> String {
        var lines = try comps.map { "\($0.raw): \(try derive($0, ctx))" }
        lines.append("\"@signature-params\": \(paramsRaw)")
        return lines.joined(separator: "\n")
    }

    // ---- signRequest ----

    /// The `Signature-Input` and `Signature` header values over the RFC 9421 signature base. `input`: method, url, headers, key ({secretKey}),
    /// keyid, created (epoch seconds, default now), expiresInSec (300), agentDirectoryUrl (also emits and covers Signature-Agent),
    /// agentDirectoryKey (dictionary form, needs agentDirectoryUrl), components (derived components replacing the default
    /// `@authority @method @path`, plus `@query` for a URL with a query; `@authority` required), coverHeaders, nonce, label.
    /// Returns {signatureInput, signature, signatureAgent?, covered, headers}.
    static func invalidUrl() -> JSError { JSError("Invalid URL", code: "ERR_INVALID_URL") }

    public static func signRequest(_ input: JSONValue?) throws -> JSONValue {
        guard input?.asObject != nil else {
            // null / undefined: reading `label` of it is a TypeError; any other value has no `url`, and `new URL(undefined)` is ERR_INVALID_URL
            if input == nil || input == .null { throw typeError("input is not an object") }
            throw invalidUrl()
        }
        let label = opt(input, "label").map { JS.toString($0) } ?? DEFAULT_SIGNATURE_LABEL
        let created = opt(input, "created").map { JS.toNumber($0) } ?? nowSec()
        let expires = created + numOr(input, "expiresInSec", DEFAULT_EXPIRES_SEC)

        var working = try normalizeHeaders(input?.get("headers"))
        var emitted: JObject = [:]
        // `new URL(x)` stringifies x: a non-string is a string only through its JS string form (an array / object / number), and must still parse
        let url = input?.get("url")?.asString ?? input?.get("url").map { JS.toString($0) } ?? "undefined"
        guard WhatwgURL.parse(url) != nil else { throw invalidUrl() }

        var derived: [JSONValue]
        if let given = opt(input, "components") {
            guard let a = given.asArray else { throw typeError("components is not iterable") }
            derived = a
        } else {
            derived = [.string("@authority"), .string("@method"), .string("@path")]
            // a URL with a query string also covers @query (the verifier requires it): /\?[^#]/
            let b = Array(url.utf8)
            if (0..<max(0, b.count - 1)).contains(where: { b[$0] == 0x3f && b[$0 + 1] != 0x23 }) { derived.append(.string("@query")) }
        }
        guard derived.contains(.string("@authority")) else { throw JSError("signRequest: the web-bot-auth profile requires @authority to be covered") }
        var comps: [Comp] = []
        for d in derived {
            guard let id = d.asString else { throw typeError("component is not a string") }
            let lower = id.lowercased()
            guard lower.hasPrefix("@") else { throw JSError("signRequest: components must be derived components, got \"\(id)\" (use coverHeaders for headers)") }
            comps.append(comp(lower))
        }

        var signatureAgent: String?
        if has(input, "agentDirectoryUrl") {
            let hasKey = has(input, "agentDirectoryKey")
            let akey = input?.get("agentDirectoryKey")
            if hasKey && akey?.asString == nil { throw JSError("signRequest: agentDirectoryKey must be a string") }
            let agentUrl = try sf(input?.get("agentDirectoryUrl"))
            let value = hasKey ? "\(akey!.asString!)=\(agentUrl)" : agentUrl
            signatureAgent = value
            working[JKey("signature-agent")] = value
            emitted[JKey(SIGNATURE_AGENT_HEADER)] = .string(value)
            comps.append(comp("signature-agent", key: hasKey ? akey!.asString! : nil))
        } else if has(input, "agentDirectoryKey") {
            throw JSError("signRequest: agentDirectoryKey requires agentDirectoryUrl")
        }

        if let cover = opt(input, "coverHeaders") {
            for n in try JS.spread(cover) {
                guard let name = n.asString else { throw typeError("header name is not a string") }
                let lower = name.lowercased()
                guard working[JKey(lower)] != nil else { throw JSError("signRequest: covered header \"\(name)\" is not present in headers") }
                if !comps.contains(where: { eq($0.id, lower) }) { comps.append(comp(lower)) }
            }
        }

        let ctx = try buildContext(input?.get("method"), .string(url), working)

        // the parameter order follows the draft's examples: created, keyid, alg, expires, nonce, tag
        var paramsRaw = "(\(comps.map { $0.raw }.joined(separator: " ")));created=\(JS.toString(.double(created)));keyid=\(try sf(input?.get("keyid")));alg=\(sf(WEB_BOT_AUTH_ALG));expires=\(JS.toString(.double(expires)))"
        if has(input, "nonce") { paramsRaw += ";nonce=\(try sf(input?.get("nonce")))" }
        paramsRaw += ";tag=\(sf(WEB_BOT_AUTH_TAG))"

        let base = try signatureBase(comps, paramsRaw, ctx)
        let sig = Ed25519Deterministic.sign(seed: try signingSeed(input?.get("key")), Array(base.utf8))
        let signatureInput = "\(label)=\(paramsRaw)"
        let signature = "\(label)=:\(b64(sig)):"
        emitted[JKey("Signature-Input")] = .string(signatureInput)
        emitted[JKey("Signature")] = .string(signature)
        var out: JObject = ["signatureInput": .string(signatureInput), "signature": .string(signature),
                            "covered": .array(comps.map { .string($0.id) }), "headers": .object(emitted)]
        if let s = signatureAgent { out[JKey("signatureAgent")] = .string(s) }
        return .object(out)
    }

    // ---- verifySignedRequest ----

    static func xFromResolved(_ k: WebBotAuthKey?) -> String? {
        switch k {
        case nil: return nil
        case let .raw(b)?: return b.count == 32 ? b64url(b) : nil
        case let .jwk(j)?:
            guard let x = j.get("x")?.asString, j.get("crv")?.asString == "Ed25519", j.get("kty")?.asString == "OKP" else { return nil }
            return x
        }
    }

    static func resolveX(_ keyid: String, _ opts: JSONValue?, _ resolveKey: ((String) throws -> WebBotAuthKey?)?, _ now: Double, _ skew: Double) throws -> String? {
        if let r = resolveKey { return xFromResolved(try r(keyid)) }
        if JS.truthy(opts?.get("resolveKey")) { throw typeError("opts.resolveKey is not a function") }
        guard JS.truthy(opts?.get("jwks")) else { return nil }
        guard let keys = opts?.get("jwks")?.get("keys")?.asArray else { throw typeError("opts.jwks.keys.find is not a function") }
        var match: JSONValue?
        for j in keys {
            if j == .null { throw typeError("Cannot read properties of null (reading 'kid')") }
            if let kid = j.get("kid")?.asString, eq(kid, keyid) { match = j; break }
        }
        guard let m = match else { return nil }
        // a published validity window is enforced; a bound that is present but not a finite number cannot be checked (fail closed)
        for b in ["nbf", "exp"] where has(m, b) { guard let d = isNum(m.get(b)), d.isFinite else { return nil } }
        if (has(m, "nbf") || has(m, "exp")) && !(now.isFinite && skew.isFinite) { return nil }
        if has(m, "nbf"), now + skew < (isNum(m.get("nbf")) ?? .nan) { return nil }
        if has(m, "exp"), now - skew > (isNum(m.get("exp")) ?? .nan) { return nil }
        return xFromResolved(.jwk(m))
    }

    static func invalid(_ reason: String) -> JSONValue { .object(["valid": .bool(false), "reason": .string(reason)]) }

    static func verifyEd25519(x: String, _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        let pub = Attest.nodeB64(x)
        guard pub.count == 32, sig.count == 64 else { return false }
        return Jose.verifySignature(alg: "EdDSA", key: .ed25519(pub), input: msg, sig: sig)
    }

    /// Verify the HTTP Message Signature of `req` ({method, url, headers}). `opts`: resolveKey (the closure takes precedence) or jwks (a key
    /// directory), now (epoch seconds), clockSkewSec (0), maxAgeSec, requireExpires (default true), requiredTag (default web-bot-auth; null =
    /// not enforced), label, requiredComponents (default `@authority @method @path`, plus `@query` for a URL with a query), maxLifetimeSec
    /// (300; infinity disables). Never throws. Returns {valid, reason?, label?, keyid?, covered?, created?, expires?, tag?, nonce?}.
    public static func verifySignedRequest(_ req: JSONValue?, _ opts: JSONValue?, resolveKey: ((String) throws -> WebBotAuthKey?)? = nil,
                                           replayCache: WebBotAuthReplayCache? = nil) -> JSONValue {
        do {
            if resolveKey == nil && !JS.truthy(opts?.get("resolveKey")) && !JS.truthy(opts?.get("jwks")) {
                return invalid("verifySignedRequest: provide resolveKey or jwks")
            }
            let headers = try normalizeHeaders(req?.get("headers"))
            guard let sigInputHeader = headers[JKey("signature-input")], let sigHeader = headers[JKey("signature")] else {
                return invalid("missing Signature-Input or Signature header")
            }
            let inputs = try parseSignatureInput(sigInputHeader)
            let sigs = try parseSignature(sigHeader)
            let requiredTag = opts?.get("requiredTag") ?? .string(WEB_BOT_AUTH_TAG)

            var chosen: SigInput?
            if has(opts, "label") {
                let l = opts?.get("label")
                chosen = inputs.first { e in l?.asString.map { eq($0, e.label) } ?? false }
            } else if requiredTag != .null {
                chosen = inputs.first { strictEq($0.params[JKey("tag")], requiredTag) } ?? inputs.first
            } else {
                chosen = inputs.first
            }
            guard let ch = chosen else { return invalid("no matching signature in Signature-Input") }
            guard let sigBytes = sigs[JKey(ch.label)] else { return invalid("no Signature entry for label \"\(ch.label)\"") }
            let tag = ch.params[JKey("tag")]?.asString
            if requiredTag != .null && !strictEq(tag.map { JSONValue.string($0) }, requiredTag) {
                return invalid("tag \"\(tag ?? "undefined")\" does not match required \"\(JS.toString(requiredTag))\"")
            }

            // @authority is required by the profile; @method and @path too, so a signature for one request cannot be replayed on another
            // method or path of the same host
            let covered = ch.comps.map { $0.id }
            let required: [JSONValue]
            if let rc = opt(opts, "requiredComponents") { required = try JS.spread(rc) }
            else { required = [.string("@authority"), .string("@method"), .string("@path")] }
            for id in required {
                if !(id.asString.map { s in covered.contains { eq($0, s) } } ?? false) { return invalid("\(JS.toString(id)) is not a covered component") }
            }
            if !has(opts, "requiredComponents") {
                guard let url = req?.get("url")?.asString else { throw typeError("Cannot read properties of undefined (reading 'indexOf')") }
                if let q = url.firstIndex(of: "?") {
                    let query = url[url.index(after: q)...].split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
                    if !query.isEmpty && !covered.contains("@query") { return invalid("@query is not a covered component") }
                }
            }

            if let alg = ch.params[JKey("alg")], !strictEq(alg, .string(WEB_BOT_AUTH_ALG)) { return invalid("unsupported alg \"\(JS.toString(alg))\"") }

            // freshness
            let now = numOr(opts, "now", nowSec())
            let skew = numOr(opts, "clockSkewSec", 0)
            let created = isNum(ch.params[JKey("created")])
            let expires = isNum(ch.params[JKey("expires")])
            if expires == nil && opts?.get("requireExpires") != .bool(false) { return invalid("missing expires parameter") }
            if let e = expires, !(now.isFinite && skew.isFinite && e.isFinite && now <= e + skew) { return invalid("signature has expired") }
            if let c = created, !(now.isFinite && skew.isFinite && c.isFinite && c <= now + skew) { return invalid("signature created-time is in the future") }
            if has(opts, "maxAgeSec"), let c = created, !(now - c <= JS.toNumber(opts?.get("maxAgeSec")) + skew) { return invalid("signature is older than maxAgeSec") }
            let maxLifetime = numOr(opts, "maxLifetimeSec", 300)
            let finite = maxLifetime.isFinite
            if finite {
                guard let c = created else { return invalid("missing created parameter (needed to bound the signature lifetime)") }
                if let e = expires, !(e - c <= maxLifetime) { return invalid("signature lifetime exceeds maxLifetimeSec") }
            }

            guard let keyid = ch.params[JKey("keyid")]?.asString else { return invalid("missing keyid parameter") }
            guard let x = try resolveX(keyid, opts, resolveKey, now, skew) else { return invalid("could not resolve key \"\(keyid)\"") }

            let ctx = try buildContext(req?.get("method"), req?.get("url"), headers)
            let base = try signatureBase(ch.comps, ch.paramsRaw, ctx)
            if !verifyEd25519(x: x, Array(base.utf8), sigBytes) { return invalid("signature does not verify under the resolved key") }

            let nonce = ch.params[JKey("nonce")]?.asString
            if let cache = replayCache {
                let until = expires ?? (created.map { $0 + (finite ? maxLifetime : 3600) } ?? now + 3600)
                if !(try cache.claim("\(keyid)|\(nonce ?? b64url(sigBytes))", until + skew, now)) { return invalid("replayed signature") }
            }
            var out: JObject = ["valid": .bool(true), "label": .string(ch.label), "keyid": .string(keyid), "covered": .array(covered.map { .string($0) })]
            if let c = created { out[JKey("created")] = .double(c) }
            if let e = expires { out[JKey("expires")] = .double(e) }
            if let t = tag { out[JKey("tag")] = .string(t) }
            if let n = nonce { out[JKey("nonce")] = .string(n) }
            return .object(out)
        } catch {
            return invalid("verification failed (fail closed): \(text(error))")
        }
    }

    // ---- key directory (JWKS) + handler ----

    /// {keys: [{kty, crv, x, kid, use?, nbf?, exp?}]}; the kid defaults to the RFC 7638 thumbprint.
    public static func buildKeyDirectory(_ keys: [WebBotAuthDirectoryKey]) -> JSONValue {
        .object(["keys": .array(keys.map { k in
            var e: JObject = ["kty": .string("OKP"), "crv": .string("Ed25519"), "x": .string(b64url(k.publicKey)), "kid": .string(k.keyid ?? jwkThumbprint(k.publicKey))]
            if let u = k.use { e[JKey("use")] = u }
            if let n = k.nbf { e[JKey("nbf")] = n }
            if let x = k.exp { e[JKey("exp")] = x }
            return .object(e)
        })])
    }

    /// The public key JWK of a directory with this `kid`, or nil.
    public static func resolveFromDirectory(_ directory: JSONValue?, _ keyid: JSONValue?) throws -> JSONValue? {
        guard let keys = directory?.get("keys")?.asArray else { throw typeError("directory.keys.find is not a function") }
        for j in keys {
            if j == .null { throw typeError("Cannot read properties of null (reading 'kid')") }
            if let kid = j.get("kid"), strictEq(kid, keyid) { return j }
        }
        return nil
    }

    /// A framework-agnostic handler for the well-known path: {status, headers, body} (200 JSON) when the path (before any `?`) is the
    /// well-known one, else nil so a caller can fall through.
    public static func directoryHandler(_ keys: [WebBotAuthDirectoryKey]) -> (String) -> JSONValue? {
        let body = JS.stringify(buildKeyDirectory(keys), order: ["keys", "kty", "crv", "x", "kid", "use", "nbf", "exp"])
        return { pathname in
            let path = pathname.firstIndex(of: "?").map { String(pathname[..<$0]) } ?? pathname
            guard eq(path, WELL_KNOWN_DIRECTORY_PATH) else { return nil }
            return .object(["status": .int(200), "headers": .object(["content-type": .string(DIRECTORY_CONTENT_TYPE), "cache-control": .string("max-age=86400")]), "body": .string(body)])
        }
    }

    // ---- PCA proof binding ----

    /// The `PCA-Action` header carrying a PCActn (base64url of its canonical wire form).
    public static func proofHeaders(_ pcactn: JSONValue) -> [String: String] { [PCA_HEADER: PCAIssue.header(pcactn)] }

    /// Reverse `proofHeaders`: refuses anything but the strict unpadded base64url of an object within the size limit.
    public static func decodeProofHeader(_ value: JSONValue?) throws -> JSONValue {
        guard let s = value?.asString, !s.isEmpty else { throw JSError("PCA-Action header is empty", code: "invalid_pca_header") }
        guard let bytes = Base64URLStrict.decode(s) else { throw JSError("PCA-Action header is not strict unpadded base64url", code: "invalid_pca_header") }
        let t = String(decoding: bytes, as: UTF8.self)
        guard Array(t.utf8) == bytes else { throw JSError("PCA-Action header does not decode to UTF-8 text", code: "invalid_pca_header") }
        if bytes.count > PCA.MAX_ARTIFACT_BYTES { throw JSError(PCA.ARTIFACT_SIZE_REASON) }
        let v = IV.normalized(try StrictJSON.parse(t))
        guard v.isObject else { throw typeError("decodePCActn: not an object") }
        return v
    }

    /// Sign a request AND bind it to a PCActn: the PCActn goes in the canonical `PCA-Action` header and that header is a covered component.
    /// `input` is the signRequest input plus `pcactn`; the result has the proof header merged into `headers`, plus `proofHeader`.
    public static func signRequestWithProof(_ input: JSONValue?) throws -> JSONValue {
        guard let io = input?.asObject else { throw typeError("input is not an object") }
        guard let pcactn = io[JKey("pcactn")] else { throw JSError("signRequestWithProof: pcactn is required") }
        let proof = proofHeaders(pcactn)
        var headers: JObject = input?.get("headers")?.asObject ?? [:]
        for (k, v) in proof { headers[JKey(k)] = .string(v) }
        var rest = io
        rest[JKey("pcactn")] = nil
        rest[JKey("headers")] = .object(headers)
        let existing = try opt(input, "coverHeaders").map { try JS.spread($0) } ?? []
        rest[JKey("coverHeaders")] = .array(existing + [.string(PCA_PROOF_COMPONENT)])
        guard case var .object(result) = try signRequest(.object(rest)) else { throw JSError("signRequest result") }
        var merged = result[JKey("headers")]?.asObject ?? [:]
        for (k, v) in proof { merged[JKey(k)] = .string(v) }
        result[JKey("headers")] = .object(merged)
        result[JKey("proofHeader")] = .object(Dictionary(uniqueKeysWithValues: proof.map { (JKey($0.key), JSONValue.string($0.value)) }))
        return .object(result)
    }

    /// Verify the HTTP Message Signature AND extract the proof: `PCA-Action` must be a covered component (else fail closed), its PCActn is
    /// decoded from it and, when `expectedPCActn` is given, must equal it by canonical digest. Returns the verify result + `pcactn`.
    public static func verifySignedRequestWithProof(_ req: JSONValue?, _ opts: JSONValue?, resolveKey: ((String) throws -> WebBotAuthKey?)? = nil,
                                                    replayCache: WebBotAuthReplayCache? = nil) -> JSONValue {
        let base = verifySignedRequest(req, opts, resolveKey: resolveKey, replayCache: replayCache)
        guard base.get("valid") == .bool(true) else { return base }
        guard base.get("covered")?.asArray?.contains(.string(PCA_PROOF_COMPONENT)) == true else {
            return invalid("the \(PCA_HEADER) proof header is not covered by the signature")
        }
        let headerValue: String?
        do { headerValue = try normalizeHeaders(req?.get("headers"))[JKey(PCA_PROOF_COMPONENT)] }
        catch { return invalid("verification failed (fail closed): \(text(error))") }
        guard let hv = headerValue else { return invalid("missing \(PCA_HEADER) header") }
        let pcactn: JSONValue
        do { pcactn = try decodeProofHeader(.string(hv)) }
        catch { return invalid("invalid PCActn in \(PCA_HEADER): \(text(error))") }
        if let expected = opt(opts, "expectedPCActn"), Canonical.hashCanonical(pcactn) != Canonical.hashCanonical(expected) {
            return invalid("carried PCActn does not match the expected proof")
        }
        guard case var .object(o) = base else { return base }
        o[JKey("pcactn")] = pcactn
        return .object(o)
    }

    // ---- Content-Digest (RFC 9530) ----

    /// The raw digest bytes of `body` under sha-256 or sha-512.
    public static func contentDigestBytes(_ body: [UInt8], _ alg: String) throws -> [UInt8] {
        switch alg {
        case "sha-256": return Array(SHA256.hash(data: Data(body)))
        case "sha-512": return Array(SHA512.hash(data: Data(body)))
        // the reference maps the name through a table: an unknown name is `createHash(undefined)`
        default: throw JSError("The \"algorithm\" argument must be of type string. Received undefined", code: "ERR_INVALID_ARG_TYPE")
        }
    }

    /// The Content-Digest field value, e.g. `sha-256=:X48E9q...=:` (members in the given order, repeats dropped).
    public static func contentDigestHeader(_ body: [UInt8], _ algs: [String] = ["sha-256"]) throws -> String {
        if algs.isEmpty { throw JSError("contentDigestHeader: name at least one algorithm") }
        var seen: [String] = []
        var parts: [String] = []
        for alg in algs {
            guard CONTENT_DIGEST_ALGS.contains(alg) else { throw JSError("contentDigestHeader: unsupported algorithm \(alg)") }
            if seen.contains(alg) { continue }
            seen.append(alg)
            parts.append("\(alg)=:\(b64(try contentDigestBytes(body, alg))):")
        }
        return parts.joined(separator: ", ")
    }

    /// `^([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/]*={0,2}):$` -> (key, base64 text), else nil.
    static func digestMember(_ m: String) -> (String, String)? {
        let u = Array(m.unicodeScalars)
        var i = 0
        guard i < u.count, isLowerAscii(u[i]) || u[i] == "*" else { return nil }
        i += 1
        while i < u.count, isLowerAscii(u[i]) || isDigitAscii(u[i]) || "_-.*".unicodeScalars.contains(u[i]) { i += 1 }
        let key = String(String.UnicodeScalarView(u[0..<i]))
        guard i + 1 < u.count, u[i] == "=", u[i + 1] == ":" else { return nil }
        i += 2
        let s = i
        while i < u.count, isAlnumAscii(u[i]) || u[i] == "+" || u[i] == "/" { i += 1 }
        var pad = 0
        while i < u.count, u[i] == "=", pad < 2 { i += 1; pad += 1 }
        guard i == u.count - 1, u[i] == ":" else { return nil }
        return (key, String(String.UnicodeScalarView(u[s..<i])))
    }

    /// key -> digest bytes, in member order. Throws on anything that is not `key=:base64:` (parameters refused, a repeated key refused).
    public static func parseContentDigest(_ value: String) throws -> [(key: String, bytes: [UInt8])] {
        var out: [(key: String, bytes: [UInt8])] = []
        for raw in value.split(separator: ",", omittingEmptySubsequences: false) {
            let member = Attest.jsTrim(String(raw))
            if member.isEmpty { throw JSError("empty dictionary member") }
            guard let (key, b64text) = digestMember(member) else { throw JSError("malformed Content-Digest member \"\(member)\"") }
            if b64text.utf8.count % 4 != 0 { throw JSError("member \"\(key)\" is not canonical base64") }
            let bytes = Attest.nodeB64(b64text)
            if b64(bytes) != b64text { throw JSError("member \"\(key)\" is not canonical base64") }
            if out.contains(where: { eq($0.key, key) }) { throw JSError("member \"\(key)\" appears twice") }
            out.append((key, bytes))
        }
        return out
    }

    /// Check `body` against a `Content-Digest` field value (nil = absent). Every supported member present must match, unsupported members are
    /// ignored (RFC 9530 section 2), at least one supported member must be present and every algorithm in `require` must be among the matched.
    /// FAILS CLOSED; never throws. Returns {valid, reason?, matched?}.
    public static func verifyContentDigest(_ header: String?, _ body: [UInt8], require: [String]? = nil) -> JSONValue {
        func fail(_ r: String) -> JSONValue { .object(["valid": .bool(false), "reason": .string(r)]) }
        guard let h = header, !Attest.jsTrim(h).isEmpty else { return fail("missing Content-Digest") }
        do {
            let members = try parseContentDigest(h)
            var matched: [String] = []
            for alg in CONTENT_DIGEST_ALGS {
                guard let m = members.first(where: { eq($0.key, alg) }) else { continue }
                if !Jose.ctEq(m.bytes, try contentDigestBytes(body, alg)) { return fail("\(alg) digest does not match the content") }
                matched.append(alg)
            }
            if matched.isEmpty { return fail("no supported digest algorithm (sha-256 or sha-512)") }
            for alg in require ?? [] where !matched.contains(alg) { return fail("required \(alg) digest is absent") }
            return .object(["valid": .bool(true), "matched": .array(matched.map { .string($0) })])
        } catch {
            return fail("malformed Content-Digest: \(text(error))")
        }
    }

    // ---- signed key directory (draft-meunier-http-message-signatures-directory section 5.2) ----

    /// Strictly parse a directory document: every key a well-formed Ed25519 OKP JWK with a string kid. Throws otherwise.
    public static func parseKeyDirectory(_ text: String) throws -> JSONValue {
        guard let doc = JSONValue.parse(text) else { throw JSError("JSON parse error") }
        guard let keys = doc.get("keys")?.asArray, !keys.isEmpty else { throw JSError("directory has no keys") }
        for j in keys {
            var bad = !j.isObject || j.get("kty")?.asString != "OKP" || j.get("crv")?.asString != "Ed25519" || (j.get("kid")?.asString ?? "").isEmpty
            if !bad {
                let x = Array((j.get("x")?.asString ?? "").unicodeScalars)
                bad = x.count != 43 || !x.allSatisfy { isAlnumAscii($0) || $0 == "_" || $0 == "-" }
            }
            for f in ["nbf", "exp"] where !bad && has(j, f) { bad = !(isNum(j.get(f))?.isFinite ?? false) }
            if bad { throw JSError("directory contains a malformed key") }
        }
        return doc
    }

    /// One signature per key (its thumbprint is the `keyid`). `input`: keys ([{secretKey}]), directory (every signing key must be in it),
    /// authority (lower-case host or host:port), created, expiresInSec (86400). Returns {body, headers}.
    public static func signDirectoryResponse(_ input: JSONValue?) throws -> JSONValue {
        guard let keys = input?.get("keys")?.asArray, !keys.isEmpty else { throw JSError("signDirectoryResponse: at least one signing key is required") }
        guard let authority = input?.get("authority")?.asString, !authority.isEmpty,
              authority.unicodeScalars.allSatisfy({ isLowerAscii($0) || isDigitAscii($0) || ".-[]:".unicodeScalars.contains($0) }) else {
            throw JSError("signDirectoryResponse: authority must be a lower-case host or host:port")
        }
        let created = opt(input, "created").map { JS.toNumber($0) } ?? nowSec()
        let expires = created + numOr(input, "expiresInSec", DEFAULT_DIRECTORY_LIFETIME_SEC)
        guard let directory = input?.get("directory") else { throw typeError("directory is undefined") }
        let body = JS.stringify(directory, order: ["keys", "kty", "crv", "x", "kid", "use", "nbf", "exp"])
        var inputs: [String] = [], sigs: [String] = []
        for (i, k) in keys.enumerated() {
            let seed = try signingSeed(k)
            let x = b64url(Ed25519Deterministic.publicKey(seed: seed))
            guard (directory.get("keys")?.asArray ?? []).contains(where: { $0.get("x")?.asString.map { eq($0, x) } ?? false }) else {
                throw JSError("signDirectoryResponse: a signing key is not in the directory")
            }
            let label = "sig\(i + 1)"
            let params = "(\"@authority\";req);created=\(JS.toString(.double(created)));expires=\(JS.toString(.double(expires)));keyid=\"\(thumbprintOfX(x))\";alg=\"ed25519\";tag=\"\(DIRECTORY_SIGNATURE_TAG)\""
            inputs.append("\(label)=\(params)")
            sigs.append("\(label)=:\(b64(Ed25519Deterministic.sign(seed: seed, Array("\"@authority\";req: \(authority)\n\"@signature-params\": \(params)".utf8)))):")
        }
        return .object(["body": .string(body), "headers": .object(["content-type": .string(DIRECTORY_CONTENT_TYPE),
                                                                     "signature-input": .string(inputs.joined(separator: ", ")),
                                                                     "signature": .string(sigs.joined(separator: ", "))])])
    }

    static func dirFail(_ reason: String) -> JSONValue { .object(["valid": .bool(false), "reason": .string(reason), "keys": .array([])]) }

    /// `^([a-z][a-z0-9_.*-]*)=` at the start of `u`: (label, index after the `=`).
    static func labelPrefix(_ u: [Unicode.Scalar]) -> (String, Int)? {
        var i = 0
        guard i < u.count, isLowerAscii(u[i]) else { return nil }
        i += 1
        while i < u.count, isLowerAscii(u[i]) || isDigitAscii(u[i]) || "_.*-".unicodeScalars.contains(u[i]) { i += 1 }
        guard i < u.count, u[i] == "=" else { return nil }
        return (String(String.UnicodeScalarView(u[0..<i])), i + 1)
    }

    /// `^label=:([A-Za-z0-9+/]+={0,2}):$` -> (label, base64 text).
    static func sigPart(_ part: String) -> (String, String)? {
        let u = Array(part.unicodeScalars)
        guard let (label, at) = labelPrefix(u), at < u.count, u[at] == ":" else { return nil }
        var i = at + 1
        let s = i
        while i < u.count, isAlnumAscii(u[i]) || u[i] == "+" || u[i] == "/" { i += 1 }
        if i == s { return nil }
        let e = i
        var pad = 0
        while i < u.count, u[i] == "=", pad < 2 { i += 1; pad += 1 }
        guard i == u.count - 1, u[i] == ":" else { return nil }
        return (label, String(String.UnicodeScalarView(u[s..<e])) + String(repeating: "=", count: pad))
    }

    /// `^label=("@authority";req)((?:;[a-z]+=(?:[0-9]+|"[A-Za-z0-9_.\-]*"))*)$` -> (label, ";a=1;b=\"x\"" parameter text).
    static func directoryEntry(_ raw: String) -> (String, String)? {
        let u = Array(raw.unicodeScalars)
        guard let (label, at) = labelPrefix(u) else { return nil }
        let fixed = Array("(\"@authority\";req)".unicodeScalars)
        guard at + fixed.count <= u.count, Array(u[at..<(at + fixed.count)]) == fixed else { return nil }
        var i = at + fixed.count
        let start = i
        while i < u.count {
            guard u[i] == ";" else { return nil }
            i += 1
            let s = i
            while i < u.count, isLowerAscii(u[i]) { i += 1 }
            guard i > s, i < u.count, u[i] == "=" else { return nil }
            i += 1
            if i < u.count, u[i] == "\"" {
                i += 1
                while i < u.count, isAlnumAscii(u[i]) || "_.-".unicodeScalars.contains(u[i]) { i += 1 }
                guard i < u.count, u[i] == "\"" else { return nil }
                i += 1
            } else {
                let d = i
                while i < u.count, isDigitAscii(u[i]) { i += 1 }
                if i == d { return nil }
            }
        }
        return (label, String(String.UnicodeScalarView(u[start...])))
    }

    /// Verify a signed directory response. `input`: authority, headers (signature-input, signature), body, now, clockSkewSec, maxLifetimeSec
    /// (86400). Fail closed: {valid: false, reason, keys: []} for a missing or malformed signature header, a body that is not a well-formed
    /// directory, or when NO signature is valid. When valid, `keys` holds only the directory keys that carry a valid signature.
    public static func verifyDirectoryResponse(_ input: JSONValue?) -> JSONValue {
        do {
            let hdrs = input?.get("headers")
            let sigInputV = hdrs?.get("signature-input"), sigHeaderV = hdrs?.get("signature")
            if !JS.truthy(sigInputV) || !JS.truthy(sigHeaderV) { return dirFail("missing signature-input or signature header") }
            guard let sigInput = sigInputV?.asString, let sigHeader = sigHeaderV?.asString, let bodyText = input?.get("body")?.asString else {
                throw typeError("header or body is not a string")
            }
            let dir = try parseKeyDirectory(bodyText)
            var sigs: [JKey: [UInt8]] = [:]
            for part in sigHeader.components(separatedBy: ", ") {
                guard let (label, b) = sigPart(part) else { return dirFail("malformed signature header") }
                sigs[JKey(label)] = Attest.nodeB64(b)
            }
            let now = numOr(input, "now", nowSec())
            let skew = numOr(input, "clockSkewSec", 0)
            let maxLife = numOr(input, "maxLifetimeSec", DEFAULT_DIRECTORY_LIFETIME_SEC)
            var good: [(kid: String, key: JSONValue)] = []
            var last = "no signature entry"
            for raw in sigInput.components(separatedBy: ", ") {
                guard let (label, ptext) = directoryEntry(raw) else {
                    last = "malformed signature-input entry (must cover exactly \"@authority\";req)"; continue
                }
                var params: [JKey: String] = [:]
                var dup = false
                for p in ptext.split(separator: ";", omittingEmptySubsequences: false).dropFirst() {
                    let eqAt = p.firstIndex(of: "=")!
                    let k = JKey(String(p[..<eqAt]))
                    if params[k] != nil { dup = true }
                    params[k] = String(p[p.index(after: eqAt)...])
                }
                if dup { last = "duplicate signature parameter"; continue }
                func strP(_ k: String) -> String? {
                    guard let v = params[JKey(k)], v.hasPrefix("\"") else { return nil }
                    return String(v.dropFirst().dropLast())
                }
                func numP(_ k: String) -> Double? {
                    guard let v = params[JKey(k)], !v.isEmpty, v.unicodeScalars.allSatisfy(isDigitAscii) else { return nil }
                    return Double(v) ?? .infinity
                }
                if strP("tag").map({ !eq($0, DIRECTORY_SIGNATURE_TAG) }) ?? true { last = "wrong tag"; continue }
                if let alg = params[JKey("alg")], alg != "\"ed25519\"" { last = "unsupported alg"; continue }
                guard let created = numP("created"), let expires = numP("expires") else { last = "created and expires are required"; continue }
                if !(now.isFinite && skew.isFinite && created.isFinite && created <= now + skew) { last = "signature created-time is in the future"; continue }
                if !(expires.isFinite && now <= expires + skew) { last = "signature has expired"; continue }
                if !(expires - created <= maxLife) { last = "signature lifetime exceeds maxLifetimeSec"; continue }
                guard let keyid = strP("keyid") else { last = "missing keyid"; continue }
                guard let key = (dir.get("keys")?.asArray ?? []).first(where: { eq(thumbprintOfX($0.get("x")?.asString ?? ""), keyid) }) else {
                    last = "keyid is not the thumbprint of any directory key"; continue
                }
                if (isNum(key.get("nbf")).map { now + skew < $0 } ?? false) || (isNum(key.get("exp")).map { now - skew > $0 } ?? false) {
                    last = "directory key is outside its validity window"; continue
                }
                guard let sig = sigs[JKey(label)], sig.count == 64 else { last = "no valid signature bytes for the label"; continue }
                let base = "\"@authority\";req: \(JS.toString(input?.get("authority")))\n\"@signature-params\": \(String(raw.unicodeScalars.dropFirst(label.unicodeScalars.count + 1)))"
                if !verifyEd25519(x: key.get("x")?.asString ?? "", Array(base.utf8), sig) { last = "signature does not verify"; continue }
                let kid = key.get("kid")?.asString ?? ""
                if let at = good.firstIndex(where: { eq($0.kid, kid) }) { good[at].key = key } else { good.append((kid, key)) }
            }
            if good.isEmpty { return dirFail(last) }
            return .object(["valid": .bool(true), "keys": .array(good.map { $0.key })])
        } catch {
            return dirFail("verification failed (fail closed): \(text(error))")
        }
    }

    // ---- fetchKeyDirectory ----

    /// One HTTP response of an injected fetcher: status, headers (names lower-cased) and the text body.
    public struct FetchResponse {
        public var status: Int
        public var headers: [String: String]
        public var body: String
        public init(status: Int, headers: [String: String], body: String) { self.status = status; self.headers = headers; self.body = body }
    }

    /// Fetch and strictly parse a key directory through the injected `fetch(url, headers, timeoutMs)` (use an SSRF-safe client that never
    /// follows redirects). FAIL-CLOSED: throws on a non-https URL, a redirect, a non-200 status, a wrong content type, an oversize body, invalid
    /// JSON or any malformed key; never returns a partial directory. Options: maxBytes (characters, 65536), timeoutMs (5000),
    /// allowInsecureHttp (tests only), requireSignature (return only the keys with a valid signature over the response; throws when none), now.
    public static func fetchKeyDirectory(_ url: String, _ options: JSONValue?, fetch: (String, [String: String], Double) throws -> FetchResponse) throws -> JSONValue {
        guard let u = WhatwgURL.parse(url) else { throw JSError("Invalid URL") }
        guard httpSchemes.contains(u.scheme) else { throw JSError("directory URL must be an http(s) URL") }
        guard u.scheme == "https" || (options?.get("allowInsecureHttp") == .bool(true) && u.scheme == "http") else { throw JSError("directory URL must be https") }
        let noFrag = noFragment(url)
        if hasCredentials(noFrag) { throw JSError("directory URL must not carry credentials") }
        let search = u.search ?? ""
        let href = u.scheme + "://" + u.host + u.pathname + search + (search.isEmpty && noFrag.contains("?") ? "?" : "")
        let res = try fetch(href, ["accept": DIRECTORY_CONTENT_TYPE], numOr(options, "timeoutMs", 5000))
        if res.status != 200 { throw JSError("directory fetch returned status \(res.status)") }
        let ct = Attest.jsTrim((res.headers["content-type"] ?? "").components(separatedBy: ";")[0]).lowercased()
        if !eq(ct, DIRECTORY_CONTENT_TYPE) { throw JSError("directory has the wrong content type") }
        if Double(JS.length(res.body)) > numOr(options, "maxBytes", 65536) { throw JSError("directory response is too large") }
        let directory = try parseKeyDirectory(res.body)
        if options?.get("requireSignature") == .bool(true) {
            var inp: JObject = ["authority": .string(u.host.lowercased()),
                                "headers": .object(["signature-input": .string(res.headers["signature-input"] ?? ""), "signature": .string(res.headers["signature"] ?? "")]),
                                "body": .string(res.body)]
            if let n = opt(options, "now") { inp[JKey("now")] = n }
            let v = verifyDirectoryResponse(.object(inp))
            if v.get("valid") != .bool(true) { throw JSError("directory signature: \(v.get("reason")?.asString ?? "")") }
            return .object(["keys": v.get("keys") ?? .array([])])
        }
        return directory
    }
}
