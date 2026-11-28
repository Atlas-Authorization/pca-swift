import Foundation

/// GNAP interaction modes (RFC 9635 sections 2.5, 3.3, 4, 5.1), mirroring `@atlasauth/pca-gnap` interaction: the start modes, the
/// finish methods, the interaction hash, single-use interaction references and the authorization-server state machine
/// (pending -> approved -> finalized). Refusals are `JSError`s whose `code` is the reference InteractionError code
/// (invalid_interaction, unknown_interaction, too_many_attempts, invalid_request, expired, wrong_state, unsupported_hash).
/// The SHA-3 interaction hashes come from Sha3 (swift-crypto, or CryptoKit on OS 26+); where neither exists they are refused as unsupported_hash.
public enum PCAGnapInteraction {
    public static let START_MODES = ["redirect", "app", "user_code", "user_code_uri"]
    public static let FINISH_METHODS = ["redirect", "push"]
    /// The Named Information hash names computed here.
    public static let HASH_METHODS = ["sha-256", "sha-384", "sha-512", "sha3-256", "sha3-512"]
    static let HASHES: [String: AHash] = ["sha-256": .sha256, "sha-384": .sha384, "sha-512": .sha512]
    /// Names a JavaScript `in` test on the reference's method table also finds (Object.prototype members); they pass validation
    /// there and fail when hashed, as here.
    static let PROTO_NAMES: Set<String> = ["constructor", "__defineGetter__", "__defineSetter__", "hasOwnProperty", "__lookupGetter__",
                                           "__lookupSetter__", "isPrototypeOf", "propertyIsEnumerable", "toString", "valueOf", "__proto__", "toLocaleString"]

    static func err(_ code: String, _ msg: String) -> JSError { JSError(msg, code: code) }
    static func s(_ v: String) -> JSONValue { .string(v) }

    static func inHashMethods(_ v: JSONValue?) -> Bool {
        let k = JS.toString(v)
        return HASHES[k] != nil || Sha3.names.contains(k) || PROTO_NAMES.contains(k)
    }

    static func startName(_ e: JSONValue) -> String? { e.asString ?? e.asObject?["mode"]?.asString }

    /// RFC 9635 2.5.2: an absolute URI without a fragment; HTTPS, plain HTTP only to a loopback host, or an application-specific scheme
    /// (never javascript:, data:, file: or blob:).
    public static func callbackUriOk(_ uri: JSONValue?) -> Bool {
        guard let str = uri?.asString, JS.length(str) <= 2048, !str.contains("#"), let u = WhatwgURL.parse(str) else { return false }
        switch u.scheme {
        case "https": return true
        case "http":
            var h = u.host
            if h.hasPrefix("[") { h = String(h[...h.firstIndex(of: "]")!]) } else if let i = h.lastIndex(of: ":") { h = String(h[..<i]) }
            return h == "localhost" || h == "127.0.0.1" || h == "[::1]"
        default:
            return !["javascript", "data", "file", "blob"].contains(u.scheme)
        }
    }

    static func printableAscii(_ s: String) -> Bool { !s.isEmpty && s.utf16.allSatisfy { $0 >= 0x21 && $0 <= 0x7e } }

    /// The problems of an `interact` request (empty = valid). Unknown start modes are tolerated (the registry is open).
    public static func validateInteractRequest(_ r: JSONValue?) -> [String] {
        guard case let .object(o)? = r else { return ["interact must be an object"] }
        var e: [String] = []
        if case let .array(st)? = o["start"], !st.isEmpty, st.count <= 16 {
            for x in st where startName(x) == nil { e.append("each start entry is a mode name or an object with a mode") }
        } else {
            e.append("start must be a non-empty array of modes")
        }
        if let f = o["finish"] {
            guard f.isObject || f.asArray != nil else { return e + ["finish must be an object"] }
            if !FINISH_METHODS.contains(f.get("method")?.asString ?? "\u{0}") { e.append("finish.method must be redirect or push") }
            if !callbackUriOk(f.get("uri")) { e.append("finish.uri must be an absolute https, loopback or app-scheme URI without a fragment") }
            let n = f.get("nonce")?.asString
            if n == nil || JS.length(n!) < 8 || JS.length(n!) > 256 || !printableAscii(n!) { e.append("finish.nonce must be 8..256 printable ASCII characters") }
            if let hm = f.get("hash_method"), !inHashMethods(hm) { e.append("finish.hash_method is not a supported Named Information hash") }
        }
        return e
    }

    /// RFC 9635 4.2.3: base64url (no padding) of HASH(clientNonce \n asNonce \n interactRef \n grantEndpoint), each code unit's low
    /// byte (Node's 'ascii' encoding). `a`: clientNonce, asNonce, interactRef, grantEndpoint, hashMethod (default sha-256).
    public static func interactionHash(_ a: JSONValue) throws -> String {
        let m = JS.present(a.get("hashMethod")) ?? s("sha-256")
        let name = JS.toString(m)
        if !inHashMethods(m) { throw err("unsupported_hash", "hash_method \(name) is not supported") }
        let text = ["clientNonce", "asNonce", "interactRef", "grantEndpoint"].map { JS.toString(a.get($0)) }.joined(separator: "\n")
        let bytes = text.utf16.map { UInt8($0 & 0xff) }
        if Sha3.names.contains(name) {
            guard let d = Sha3.digest(name, bytes) else { throw err("unsupported_hash", "hash_method \(name) is not supported on this platform") }
            return Base64URLStrict.encode(d)
        }
        guard let h = HASHES[name] else { throw JSError("The \"algorithm\" argument must be of type string", code: "ERR_INVALID_ARG_TYPE") }
        return Base64URLStrict.encode(h.digest(bytes))
    }

    /// Client side: does the callback's `hash` match? Constant time. A hash that does not validate means the interact_ref must not be sent.
    public static func verifyInteractionHash(_ received: JSONValue?, _ a: JSONValue) throws -> Bool {
        guard let got = received?.asString else { return false }
        let want = Array(try interactionHash(a).utf8), g = Array(got.utf8)
        return want.count == g.count && PCAEvents.timingSafeEqual(want, g)
    }

    static let CODE_ALPHABET = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    /// A user code of `len` (6..12) characters from an alphabet without look-alikes (32 symbols: no modulo bias).
    public static func newUserCode(_ len: Int = 8) throws -> String {
        if len < 6 || len > 12 { throw JSError("user code length 6..12") }
        var g = SystemRandomNumberGenerator()
        return String((0..<len).map { _ in CODE_ALPHABET[Int(UInt8.random(in: 0...255, using: &g) % 32)] })
    }

    /// `c.replace(/[\s-]/g, '').toUpperCase()`.
    static func normCode(_ c: String) -> String {
        let ws: Set<UInt32> = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff, 0x2d]
        var out = String.UnicodeScalarView()
        for u in c.unicodeScalars where !ws.contains(u.value) && !(0x2000...0x200a).contains(u.value) { out.append(u) }
        return String(out).uppercased()
    }

    /// Client side: validate a finish callback ({hash, interact_ref}) against the client's context (clientNonce, asNonce, grantEndpoint,
    /// hashMethod?); returns the interact_ref to send.
    public static func acceptFinish(_ cb: JSONValue?, _ ctx: JObject) throws -> String {
        guard let ref = cb?.get("interact_ref")?.asString, !ref.isEmpty, let hash = cb?.get("hash"), hash.asString != nil else {
            throw err("unknown_interaction", "hash and interact_ref are required")
        }
        var a = ctx
        a["interactRef"] = s(ref)
        if try !verifyInteractionHash(hash, .object(a)) { throw err("unknown_interaction", "the callback hash does not validate") }
        return ref
    }

    /// One need per (action, location), resource `gnap:<type>:<location>`. A right without explicit actions and locations is refused.
    public static func accessToNeeds(_ access: [JSONValue]) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for a in access {
            guard let o = a.asObject else { throw JSError("Cannot read properties of \(a.isNull ? "null" : "a non-object") (reading 'actions')") }
            guard let acts = PCAGnap.nonEmptyList(o["actions"]), let locs = PCAGnap.nonEmptyList(o["locations"]) else {
                throw err("invalid_request", "access \"\(JS.toString(o["type"]))\" needs explicit actions and locations to become a need")
            }
            for v in acts { for l in locs { out.append(.object(["verb": v, "resource": s("gnap:\(JS.toString(o["type"])):\(JS.toString(l))")])) } }
        }
        return out
    }

    // ---- the authorization-server state machine ----

    static func randB64(_ n: Int) -> String {
        var g = SystemRandomNumberGenerator()
        return Base64URLStrict.encode((0..<n).map { _ in UInt8.random(in: 0...255, using: &g) })
    }

    /// One interaction's state (a reference: the server mutates it).
    public final class Interaction {
        public let id: String
        public internal(set) var state: String // pending | approved | finalized
        public let grantEndpoint: String
        public let modes: [String]
        /// method, uri, clientNonce, asNonce, hashMethod
        public internal(set) var finish: JObject?
        public internal(set) var userCode: String?
        public internal(set) var interactRef: String?
        public internal(set) var refUsed = false
        public let expiresAt: Double
        init(id: String, grantEndpoint: String, modes: [String], expiresAt: Double) {
            self.id = id; self.state = "pending"; self.grantEndpoint = grantEndpoint; self.modes = modes; self.expiresAt = expiresAt
        }
        public var json: JSONValue {
            var o: JObject = ["id": .string(id), "state": .string(state), "grantEndpoint": .string(grantEndpoint), "modes": .array(modes.map { .string($0) }),
                              "refUsed": .bool(refUsed), "expiresAt": PCASdJwt.jnum(expiresAt)]
            if let f = finish { o["finish"] = .object(f) }
            if let c = userCode { o["userCode"] = .string(c) }
            if let r = interactRef { o["interactRef"] = .string(r) }
            return .object(o)
        }
    }

    public struct ServerOptions {
        public var grantEndpoint: String
        public var supports: [String]
        public var redirectUri: (String) -> String
        public var appUri: ((String) -> String)?
        public var userCodeUri: String?
        /// Default 600.
        public var ttlSec: Double?
        public var now: () -> Double
        public init(grantEndpoint: String, supports: [String], redirectUri: @escaping (String) -> String, now: @escaping () -> Double) {
            self.grantEndpoint = grantEndpoint; self.supports = supports; self.redirectUri = redirectUri; self.now = now
        }
    }

    /// The AS side: the response never offers a mode the client did not ask for nor one the AS does not support, and each interact_ref
    /// is single use (a second presentation is too_many_attempts and finalizes the grant).
    public final class Server {
        let o: ServerOptions
        var byId: [String: Interaction] = [:]
        var byCode: [String: String] = [:]
        var byRef: [String: String] = [:]
        public init(_ o: ServerOptions) { self.o = o }

        /// Begin an interaction for an `interact` request: the interaction and the interact response.
        public func start(_ req: JSONValue) throws -> (interaction: Interaction, response: JSONValue) {
            let problems = validateInteractRequest(req)
            if !problems.isEmpty { throw err("invalid_request", problems.joined(separator: "; ")) }
            let asked = Set((req.get("start")?.asArray ?? []).compactMap(startName))
            let hasCodeUri = !(o.userCodeUri ?? "").isEmpty
            let modes = o.supports.filter { asked.contains($0) && ($0 != "app" || o.appUri != nil) && ($0 != "user_code_uri" || hasCodeUri) }
            let finish = req.get("finish")
            if modes.isEmpty && finish == nil { throw err("invalid_interaction", "no requested interaction mode is supported") }
            let id = randB64(16)
            let ttl = o.ttlSec ?? 600
            let it = Interaction(id: id, grantEndpoint: o.grantEndpoint, modes: modes, expiresAt: o.now() + ttl)
            var res: JObject = ["expires_in": PCASdJwt.jnum(ttl)]
            if modes.contains("redirect") { res["redirect"] = s(o.redirectUri(id)) }
            if modes.contains("app"), let app = o.appUri { res["app"] = s(app(id)) }
            if modes.contains("user_code") || modes.contains("user_code_uri") {
                let code = try newUserCode()
                it.userCode = code
                byCode[code] = id
                if modes.contains("user_code") { res["user_code"] = s(code) }
                if modes.contains("user_code_uri") { res["user_code_uri"] = .object(["code": s(code), "uri": s(o.userCodeUri ?? "")]) }
            }
            if let f = finish {
                let asNonce = randB64(24)
                it.finish = ["method": f.get("method") ?? .null, "uri": f.get("uri") ?? .null, "clientNonce": f.get("nonce") ?? .null,
                             "asNonce": s(asNonce), "hashMethod": JS.present(f.get("hash_method")) ?? s("sha-256")]
                res["finish"] = s(asNonce)
            }
            byId[id] = it
            return (it, .object(res))
        }

        /// The resource owner typed a code (case-insensitive, spaces and dashes ignored). A 32^8 code space is only safe behind a
        /// per-source rate limit on this lookup: the caller MUST apply one.
        public func lookupUserCode(_ code: String) -> Interaction? {
            guard let id = byCode[normCode(code)], let it = byId[id], it.state == "pending", !expired(it) else { return nil }
            return it
        }

        public func get(_ id: String) -> Interaction? { byId[id] }

        /// Fail closed: a non-finite clock or expiry reads as expired.
        func expired(_ it: Interaction) -> Bool {
            let t = o.now()
            return !(t.isFinite && it.expiresAt.isFinite && t <= it.expiresAt)
        }

        func live(_ id: String) throws -> Interaction {
            guard let it = byId[id] else { throw err("unknown_interaction", "no such interaction") }
            if expired(it) { throw err("expired", "the interaction expired") }
            return it
        }

        /// The resource owner approved: `{interactRef, finish?}`, the finish message to deliver (a redirect {method, url} or a push
        /// {method, uri, body: {hash, interact_ref}}).
        public func approve(_ id: String) throws -> JSONValue {
            let it = try live(id)
            if it.state != "pending" { throw err("wrong_state", "interaction is \(it.state)") }
            it.state = "approved"
            let ref = randB64(18)
            it.interactRef = ref
            byRef[ref] = id
            if let c = it.userCode { byCode[c] = nil }
            guard let f = it.finish else { return .object(["interactRef": s(ref)]) }
            let hash = try interactionHash(.object(["clientNonce": f["clientNonce"] ?? .null, "asNonce": f["asNonce"] ?? .null, "interactRef": s(ref),
                                                    "grantEndpoint": s(it.grantEndpoint), "hashMethod": f["hashMethod"] ?? .null]))
            let uri = f["uri"]?.asString ?? ""
            if f["method"] == s("push") {
                return .object(["interactRef": s(ref), "finish": .object(["method": s("push"), "uri": s(uri), "body": .object(["hash": s(hash), "interact_ref": s(ref)])])])
            }
            return .object(["interactRef": s(ref), "finish": .object(["method": s("redirect"), "url": s(try redirectURL(uri, hash, ref))])])
        }

        /// Continuation (RFC 9635 5.1): present the interact_ref once. A replay finalizes the grant and is too_many_attempts.
        public func consume(_ ref: String) throws -> Interaction {
            guard let id = byRef[ref], let it = byId[id] else { throw err("unknown_interaction", "no such interaction reference") }
            if it.refUsed || it.state == "finalized" {
                it.state = "finalized"
                throw err("too_many_attempts", "the interaction reference was already used")
            }
            if expired(it) { throw err("expired", "the interaction expired") }
            if it.state != "approved" { throw err("wrong_state", "interaction is \(it.state)") }
            it.refUsed = true
            return it
        }

        public func finalize(_ id: String) { byId[id]?.state = "finalized" }
    }

    // ---- the redirect callback URL ----

    static let USERINFO_ENC = Set("\"#<>?`{}/:;=@[\\]^|".unicodeScalars.map { $0.value })

    static func pct(_ s: String, _ set: Set<UInt32>) -> String {
        var out = ""
        for b in s.utf8 {
            if b < 0x21 || b > 0x7e || set.contains(UInt32(b)) { out += String(format: "%%%02X", b) } else { out.append(Character(Unicode.Scalar(b))) }
        }
        return out
    }

    static func formDecode(_ s: String) -> String {
        let plus = s.replacingOccurrences(of: "+", with: " ")
        return String(decoding: WhatwgURL.pctDecode(Array(plus.unicodeScalars)), as: UTF8.self)
    }

    static func formEncode(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            switch b {
            case 0x20: out += "+"
            case 0x30...0x39, 0x41...0x5a, 0x61...0x7a, 0x2a, 0x2d, 0x2e, 0x5f: out.append(Character(Unicode.Scalar(b)))
            default: out += String(format: "%%%02X", b)
            }
        }
        return out
    }

    /// `u = new URL(uri); u.searchParams.set('hash', h); u.searchParams.set('interact_ref', ref); u.toString()` for a URI that
    /// callbackUriOk accepted (no fragment): the URL re-serialized, its query rebuilt as form-urlencoded pairs.
    static func redirectURL(_ uri: String, _ h: String, _ ref: String) throws -> String {
        guard let d = WhatwgURL.parse(uri) else { throw JSError("Invalid URL") }
        var sc = Array(uri.unicodeScalars)
        while let f = sc.first, f.value <= 0x20 { sc.removeFirst() }
        while let l = sc.last, l.value <= 0x20 { sc.removeLast() }
        sc.removeAll { $0 == "\t" || $0 == "\n" || $0 == "\r" }
        var rest = String(String.UnicodeScalarView(sc))
        rest = String(rest[rest.index(after: rest.firstIndex(of: ":")!)...])
        var rawQ = ""
        if let q = rest.firstIndex(of: "?") { rawQ = String(rest[rest.index(after: q)...]); rest = String(rest[..<q]) }
        let special = WhatwgURL.special[d.scheme] != nil
        var authority: String? = nil
        if special {
            let t = rest.drop { $0 == "/" || $0 == "\\" }
            authority = String(t.prefix { $0 != "/" && $0 != "\\" })
            rest = ""
        } else if rest.hasPrefix("//") {
            let inner = rest.dropFirst(2)
            let a = inner.prefix { $0 != "/" }
            authority = String(a)
            rest = String(inner.dropFirst(a.count))
        }
        var out = d.scheme + ":"
        if let auth = authority {
            out += "//"
            if let at = auth.lastIndex(of: "@") {
                let cred = auth[..<at]
                let user = cred.prefix { $0 != ":" }, pw = cred.dropFirst(user.count).dropFirst()
                let u = pct(String(user), USERINFO_ENC), p = pct(String(pw), USERINFO_ENC)
                if !u.isEmpty || !p.isEmpty { out += u + (p.isEmpty ? "" : ":" + p) + "@" }
            }
            out += d.host
        }
        if !(authority != nil && !special && rest.isEmpty) { out += d.pathname }
        var pairs: [(String, String)] = rawQ.split(separator: "&", omittingEmptySubsequences: true).map { seg in
            let n = seg.prefix { $0 != "=" }
            return (formDecode(String(n)), formDecode(String(seg.dropFirst(n.count).dropFirst())))
        }
        for (name, value) in [("hash", h), ("interact_ref", ref)] {
            var kept: [(String, String)] = [], found = false
            for p in pairs {
                if p.0 == name { if found { continue }; found = true; kept.append((name, value)) } else { kept.append(p) }
            }
            if !found { kept.append((name, value)) }
            pairs = kept
        }
        return out + "?" + pairs.map { formEncode($0.0) + "=" + formEncode($0.1) }.joined(separator: "&")
    }
}
