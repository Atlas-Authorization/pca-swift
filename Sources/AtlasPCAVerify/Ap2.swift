import Foundation
import CryptoKit

/// AP2 (Agent Payments Protocol) mandates as real SD-JWT credentials, bound to a PCA grant.
///
/// PCA governs: it decides who may spend, how much, until when, and when a human must co-sign. AP2 is the mandate wire other parties
/// verify. This file carries the SD-JWT primitives (RFC 9901): strict compact parsing (duplicate keys, fatal UTF-8, canonical
/// base64url), disclosure processing, the `sd_hash` / `issuer_jwt_hash` binding digests and ES256 (P-256) signing and verification, and
/// the mandate claim validators. `Ap2Constraints.swift` evaluates open-mandate constraints, `Ap2Chain.swift` issues, presents and verifies chains and
/// purchases (and the redeem ledger), `Ap2Pca.swift` carries the PCA terms bridge, the payment binding and the settlement payloads, and
/// `Ap2Binding.swift` verifies the PCA side of a verified payment chain.
///
/// Values are the reference's JSON shapes. A JSON object is a dictionary here, so the member ORDER of a value the producer writes into
/// a signed token (issuance / presentation) is the schema order of the mandate members and, for members outside the AP2 schema, code
/// unit order (the reference keeps insertion order). Time arguments are epoch seconds. Keys are CryptoKit P-256 private keys.
public enum PCAAp2 {
    typealias P = PayJS
    public typealias PrivateKey = P256.Signing.PrivateKey

    public static let AP2_COMMIT = "e1ea56db72a6385bce3e5c1112b3a56ce60acb43"
    public static let VCT_CHECKOUT = "mandate.checkout.1"
    public static let VCT_CHECKOUT_OPEN = "mandate.checkout.open.1"
    public static let VCT_PAYMENT = "mandate.payment.1"
    public static let VCT_PAYMENT_OPEN = "mandate.payment.open.1"
    public static let PCA_CLAIM = "x_pca"
    public static let FREQUENCIES = ["ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY"]
    public static let PCA_BINDING_VERSION = 1
    public static let TYP_TERMINAL = ["kb+sd-jwt", "kb-sd-jwt"]
    public static let TYP_INTERMEDIATE = ["kb+sd-jwt+kb", "kb-sd-jwt+kb"]
    static let MAX_HOPS = 8
    static let ROOT_TYP = "dc+sd-jwt"
    static let SD_ALGS = ["sha-256", "sha-384", "sha-512"]

    /// The producer's member order for what it signs (the schema order of the reference's object literals).
    static let KEY_ORDER: [String] = [
        "alg", "typ", "kid", "x5c", "delegate_payload", "_sd", "vct", "constraints", "transaction_id", "id", "type", "name", "website", "legal_name", "brand_name", "domain_name",
        "payee", "payment_amount", "payment_instrument", "pisp", "execution_date", "risk_data", "checkout_hash", "cnf", "jwk", "crv", "kty", "x", "y", "iat", "aud", "nonce",
        "sd_hash", "issuer_jwt_hash", "_sd_alg", "exp", "x_pca", "amount", "currency", "description", "frequency", "max_occurrences", "allowed", "min", "max",
        "conditional_transaction_id", "not_before", "not_after", "items", "acceptable_items", "quantity", "title",
        "x402Version", "scheme", "network", "payload", "transactionId",
    ]

    static func stringify(_ v: JSONValue) -> String { JS.stringify(v, order: KEY_ORDER) }

    // ---- small value helpers (JS semantics over `JSONValue?`, nil = undefined) ----

    static func isStr(_ v: JSONValue?) -> Bool { v?.asString != nil }
    static func isNonEmptyStr(_ v: JSONValue?) -> Bool { !(v?.asString ?? "").isEmpty }
    static func negZero(_ v: JSONValue?) -> Bool { if case let .double(d)? = v, d == 0, d.sign == .minus { return true }; return false }
    static func isInt(_ v: JSONValue?) -> Bool { P.safeInt(v) && !negZero(v) }
    static func isNonNegInt(_ v: JSONValue?) -> Bool { isInt(v) && (P.numOf(v) ?? -1) >= 0 }
    static func isNum(_ v: JSONValue?) -> Bool { v?.isNumber ?? false }
    static func get(_ o: JObject, _ k: String) -> JSONValue? { o[JKey(k)] }
    static func seq(_ a: JSONValue?, _ s: String) -> Bool { a?.asString == s }

    static func currencyOk(_ v: JSONValue?) -> Bool {
        guard let s = v?.asString else { return false }
        let u = Array(s.utf8)
        return u.count == 3 && u.allSatisfy { $0 >= 0x41 && $0 <= 0x5a }
    }

    static func splitS(_ s: String, _ sep: Unicode.Scalar) -> [String] {
        P.splitScalars(s, sep).map { String(String.UnicodeScalarView($0)) }
    }

    /// Node's base64url decoder: every alphabet character counts, trailing bits that do not make a byte are dropped.
    static func lenientB64u(_ s: String) -> [UInt8] {
        var out: [UInt8] = []
        var acc: UInt32 = 0, bits = 0
        for c in s.utf8 {
            let v: UInt32
            switch c {
            case 0x41...0x5a: v = UInt32(c - 0x41)
            case 0x61...0x7a: v = UInt32(c - 0x61 + 26)
            case 0x30...0x39: v = UInt32(c - 0x30 + 52)
            case 0x2d, 0x2b: v = 62
            case 0x5f, 0x2f: v = 63
            default: continue
            }
            acc = (acc << 6) | v
            bits += 6
            if bits >= 8 { bits -= 8; out.append(UInt8((acc >> UInt32(bits)) & 0xff)) }
        }
        return out
    }

    // ---- base64url + JSON helpers ----

    public static func b64uEncode(_ s: String) -> String { Base64URLStrict.encode(Array(s.utf8)) }
    public static func b64uEncode(bytes: [UInt8]) -> String { Base64URLStrict.encode(bytes) }

    /// Strict base64url decode: canonical alphabet, no padding, and the encoding must round-trip.
    public static func b64uDecode(_ s: JSONValue?, _ what: String) throws -> [UInt8] {
        guard let str = s?.asString, str.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x2d || $0 == 0x5f }) else {
            throw JSError("\(what): not base64url")
        }
        guard let b = Base64URLStrict.decode(str) else { throw JSError("\(what): non-canonical base64url") }
        return b
    }

    public static func isObject(_ v: JSONValue?) -> Bool { v?.isObject ?? false }

    /// Reject an object that repeats a key (`JSON.parse` keeps the last): run on text that already parsed.
    static func assertNoDuplicateKeys(_ text: String, _ what: String) throws {
        if let key = NoDuplicateKeys.duplicateKey(text) { throw JSError("\(what): duplicate key \(JS.stringify(.string(key)))") }
    }

    /// JSON parse that rejects duplicate keys. Numbers are parsed as written (`1000.0` is accepted).
    public static func parseJson(_ text: JSONValue?, _ what: String) throws -> JSONValue {
        guard let s = text?.asString else { throw JSError("\(what): invalid JSON (not a string)") }
        let v: JSONValue
        do { v = IV.normalized(try StrictJSON.parseLenientLastWins(s)) }
        catch { throw JSError("\(what): invalid JSON (\(error))") }
        try assertNoDuplicateKeys(s, what)
        return v
    }

    static func utf8Text(_ b: [UInt8], _ what: String) throws -> String {
        let t = String(decoding: b, as: UTF8.self)
        if Array(t.utf8) != b { throw JSError("\(what): not valid UTF-8") }
        return t
    }

    static func decodeJsonSegment(_ segment: String, _ what: String) throws -> JObject {
        let v = try parseJson(.string(try utf8Text(try b64uDecode(.string(segment), what), what)), what)
        guard case let .object(o) = v else { throw JSError("\(what): must be a JSON object") }
        return o
    }

    // ---- hashing ----

    public static func isSdAlg(_ v: JSONValue?) -> Bool { v?.asString.map { SD_ALGS.contains($0) } ?? false }

    static func digestBytes(_ data: [UInt8], _ alg: String) throws -> [UInt8] {
        switch alg {
        case "sha-256": return Array(SHA256.hash(data: Data(data)))
        case "sha-384": return Array(SHA384.hash(data: Data(data)))
        case "sha-512": return Array(SHA512.hash(data: Data(data)))
        // the reference's table has no entry for the name, so `createHash(undefined)` refuses with Node's argument-type error
        default: throw JSError("The \"algorithm\" argument must be of type string. Received undefined", code: "ERR_INVALID_ARG_TYPE")
        }
    }

    /// base64url(hash(ascii(value))): the digest used for disclosures, `sd_hash` and `checkout_hash`.
    public static func sdDigest(_ value: JSONValue?, _ alg: JSONValue? = nil) throws -> String {
        guard let s = value?.asString, s.utf8.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) else { throw JSError("digest input must be ASCII") }
        let a: String = P.nullish(alg) ? "sha-256" : (alg?.asString ?? "")
        return Base64URLStrict.encode(try digestBytes(Array(s.utf8), a))
    }

    static func sdDigest(_ s: String, _ alg: String) throws -> String { try sdDigest(.string(s), .string(alg)) }

    // ---- ES256 keys (P-256) ----

    static func publicKey(_ jwk: JObject) throws -> P256.Signing.PublicKey {
        let x = lenientB64u(get(jwk, "x")?.asString ?? ""), y = lenientB64u(get(jwk, "y")?.asString ?? "")
        guard x.count == 32, y.count == 32, let k = try? P256.Signing.PublicKey(x963Representation: Data([0x04] + x + y)) else { throw JSError("not a valid P-256 point") }
        return k
    }

    /// Validate a public JWK against `types/jwk.json` and prove the point is on the curve. Returns the JWK itself.
    @discardableResult
    public static func assertP256Jwk(_ jwk: JSONValue?, _ what: String) throws -> JObject {
        guard case let .object(o)? = jwk else { throw JSError("\(what): JWK must be an object") }
        if !seq(get(o, "kty"), "EC") || !seq(get(o, "crv"), "P-256") { throw JSError("\(what): JWK must be EC P-256") }
        for c in ["x", "y"] {
            let v = get(o, c)?.asString
            if v == nil || v!.utf8.count != 43 || !v!.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x2d || $0 == 0x5f }) {
                throw JSError("\(what): bad JWK \(c)")
            }
        }
        if o[JKey("d")] != nil { throw JSError("\(what): JWK carries private material") }
        if let a = get(o, "alg"), a.asString != "ES256" { throw JSError("\(what): JWK alg must be ES256") }
        do { _ = try publicKey(o) } catch { throw JSError("\(what): JWK is not a valid P-256 point") }
        return o
    }

    /// The public JWK of a P-256 key (never contains `d`), with an optional `kid`.
    public static func publicJwk(_ key: PrivateKey, kid: String? = nil) -> JObject {
        let raw = Array(key.publicKey.x963Representation)
        var o: JObject = ["kty": .string("EC"), "crv": .string("P-256"), "x": .string(Base64URLStrict.encode(Array(raw[1..<33]))), "y": .string(Base64URLStrict.encode(Array(raw[33..<65])))]
        if let k = kid { o["kid"] = .string(k) }
        return o
    }

    /// RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 key.
    public static func jwkThumbprint(_ jwk: JSONValue?) throws -> String {
        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(P.tostr(try P.prop(jwk, "x")))\",\"y\":\"\(P.tostr(try P.prop(jwk, "y")))\"}"
        return Base64URLStrict.encode(Canonical.sha256(Array(canonical.utf8)))
    }

    static func es256Sign(_ key: PrivateKey, _ signingInput: String) throws -> String {
        Base64URLStrict.encode(Array(try key.signature(for: Data(signingInput.utf8)).rawRepresentation))
    }

    static func es256Verify(_ jwk: JObject, _ signingInput: String, _ signature: [UInt8]) -> Bool {
        guard signature.count == 64, signature[0..<32].contains(where: { $0 != 0 }), signature[32...].contains(where: { $0 != 0 }),
              let pub = try? publicKey(jwk), let sig = try? P256.Signing.ECDSASignature(rawRepresentation: Data(signature)) else { return false }
        return pub.isValidSignature(sig, for: Data(signingInput.utf8))
    }

    // ---- compact JWT / SD-JWT parsing ----

    /// One SD-JWT: an issuer-signed JWT plus its disclosures (no trailing KB-JWT; AP2 binds with chain hops).
    public struct Hop {
        public let raw: String
        public let jwt: String
        public let header: JObject
        public let payload: JObject
        public let disclosures: [String]
        public let sdAlg: String
        public let signingInput: String
        public let signature: [UInt8]

        public var json: JSONValue {
            .object(["raw": .string(raw), "jwt": .string(jwt), "header": .object(header), "payload": .object(payload), "disclosures": .array(disclosures.map { .string($0) }),
                     "sdAlg": .string(sdAlg), "signingInput": .string(signingInput), "signature": .object(["$bytes": .string(Base64URLStrict.encode(signature))])])
        }
    }

    /// The hop's `~`-joined serialisation: what `sd_hash` is computed over.
    public static func hopSdJwt(_ hop: Hop) -> String { hop.jwt + "~" + hop.disclosures.map { $0 + "~" }.joined() }

    /// Parse one SD-JWT (`jwt~d1~...~dn~`; it must end with `~`).
    public static func parseSdJwtHop(_ token: JSONValue?) throws -> Hop {
        guard let t = token?.asString, !t.isEmpty else { throw JSError("SD-JWT: empty") }
        let us = t.unicodeScalars
        if us.first == "~" { throw JSError("SD-JWT: empty issuer JWT") }
        if us.last != "~" { throw JSError("SD-JWT: must end with \"~\" (a trailing KB-JWT is not an AP2 form)") }
        let body = String(String.UnicodeScalarView(us.dropLast()))
        let parts = splitS(body, "~")
        let jwt = parts[0]
        let disclosures = Array(parts.dropFirst())
        if disclosures.contains(where: { $0.isEmpty }) { throw JSError("SD-JWT: empty disclosure segment") }
        let seg = splitS(jwt, ".")
        if seg.count != 3 || seg.contains(where: { $0.isEmpty }) { throw JSError("SD-JWT: issuer JWT must be header.payload.signature") }
        let header = try decodeJsonSegment(seg[0], "JWT header")
        let payload = try decodeJsonSegment(seg[1], "JWT payload")
        let signature = try b64uDecode(.string(seg[2]), "JWT signature")
        let rawAlg = get(payload, "_sd_alg")
        if let ra = rawAlg, !isSdAlg(ra) { throw JSError("SD-JWT: unsupported _sd_alg \(JS.stringify(ra))") }
        return Hop(raw: t, jwt: jwt, header: header, payload: payload, disclosures: disclosures, sdAlg: rawAlg?.asString ?? "sha-256", signingInput: seg[0] + "." + seg[1], signature: signature)
    }

    /// `sd_hash` of a hop: the digest of `<jwt>~<d1>~...~` (the on-wire form of the preceding hop).
    public static func sdHashOf(_ hop: Hop, _ alg: JSONValue? = nil) throws -> String { try sdDigest(.string(hopSdJwt(hop)), P.nullish(alg) ? .string(hop.sdAlg) : alg) }

    /// `issuer_jwt_hash` of a hop: the digest of the issuer-signed JWT alone.
    public static func issuerJwtHashOf(_ hop: Hop, _ alg: JSONValue? = nil) throws -> String { try sdDigest(.string(hop.jwt), P.nullish(alg) ? .string(hop.sdAlg) : alg) }

    /// Verify the issuer JWT's ES256 signature. Anything other than `alg: ES256` is rejected.
    public static func verifyHopSignature(_ hop: Hop, _ key: JSONValue?) throws -> Bool {
        if !seq(get(hop.header, "alg"), "ES256") { return false }
        return es256Verify(try assertP256Jwk(key, "verification key"), hop.signingInput, hop.signature)
    }

    public struct ParsedJwt {
        public let header: JObject
        public let payload: JObject
        public let signingInput: String
        public let signature: [UInt8]
        public var json: JSONValue {
            .object(["header": .object(header), "payload": .object(payload), "signingInput": .string(signingInput), "signature": .object(["$bytes": .string(Base64URLStrict.encode(signature))])])
        }
    }

    /// Parse a compact JWT.
    public static func parseJwt(_ jwt: JSONValue?, _ what: String) throws -> ParsedJwt {
        guard let t = jwt?.asString else { throw JSError("expected a string") }
        let seg = splitS(t, ".")
        if seg.count != 3 || seg.contains(where: { $0.isEmpty }) { throw JSError("\(what): must be header.payload.signature") }
        return ParsedJwt(header: try decodeJsonSegment(seg[0], "\(what) header"), payload: try decodeJsonSegment(seg[1], "\(what) payload"), signingInput: seg[0] + "." + seg[1],
                         signature: try b64uDecode(.string(seg[2]), "\(what) signature"))
    }

    public static func verifyJwtEs256(_ parsed: ParsedJwt, _ key: JSONValue?) throws -> Bool {
        if !seq(get(parsed.header, "alg"), "ES256") { return false }
        return es256Verify(try assertP256Jwk(key, "verification key"), parsed.signingInput, parsed.signature)
    }

    // ---- disclosure processing (RFC 9901 section 7) ----

    enum Disclosure {
        case property(name: String, value: JSONValue)
        case element(value: JSONValue)
        var kind: String { if case .property = self { return "property" } else { return "element" } }
        var value: JSONValue { switch self { case let .property(_, v): return v; case let .element(v): return v } }
    }

    static func decodeDisclosure(_ raw: String) throws -> Disclosure {
        let parsed = try parseJson(.string(try utf8Text(try b64uDecode(.string(raw), "disclosure"), "disclosure")), "disclosure")
        guard case let .array(arr) = parsed else { throw JSError("disclosure: must be a JSON array") }
        guard let salt = arr.first?.asString, !salt.isEmpty else { throw JSError("disclosure: salt must be a non-empty string") }
        if arr.count == 3 {
            guard let name = arr[1].asString else { throw JSError("disclosure: claim name must be a string") }
            if name == "_sd" || name == "..." { throw JSError("disclosure: claim name \(name) is reserved") }
            return .property(name: name, value: arr[2])
        }
        if arr.count == 2 { return .element(value: arr[1]) }
        throw JSError("disclosure: array must have 2 or 3 elements")
    }

    /// The own keys of a JSON object in the order JavaScript lists them for a parsed object that kept no insertion order: index keys
    /// ascending, then the rest by code unit.
    static func keys(_ o: JObject) -> [JKey] {
        let idx = o.keys.compactMap { k in JS.indexKey(k.s).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        let rest = o.keys.filter { JS.indexKey($0.s) == nil }.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }
        return idx + rest
    }

    /// Resolve every selectively-disclosable claim in `payload` using `disclosures`; `_sd`, `...` markers and `_sd_alg` are removed.
    public static func processDisclosures(_ payload: JSONValue, _ disclosures: [String], _ alg: String) throws -> JSONValue {
        var byDigest: [String: Disclosure] = [:]
        for raw in disclosures {
            let d = try decodeDisclosure(raw)
            let digest = try sdDigest(raw, alg)
            if byDigest[digest] != nil { throw JSError("SD-JWT: duplicate disclosure") }
            byDigest[digest] = d
        }
        var used = Set<String>()
        func take(_ digest: JSONValue?, _ want: String) throws -> Disclosure? {
            guard let ds = digest?.asString, let d = byDigest[ds] else { return nil } // decoy digest, or a disclosure the holder chose not to reveal
            if used.contains(ds) { throw JSError("SD-JWT: a digest is referenced more than once") }
            if d.kind != want { throw JSError("SD-JWT: a \(d.kind) disclosure is referenced from a \(want) position") }
            used.insert(ds)
            return d
        }
        func walk(_ node: JSONValue, _ depth: Int) throws -> JSONValue {
            if depth > 32 { throw JSError("SD-JWT: nesting too deep") }
            switch node {
            case let .array(a):
                var out: [JSONValue] = []
                for el in a {
                    if case let .object(eo) = el, eo[JKey("...")] != nil {
                        guard eo.count == 1, eo[JKey("...")]?.asString != nil else { throw JSError("SD-JWT: malformed array digest placeholder") }
                        if let d = try take(eo[JKey("...")], "element") { out.append(try walk(d.value, depth + 1)) }
                    } else { out.append(try walk(el, depth + 1)) }
                }
                return .array(out)
            case let .object(o):
                var res: JObject = [:]
                for k in keys(o) {
                    if k.s == "_sd" || k.s == "_sd_alg" { continue }
                    if k.s == "..." { throw JSError("SD-JWT: \"...\" is only valid as the sole key of an array element") }
                    res[k] = try walk(o[k]!, depth + 1)
                }
                if let sd = o[JKey("_sd")] {
                    guard case let .array(sda) = sd, sda.allSatisfy({ $0.asString != nil }) else { throw JSError("SD-JWT: _sd must be an array of strings") }
                    for digest in sda {
                        guard let d = try take(digest, "property"), case let .property(name, value) = d else { continue }
                        if res[JKey(name)] != nil { throw JSError("SD-JWT: disclosed claim \(name) collides with an existing claim") }
                        res[JKey(name)] = try walk(value, depth + 1)
                    }
                }
                return .object(res)
            default: return node
            }
        }
        let result = try walk(payload, 0)
        if used.count != byDigest.count { throw JSError("SD-JWT: a disclosure is not referenced by the signed payload") }
        return result
    }

    // ---- issuing ----

    public static func newSalt() -> String { Base64URLStrict.encode((0..<16).map { _ in UInt8.random(in: 0...255) }) }

    public final class DisclosureBuilder {
        let alg: JSONValue?
        let salt: () -> String
        public private(set) var disclosures: [String] = []
        init(alg: JSONValue?, salt: @escaping () -> String) { self.alg = alg; self.salt = salt }

        /// Array-element disclosure for `value`; returns the `{"...": digest}` placeholder.
        public func element(_ value: JSONValue?) throws -> JSONValue {
            let raw = b64uEncode(PCAAp2.stringify(.array([.string(salt()), value ?? .null])))
            disclosures.append(raw)
            return .object(["...": .string(try PCAAp2.sdDigest(.string(raw), alg))])
        }

        /// Property disclosure; returns the digest to put into the parent's `_sd`.
        public func property(_ name: String, _ value: JSONValue?) throws -> JSONValue {
            let raw = b64uEncode(PCAAp2.stringify(.array([.string(salt()), .string(name), value ?? .null])))
            disclosures.append(raw)
            return .string(try PCAAp2.sdDigest(.string(raw), alg))
        }
    }

    public static func disclosureBuilder(_ alg: JSONValue? = nil, salt: (() -> String)? = nil) -> DisclosureBuilder {
        DisclosureBuilder(alg: P.nullish(alg) ? .string("sha-256") : alg, salt: salt ?? newSalt)
    }

    /// Sign `payload` as an ES256 JWT and append `disclosures`: `<jwt>~<d1>~...~<dn>~`. `header` members override `alg`.
    public static func signSdJwt(header: JSONValue?, payload: JSONValue, disclosures: [String], privateKey: PrivateKey) throws -> String {
        var h: JObject = [:]
        h[o: "alg"] = .string("ES256") // positioned like the spread members that follow: `{ alg, ...header }` keeps alg ahead of them
        let src = P.spreadObj(header); for k in JS.keyOrder(src) { h[o: k.s] = src[k] }
        let hs = b64uEncode(stringify(.object(h))), ps = b64uEncode(stringify(payload))
        let jwt = "\(hs).\(ps).\(try es256Sign(privateKey, "\(hs).\(ps)"))"
        return jwt + "~" + disclosures.map { $0 + "~" }.joined()
    }

    /// Sign an arbitrary compact JWT (used for merchant-signed `checkout_jwt`).
    public static func signJwtEs256(header: JSONValue?, payload: JSONValue, privateKey: PrivateKey) throws -> String {
        var h: JObject = [:]
        h[o: "alg"] = .string("ES256"); h[o: "typ"] = .string("JWT")
        let src = P.spreadObj(header); for k in JS.keyOrder(src) { h[o: k.s] = src[k] }
        let hs = b64uEncode(stringify(.object(h))), ps = b64uEncode(stringify(payload))
        return "\(hs).\(ps).\(try es256Sign(privateKey, "\(hs).\(ps)"))"
    }

    // ---- currencies and minor units ----

    static let ZERO_DECIMAL: Set<String> = ["BIF", "CLP", "DJF", "GNF", "ISK", "JPY", "KMF", "KRW", "PYG", "RWF", "UGX", "UYI", "VND", "VUV", "XAF", "XOF", "XPF"]
    static let THREE_DECIMAL: Set<String> = ["BHD", "IQD", "JOD", "KWD", "LYD", "OMR", "TND"]
    static let FOUR_DECIMAL: Set<String> = ["CLF", "UYW"]

    /// ISO 4217 minor-unit exponent for `currency` (2 for any code not in the 0/3/4-digit tables).
    public static func currencyExponent(_ currency: JSONValue?) throws -> Int {
        let text = currency?.asString ?? P.tostr(currency) // RegExp#test coerces its argument
        let u = Array(text.utf8)
        if !(u.count == 3 && u.allSatisfy { $0 >= 0x41 && $0 <= 0x5a }) {
            throw JSError("currency must be an ISO 4217 alpha-3 code, got \(currency == nil ? "undefined" : JS.stringify(currency!))")
        }
        if let s = currency?.asString {
            if ZERO_DECIMAL.contains(s) { return 0 }
            if THREE_DECIMAL.contains(s) { return 3 }
            if FOUR_DECIMAL.contains(s) { return 4 }
        }
        return 2
    }

    /// A major-unit amount (`120.5` USD) to integer minor units (`12050`). Float drift (`0.1 + 0.2`) is refused rather than rounded away.
    public static func toMinorUnits(_ major: JSONValue?, _ currency: JSONValue?) throws -> JSONValue {
        let e = try currencyExponent(currency)
        guard let m = P.numOf(major), m.isFinite, m >= 0 else { throw JSError("amount must be a finite non-negative number, got \(P.tostr(major))") }
        let fixed = String(format: "%.\(e)f", m)
        if (Double(fixed) ?? .nan) != m { throw JSError("amount \(P.tostr(major)) is not exactly representable in \(P.tostr(currency)) minor units") }
        let minor = Double(fixed.replacingOccurrences(of: ".", with: "")) ?? .infinity
        if minor > P.MAX_SAFE { throw JSError("amount \(P.tostr(major)) is outside the safe integer range in minor units") }
        return P.num(minor)
    }

    /// Integer minor units to the major-unit number PCA budgets use (exact for any safe integer).
    public static func fromMinorUnits(_ minor: JSONValue?, _ currency: JSONValue?) throws -> JSONValue {
        let e = try currencyExponent(currency)
        guard P.safeInt(minor), let f = P.numOf(minor), f >= 0, !negZero(minor) else { throw JSError("minor-unit amount must be a non-negative safe integer, got \(P.tostr(minor))") }
        return P.num(f / pow(10.0, Double(e)))
    }

    // ---- mandate validators: each returns the list of problems (empty = valid) ----

    static func merchantProblems(_ v: JSONValue?, _ at: String) -> [String] {
        guard case let .object(o)? = v else { return ["\(at): not an object"] }
        var p: [String] = []
        if !isNonEmptyStr(get(o, "id")) { p.append("\(at).id: required string") }
        if !isNonEmptyStr(get(o, "name")) { p.append("\(at).name: required string") }
        if let w = get(o, "website"), !isStr(w) { p.append("\(at).website: must be a string") }
        return p
    }

    static func amountProblems(_ v: JSONValue?, _ at: String) -> [String] {
        guard case let .object(o)? = v else { return ["\(at): not an object"] }
        var p: [String] = []
        if !isNonNegInt(get(o, "amount")) { p.append("\(at).amount: must be a non-negative integer (minor units)") }
        if !currencyOk(get(o, "currency")) { p.append("\(at).currency: must be an ISO 4217 alpha-3 code") }
        return p
    }

    static func instrumentProblems(_ v: JSONValue?, _ at: String) -> [String] {
        guard case let .object(o)? = v else { return ["\(at): not an object"] }
        var p: [String] = []
        if !isNonEmptyStr(get(o, "id")) { p.append("\(at).id: required string") }
        if !isNonEmptyStr(get(o, "type")) { p.append("\(at).type: required string") }
        if let d = get(o, "description"), !isStr(d) { p.append("\(at).description: must be a string") }
        return p
    }

    static func pispProblems(_ v: JSONValue?, _ at: String) -> [String] {
        guard case let .object(o)? = v else { return ["\(at): not an object"] }
        return ["legal_name", "brand_name", "domain_name"].filter { !isNonEmptyStr(get(o, $0)) }.map { "\(at).\($0): required string" }
    }

    static func timeProblems(_ v: JObject) -> [String] {
        ["iat", "exp"].filter { get(v, $0) != nil && !isNonNegInt(get(v, $0)) }.map { "\($0): must be an integer epoch-seconds" }
    }

    static func cnfProblems(_ v: JSONValue?) -> [String] {
        guard case let .object(o)? = v, case .object? = get(o, "jwk") else { return ["cnf: must be { jwk }"] }
        do { _ = try assertP256Jwk(get(o, "jwk"), "cnf.jwk"); return [] }
        catch { return [(error as? JSError)?.message ?? "\(error)"] }
    }

    static func pcaClaimProblems(_ v: JObject) -> [String] {
        if let c = get(v, PCA_CLAIM), !c.isObject { return ["\(PCA_CLAIM): must be an object"] }
        return []
    }

    static func listProblems(_ v: JSONValue?, _ at: String, _ each: (JSONValue?, String) -> [String]) -> [String] {
        guard case let .array(a)? = v else { return ["\(at): must be an array"] }
        var out: [String] = []
        for (i, x) in a.enumerated() { out.append(contentsOf: each(x, "\(at)[\(i)]")) }
        return out
    }

    static func paymentConstraintProblems(_ cv: JSONValue?, _ at: String) -> [String] {
        guard case let .object(c)? = cv, let t = get(c, "type")?.asString else { return ["\(at): constraint must be an object with a string type"] }
        switch t {
        case "payment.agent_recurrence":
            var p: [String] = []
            if let f = get(c, "frequency")?.asString, FREQUENCIES.contains(f) {} else { p.append("\(at).frequency: not a known frequency") }
            if let m = get(c, "max_occurrences"), !(isInt(m) && (P.numOf(m) ?? 0) > 0) { p.append("\(at).max_occurrences: must be a positive integer") }
            return p
        case "payment.allowed_payees": return listProblems(get(c, "allowed"), "\(at).allowed", merchantProblems)
        case "payment.allowed_payment_instruments": return listProblems(get(c, "allowed"), "\(at).allowed", instrumentProblems)
        case "payment.allowed_pisps": return listProblems(get(c, "allowed"), "\(at).allowed", pispProblems)
        case "payment.amount_range":
            var p: [String] = []
            if !currencyOk(get(c, "currency")) { p.append("\(at).currency: must be an ISO 4217 alpha-3 code") }
            if !isNonNegInt(get(c, "max")) { p.append("\(at).max: must be a non-negative integer (minor units)") }
            if let mn = get(c, "min"), !isNonNegInt(mn) { p.append("\(at).min: must be a non-negative integer (minor units)") }
            if isInt(get(c, "max")), isInt(get(c, "min")), (P.numOf(get(c, "min")) ?? 0) > (P.numOf(get(c, "max")) ?? 0) { p.append("\(at): min exceeds max") }
            return p
        case "payment.budget":
            var p: [String] = []
            if !currencyOk(get(c, "currency")) { p.append("\(at).currency: must be an ISO 4217 alpha-3 code") }
            if let mx = P.numOf(get(c, "max")), mx.isFinite, mx >= 0 {} else { p.append("\(at).max: must be a non-negative number (major units)") }
            return p
        case "payment.execution_date":
            return ["not_before", "not_after"].filter { get(c, $0) != nil && !isStr(get(c, $0)) }.map { "\(at).\($0): must be a string" }
        case "payment.reference":
            return isNonEmptyStr(get(c, "conditional_transaction_id")) ? [] : ["\(at).conditional_transaction_id: required string"]
        default: return ["\(at): unknown constraint type \(t)"]
        }
    }

    static func acceptableItemProblems(_ x: JSONValue?, _ ax: String) -> [String] {
        guard case let .object(o)? = x else { return ["\(ax): not an object"] }
        return ["id", "title"].filter { !isNonEmptyStr(get(o, $0)) }.map { "\(ax).\($0): required string" }
    }

    static func checkoutConstraintProblems(_ cv: JSONValue?, _ at: String) -> [String] {
        guard case let .object(c)? = cv, let t = get(c, "type")?.asString else { return ["\(at): constraint must be an object with a string type"] }
        if t == "checkout.allowed_merchants" { return listProblems(get(c, "allowed"), "\(at).allowed", merchantProblems) }
        if t == "checkout.line_items" {
            guard case let .array(items)? = get(c, "items"), !items.isEmpty else { return ["\(at).items: must be a non-empty array"] }
            var out: [String] = []
            for (i, it) in items.enumerated() {
                let a = "\(at).items[\(i)]"
                guard case let .object(io) = it else { out.append("\(a): not an object"); continue }
                if !isNonEmptyStr(get(io, "id")) { out.append("\(a).id: required string") }
                if !isInt(get(io, "quantity")) || (P.numOf(get(io, "quantity")) ?? 0) <= 0 { out.append("\(a).quantity: must be a positive integer") }
                out.append(contentsOf: listProblems(get(io, "acceptable_items"), "\(a).acceptable_items", acceptableItemProblems))
            }
            return out
        }
        return ["\(at): unknown constraint type \(t)"]
    }

    static func vctProblem(_ v: JObject, _ want: String) -> [String] { seq(get(v, "vct"), want) ? [] : ["vct: must be \(want)"] }

    static func hasType(_ constraints: JSONValue?, _ t: String) -> Bool {
        guard case let .array(a)? = constraints else { return false }
        return a.contains { c in if case let .object(o) = c { return seq(get(o, "type"), t) }; return false }
    }

    public static func openPaymentMandateProblems(_ vv: JSONValue?) -> [String] {
        guard case let .object(v)? = vv else { return ["mandate: not an object"] }
        var p = vctProblem(v, VCT_PAYMENT_OPEN) + timeProblems(v) + cnfProblems(get(v, "cnf")) + pcaClaimProblems(v)
        p.append(contentsOf: listProblems(get(v, "constraints"), "constraints", paymentConstraintProblems))
        if case .array? = get(v, "constraints"), !hasType(get(v, "constraints"), "payment.reference") { p.append("constraints: must contain a payment.reference constraint") }
        if let x = get(v, "payee") { p.append(contentsOf: merchantProblems(x, "payee")) }
        if let x = get(v, "payment_amount") { p.append(contentsOf: amountProblems(x, "payment_amount")) }
        if let x = get(v, "payment_instrument") { p.append(contentsOf: instrumentProblems(x, "payment_instrument")) }
        if let x = get(v, "pisp") { p.append(contentsOf: pispProblems(x, "pisp")) }
        if let x = get(v, "execution_date"), !isStr(x) { p.append("execution_date: must be a string") }
        if let x = get(v, "risk_data"), !x.isObject { p.append("risk_data: must be an object") }
        return p
    }

    public static func paymentMandateProblems(_ vv: JSONValue?) -> [String] {
        guard case let .object(v)? = vv else { return ["mandate: not an object"] }
        var p = vctProblem(v, VCT_PAYMENT) + timeProblems(v) + pcaClaimProblems(v)
        if !isNonEmptyStr(get(v, "transaction_id")) { p.append("transaction_id: required string") }
        p.append(contentsOf: merchantProblems(get(v, "payee"), "payee"))
        p.append(contentsOf: amountProblems(get(v, "payment_amount"), "payment_amount"))
        p.append(contentsOf: instrumentProblems(get(v, "payment_instrument"), "payment_instrument"))
        if let x = get(v, "pisp") { p.append(contentsOf: pispProblems(x, "pisp")) }
        if let x = get(v, "execution_date"), !isStr(x) { p.append("execution_date: must be a string") }
        if let x = get(v, "risk_data"), !x.isObject { p.append("risk_data: must be an object") }
        return p
    }

    public static func openCheckoutMandateProblems(_ vv: JSONValue?) -> [String] {
        guard case let .object(v)? = vv else { return ["mandate: not an object"] }
        var p = vctProblem(v, VCT_CHECKOUT_OPEN) + timeProblems(v) + cnfProblems(get(v, "cnf")) + pcaClaimProblems(v)
        p.append(contentsOf: listProblems(get(v, "constraints"), "constraints", checkoutConstraintProblems))
        if case .array? = get(v, "constraints"), !hasType(get(v, "constraints"), "checkout.line_items") { p.append("constraints: must contain a checkout.line_items constraint") }
        return p
    }

    public static func checkoutMandateProblems(_ vv: JSONValue?) -> [String] {
        guard case let .object(v)? = vv else { return ["mandate: not an object"] }
        var p = vctProblem(v, VCT_CHECKOUT) + timeProblems(v) + pcaClaimProblems(v)
        if !isNonEmptyStr(get(v, "checkout_jwt")) { p.append("checkout_jwt: required string") }
        if !isNonEmptyStr(get(v, "checkout_hash")) { p.append("checkout_hash: required string") }
        return p
    }

    @discardableResult
    public static func assertValid(_ v: JSONValue?, _ problems: (JSONValue?) -> [String], _ what: String) throws -> JSONValue? {
        let p = problems(v)
        if !p.isEmpty { throw JSError("\(what): \(p.joined(separator: "; "))") }
        return v
    }
}
