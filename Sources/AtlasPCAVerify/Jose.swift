import Foundation
import CryptoKit

/// The compact-JWS / JWT layer shared by the protocol bridges: the canonical-spelling gate (one accepted string form per token:
/// strict unpadded base64url, strict JSON objects, no BOM) and a JWT verifier with the semantics of the reference's JOSE library
/// (crit / alg allow-list / signature, then typ, required claims, iss / sub / aud, iat / nbf / exp with a clock tolerance), with the
/// same stable error codes. Signing writes the protected header and the claims in the given member order.
public enum Jose {
    /// Test seam: the clock a default `now` reads, in epoch ms (a replay of a corpus made under a frozen clock sets it for the cases that depend on it).
    nonisolated(unsafe) static var clockOverrideMs: Double?

    public static let DEFAULT_MAX_JWS_BYTES = 64 * 1024

    public struct CanonicalJws {
        public let segments: [String]
        public let header: JObject
        public let payload: JObject?
    }

    static func canonicalError(_ reason: String, _ detail: String? = nil) -> JSError {
        JSError("non-canonical compact JWS: \(reason)" + (detail.map { " (\($0))" } ?? ""))
    }

    /// One strictly canonical unpadded base64url segment.
    public static func decodeCanonicalBase64url(_ seg: String) throws -> [UInt8] {
        let d = JWS.decodeCanonical(seg)
        guard let b = d.bytes else {
            if d.error.contains("bad-character") { throw canonicalError("bad-character") }
            if d.error.contains("impossible length") { throw canonicalError("non-canonical-base64url", "impossible length") }
            throw canonicalError("non-canonical-base64url")
        }
        return b
    }

    /// A strict-JSON document from segment bytes (no BOM, valid UTF-8, the strict profile).
    public static func parseJSONBytes(_ b: [UInt8]) throws -> JSONValue {
        if b.count >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF { throw canonicalError("bom") }
        guard let text = String(bytes: b, encoding: .utf8) else { throw canonicalError("bad-utf8") }
        do { return try StrictJSON.parse(text) } catch { throw canonicalError("bad-json", (error as? StrictJSON.ParseError)?.message) }
    }

    /// assertCanonicalCompactJws: throws unless `token` is the one canonical spelling of a compact JWS (3 parts) / JWE (5 parts).
    public static func assertCanonicalCompactJws(_ token: JSONValue?, parts: Int = 3, maxBytes: Int = DEFAULT_MAX_JWS_BYTES, jsonPayload: Bool = true) throws -> CanonicalJws {
        guard let t = token?.asString else { throw canonicalError("not-a-string") }
        if JS.length(t) > maxBytes { throw canonicalError("too-long") }
        let segs = t.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if segs.count != parts { throw canonicalError("bad-segment-count", "\(segs.count) != \(parts)") }
        var raws: [[UInt8]] = []
        for (i, s) in segs.enumerated() {
            if s.isEmpty {
                if parts == 5 && i == 1 { raws.append([]); continue }
                throw canonicalError("empty-segment", "segment \(i)")
            }
            raws.append(try decodeCanonicalBase64url(s))
        }
        guard let header = try parseJSONBytes(raws[0]).asObject else { throw canonicalError("not-an-object") }
        var payload: JObject? = nil
        if parts == 3 && jsonPayload {
            guard let p = try parseJSONBytes(raws[1]).asObject else { throw canonicalError("not-an-object") }
            payload = p
        }
        return CanonicalJws(segments: segs, header: header, payload: payload)
    }

    /// A verification key.
    public enum Key {
        case ed25519([UInt8])
        /// A 57-byte Ed448 public key; verifies only once AtlasPCAOpenSSL registers a verifier.
        case ed448([UInt8])
        /// curve "P-256" / "P-384" / "P-521", uncompressed SEC1 point.
        case ec(curve: String, point: [UInt8])
        case rsa(n: [UInt8], e: [UInt8])
        case hmac([UInt8])
    }

    /// The signature check of one JWS algorithm under one key; false for any mismatch of algorithm and key type.
    public static func verifySignature(alg: String, key: Key, input: [UInt8], sig: [UInt8]) -> Bool {
        switch (alg, key) {
        case let ("EdDSA", .ed25519(pk)), let ("Ed25519", .ed25519(pk)):
            return Ed25519Strict.verify(publicKey: pk, message: input, signature: sig)
        case let ("EdDSA", .ed448(pk)): return pk.count == 57 && sig.count == 114 && (PCAExtraCrypto.ed448Verify?(pk, input, sig) ?? false)
        case let ("ES256", .ec(c, p)) where c == "P-256": return ACrypto.ecVerify(curve: c, point: p, hash: .sha256, message: input, raw: sig)
        case let ("ES384", .ec(c, p)) where c == "P-384": return ACrypto.ecVerify(curve: c, point: p, hash: .sha384, message: input, raw: sig)
        case let ("ES512", .ec(c, p)) where c == "P-521": return ACrypto.ecVerify(curve: c, point: p, hash: .sha512, message: input, raw: sig)
        case let ("RS256", .rsa(n, e)): return rsaOK(n, e) && ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha256, message: input, sig: sig)
        case let ("RS384", .rsa(n, e)): return rsaOK(n, e) && ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha384, message: input, sig: sig)
        case let ("RS512", .rsa(n, e)): return rsaOK(n, e) && ACrypto.rsaVerifyPKCS1(n: n, e: e, hash: .sha512, message: input, sig: sig)
        case let ("PS256", .rsa(n, e)): return rsaOK(n, e) && ACrypto.rsaVerifyPSS(n: n, e: e, hash: .sha256, message: input, sig: sig, saltLength: 32)
        case let ("PS384", .rsa(n, e)): return rsaOK(n, e) && ACrypto.rsaVerifyPSS(n: n, e: e, hash: .sha384, message: input, sig: sig, saltLength: 48)
        case let ("PS512", .rsa(n, e)): return rsaOK(n, e) && ACrypto.rsaVerifyPSS(n: n, e: e, hash: .sha512, message: input, sig: sig, saltLength: 64)
        case let ("HS256", .hmac(k)): return k.count > 0 && ctEq(Array(HMAC<SHA256>.authenticationCode(for: Data(input), using: SymmetricKey(data: k))), sig)
        case let ("HS384", .hmac(k)): return k.count > 0 && ctEq(Array(HMAC<SHA384>.authenticationCode(for: Data(input), using: SymmetricKey(data: k))), sig)
        case let ("HS512", .hmac(k)): return k.count > 0 && ctEq(Array(HMAC<SHA512>.authenticationCode(for: Data(input), using: SymmetricKey(data: k))), sig)
        default: return false
        }
    }

    /// jose's checkKeyLength: RSA keys under 2048 bits are refused for RS* / PS*.
    static func rsaOK(_ n: [UInt8], _ e: [UInt8]) -> Bool { BigNat(bytes: n).bitLength >= 2048 && ACrypto.rsaKeyOK(n: n, e: e) }

    static func ctEq(_ a: [UInt8], _ b: [UInt8]) -> Bool { PCAEvents.timingSafeEqual(a, b) }

    public struct VerifyOptions {
        public var algorithms: [String]? = nil
        public var typ: String? = nil
        public var requiredClaims: [String] = []
        /// The accepted audiences (a token's `aud` string, or one of its array members, must be one of them).
        public var audience: [String]? = nil
        public var issuer: [String]? = nil
        public var subject: String? = nil
        /// Seconds.
        public var clockTolerance: Double = 0
        /// Unix seconds (floored); nil = the system clock.
        public var now: Double? = nil
        /// Seconds: iat required, and now - iat must be within it (and not in the future) beyond the tolerance.
        public var maxTokenAge: Double? = nil
        public init() {}
    }

    /// The claim a JWT claim error is about (the reference's `error.claim`): the first quoted name in its message.
    public static func claimOf(_ e: JSError) -> String? {
        let parts = e.message.split(separator: "\"", omittingEmptySubsequences: false)
        return parts.count >= 3 ? String(parts[1]) : nil
    }

    static func claimFailed(_ m: String) -> JSError { JSError(m, code: "ERR_JWT_CLAIM_VALIDATION_FAILED") }

    static func normalizeTyp(_ t: String) -> String {
        let l = t.lowercased()
        return l.hasPrefix("application/") ? String(l.dropFirst("application/".count)) : l
    }

    /// The header checks before the signature: crit (only `b64: true` is understood), alg present and allowed.
    static func checkProtectedHeader(_ h: JObject, algorithms: [String]?) throws -> String {
        if let crit = h["crit"] {
            guard let list = crit.asArray, !list.isEmpty, list.allSatisfy({ ($0.asString ?? "").isEmpty == false }) else {
                throw JSError("\"crit\" (Critical) Header Parameter MUST be an array of non-empty strings when present", code: "ERR_JWS_INVALID")
            }
            for p in list.compactMap({ $0.asString }) {
                if p != "b64" { throw JSError("Extension Header Parameter \"\(p)\" is not recognized", code: "ERR_JOSE_NOT_SUPPORTED") }
                if h["b64"] == nil { throw JSError("Extension Header Parameter \"b64\" is missing", code: "ERR_JWS_INVALID") }
            }
            guard case .bool? = h["b64"] else { throw JSError("The \"b64\" (base64url-encode payload) Header Parameter must be a boolean", code: "ERR_JWS_INVALID") }
        }
        guard let alg = JS.nonEmptyString(h["alg"]) else { throw JSError("JWS \"alg\" (Algorithm) Header Parameter missing or invalid", code: "ERR_JWS_INVALID") }
        if let a = algorithms, !a.contains(alg) { throw JSError("\"alg\" (Algorithm) Header Parameter value not allowed", code: "ERR_JOSE_ALG_NOT_ALLOWED") }
        return alg
    }

    /// jwtVerify's own check, made AFTER the signature verified (jose order): an unencoded payload (crit b64 false) is never a JWT.
    static func rejectUnencodedPayload(_ h: JObject) throws {
        if h["crit"]?.asArray?.contains(.string("b64")) == true, h["b64"] == .bool(false) { throw JSError("JWTs MUST NOT use unencoded payload", code: "ERR_JWT_INVALID") }
    }

    /// The claim-set checks (after the signature).
    public static func validateClaims(header: JObject, payload: JObject, _ o: VerifyOptions) throws {
        if let typ = o.typ, !typ.isEmpty {
            guard let ht = header["typ"]?.asString, normalizeTyp(ht) == normalizeTyp(typ) else { throw claimFailed("unexpected \"typ\" JWT header value") }
        }
        var presence = o.requiredClaims
        if o.maxTokenAge != nil { presence.append("iat") }
        if o.audience != nil { presence.append("aud") }
        if o.subject != nil { presence.append("sub") }
        if o.issuer != nil { presence.append("iss") }
        var checked: Set<String> = []
        for c in presence.reversed() where checked.insert(c).inserted && payload[JKey(c)] == nil { throw claimFailed("missing required \"\(c)\" claim") }
        if let iss = o.issuer, !iss.contains(where: { payload["iss"] == .string($0) }) { throw claimFailed("unexpected \"iss\" claim value") }
        if let sub = o.subject, payload["sub"] != .string(sub) { throw claimFailed("unexpected \"sub\" claim value") }
        if let aud = o.audience {
            let ok: Bool
            switch payload["aud"] {
            case let .string(s)?: ok = aud.contains(s)
            case let .array(a)?: ok = a.contains { m in m.asString.map { aud.contains($0) } ?? false }
            default: ok = false
            }
            if !ok { throw claimFailed("unexpected \"aud\" claim value") }
        }
        let now = o.now ?? (clockOverrideMs.map { ($0 / 1000).rounded(.down) } ?? Date().timeIntervalSince1970.rounded(.down))
        let tol = o.clockTolerance
        let maxAge = o.maxTokenAge.flatMap { $0 != 0 && !$0.isNaN ? $0 : nil }
        if payload["iat"] != nil || maxAge != nil, !(payload["iat"]?.isNumber ?? false) { throw claimFailed("\"iat\" claim must be a number") }
        if let nbf = payload["nbf"] {
            guard let n = IV.num(nbf) else { throw claimFailed("\"nbf\" claim must be a number") }
            if n > now + tol { throw claimFailed("\"nbf\" claim timestamp check failed") }
        }
        if let exp = payload["exp"] {
            guard let e = IV.num(exp) else { throw claimFailed("\"exp\" claim must be a number") }
            if e <= now - tol { throw JSError("\"exp\" claim timestamp check failed", code: "ERR_JWT_EXPIRED") }
        }
        if let max = maxAge, let iat = IV.num(payload["iat"]) {
            let age = now - iat
            if age - tol > max { throw JSError("\"iat\" claim timestamp check failed (too far in the past)", code: "ERR_JWT_EXPIRED") }
            if age < 0 - tol { throw claimFailed("\"iat\" claim timestamp check failed (it should be in the past)") }
        }
    }

    /// jwtVerify over a canonical compact JWS: header checks, the signature under `key`, then the claims. Returns (payload, header).
    public static func jwtVerify(_ jwt: JSONValue?, key: Key, _ o: VerifyOptions) throws -> (payload: JObject, header: JObject) {
        let c = try assertCanonicalCompactJws(jwt)
        let alg = try checkProtectedHeader(c.header, algorithms: o.algorithms)
        let sig = try decodeCanonicalBase64url(c.segments[2])
        if !verifySignature(alg: alg, key: key, input: Array((c.segments[0] + "." + c.segments[1]).utf8), sig: sig) {
            throw JSError("signature verification failed", code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED")
        }
        try rejectUnencodedPayload(c.header)
        try validateClaims(header: c.header, payload: c.payload!, o)
        return (c.payload!, c.header)
    }

    /// A compact JWS over JSON.stringify(header) and JSON.stringify(payload), members in the given orders (index keys first).
    public static func sign(header: JSONValue, headerOrder: [String], payload: JSONValue, payloadOrder: [String], signer: ([UInt8]) throws -> [UInt8]) throws -> String {
        let input = Base64URLStrict.encode(Array(JS.stringify(header, order: headerOrder).utf8)) + "." + Base64URLStrict.encode(Array(JS.stringify(payload, order: payloadOrder).utf8))
        return input + "." + Base64URLStrict.encode(try signer(Array(input.utf8)))
    }
}
