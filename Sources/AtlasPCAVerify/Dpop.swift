import Foundation
import CryptoKit

/// A replay store for DPoP proofs: true iff `key` has no live entry (one whose expiry is after `nowSec`); it then holds the key
/// until `expiresAtSec`. Must be atomic (concurrent adds of one key: exactly one wins).
public protocol DpopReplayStore {
    func addIfAbsent(_ key: String, expiresAtSec: Double, nowSec: Double) throws -> Bool
}

/// The set of jti values already seen (the caller's own replay memory).
public protocol DpopJtiSeenSet: AnyObject {
    func has(_ jti: String) -> Bool
    func add(_ jti: String)
}

/// An insertion-ordered in-memory jti set.
public final class DpopJtiSet: DpopJtiSeenSet {
    public private(set) var items: [String] = []
    private var set: Set<String> = []
    public init(_ initial: [String] = []) { for j in initial { add(j) } }
    public func has(_ jti: String) -> Bool { set.contains(jti) }
    public func add(_ jti: String) { if set.insert(jti).inserted { items.append(jti) } }
}

/// The bounded in-memory replay store: when full, expired entries are evicted; if it is still full the add throws (fail closed).
public final class InMemoryDpopReplayStore: DpopReplayStore {
    private var seen: [String: Double] = [:]
    private let max: Int
    private let lock = NSLock()

    /// `maxEntries` must be a positive integer (default 100000).
    public init(maxEntries: JSONValue? = nil) throws {
        let m = JS.present(maxEntries) ?? .int(Int64(PCADpop.INMEMORY_MAX_ENTRIES))
        guard m.isNumber, let v = m.safeInt, v >= 1 else {
            throw JSError("maxEntries must be a positive integer", code: "misconfigured")
        }
        max = Int(v)
    }

    public func addIfAbsent(_ key: String, expiresAtSec: Double, nowSec: Double) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        let held = seen[key]
        if let h = held, !(nowSec.isFinite && nowSec >= h) { return false }
        if held == nil && seen.count >= max {
            seen = seen.filter { !(nowSec.isFinite && nowSec >= $0.value) }
            if seen.count >= max { throw JSError("replay store is full") }
        }
        seen[key] = expiresAtSec
        return true
    }
}

/// Stateless server nonces (RFC 9449 section 8): base64url(ts8 || HMAC-SHA256(secret, "dpop-nonce\0" || ts8)[0..16]), valid
/// from 5 s before issue until `ttlSec` after it. Only the one canonical spelling is accepted.
public final class DpopNonceIssuer {
    let secret: [UInt8]
    let ttl: Double

    public init(secret: [UInt8]?, ttlSec: JSONValue? = nil) throws {
        guard let s = secret, s.count >= 32 else { throw JSError("nonce secret must be at least 32 bytes", code: "misconfigured") }
        let t = JS.present(ttlSec) ?? .int(300)
        guard t.isNumber, let ttl = IV.num(t), ttl.isFinite, ttl > 0 else { throw JSError("nonce ttlSec must be positive", code: "misconfigured") }
        self.secret = s
        self.ttl = ttl
    }

    func mac(_ ts: [UInt8]) -> [UInt8] {
        Array(Array(HMAC<SHA256>.authenticationCode(for: Data(Array("dpop-nonce\0".utf8) + ts), using: SymmetricKey(data: secret)))[0..<16])
    }

    static func nowSec() -> Double { Date().timeIntervalSince1970.rounded(.down) }

    /// Throws for a time that is not an integer in 0 ..< 2^64.
    public func issue(nowSec: Double? = nil) throws -> String {
        let n = nowSec ?? Self.nowSec()
        guard n.isFinite, n.rounded() == n else {
            throw JSError("The number \(JS.toString(.double(n))) cannot be converted to a BigInt because it is not an integer")
        }
        guard n >= 0, n < 18446744073709551616.0 else { throw JSError("The value of \"value\" is out of range.", code: "ERR_OUT_OF_RANGE") }
        let v = UInt64(n)
        let ts = (0..<8).map { UInt8((v >> (56 - 8 * UInt64($0))) & 0xff) }
        return Base64URLStrict.encode(ts + mac(ts))
    }

    public func check(_ nonce: JSONValue?, nowSec: Double? = nil) -> Bool {
        guard let s = nonce?.asString, let raw = Base64URLStrict.decode(s), raw.count == 24, Base64URLStrict.encode(raw) == s else { return false }
        let ts = Array(raw[0..<8])
        if !PCAEvents.timingSafeEqual(Array(raw[8...]), mac(ts)) { return false }
        let issued = Double(ts.reduce(UInt64(0)) { $0 << 8 | UInt64($1) })
        let now = nowSec ?? Self.nowSec()
        return issued <= now + PCADpop.CLOCK_SKEW_SEC && now - issued <= ttl
    }
}

/// RFC 9449 DPoP proofs (create / verify), RFC 7638 thumbprints, RFC 8705 mTLS confirmation and the PCActn <-> DPoP binding
/// (the leaf holder key is the DPoP key). Verification is fail closed: a replay store (or jti set) is required unless explicitly
/// waived, the canonical-spelling gate, exact typ, no private members in the embedded key, alg allow-list and alg / key match,
/// method / URL / age / jkt / nonce / ath checks, then the replay add. Errors carry the reference's stable `code`.
public enum PCADpop {
    public static let ALLOWED_ALGS = ["EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256"]
    public static let JWT_TYP = "dpop+jwt"
    public static let DEFAULT_MAX_AGE_SEC: Double = 300
    public static let CLOCK_SKEW_SEC: Double = 5
    public static let MAX_PROOF_BYTES = 8192
    public static let INMEMORY_MAX_ENTRIES = 100_000
    static let PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k"]

    static func fail(_ code: String, _ m: String) -> JSError { JSError(m, code: code) }
    static func member(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.asObject?[JKey(k)] }
    /// `x.kty` on null / undefined is a TypeError in the reference.
    static func readable(_ v: JSONValue?, _ prop: String) throws {
        if v == nil || v == .null { throw JSError("Cannot read properties of \(v == nil ? "undefined" : "null") (reading '\(prop)')") }
    }

    // ---- thumbprints, alg mapping ----

    /// RFC 7638 JWK thumbprint (base64url of the digest of the required members), digest sha256 (default) / sha384 / sha512.
    public static func jwkThumbprint(_ jwk: JSONValue?, digest: JSONValue? = nil) throws -> String {
        guard let j = jwk?.asObject else { throw JSError("JWK must be an object") }
        let d = JS.present(digest) ?? .string("sha256")
        let hash: AHash
        switch d {
        case .string("sha256"): hash = .sha256
        case .string("sha384"): hash = .sha384
        case .string("sha512"): hash = .sha512
        default: throw JSError("digestAlgorithm must one of \"sha256\", \"sha384\", or \"sha512\"")
        }
        func req(_ k: String, _ label: String) throws -> JSONValue {
            guard let s = JS.nonEmptyString(j[JKey(k)]) else { throw JSError("\"\(k)\" (\(label)) Parameter missing or invalid", code: "ERR_JWK_INVALID") }
            return .string(s)
        }
        var c: JObject = [:]
        switch j["kty"] {
        case .string("EC")?: c = try ["crv": req("crv", "Curve"), "x": req("x", "X Coordinate"), "y": req("y", "Y Coordinate")]
        case .string("OKP")?: c = try ["crv": req("crv", "Subtype of Key Pair"), "x": req("x", "Public Key")]
        case .string("RSA")?: c = try ["e": req("e", "Exponent"), "n": req("n", "Modulus")]
        case .string("oct")?: c = try ["k": req("k", "Key Value")]
        default: throw JSError("\"kty\" (Key Type) Parameter missing or unsupported", code: "ERR_JOSE_NOT_SUPPORTED")
        }
        c["kty"] = j["kty"]
        return Base64URLStrict.encode(hash.digest(Array(JS.stringify(.object(c)).utf8)))
    }

    public static func dpopAlgForJwk(_ jwk: JSONValue?) throws -> String {
        try readable(jwk, "kty")
        let kty = member(jwk, "kty"), crv = member(jwk, "crv")
        switch kty {
        case .string("OKP")?:
            if crv == .string("Ed25519") || crv == .string("Ed448") { return "EdDSA" }
            throw fail("unsupported_key", "unsupported OKP curve '\(JS.toString(crv))' for DPoP")
        case .string("EC")?:
            switch crv {
            case .string("P-256")?: return "ES256"
            case .string("P-384")?: return "ES384"
            case .string("P-521")?: return "ES512"
            default: throw fail("unsupported_key", "unsupported EC curve '\(JS.toString(crv))' for DPoP")
            }
        case .string("RSA")?: return "PS256"
        default: throw fail("unsupported_key", "unsupported key type '\(JS.toString(kty))' for DPoP")
        }
    }

    public static func dpopAlgMatchesJwk(_ alg: JSONValue?, _ jwk: JSONValue?) throws -> Bool {
        guard let a = alg?.asString, ALLOWED_ALGS.contains(a) else { return false }
        try readable(jwk, "kty")
        let kty = member(jwk, "kty"), crv = member(jwk, "crv")
        switch a {
        case "EdDSA": return kty == .string("OKP") && (crv == .string("Ed25519") || crv == .string("Ed448"))
        case "ES256": return kty == .string("EC") && crv == .string("P-256")
        case "ES384": return kty == .string("EC") && crv == .string("P-384")
        case "ES512": return kty == .string("EC") && crv == .string("P-521")
        default: return kty == .string("RSA")
        }
    }

    /// `${protocol}//${host}${pathname}` of the WHATWG-parsed URL (query and fragment dropped).
    public static func normalizeHtu(_ url: JSONValue?) throws -> String {
        guard let u = WhatwgURL.parse(JS.toString(url)) else { throw JSError("Invalid URL", code: "ERR_INVALID_URL") }
        return u.htu
    }

    public static func athFor(_ accessToken: String) -> String { Base64URLStrict.encode(Canonical.sha256(Array(accessToken.utf8))) }

    // ---- create ----

    static func toPublicJwk(_ jwk: JSONValue?) throws -> JSONValue {
        try readable(jwk, "kty")
        var pub: JObject = [:]
        for k in ["kty", "crv", "x", "y", "n", "e"] { if let v = member(jwk, k) { pub[JKey(k)] = v } }
        return .object(pub)
    }

    static func ecSign(_ alg: String, _ priv: JObject, _ msg: [UInt8]) throws -> [UInt8] {
        let curve = ["ES256": "P-256", "ES384": "P-384", "ES512": "P-521"][alg]!
        guard priv["kty"] == .string("EC") else { throw JSError("Invalid key for this operation, its asymmetricKeyType must be ec") }
        guard priv["crv"] == .string(curve) else { throw JSError("Invalid key curve for the algorithm, its curve must be \(curve)") }
        guard let d = priv["d"]?.asString.flatMap({ Base64URLStrict.decode($0) }) else { throw JSError("Invalid JWK EC key") }
        let data = Data(msg)
        do {
            switch alg {
            case "ES256": return Array(try P256.Signing.PrivateKey(rawRepresentation: d).signature(for: data).rawRepresentation)
            case "ES384": return Array(try P384.Signing.PrivateKey(rawRepresentation: d).signature(for: data).rawRepresentation)
            default: return Array(try P521.Signing.PrivateKey(rawRepresentation: d).signature(for: data).rawRepresentation)
            }
        } catch { throw JSError("Invalid JWK EC key") }
    }

    /// A DPoP proof for `input` {method, url, privateKey (a private JWK), publicJwk, nonce?, ath?, iat?, jti?}. Ed25519 and
    /// P-256 / P-384 / P-521 keys sign; RSA and Ed448 keys sign once AtlasPCAOpenSSL registers a signer.
    public static func createDpopProof(_ input: JSONValue?) throws -> String {
        try readable(input, "publicJwk")
        let i = input?.asObject ?? [:]
        let pub = try toPublicJwk(i["publicJwk"])
        let alg = try dpopAlgForJwk(pub)
        let iat = JS.present(i["iat"]) ?? .int(Int64(Date().timeIntervalSince1970.rounded(.down)))
        guard let method = i["method"]?.asString else { throw JSError("input.method.toUpperCase is not a function") }
        let htu = try normalizeHtu(i["url"])
        var claims: JObject = ["htm": .string(method.uppercased()), "htu": .string(htu), "iat": iat,
                               "jti": JS.present(i["jti"]) ?? .string(UUID().uuidString.lowercased())]
        if let n = i["nonce"] { claims["nonce"] = n }
        if let a = i["ath"] { claims["ath"] = a }
        guard let priv = i["privateKey"]?.asObject, priv["d"]?.asString != nil else {
            throw JSError("JSON Web Key for this operation be a private JWK")
        }
        let signer: ([UInt8]) throws -> [UInt8]
        if alg == "EdDSA" {
            guard priv["kty"] == .string("OKP"), priv["crv"] == .string("Ed25519") || priv["crv"] == .string("Ed448") else {
                throw JSError("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448")
            }
            if priv["crv"] == .string("Ed448") {
                guard let sign = PCAExtraCrypto.ed448Sign else { throw fail("unsupported_key", "Ed448 signing is not supported (link AtlasPCAOpenSSL)") }
                guard let seed = priv["d"]?.asString.flatMap({ Base64URLStrict.decode($0) }), seed.count == 57 else { throw JSError("Invalid JWK OKP key") }
                signer = { try sign(seed, $0) }
            } else {
                guard let seed = priv["d"]?.asString.flatMap({ Base64URLStrict.decode($0) }), seed.count == 32 else { throw JSError("Invalid JWK OKP key") }
                signer = { Ed25519Deterministic.sign(seed: seed, $0) }
            }
        } else if alg.hasPrefix("ES") {
            signer = { try ecSign(alg, priv, $0) }
        } else {
            guard priv["kty"] == .string("RSA") else { throw JSError("Invalid key for this operation, its asymmetricKeyType must be rsa") }
            guard let rsaSign = PCAExtraCrypto.rsaSign else { throw fail("unsupported_key", "RSA signing is not supported (link AtlasPCAOpenSSL)") }
            let parts = try PCAExtraCrypto.rsaPrivateParts(priv)
            signer = { try rsaSign(alg, parts, $0) }
        }
        let header: JSONValue = .object(["typ": .string(JWT_TYP), "alg": .string(alg), "jwk": pub])
        return try Jose.sign(header: header, headerOrder: ["typ", "alg", "jwk", "kty", "crv", "x", "y", "n", "e"],
                             payload: .object(claims), payloadOrder: ["htm", "htu", "iat", "jti", "nonce", "ath"], signer: signer)
    }

    // ---- verify ----

    public struct VerifyOptions {
        public var method: String
        public var url: String
        /// Default 300; a non-finite value is refused (misconfigured).
        public var maxAgeSec: Double? = nil
        public var expectedJkt: String? = nil
        public var seenJti: DpopJtiSeenSet? = nil
        public var replayStore: DpopReplayStore? = nil
        /// false waives the replay-store requirement (the caller detects replay elsewhere).
        public var requireReplayStore: Bool? = nil
        public var nonceIssuer: DpopNonceIssuer? = nil
        public var nowSec: Double? = nil
        public var expectedNonce: String? = nil
        public var accessToken: String? = nil
        public init(method: String, url: String) { self.method = method; self.url = url }
    }

    static func b64(_ v: JSONValue?) -> [UInt8]? { v?.asString.flatMap { Base64URLStrict.decode($0) } }

    /// The embedded JWK as a verification key for `alg` (jose EmbeddedJWK + importJWK): exact coordinate sizes, RSA >= 2048 bits.
    static func embeddedKey(_ jwk: JSONValue?, alg: String) throws -> Jose.Key {
        guard let j = jwk?.asObject else { throw JSError("\"jwk\" (JSON Web Key) Header Parameter must be a JSON Web Key") }
        switch alg {
        case "EdDSA":
            if j["crv"] == .string("Ed448") {
                guard PCAExtraCrypto.ed448Verify != nil else { throw JSError("Ed448 verification is not supported (link AtlasPCAOpenSSL)") }
                guard let x = b64(j["x"]), x.count == 57 else { throw JSError("Invalid JWK OKP key") }
                return .ed448(x)
            }
            guard j["crv"] == .string("Ed25519"), let x = b64(j["x"]), x.count == 32 else { throw JSError("Invalid JWK OKP key") }
            return .ed25519(x)
        case "ES256", "ES384", "ES512":
            let (curve, size) = ["ES256": ("P-256", 32), "ES384": ("P-384", 48), "ES512": ("P-521", 66)][alg]!
            guard let x = b64(j["x"]), let y = b64(j["y"]), x.count == size, y.count == size else { throw JSError("Invalid JWK EC key") }
            return .ec(curve: curve, point: [0x04] + x + y)
        default:
            if j["oth"] != nil { throw JSError("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported") }
            guard let n = b64(j["n"]), let e = b64(j["e"]) else { throw JSError("Invalid JWK RSA key") }
            if BigNat(bytes: n).bitLength < 2048 { throw JSError("\(alg) requires key modulusLength to be 2048 bits or larger") }
            return .rsa(n: n, e: e)
        }
    }

    /// Verify a DPoP proof: {claims, jwk, jkt}. Throws JSError with the reference's code.
    public static func verifyDpopProof(_ proof: JSONValue?, _ o: VerifyOptions) throws -> JSONValue {
        // an absent max age means the default, never "no limit"; a NaN / negative / infinite one would disable the stale check
        let maxAge = o.maxAgeSec ?? DEFAULT_MAX_AGE_SEC
        guard maxAge.isFinite, maxAge >= 0 else { throw fail("max_age", "maxAgeSec must be a finite, non-negative number of seconds") }
        if o.requireReplayStore != false && o.replayStore == nil && o.seenJti == nil {
            throw fail("replay_store_required", "no replay store configured; replay cannot be detected")
        }
        guard let p = proof?.asString, JS.length(p) <= MAX_PROOF_BYTES else {
            throw fail("oversize", "proof is not a string or exceeds \(MAX_PROOF_BYTES) bytes")
        }
        let header: JObject
        do { header = try Jose.assertCanonicalCompactJws(proof).header } catch {
            throw fail("malformed", "not a JWS: \((error as? JSError)?.message ?? "\(error)")")
        }
        if header["typ"] != .string(JWT_TYP) { throw fail("typ", "header typ must be '\(JWT_TYP)', got '\(JS.toString(header["typ"]))'") }
        guard let hj = header["jwk"] else { throw fail("no_jwk", "proof header has no embedded jwk") }
        if let obj = hj.asObject, PRIVATE_MEMBERS.contains(where: { obj[JKey($0)] != nil }) {
            throw fail("private_jwk", "proof header jwk contains private key material")
        }
        if let alg = header["alg"]?.asString, ALLOWED_ALGS.contains(alg) {
            let matches = try dpopAlgMatchesJwk(header["alg"], hj)
            if !matches { throw fail("alg_jwk_mismatch", "alg '\(alg)' does not match the embedded jwk key type") }
        }
        let payload: JObject
        do {
            _ = try Jose.checkProtectedHeader(header, algorithms: ALLOWED_ALGS)
            let key = try embeddedKey(hj, alg: header["alg"]!.asString!)
            var vo = Jose.VerifyOptions()
            vo.algorithms = ALLOWED_ALGS
            vo.typ = JWT_TYP
            vo.now = o.nowSec
            payload = try Jose.jwtVerify(proof, key: key, vo).payload
        } catch {
            throw fail("signature", "DPoP signature did not verify: \((error as? JSError)?.message ?? "\(error)")")
        }
        guard let htm = payload["htm"]?.asString else { throw fail("htm", "htm is missing or not a string") }
        guard let htu = payload["htu"]?.asString else { throw fail("htu", "htu is missing or not a string") }
        guard let iatV = payload["iat"], iatV.isNumber, let iat = IV.num(iatV), iat.isFinite else { throw fail("iat", "iat is missing or not a number") }
        guard let jti = JS.nonEmptyString(payload["jti"]) else { throw fail("jti", "jti is missing or empty") }
        if htm != o.method.uppercased() { throw fail("htm", "htm '\(htm)' does not match request method") }
        let wantHtu = try normalizeHtu(.string(o.url))
        if htu != wantHtu { throw fail("htu", "htu '\(htu)' does not match request URL") }
        let now = o.nowSec ?? Date().timeIntervalSince1970.rounded(.down)
        guard now.isFinite else { throw fail("now", "nowSec must be a finite number") }
        if !(iat <= now + CLOCK_SKEW_SEC) { throw fail("iat_future", "iat is in the future") }
        if !(now - iat <= maxAge) { throw fail("iat_stale", "proof is older than \(JS.number(maxAge))s") }
        let jkt = try jwkThumbprint(hj)
        if let want = o.expectedJkt, jkt != want { throw fail("jkt", "embedded key thumbprint does not match expected jkt") }
        if let want = o.expectedNonce, payload["nonce"] != .string(want) {
            throw fail("nonce", "proof nonce is missing or does not match the expected nonce")
        }
        if let iss = o.nonceIssuer, !iss.check(payload["nonce"], nowSec: now) { throw fail("nonce", "proof nonce is missing, forged or expired") }
        if let tok = o.accessToken, payload["ath"] != .string(athFor(tok)) {
            throw fail("ath", "proof ath is missing or does not match the access token")
        }
        if let seen = o.seenJti {
            if seen.has(jti) { throw fail("jti_replay", "jti '\(jti)' has already been seen") }
            seen.add(jti)
        }
        if let store = o.replayStore {
            let fresh: Bool
            do { fresh = try store.addIfAbsent("\(jkt).\(jti)", expiresAtSec: iat + maxAge + CLOCK_SKEW_SEC, nowSec: now) } catch {
                throw fail("replay_store_error", "replay store failed: \((error as? JSError)?.message ?? "\(error)")")
            }
            if !fresh { throw fail("jti_replay", "jti '\(jti)' has already been seen") }
        }
        return .object(["claims": .object(payload), "jwk": hj, "jkt": .string(jkt)])
    }

    /// The replay-store conformance checks; returns the names of the failed ones (empty = conformant).
    public static func runReplayStoreConformance(_ make: () throws -> DpopReplayStore) throws -> [String] {
        var failures: [String] = []
        func check(_ ok: Bool, _ name: String) { if !ok { failures.append(name) } }
        let s = try make()
        check(try s.addIfAbsent("a", expiresAtSec: 200, nowSec: 100) == true, "first sight of a key returns true")
        check(try s.addIfAbsent("a", expiresAtSec: 200, nowSec: 101) == false, "second sight of the same key returns false")
        check(try s.addIfAbsent("b", expiresAtSec: 200, nowSec: 101) == true, "a different key is independent")
        check(try s.addIfAbsent("a", expiresAtSec: 200, nowSec: 199) == false, "still seen one second before expiry")
        let t = try make()
        _ = try t.addIfAbsent("c", expiresAtSec: 200, nowSec: 100)
        check(try t.addIfAbsent("c", expiresAtSec: 400, nowSec: 200) == true, "an expired entry may be added again (nowSec >= expiresAtSec)")
        let u = try make()
        let lock = NSLock()
        var wins = 0
        var err: Error? = nil
        DispatchQueue.concurrentPerform(iterations: 16) { _ in
            do {
                let w = try u.addIfAbsent("race", expiresAtSec: 200, nowSec: 100)
                lock.lock(); if w { wins += 1 }; lock.unlock()
            } catch { lock.lock(); err = error; lock.unlock() }
        }
        if let e = err { throw e }
        check(wins == 1, "16 concurrent adds of one key: exactly one wins (got \(wins))")
        return failures
    }

    // ---- mTLS (RFC 8705) ----

    public enum CertInput {
        case der([UInt8])
        case pem(String)
    }

    /// The PEM body (or the whole text without a certificate block), lenient base64 as the reference decodes it.
    public static func pemToDer(_ pem: String) -> [UInt8] {
        var body = Substring(pem)
        if let b = pem.range(of: "-----BEGIN CERTIFICATE-----"),
           let e = pem.range(of: "-----END CERTIFICATE-----", range: b.upperBound..<pem.endIndex), b.upperBound < e.lowerBound {
            body = pem[b.upperBound..<e.lowerBound]
        }
        var out: [UInt8] = []
        var acc: UInt32 = 0, bits = 0
        for c in body.utf8 {
            let v: UInt32
            switch c {
            case 0x41...0x5A: v = UInt32(c - 0x41)
            case 0x61...0x7A: v = UInt32(c - 0x61 + 26)
            case 0x30...0x39: v = UInt32(c - 0x30 + 52)
            case 0x2B: v = 62
            case 0x2F: v = 63
            case 0x3D: return out // decoding stops at the first '='
            default: continue
            }
            acc = (acc << 6) | v; bits += 6
            if bits >= 8 { bits -= 8; out.append(UInt8((acc >> UInt32(bits)) & 0xff)) }
        }
        return out
    }

    /// {x5t#S256} over the given bytes (DER) or the decoded PEM body; no certificate parsing.
    public static func mtlsCnf(_ cert: CertInput) -> JSONValue {
        let der: [UInt8]
        switch cert { case let .der(b): der = b; case let .pem(s): der = pemToDer(s) }
        return .object(["x5t#S256": .string(Base64URLStrict.encode(Canonical.sha256(der)))])
    }

    /// The SHA-256 thumbprint of the parsed certificate's DER (bytes after a DER certificate are ignored); code `cert` otherwise.
    public static func mtlsThumbprint(_ cert: CertInput) throws -> String {
        let raw: [UInt8]
        do {
            switch cert {
            case let .pem(s): raw = try Cert.fromPEM(s).raw
            case let .der(b):
                if let c = try? Cert.parseDER(b) { raw = c.raw }
                else { raw = try Cert.fromPEM(String(decoding: b, as: UTF8.self)).raw }
            }
        } catch {
            throw fail("cert", "not an X.509 certificate: \(error)")
        }
        return Base64URLStrict.encode(Canonical.sha256(raw))
    }

    public static func assertMtlsBound(_ cert: CertInput, _ cnf: JSONValue?) throws -> JSONValue {
        guard let want = JS.nonEmptyString(cnf?.asObject?["x5t#S256"]) else { throw fail("x5t_missing", "cnf has no 'x5t#S256' thumbprint") }
        let got = try mtlsThumbprint(cert)
        if !PCAEvents.timingSafeEqual(Array(got.utf8), Array(want.utf8)) {
            throw fail("x5t", "client certificate thumbprint does not match cnf x5t#S256")
        }
        return .object(["x5t#S256": .string(got)])
    }

    // ---- PCActn binding ----

    /// The leaf holder's Ed25519 public key as an OKP JWK.
    public static func leafHolderJwk(_ p: JSONValue?) throws -> JSONValue {
        try readable(p, "cap_chain")
        let chain = member(p, "cap_chain")
        try readable(chain, "length")
        var leaf: JSONValue? = nil
        switch chain! {
        case let .array(a): leaf = a.last
        case let .string(s): if let u = s.utf16.last { leaf = .string(String(decoding: [u], as: UTF16.self)) }
        case let .object(o):
            if let n = o["length"]?.safeInt, n >= 1 { leaf = o[JKey(String(n - 1))] }
        default: leaf = nil
        }
        guard let l = leaf else { throw fail("no_leaf", "PCActn capability chain is empty; no bound holder key") }
        try readable(l, "holder")
        var jwk: JObject = ["kty": .string("OKP"), "crv": .string("Ed25519")]
        if let h = member(l, "holder") { jwk["x"] = h }
        return .object(jwk)
    }

    public static func bindPcaToDpop(_ p: JSONValue?) throws -> JSONValue {
        .object(["jkt": .string(try jwkThumbprint(try leafHolderJwk(p)))])
    }

    /// verifyDpopProof with expectedJkt = the PCActn leaf holder's thumbprint (maxAgeSec default 300).
    public static func assertPcaDpop(_ p: JSONValue?, _ proof: JSONValue?, _ opts: VerifyOptions) throws -> JSONValue {
        let jkt = try bindPcaToDpop(p).get("jkt")!.asString!
        var o = opts
        o.expectedJkt = jkt
        return try verifyDpopProof(proof, o)
    }
}
