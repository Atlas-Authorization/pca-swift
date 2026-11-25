import Foundation

/// WebAuthn / FIDO2 assertion verification as the PCA step-up co-sign (the reference @atlasauth/pca-webauthn): a minimal COSE_Key
/// reader, the authenticatorData header, the step-up / approval challenges a passkey signs, Secure Payment Confirmation binding, and
/// verifyAssertion (fail closed: every failure is an {ok: false, reason} result, never a throw).
public enum PCAWebauthn {
    public static let MAX_AUTHENTICATOR_DATA_BYTES = 4096
    public static let MAX_CLIENT_DATA_BYTES = 8192
    public static let MAX_SIGNATURE_BYTES = 1024

    // ---- COSE_Key ----

    indirect enum Cbor {
        case int(Int64)
        case bytes([UInt8])
        case map([Int64: Cbor])
    }

    /// One CBOR item: unsigned / negative ints, byte strings and maps with integer keys (a repeated key: last wins), with 0..4-byte
    /// arguments. Anything else is an error.
    static func coseRead(_ b: [UInt8], _ off: Int) throws -> (Cbor, Int) {
        let short = JSError("cose: unexpected end of input")
        if off >= b.count { throw short }
        let major = b[off] >> 5, ai = b[off] & 0x1f
        var p = off + 1
        var arg: UInt64 = 0
        if ai < 24 {
            arg = UInt64(ai)
        } else if ai <= 26 {
            let n = 1 << Int(ai - 24)
            if p + n > b.count { throw short }
            for i in 0..<n { arg = arg << 8 | UInt64(b[p + i]) }
            p += n
        } else {
            throw JSError("cose: unsupported CBOR argument encoding (8-byte or indefinite length)")
        }
        switch major {
        case 0: return (.int(Int64(arg)), p)
        case 1: return (.int(-1 - Int64(arg)), p)
        case 2:
            if UInt64(p) + arg > UInt64(b.count) { throw JSError("cose: byte string length out of range") }
            return (.bytes(Array(b[p..<(p + Int(arg))])), p + Int(arg))
        case 5:
            var m: [Int64: Cbor] = [:]
            var i: UInt64 = 0
            while i < arg {
                let (k, q) = try coseRead(b, p)
                guard case let .int(ki) = k else { throw JSError("cose: non-integer map key") }
                let (v, q2) = try coseRead(b, q)
                m[ki] = v
                p = q2
                i += 1
            }
            return (.map(m), p)
        default:
            throw JSError("cose: unsupported CBOR major type \(major)")
        }
    }

    static func isInt(_ v: Cbor?, _ n: Int64) -> Bool { if case let .int(i)? = v { return i == n } else { return false } }
    static func bytesOf(_ v: Cbor?) -> [UInt8]? { if case let .bytes(b)? = v { return b } else { return nil } }

    /// A COSE_Key (EC2 P-256 or OKP Ed25519) as its public JWK.
    public static func coseKeyToJwk(_ cose: [UInt8]) throws -> JObject {
        guard case let .map(m) = try coseRead(cose, 0).0 else { throw JSError("coseKeyToJwk: COSE_Key is not a CBOR map") }
        if isInt(m[1], 2) {
            if !isInt(m[-1], 1) { throw JSError("coseKeyToJwk: EC2 key is not P-256 (crv != 1)") }
            guard let x = bytesOf(m[-2]), let y = bytesOf(m[-3]) else { throw JSError("coseKeyToJwk: EC2 key missing an x/y coordinate") }
            if x.count != 32 || y.count != 32 { throw JSError("coseKeyToJwk: EC2 coordinate is not 32 bytes") }
            return ["kty": .string("EC"), "crv": .string("P-256"), "x": .string(Base64URLStrict.encode(x)), "y": .string(Base64URLStrict.encode(y)), "alg": .string("ES256")]
        }
        if isInt(m[1], 1) {
            if !isInt(m[-1], 6) { throw JSError("coseKeyToJwk: OKP key is not Ed25519 (crv != 6)") }
            guard let x = bytesOf(m[-2]) else { throw JSError("coseKeyToJwk: OKP key missing its public key") }
            if x.count != 32 { throw JSError("coseKeyToJwk: Ed25519 public key is not 32 bytes") }
            return ["kty": .string("OKP"), "crv": .string("Ed25519"), "x": .string(Base64URLStrict.encode(x)), "alg": .string("EdDSA")]
        }
        throw JSError("coseKeyToJwk: unsupported COSE key type")
    }

    /// The credential public key: a COSE_Key, or a public JWK.
    public enum PublicKey {
        case cose([UInt8])
        case jwk(JSONValue)
    }

    /// A JWK coordinate: trailing "=" dropped, the standard alphabet mapped to base64url, then strict.
    static func jwkBytes(_ v: JSONValue?) -> [UInt8]? {
        guard var s = v?.asString else { return nil }
        while s.hasSuffix("=") { s.removeLast() }
        return Base64URLStrict.decode(s.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_"))
    }

    static func resolveKey(_ pub: PublicKey?) throws -> (alg: String, raw: [UInt8]) {
        let jwk: JObject
        switch pub {
        case let .cose(b)?: jwk = try coseKeyToJwk(b)
        case let .jwk(j)?:
            guard let o = j.asObject else { throw JSError("resolveKey: unsupported public key") }
            jwk = o
        case nil: throw JSError("resolveKey: unsupported public key")
        }
        switch jwk["kty"] {
        case .string("EC")?:
            if jwk["crv"] != .string("P-256") { throw JSError("resolveKey: EC JWK is not P-256") }
            guard let x = jwkBytes(jwk["x"]), let y = jwkBytes(jwk["y"]), x.count == 32, y.count == 32 else {
                throw JSError("resolveKey: invalid EC JWK coordinates")
            }
            return ("ES256", [4] + x + y)
        case .string("OKP")?:
            if jwk["crv"] != .string("Ed25519") { throw JSError("resolveKey: OKP JWK is not Ed25519") }
            guard let x = jwkBytes(jwk["x"]), x.count == 32 else { throw JSError("resolveKey: invalid OKP JWK public key") }
            return ("EdDSA", x)
        default:
            throw JSError("resolveKey: unsupported public key")
        }
    }

    // ---- authenticatorData ----

    public struct Flags: Equatable {
        public let up, uv, be, bs, at, ed: Bool
        public var json: JSONValue {
            .object(["up": .bool(up), "uv": .bool(uv), "be": .bool(be), "bs": .bool(bs), "at": .bool(at), "ed": .bool(ed)])
        }
    }

    public struct AuthenticatorData {
        public let rpIdHash: [UInt8]
        public let flags: Flags
        public let signCount: UInt32
    }

    /// The fixed 37-byte authenticatorData header; nil when shorter.
    public static func parseAuthenticatorData(_ ad: [UInt8]) -> AuthenticatorData? {
        if ad.count < 37 { return nil }
        let f = ad[32]
        let count = ad[33..<37].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return AuthenticatorData(rpIdHash: Array(ad[0..<32]),
                                 flags: Flags(up: f & 0x01 != 0, uv: f & 0x04 != 0, be: f & 0x08 != 0, bs: f & 0x10 != 0, at: f & 0x40 != 0, ed: f & 0x80 != 0),
                                 signCount: count)
    }

    // ---- challenges ----

    /// What a step-up challenge is built from: a PCActn, or a 32-byte action digest (raw, or canonical base64url).
    public enum StepUpInput {
        case actn(JObject)
        case digest([UInt8])
        case b64u(String)
    }

    /// The 32 bytes a passkey signs for a step-up: SHA-256 of the PCActn's threshold message, or the given action digest.
    public static func buildStepUpChallenge(_ x: StepUpInput) throws -> [UInt8] {
        switch x {
        case let .digest(b):
            if b.count != 32 { throw JSError("buildStepUpChallenge: digest bytes must be 32 bytes") }
            return b
        case let .b64u(s):
            guard let b = Base64URLStrict.decode(s, length: 32) else { throw JSError("buildStepUpChallenge: digest is not a canonical base64url 32-byte value") }
            return b
        case let .actn(p):
            return ACrypto.sha256(try PCA.thresholdMessage(p))
        }
    }

    /// The step-up challenge bound to the approval render the person saw.
    public static func buildApprovalChallenge(_ x: StepUpInput, _ renderDigest: String) throws -> [UInt8] {
        let d = try buildStepUpChallenge(x)
        guard let c = Approval.challenge(actionDigest: Base64URLStrict.encode(d), renderDigest: renderDigest), let b = Base64URLStrict.decode(c) else {
            throw JSError("approvalChallenge: both digests must be canonical 32-byte values")
        }
        return b
    }

    public static func approvalChallengeForActn(_ x: StepUpInput, _ renderDigest: String) throws -> String {
        Base64URLStrict.encode(try buildApprovalChallenge(x, renderDigest))
    }

    public static func stepUpChallengeB64u(_ x: StepUpInput) throws -> String { Base64URLStrict.encode(try buildStepUpChallenge(x)) }

    // ---- Secure Payment Confirmation ----

    /// The canonical payment the person approves. At least one of payeeName / payeeOrigin is required.
    public struct PaymentExpectation {
        public var topOrigin: String
        public var currency: String
        public var value: String
        public var payeeName: String? = nil
        public var payeeOrigin: String? = nil
        public init(topOrigin: String, currency: String, value: String) { self.topOrigin = topOrigin; self.currency = currency; self.value = value }
    }

    /// clientData.payment against the expectation; nil when it matches.
    public static func spcPaymentError(_ payment: JSONValue?, _ e: PaymentExpectation, _ rpId: String) -> String? {
        guard let p = payment?.asObject else { return "clientData.payment is missing" }
        if e.payeeName == nil && e.payeeOrigin == nil { return "the expectation names no payee (refused: a payment approval must bind the payee)" }
        if e.topOrigin.isEmpty { return "the expectation names no topOrigin (refused: a payment approval must bind the approval origin)" }
        if p["rpId"] != .string(rpId) { return "clientData.payment.rpId is not the verifier rpId" }
        if p["topOrigin"] != .string(e.topOrigin) { return "clientData.payment.topOrigin is not the verifier approval origin" }
        let total = p["total"]
        if total?.get("currency") != .string(e.currency) || total?.get("value") != .string(e.value) {
            return "clientData.payment.total does not equal the canonical render"
        }
        for (k, want) in [("payeeName", e.payeeName), ("payeeOrigin", e.payeeOrigin)] {
            if let w = want, p[JKey(k)] != .string(w) { return "clientData.payment.\(k) does not equal the canonical render" }
        }
        return nil
    }

    // ---- assertion ----

    /// A WebAuthn assertion plus the credential public key. A nil byte field is "not bytes".
    public struct Assertion {
        public var authenticatorData: [UInt8]?
        public var clientDataJSON: [UInt8]?
        public var signature: [UInt8]?
        public var publicKey: PublicKey?
        public init(authenticatorData: [UInt8]?, clientDataJSON: [UInt8]?, signature: [UInt8]?, publicKey: PublicKey?) {
            self.authenticatorData = authenticatorData; self.clientDataJSON = clientDataJSON; self.signature = signature; self.publicKey = publicKey
        }
    }

    public enum Challenge {
        case bytes([UInt8])
        case b64u(String)
    }

    public struct Expectations {
        /// nil = not decodable.
        public var expectedChallenge: Challenge?
        public var rpId: String
        /// The exact-match origin allowlist.
        public var origins: [String]
        public var requireUV = false
        public var requireLowS = false
        /// Required (0 for a credential never used).
        public var storedSignCount: Double?
        public var onSignCountRegression: ((_ stored: Double, _ reported: Double) -> Void)? = nil
        public var rejectCrossOrigin = true
        /// Switches to an SPC payment.get assertion.
        public var payment: PaymentExpectation? = nil
        public init(expectedChallenge: Challenge?, rpId: String, origins: [String], storedSignCount: Double?) {
            self.expectedChallenge = expectedChallenge; self.rpId = rpId; self.origins = origins; self.storedSignCount = storedSignCount
        }
    }

    public struct Result {
        public let ok: Bool
        public let alg: String
        public let signCount: UInt32
        public let flags: Flags?
        public let reason: String
        public var json: JSONValue {
            ok ? .object(["ok": .bool(true), "alg": .string(alg), "signCount": .int(Int64(signCount)), "flags": flags!.json])
               : .object(["ok": .bool(false), "reason": .string(reason)])
        }
    }

    static let P256_HALF_N: [UInt8] = [0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8]

    /// A strict DER ECDSA-Sig-Value as r || s (32 bytes each); nil when malformed or out of range.
    static func derToRaw(_ d: [UInt8]) -> [UInt8]? {
        guard ACrypto.derSigMinimal(d, maxInt: 33) else { return nil }
        var off = d[1] < 0x80 ? 2 : 3
        var out: [UInt8] = []
        for _ in 0..<2 {
            let len = Int(d[off + 1])
            let v = Array(d[(off + 2)..<(off + 2 + len)].drop { $0 == 0 })
            if v.count > 32 { return nil }
            out += [UInt8](repeating: 0, count: 32 - v.count) + v
            off += 2 + len
        }
        return out
    }

    static func es256(_ sig: [UInt8], _ signed: [UInt8], _ point: [UInt8], lowS: Bool) -> Bool {
        let raw: [UInt8]
        if sig.first == 0x30 && sig.count != 64 {
            guard let r = derToRaw(sig) else { return false }
            raw = r
        } else {
            guard sig.count == 64 else { return false }
            raw = sig
        }
        if lowS && P256_HALF_N.lexicographicallyPrecedes(raw[32...]) { return false } // s > n/2
        return ACrypto.ecVerify(curve: "P-256", point: point, hash: .sha256, message: signed, raw: raw)
    }

    /// Verifies a passkey assertion for a step-up: clientData type / challenge / origin / crossOrigin (and SPC payment), the
    /// rpIdHash, UP (and UV when required), the signature over authenticatorData || SHA-256(clientDataJSON) (ES256 low-S when
    /// required, strict RFC 8032 EdDSA), and that the signature counter increased.
    public static func verifyAssertion(_ a: Assertion, _ e: Expectations) -> Result {
        func fail(_ r: String) -> Result { Result(ok: false, alg: "", signCount: 0, flags: nil, reason: r) }
        guard let adBytes = a.authenticatorData else { return fail("authenticatorData is not bytes") }
        guard let cdBytes = a.clientDataJSON else { return fail("clientDataJSON is not bytes") }
        guard let sig = a.signature else { return fail("signature is not bytes") }
        if adBytes.count > MAX_AUTHENTICATOR_DATA_BYTES { return fail("authenticatorData is too large") }
        if cdBytes.count > MAX_CLIENT_DATA_BYTES { return fail("clientDataJSON is too large") }
        if sig.count > MAX_SIGNATURE_BYTES { return fail("signature is too large") }
        if e.rpId.isEmpty { return fail("rpId is required") }
        if e.origins.isEmpty { return fail("origins allowlist is empty") }
        guard let stored = e.storedSignCount else { return fail("storedSignCount is required (use 0 for a credential never used)") }
        guard var text = String(bytes: cdBytes, encoding: .utf8) else { return fail("clientDataJSON is not valid UTF-8") }
        if text.unicodeScalars.first == "\u{FEFF}" { text.unicodeScalars.removeFirst() } // the WHATWG decoder drops a BOM
        // a duplicate member is refused (the reference's JSON.parse keeps the last one): the signed client data must be unambiguous
        guard let parsed = try? StrictJSON.parseLenient(text) else { return fail("clientDataJSON is not valid JSON") }
        guard let client = parsed.asObject else { return fail("clientDataJSON is not a JSON object") }
        let wantType = e.payment != nil ? "payment.get" : "webauthn.get"
        if client["type"] != .string(wantType) { return fail("clientData.type is not \"\(wantType)\" (\(JS.toString(client["type"])))") }
        if let pay = e.payment, let pe = spcPaymentError(client["payment"], pay, e.rpId) { return fail(pe) }
        guard let cs = client["challenge"]?.asString, let got = Base64URLStrict.decode(cs) else {
            return fail("clientData.challenge is missing or not canonical base64url")
        }
        let want: [UInt8]?
        switch e.expectedChallenge {
        case let .bytes(b)?: want = b
        case let .b64u(s)?: want = Base64URLStrict.decode(s)
        case nil: want = nil
        }
        guard let w = want else { return fail("expectedChallenge is not decodable") }
        if !PCAEvents.timingSafeEqual(got, w) { return fail("clientData.challenge does not match the step-up challenge") }
        if e.rejectCrossOrigin, let co = client["crossOrigin"] {
            if co == .bool(true) { return fail("clientData.crossOrigin is true") }
            if co != .bool(false) { return fail("clientData.crossOrigin is not a boolean") }
        }
        guard let origin = client["origin"]?.asString else { return fail("clientData.origin is missing") }
        if !e.origins.contains(origin) { return fail("clientData.origin \"\(origin)\" is not in the allowlist") }
        guard let ad = parseAuthenticatorData(adBytes) else { return fail("authenticatorData is too short (< 37 bytes)") }
        if !PCAEvents.timingSafeEqual(ad.rpIdHash, ACrypto.sha256(Array(e.rpId.utf8))) { return fail("rpIdHash does not match sha256(rpId)") }
        if !ad.flags.up { return fail("User Present (UP) flag is not set") }
        if e.requireUV && !ad.flags.uv { return fail("User Verified (UV) flag is required but not set") }
        let signed = adBytes + ACrypto.sha256(cdBytes)
        let key: (alg: String, raw: [UInt8])
        do { key = try resolveKey(a.publicKey) } catch { return fail("public key could not be resolved: \((error as? JSError)?.message ?? "unknown")") }
        let valid = key.alg == "ES256" ? es256(sig, signed, key.raw, lowS: e.requireLowS) : Ed25519Strict.verify(publicKey: key.raw, message: signed, signature: sig)
        if !valid { return fail("assertion signature did not verify") }
        if stored != stored.rounded(.towardZero) || stored < 0 || stored.sign == .minus || stored > 0xffffffff { return fail("storedSignCount is not a uint32") }
        if (ad.signCount != 0 || stored != 0) && Double(ad.signCount) <= stored {
            e.onSignCountRegression?(stored, Double(ad.signCount))
            return fail("signCount did not increase (possible cloned authenticator)")
        }
        return Result(ok: true, alg: key.alg, signCount: ad.signCount, flags: ad.flags, reason: "")
    }
}
