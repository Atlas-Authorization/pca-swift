import Foundation

/// Verifiable-credential bridges (mirrors `@atlasauth/pca-vc`): did:key (Ed25519) with base58btc, the agent-passport SD-JWT VC
/// (issue + verify, with selectively disclosed measurement digests) and RFC 9421 / Web Bot Auth HTTP message signatures.
public enum PCAVc {
    public static let VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
    public static let AGENT_PASSPORT_CONTEXT = "https://atlasauth.net/credentials/agent-passport/v1"
    public static let AGENT_PASSPORT_VC_TYPE = "AgentPassportCredential"
    static let VC_TYP = "vc+sd-jwt"
    static let SD_DIGEST_FIELDS = ["weights_digest", "system_prompt_digest", "tool_manifest_digest", "runtime_measurement"]
    static let MAX_BASE58_INPUT = 1024
    static let SIG_LABEL = "sig1"

    static func err(_ m: String) -> JSError { JSError("pca-vc: " + m) }

    // ---- base58btc / did:key ----

    static let B58 = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf16)

    public static func base58btcEncode(_ bytes: [UInt8]) -> String {
        let zeros = bytes.prefix { $0 == 0 }.count
        var digits: [Int] = []
        for b in bytes[zeros...] {
            var carry = Int(b)
            for j in 0..<digits.count {
                carry += digits[j] << 8
                digits[j] = carry % 58
                carry /= 58
            }
            while carry > 0 { digits.append(carry % 58); carry /= 58 }
        }
        return String(repeating: "1", count: zeros) + String(decoding: digits.reversed().map { B58[$0] }, as: UTF16.self)
    }

    public static func base58btcDecode(_ str: String) throws -> [UInt8] {
        let u = Array(str.utf16)
        if u.count > MAX_BASE58_INPUT { throw err("base58btc input too long") }
        let zeros = u.prefix { $0 == 0x31 }.count
        var bytes: [Int] = []
        for c in u[zeros...] {
            guard let start = B58.firstIndex(of: c) else { throw err("invalid base58btc character") }
            var carry = start
            for j in 0..<bytes.count {
                carry += bytes[j] * 58
                bytes[j] = carry & 0xff
                carry >>= 8
            }
            while carry > 0 { bytes.append(carry & 0xff); carry >>= 8 }
        }
        return [UInt8](repeating: 0, count: zeros) + bytes.reversed().map { UInt8($0) }
    }

    public static func didKeyFromEd25519(_ publicKey: [UInt8]) throws -> String {
        guard publicKey.count == 32 else { throw err("Ed25519 public key must be 32 bytes") }
        return "did:key:z" + base58btcEncode([0xed, 0x01] + publicKey)
    }

    public static func ed25519FromDidKey(_ did: String) throws -> [UInt8] {
        let prefix = "did:key:z"
        guard did.hasPrefix(prefix) else { throw err("not a did:key:z\u{2026} identifier") }
        let u = Array(did.utf16)
        if u.count > prefix.utf16.count + 64 { throw err("did:key is not an Ed25519 (0xed01) key") } // exactly 48 base58 chars
        let mc = try base58btcDecode(String(decoding: u[prefix.utf16.count...], as: UTF16.self))
        guard mc.count == 34, mc[0] == 0xed, mc[1] == 0x01 else { throw err("did:key is not an Ed25519 (0xed01) key") }
        return Array(mc[2...])
    }

    // ---- the bundled JSON-LD context ----

    public static let AGENT_PASSPORT_CONTEXT_DOC: JSONValue = {
        let v = "https://atlasauth.net/credentials/agent-passport/v1#", xsd = "http://www.w3.org/2001/XMLSchema#"
        func term(_ id: String, _ t: String) -> JSONValue { .object(["@id": .string(v + id), "@type": .string(xsd + t)]) }
        return .object(["@context": .object([
            "@protected": .bool(true),
            "AgentPassportCredential": .object([
                "@id": .string(v + "AgentPassportCredential"),
                "@context": .object([
                    "@protected": .bool(true), "id": .string("@id"), "type": .string("@type"),
                    "passport_id": term("passportId", "string"), "model_id": term("modelId", "string"), "operator": term("operator", "string"),
                    "hardware_rooted": term("hardwareRooted", "boolean"), "weights_measured": term("weightsMeasured", "boolean"),
                    "issued_at": term("issuedAt", "integer"), "weights_digest": term("weightsDigest", "string"),
                    "system_prompt_digest": term("systemPromptDigest", "string"), "tool_manifest_digest": term("toolManifestDigest", "string"),
                    "runtime_measurement": term("runtimeMeasurement", "string"),
                    "_sd": .object(["@id": .string(v + "selectiveDisclosureDigest"), "@container": .string("@set")]),
                ]),
            ]),
        ])])
    }()

    /// SHA-256 (hex) of the key-sorted JSON of the context document.
    public static let AGENT_PASSPORT_CONTEXT_DIGEST: String =
        AHash.sha256.digest(Array(JS.stringify(AGENT_PASSPORT_CONTEXT_DOC).utf8)).map { String(format: "%02x", $0) }.joined()

    /// The bundled document for its IRI, nil for anything else (never fetched).
    public static func resolveAgentPassportContext(_ iri: String?) -> JSONValue? { iri == AGENT_PASSPORT_CONTEXT ? AGENT_PASSPORT_CONTEXT_DOC : nil }

    // ---- the agent-passport SD-JWT VC ----

    /// `<issuer JWT>~<Disclosure>~…~`: the measurement digests are selectively disclosable. `nowSec` nil = the system clock.
    public static func passportToVC(_ passport: JSONValue?, issuerSeed: [UInt8], issuerDid: String?, subjectDid: String?,
                                    ttlSec: Double? = nil, nowSec: Double? = nil) throws -> String {
        guard let pv = passport, pv != .null else { throw JSError("Cannot read properties of null (reading 'weights_digest')") }
        guard issuerSeed.count == 32 else { throw err("Ed25519 private seed must be 32 bytes") }
        let p = pv.asObject ?? [:]
        var disclosures: [String] = [], sd: [JSONValue] = []
        for f in SD_DIGEST_FIELDS {
            guard let value = p[JKey(f)] else { continue }
            let salt = Base64URLStrict.encode((0..<16).map { _ in UInt8.random(in: 0...255) })
            let d = Base64URLStrict.encode(Array(JS.stringify(.array([.string(salt), .string(f), value])).utf8))
            disclosures.append(d)
            sd.append(.string(PCASdJwt.sha(d)))
        }
        var cs: JObject = [:]
        if let s = subjectDid { cs["id"] = .string(s) }
        for (k, src) in [("passport_id", "id"), ("model_id", "model_id"), ("operator", "operator"), ("hardware_rooted", "hardware_rooted"),
                         ("issued_at", "issued_at"), ("weights_measured", "weights_measured")] {
            if let v = p[JKey(src)] { cs[JKey(k)] = v }
        }
        if !sd.isEmpty { cs["_sd"] = .array(sd) }
        let vc: JSONValue = .object(["@context": .array([.string(VC_CONTEXT), .string(AGENT_PASSPORT_CONTEXT)]),
                                     "type": .array([.string("VerifiableCredential"), .string(AGENT_PASSPORT_VC_TYPE)]), "credentialSubject": .object(cs)])
        let now = nowSec ?? Date().timeIntervalSince1970.rounded(.down)
        var payload: JObject = ["vc": vc, "iat": PCASdJwt.jnum(now)]
        if !sd.isEmpty { payload["_sd_alg"] = .string("sha-256") }
        if let i = issuerDid { payload["iss"] = .string(i) }
        if let s = subjectDid { payload["sub"] = .string(s) }
        if let t = ttlSec {
            guard (now + t).isFinite else { throw JSError("Invalid exp input") }
            payload["exp"] = PCASdJwt.jnum(now + t)
        }
        let jwt = try Jose.sign(header: .object(["alg": .string("EdDSA"), "typ": .string(VC_TYP)]), headerOrder: ["alg", "typ"], payload: .object(payload),
                                payloadOrder: ["vc", "_sd_alg", "iss", "sub", "iat", "exp", "@context", "type", "credentialSubject", "id", "passport_id",
                                               "model_id", "operator", "hardware_rooted", "issued_at", "weights_measured", "_sd"]) {
            Ed25519Deterministic.sign(seed: issuerSeed, $0)
        }
        return ([jwt] + disclosures).map { $0 + "~" }.joined()
    }

    static func str(_ v: JSONValue?, _ label: String) throws -> JSONValue {
        guard let x = v, x.asString != nil else { throw err("expected string for \(label)") }
        return x
    }
    static func bool(_ v: JSONValue?, _ label: String) throws -> JSONValue {
        guard case .bool? = v else { throw err("expected boolean for \(label)") }
        return v!
    }

    /// Verify an agent-passport VC under the issuer's Ed25519 key: {passport, issuerDid, subjectDid}. Throws on any failure.
    public static func verifyPassportVC(_ vc: String, issuerPublicKey: [UInt8], expectedIssuerDid: String? = nil, nowSec: Double? = nil) throws -> JSONValue {
        let parts = vc.utf8.split(separator: UInt8(ascii: "~"), omittingEmptySubsequences: false).map { String(decoding: $0, as: UTF8.self) }
        guard let jwt = parts.first, !jwt.isEmpty else { throw err("empty SD-JWT") }
        let disclosures = parts.dropFirst().filter { !$0.isEmpty }
        _ = try Jose.assertCanonicalCompactJws(.string(jwt))
        let raw = try disclosures.map { try Jose.decodeCanonicalBase64url($0) }

        var jo = Jose.VerifyOptions()
        jo.algorithms = ["EdDSA"]
        jo.now = nowSec
        let (payload, header) = try Jose.jwtVerify(.string(jwt), key: .ed25519(issuerPublicKey), jo)
        if header["typ"] != .string(VC_TYP) { throw err("header typ must be 'vc+sd-jwt'") }
        guard let v = payload["vc"]?.asObject else { throw err("missing vc claim") }
        let ctx = v["@context"]?.asArray
        guard let c = ctx, c.first == .string(VC_CONTEXT) else { throw err("@context must begin with \(VC_CONTEXT)") }
        if c.count != 2 || c[1] != .string(AGENT_PASSPORT_CONTEXT) { throw err("@context must be exactly [\(VC_CONTEXT), \(AGENT_PASSPORT_CONTEXT)]") }
        guard let types = v["type"]?.asArray, types.contains(.string("VerifiableCredential")), types.contains(.string(AGENT_PASSPORT_VC_TYPE)) else {
            throw err("type must include VerifiableCredential and \(AGENT_PASSPORT_VC_TYPE)")
        }
        guard let cs = v["credentialSubject"]?.asObject else { throw err("missing credentialSubject") }
        if cs["_sd_alg"] != nil { throw err("_sd_alg must be a top-level claim") }
        if let a = payload["_sd_alg"], a != .string("sha-256") { throw err("unsupported _sd_alg (require sha-256)") }

        let sdList = Set((cs["_sd"]?.asArray ?? []).compactMap { $0.asString })
        var recovered: JObject = [:]
        var seen: Set<String> = []
        for (d, bytes) in zip(disclosures, raw) {
            let digest = PCASdJwt.sha(d)
            guard sdList.contains(digest) else { throw err("disclosure does not match any _sd digest") }
            guard seen.insert(digest).inserted else { throw err("duplicate disclosure") }
            guard let dec = try? StrictJSON.parseLenient(String(decoding: bytes, as: UTF8.self)), let a = dec.asArray, a.count == 3 else {
                throw err("malformed disclosure")
            }
            guard let name = a[1].asString else { throw err("expected string for disclosure name") }
            guard SD_DIGEST_FIELDS.contains(name) else { throw err("unexpected disclosure claim '\(name)'") }
            if recovered[JKey(name)] != nil { throw err("disclosure claim '\(name)' appears more than once") }
            recovered[JKey(name)] = try str(a[2], "disclosure value")
        }

        var passport: JObject = ["id": try str(cs["passport_id"], "passport_id"), "model_id": try str(cs["model_id"], "model_id"),
                                 "operator": try str(cs["operator"], "operator"), "hardware_rooted": try bool(cs["hardware_rooted"], "hardware_rooted")]
        guard let ia = cs["issued_at"], ia.isNumber else { throw err("expected number for issued_at") }
        passport["issued_at"] = ia
        if let w = cs["weights_measured"] { passport["weights_measured"] = try bool(w, "weights_measured") }
        for f in SD_DIGEST_FIELDS { if let r = recovered[JKey(f)] { passport[JKey(f)] = r } }

        let issuer = try str(payload["iss"], "iss")
        let subject = try str(cs["id"], "credentialSubject.id")
        if payload["sub"] != subject { throw err("sub does not match credentialSubject.id") }
        if let e = expectedIssuerDid, issuer != .string(e) { throw err("iss does not match expectedIssuerDid") }
        return .object(["passport": .object(passport), "issuerDid": issuer, "subjectDid": subject])
    }

    // ---- RFC 9421 / Web Bot Auth ----

    /// Lower-cased names; a later spelling of the same name wins (insertion order).
    static func normalize(_ headers: [(String, String)]) -> [String: String] {
        var out: [String: String] = [:]
        for (k, v) in headers { out[k.lowercased()] = v }
        return out
    }

    static func host(_ url: String) throws -> String {
        guard let u = WhatwgURL.parse(url) else { throw JSError("Invalid URL", code: "ERR_INVALID_URL") }
        return u.host
    }

    static func component(_ name: String, _ method: String, _ url: String, _ headers: [String: String]) throws -> String {
        switch name {
        case "@method": return method.uppercased()
        case "@target-uri": return url
        case "@authority": return try host(url)
        default:
            guard let v = headers[name] else { throw err("covered header '\(name)' absent from request") }
            return Attest.jsTrim(v)
        }
    }

    static func signatureBase(_ components: [String], _ params: String, _ method: String, _ url: String, _ headers: [String: String]) throws -> String {
        var lines = try components.map { "\"\($0)\": \(try component($0, method, url, headers))" }
        lines.append("\"@signature-params\": \(params)")
        return lines.joined(separator: "\n")
    }

    public struct SignRequest {
        public var method: String
        public var url: String
        /// In insertion order (a later spelling of the same lower-cased name wins).
        public var headers: [(String, String)]
        /// The signer's 32-byte Ed25519 seed.
        public var seed: [UInt8]
        public var keyid: String
        /// Unix seconds (nil = the system clock).
        public var created: Double? = nil
        public var signatureAgent: String? = nil
        public init(method: String, url: String, headers: [(String, String)], seed: [UInt8], keyid: String) {
            self.method = method; self.url = url; self.headers = headers; self.seed = seed; self.keyid = keyid
        }
    }

    /// {signatureInput, signature, signatureAgent?}: covers @method, @target-uri and every header (host added from the URL).
    public static func signRequestMessage(_ a: SignRequest) throws -> JSONValue {
        guard a.seed.count == 32 else { throw err("Ed25519 private seed must be 32 bytes") }
        let created = a.created ?? Date().timeIntervalSince1970.rounded(.down)
        var headers = normalize(a.headers)
        if headers["host"] == nil { headers["host"] = try host(a.url) }
        if let s = a.signatureAgent { headers["signature-agent"] = "\"\(s)\"" }
        let components = ["@method", "@target-uri"] + headers.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        var params = "(\(components.map { "\"\($0)\"" }.joined(separator: " ")));created=\(JS.toString(.double(created)));keyid=\"\(a.keyid)\";alg=\"ed25519\""
        if a.signatureAgent != nil { params += ";tag=\"web-bot-auth\"" }
        let base = try signatureBase(components, params, a.method, a.url, headers)
        let sig = Ed25519Deterministic.sign(seed: a.seed, Array(base.utf8))
        var out: JObject = ["signatureInput": .string("\(SIG_LABEL)=\(params)"), "signature": .string("\(SIG_LABEL)=:\(Data(sig).base64EncodedString()):")]
        if let s = a.signatureAgent { out["signatureAgent"] = .string("\"\(s)\"") }
        return .object(out)
    }

    public struct VerifyRequest {
        public var method: String
        public var url: String
        public var headers: [(String, String)]
        public var signatureInput: String
        public var signature: String
        /// The Signature-Agent value when it is covered but not among the headers.
        public var signatureAgent: String? = nil
        public var requiredComponents: [String] = []
        /// When set, `created` must be within this many seconds of now (and at most 5 s ahead).
        public var maxAgeSec: Double? = nil
        public var nowSec: Double? = nil
        public init(method: String, url: String, headers: [(String, String)], signatureInput: String, signature: String) {
            self.method = method; self.url = url; self.headers = headers; self.signatureInput = signatureInput; self.signature = signature
        }
    }

    static func isLineTerminator(_ u: Unicode.Scalar) -> Bool { u == "\n" || u == "\r" || u == "\u{2028}" || u == "\u{2029}" }

    static func parseComponents(_ v: String) throws -> [String] {
        guard v.hasPrefix("("), let close = v.firstIndex(of: ")") else { throw err("malformed @signature-params") }
        let inner = Attest.jsTrim(String(v[v.index(after: v.startIndex)..<close]))
        if inner.isEmpty { return [] }
        return try inner.unicodeScalars.split(whereSeparator: Attest.isJSSpace).map { tok in
            guard tok.count >= 2, tok.first == "\"", tok.last == "\"", !tok.contains(where: isLineTerminator) else {
                throw err("malformed component identifier")
            }
            return String(String.UnicodeScalarView(tok.dropFirst().dropLast()))
        }
    }

    /// The `;created=<digits>` value (the first occurrence followed by a digit), as Number() reads it.
    static func createdParam(_ v: String) -> Double? {
        var rest = Substring(v)
        while let r = rest.range(of: ";created=") {
            let digits = rest[r.upperBound...].prefix { $0.isASCII && $0.isNumber }
            if !digits.isEmpty { return Double(String(digits)) ?? .infinity }
            rest = rest[r.upperBound...]
        }
        return nil
    }

    /// Verify an RFC 9421 signature (Ed25519, raw 32-byte key). Never throws: any malformed input is false.
    public static func verifyRequestSignature(_ a: VerifyRequest, publicKey: [UInt8]) -> Bool {
        do {
            guard let eq = a.signatureInput.firstIndex(of: "=") else { return false }
            let params = String(a.signatureInput[a.signatureInput.index(after: eq)...])
            let components = try parseComponents(params)
            for need in a.requiredComponents where !components.contains(need) { return false }
            if let r = params.range(of: ";alg=\""), let q = params[r.upperBound...].firstIndex(of: "\""), params[r.upperBound..<q] != "ed25519" { return false }
            if let max = a.maxAgeSec {
                guard let c = createdParam(params) else { return false }
                let now = a.nowSec ?? Date().timeIntervalSince1970.rounded(.down)
                if !now.isFinite || !c.isFinite || !(now - c <= max) || !(c - now <= 5) { return false }
            }
            var headers = normalize(a.headers)
            if headers["host"] == nil { headers["host"] = try host(a.url) }
            if components.contains("signature-agent") && headers["signature-agent"] == nil {
                guard let s = a.signatureAgent else { return false }
                headers["signature-agent"] = s
            }
            let base = try signatureBase(components, params, a.method, a.url, headers)
            guard let se = a.signature.firstIndex(of: "=") else { return false }
            let wrapped = Attest.jsTrim(String(a.signature[a.signature.index(after: se)...]))
            let w = Array(wrapped.unicodeScalars)
            guard w.count >= 2, w.first == ":", w.last == ":", !w.contains(where: isLineTerminator) else { return false }
            let sig = Attest.nodeB64(String(String.UnicodeScalarView(w[1..<(w.count - 1)])))
            return publicKey.count == 32 && Jose.verifySignature(alg: "EdDSA", key: .ed25519(publicKey), input: Array(base.utf8), sig: sig)
        } catch {
            return false
        }
    }
}
