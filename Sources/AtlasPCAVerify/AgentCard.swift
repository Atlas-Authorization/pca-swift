import Foundation
import CryptoKit

/// Signed A2A Agent Cards and NANDA-style AgentFacts attested by PCA (the reference's @atlasauth/pca-agentcard): the RFC 8785
/// canonical bytes a card signature covers, the A2A 1.0 `AgentCard` shape check, detached-payload JWS signing / verification
/// (EdDSA signs; the unencoded `b64:false` profile and the A2A 1.0 `typ:"JOSE"` profile), AgentFacts attestations with validity
/// windows, the well-known hosting handlers and the registry entry.
///
/// Values are `JSONValue`s with the reference's JS semantics (a missing member is `undefined`, a JSON null is null). A parsed object
/// has no insertion order, so the places where the reference's output depends on it (the served JSON body, the claim-name lists)
/// take an optional `order` hint, as `JS.stringify(order:)` does.
/// shortcut: signing supports EdDSA (Ed25519) and ES256 / ES384 / ES512, plus Ed448 and RS* / PS* once AtlasPCAOpenSSL registers a signer (refused otherwise), and a
/// verification key of an unsupported kind never verifies; date strings must be ISO 8601 with an offset or date-only (else invalid).
public enum PCAAgentCard {
    public static let DEFAULT_ALG = "EdDSA"
    public static let AGENT_FACTS_CONTEXT = ["https://www.w3.org/ns/did/v1", "https://nanda.ai/agentfacts/v1"]
    public static let PCA_ATTESTOR_ID = "did:atlas:pca-attestor"
    public static let WELL_KNOWN_AGENT_CARD_PATH = "/.well-known/agent-card.json"
    public static let WELL_KNOWN_AGENT_FACTS_PATH = "/.well-known/agent-facts.json"

    /// The members this package writes, in the order it writes them (the default `order` hint of the hosting handlers).
    public static let MEMBER_ORDER = ["name", "description", "url", "version", "skills", "pcaPassport", "pcaProof", "signatures",
                                      "@context", "id", "type", "selfAsserted", "attestations", "uri", "verificationEndpoint", "proofRef", "aud",
                                      "protected", "issuer", "subject", "attests", "validFrom", "validUntil", "signature"]

    static func err(_ m: String) -> JSError { JSError(m) }
    static func key(_ s: String) -> JKey { JKey(s) }

    // MARK: - RFC 8785 JCS

    static let MAX_DEPTH = 64

    /// An Ed25519 signer over (seed, message). The default is the platform key (CryptoKit hedges its nonce on Apple platforms; swift-crypto
    /// on Linux is deterministic); a caller that needs RFC 8032 deterministic bytes supplies its own.
    public typealias EdSign = (_ seed: [UInt8], _ message: [UInt8]) throws -> [UInt8]

    static func jcs(_ v: JSONValue?, _ depth: Int) throws -> String {
        guard let v = v else { throw err("jcs: unsupported type undefined") }
        switch v {
        case .null: return "null"
        case let .bool(b): return b ? "true" : "false"
        case let .int(i): return String(i)
        case let .double(d):
            if !d.isFinite { throw err("jcs: non-finite number") }
            return JS.number(d)
        case let .string(s):
            if Canonical.hasLoneSurrogate(s) { throw err("jcs: lone surrogate in string") }
            return Canonical.canonicalize(v)
        case let .array(a):
            if depth > MAX_DEPTH { throw err("jcs: nesting too deep") }
            return "[" + (try a.map { try jcs($0, depth + 1) }).joined(separator: ",") + "]"
        case let .object(o):
            if depth > MAX_DEPTH { throw err("jcs: nesting too deep") }
            var parts: [String] = []
            for k in o.keys.sorted(by: { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }) {
                if Canonical.hasLoneSurrogate(k.s) { throw err("jcs: lone surrogate in key") }
                parts.append(Canonical.canonicalize(.string(k.s)) + ":" + (try jcs(o[k], depth + 1)))
            }
            return "{" + parts.joined(separator: ",") + "}"
        }
    }

    /// RFC 8785 canonical UTF-8 bytes of a JSON value; throws for a value with no JSON form.
    public static func jcsBytes(_ v: JSONValue?) throws -> [UInt8] { Array(try jcs(v, 1).utf8) }

    // MARK: - A2A 1.0 AgentCard shape

    /// The problems of an object against the A2A 1.0 `AgentCard` message (empty = valid), each with a JSON path.
    public static func validateAgentCard1(_ card: JSONValue?) -> [String] {
        var p: [String] = []
        guard let c = card?.asObject else { return ["$: the agent card must be an object"] }
        func reqStr(_ o: JObject, _ k: String, _ at: String) {
            if let s = o[key(k)]?.asString, !s.isEmpty { return }
            p.append("\(at).\(k): required non-empty string")
        }
        func optStr(_ o: JObject, _ k: String, _ at: String) {
            if let v = o[key(k)], v.asString == nil { p.append("\(at).\(k): must be a string") }
        }
        func optBool(_ o: JObject, _ k: String, _ at: String) {
            if let v = o[key(k)] { if case .bool = v { return }; p.append("\(at).\(k): must be a boolean") }
        }
        func strArray(_ v: JSONValue?, _ at: String, _ nonEmpty: Bool) {
            guard let a = v?.asArray, a.allSatisfy({ $0.asString != nil }) else { p.append("\(at): must be an array of strings"); return }
            if nonEmpty && a.isEmpty { p.append("\(at): must not be empty") }
        }
        func objArray(_ o: JObject, _ k: String, _ at: String, _ required: Bool, _ nonEmpty: Bool, _ each: (JObject, String) -> Void) {
            guard let v = o[key(k)] else {
                if required { p.append("\(at).\(k): required array") }
                return
            }
            guard let a = v.asArray else { p.append("\(at).\(k): must be an array"); return }
            if nonEmpty && a.isEmpty { p.append("\(at).\(k): must not be empty") }
            for (i, e) in a.enumerated() {
                if let eo = e.asObject { each(eo, "\(at).\(k)[\(i)]") } else { p.append("\(at).\(k)[\(i)]: must be an object") }
            }
        }

        reqStr(c, "name", "$")
        reqStr(c, "description", "$")
        reqStr(c, "version", "$")
        optStr(c, "documentationUrl", "$")
        optStr(c, "iconUrl", "$")
        objArray(c, "supportedInterfaces", "$", true, true) { e, at in
            reqStr(e, "url", at)
            reqStr(e, "protocolBinding", at)
            reqStr(e, "protocolVersion", at)
            optStr(e, "tenant", at)
        }
        if let prov = c["provider"] {
            if let po = prov.asObject {
                reqStr(po, "url", "$.provider")
                reqStr(po, "organization", "$.provider")
            } else { p.append("$.provider: must be an object") }
        }
        if let caps = c["capabilities"]?.asObject {
            optBool(caps, "streaming", "$.capabilities")
            optBool(caps, "pushNotifications", "$.capabilities")
            optBool(caps, "extendedAgentCard", "$.capabilities")
            objArray(caps, "extensions", "$.capabilities", false, false) { e, at in
                optStr(e, "uri", at)
                optStr(e, "description", at)
                optBool(e, "required", at)
                if let pr = e["params"], pr.asObject == nil { p.append("\(at).params: must be an object") }
            }
        } else { p.append("$.capabilities: required object") }
        if let s = c["securitySchemes"], s.asObject == nil { p.append("$.securitySchemes: must be an object") }
        if let s = c["securityRequirements"], s.asArray == nil { p.append("$.securityRequirements: must be an array") }
        if let m = c["defaultInputModes"] { strArray(m, "$.defaultInputModes", true) } else { p.append("$.defaultInputModes: required array of strings") }
        if let m = c["defaultOutputModes"] { strArray(m, "$.defaultOutputModes", true) } else { p.append("$.defaultOutputModes: required array of strings") }
        objArray(c, "skills", "$", true, false) { e, at in
            reqStr(e, "id", at)
            reqStr(e, "name", at)
            reqStr(e, "description", at)
            if let t = e["tags"] { strArray(t, "\(at).tags", false) } else { p.append("\(at).tags: required array of strings") }
            for k in ["examples", "inputModes", "outputModes"] { if let v = e[key(k)] { strArray(v, "\(at).\(k)", false) } }
            if let s = e["securityRequirements"], s.asArray == nil { p.append("\(at).securityRequirements: must be an array") }
        }
        objArray(c, "signatures", "$", false, false) { e, at in
            reqStr(e, "protected", at)
            reqStr(e, "signature", at)
            if let h = e["header"], h.asObject == nil { p.append("\(at).header: must be an object") }
        }
        return p
    }

    // MARK: - detached JWS core

    static let PCA_PASSPORT_HEADER = "pca_passport"
    /// The algorithms the reference's JOSE library knows (anything else is refused).
    static let JOSE_ALGS: Set<String> = ["EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512"]

    /// A detached-payload JWS `{protected, signature}` over `payload`. Header members are written alg, typ | b64 + crit, kid, extras.
    public static func signDetached(_ payload: [UInt8], key signingKey: JSONValue?, alg algIn: JSONValue?, kid: JSONValue?, extra: [(String, JSONValue)], standard: Bool, edSign: EdSign?) throws -> JObject {
        guard let alg = (JS.present(algIn) ?? .string(DEFAULT_ALG)).asString, !alg.isEmpty else { throw err("\"alg\" must be a non-empty string") }
        guard let jwk = signingKey?.asObject, jwk["kty"] != nil else { throw err("signDetached: the signing key must be a JWK") }
        var h: JObject = ["alg": .string(alg)]
        if standard { h["typ"] = .string("JOSE") } else { h["b64"] = .bool(false); h["crit"] = .array([.string("b64")]) }
        if let k = kid { h["kid"] = k }
        for (k, v) in extra { h[JKey(k)] = v }
        let order = ["alg", "typ", "b64", "crit", "kid"] + extra.map { $0.0 }
        let prot = Base64URLStrict.encode(Array(JS.stringify(.object(h), order: order).utf8))
        let input = Array(prot.utf8) + [0x2e] + (standard ? Array(Base64URLStrict.encode(payload).utf8) : payload)
        let sig: [UInt8]
        if alg == "EdDSA" {
            guard jwk["kty"] == .string("OKP"), jwk["crv"] == .string("Ed25519") || jwk["crv"] == .string("Ed448") else { throw err("Invalid key for this operation, its asymmetricKeyType must be ed25519 or ed448") }
            if jwk["crv"] == .string("Ed448") {
                guard let sign = PCAExtraCrypto.ed448Sign else { throw err("Ed448 signing is not supported") }
                guard jwk["x"]?.asString != nil, let seed = jwk["d"]?.asString.flatMap({ Base64URLStrict.decode($0) }), seed.count == 57 else { throw err("a private Ed448 JWK is required to sign") }
                sig = try sign(seed, input)
            } else {
                guard jwk["x"]?.asString != nil, let seed = jwk["d"]?.asString.flatMap({ Base64URLStrict.decode($0) }), seed.count == 32 else { throw err("a private Ed25519 JWK is required to sign") }
                sig = try edSign.map { try $0(seed, input) } ?? PCAEdKey(seed: seed).sign(input)
            }
        } else if ["ES256", "ES384", "ES512"].contains(alg) {
            sig = try PCADpop.ecSign(alg, jwk, input)
        } else if ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"].contains(alg), let rsaSign = PCAExtraCrypto.rsaSign {
            guard jwk["kty"] == .string("RSA") else { throw err("Invalid key for this operation, its asymmetricKeyType must be rsa") }
            sig = try rsaSign(alg, try PCAExtraCrypto.rsaPrivateParts(jwk), input)
        } else {
            throw err("signing with \(alg) is not supported")
        }
        return ["protected": .string(prot), "signature": .string(Base64URLStrict.encode(sig))]
    }

    enum Resolver { case key(Jose.Key), set(OidcLocalJwks) }

    /// jose's importJWK for a verification key: what it refuses to import is a resolve failure; anything else is a key that may
    /// simply never verify. A value that is not a JWK is passed through by the reference and fails at verification (never verifies).
    static func importVerifyKey(_ k: JSONValue) throws -> Jose.Key {
        guard let j = k.asObject, j["kty"] != nil else { return .hmac([]) }
        func b64(_ n: String) -> [UInt8]? { j[key(n)]?.asString.flatMap { Base64URLStrict.decode($0) } }
        switch j["kty"]?.asString {
        case "OKP"?:
            let crv = j["crv"]?.asString
            let want: Int
            switch crv { case "Ed25519"?, "X25519"?: want = 32; case "Ed448"?, "X448"?: want = 57; default: throw err("Invalid or unsupported JWK \"crv\"") }
            guard let x = b64("x"), x.count == want else { throw err("Invalid JWK OKP key") }
            var pk = x
            if j["d"] != nil {
                guard let d = b64("d"), d.count == want else { throw err("Invalid JWK OKP key") }
                if crv == "Ed25519" { pk = Ed25519Deterministic.publicKey(seed: d) }
                if crv == "Ed448" { guard let derived = PCAExtraCrypto.ed448PublicKey?(d) else { return .hmac([]) }; pk = derived }
            }
            if crv == "Ed448", PCAExtraCrypto.ed448Verify != nil { return .ed448(pk) }
            return crv == "Ed25519" ? .ed25519(pk) : .hmac([]) // other curves never verify here (Ed448 only with AtlasPCAOpenSSL)
        case "EC"?:
            guard let crv = j["crv"]?.asString, let x = b64("x"), let y = b64("y") else { throw err("Invalid JWK EC key") }
            let pt = [UInt8(4)] + x + y
            do {
                switch crv {
                case "P-256": _ = try P256.Signing.PublicKey(x963Representation: Data(pt))
                case "P-384": _ = try P384.Signing.PublicKey(x963Representation: Data(pt))
                case "P-521": _ = try P521.Signing.PublicKey(x963Representation: Data(pt))
                default: throw err("Unsupported key curve")
                }
            } catch { throw err("Invalid JWK EC key") }
            return .ec(curve: crv, point: pt)
        case "RSA"?:
            if j["oth"] != nil { throw err("RSA JWK \"oth\" (Other Primes Info) Parameter value is not supported") }
            guard let n = b64("n"), let e = b64("e") else { throw err("Invalid JWK RSA key") }
            return .rsa(n: n, e: e)
        case "oct"?:
            guard let kk = b64("k") else { throw err("Invalid JWK oct key") }
            return .hmac(kk)
        default:
            throw err("Invalid or unsupported JWK \"kty\" (Key Type) Parameter value")
        }
    }

    static func resolveVerifyKey(_ o: JObject) -> (resolver: Resolver?, error: String?) {
        do {
            if JS.truthy(o["jwks"]) { return (.set(try OidcLocalJwks(o["jwks"])), nil) }
            if let k = o["key"] { return (.key(try importVerifyKey(k)), nil) }
            return (nil, "no verification key or JWKS supplied")
        } catch {
            return (nil, "could not resolve verification key: \((error as? JSError)?.message ?? "\(error)")")
        }
    }

    /// assertCanonicalJwsSegments: the canonical-spelling gate on a detached JWS's two segments; returns the protected header.
    static func gateSegments(_ p: String, _ s: String) throws -> JObject {
        if JS.length(p) + JS.length(s) > Jose.DEFAULT_MAX_JWS_BYTES { throw err("non-canonical JWS: too-long") }
        if p.isEmpty || s.isEmpty { throw err("non-canonical JWS: empty-segment") }
        guard let h = try Jose.parseJSONBytes(try Jose.decodeCanonicalBase64url(p)).asObject else { throw err("non-canonical JWS: not-an-object") }
        _ = try Jose.decodeCanonicalBase64url(s)
        return h
    }

    /// Verifies a detached JWS over `payload`; never throws for a bad signature (a null / undefined `sig` is the reference's TypeError).
    static func verifyDetached(_ payload: [UInt8], _ sig: JSONValue?, _ resolver: Resolver) throws -> (ok: Bool, header: JObject, reason: String) {
        guard let sv = sig, sv != .null else { throw err("Cannot read properties of \(sig == nil ? "undefined" : "null") (reading 'protected')") }
        func bad(_ r: String) -> (ok: Bool, header: JObject, reason: String) { (false, [:], r) }
        guard let so = sv.asObject, let prot = so["protected"]?.asString, let sg = so["signature"]?.asString else { return bad("signature is malformed") }
        let h: JObject
        do { h = try gateSegments(prot, sg) } catch { return bad((error as? JSError)?.message ?? "non-canonical JWS") }
        let rawPayload = h["b64"] == .bool(false)
        var b64 = true
        if let crit = h["crit"] {
            guard let list = crit.asArray, !list.isEmpty, list.allSatisfy({ ($0.asString ?? "").isEmpty == false }) else { return bad("\"crit\" must be an array of non-empty strings") }
            for c in list.compactMap({ $0.asString }) {
                if c != "b64" { return bad("Extension Header Parameter \"\(c)\" is not recognized") }
                if h["b64"] == nil { return bad("Extension Header Parameter \"b64\" is missing") }
            }
            guard case let .bool(b)? = h["b64"] else { return bad("The \"b64\" Header Parameter must be a boolean") }
            b64 = b
        }
        guard let alg = JS.nonEmptyString(h["alg"]) else { return bad("JWS \"alg\" (Algorithm) Header Parameter missing or invalid") }
        if b64 && rawPayload { return bad("JWS Payload must be a string") }
        guard JOSE_ALGS.contains(alg) else { return bad("unsupported alg") }
        let key: Jose.Key
        switch resolver {
        case let .key(k): key = k
        case let .set(s):
            do { key = try s.select(h).key } catch { return bad((error as? JSError)?.message ?? "no applicable key") }
        }
        guard let sigBytes = Base64URLStrict.decode(sg) else { return bad("Failed to base64url decode the signature") }
        let input = Array(prot.utf8) + [0x2e] + (rawPayload ? payload : Array(Base64URLStrict.encode(payload).utf8))
        guard Jose.verifySignature(alg: alg, key: key, input: input, sig: sigBytes) else { return bad("signature verification failed") }
        return (true, h, "")
    }

    // MARK: - passport reference + card build

    /// passportRefFrom: a full passport (it has `model_id`) takes only the `uri` argument; a bare reference keeps its own `uri` first.
    static func passportRefFrom(_ p: JSONValue?, _ uri: JSONValue?) throws -> JSONValue {
        guard let po = p?.asObject else { throw err("Cannot use 'in' operator on a non-object") }
        var r: JObject = [:]
        if let id = po["id"] { r["id"] = id }
        if po["model_id"] != nil { if let u = uri { r["uri"] = u } }
        else if let u = po["uri"] ?? uri { r["uri"] = u }
        return .object(r)
    }

    /// Builds an (unsigned) A2A Agent Card from a passport (or a bare `{id, uri?}` reference). `opts`: name, skills?, url?,
    /// description?, version?, passportUri?, pcaProofRef?.
    public static func buildAgentCard(_ passport: JSONValue?, _ opts: JObject) throws -> JSONValue {
        var card: JObject = [:]
        if let n = opts["name"] { card["name"] = n }
        for k in ["description", "url", "version", "skills"] { if let v = opts[key(k)] { card[JKey(k)] = v } }
        card["pcaPassport"] = try passportRefFrom(passport, opts["passportUri"])
        if let p = opts["pcaProofRef"] { card["pcaProof"] = p }
        return .object(card)
    }

    static func cardSigningBytes(_ card: JObject) throws -> [UInt8] {
        var rest = card
        rest["signatures"] = nil
        return try jcsBytes(.object(rest))
    }

    /// Signs an A2A Agent Card with a private JWK. `opts`: alg?, passport?, kid?, profile? ('pca-detached' | 'a2a-1.0'), schema? ('a2a-1.0').
    public static func issueSignedAgentCard(_ card: JSONValue?, _ signingKey: JSONValue?, _ opts: JObject = [:], edSign: EdSign? = nil) throws -> JSONValue {
        guard let co = card?.asObject else { throw err("issueSignedAgentCard: the card must be an object") }
        var passport: JSONValue? = nil
        var fromOpts = false
        if JS.truthy(opts["passport"]) {
            fromOpts = true
            guard let po = opts["passport"]?.asObject else { throw err("Cannot use 'in' operator on a non-object") }
            var r: JObject = [:]
            if let id = po["id"] { r["id"] = id }
            if let u = po["uri"] { r["uri"] = u }
            passport = .object(r)
        } else { passport = co["pcaPassport"] }
        // a passport option with no id has an undefined member in the reference, which has no canonical form
        if fromOpts && passport?.get("id") == nil { throw err("jcs: unsupported type undefined") }
        var toSign = co
        if JS.truthy(passport) { toSign["pcaPassport"] = passport }
        if opts["schema"] == .string("a2a-1.0") {
            let problems = validateAgentCard1(.object(toSign))
            if !problems.isEmpty { throw err("issueSignedAgentCard: the card does not match the A2A 1.0 schema: \(problems.joined(separator: "; "))") }
        }
        let payload = try cardSigningBytes(toSign)
        let spec = opts["profile"] == .string("a2a-1.0")
        if spec && JS.nonEmptyString(opts["kid"]) == nil { throw err("issueSignedAgentCard: the 'a2a-1.0' profile requires a kid") }
        var extra: [(String, JSONValue)] = []
        if JS.truthy(passport), let id = passport?.get("id") { extra.append((PCA_PASSPORT_HEADER, id)) }
        let sig = try signDetached(payload, key: signingKey, alg: opts["alg"], kid: opts["kid"], extra: extra, standard: spec, edSign: edSign)
        var existing: [JSONValue] = []
        if let s = JS.present(toSign["signatures"]) {
            // `[...toSign.signatures, sig]`: an array spreads its elements and a string its code points; anything else is not iterable
            if let a = s.asArray { existing = a }
            else if let t = s.asString { existing = t.unicodeScalars.map { .string(String($0)) } }
            else { throw err("signatures is not iterable") }
        }
        toSign["signatures"] = .array(existing + [.object(sig)])
        return .object(toSign)
    }

    /// Validates the card's signatures. Fail-closed; the result is {ok, reason?, passportRef?, passport?, pcaProof?}.
    /// `opts`: jwks? | key?, alg?, schema? ('a2a-1.0').
    public static func verifyAgentCard(_ card: JSONValue?, _ opts: JObject) throws -> JSONValue { try verifyCard(card, opts, agentCardPkg: true) }

    /// Shared by the agent-card and the A2A verifiers: `agentCardPkg` adds the live proof pointer and the agent-card wording of a missing signature;
    /// the A2A one refuses an entry that is not `{protected: string, signature: string}` as malformed.
    static func verifyCard(_ card: JSONValue?, _ opts: JObject, agentCardPkg: Bool) throws -> JSONValue {
        func no(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        let c: JObject
        switch card {
        case let .object(o)?: c = o
        case .array?: c = [:] // typeof [] is 'object': it has no signatures
        default: return no("agent card is not an object")
        }
        guard let sigs = c["signatures"]?.asArray, !sigs.isEmpty else { return no("agent card carries no signatures") }
        if opts["schema"] == .string("a2a-1.0") {
            let problems = validateAgentCard1(card)
            if !problems.isEmpty { return no("agent card does not match the A2A 1.0 schema: \(problems.joined(separator: "; "))") }
        }
        let res = resolveVerifyKey(opts)
        guard let resolver = res.resolver else { return no(res.error ?? "no verification key or JWKS supplied") }
        let payload: [UInt8]
        do { payload = try cardSigningBytes(c) } catch { return no("agent card has no canonical form: \((error as? JSError)?.message ?? "")") }
        var passportRef: String? = nil
        for (i, sig) in sigs.enumerated() {
            if agentCardPkg {
                if !JS.truthy(sig) { return no("signature \(i) is missing") }
            } else if sig.get("protected")?.asString == nil || sig.get("signature")?.asString == nil {
                return no("signature \(i) is malformed")
            }
            let r = try verifyDetached(payload, sig, resolver)
            if !r.ok { return no("signature \(i) did not verify: \(r.reason)") }
            if let ref = r.header[key(PCA_PASSPORT_HEADER)]?.asString, passportRef == nil { passportRef = ref }
        }
        var out: JObject = ["ok": .bool(true)]
        if let p = passportRef { out["passportRef"] = .string(p) }
        if JS.truthy(c["pcaPassport"]) { out["passport"] = c["pcaPassport"] }
        if agentCardPkg, JS.truthy(c["pcaProof"]) { out["pcaProof"] = c["pcaProof"] }
        return .object(out)
    }

    // MARK: - AgentFacts

    static func attestationStatementBytes(issuer: JSONValue?, subject: JSONValue?, attests: JSONValue?, validFrom: JSONValue?, validUntil: JSONValue?) throws -> [UInt8] {
        func need(_ v: JSONValue?) throws -> JSONValue { guard let v = v else { throw err("canonicalize: unsupported type undefined") }; return v }
        let o: JObject = ["d": .string("atlas-pca/agentfacts/attestation/v1"), "issuer": try need(issuer), "subject": try need(subject),
                          "attests": try need(attests), "validFrom": try need(validFrom), "validUntil": JS.present(validUntil) ?? .null]
        return try Canonical.canonicalBytes(.object(o))
    }

    static func nowMs(_ v: JSONValue?) throws -> Double {
        guard let p = JS.present(v) else { return Date().timeIntervalSince1970.rounded(.down) * 1000 }
        guard let n = IV.num(p) else { throw err("now must be a number") }
        return n
    }

    static func signAttestation(_ statement: JObject, key: JSONValue?, opts: JObject, edSign: EdSign?) throws -> JObject {
        let issuer = statement["issuer"]
        let payload = try attestationStatementBytes(issuer: issuer, subject: statement["subject"], attests: statement["attests"], validFrom: statement["validFrom"], validUntil: statement["validUntil"])
        let sig = try signDetached(payload, key: key, alg: opts["alg"], kid: opts["kid"], extra: [("attestor", issuer ?? .null)], standard: false, edSign: edSign)
        var out = statement
        out["signature"] = .object(sig)
        return out
    }

    static func statement(issuer: JSONValue?, subject: JSONValue?, opts: JObject) throws -> JObject {
        let validFrom: JSONValue = try JS.present(opts["validFrom"]) ?? .string(PCAScim.isoString(nowMs(opts["now"])))
        var s: JObject = ["issuer": JS.present(issuer) ?? .string(PCA_ATTESTOR_ID), "validFrom": validFrom]
        if let sub = subject { s["subject"] = sub }
        if let a = opts["attests"] { s["attests"] = a }
        if let u = opts["validUntil"] { s["validUntil"] = u }
        return s
    }

    /// Issues an AgentFacts document with PCA as the third-party attestor. `passport` is `{id}`; `opts`: attestorKey, attests,
    /// selfAsserted?, attestorId?, agentId?, alg?, kid?, validFrom?, validUntil?, now?, context?.
    public static func issueAgentFacts(_ passport: JSONValue?, _ opts: JObject, edSign: EdSign? = nil) throws -> JSONValue {
        guard let po = passport?.asObject else { throw err("Cannot read properties of \(passport == nil ? "undefined" : "null") (reading 'id')") }
        let agentId = JS.present(opts["agentId"]) ?? po["id"]
        let st = try statement(issuer: opts["attestorId"], subject: agentId, opts: opts)
        let att = try signAttestation(st, key: opts["attestorKey"], opts: opts, edSign: edSign)
        var out: JObject = ["@context": JS.present(opts["context"]) ?? .array(AGENT_FACTS_CONTEXT.map { .string($0) }), "type": .string("AgentFacts"),
                            "selfAsserted": JS.present(opts["selfAsserted"]) ?? .object([:]), "attestations": .array([.object(att)])]
        if let id = agentId { out["id"] = id }
        return .object(out)
    }

    /// Appends another attestation (a copy). `opts`: attestorKey, attests, attestorId?, alg?, kid?, validFrom?, validUntil?, now?.
    public static func addAttestation(_ facts: JSONValue?, _ opts: JObject, edSign: EdSign? = nil) throws -> JSONValue {
        guard var fo = facts?.asObject else { throw err("addAttestation: facts must be an object") }
        let st = try statement(issuer: opts["attestorId"], subject: fo["id"], opts: opts)
        let att = try signAttestation(st, key: opts["attestorKey"], opts: opts, edSign: edSign)
        guard let list = fo["attestations"]?.asArray else { throw err("facts.attestations is not iterable") }
        fo["attestations"] = .array(list + [.object(att)])
        return .object(fo)
    }

    /// Date.parse for the ISO 8601 forms (date-only = UTC; a date-time needs Z or an offset; anything else is NaN).
    static func dateParse(_ s: String) -> Double {
        let u = Array(s.unicodeScalars)
        var i = 0
        func digits(_ n: Int) -> Int? {
            guard i + n <= u.count else { return nil }
            var v = 0
            for k in 0..<n { let c = u[i + k].value; guard c >= 48 && c <= 57 else { return nil }; v = v * 10 + Int(c - 48) }
            i += n
            return v
        }
        func eat(_ c: Unicode.Scalar) -> Bool { if i < u.count && u[i] == c { i += 1; return true }; return false }
        var year: Int
        if i < u.count, u[i] == "+" || u[i] == "-" {
            let neg = u[i] == "-"; i += 1
            guard let y = digits(6) else { return .nan }
            if neg && y == 0 { return .nan }
            year = neg ? -y : y
        } else { guard let y = digits(4) else { return .nan }; year = y }
        var month = 1, day = 1
        if eat("-") {
            guard let m = digits(2) else { return .nan }
            month = m
            if eat("-") { guard let d = digits(2) else { return .nan }; day = d }
        }
        var h = 0, mi = 0, sec = 0, ms = 0, off = 0
        if i < u.count {
            guard eat("T"), let hh = digits(2), eat(":"), let mm = digits(2) else { return .nan }
            h = hh; mi = mm
            if eat(":") {
                guard let ss = digits(2) else { return .nan }
                sec = ss
                if eat(".") {
                    var frac = 0, n = 0
                    while i < u.count, u[i].value >= 48 && u[i].value <= 57 { if n < 3 { frac = frac * 10 + Int(u[i].value - 48); n += 1 }; i += 1 }
                    if n == 0 { return .nan }
                    while n < 3 { frac *= 10; n += 1 }
                    ms = frac
                }
            }
            if eat("Z") { off = 0 }
            else if i < u.count, u[i] == "+" || u[i] == "-" {
                let sign = u[i] == "-" ? -1 : 1; i += 1
                guard let oh = digits(2), eat(":"), let om = digits(2), oh <= 23, om <= 59 else { return .nan }
                off = sign * (oh * 60 + om)
            } else { return .nan }
            if i != u.count { return .nan }
        }
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
        let dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard month >= 1 && month <= 12, day >= 1 && day <= dim[month - 1], mi <= 59, sec <= 59 else { return .nan }
        guard h <= 24, h < 24 || (mi == 0 && sec == 0 && ms == 0) else { return .nan }
        // days from civil (Howard Hinnant)
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        let t = Double(days) * 86_400_000 + Double(h * 3_600_000 + mi * 60_000 + sec * 1000 + ms) - Double(off) * 60_000
        return abs(t) > 8.64e15 ? .nan : t
    }

    /// The names of an object's members in JS order: array-index keys ascending, then the `order` hint, then the rest by code unit.
    static func orderedKeys(_ o: JObject, _ order: [String] = []) -> [String] {
        let idx = o.keys.compactMap { k in JS.indexKey(k.s).map { (k.s, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
        let named = order.filter { n in o[JKey(n)] != nil && JS.indexKey(n) == nil }
        let rest = o.keys.map { $0.s }.filter { JS.indexKey($0) == nil && !order.contains($0) }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        return idx + named + rest
    }

    static func mkCheck(_ issuer: String, _ ok: Bool, _ reason: String?, _ attests: JSONValue? = nil) -> JSONValue {
        var o: JObject = ["issuer": .string(issuer), "ok": .bool(ok)]
        if let r = reason { o["reason"] = .string(r) }
        if let a = attests { o["attests"] = a }
        return .object(o)
    }

    static func verifyOneAttestation(_ a: JSONValue?, docId: JSONValue?, now: Double, resolver: Resolver?) throws -> JSONValue {
        let ao = a?.asObject
        let issuer = ao?["issuer"]?.asString ?? "<unknown>"
        guard let o = ao, let subject = o["subject"]?.asString, let attests = o["attests"], attests.asObject != nil, let validFrom = o["validFrom"]?.asString else {
            return mkCheck(issuer, false, "attestation is malformed")
        }
        if docId != .string(subject) { return mkCheck(issuer, false, "attestation subject '\(subject)' does not match agent id '\(JS.toString(docId))'") }
        let from = dateParse(validFrom)
        if !from.isFinite { return mkCheck(issuer, false, "attestation validFrom is not a valid date") }
        if !(now.isFinite && now >= from) { return mkCheck(issuer, false, "attestation is not yet valid") }
        if let vu = o["validUntil"] {
            let until = vu.asString.map(dateParse) ?? .nan // a non-string date is refused (the reference's legacy parser may read it)
            if !until.isFinite { return mkCheck(issuer, false, "attestation validUntil is not a valid date") }
            if !(now <= until) { return mkCheck(issuer, false, "attestation has expired") }
        }
        guard let rs = resolver else { return mkCheck(issuer, false, "no verification key or JWKS supplied") }
        let payload = try attestationStatementBytes(issuer: o["issuer"], subject: o["subject"], attests: attests, validFrom: o["validFrom"], validUntil: o["validUntil"])
        let r = try verifyDetached(payload, o["signature"], rs)
        if !r.ok { return mkCheck(issuer, false, "signature did not verify: \(r.reason)") }
        return mkCheck(issuer, true, nil, attests)
    }

    /// Verifies an AgentFacts document. `opts`: jwks? | key?, alg?, now?. The result is {ok, reason?, agentId, attestations,
    /// attested, selfAsserted, claims}.
    public static func verifyAgentFacts(_ facts: JSONValue?, _ opts: JObject) throws -> JSONValue {
        guard let f = facts?.asObject else { throw err("Cannot read properties of \(facts == nil ? "undefined" : "null") (reading 'selfAsserted')") }
        let selfAsserted = f["selfAsserted"]?.asObject ?? [:]
        let now = try nowMs(opts["now"])
        func result(ok: Bool, reason: String?, checks: [JSONValue], attested: JObject, claims: JObject) -> JSONValue {
            var o: JObject = ["ok": .bool(ok), "attestations": .array(checks), "attested": .object(attested), "selfAsserted": .object(selfAsserted), "claims": .object(claims)]
            if let r = reason { o["reason"] = .string(r) }
            if let id = f["id"] { o["agentId"] = id }
            return .object(o)
        }
        guard let list = f["attestations"]?.asArray else { return result(ok: false, reason: "agent facts has no attestations array", checks: [], attested: [:], claims: [:]) }
        var resolver: Resolver? = nil
        if !list.isEmpty {
            let res = resolveVerifyKey(opts)
            guard let r = res.resolver else {
                let checks = list.map { a -> JSONValue in mkCheck(a.asObject?["issuer"]?.asString ?? "<unknown>", false, "no verification key or JWKS supplied") }
                return result(ok: false, reason: res.error, checks: checks, attested: [:], claims: [:])
            }
            resolver = r
        }
        var checks: [JSONValue] = []
        var attested: JObject = [:]
        var allOk = true
        for a in list {
            let check = try verifyOneAttestation(a, docId: f["id"], now: now, resolver: resolver)
            checks.append(check)
            if check.get("ok") != .bool(true) { allOk = false; continue }
            if let at = check.get("attests")?.asObject { for (k, v) in at { attested[k] = v } }
        }
        var claims: JObject = [:]
        for k in selfAsserted.keys { claims[k] = .string("self-asserted") }
        for k in attested.keys { claims[k] = .string("attested") }
        return result(ok: allOk, reason: allOk ? nil : "one or more attestations did not verify", checks: checks, attested: attested, claims: claims)
    }

    // MARK: - well-known hosting

    static func jsonResponse(_ v: JSONValue, _ order: [String]) -> JSONValue {
        .object(["status": .int(200), "headers": .object(["content-type": .string("application/json"), "cache-control": .string("no-store")]),
                 "body": .string(JS.stringify(v, order: order))])
    }

    static func normalizePath(_ path: String) -> [Unicode.Scalar] {
        var s = Array(path.unicodeScalars)
        if let q = s.firstIndex(of: "?") { s = Array(s[..<q]) }
        if s.count > 1 && s.last == "/" { s.removeLast() }
        return s
    }

    /// A handler serving `value` at `path`; it returns the response for the resource, or nil when the path is not this handler's.
    static func handler(_ value: JSONValue, _ path: String, _ order: [String]) -> (String) -> JSONValue? {
        let target = normalizePath(path)
        let response = jsonResponse(value, order)
        return { req in normalizePath(req) == target ? response : nil }
    }

    public static func agentCardHandler(_ card: JSONValue, path: String? = nil, order: [String] = MEMBER_ORDER) -> (String) -> JSONValue? {
        handler(card, path ?? WELL_KNOWN_AGENT_CARD_PATH, order)
    }

    public static func agentFactsHandler(_ facts: JSONValue, path: String? = nil, order: [String] = MEMBER_ORDER) -> (String) -> JSONValue? {
        handler(facts, path ?? WELL_KNOWN_AGENT_FACTS_PATH, order)
    }

    // MARK: - registry entry

    /// `new URL(path, base).toString()` for a special-scheme base without credentials; nil when the reference's URL class would
    /// refuse, and for a base this parser does not model (credentials, non-special schemes), which fails closed to "no URL".
    static func wellKnownUrl(_ service: JSONValue?, _ path: String) -> String? {
        guard let s = service?.asString, let u = WhatwgURL.parse(s), let origin = u.origin else { return nil }
        let authority = s.split(separator: "/", maxSplits: 3, omittingEmptySubsequences: false).dropFirst(2).first.map(String.init) ?? ""
        if authority.contains("@") { return nil }
        return origin + path
    }

    /// The registry entry for a signed card and its AgentFacts: identity, the card / facts verbatim, the well-known card URL, and
    /// the attested vs self-asserted claim names (`order` = the key order of the self-asserted members).
    public static func toRegistryEntry(_ card: JSONValue?, _ facts: JSONValue?, order: [String] = []) throws -> JSONValue {
        guard let c = card?.asObject, let f = facts?.asObject else { throw err("toRegistryEntry: card and facts must be objects") }
        var attestedList: [String] = []
        var seen = Set<String>()
        switch JS.present(f["attestations"]) {
        case nil, .string?: break
        case let .array(items)?:
            for a in items {
                guard let at = a.asObject?["attests"]?.asObject else { continue }
                for k in orderedKeys(at, order) where seen.insert(k).inserted { attestedList.append(k) }
            }
        default: throw err("facts.attestations is not iterable")
        }
        let selfOnly = orderedKeys(f["selfAsserted"]?.asObject ?? [:], order).filter { !seen.contains($0) }
        var o: JObject = ["card": card!, "facts": facts!, "attestedClaims": .array(attestedList.map { .string($0) }), "selfAssertedClaims": .array(selfOnly.map { .string($0) })]
        if let id = f["id"] { o["id"] = id }
        if let n = c["name"] { o["name"] = n }
        for k in ["url", "version", "skills"] { if let v = c[key(k)] { o[JKey(k)] = v } }
        if JS.truthy(c["pcaPassport"]) { o["passport"] = c["pcaPassport"] }
        if JS.truthy(c["pcaProof"]) { o["pcaProof"] = c["pcaProof"] }
        if let u = wellKnownUrl(c["url"], WELL_KNOWN_AGENT_CARD_PATH) { o["agentCardUrl"] = .string(u) }
        return .object(o)
    }
}
