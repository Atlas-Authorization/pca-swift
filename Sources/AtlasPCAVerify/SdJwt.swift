import Foundation

/// SD-JWT serialization of a PCActn (mirrors `@atlasauth/pca-sdjwt`): issue an issuer-signed SD-JWT whose capability claims are
/// selectively disclosable, present a subset (optionally with a holder KB-JWT), verify fail-closed (RFC 9901 processing, key
/// binding) and re-verify the rebuilt PCActn with the core verifier. Issuer and holder signing is Ed25519 (EdDSA); verification
/// takes Ed25519 or ECDSA keys.
public enum PCASdJwt {
    public static let SD_ALG = "sha-256"
    public static let PCA_SD_JWT_TYP = "pca+sd-jwt"
    public static let KB_JWT_TYP = "kb+jwt"
    public static let DEFAULT_SIGNING_ALG = "EdDSA"
    public static let PCA_CAPABILITY_CLAIMS: [String] = [
        "action", "grant_ref", "cap_chain", "plan", "attestation", "provenance", "freshness", "counter", "risk_claim", "nonce", "caution",
        "rationale_commitment", "progress_step", "prohibition_evidence", "tool_binding", "alg", "pq_pk", "sig", "pq_sig", "threshold",
        "zk_compliance", "bond_ref",
    ]
    static let STANDARD_MAPPED: Set<String> = ["aud", "iat", "exp"]
    static let CLEAR_DISCRIMINATOR = "ver"
    static let CRITICAL_CLAIMS: Set<String> = ["iss", "aud", "exp", "nbf", "cnf", "status"]
    static let RESERVED_CLAIMS: Set<String> = ["iss", "sub", "aud", "iat", "exp", "_sd", "_sd_alg", "cnf"]
    static let SIGNING_ALGS: Set<String> = ["EdDSA", "Ed25519"]
    /// The JS Date range: a clock outside it is not a usable verification time.
    static let MAX_CLOCK_MS = 8.64e15

    static func err(_ m: String) -> JSError { JSError("pca-sdjwt: " + m) }

    /// base64url(SHA-256(ASCII(s))): Node's 'ascii' encoding keeps the low byte of each UTF-16 code unit.
    static func sha(_ s: String) -> String { Base64URLStrict.encode(AHash.sha256.digest(s.utf16.map { UInt8($0 & 0xff) })) }

    // ---- keys ----

    /// A public key given as raw Ed25519 bytes or as a JWK.
    public enum HolderKey {
        case raw([UInt8])
        case jwk(JSONValue)
    }

    public static func ed25519PublicJwk(_ raw: [UInt8]) throws -> JSONValue {
        guard raw.count == 32 else { throw err("Ed25519 public key must be 32 bytes") }
        return .object(["kty": .string("OKP"), "crv": .string("Ed25519"), "x": .string(Base64URLStrict.encode(raw))])
    }

    /// The verification key of a raw 32-byte Ed25519 public key.
    public static func ed25519PublicKey(_ raw: [UInt8]) throws -> Jose.Key {
        guard raw.count == 32 else { throw err("Ed25519 public key must be 32 bytes") }
        return .ed25519(raw)
    }

    static func checkSeed(_ seed: [UInt8]) throws {
        guard seed.count == 32 else { throw err("Ed25519 private seed must be 32 bytes") }
    }

    static func isJwk(_ v: JSONValue?) -> Bool { v?.get("kty")?.asString != nil && v?.asObject != nil }

    static func signer(_ alg: JSONValue?, seed: [UInt8]) throws -> String {
        guard let a = JS.nonEmptyString(alg) else { throw JSError("JWS \"alg\" (Algorithm) Header Parameter missing or invalid", code: "ERR_JWS_INVALID") }
        guard SIGNING_ALGS.contains(a) else { throw JSError("Invalid key for this operation: an Ed25519 key signs EdDSA only") }
        try checkSeed(seed)
        return a
    }

    // ---- issuance ----

    public struct IssueOptions {
        /// The issuer's 32-byte Ed25519 seed.
        public var issuerSeed: [UInt8]
        /// Capability claim names to make selectively disclosable (nil = PCA_CAPABILITY_CLAIMS); the others go in the clear.
        public var disclosable: [String]? = nil
        /// Embed a `cnf` holder key (enables a KB-JWT at presentation).
        public var keyBinding = false
        /// The `cnf` key (nil = the chain's leaf holder).
        public var holderPublicKey: HolderKey? = nil
        public var iss: String? = nil
        public var sub: String? = nil
        public var typ: String? = nil
        public var signingAlg: JSONValue? = nil
        public init(issuerSeed: [UInt8]) { self.issuerSeed = issuerSeed }
    }

    static func numericDate(_ v: JSONValue?, _ label: String, _ rule: FloatingPointRoundingRule) throws -> Double {
        guard let x = v, x.isNumber, let n = IV.num(x), n.isFinite else { throw err("PCActn.\(label) must be a finite number (epoch ms)") }
        return (n / 1000).rounded(rule)
    }

    /// A JSON number for a computed value (integral values as integers, as JSON.stringify prints them).
    static func jnum(_ d: Double) -> JSONValue {
        d == d.rounded() && abs(d) < 9_007_199_254_740_992 && !(d == 0 && d.sign == .minus) ? .int(Int64(d)) : .double(d)
    }

    static func cnfJwk(_ pc: JObject, _ hp: HolderKey?) throws -> JSONValue {
        switch hp {
        case nil:
            guard let h = pc["cap_chain"]?.asArray?.last?.get("holder")?.asString, !h.isEmpty else {
                throw err("cannot derive holder key — cap_chain leaf holder is missing")
            }
            return try ed25519PublicJwk(Attest.nodeB64(h))
        case let .raw(b)?: return try ed25519PublicJwk(b)
        case let .jwk(j)?:
            guard isJwk(j) else { throw err("keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key") }
            return j
        }
    }

    /// `<issuer JWT>~<Disclosure 1>~…~<Disclosure N>~` with fresh random salts. No KB-JWT at issuance.
    public static func issuePcaSdJwt(_ pcActn: JSONValue?, _ o: IssueOptions) throws -> String {
        guard let pc = pcActn?.asObject else { throw err("pcActn must be an object") }
        guard let chain = pc["cap_chain"]?.asArray, let root = chain.first, let leaf = chain.last else {
            throw err("pcActn.cap_chain must be a non-empty array")
        }
        guard let rootIss = root.get("issuer")?.asString else { throw err("cap_chain root issuer is missing") }
        guard let leafHolder = leaf.get("holder")?.asString else { throw err("cap_chain leaf holder is missing") }
        guard let aud = pc["aud"]?.asString, !aud.isEmpty else { throw err("pcActn.aud is required") }
        let iat = try numericDate(pc["iat"], "iat", .down)
        var exp = try numericDate(pc["exp"], "exp", .up)
        if exp <= iat { exp = iat + 1 }
        let disclosable = Set(o.disclosable ?? PCA_CAPABILITY_CLAIMS)

        var payload: JObject = ["iss": .string(o.iss ?? rootIss), "sub": .string(o.sub ?? leafHolder), "aud": .string(aud),
                                "iat": jnum(iat), "exp": jnum(exp), "iat_ms": pc["iat"]!, "exp_ms": pc["exp"]!, "_sd_alg": .string(SD_ALG)]
        if let v = pc["ver"] { payload["ver"] = v }
        var disclosures: [String] = []
        var sd: [JSONValue] = []
        for (k, v) in pc where !STANDARD_MAPPED.contains(k.s) && k.s != CLEAR_DISCRIMINATOR {
            if disclosable.contains(k.s) {
                let salt = Base64URLStrict.encode((0..<16).map { _ in UInt8.random(in: 0...255) })
                let enc = Base64URLStrict.encode(Array(JS.stringify(.array([.string(salt), .string(k.s), v])).utf8))
                disclosures.append(enc)
                sd.append(.string(sha(enc)))
            } else {
                payload[k] = v // kept in the clear (it may replace a standard claim of the same name, as the reference)
            }
        }
        if !sd.isEmpty { payload["_sd"] = .array(sd) }
        if o.keyBinding { payload["cnf"] = .object(["jwk": try cnfJwk(pc, o.holderPublicKey)]) }

        let alg = try signer(o.signingAlg ?? .string(DEFAULT_SIGNING_ALG), seed: o.issuerSeed)
        let header: JSONValue = .object(["alg": .string(alg), "typ": .string(o.typ ?? PCA_SD_JWT_TYP)])
        let jwt = try Jose.sign(header: header, headerOrder: ["alg", "typ"], payload: .object(payload),
                                payloadOrder: ["iss", "sub", "aud", "iat", "exp", "ver", "iat_ms", "exp_ms", "_sd_alg"]) {
            Ed25519Deterministic.sign(seed: o.issuerSeed, $0)
        }
        return ([jwt] + disclosures).map { $0 + "~" }.joined()
    }

    // ---- parsing ----

    struct Parsed {
        let jwt: Jose.CanonicalJws
        let jwtText: String
        let disclosures: [String]
        let kbJwt: String?
        let head: String
    }

    static func parse(_ s: String?) throws -> Parsed {
        guard let s = s, !s.isEmpty else { throw err("empty SD-JWT") }
        let segs = s.utf8.split(separator: UInt8(ascii: "~"), omittingEmptySubsequences: false).map { String(decoding: $0, as: UTF8.self) }
        guard segs.count >= 2 else { throw err("malformed SD-JWT (missing ~ separator)") }
        guard !segs[0].isEmpty else { throw err("empty issuer JWT") }
        let disclosures = Array(segs[1..<(segs.count - 1)])
        if disclosures.contains(where: { $0.isEmpty }) { throw err("empty disclosure segment") }
        let jwt = try Jose.assertCanonicalCompactJws(.string(segs[0]))
        let last = segs[segs.count - 1]
        if !last.isEmpty { _ = try Jose.assertCanonicalCompactJws(.string(last)) }
        return Parsed(jwt: jwt, jwtText: segs[0], disclosures: disclosures, kbJwt: last.isEmpty ? nil : last,
                      head: segs.dropLast().joined(separator: "~") + "~")
    }

    static func decodeDisclosure(_ enc: String) throws -> [JSONValue] {
        let v: JSONValue
        do { v = try Jose.parseJSONBytes(try Jose.decodeCanonicalBase64url(enc)) } catch { throw err("disclosure is not canonical base64url strict JSON") }
        guard let a = v.asArray, a.count == 2 || a.count == 3 else {
            throw err("disclosure must be a [salt, name, value] triple or a [salt, value] pair")
        }
        guard a[0].asString != nil else { throw err("disclosure salt must be a string") }
        return a
    }

    /// Every digest referenced by `_sd` arrays or `{"...": digest}` entries inside `node`.
    static func collectDigests(_ node: JSONValue) -> [String] {
        switch node {
        case let .array(a): return a.flatMap(collectDigests)
        case let .object(o):
            var out: [String] = []
            for (k, v) in o {
                if k == "_sd", let a = v.asArray { out += a.compactMap { $0.asString } } else if k == "...", let s = v.asString { out.append(s) } else { out += collectDigests(v) }
            }
            return out
        default: return []
        }
    }

    // ---- presentation ----

    /// The holder's KB-JWT inputs. `audience` / `nonce` are omitted when nil; `iat` nil = now (unix seconds).
    public struct PresentKeyBinding {
        public var holderSeed: [UInt8]
        public var audience: JSONValue?
        public var nonce: JSONValue? = nil
        public var iat: JSONValue? = nil
        public var alg: JSONValue? = nil
        public init(holderSeed: [UInt8], audience: JSONValue?) { self.holderSeed = holderSeed; self.audience = audience }
    }

    /// A presentation disclosing only `select` (each selected claim with everything nested in it); any KB-JWT is stripped and a
    /// fresh one is signed when `keyBinding` is given.
    public static func present(_ sdjwt: String?, _ select: [String], keyBinding: PresentKeyBinding? = nil) throws -> String {
        let p = try parse(sdjwt)
        let keep = Set(select)
        var byDigest: [String: String] = [:]
        for e in p.disclosures { byDigest[sha(e)] = e }
        var kept: Set<String> = []
        func include(_ digest: String) throws {
            guard let enc = byDigest[digest], kept.insert(digest).inserted else { return }
            let parts = try decodeDisclosure(enc)
            for d in collectDigests(parts[parts.count - 1]) { try include(d) }
        }
        let payload = p.jwt.payload ?? [:]
        for d in payload["_sd"]?.asArray ?? [] {
            guard let digest = d.asString, let enc = byDigest[digest] else { continue }
            let parts = try decodeDisclosure(enc)
            if parts.count == 3, let n = parts[1].asString, keep.contains(n) { try include(digest) }
        }
        for (k, v) in payload where k != "_sd" && keep.contains(k.s) { for d in collectDigests(v) { try include(d) } }
        let head = ([p.jwtText] + p.disclosures.filter { kept.contains(sha($0)) }).joined(separator: "~") + "~"
        guard let kb = keyBinding else { return head }

        let alg = try signer(kb.alg ?? .string(DEFAULT_SIGNING_ALG), seed: kb.holderSeed)
        var claims: JObject = ["iat": kb.iat ?? jnum(Date().timeIntervalSince1970.rounded(.down)), "sd_hash": .string(sha(head))]
        if let a = kb.audience { claims["aud"] = a }
        if let n = kb.nonce { claims["nonce"] = n }
        let jwt = try Jose.sign(header: .object(["alg": .string(alg), "typ": .string(KB_JWT_TYP)]), headerOrder: ["alg", "typ"],
                                payload: .object(claims), payloadOrder: ["iat", "aud", "sd_hash", "nonce"]) {
            Ed25519Deterministic.sign(seed: kb.holderSeed, $0)
        }
        return head + jwt
    }

    // ---- verification ----

    public struct VerifyOptions {
        public var issuerKey: Jose.Key
        /// Claim names that must be among the presented top-level Disclosures.
        public var requiredDisclosures: [String] = []
        /// The issuer JWT `aud` must be one of these (and the KB-JWT's, unless `expectedKbAudience` is set).
        public var expectedAudience: [String]? = nil
        public var expectedKbAudience: [String]? = nil
        /// The `cnf` key must be this key (a KB-JWT is then required).
        public var keyBindingKey: HolderKey? = nil
        public var expectedNonce: String? = nil
        public var requireKeyBinding = false
        /// Issuer JWT algorithms (nil = EdDSA only).
        public var algorithms: [String]? = nil
        /// KB-JWT algorithms (nil = EdDSA only).
        public var kbAlgorithms: [String]? = nil
        /// Unix ms (nil = the system clock).
        public var nowMs: Double? = nil
        /// The KB-JWT `iat` must be within this many seconds of now.
        public var kbMaxAgeSec: Double? = nil
        public var clockToleranceSec: Double? = nil
        public init(issuerKey: Jose.Key) { self.issuerKey = issuerKey }
    }

    final class Decoded {
        let parts: [JSONValue]
        var used = false
        init(_ p: [JSONValue]) { parts = p }
    }

    struct ProcessingError: Error { let message: String }

    /// RFC 9901 §7.1 processing: resolve `_sd` digests and `{"...": digest}` array elements recursively, refusing reserved and
    /// colliding names, reused digests, security-critical disclosed claims and unreferenced Disclosures.
    static func process(_ payload: JObject, _ byDigest: [String: Decoded]) throws -> (processed: JObject, disclosed: JObject) {
        var seen: Set<String> = []
        var disclosed: JObject = [:]
        func claim(_ d: String) throws -> Decoded? {
            guard seen.insert(d).inserted else { throw ProcessingError(message: "a digest appears more than once in the payload") }
            return byDigest[d]
        }
        func walk(_ node: JSONValue, _ top: Bool) throws -> JSONValue {
            switch node {
            case let .array(a):
                var out: [JSONValue] = []
                for el in a {
                    if let o = el.asObject, o.count == 1, let dv = o["..."] {
                        guard let digest = dv.asString else { throw ProcessingError(message: "an array '...' entry must reference a string digest") }
                        guard let d = try claim(digest) else { continue }
                        guard d.parts.count == 2 else { throw ProcessingError(message: "an array-element disclosure must be [salt, value]") }
                        d.used = true
                        out.append(try walk(d.parts[1], false))
                    } else {
                        out.append(try walk(el, false))
                    }
                }
                return .array(out)
            case let .object(o):
                var out: JObject = [:]
                for (k, v) in o where k != "_sd" { out[k] = try walk(v, false) }
                if let sdv = o["_sd"] {
                    guard let sd = sdv.asArray, sd.allSatisfy({ $0.asString != nil }) else { throw ProcessingError(message: "_sd must be an array of strings") }
                    for digest in sd.compactMap({ $0.asString }) {
                        guard let d = try claim(digest) else { continue }
                        guard d.parts.count == 3 else { throw ProcessingError(message: "an object-property disclosure must be [salt, name, value]") }
                        guard let name = d.parts[1].asString else { throw ProcessingError(message: "disclosure claim name must be a string") }
                        if name == "_sd" || name == "..." { throw ProcessingError(message: "disclosure claim name '\(name)' is reserved") }
                        if out[JKey(name)] != nil { throw ProcessingError(message: "disclosure claim '\(name)' collides with an existing claim") }
                        if top && CRITICAL_CLAIMS.contains(name) {
                            throw ProcessingError(message: "'\(name)' is security-critical and must not be selectively disclosable")
                        }
                        d.used = true
                        let value = try walk(d.parts[2], false)
                        out[JKey(name)] = value
                        if top { disclosed[JKey(name)] = value }
                    }
                }
                return .object(out)
            default:
                return node
            }
        }
        guard var processed = try walk(.object(payload), true).asObject else { throw ProcessingError(message: "payload is not an object") }
        processed["_sd_alg"] = nil
        if byDigest.values.contains(where: { !$0.used }) {
            throw ProcessingError(message: "a presented disclosure is not referenced by any digest in the payload")
        }
        return (processed, disclosed)
    }

    static func keyX(_ k: HolderKey) -> String? {
        switch k {
        case let .raw(b): return Base64URLStrict.encode(b)
        case let .jwk(j): return j.get("x")?.asString
        }
    }

    /// The `cnf` JWK as a KB-JWT verification key. An OKP / EC key that does not import is refused here; a key of another type
    /// is nil (the KB-JWT then fails verification). A `cnf` carrying private material is refused (the holder key leaked).
    static func kbKey(_ j: JObject) throws -> Jose.Key? {
        if j["d"] != nil { throw err("the cnf key carries private key material") }
        let b = { (k: String) in j[JKey(k)]?.asString.flatMap { Base64URLStrict.decode($0) } }
        switch j["kty"]?.asString {
        case "OKP":
            guard j["crv"] == .string("Ed25519"), let x = b("x"), x.count == 32 else { throw JSError("Invalid JWK OKP key") }
            return .ed25519(x)
        case "EC":
            let sizes = ["P-256": 32, "P-384": 48, "P-521": 66]
            guard let c = j["crv"]?.asString, let n = sizes[c], let x = b("x"), let y = b("y"), x.count == n, y.count == n else {
                throw JSError("Invalid JWK EC key")
            }
            return .ec(curve: c, point: [0x04] + x + y)
        default:
            return nil
        }
    }

    static func refuse(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason)]) }

    /// Verify a PCA SD-JWT, fail-closed: {ok: true, payload, processed, protectedHeader, disclosed, claims, keyBinding} or
    /// {ok: false, reason}. Never throws.
    public static func verifyPcaSdJwt(_ sdjwt: String?, _ o: VerifyOptions) -> JSONValue {
        do {
            if let n = o.nowMs, !(n.isFinite && abs(n) <= MAX_CLOCK_MS) { return refuse("pca-sdjwt: now is not a valid clock") }
            if let t = o.clockToleranceSec, !t.isFinite { return refuse("pca-sdjwt: clockToleranceSec must be finite") }
            if let m = o.kbMaxAgeSec, !m.isFinite { return refuse("pca-sdjwt: kbMaxAgeSec must be finite") }
            let p = try parse(sdjwt)
            var jo = Jose.VerifyOptions()
            jo.algorithms = o.algorithms ?? [DEFAULT_SIGNING_ALG]
            jo.audience = o.expectedAudience
            jo.now = o.nowMs.map { ($0 / 1000).rounded(.down) }
            jo.clockTolerance = o.clockToleranceSec ?? 0
            let (payload, header) = try Jose.jwtVerify(.string(p.jwtText), key: o.issuerKey, jo)

            if let a = payload["_sd_alg"], a != .string(SD_ALG) { return refuse("unsupported _sd_alg (require \"\(SD_ALG)\")") }
            var byDigest: [String: Decoded] = [:]
            for enc in p.disclosures {
                let d = sha(enc)
                if byDigest[d] != nil { return refuse("duplicate disclosure") }
                byDigest[d] = Decoded(try decodeDisclosure(enc))
            }
            let r: (processed: JObject, disclosed: JObject)
            do {
                r = try process(payload, byDigest)
            } catch let e as ProcessingError {
                return refuse(e.message.contains("not referenced") ? "a presented disclosure does not match any _sd digest (tampered)" : e.message)
            }
            let (processed, disclosed) = r
            for r in o.requiredDisclosures where disclosed[JKey(r)] == nil { return refuse("required disclosure '\(r)' was not presented") }

            let cnf = payload["cnf"]?.get("jwk")
            let cnfJwk = isJwk(cnf) ? cnf?.asObject : nil
            var kbOut: JObject = ["presented": .bool(p.kbJwt != nil), "verified": .bool(false)]
            if let kbJwt = p.kbJwt {
                guard let cj = cnfJwk else { return refuse("KB-JWT presented but issuer JWT has no cnf key") }
                if let want = o.keyBindingKey {
                    guard let w = keyX(want), let h = cj["x"]?.asString, w == h else { return refuse("cnf key does not match the expected keyBindingKey") }
                }
                let key = try kbKey(cj)
                let kb: (payload: JObject, header: JObject)
                do {
                    guard let k = key else { throw JSError("the cnf key type cannot verify a KB-JWT") }
                    var ko = Jose.VerifyOptions()
                    ko.algorithms = o.kbAlgorithms ?? [DEFAULT_SIGNING_ALG]
                    ko.audience = o.expectedKbAudience ?? o.expectedAudience
                    ko.now = jo.now
                    ko.clockTolerance = jo.clockTolerance
                    kb = try Jose.jwtVerify(.string(kbJwt), key: k, ko)
                } catch {
                    return refuse("KB-JWT signature/claims invalid: \((error as? JSError)?.message ?? "\(error)")")
                }
                if kb.header["typ"] != .string(KB_JWT_TYP) { return refuse("KB-JWT typ must be \"\(KB_JWT_TYP)\"") }
                guard let iatV = kb.payload["iat"], iatV.isNumber, let iat = IV.num(iatV) else { return refuse("KB-JWT iat is required") }
                if let max = o.kbMaxAgeSec {
                    let nowSec = ((o.nowMs ?? Date().timeIntervalSince1970 * 1000) / 1000).rounded(.down)
                    if !(nowSec - iat <= max) { return refuse("KB-JWT is older than the accepted window") }
                    if !(iat - nowSec <= (o.clockToleranceSec ?? 0)) { return refuse("KB-JWT iat is in the future") }
                }
                let aud = kb.payload["aud"]
                guard aud?.asString != nil || aud?.asArray != nil else { return refuse("KB-JWT aud is required") }
                if kb.payload["sd_hash"] != .string(sha(p.head)) { return refuse("KB-JWT sd_hash does not cover this presentation") }
                if let n = o.expectedNonce, kb.payload["nonce"] != .string(n) { return refuse("KB-JWT nonce does not match") }
                kbOut["verified"] = .bool(true)
                if let a = aud?.asString { kbOut["aud"] = .string(a) }
                if let n = kb.payload["nonce"]?.asString { kbOut["nonce"] = .string(n) }
            } else if o.keyBindingKey != nil || o.requireKeyBinding {
                return refuse("key binding required but no KB-JWT was presented")
            }

            var claims: JObject = [:]
            for (k, v) in processed where !RESERVED_CLAIMS.contains(k.s) { claims[k] = v }
            return .object(["ok": .bool(true), "payload": .object(payload), "processed": .object(processed), "protectedHeader": .object(header),
                            "disclosed": .object(disclosed), "claims": .object(claims), "keyBinding": .object(kbOut)])
        } catch {
            return refuse((error as? JSError)?.message ?? "\(error)")
        }
    }

    /// JS strict equality of two JSON members (objects and arrays are never equal; absent equals absent).
    static func strictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?):
            if x.isNumber && y.isNumber { return IV.num(x) == IV.num(y) }
            switch (x, y) {
            case let (.string(s), .string(t)): return s == t
            case let (.bool(s), .bool(t)): return s == t
            case (.null, .null): return true
            default: return false
            }
        default: return false
        }
    }

    /// Rebuild the PCActn from a verified result's claims and run the core verifier. Fail-closed on a withheld required claim,
    /// missing / inconsistent iat_ms / exp_ms, or an iss / sub that disagrees with the chain.
    public static func verifyRecovered(_ res: JSONValue, grant: JSONValue, now: Int64, audience: PCA.Audience,
                                       authorizedPlanRoots: [String]? = nil, insecureSkipPlanRootCheck: Bool = false) -> PCA.Verdict {
        let deny = { (r: String) in PCA.Verdict(allow: false, checks: [:], reason: "pca-sdjwt: " + r) }
        var rest = res.get("claims")?.asObject ?? [:]
        let p = res.get("processed")?.asObject ?? [:]
        guard let im = rest["iat_ms"], im.isNumber, let em = rest["exp_ms"], em.isNumber, let iatMs = IV.num(im), let expMs = IV.num(em) else {
            return deny("iat_ms/exp_ms missing; cannot rebuild the PCActn")
        }
        rest["iat_ms"] = nil
        rest["exp_ms"] = nil
        let pIat = p["iat"].flatMap { $0.isNumber ? IV.num($0) : nil }, pExp = p["exp"].flatMap { $0.isNumber ? IV.num($0) : nil }
        if (iatMs / 1000).rounded(.down) != pIat { return deny("iat_ms disagrees with iat") }
        if max((expMs / 1000).rounded(.up), (iatMs / 1000).rounded(.down) + 1) != pExp { return deny("exp_ms disagrees with exp") }
        for k in ["action", "cap_chain", "plan", "sig", "grant_ref", "counter"] where rest[JKey(k)] == nil {
            return deny("required claim '\(k)' was not disclosed")
        }
        guard let aud = p["aud"], aud.asString != nil else { return deny("aud must be a string") }
        guard let chain = rest["cap_chain"]?.asArray, let root = chain.first, let leaf = chain.last else { return deny("cap_chain is empty") }
        if !strictEq(p["iss"], root.get("issuer")) { return deny("iss does not match the chain root issuer") }
        if !strictEq(p["sub"], leaf.get("holder")) { return deny("sub does not match the chain leaf holder") }
        var pc = rest
        pc["ver"] = p["ver"]
        pc["aud"] = aud
        pc["iat"] = im
        pc["exp"] = em
        return PCA.verify(pcactn: .object(pc), grant: grant, now: now, audience: audience,
                          authorizedPlanRoots: authorizedPlanRoots, insecureSkipPlanRootCheck: insecureSkipPlanRootCheck)
    }
}
