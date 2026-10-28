import Foundation

// Google Cloud Confidential Space: the attestation token (RS256, ES256 defensively) verified under a signing key anchored in the
// configured trust anchors (a pinned JWKS, SPKI pins or an x5c chain to a configured root), with iss / time window, the
// Confidential Space claims, the eat_nonce binding and the workload image-digest allowlist. Same checks, order and reason text as
// the reference verifier. Classical; no network I/O.

final class GcpVerifier: HardwareAttestationVerifier {
    let issuers: Set<String>
    let trustedKeys: [JObject?]
    let spkiPins: Set<String>
    let rootCertsPem: [String]
    let images: Set<String>
    let teeTypes: Set<String>
    let hasTeeTypes: Bool
    let swName: String
    let swVersions: Set<String>
    let hasSwVersions: Bool
    let allowDebug: Bool
    let nonceHash: String
    let skew: Double

    init(_ cfg: JObject) throws {
        let p = "createGcpConfidentialSpaceVerifier: "
        guard case let .array(issArr)? = cfg["trustedIssuers"], !issArr.isEmpty else {
            throw AttestError(p + "trustedIssuers must be a NON-EMPTY list of trusted Google attestation issuer URLs")
        }
        var iss = Set<String>()
        for x in issArr {
            guard let s = x.asString, !s.isEmpty else { throw AttestError(p + "every trusted issuer must be a non-empty URL string") }
            iss.insert(s)
        }
        let anch = cfg["trustAnchors"]?.asObject ?? [:]
        var keys: [JObject?] = []
        if let tj = anch["trustedJwks"]?.asObject, let ks = tj["keys"]?.asArray {
            for k in ks { keys.append(k.asObject) }
        }
        let spkiCount = AttestUtil.listLen(anch["trustedKeySpki"])
        var pins = Set<String>()
        if case let .array(a)? = anch["trustedKeySpki"] { for x in a { if let s = x.asString { pins.insert(s.lowercased()) } } }
        let roots = Attest.asStrList(anch["rootCertsPem"]) ?? []
        if keys.count + spkiCount + AttestUtil.listLen(anch["rootCertsPem"]) == 0 {
            throw AttestError(p + "trustAnchors must configure at least one anchor (trustedJwks and/or trustedKeySpki and/or rootCertsPem) — accept-all is not permitted")
        }
        let pol = cfg["policy"]?.asObject ?? [:]
        guard let digests = Attest.asStrList(pol["imageDigests"]), !digests.isEmpty else {
            throw AttestError(p + "policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)")
        }
        var tee = Set<String>()
        var hasTee = false
        if let raw = pol["allowedTeeTypes"], case let .array(arr) = raw {
            if arr.isEmpty { throw AttestError(p + "policy.allowedTeeTypes, when present, must be non-empty") }
            hasTee = true
            for x in arr { if let s = x.asString { tee.insert(s) } }
        }
        var sw = Set<String>()
        var hasSw = false
        if case let .array(arr)? = pol["allowedSwVersions"] {
            hasSw = true
            for x in arr { if let s = x.asString { sw.insert(s) } }
        }
        issuers = iss
        trustedKeys = keys
        spkiPins = pins
        rootCertsPem = roots
        images = Set(digests.map { $0.lowercased() })
        teeTypes = tee
        hasTeeTypes = hasTee
        swName = pol["expectedSwName"]?.asString ?? "CONFIDENTIAL_SPACE"
        swVersions = sw
        hasSwVersions = hasSw
        allowDebug = pol["allowDebug"] == .bool(true)
        nonceHash = pol["nonceHash"]?.asString ?? ""
        skew = AttestUtil.skewOf(cfg)
    }

    /// A public key from a JWK (RSA n/e, EC x/y, or the leaf of an x5c chain). The key, or the reason on failure.
    static func jwkKey(_ jwk: JObject) -> (CertKey?, String) {
        if let n = jwk["n"]?.asString, let e = jwk["e"]?.asString {
            do { return (try JWS.jwkRSAKey(n, e), "") } catch { return (nil, "JWKS key is not a usable public key: " + AttestUtil.msg(error)) }
        }
        if jwk["kty"]?.asString == "EC", let crv = jwk["crv"]?.asString, let x = jwk["x"]?.asString, let y = jwk["y"]?.asString {
            do { return (try JWS.jwkECKey(crv, x, y), "") } catch { return (nil, "JWKS key is not a usable public key: " + AttestUtil.msg(error)) }
        }
        if let x5c = jwk["x5c"]?.asArray, !x5c.isEmpty, let s = x5c[0].asString {
            do {
                let c = try Cert.parseDER(Attest.nodeB64(s))
                return (try Cert.keyOf(c), "")
            } catch { return (nil, "JWKS key is not a usable public key: " + AttestUtil.msg(error)) }
        }
        return (nil, "JWKS key carries neither RSA n/e, EC x/y, nor an x5c certificate")
    }

    /// A trust root given as a certificate or as a bare public key.
    static func rootKeyFromPEM(_ pemText: String) -> CertKey? {
        if let c = try? Cert.fromPEM(pemText), let k = try? Cert.keyOf(c) { return k }
        if let der = Cert.pemDecodeFirst(pemText), let k = try? Cert.keyOfSPKI(der) { return k }
        return nil
    }

    /// A JWK x5c chain to a configured SPKI pin or root certificate; "" when it anchors.
    func verifyJwkX5cChain(_ x5c: [JSONValue], _ nowMs: Int64) -> String {
        if x5c.isEmpty { return "empty x5c certificate chain" }
        var certs: [AttCert] = []
        for (i, e) in x5c.enumerated() {
            guard let b64 = e.asString, !b64.isEmpty else { return "empty x5c entry at index \(i)" }
            let c: AttCert
            do { c = try Cert.parseDER(Attest.nodeB64(b64)) } catch { return "malformed x5c certificate at index \(i): " + AttestUtil.msg(error) }
            if !DER.derValidAtF(c.raw, nowMs, skew) { return "x5c certificate at index \(i) is outside its validity window" }
            certs.append(c)
        }
        for i in 0..<(certs.count - 1) where !Cert.sigOKBy(certs[i], certs[i + 1]) { return "x5c link \(i) is not signed by the certificate above it" }
        for c in certs {
            if let k = try? Cert.keyOf(c), spkiPins.contains(k.spkiSHA256) { return "" }
        }
        let top = certs[certs.count - 1]
        for pemText in rootCertsPem {
            if let rk = Self.rootKeyFromPEM(pemText), Cert.sigOK(top, rk) { return "" }
        }
        return "x5c chain does not anchor in a configured GCP trust root"
    }

    /// The key the token was signed under: by kid if present, else the sole key.
    static func pickJwk(_ tok: JwtParsed, _ keys: [JObject?]) -> JObject? {
        if tok.hasKid && !tok.kid.isEmpty {
            for k in keys {
                if let kk = k, let kid = kk["kid"]?.asString, kid == tok.kid { return kk }
            }
            return nil
        }
        if keys.count == 1 { return keys[0] }
        return nil
    }

    /// The token's signing key, confirmed anchored. The key, or the failure reason.
    func signingKey(_ tok: JwtParsed, _ evidenceJwks: JSONValue?, _ nowMs: Int64) -> (CertKey?, String) {
        var evKeys: [JObject?] = []
        if let ks = evidenceJwks?.asObject?["keys"]?.asArray { evKeys = ks.map { $0.asObject } }
        var jwk = Self.pickJwk(tok, evKeys)
        var fromTrusted = false
        if jwk == nil {
            jwk = Self.pickJwk(tok, trustedKeys)
            fromTrusted = jwk != nil
        }
        let hasKid = tok.hasKid && !tok.kid.isEmpty
        if jwk == nil && tok.hasX5c && !tok.x5c.isEmpty { jwk = ["x5c": .array(tok.x5c.map { JSONValue.string($0) })] }
        guard let jw = jwk else {
            if hasKid { return (nil, "no JWKS key matches the token kid '\(tok.kid)' (untrusted signer)") }
            return (nil, "no kid on the token and no unambiguous single signing key available")
        }
        let (keyOpt, why) = Self.jwkKey(jw)
        guard let key = keyOpt else { return (nil, why) }
        let spki = key.spkiSHA256
        if fromTrusted || spkiPins.contains(spki) { return (key, "") }
        for tk in trustedKeys {
            if let t = tk, case let (tb?, w) = Self.jwkKey(t), w.isEmpty, tb.spkiSHA256 == spki { return (key, "") }
        }
        if let x5c = jw["x5c"]?.asArray, !x5c.isEmpty, !rootCertsPem.isEmpty || !spkiPins.isEmpty {
            let chainErr = verifyJwkX5cChain(x5c, nowMs)
            if chainErr.isEmpty { return (key, "") }
            return (nil, "signing key not trusted: " + chainErr)
        }
        return (nil, "signing key is not anchored to any configured trust anchor (pinned JWKS / SPKI / root CA)")
    }

    func jwsSignature(_ tok: JwtParsed, _ k: CertKey) -> String {
        let (kty, crv) = JWS.ktyCrv(k)
        switch tok.alg {
        case "RS256":
            if kty != "RSA" { return "RS256 token but signing key is \(kty) (not RSA)" }
            if !JWS.rs256OK(tok.signature, tok.signingInput, k) { return "JWS RS256 signature does not verify under the Confidential Space signing key" }
            return ""
        case "ES256":
            if kty != "EC" || crv != "P-256" { return "ES256 token but signing key is \(kty)/\(crv) (not EC P-256)" }
            if tok.signature.count != 64 { return "ES256 signature is \(tok.signature.count) bytes (expected 64: r‖s)" }
            if !JWS.es256OK(tok.signature, tok.signingInput, k) { return "JWS ES256 signature does not verify under the Confidential Space signing key" }
            return ""
        default:
            return "unsupported JWS alg '\(tok.alg)' (Confidential Space uses RS256)"
        }
    }

    /// A Confidential Space hwmodel's isolation family ("" when unrecognised).
    static func teeType(_ hwmodel: String) -> String {
        switch hwmodel {
        case "GCP_AMD_SEV", "GCP_AMD_SEV_SNP", "GCP_AMD_SEV_ES": return "sev-snp"
        case "GCP_INTEL_TDX": return "tdx"
        default: break
        }
        let up = hwmodel.uppercased()
        if up.hasPrefix("GCP_AMD_SEV") { return "sev-snp" }
        if up.hasPrefix("GCP_INTEL_TDX") { return "tdx" }
        return ""
    }

    static func nonceCandidates(_ v: JSONValue?) -> [String] {
        if let s = v?.asString { return s.isEmpty ? [] : [s] }
        guard let arr = Attest.asStrList(v) else { return [] }
        return arr.filter { !$0.isEmpty }
    }

    func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult {
        let ev = evidence?.asObject
        guard let token = ev?["token"]?.asString, !token.isEmpty else { return .fail("no GCP Confidential Space token for this action") }
        let tok: JwtParsed
        do { tok = try JWS.parse(token, "parseGcpCsJwt") } catch { return .fail("Confidential Space token parse failed: " + AttestUtil.msg(error)) }
        if tok.alg != "RS256" && tok.alg != "ES256" { return .fail("unsupported JWS alg '\(tok.alg)' (Confidential Space uses RS256)") }
        let (keyOpt, why) = signingKey(tok, ev?["jwks"], nowMs)
        guard let key = keyOpt else { return .fail("Confidential Space signing key invalid: " + why) }
        let sigErr = jwsSignature(tok, key)
        if !sigErr.isEmpty { return .fail(sigErr) }

        let payload = tok.payload
        let issStr = payload["iss"]?.asString
        if (issStr ?? "").isEmpty || !issuers.contains(issStr ?? "") {
            return .fail("token iss '\(issStr ?? "undefined")' is not a configured trusted Google attestation issuer")
        }
        let nowSec = (Double(nowMs) / 1000).rounded(.down)
        let skewSec = (skew / 1000).rounded(.up)
        let exp = Attest.asFinite(payload["exp"])
        let iat = Attest.asFinite(payload["iat"])
        let nbf = Attest.asFinite(payload["nbf"])
        guard let expV = exp else { return .fail("token has no exp (cannot bound validity — fail closed)") }
        if nowSec - skewSec > expV { return .fail("Confidential Space token expired") }
        if let n = nbf, nowSec + skewSec < n { return .fail("Confidential Space token not yet valid (nbf)") }
        if let i = iat, nowSec + skewSec < i { return .fail("Confidential Space token issued in the future (iat)") }

        let submods = payload["submods"]?.asObject ?? [:]
        guard submods["confidential_space"]?.asObject != nil else { return .fail("token carries no submods.confidential_space (not a Confidential Space token)") }
        let swname = payload["swname"]?.asString
        if swname == nil || swname != swName { return .fail("unexpected swname '\(swname ?? "undefined")' (expected '\(swName)')") }
        if hasSwVersions {
            var versions: [String] = []
            if let l = Attest.asStrList(payload["swversion"]) { versions = l } else if let s = payload["swversion"]?.asString, !s.isEmpty { versions = [s] }
            if !versions.contains(where: { swVersions.contains($0) }) { return .fail("swversion not in policy allowlist") }
        }
        let hwmodel = payload["hwmodel"]?.asString ?? ""
        if hwmodel.isEmpty { return .fail("token carries no hwmodel claim") }
        let tee = Self.teeType(hwmodel)
        if tee.isEmpty { return .fail("unrecognized hwmodel '\(hwmodel)' (not a known AMD SEV-SNP / Intel TDX model)") }
        if hasTeeTypes && !teeTypes.contains(tee) { return .fail("attestation type '\(tee)' (hwmodel '\(hwmodel)') is not in the policy allowlist") }
        let dbgstat = payload["dbgstat"]?.asString
        if !allowDebug && dbgstat != "disabled-since-boot" { return .fail("token dbgstat '\(dbgstat ?? "undefined")' is not 'disabled-since-boot' (debug build — no confidentiality)") }
        guard let exp2 = expected else { return .fail("no expected attestation binding supplied") }
        let rawB = Attest.bindingBytes(exp2)
        guard let raw = rawB.bytes else { return .fail("binding not constructible: " + rawB.error) }
        let bindingBytes = AttestUtil.transformBinding(raw, nonceHash)
        let candidates = Self.nonceCandidates(payload["eat_nonce"])
        if candidates.isEmpty { return .fail("token carries no eat_nonce claim to bind the PCA challenge") }
        var bound = false
        for c in candidates {
            if let b = Attest.decodeClaimBytes(c), ACrypto.eq(b, bindingBytes) {
                bound = true
                break
            }
        }
        if !bound { return .fail("eat_nonce does not bind holder/grant/epoch/nonce (relayed or unbound token)") }
        let container = submods["container"]?.asObject ?? [:]
        guard let imageDigest = AttestUtil.firstString(container, ["image_digest"]) else { return .fail("token carries no submods.container.image_digest to measure the workload") }
        if !images.contains(imageDigest.lowercased()) { return .fail("workload image_digest not in policy allowlist") }
        var host: [String: String] = ["attestation_type": tee, "hwmodel": hwmodel, "image_digest": imageDigest]
        if let ref = AttestUtil.firstString(container, ["image_reference"]) { host["image_reference"] = ref }
        return HardwareResult(ok: true, bound: true, measured: Attest.newMeasured(imageDigest, ""), hostAsserted: host)
    }
}
