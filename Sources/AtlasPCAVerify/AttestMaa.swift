import Foundation

// Microsoft Azure Attestation (MAA): the signed MAA JWT of an Azure confidential VM (SEV-SNP "sevsnpvm" or TDX "tdxvm"), verified
// under the token-signing x5c chain anchored in a configured MAA root, with the PCA challenge bound through the report-data or
// runtime user-data claim. Same checks, order and reason text as the reference verifier. Classical (ES256 / RS256); no network
// I/O. Anchors are configured explicitly (the reference's key-rotation trust store is not part of the verifier).

enum AttestUtil {
    static func listLen(_ v: JSONValue?) -> Int {
        switch v {
        case let .array(a)?: return a.count
        case let .string(s)?: return s.utf8.count
        default: return 0
        }
    }

    static func skewOf(_ cfg: JObject) -> Double {
        if let f = Attest.asFinite(cfg["clockSkewMs"]) { return max(0, f) }
        return 0
    }

    static func firstString(_ rec: JObject, _ keys: [String]) -> String? {
        for k in keys { if let s = rec[JKey(k)]?.asString, !s.isEmpty { return s } }
        return nil
    }

    static func transformBinding(_ binding: [UInt8], _ mode: String) -> [UInt8] {
        switch mode {
        case "sha256": return ACrypto.sha256(binding)
        case "sha512": return ACrypto.sha512(binding)
        default: return binding
        }
    }

    static func msg(_ e: Error) -> String { (e as? AttestError)?.message ?? "invalid" }
}

final class MaaVerifier: HardwareAttestationVerifier {
    struct Policy {
        var sevSnp: [String] = []
        var tdx: [String] = []
        var sevHost: [String] = []
        var tdxRtmrs: [String] = []
        var minTcb: [String: Double] = [:]
        var allowDebug = false
        var runtimeUserData = false
        var tdxStatuses: [String] = []
        var hasTdxStatuses = false
        var reportDataHash = ""
        var hasSev = false
        var hasTdx = false
    }

    static let TCB_CLAIMS: [(name: String, claim: String, hostKey: String)] = [
        ("bootloader", "x-ms-sevsnpvm-bootloader-svn", "bootloader_svn"),
        ("snp", "x-ms-sevsnpvm-snpfw-svn", "snpfw_svn"),
        ("microcode", "x-ms-sevsnpvm-microcode-svn", "microcode_svn"),
        ("tee", "x-ms-sevsnpvm-tee-svn", "tee_svn"),
    ]

    let issuers: Set<String>
    let rootCertsPem: [String]
    let rootSpki: [String]
    let policy: Policy
    let skew: Double

    init(_ cfg: JObject) throws {
        let p = "createAzureMaaVerifier: "
        guard case let .array(issArr)? = cfg["trustedIssuers"], !issArr.isEmpty else {
            throw AttestError(p + "trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs")
        }
        var iss = Set<String>()
        for x in issArr {
            guard let s = x.asString, !s.isEmpty else { throw AttestError(p + "every trusted issuer must be a non-empty URL string") }
            iss.insert(s)
        }
        let anch = cfg["trustAnchors"]?.asObject ?? [:]
        if AttestUtil.listLen(anch["rootCertsPem"]) + AttestUtil.listLen(anch["rootSpkiSha256"]) == 0 {
            throw AttestError(p + "trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted")
        }
        let roots = Attest.asStrList(anch["rootCertsPem"]) ?? []
        let spkis = Attest.asStrList(anch["rootSpkiSha256"]) ?? []
        let polObj = cfg["policy"]?.asObject
        var sev: [String] = [], tdx: [String] = []
        if let po = polObj {
            sev = Attest.asStrList(po["sevSnpMeasurements"]) ?? []
            tdx = Attest.asStrList(po["tdxMrtds"]) ?? []
        }
        var pol = Policy()
        pol.hasSev = !sev.isEmpty
        pol.hasTdx = !tdx.isEmpty
        guard let po = polObj, pol.hasSev || pol.hasTdx else {
            throw AttestError(p + "policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)")
        }
        pol.sevSnp = Attest.lowerAll(sev)
        pol.tdx = Attest.lowerAll(tdx)
        if let raw = po["sevSnpMinTcb"] {
            guard case let .object(m) = raw else { throw AttestError(p + "policy.sevSnpMinTcb must be an object") }
            for k in m.keys.map({ $0.s }).sorted(by: { IV.utf8Less($0, $1) }) {
                if !Self.TCB_CLAIMS.contains(where: { $0.name == k }) {
                    throw AttestError("\(p)policy.sevSnpMinTcb.\(k) is not a known field (bootloader | snp | microcode | tee)")
                }
                guard let f = Attest.asFinite(m[JKey(k)]), f == f.rounded(.towardZero), f >= 0 else {
                    throw AttestError("\(p)policy.sevSnpMinTcb.\(k) must be a non-negative integer")
                }
                pol.minTcb[k] = f
            }
        }
        if let l = Attest.asStrList(po["sevSnpHostData"]) { pol.sevHost = Attest.lowerAll(l) }
        if let l = Attest.asStrList(po["tdxRtmrs"]) { pol.tdxRtmrs = Attest.lowerAll(l) }
        pol.allowDebug = po["allowDebug"] == .bool(true)
        pol.runtimeUserData = po["runtimeUserDataBinding"] == .bool(true)
        if let l = Attest.asStrList(po["tdxAllowedTcbStatuses"]) {
            pol.tdxStatuses = l
            pol.hasTdxStatuses = true
        }
        pol.reportDataHash = po["reportDataHash"]?.asString ?? ""
        issuers = iss
        rootCertsPem = roots
        rootSpki = spkis
        policy = pol
        skew = AttestUtil.skewOf(cfg)
    }

    // ---- x5c chain ----

    /// An x5c chain (base64 DER, leaf first) to a configured trust anchor. The leaf, or the failure reason.
    func verifyX5cChain(_ x5c: [JSONValue], _ nowMs: Int64, _ skew: Double) -> (AttCert?, String) {
        func thrown(_ e: Error) -> (AttCert?, String) { (nil, "x5c chain verification error (fail closed): " + AttestUtil.msg(e)) }
        if x5c.isEmpty { return (nil, "empty x5c certificate chain") }
        var certs: [AttCert] = []
        for (i, e) in x5c.enumerated() {
            guard let b64 = e.asString, !b64.isEmpty else { return (nil, "empty x5c entry at index \(i)") }
            let c: AttCert
            do { c = try Cert.parseDER(Attest.nodeB64(b64)) } catch { return (nil, "malformed x5c certificate at index \(i): " + AttestUtil.msg(error)) }
            if !DER.derValidAtF(c.raw, nowMs, skew) { return (nil, "x5c certificate at index \(i) is outside its validity window") }
            certs.append(c)
        }
        var fingerprints = Set<String>()
        for fp in rootSpki where !fp.isEmpty { fingerprints.insert(fp.lowercased()) }
        var roots: [AttCert] = []
        for pem in rootCertsPem {
            do {
                let c = try Cert.fromPEM(pem)
                let k = try Cert.keyOf(c)
                roots.append(c)
                fingerprints.insert(k.spkiSHA256)
            } catch { return thrown(error) }
        }
        if fingerprints.isEmpty && roots.isEmpty { return (nil, "no MAA trust anchor configured (fail closed)") }
        var anchorIdx = -1
        for (j, c) in certs.enumerated() {
            let k: CertKey
            do { k = try Cert.keyOf(c) } catch { return thrown(error) }
            if fingerprints.contains(k.spkiSHA256) {
                anchorIdx = j
                break
            }
        }
        if anchorIdx >= 0 {
            for i in 0..<anchorIdx where !Cert.sigOKBy(certs[i], certs[i + 1]) { return (nil, "x5c link \(i) is not signed by the certificate above it") }
            return (certs[0], "")
        }
        for i in 0..<(certs.count - 1) where !Cert.sigOKBy(certs[i], certs[i + 1]) { return (nil, "x5c link \(i) is not signed by the certificate above it") }
        let top = certs[certs.count - 1]
        for r in roots where Cert.sigOKBy(top, r) { return (certs[0], "") }
        return (nil, "x5c chain does not anchor in a configured MAA trust root")
    }

    /// The JWKS entry matched by kid, else the header's own x5c.
    static func resolveSigningX5c(_ tok: JwtParsed, _ jwks: JSONValue?) -> ([JSONValue]?, String) {
        let keys = jwks?.asObject?["keys"]?.asArray ?? []
        func chainOf(_ k: JSONValue) -> [JSONValue] { k.asObject?["x5c"]?.asArray ?? [] }
        if !keys.isEmpty {
            if !tok.hasKid || tok.kid.isEmpty {
                if keys.count != 1 { return (nil, "token has no kid and the JWKS publishes multiple keys (ambiguous)") }
                let c = chainOf(keys[0])
                return c.isEmpty ? (nil, "JWKS key carries no x5c chain") : (c, "")
            }
            for k in keys {
                if let kid = k.asObject?["kid"]?.asString, kid == tok.kid {
                    let c = chainOf(k)
                    return c.isEmpty ? (nil, "JWKS key '\(tok.kid)' carries no x5c chain") : (c, "")
                }
            }
            return (nil, "no JWKS key matches the token kid '\(tok.kid)' (untrusted signer)")
        }
        if tok.hasX5c && !tok.x5c.isEmpty { return (tok.x5c.map { JSONValue.string($0) }, "") }
        return (nil, "no signing x5c available (no JWKS and no header x5c)")
    }

    func jwsSignature(_ tok: JwtParsed, _ leaf: AttCert) -> String {
        let k: CertKey
        do { k = try Cert.keyOf(leaf) } catch { return "x5c chain verification error (fail closed): " + AttestUtil.msg(error) }
        let (kty, crv) = JWS.ktyCrv(k)
        switch tok.alg {
        case "ES256":
            if kty != "EC" || crv != "P-256" { return "ES256 token but signing key is \(kty)/\(crv) (not EC P-256)" }
            if tok.signature.count != 64 { return "ES256 signature is \(tok.signature.count) bytes (expected 64: r‖s)" }
            if !JWS.es256OK(tok.signature, tok.signingInput, k) { return "JWS ES256 signature does not verify under the MAA signing key" }
            return ""
        case "RS256":
            if kty != "RSA" { return "RS256 token but signing key is \(kty) (not RSA)" }
            if !JWS.rs256OK(tok.signature, tok.signingInput, k) { return "JWS RS256 signature does not verify under the MAA signing key" }
            return ""
        default:
            return "unsupported JWS alg '\(tok.alg)' (MAA uses ES256 / RS256)"
        }
    }

    func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult {
        let ev = evidence?.asObject
        guard let token = ev?["token"]?.asString, !token.isEmpty else { return .fail("no Azure MAA token for this action") }
        let tok: JwtParsed
        do { tok = try JWS.parse(token, "parseMaaJwt") } catch { return .fail("MAA token parse failed: " + AttestUtil.msg(error)) }
        if tok.alg != "ES256" && tok.alg != "RS256" { return .fail("unsupported JWS alg '\(tok.alg)' (MAA uses ES256 / RS256)") }
        let (x5cOpt, why) = Self.resolveSigningX5c(tok, ev?["jwks"])
        guard let x5c = x5cOpt else { return .fail(why) }
        let (leafOpt, why2) = verifyX5cChain(x5c, nowMs, skew)
        guard let leaf = leafOpt else { return .fail("MAA signing chain invalid: " + why2) }
        let sigErr = jwsSignature(tok, leaf)
        if !sigErr.isEmpty { return .fail(sigErr) }

        let payload = tok.payload
        let issStr = payload["iss"]?.asString
        if (issStr ?? "").isEmpty || !issuers.contains(issStr ?? "") {
            return .fail("token iss '\(issStr ?? "undefined")' is not a configured trusted MAA instance")
        }
        let nowSec = (Double(nowMs) / 1000).rounded(.down)
        let skewSec = (skew / 1000).rounded(.up)
        let exp = Attest.asFinite(payload["exp"])
        let iat = Attest.asFinite(payload["iat"])
        let nbf = Attest.asFinite(payload["nbf"])
        guard let expV = exp else { return .fail("token has no exp (cannot bound validity — fail closed)") }
        if nowSec - skewSec > expV { return .fail("MAA token expired") }
        if let n = nbf, nowSec + skewSec < n { return .fail("MAA token not yet valid (nbf)") }
        if let i = iat, nowSec + skewSec < i { return .fail("MAA token issued in the future (iat)") }

        var teeClaims = payload
        if let iso = payload["x-ms-isolation-tee"]?.asObject { teeClaims = iso }
        var isolation = teeClaims["x-ms-attestation-type"]?.asString
        if isolation == nil { isolation = payload["x-ms-attestation-type"]?.asString }
        guard let iso = isolation, iso == "sevsnpvm" || iso == "tdxvm" else {
            return .fail("unexpected x-ms-attestation-type '\(isolation ?? "undefined")' (expected sevsnpvm | tdxvm)")
        }

        guard let exp2 = expected else { return .fail("no expected attestation binding supplied") }
        let rawB = Attest.bindingBytes(exp2)
        if policy.runtimeUserData {
            guard let raw = rawB.bytes else { return .fail("binding not constructible: " + rawB.error) }
            guard let runtime = payload["x-ms-runtime"]?.asObject else {
                return .fail("token carries no x-ms-runtime claim (MAA emits it only when sha256(runtimeData) matches the quote report_data)")
            }
            let ud = runtime["user-data"]?.asString ?? ""
            if ud.isEmpty { return .fail("x-ms-runtime carries no user-data to bind the PCA challenge") }
            guard let got = Attest.decodeClaimBytes(ud), ACrypto.eq(got, raw) else {
                return .fail("runtime user-data does not bind holder/grant/epoch/nonce (relayed or unbound token)")
            }
        } else {
            guard let raw = rawB.bytes else { return .fail("binding not constructible: " + rawB.error) }
            let bindingBytes = AttestUtil.transformBinding(raw, policy.reportDataHash)
            let keys = iso == "sevsnpvm" ? ["x-ms-sevsnpvm-reportdata"] : ["tdx_report_data", "x-ms-tdx-report-data", "x-ms-tdx-reportdata"]
            guard let claim = AttestUtil.firstString(teeClaims, keys) else { return .fail("token carries no report-data claim to bind the PCA challenge") }
            guard let got = Attest.decodeClaimBytes(claim) else { return .fail("report-data claim is not decodable (hex/base64)") }
            if !ACrypto.eq(got, bindingBytes) { return .fail("report-data does not bind holder/grant/epoch/nonce (relayed or unbound token)") }
        }
        return iso == "sevsnpvm" ? sevSnpResult(teeClaims) : tdxResult(teeClaims)
    }

    func sevSnpResult(_ tee: JObject) -> HardwareResult {
        if !policy.hasSev { return .fail("sevsnpvm token but policy configures no SEV-SNP measurement allowlist (fail closed)") }
        guard let measurement = AttestUtil.firstString(tee, ["x-ms-sevsnpvm-launchmeasurement"]) else { return .fail("sevsnpvm token carries no launch-measurement claim") }
        let mHex = measurement.lowercased()
        if !policy.sevSnp.contains(mHex) { return .fail("SEV-SNP launch measurement not in policy allowlist") }
        if case .bool(true)? = tee["x-ms-sevsnpvm-is-debuggable"], !policy.allowDebug { return .fail("SEV-SNP guest is debuggable (no confidentiality)") }
        let hostData = AttestUtil.firstString(tee, ["x-ms-sevsnpvm-hostdata"])
        if !policy.sevHost.isEmpty {
            guard let h = hostData, policy.sevHost.contains(h.lowercased()) else { return .fail("SEV-SNP host-data not in policy allowlist") }
        }
        var reported: [String: String] = [:]
        for c in Self.TCB_CLAIMS {
            let f = Attest.asFinite(tee[JKey(c.claim)])
            let isSvn = f.map { $0 == $0.rounded(.towardZero) && $0 >= 0 } ?? false
            if isSvn, let v = f { reported[c.hostKey] = Attest.jsNumString(v) }
            guard let floor = policy.minTcb[c.name] else { continue }
            guard isSvn, let v = f else { return .fail("SEV-SNP \(c.name) SVN claim '\(c.claim)' is missing or not a non-negative integer (policy requires a minimum)") }
            if v < floor { return .fail("SEV-SNP \(c.name) SVN \(Attest.jsNumString(v)) is below the policy minimum \(Attest.jsNumString(floor))") }
        }
        var host: [String: String] = ["attestation_type": "sevsnpvm"]
        for (k, v) in reported { host[k] = v }
        if let h = hostData { host["host_data"] = h.lowercased() }
        return HardwareResult(ok: true, bound: true, measured: Attest.newMeasured(mHex, ""), hostAsserted: host)
    }

    func tdxResult(_ tee: JObject) -> HardwareResult {
        if !policy.hasTdx { return .fail("tdxvm token but policy configures no TDX MRTD allowlist (fail closed)") }
        guard let mrtd = AttestUtil.firstString(tee, ["tdx_mrtd", "x-ms-tdx-mrtd"]) else { return .fail("tdxvm token carries no MRTD claim") }
        let mrtdHex = mrtd.lowercased()
        if !policy.tdx.contains(mrtdHex) { return .fail("TDX MRTD not in policy allowlist") }
        let tdDebug = tee["tdx_td_attributes_debug"] == .bool(true)
        let dbgstat = tee["dbgstat"]?.asString
        if !policy.allowDebug && (tdDebug || (dbgstat != nil && dbgstat != "disabled")) { return .fail("TDX guest is debuggable (no confidentiality)") }
        let tcbStatus = tee["attester_tcb_status"]?.asString
        if let st = tcbStatus {
            let accepted = policy.hasTdxStatuses ? policy.tdxStatuses : IntelCollateral.DEFAULT_ACCEPTED
            if !accepted.contains(st) { return .fail("TDX platform TCB status '\(st)' is not accepted by policy") }
        }
        let rtmr0 = AttestUtil.firstString(tee, ["tdx_rtmr0", "x-ms-tdx-rtmr0"])
        if !policy.tdxRtmrs.isEmpty {
            guard let r = rtmr0, policy.tdxRtmrs.contains(r.lowercased()) else { return .fail("TDX RTMR0 not in policy allowlist") }
        }
        var host: [String: String] = ["attestation_type": "tdxvm"]
        if let st = tcbStatus, !st.isEmpty { host["tcb_status"] = st }
        if let r = rtmr0 { host["rtmr0"] = r.lowercased() }
        return HardwareResult(ok: true, bound: true, measured: Attest.newMeasured(mrtdHex, ""), hostAsserted: host)
    }
}
