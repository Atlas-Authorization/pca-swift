import Foundation

// Intel TDX (DCAP v4, ECDSA-P256): the genuine quote end to end (PCK chain to the pinned Intel SGX Root CA, QE report under the PCK
// leaf, attestation key endorsed by the QE, TD quote signature), the PCA binding in its two modes, and the optional Intel PCS
// collateral (AttestIntelCollateral.swift). Same checks, order and reason text as the reference verifier.

final class DcapVerifier: HardwareAttestationVerifier {
    /// Intel's SGX Provisioning Certification Root CA (SPKI SHA-256, lowercase hex).
    static let INTEL_ROOT_SPKI_SHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"

    static let HEADER_LEN = 48, TD_REPORT_LEN = 584, SGX_REPORT = 384, QE_ATTR_OFF = 48, QE_RDATA_OFF = 0x140

    struct Quote {
        var header: [UInt8] = []
        var tdReportBody: [UInt8] = []
        var quoteSignature: [UInt8] = []
        var akPubRaw: [UInt8] = []
        var qeReportBody: [UInt8] = []
        var qeReportSignature: [UInt8] = []
        var qeAuthData: [UInt8] = []
        var pckChainPem = ""
    }

    static func le(_ b: [UInt8], _ o: Int, _ n: Int) -> Int {
        var v = 0
        for i in (0..<n).reversed() { v = v << 8 | Int(b[o + i]) }
        return v
    }

    static func parseQuote(_ q: [UInt8]) throws -> Quote {
        if q.count < HEADER_LEN + TD_REPORT_LEN + 4 { throw AttestError("parseDcapQuote: too short for header + TD report + sig length") }
        let version = le(q, 0, 2), attKeyType = le(q, 2, 2), teeType = le(q, 4, 4)
        if version != 4 { throw AttestError("parseDcapQuote: unsupported quote version \(version) (expected 4)") }
        if attKeyType != 2 { throw AttestError("parseDcapQuote: unsupported attestation key type \(attKeyType) (expected ECDSA-P256 = 2)") }
        if teeType != 0x81 { throw AttestError("parseDcapQuote: unexpected TEE type 0x\(String(teeType, radix: 16)) (expected TDX = 0x81)") }
        var out = Quote()
        out.header = Array(q[0..<HEADER_LEN])
        out.tdReportBody = Array(q[HEADER_LEN..<(HEADER_LEN + TD_REPORT_LEN)])
        var o = HEADER_LEN + TD_REPORT_LEN
        let sigDataLen = le(q, o, 4)
        o += 4
        let sigEnd = o + sigDataLen
        if sigEnd > q.count { throw AttestError("parseDcapQuote: signature data (\(sigDataLen)) overruns the quote") }
        func need(_ n: Int, _ what: String) throws { if o + n > sigEnd { throw AttestError("parseDcapQuote: truncated reading \(what)") } }
        try need(64, "quote signature")
        out.quoteSignature = Array(q[o..<(o + 64)])
        o += 64
        try need(64, "attestation public key")
        out.akPubRaw = Array(q[o..<(o + 64)])
        o += 64
        try need(6, "outer cert-data header")
        let outerType = le(q, o, 2), outerSize = le(q, o + 2, 4)
        o += 6
        if outerType != 6 { throw AttestError("parseDcapQuote: outer cert-data type \(outerType) (expected QE-report-cert-data = 6)") }
        let outerEnd = o + outerSize
        if outerEnd > sigEnd { throw AttestError("parseDcapQuote: outer cert-data overruns signature data") }
        try need(SGX_REPORT, "QE report")
        out.qeReportBody = Array(q[o..<(o + SGX_REPORT)])
        o += SGX_REPORT
        try need(64, "QE report signature")
        out.qeReportSignature = Array(q[o..<(o + 64)])
        o += 64
        try need(2, "QE auth-data size")
        let authSize = le(q, o, 2)
        o += 2
        try need(authSize, "QE auth-data")
        out.qeAuthData = Array(q[o..<(o + authSize)])
        o += authSize
        try need(6, "inner cert-data header")
        let innerType = le(q, o, 2), innerSize = le(q, o + 2, 4)
        o += 6
        if innerType != 5 { throw AttestError("parseDcapQuote: inner cert-data type \(innerType) (expected PCK-cert-chain = 5)") }
        if o + innerSize > outerEnd { throw AttestError("parseDcapQuote: inner cert-data overruns outer cert-data") }
        out.pckChainPem = String(decoding: q[o..<(o + innerSize)], as: UTF8.self)
        if q[sigEnd...].contains(where: { $0 != 0 }) { throw AttestError("parseDcapQuote: non-zero bytes after the signature data") }
        return out
    }

    // ---- the Intel SGX extension (byte scan, as the reference does) ----

    static let OID_SGX_FMSPC: [UInt8] = [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04]
    static let OID_SGX_TCB: [UInt8] = [0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02]

    static func indexOf(_ hay: [UInt8], _ needle: [UInt8]) -> Int {
        if needle.isEmpty || hay.count < needle.count { return -1 }
        var i = 0
        while i + needle.count <= hay.count {
            if hay[i] == needle[0] {
                var match = true
                for j in 1..<needle.count where hay[i + j] != needle[j] {
                    match = false
                    break
                }
                if match { return i }
            }
            i += 1
        }
        return -1
    }

    struct PckTcb {
        var fmspc: [UInt8]
        var sgx: [UInt8] // 16 SGX TCB component SVNs
        var pcesvn: Int
    }

    /// The FMSPC and the issued TCB from the PCK leaf's Intel SGX extension.
    static func extractPckFmspcAndTcb(_ leaf: [UInt8]) throws -> PckTcb {
        let fi = indexOf(leaf, OID_SGX_FMSPC)
        if fi < 0 { throw AttestError("extractPckFmspcAndTcb: FMSPC OID not found in certificate") }
        guard let fv = try? DER.tlvAt(leaf, fi + OID_SGX_FMSPC.count), fv.tag == 0x04, fv.end - fv.start == 6 else {
            throw AttestError("extractPckFmspcAndTcb: malformed FMSPC OCTET STRING")
        }
        let fmspc = Array(leaf[fv.start..<fv.end])
        let ti = indexOf(leaf, OID_SGX_TCB)
        if ti < 0 { throw AttestError("extractPckFmspcAndTcb: TCB OID not found in certificate") }
        guard let seq = try? DER.tlvAt(leaf, ti + OID_SGX_TCB.count), seq.tag == 0x30 else { throw AttestError("extractPckFmspcAndTcb: malformed TCB SEQUENCE") }
        var sgx = [UInt8](repeating: 0, count: 16)
        var pcesvn = -1
        var p = seq.start
        var idx = 0
        while p < seq.end {
            guard let pair = try? DER.tlvAt(leaf, p), pair.tag == 0x30 else { throw AttestError("extractPckFmspcAndTcb: malformed TCB component") }
            guard let oid = try? DER.tlvAt(leaf, pair.start), oid.tag == 0x06 else { throw AttestError("extractPckFmspcAndTcb: TCB component missing OID") }
            guard let val = try? DER.tlvAt(leaf, oid.end) else { throw AttestError("extractPckFmspcAndTcb: TCB component missing value") }
            let last = Int(leaf[oid.end - 1])
            if val.tag == 0x02 {
                var n: UInt32 = 0
                for b in val.start..<val.end { n = n << 8 | UInt32(leaf[b]) }
                if last >= 1 && last <= 16 { sgx[last - 1] = UInt8(n & 0xff) } else if last == 17 { pcesvn = Int(n & 0xffff) }
            }
            p = pair.end
            idx += 1
            if idx > 64 { break }
        }
        if pcesvn < 0 { throw AttestError("extractPckFmspcAndTcb: PCESVN not found in TCB extension") }
        return PckTcb(fmspc: fmspc, sgx: sgx, pcesvn: pcesvn)
    }

    // ---- PCK chain ----

    struct ChainResult {
        var ok = false
        var reason = ""
        var validity = false // the failure was a validity-window failure
        var leaf: AttCert?
        var leafPoint: [UInt8]?
        var depth = 0
    }

    static func msg(_ e: Error) -> String { (e as? AttestError)?.message ?? "invalid" }

    /// Verifies a PEM chain to the pinned Intel SGX Root CA (every certificate valid at nowMs, every link signed, the root self-signed
    /// and pinned, CA roles, no unrecognised critical extension, an EC P-256 leaf).
    static func verifyPckChain(_ pckChainPem: String, _ pin: String, _ nowMs: Int64) -> ChainResult {
        func thrown(_ e: Error) -> ChainResult { ChainResult(reason: "PCK chain X.509 verification error (fail closed): " + msg(e)) }
        func fail(_ r: String) -> ChainResult { ChainResult(reason: r) }
        let blocks = Cert.pemBlocks(pckChainPem)
        if blocks.isEmpty { return fail("no PEM certificates in the PCK chain") }
        var certs: [AttCert] = []
        for b in blocks {
            do { certs.append(try Cert.fromPEM(b)) } catch { return thrown(error) }
        }
        var issuers = Set<[UInt8]>()
        var bySubject: [[UInt8]: AttCert] = [:]
        for c in certs {
            issuers.insert(c.rawIssuer)
            bySubject[c.rawSubject] = c
        }
        var leaf = certs[0]
        for c in certs where !issuers.contains(c.rawSubject) {
            leaf = c
            break
        }
        var ordered: [AttCert] = []
        var seen = Set<[UInt8]>()
        var cur: AttCert? = leaf
        while let c = cur, !seen.contains(c.rawSubject) {
            ordered.append(c)
            seen.insert(c.rawSubject)
            if Cert.selfIssued(c) { break }
            cur = bySubject[c.rawIssuer]
        }
        guard let root = ordered.last else { return fail("PCK chain does not terminate in a self-signed root") }
        if !Cert.selfIssued(root) { return fail("PCK chain does not terminate in a self-signed root") }
        if ordered.count != certs.count { return fail("PCK chain is not a single connected path (orphan/duplicate certificates)") }
        for c in ordered where !DER.derValidAt(c.raw, nowMs, 0) { return ChainResult(reason: "PCK chain certificate outside its validity period", validity: true) }
        for i in 0..<(ordered.count - 1) {
            let child = ordered[i], parent = ordered[i + 1]
            if child.rawIssuer != parent.rawSubject { return fail("certificate at depth \(i) issuer does not match its parent subject") }
            if !Cert.sigOKBy(child, parent) { return fail("certificate at depth \(i) is not signed by its issuer") }
        }
        if !Cert.sigOKBy(root, root) { return fail("root certificate is not self-signed") }
        let rootKey: CertKey
        do { rootKey = try Cert.keyOf(root) } catch { return thrown(error) }
        if rootKey.spkiSHA256 != pin.lowercased() { return fail("Intel SGX Root CA does not match the pinned trust anchor") }
        let ders = ordered.map { $0.raw }
        let roleFail = DER.checkChainRoles(ders)
        if !roleFail.isEmpty { return fail(roleFail) }
        for (i, d) in ders.enumerated() {
            do {
                if let crit = try DER.unrecognisedCriticalExtension(d) { return fail("PCK chain certificate at depth \(i) has an unrecognised critical extension \(crit)") }
            } catch { return thrown(error) }
        }
        let lk: CertKey
        do { lk = try Cert.keyOf(leaf) } catch { return thrown(error) }
        if lk.typ != "ec" { return fail("PCK leaf key is not EC (got \(lk.typ))") }
        let point: [UInt8]
        do { point = try Cert.ecPoint(lk, "P-256") } catch { return thrown(error) }
        return ChainResult(ok: true, leaf: leaf, leafPoint: point, depth: ordered.count)
    }

    // ---- genuine quote ----

    struct QuotePolicy {
        var mrtds: [String] = []
        var fmspcs: [String] = []
        var rtmrs: [String] = []
        var mrSeams: [String] = []
        var mrSignerSeams: [String] = []
        var hasMrSeams = false
        var hasMrSigner = false
        var allowDebug = false
    }

    struct TdxResult {
        var ok = false
        var reason = ""
        var reportData: [UInt8] = []
        var fmspc = ""
        var pck: PckTcb?
        var mrTd: [UInt8] = []
    }

    static func p256Compact(_ msg: [UInt8], _ sig: [UInt8], _ point: [UInt8]) -> Bool {
        sig.count == 64 && ACrypto.ecVerify(curve: "P-256", point: point, hash: .sha256, message: msg, raw: sig)
    }

    static func verifyGenuineQuote(_ quote: [UInt8], _ pin: String, _ nowMs: Int64, _ pol: QuotePolicy?, _ allowDebugOnly: Bool) -> TdxResult {
        func bad(_ r: String) -> TdxResult { TdxResult(reason: r) }
        let q: Quote
        do { q = try parseQuote(quote) } catch { return bad("quote parse failed: " + msg(error)) }
        let body = q.tdReportBody
        let chain = verifyPckChain(q.pckChainPem, pin, nowMs)
        guard chain.ok, let leafPoint = chain.leafPoint, let leaf = chain.leaf else { return bad("PCK chain invalid: " + chain.reason) }
        let tcb: PckTcb
        do { tcb = try extractPckFmspcAndTcb(leaf.raw) } catch { return bad("PCK FMSPC/TCB extraction failed: " + msg(error)) }
        if !p256Compact(q.qeReportBody, q.qeReportSignature, leafPoint) { return bad("QE report signature does not verify under the PCK leaf") }
        if q.qeReportBody[QE_ATTR_OFF] & 0x02 != 0 { return bad("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)") }
        let qeReportData = Array(q.qeReportBody[QE_RDATA_OFF..<(QE_RDATA_OFF + 64)])
        let akBinding = ACrypto.sha256(q.akPubRaw + q.qeAuthData)
        let zero = !qeReportData[32..<64].contains { $0 != 0 }
        if !ACrypto.eq(Array(qeReportData[0..<32]), akBinding) || !zero { return bad("QE report_data does not bind the attestation key (AK not endorsed by this QE)") }
        let akPoint: [UInt8] = [0x04] + q.akPubRaw
        if !ACrypto.ecPointValid(curve: "P-256", point: akPoint) { return bad("attestation public key is not a valid P-256 point") }
        if !p256Compact(q.header + body, q.quoteSignature, akPoint) { return bad("TD quote signature does not verify under the attestation key") }
        let allowDebug = allowDebugOnly || (pol?.allowDebug ?? false)
        if !allowDebug && body[120] & 1 != 0 { return bad("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)") }
        let mrTd = Array(body[136..<184])
        let fmspcHex = ACrypto.hex(tcb.fmspc)
        if let p = pol {
            if !p.mrtds.isEmpty && !p.mrtds.contains(ACrypto.hex(mrTd)) { return bad("MRTD not in policy allowlist") }
            if !p.fmspcs.isEmpty && !p.fmspcs.contains(fmspcHex) { return bad("FMSPC not in policy allowlist") }
            if p.hasMrSeams && !p.mrSeams.contains(ACrypto.hex(Array(body[16..<64]))) { return bad("MRSEAM not in policy allowlist") }
            if p.hasMrSigner && !p.mrSignerSeams.contains(ACrypto.hex(Array(body[64..<112]))) { return bad("MRSIGNERSEAM not in policy allowlist") }
            if !p.rtmrs.isEmpty && !p.rtmrs.contains(ACrypto.hex(Array(body[328..<376]))) { return bad("RTMR0 not in policy allowlist") }
        }
        return TdxResult(ok: true, reportData: Array(body[520..<584]), fmspc: fmspcHex, pck: tcb, mrTd: mrTd)
    }

    // ---- the verifier ----

    let binding: String
    let pol: QuotePolicy
    let pin: String
    let allowMissing: Bool
    let collateralPol: CollateralPolicy
    let hasCollateralPol: Bool

    static func isHex(_ s: String, _ len: Int) -> Bool { s.utf8.count == len && ACrypto.unhex(s) != nil }

    init(_ cfg: JObject) throws {
        let b = cfg["binding"]?.asString ?? ""
        if b != "report-data" && b != "azure-runtime-data" { throw AttestError("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'") }
        let polObj = cfg["policy"]?.asObject ?? [:]
        guard let mr = Attest.asStrList(polObj["mrtds"]), !mr.isEmpty else {
            throw AttestError("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)")
        }
        let mrtds = Attest.lowerAll(mr)
        for m in mrtds where !Self.isHex(m, 96) { throw AttestError("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)") }
        var qp = QuotePolicy()
        qp.mrtds = mrtds
        for name in ["mrSeams", "mrSignerSeams"] {
            guard let raw = polObj[JKey(name)] else { continue }
            guard let list = Attest.asStrList(raw), !list.isEmpty else { throw AttestError("createIntelDcapVerifier: policy.\(name), if given, must be a NON-EMPTY list") }
            for m in list where !Self.isHex(m, 96) { throw AttestError("createIntelDcapVerifier: every \(name) entry must be 96 hex chars (48 bytes)") }
            if name == "mrSeams" {
                qp.mrSeams = Attest.lowerAll(list)
                qp.hasMrSeams = true
            } else {
                qp.mrSignerSeams = Attest.lowerAll(list)
                qp.hasMrSigner = true
            }
        }
        if let l = Attest.asStrList(polObj["fmspcs"]) { qp.fmspcs = Attest.lowerAll(l) }
        if let l = Attest.asStrList(polObj["rtmrs"]) { qp.rtmrs = Attest.lowerAll(l) }
        qp.allowDebug = polObj["allowDebug"] == .bool(true)
        var p = Self.INTEL_ROOT_SPKI_SHA256
        if let o = cfg["trustAnchorRootCaSpkiSha256"]?.asString { p = o.lowercased() }
        var cpol = CollateralPolicy()
        var hasC = false
        if let cp = polObj["collateral"]?.asObject {
            hasC = true
            if let l = Attest.asStrList(cp["acceptStatuses"]) {
                cpol.acceptStatuses = l
                cpol.hasAccept = true
            }
            if let f = Attest.asFinite(cp["minTcbEvaluationDataNumber"]) {
                cpol.minEval = f
                cpol.hasMinEval = true
            }
        }
        binding = b
        pol = qp
        pin = p
        allowMissing = cfg["allowMissingCollateral"] == .bool(true)
        collateralPol = cpol
        hasCollateralPol = hasC
    }

    func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult {
        let ev = evidence?.asObject
        guard let quote = Attest.evBytes(ev, "quote") else { return .fail("no Intel DCAP quote for this action") }
        guard let exp = expected else { return .fail("no expected attestation binding supplied") }
        let q = Self.verifyGenuineQuote(quote, pin, nowMs, pol, false)
        if !q.ok { return .fail("DCAP quote invalid: " + q.reason) }
        if binding == "report-data" {
            let want = Attest.bindingBytes(exp)
            guard let wb = want.bytes else { return .fail("binding not constructible: " + want.error) }
            if !ACrypto.eq(q.reportData, wb) { return .fail("report_data does not bind holder/grant/epoch/nonce") }
        } else {
            guard let rd = Attest.evBytes(ev, "runtimeData") else { return .fail("azure-runtime-data binding needs the runtime-data JSON bytes") }
            let why = Attest.checkAzureRuntimeDataBinding(q.reportData, rd, exp)
            if !why.isEmpty { return .fail(why) }
        }
        var host: [String: String] = ["attestation_type": "tdx-dcap", "fmspc": q.fmspc]
        if let col = ev?["collateral"]?.asObject {
            let c = IntelCollateral.fromWire(col)
            let res = IntelCollateral.verify(quote, c, nowMs, hasCollateralPol ? collateralPol : nil, pin, pol.allowDebug)
            if !res.status.isEmpty { host["tcb_status"] = res.status }
            if !res.advisoryIDs.isEmpty { host["advisory_ids"] = res.advisoryIDs.joined(separator: ",") }
            if !res.ok { return .fail("Intel collateral: " + (res.reason.isEmpty ? "rejected" : res.reason)) }
        } else if allowMissing {
            host["tcb_status"] = "unevaluated"
        } else {
            return .fail("Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)")
        }
        return HardwareResult(ok: true, bound: true, measured: Attest.newMeasured(ACrypto.hex(q.mrTd), ""), hostAsserted: host)
    }
}
