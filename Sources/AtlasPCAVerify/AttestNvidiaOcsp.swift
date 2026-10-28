import Foundation

// NVIDIA GPU-CC device-chain revocation through OCSP (RFC 6960): the offline-verifiable equivalent of NVIDIA's own check. For each
// non-root certificate the supplied responses are verified (responseStatus, CertID, BasicOCSPResponse signature under the issuer
// or a delegated responder certificate signed by the supplied chain, freshness) and the status must be GOOD where it is
// required. Every time value in a response must be a well-formed DER time (no roll-over).

struct OcspNode {
    var tag: UInt8
    var hdr: Int
    var start: Int
    var end: Int
    var constructed: Bool { tag & 0x20 != 0 }
}

struct OcspResult {
    var ok = false
    var reason = ""
    var status = ""
}

enum OCSP {
    static let OID_BASIC = "1.3.6.1.5.5.7.48.1.1"
    static let DEFAULT_MAX_MS: Int64 = 7 * 24 * 3600 * 1000

    static let SIG_ALGS: [String: (hash: AHash, ec: Bool)] = [
        "1.2.840.10045.4.3.2": (.sha256, true), "1.2.840.10045.4.3.3": (.sha384, true), "1.2.840.10045.4.3.4": (.sha512, true),
        "1.2.840.113549.1.1.11": (.sha256, false), "1.2.840.113549.1.1.12": (.sha384, false), "1.2.840.113549.1.1.13": (.sha512, false),
    ]

    static let CERT_ID_HASHES: [String: AHash] = [
        "1.3.14.3.2.26": .sha1, "2.16.840.1.101.3.4.2.1": .sha256, "2.16.840.1.101.3.4.2.2": .sha384, "2.16.840.1.101.3.4.2.3": .sha512,
    ]

    static func readNode(_ b: [UInt8], _ off: Int, _ limit: Int) throws -> OcspNode {
        let t: DerTlv
        do { t = try DER.tlvAt(b, off, limit: limit) } catch { throw AttestError("not valid DER") }
        if t.tag & 0x1f == 0x1f { throw AttestError("multi-byte tags are not supported") }
        return OcspNode(tag: t.tag, hdr: off, start: t.start, end: t.end)
    }

    static func kids(_ b: [UInt8], _ n: OcspNode) throws -> [OcspNode] {
        var out: [OcspNode] = []
        var p = n.start
        while p < n.end {
            let k = try readNode(b, p, n.end)
            out.append(k)
            p = k.end
        }
        return out
    }

    static func oid(_ b: [UInt8], _ n: OcspNode) throws -> String {
        if n.tag != 0x06 { throw AttestError("expected an OBJECT IDENTIFIER") }
        do { return try DER.oidToDotted(b, DerTlv(tag: n.tag, start: n.start, end: n.end)) } catch { throw AttestError("asn1: syntax error: invalid object identifier") }
    }

    /// A DER time in range (no roll-over): epoch ms, or nil.
    static func timeMs(_ text: [UInt8], _ utc: Bool) -> Int64? {
        func digits(_ a: Int, _ n: Int) -> Int? {
            if a + n > text.count { return nil }
            var v = 0
            for i in a..<(a + n) {
                guard text[i] >= 0x30 && text[i] <= 0x39 else { return nil }
                v = v * 10 + Int(text[i] - 0x30)
            }
            return v
        }
        var y: Int, p: Int
        if utc {
            guard text.count == 13, let yy = digits(0, 2) else { return nil }
            y = yy < 50 ? 2000 + yy : 1900 + yy
            p = 2
        } else {
            guard text.count >= 15, let yy = digits(0, 4) else { return nil }
            y = yy
            p = 4
        }
        guard let mo = digits(p, 2), let d = digits(p + 2, 2), let h = digits(p + 4, 2), let mi = digits(p + 6, 2), let s = digits(p + 8, 2) else { return nil }
        p += 10
        var fracMs: Int64 = 0
        if !utc && p < text.count && text[p] == 0x2e {
            p += 1
            var fd: [UInt8] = []
            while p < text.count && text[p] >= 0x30 && text[p] <= 0x39 {
                fd.append(text[p])
                p += 1
            }
            if fd.isEmpty || fd.last == 0x30 { return nil }
            var frac = 0
            for digit in (fd + [0x30, 0x30, 0x30]).prefix(3) { frac = frac * 10 + Int(digit - 0x30) }
            fracMs = Int64(frac)
        }
        if p != text.count - 1 || text[p] != 0x5a { return nil }
        guard let base = DER.epochMs(y, mo, d, h, mi, s) else { return nil }
        return base + fracMs
    }

    /// Every UTCTime / GeneralizedTime in the structure must be a well-formed DER time.
    static func timesWellFormed(_ b: [UInt8], _ n: OcspNode) -> Bool {
        if n.constructed {
            guard let ks = try? kids(b, n) else { return false }
            return ks.allSatisfy { timesWellFormed(b, $0) }
        }
        if n.tag == 0x17 || n.tag == 0x18 { return timeMs(Array(b[n.start..<n.end]), n.tag == 0x17) != nil }
        return true
    }

    static func stripLeading0(_ b: [UInt8]) -> [UInt8] {
        var i = 0
        while i < b.count - 1 && b[i] == 0 { i += 1 }
        return Array(b[i...])
    }

    /// The subjectPublicKey BIT STRING content of a certificate (without the unused-bits octet).
    static func spkiKeyBits(_ c: AttCert) throws -> [UInt8] {
        let spki = try Cert.readElem(c.rawSPKI, 0, c.rawSPKI.count, 0x30)
        let ks = try Cert.kids(c.rawSPKI, spki)
        if ks.count != 2 || ks[1].end - ks[1].start < 1 { throw AttestError("malformed SubjectPublicKeyInfo") }
        return Array(c.rawSPKI[(ks[1].start + 1)..<ks[1].end])
    }

    static func sigOK(_ alg: String, _ tbs: [UInt8], _ sig: [UInt8], _ k: CertKey) -> Bool {
        guard let a = SIG_ALGS[alg] else { return false }
        switch k.typ {
        case "ec": return a.ec && ACrypto.ecVerify(curve: k.ecName, point: k.point, hash: a.hash, message: tbs, der: sig)
        case "rsa", "rsa-pss": return !a.ec && ACrypto.rsaVerifyPKCS1(n: k.rsaN, e: k.rsaE, hash: a.hash, message: tbs, sig: sig)
        default: return false
        }
    }

    static func fail(_ r: String) -> OcspResult { OcspResult(reason: r) }

    /// One DER OCSPResponse for `cert` (issued by `issuer`); malformation is a failure, never a trap.
    static func verifyResponse(_ der: [UInt8], _ cert: AttCert, _ issuer: AttCert, _ chain: [AttCert], _ nowMs: Int64) -> OcspResult {
        do { return try verifyInner(der, cert, issuer, chain, nowMs) } catch { return fail("OCSP response rejected: " + ((error as? AttestError)?.message ?? "invalid")) }
    }

    struct Single {
        var status: OcspNode
        var thisUpdate: Int64
        var nextUpdate: Int64 = 0
        var hasNext = false
    }

    static func verifyInner(_ der: [UInt8], _ cert: AttCert, _ issuer: AttCert, _ chain: [AttCert], _ nowMs: Int64) throws -> OcspResult {
        guard let top = try? readNode(der, 0, der.count) else { return fail("response is not valid DER") }
        if top.end != der.count { return fail("trailing bytes after OCSPResponse") }
        if top.tag != 0x30 { throw AttestError("OCSPResponse is not a SEQUENCE") }
        guard let tk = try? kids(der, top), !tk.isEmpty, tk[0].tag == 0x0a, tk[0].end - tk[0].start == 1 else { throw AttestError("malformed OCSPResponse") }
        let status = Int(der[tk[0].start])
        if status != 0 { return fail("OCSP responseStatus is \(status) (not successful)") }
        if tk.count < 2 || tk[1].tag != 0xa0 { return fail("successful response carries no responseBytes") }
        guard let rbWrap = try? kids(der, tk[1]), rbWrap.count == 1, rbWrap[0].tag == 0x30 else { throw AttestError("malformed responseBytes") }
        guard let rb = try? kids(der, rbWrap[0]), rb.count == 2, rb[1].tag == 0x04 else { throw AttestError("malformed responseBytes") }
        let rtype = try oid(der, rb[0])
        if rtype != OID_BASIC { return fail("responseType is not id-pkix-ocsp-basic") }
        let basic = Array(der[rb[1].start..<rb[1].end])
        guard let bn = try? readNode(basic, 0, basic.count) else { return fail("BasicOCSPResponse is not valid DER") }
        if bn.tag != 0x30 { throw AttestError("BasicOCSPResponse is not a SEQUENCE") }
        guard let bk = try? kids(basic, bn), bk.count >= 3, bk[0].tag == 0x30, bk[1].tag == 0x30, bk[2].tag == 0x03 else { throw AttestError("malformed BasicOCSPResponse") }
        if !timesWellFormed(basic, bn) { return fail("response carries a malformed (out-of-range) ASN.1 time") }
        let tbsNode = bk[0]
        let tbsBytes = Array(basic[tbsNode.hdr..<tbsNode.end])
        guard let algKids = try? kids(basic, bk[1]), !algKids.isEmpty else { throw AttestError("malformed signatureAlgorithm") }
        let sigAlg = try oid(basic, algKids[0])
        if SIG_ALGS[sigAlg] == nil { return fail("unsupported OCSP signature algorithm " + sigAlg) }
        if bk[2].end - bk[2].start < 1 { throw AttestError("malformed signature") }
        let sig = Array(basic[(bk[2].start + 1)..<bk[2].end])

        // ResponseData: [0] version?, responderID, producedAt, responses, [1] extensions?
        let rd = try kids(basic, tbsNode)
        var ri = 0
        if ri < rd.count && rd[ri].tag == 0xa0 { ri += 1 }
        if ri + 3 > rd.count { throw AttestError("malformed ResponseData") }
        let rid = rd[ri], produced = rd[ri + 1], responses = rd[ri + 2]
        if produced.tag != 0x18 || responses.tag != 0x30 || (rid.tag != 0xa1 && rid.tag != 0xa2) { throw AttestError("malformed ResponseData") }
        let producedAt = timeMs(Array(basic[produced.start..<produced.end]), false) ?? 0

        let subjectSerial = stripLeading0(cert.serial)
        let issuerKeyBits = try spkiKeyBits(issuer)
        let singles = try kids(basic, responses)
        var matches: [Single] = []
        for s in singles {
            guard let sk = try? kids(basic, s), sk.count >= 3, sk[0].tag == 0x30, sk[2].tag == 0x18 else { throw AttestError("malformed SingleResponse") }
            guard let cid = try? kids(basic, sk[0]), cid.count == 4, cid[0].tag == 0x30, cid[1].tag == 0x04, cid[2].tag == 0x04, cid[3].tag == 0x02 else {
                throw AttestError("malformed CertID")
            }
            guard let hk = try? kids(basic, cid[0]), !hk.isEmpty else { throw AttestError("malformed CertID hash algorithm") }
            let hoid = try oid(basic, hk[0])
            guard let h = CERT_ID_HASHES[hoid] else { continue }
            let wantName = h.digest(issuer.rawSubject)
            let wantKey = h.digest(issuerKeyBits)
            if stripLeading0(Array(basic[cid[3].start..<cid[3].end])) != subjectSerial || Array(basic[cid[1].start..<cid[1].end]) != wantName
                || Array(basic[cid[2].start..<cid[2].end]) != wantKey { continue }
            let tu = timeMs(Array(basic[sk[2].start..<sk[2].end]), false) ?? 0
            var m = Single(status: sk[1], thisUpdate: tu)
            if sk.count > 3 && sk[3].tag == 0xa0, let nk = try? kids(basic, sk[3]), nk.count == 1, nk[0].tag == 0x18 {
                m.nextUpdate = timeMs(Array(basic[nk[0].start..<nk[0].end]), false) ?? 0
                m.hasNext = true
            }
            matches.append(m)
        }
        if matches.isEmpty { return fail("no SingleResponse matches the certificate (serial / issuer hashes differ)") }
        if matches.count > 1 { return fail("ambiguous: multiple SingleResponses match the certificate") }
        let one = matches[0]

        // responder authentication
        let issuerKey = try Cert.keyOf(issuer)
        guard let ridInner = try? kids(basic, rid), ridInner.count == 1 else { throw AttestError("malformed responderID") }
        let rIn = ridInner[0]
        func matchesResponder(_ c: AttCert) -> Bool {
            if rid.tag == 0xa1 { return rIn.tag == 0x30 && Array(basic[rIn.hdr..<rIn.end]) == c.rawSubject }
            guard let bits = try? spkiKeyBits(c), rIn.tag == 0x04 else { return false }
            return Array(basic[rIn.start..<rIn.end]) == AHash.sha1.digest(bits)
        }
        let isIssuerID = matchesResponder(issuer)
        if !(isIssuerID && sigOK(sigAlg, tbsBytes, sig, issuerKey)) {
            var embedded: [AttCert] = []
            if bk.count > 3 && bk[3].tag == 0xa0, let wrap = try? kids(basic, bk[3]), wrap.count == 1, let cs = try? kids(basic, wrap[0]) {
                for c in cs { if let x = try? Cert.parseDER(Array(basic[c.hdr..<c.end])) { embedded.append(x) } }
            }
            var why = "no embedded responder certificate verifies the response"
            var found = false
            for cand in embedded {
                if !matchesResponder(cand) {
                    why = "embedded certificates do not match the responderID"
                    continue
                }
                if !Cert.hasOCSPSigningEKU(cand) {
                    why = "delegated responder certificate lacks the id-kp-OCSPSigning EKU"
                    continue
                }
                let (from, to) = DER.derValidity(cand.raw)
                guard let f = from, let t = to, f <= nowMs && nowMs <= t else {
                    why = "delegated responder certificate is outside its validity window"
                    continue
                }
                var signers = [issuer]
                if let i = chain.firstIndex(where: { $0.raw == issuer.raw }) { signers = Array(chain[i...]) }
                var okSigner = false
                for s in signers where cand.rawIssuer == s.rawSubject && Cert.sigOKBy(cand, s) { okSigner = true }
                if !okSigner {
                    why = "delegated responder certificate is not signed by the supplied NVIDIA chain"
                    continue
                }
                guard let ck = try? Cert.keyOf(cand), sigOK(sigAlg, tbsBytes, sig, ck) else {
                    why = "OCSP response signature does not verify under the delegated responder key"
                    continue
                }
                found = true
                break
            }
            if !found {
                if isIssuerID { return fail("OCSP response signature does not verify under the issuer key") }
                return fail(why)
            }
        }

        // freshness
        if one.thisUpdate > nowMs { return fail("response thisUpdate is in the future") }
        if producedAt > nowMs { return fail("response producedAt is in the future") }
        if one.hasNext {
            if one.nextUpdate < one.thisUpdate { return fail("response nextUpdate is invalid") }
            if nowMs > one.nextUpdate { return fail("response is stale (past nextUpdate)") }
        }
        if nowMs - one.thisUpdate > DEFAULT_MAX_MS { return fail("response is older than the maximum accepted age") }

        // certStatus: CHOICE [0] good, [1] revoked, [2] unknown
        let st = one.status
        if st.tag & 0xc0 != 0x80 { return fail("malformed certStatus") }
        switch st.tag & 0x1f {
        case 0: return OcspResult(ok: true, reason: "", status: "good")
        case 2: return OcspResult(ok: true, reason: "", status: "unknown")
        case 1:
            guard let items = try? kids(basic, st), items.count >= 1, isRevTime(Array(basic[items[0].start..<items[0].end])) else { return fail("malformed revoked certStatus") }
            return OcspResult(ok: true, reason: "", status: "revoked")
        default: return fail("unrecognised certStatus")
        }
    }

    /// `^[0-9]{14}Z$`
    static func isRevTime(_ t: [UInt8]) -> Bool { t.count == 15 && t[14] == 0x5a && t[0..<14].allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }

    /// The device chain with OCSP responses: every response must verify for exactly one chain certificate, any REVOKED fails, and
    /// every certificate that advertises an OCSP responder must have a GOOD response.
    static func checkChain(_ chain: [AttCert], _ responses: [[UInt8]], _ nowMs: Int64) -> String {
        if chain.count < 2 { return "chain too short for OCSP" }
        if responses.isEmpty { return "no OCSP responses supplied" }
        let last = chain.count - 1
        var required = Set<Int>()
        for i in 0..<last where !Cert.ocspServers(chain[i]).isEmpty { required.insert(i) }
        var statuses: [Int: String] = [:]
        for i in 0..<last { statuses[i] = "absent" }
        for (ri, der) in responses.enumerated() {
            var matched = false
            var lastReason = "matches no chain certificate"
            for i in 0..<last {
                let r = verifyResponse(der, chain[i], chain[i + 1], chain, nowMs)
                if !r.ok {
                    if !r.reason.hasPrefix("no SingleResponse matches") { return "OCSP response #\(ri) for '\(Nvidia.subjectLine(chain[i]))' rejected: \(r.reason)" }
                    lastReason = r.reason
                    continue
                }
                if matched { return "OCSP response #\(ri) matches more than one chain certificate" }
                matched = true
                if statuses[i] != "absent" { return "duplicate OCSP responses for chain certificate #\(i)" }
                statuses[i] = r.status
                if r.status == "revoked" { return "chain certificate '\(Nvidia.subjectLine(chain[i]))' is revoked (OCSP)" }
            }
            if !matched { return "OCSP response #\(ri) rejected: \(lastReason)" }
        }
        for i in 0..<last where required.contains(i) && statuses[i] != "good" {
            return "no GOOD OCSP response for required certificate '\(Nvidia.subjectLine(chain[i]))' (status: \(statuses[i] ?? "absent"))"
        }
        return ""
    }
}
