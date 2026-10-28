import Foundation

// Intel PCS collateral for the genuine DCAP TDX quote path: signed TCB info and QE identity (ECDSA-P256 over the exact bytes of the
// signed value, under the TCB Signing certificate whose issuer chain ends at the pinned Intel SGX Root CA), the PCK and Root CA
// CRLs, the evaluated TCB status and a status policy. Offline given the collateral bytes; fails closed on missing, stale,
// malformed, unsigned or revoked collateral. The CRL reader is shared with the NVIDIA CRL checks.

struct CollateralPolicy {
    var acceptStatuses: [String] = []
    var hasAccept = false
    var minEval = 0.0
    var hasMinEval = false
}

struct CollateralResult {
    var ok = false
    var reason = ""
    var status = ""
    var advisoryIDs: [String] = []
}

struct IntelCollateral {
    var tcbInfoJSON = "", tcbInfoChain = "", qeIdentityJSON = "", qeIdentityChain = ""
    var pckCrl: [UInt8] = []
    var rootCrl: [UInt8] = []

    static let TCB_STATUS_ORDER = ["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded", "ConfigurationAndSWHardeningNeeded", "OutOfDateConfigurationNeeded", "OutOfDate", "Revoked"]
    static let DEFAULT_ACCEPTED = ["UpToDate", "SWHardeningNeeded"]

    static func fromWire(_ m: JObject) -> IntelCollateral {
        func s(_ k: String) -> String { m[JKey(k)]?.asString ?? "" }
        var c = IntelCollateral(tcbInfoJSON: s("tcbInfoJson"), tcbInfoChain: s("tcbInfoIssuerChainPem"), qeIdentityJSON: s("qeIdentityJson"), qeIdentityChain: s("qeIdentityIssuerChainPem"))
        c.pckCrl = Attest.evBytes(m, "pckCrlDer") ?? []
        c.rootCrl = Attest.evBytes(m, "rootCrlDer") ?? []
        return c
    }

    static func msg(_ e: Error) -> String { (e as? AttestError)?.message ?? "invalid" }

    // ---- CRL reading (lenient lengths, as the reference) ----

    static func tlvLenient(_ b: [UInt8], _ off: Int, _ limit: Int) throws -> DerTlv {
        if off + 2 > limit { throw AttestError("DER truncated") }
        let tag = b[off]
        var l = Int(b[off + 1])
        var p = off + 2
        if l & 0x80 != 0 {
            let n = l & 0x7f
            if n == 0 || n > 4 || p + n > limit { throw AttestError("DER bad length") }
            l = 0
            for i in 0..<n { l = l * 256 + Int(b[p + i]) }
            p += n
        }
        if p + l > limit { throw AttestError("DER overrun") }
        return DerTlv(tag: tag, start: p, end: p + l)
    }

    static func daysFromCivil(_ y: Int, _ m: Int, _ d: Int) -> Int64 {
        let yy = Int64(m <= 2 ? y - 1 : y)
        let era = (yy >= 0 ? yy : yy - 399) / 400
        let yoe = yy - era * 400
        let mp = Int64((m + 9) % 12)
        let doy = (153 * mp + 2) / 5 + Int64(d) - 1
        return era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
    }

    /// Date.UTC: fields roll over; a year 0..99 means 19YY.
    static func dateUTC(_ y0: Int, _ mo: Int, _ d: Int, _ h: Int, _ mi: Int, _ s: Int) -> Int64 {
        var y = y0
        if y >= 0 && y <= 99 { y += 1900 }
        let m0 = mo - 1
        let yAdj = y + (m0 >= 0 ? m0 / 12 : -((11 - m0) / 12))
        let mAdj = ((m0 % 12) + 12) % 12 + 1
        let days = daysFromCivil(yAdj, mAdj, 1) + Int64(d - 1)
        return (days * 86_400 + Int64(h) * 3_600 + Int64(mi) * 60 + Int64(s)) * 1000
    }

    static func digits(_ u: ArraySlice<UInt8>) -> Bool { u.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }

    static func crlTime(_ b: [UInt8], _ t: DerTlv) throws -> Int64 {
        let s = Array(b[t.start..<t.end])
        func n(_ a: Int, _ c: Int) -> Int { s[a..<c].reduce(0) { $0 * 10 + Int($1 - 0x30) } }
        switch t.tag {
        case 0x17:
            guard s.count == 13, digits(s[0..<12]), s[12] == 0x5a else { throw AttestError("bad UTCTime") }
            let yy = n(0, 2)
            return dateUTC(yy >= 50 ? 1900 + yy : 2000 + yy, n(2, 4), n(4, 6), n(6, 8), n(8, 10), n(10, 12))
        case 0x18:
            guard s.count == 15, digits(s[0..<14]), s[14] == 0x5a else { throw AttestError("bad GeneralizedTime") }
            return dateUTC(n(0, 4), n(4, 6), n(6, 8), n(8, 10), n(10, 12), n(12, 14))
        default: throw AttestError("not a DER time")
        }
    }

    struct ParsedCRL {
        var tbs: [UInt8] = []
        var thisUpdate: Int64 = 0
        var nextUpdate: Int64 = 0
        var hasNext = false
        var revoked = Set<String>()
        var sigDer: [UInt8] = []
    }

    static func normSerial(_ s: String) -> String { String(s.lowercased().drop { $0 == "0" }) }

    static func parseCRL(_ der: [UInt8]) throws -> ParsedCRL {
        let outer = try tlvLenient(der, 0, der.count)
        if outer.tag != 0x30 || outer.end != der.count { throw AttestError("CRL: bad outer SEQUENCE") }
        let tbsT = try tlvLenient(der, outer.start, outer.end)
        if tbsT.tag != 0x30 { throw AttestError("CRL: bad TBSCertList") }
        var crl = ParsedCRL()
        crl.tbs = Array(der[outer.start..<tbsT.end])
        let algT = try tlvLenient(der, tbsT.end, outer.end)
        let sigT = try tlvLenient(der, algT.end, outer.end)
        if sigT.tag != 0x03 || sigT.end != outer.end { throw AttestError("CRL: bad signature") }
        if sigT.start + 1 <= sigT.end { crl.sigDer = Array(der[(sigT.start + 1)..<sigT.end]) }
        var p = tbsT.start
        var t = try tlvLenient(der, p, tbsT.end)
        if t.tag == 0x02 {
            p = t.end
            t = try tlvLenient(der, p, tbsT.end)
        }
        p = t.end // signature AlgorithmIdentifier
        let iss = try tlvLenient(der, p, tbsT.end)
        if iss.tag != 0x30 { throw AttestError("CRL: bad issuer") }
        let tu = try tlvLenient(der, iss.end, tbsT.end)
        crl.thisUpdate = try crlTime(der, tu)
        var q = tu.end
        if q < tbsT.end {
            var n = try tlvLenient(der, q, tbsT.end)
            if n.tag == 0x17 || n.tag == 0x18 {
                crl.nextUpdate = try crlTime(der, n)
                crl.hasNext = true
                q = n.end
            }
            if q < tbsT.end {
                n = try tlvLenient(der, q, tbsT.end)
                if n.tag == 0x30 {
                    var e = n.start
                    while e < n.end {
                        let ent = try tlvLenient(der, e, n.end)
                        let ser = try tlvLenient(der, ent.start, ent.end)
                        if ser.tag != 0x02 { throw AttestError("CRL: bad revoked entry") }
                        crl.revoked.insert(normSerial(ACrypto.hex(Array(der[ser.start..<ser.end]))))
                        e = ent.end
                    }
                }
            }
        }
        if !crl.hasNext { throw AttestError("CRL: missing nextUpdate") }
        return crl
    }

    /// verify('sha256', tbs, issuerKey, sig): ECDSA (DER) or RSA PKCS#1 v1.5 under the issuer key.
    static func crlSigOK(_ tbs: [UInt8], _ sig: [UInt8], _ k: CertKey) -> Bool {
        switch k.typ {
        case "ec": return ACrypto.ecVerify(curve: k.ecName, point: k.point, hash: .sha256, message: tbs, der: sig)
        case "rsa", "rsa-pss": return ACrypto.rsaVerifyPKCS1(n: k.rsaN, e: k.rsaE, hash: .sha256, message: tbs, sig: sig)
        default: return false
        }
    }

    /// A DER CRL under the issuer key at nowMs. The revoked serials (lowercase hex, no leading zeros), or the reason.
    static func verifyCRL(_ der: [UInt8], _ issuer: CertKey, _ nowMs: Int64) -> (Set<String>?, String) {
        let crl: ParsedCRL
        do { crl = try parseCRL(der) } catch { return (nil, "CRL parse failed: " + msg(error)) }
        if !crlSigOK(crl.tbs, crl.sigDer, issuer) { return (nil, "CRL signature does not verify under the issuer") }
        if nowMs < crl.thisUpdate { return (nil, "CRL thisUpdate is in the future") }
        if nowMs > crl.nextUpdate { return (nil, "CRL is stale (nextUpdate passed)") }
        return (crl.revoked, "")
    }

    // ---- signed JSON documents ----

    /// Skips JS whitespace (including the multibyte spaces) from byte offset `i`.
    static func skipJSSpace(_ s: [UInt8], _ i0: Int) -> Int {
        var i = i0
        while i < s.count {
            let b = s[i]
            if b < 0x80 {
                if b == 0x09 || b == 0x0a || b == 0x0b || b == 0x0c || b == 0x0d || b == 0x20 { i += 1; continue }
                break
            }
            let n = b >= 0xf0 ? 4 : (b >= 0xe0 ? 3 : (b >= 0xc0 ? 2 : 1))
            if i + n > s.count { break }
            let text = String(decoding: s[i..<(i + n)], as: UTF8.self)
            guard let u = text.unicodeScalars.first, text.unicodeScalars.count == 1, Attest.isJSSpace(u) else { break }
            i += n
        }
        return i
    }

    /// The exact source text of the JSON object following `"<name>":` in a top-level object.
    static func rawJSONObject(_ text: [UInt8], _ name: String) -> [UInt8]? {
        var i = skipJSSpace(text, 0)
        if i >= text.count || text[i] != 0x7b { return nil }
        i = skipJSSpace(text, i + 1)
        let key = Array(("\"" + name + "\"").utf8)
        if i + key.count > text.count || Array(text[i..<(i + key.count)]) != key { return nil }
        i = skipJSSpace(text, i + key.count)
        if i >= text.count || text[i] != 0x3a { return nil }
        i = skipJSSpace(text, i + 1)
        if i >= text.count || text[i] != 0x7b { return nil }
        let start = i
        var depth = 0
        var inStr = false
        while i < text.count {
            let ch = text[i]
            if inStr {
                if ch == 0x5c { i += 1 } else if ch == 0x22 { inStr = false }
            } else if ch == 0x22 {
                inStr = true
            } else if ch == 0x7b {
                depth += 1
            } else if ch == 0x7d {
                depth -= 1
                if depth == 0 { return Array(text[start...i]) }
            }
            i += 1
        }
        return nil
    }

    /// A PCS document: the body under `name`, or the failure text.
    static func verifySignedJSON(_ text: String, _ name: String, _ k: CertKey) -> (JObject?, String) {
        let bytes = Array(text.utf8)
        guard let raw = rawJSONObject(bytes, name) else { return (nil, name + " not found / malformed") }
        guard let doc = Attest.jsonLenient(bytes) else { return (nil, name + " document is not valid JSON") }
        let top = doc.asObject ?? [:]
        let sig = top["signature"]?.asString ?? ""
        guard sig.utf8.count == 128, let sigBytes = ACrypto.unhex(sig) else { return (nil, name + " signature missing or malformed") }
        if k.typ != "ec" || !ACrypto.ecVerify(curve: k.ecName, point: k.point, hash: .sha256, message: raw, raw: sigBytes) {
            return (nil, name + " signature does not verify under the TCB Signing certificate")
        }
        guard let body = top[JKey(name)]?.asObject else { return (nil, name + " is not an object") }
        return (body, "")
    }

    /// Date.parse for the ISO-8601 forms PCS documents use (epoch ms), nil otherwise.
    static func jsDateParse(_ s: String) -> Int64? {
        let u = Array(s.utf8)
        func num(_ a: Int, _ n: Int) -> Int? {
            if a + n > u.count { return nil }
            var v = 0
            for i in a..<(a + n) {
                guard u[i] >= 0x30 && u[i] <= 0x39 else { return nil }
                v = v * 10 + Int(u[i] - 0x30)
            }
            return v
        }
        guard u.count >= 10, let y = num(0, 4), u[4] == 0x2d, let mo = num(5, 2), u[7] == 0x2d, let d = num(8, 2) else { return nil }
        guard let base = DER.epochMs(y, mo, d, 0, 0, 0) else { return nil }
        if u.count == 10 { return base }
        guard u[10] == 0x54, let h = num(11, 2), u[13] == 0x3a, let mi = num(14, 2) else { return nil }
        var pos = 16
        var sec = 0
        var fracMs = 0
        if pos < u.count && u[pos] == 0x3a {
            guard let ss = num(pos + 1, 2) else { return nil }
            sec = ss
            pos += 3
            if pos < u.count && u[pos] == 0x2e {
                pos += 1
                var digits: [UInt8] = []
                while pos < u.count && u[pos] >= 0x30 && u[pos] <= 0x39 {
                    digits.append(u[pos])
                    pos += 1
                }
                if digits.isEmpty { return nil }
                let three = Array((digits + [0x30, 0x30, 0x30]).prefix(3))
                fracMs = three.reduce(0) { $0 * 10 + Int($1 - 0x30) }
            }
        }
        guard let t = DER.epochMs(y, mo, d, h, mi, sec) else { return nil }
        var offsetMs: Int64 = 0
        if pos == u.count - 1 && u[pos] == 0x5a {
            // UTC
        } else if pos == u.count - 6 && (u[pos] == 0x2b || u[pos] == 0x2d), let oh = num(pos + 1, 2), u[pos + 3] == 0x3a, let om = num(pos + 4, 2) {
            offsetMs = Int64(oh * 3600 + om * 60) * 1000 * (u[pos] == 0x2d ? -1 : 1)
        } else {
            return nil
        }
        return t + Int64(fracMs) - offsetMs
    }

    static func checkFresh(_ body: JObject, _ what: String, _ nowMs: Int64) -> String {
        guard let is0 = body["issueDate"]?.asString, let ns = body["nextUpdate"]?.asString, let issue = jsDateParse(is0), let next = jsDateParse(ns) else {
            return what + ": issueDate/nextUpdate missing"
        }
        if nowMs < issue { return what + ": issueDate is in the future" }
        if nowMs > next { return what + ": stale (nextUpdate passed)" }
        return ""
    }

    // ---- status evaluation ----

    static func statusRank(_ s: String) -> Int { TCB_STATUS_ORDER.firstIndex(of: s) ?? -1 }

    static func asTcbStatus(_ v: JSONValue?) -> String? {
        guard let s = v?.asString, statusRank(s) >= 0 else { return nil }
        return s
    }

    static func worstStatus(_ a: String, _ b: String) -> String { statusRank(a) >= statusRank(b) ? a : b }

    static func svnList(_ v: JSONValue?) -> [Double]? {
        guard case let .array(arr)? = v, arr.count == 16 else { return nil }
        var out: [Double] = []
        for c in arr {
            guard case let .object(rec) = c, let f = Attest.asFinite(rec["svn"]) else { return nil }
            out.append(f)
        }
        return out
    }

    static func hexBytesN(_ v: JSONValue?, _ n: Int) -> [UInt8]? {
        guard let s = v?.asString, s.utf8.count == n * 2 else { return nil }
        return ACrypto.unhex(s)
    }

    static func advisoryList(_ level: JObject) -> [String] {
        guard case let .array(arr)? = level["advisoryIDs"] else { return [] }
        return arr.compactMap { $0.asString }
    }

    static func maskedEq(_ value: [UInt8], _ mask: [UInt8], _ expected: [UInt8]) -> Bool {
        for i in 0..<value.count where (value[i] & mask[i]) ^ (expected[i] & mask[i]) != 0 { return false }
        return true
    }

    /// levels.find(l => isRecord(l) && isRecord(l.tcb) && typeof l.tcb.isvsvn === 'number' && l.tcb.isvsvn <= svn).
    static func findLevel(_ levels: JSONValue?, _ svn: Double) -> JObject? {
        guard case let .array(arr)? = levels else { return nil }
        for x in arr {
            guard case let .object(l) = x, case let .object(tcb)? = l["tcb"], let f = Attest.asFinite(tcb["isvsvn"]), f <= svn else { continue }
            return l
        }
        return nil
    }

    struct TcbEval {
        var platform = "", module = ""
        var advisories: [String] = []
        var err = ""
    }

    static func evaluateTcb(_ info: JObject, _ pckSgx: [UInt8], _ pckPcesvn: Int, _ teeTcbSvn: [UInt8], _ mrSignerSeam: [UInt8], _ seamAttributes: [UInt8]) -> TcbEval {
        func err(_ m: String) -> TcbEval { TcbEval(err: m) }
        let levels = info["tcbLevels"]?.asArray ?? []
        if levels.isEmpty { return err("TCB info has no tcbLevels") }
        let minor = teeTcbSvn[1]
        var moduleStatus = "UpToDate"
        var adv = Set<String>()
        var modMrSigner: JSONValue?, modAttr: JSONValue?, modMask: JSONValue?
        if minor > 0 {
            let id = "TDX_" + String(format: "%02X", UInt32(minor))
            var ident: JObject?
            if let ids = info["tdxModuleIdentities"]?.asArray {
                for x in ids {
                    if case let .object(r) = x, r["id"]?.asString == id {
                        ident = r
                        break
                    }
                }
            }
            guard let identity = ident else { return err("TDX module identity \(id) not present in TCB info") }
            modMrSigner = identity["mrsigner"]
            modAttr = identity["attributes"]
            modMask = identity["attributesMask"]
            guard let hit = findLevel(identity["tcbLevels"], Double(teeTcbSvn[0])) else { return err("TDX module \(id) SVN \(teeTcbSvn[0]) is below every known level") }
            guard let st = asTcbStatus(hit["tcbStatus"]) else { return err("TDX module level has an unknown tcbStatus") }
            moduleStatus = st
            for a in advisoryList(hit) { adv.insert(a) }
        } else {
            guard case let .object(m)? = info["tdxModule"] else { return err("TCB info missing tdxModule") }
            modMrSigner = m["mrsigner"]
            modAttr = m["attributes"]
            modMask = m["attributesMask"]
        }
        guard let exMr = hexBytesN(modMrSigner, 48), let exAttr = hexBytesN(modAttr, 8), let mask = hexBytesN(modMask, 8) else { return err("TDX module identity fields malformed") }
        if exMr != mrSignerSeam { return err("TD report MRSIGNERSEAM does not match the TDX module identity") }
        if !maskedEq(seamAttributes, mask, exAttr) { return err("TD report SEAM attributes do not match the TDX module identity") }
        let from = minor > 0 ? 2 : 0
        for x in levels {
            guard case let .object(l) = x, case let .object(tcb)? = l["tcb"] else { return err("malformed TCB level") }
            guard let sgx = svnList(tcb["sgxtcbcomponents"]), let tdx = svnList(tcb["tdxtcbcomponents"]), let pce = Attest.asFinite(tcb["pcesvn"]) else {
                return err("malformed TCB level components")
            }
            guard let st = asTcbStatus(l["tcbStatus"]) else { return err("TCB level has an unknown tcbStatus") }
            var match = Double(pckPcesvn) >= pce
            var i = 0
            while match && i < 16 {
                if Double(pckSgx[i]) < sgx[i] { match = false }
                i += 1
            }
            i = from
            while match && i < 16 {
                if Double(teeTcbSvn[i]) < tdx[i] { match = false }
                i += 1
            }
            if !match { continue }
            for a in advisoryList(l) { adv.insert(a) }
            return TcbEval(platform: st, module: moduleStatus, advisories: adv.sorted { IV.utf8Less($0, $1) }, err: "")
        }
        return err("platform TCB is below every level in the TCB info")
    }

    struct QeEval {
        var status = ""
        var advisories: [String] = []
        var err = ""
    }

    static func evaluateQe(_ ident: JObject, _ qe: [UInt8]) -> QeEval {
        func err(_ m: String) -> QeEval { QeEval(err: m) }
        if ident["id"]?.asString != "TD_QE" { return err("QE identity id is not TD_QE") }
        guard let v = Attest.asFinite(ident["version"]), v == 2 else { return err("unsupported QE identity version") }
        guard let miscsel = hexBytesN(ident["miscselect"], 4), let miscMask = hexBytesN(ident["miscselectMask"], 4), let attr = hexBytesN(ident["attributes"], 16),
              let attrMask = hexBytesN(ident["attributesMask"], 16), let mrsigner = hexBytesN(ident["mrsigner"], 32), let prodID = Attest.asFinite(ident["isvprodid"]) else {
            return err("QE identity fields malformed")
        }
        if qe.count != 384 { return err("QE report has wrong length") }
        if !maskedEq(Array(qe[16..<20]), miscMask, miscsel) { return err("QE MISCSELECT does not match the QE identity") }
        if !maskedEq(Array(qe[48..<64]), attrMask, attr) { return err("QE ATTRIBUTES do not match the QE identity") }
        if Array(qe[128..<160]) != mrsigner { return err("QE MRSIGNER does not match the QE identity") }
        let prod = Int(qe[256]) | Int(qe[257]) << 8
        let isvsvn = Int(qe[258]) | Int(qe[259]) << 8
        if Double(prod) != prodID { return err("QE ISVPRODID does not match the QE identity") }
        guard let hit = findLevel(ident["tcbLevels"], Double(isvsvn)) else { return err("QE ISVSVN is below every known level") }
        guard let st = asTcbStatus(hit["tcbStatus"]) else { return err("QE level has an unknown tcbStatus") }
        return QeEval(status: st, advisories: advisoryList(hit), err: "")
    }

    /// A PCS issuer chain (leaf first) to the pinned root, validity at nowMs and that no certificate is on the Root CA CRL. The
    /// leaf's key, or the failure text.
    static func signerKeyFromChain(_ chainPem: String, _ pin: String, _ nowMs: Int64, _ rootRevoked: Set<String>) -> (CertKey?, String) {
        let chain = DcapVerifier.verifyPckChain(chainPem, pin, nowMs)
        if chain.validity { return (nil, "issuer chain certificate outside its validity period") }
        guard chain.ok, let leaf = chain.leaf else { return (nil, "issuer chain invalid: " + chain.reason) }
        for b in Cert.pemBlocks(chainPem) {
            let c: AttCert
            do { c = try Cert.fromPEM(b) } catch { return (nil, "collateral verification error (fail closed): " + msg(error)) }
            if !DER.derValidAt(c.raw, nowMs, 0) { return (nil, "issuer chain certificate outside its validity period") }
            if rootRevoked.contains(Cert.serialHex(c)) { return (nil, "issuer chain certificate is revoked by the Intel Root CA CRL") }
        }
        do { return (try Cert.keyOf(leaf), "") } catch { return (nil, "collateral verification error (fail closed): " + msg(error)) }
    }

    /// Verifies the quote and then its PCS collateral at nowMs: the evaluated TCB status and the policy decision.
    static func verify(_ quote: [UInt8], _ c: IntelCollateral?, _ nowMs: Int64, _ pol: CollateralPolicy?, _ pin: String, _ allowDebug: Bool) -> CollateralResult {
        func fail(_ r: String) -> CollateralResult { CollateralResult(reason: r) }
        func thrown(_ e: Error) -> CollateralResult { fail("collateral verification error (fail closed): " + msg(e)) }
        guard let c = c, !c.tcbInfoJSON.isEmpty, !c.qeIdentityJSON.isEmpty, !c.pckCrl.isEmpty, !c.rootCrl.isEmpty, !c.tcbInfoChain.isEmpty, !c.qeIdentityChain.isEmpty else {
            return fail("collateral incomplete (fail closed)")
        }
        let base = DcapVerifier.verifyGenuineQuote(quote, pin, nowMs, nil, allowDebug)
        guard base.ok, let basePck = base.pck, !base.fmspc.isEmpty else { return fail("quote invalid: " + base.reason) }
        let q: DcapVerifier.Quote
        do { q = try DcapVerifier.parseQuote(quote) } catch { return thrown(error) }
        var quoteCerts: [AttCert] = []
        for b in Cert.pemBlocks(q.pckChainPem) {
            do { quoteCerts.append(try Cert.fromPEM(b)) } catch { return thrown(error) }
        }
        for x in quoteCerts where !DER.derValidAt(x.raw, nowMs, 0) { return fail("PCK chain certificate outside its validity period") }
        var leaf: AttCert?, ca: AttCert?, root: AttCert?
        for x in quoteCerts {
            if !quoteCerts.contains(where: { $0.rawIssuer == x.rawSubject }) {
                leaf = x
                break
            }
        }
        guard let leafCert = leaf else { return fail("PCK leaf not found") }
        for x in quoteCerts where x.rawSubject == leafCert.rawIssuer {
            ca = x
            break
        }
        guard let caCert = ca else { return fail("PCK CA not found in the quote chain") }
        for x in quoteCerts where Cert.selfIssued(x) {
            root = x
            break
        }
        guard let rootCert = root else { return fail("Intel root not found in the quote chain") }
        let rootKey: CertKey, caKey: CertKey
        do { rootKey = try Cert.keyOf(rootCert) } catch { return thrown(error) }
        do { caKey = try Cert.keyOf(caCert) } catch { return thrown(error) }
        let (rootRevokedOpt, why1) = verifyCRL(c.rootCrl, rootKey, nowMs)
        guard let rootRevoked = rootRevokedOpt else { return fail("Intel Root CA CRL: " + why1) }
        let (pckRevokedOpt, why2) = verifyCRL(c.pckCrl, caKey, nowMs)
        guard let pckRevoked = pckRevokedOpt else { return fail("PCK CRL: " + why2) }
        if rootRevoked.contains(Cert.serialHex(caCert)) { return fail("PCK CA certificate is revoked by the Intel Root CA CRL") }
        if pckRevoked.contains(Cert.serialHex(leafCert)) { return fail("PCK leaf certificate is revoked by the PCK CRL") }

        let (tcbKeyOpt, why3) = signerKeyFromChain(c.tcbInfoChain, pin, nowMs, rootRevoked)
        guard let tcbKey = tcbKeyOpt else { return fail("TCB info: " + why3) }
        let (infoOpt, why4) = verifySignedJSON(c.tcbInfoJSON, "tcbInfo", tcbKey)
        guard let info = infoOpt else { return fail("TCB info: " + why4) }
        let stale1 = checkFresh(info, "TCB info", nowMs)
        if !stale1.isEmpty { return fail(stale1) }
        if info["id"]?.asString != "TDX" { return fail("TCB info is not a TDX v3 document") }
        guard let ver = Attest.asFinite(info["version"]), ver == 3 else { return fail("TCB info is not a TDX v3 document") }
        guard let fm = info["fmspc"]?.asString, fm.lowercased() == base.fmspc else { return fail("TCB info FMSPC does not match the quote PCK") }

        let (qeKeyOpt, why5) = signerKeyFromChain(c.qeIdentityChain, pin, nowMs, rootRevoked)
        guard let qeKey = qeKeyOpt else { return fail("QE identity: " + why5) }
        let (qeBodyOpt, why6) = verifySignedJSON(c.qeIdentityJSON, "enclaveIdentity", qeKey)
        guard let qeBody = qeBodyOpt else { return fail("QE identity: " + why6) }
        let stale2 = checkFresh(qeBody, "QE identity", nowMs)
        if !stale2.isEmpty { return fail(stale2) }

        let infoNum = Attest.asFinite(info["tcbEvaluationDataNumber"]) ?? -1
        let qeNum = Attest.asFinite(qeBody["tcbEvaluationDataNumber"]) ?? -1
        if infoNum < 0 || qeNum < 0 { return fail("tcbEvaluationDataNumber missing") }
        if let p = pol, p.hasMinEval, infoNum < p.minEval || qeNum < p.minEval { return fail("tcbEvaluationDataNumber below policy minimum") }

        let body = q.tdReportBody
        let tcb = evaluateTcb(info, basePck.sgx, basePck.pcesvn, Array(body[0..<16]), Array(body[64..<112]), Array(body[112..<120]))
        if !tcb.err.isEmpty { return fail("TCB evaluation: " + tcb.err) }
        let qe = evaluateQe(qeBody, q.qeReportBody)
        if !qe.err.isEmpty { return fail("QE identity: " + qe.err) }
        let status = worstStatus(worstStatus(tcb.platform, tcb.module), qe.status)
        var seen = Set<String>()
        var ids: [String] = []
        for a in tcb.advisories + qe.advisories where !seen.contains(a) {
            seen.insert(a)
            ids.append(a)
        }
        ids.sort { IV.utf8Less($0, $1) }
        var res = CollateralResult(ok: false, reason: "", status: status, advisoryIDs: ids)
        let accepted = (pol?.hasAccept ?? false) ? (pol?.acceptStatuses ?? DEFAULT_ACCEPTED) : DEFAULT_ACCEPTED
        if !accepted.contains(status) {
            res.reason = "TCB status \(status) is not accepted by policy"
            return res
        }
        res.ok = true
        return res
    }
}
