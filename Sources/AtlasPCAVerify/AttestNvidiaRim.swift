import Foundation
import CryptoKit

// NVIDIA GPU-CC collateral: Reference Integrity Manifests (SWID/CoRIM XML, enveloped XMLDSig, strict profile), the golden
// measurement comparison with NVIDIA's merge / alternatives / NVDEC0 rules, the driver / VBIOS version binding, certificate
// revocation through CRLs (here) and OCSP (AttestNvidiaOcsp.swift), and a firmware policy. Fetching is never automatic: the RIMs,
// CRLs and OCSP responses arrive with the evidence. Same checks, order and reason text as the reference.

struct RimGolden {
    var index: Int
    var active: Bool
    var alternatives: Int
    var size: Int
    var hashes: [String]
}

struct VerifiedRim {
    var product: String
    var version: String
    var golden: [Int: RimGolden]
}

struct NvidiaRimIDs {
    var chip = "", driver = "", vbios = "", driverVersion = "", vbiosVersion = ""
}

enum RIM {
    static let NS_DSIG = "http://www.w3.org/2000/09/xmldsig#"
    static let ALG_C14N11 = "http://www.w3.org/2006/12/xml-c14n11"
    static let ALG_ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    static let ALG_ECDSA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
    static let ALG_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
    static let NVDEC0_OFF: UInt8 = 0x55
    static let NVDEC_BLOCK = 35

    static func pemOfDerB64(_ b64: String) -> String {
        let body = Array(Attest.stripJSSpace(b64).utf8)
        var lines: [String] = []
        var i = 0
        while i < body.count {
            lines.append(String(decoding: body[i..<min(i + 64, body.count)], as: UTF8.self))
            i += 64
        }
        return "-----BEGIN CERTIFICATE-----\n" + lines.joined(separator: "\n") + "\n-----END CERTIFICATE-----"
    }

    static func isLowerHex(_ s: String) -> Bool { !s.isEmpty && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) } }

    /// A RIM document's golden measurements. A failure reason, or the manifest.
    static func verify(_ xml: String, _ rimPins: [String], _ nowMs: Int64) -> (VerifiedRim?, String) {
        func fail(_ r: String) -> (VerifiedRim?, String) { (nil, r) }
        if xml.isEmpty || xml.unicodeScalars.count > 4_000_000 { return fail("RIM: empty or oversized document") }
        if rimPins.isEmpty { return fail("RIM: no pinned RIM root configured") }
        let doc: XmlDoc
        do { doc = try XML.parse(xml) } catch { return fail("RIM: verification error (fail closed): " + Nvidia.msg(error)) }
        if !doc.violation.isEmpty { return fail("RIM: " + doc.violation) }
        guard let root = doc.root else { return fail("RIM: verification error (fail closed): no document element") }
        if root.local != "SoftwareIdentity" { return fail("RIM: root element is not SoftwareIdentity") }
        if root.descendantsNS(NS_DSIG, "Signature") != 1 { return fail("RIM: expected exactly one Signature element") }
        let sigs = root.elementChildrenNS(NS_DSIG, "Signature")
        if sigs.count != 1 { return fail("RIM: the Signature must be a direct child of the root") }
        let sig = sigs[0]
        let signedInfo = sig.elementChildrenNS(NS_DSIG, "SignedInfo")
        if signedInfo.count != 1 { return fail("RIM: expected exactly one SignedInfo") }
        let si = signedInfo[0]
        func algOf(_ els: [XmlNode]) -> String { els.first?.attr("Algorithm") ?? "" }
        if algOf(si.elementChildrenNS(NS_DSIG, "CanonicalizationMethod")) != ALG_C14N11 { return fail("RIM: CanonicalizationMethod must be C14N 1.1") }
        if algOf(si.elementChildrenNS(NS_DSIG, "SignatureMethod")) != ALG_ECDSA384 { return fail("RIM: SignatureMethod must be ECDSA-SHA384") }
        let refs = si.elementChildrenNS(NS_DSIG, "Reference")
        if refs.count != 1 { return fail("RIM: expected exactly one Reference") }
        let ref = refs[0]
        if !ref.attr("URI").isEmpty { return fail("RIM: Reference URI must be \"\" (the whole document)") }
        var holder = ref
        if let ts = ref.elementChildrenNS(NS_DSIG, "Transforms").first { holder = ts }
        let transforms = holder.elementChildrenNS(NS_DSIG, "Transform").map { $0.attr("Algorithm") }
        if transforms.count != 2 || transforms[0] != ALG_ENVELOPED || transforms[1] != ALG_C14N11 { return fail("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]") }
        if algOf(ref.elementChildrenNS(NS_DSIG, "DigestMethod")) != ALG_SHA384 { return fail("RIM: DigestMethod must be SHA-384") }
        var digestValue = "", sigValueB64 = ""
        if let d = ref.elementChildrenNS(NS_DSIG, "DigestValue").first { digestValue = Attest.stripJSSpace(d.textContent()) }
        if let d = sig.elementChildrenNS(NS_DSIG, "SignatureValue").first { sigValueB64 = Attest.stripJSSpace(d.textContent()) }
        if digestValue.isEmpty || sigValueB64.isEmpty { return fail("RIM: missing DigestValue / SignatureValue") }

        var certB64: [String] = []
        if let ki = sig.elementChildrenNS(NS_DSIG, "KeyInfo").first, let xd = ki.elementChildrenNS(NS_DSIG, "X509Data").first {
            for c in xd.elementChildrenNS(NS_DSIG, "X509Certificate") { certB64.append(c.textContent()) }
        }
        if certB64.isEmpty { return fail("RIM: no signer certificates in KeyInfo") }
        let (chainOpt, why) = Nvidia.verifyDeviceChain(certB64.map { pemOfDerB64($0) }.joined(separator: "\n"), rimPins, nowMs)
        guard let chain = chainOpt else { return fail("RIM signer chain: " + why) }

        let siCanon = XML.canonicalize(si, si.parent?.scope() ?? [:], nil)
        let sigRaw = Attest.nodeB64(sigValueB64)
        if sigRaw.count != 96 { return fail("RIM: SignatureValue is not a 96-byte P-384 signature") }
        guard let lk = try? Cert.keyOf(chain[0]), lk.typ == "ec",
              ACrypto.ecVerify(curve: lk.ecName, point: lk.point, hash: .sha384, message: Array(siCanon.utf8), raw: sigRaw) else {
            return fail("RIM: SignedInfo signature does not verify under the signer certificate")
        }
        let canon = XML.canonicalize(root, [:], sig)
        if Attest.base64StdEncode(ACrypto.sha384(Array(canon.utf8))) != digestValue { return fail("RIM: document digest does not match the signed DigestValue") }

        var meta: XmlNode?, payload: XmlNode?
        for c in root.elementChildren() {
            if meta == nil && c.local == "Meta" { meta = c }
            if payload == nil && c.local == "Payload" { payload = c }
        }
        guard let metaN = meta, let payloadN = payload else { return fail("RIM: missing Meta / Payload") }
        var golden: [Int: RimGolden] = [:]
        for r in payloadN.elementChildren() {
            if r.local != "Resource" || r.attr("type") != "Measurement" { continue }
            let (index, iok) = Nvidia.jsNumberFromString(r.attr("index"))
            let (alts, aok) = Nvidia.jsNumberFromString(r.attr("alternatives"))
            let (size, sok) = Nvidia.jsNumberFromString(r.attr("size"))
            var hs: [(n: Int, v: String)] = []
            for a in r.attrs where a.local.hasPrefix("Hash") && a.local.count > 4 && a.local.dropFirst(4).allSatisfy({ $0.isASCII && $0.isNumber }) {
                hs.append((Int(a.local.dropFirst(4)) ?? 0, a.value.lowercased()))
            }
            hs = hs.enumerated().sorted { $0.element.n != $1.element.n ? $0.element.n < $1.element.n : $0.offset < $1.offset }.map { $0.element }
            func isInt(_ f: Double, _ ok: Bool, _ min: Double) -> Bool { ok && f.isFinite && f == f.rounded(.towardZero) && f >= min }
            if !isInt(index, iok, 0) || !isInt(alts, aok, 1) || !isInt(size, sok, 1) { return fail("RIM: malformed Measurement resource") }
            let hashes = hs.map { $0.v }
            var bad = hashes.count != Int(alts)
            for h in hashes where !isLowerHex(h) || h.utf8.count != Int(size) * 2 { bad = true }
            if bad { return fail("RIM: Measurement \(Int(index)) hash list is inconsistent with alternatives/size") }
            if golden[Int(index)] != nil { return fail("RIM: duplicate Measurement index \(Int(index))") }
            golden[Int(index)] = RimGolden(index: Int(index), active: r.attr("active").lowercased() == "true", alternatives: Int(alts), size: Int(size), hashes: hashes)
        }
        if golden.isEmpty { return fail("RIM: no measurements") }
        return (VerifiedRim(product: metaN.attr("product"), version: metaN.attr("colloquialVersion"), golden: golden), "")
    }

    // ---- RIM ids named by the (signed) GPU report ----

    static func opaqueASCII(_ b: [UInt8]?) -> String {
        guard let b = b else { return "" }
        var s = String.UnicodeScalarView()
        for c in b { s.append(Unicode.Scalar(c)) }
        var u = Array(String(s).unicodeScalars)
        while let l = u.last, l == "\u{0}" { u.removeLast() }
        var v = String.UnicodeScalarView()
        v.append(contentsOf: u)
        return Attest.jsTrim(String(v))
    }

    /// `^[A-Z][A-Z0-9]{2,11}$`
    static func isChipName(_ s: String) -> Bool {
        let u = Array(s.utf8)
        guard (3...12).contains(u.count), u[0] >= 0x41 && u[0] <= 0x5a else { return false }
        return u.dropFirst().allSatisfy { ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x30 && $0 <= 0x39) }
    }

    static func idsForReport(_ rep: SpdmReport) -> NvidiaRimIDs? {
        let o = rep.opaque
        let driverVersion = opaqueASCII(o[Nvidia.OPAQUE_DRIVER_VERSION])
        guard let vb = o[Nvidia.OPAQUE_VBIOS_VERSION] else { return nil }
        let project = opaqueASCII(o[17]).uppercased()
        let projectSku = opaqueASCII(o[18]).uppercased()
        let chipSku = opaqueASCII(o[15]).uppercased()
        if driverVersion.isEmpty || project.isEmpty || projectSku.isEmpty || chipSku.isEmpty { return nil }
        var chip = "GH100"
        if let raw = o[Nvidia.OPAQUE_CHIP_INFO] {
            chip = opaqueASCII(raw)
            if !isChipName(chip) { return nil }
        }
        let vbiosVersion = Nvidia.formatVbiosVersion(vb)
        var ids = NvidiaRimIDs()
        ids.chip = chip
        ids.driverVersion = driverVersion
        ids.vbiosVersion = vbiosVersion
        ids.driver = chip == "GH100" ? "NV_GPU_DRIVER_GH100_" + driverVersion : "NV_GPU_CC_DRIVER_" + chip + "_" + driverVersion
        ids.vbios = "NV_GPU_VBIOS_" + project + "_" + projectSku + "_" + chipSku + "_" + vbiosVersion.replacingOccurrences(of: ".", with: "").uppercased()
        return ids
    }

    /// A report against the driver and VBIOS RIMs (NVIDIA's merge / alternatives / NVDEC0 rules); "" when it matches.
    static func compareReportToRims(_ rep: SpdmReport, _ driver: VerifiedRim, _ vbios: VerifiedRim) -> String {
        var merged: [Int: RimGolden] = [:]
        for (_, g) in driver.golden where g.active { merged[g.index] = g }
        for i in vbios.golden.keys.sorted() {
            guard let g = vbios.golden[i], g.active else { continue }
            if merged[g.index] != nil { return "driver and VBIOS RIMs both have an active measurement at index \(g.index)" }
            merged[g.index] = g
        }
        if merged.isEmpty { return "RIMs carry no active golden measurements" }
        var runtime: [Int: [UInt8]] = [:]
        for m in rep.measurements { runtime[m.index - 1] = m.digest }
        if merged.count > runtime.count { return "RIMs list more active measurements than the report carries" }
        var nvdecDisabled = false
        if let nv = rep.opaque[11], !nv.isEmpty, nv[0] == NVDEC0_OFF { nvdecDisabled = true }
        var mismatches = 0
        for index in merged.keys.sorted() {
            guard let g = merged[index] else { continue }
            if index + 1 == NVDEC_BLOCK && nvdecDisabled { continue }
            guard let digest = runtime[index], digest.count == g.size, g.hashes.contains(ACrypto.hex(digest)) else {
                mismatches += 1
                continue
            }
        }
        if mismatches > 0 { return "runtime measurements differ from the golden RIM values at \(mismatches) index(es)" }
        return ""
    }

    /// The device chain against CRLs: every CRL must verify under one chain certificate and be fresh, no chain certificate may be
    /// listed by its issuer's CRL, and each required issuer must have a verified CRL. "" when it holds.
    static func checkChainRevocation(_ chain: [AttCert], _ crls: [[UInt8]], _ nowMs: Int64, _ requireIssuers: [String]) -> String {
        if crls.isEmpty { return "no CRLs supplied" }
        var covered = Set<Int>()
        for (ci, crl) in crls.enumerated() {
            var issuerIdx = -1
            var revoked: Set<String>?
            var lastReason = "no chain certificate verifies it"
            for (i, cert) in chain.enumerated() {
                guard let k = try? Cert.keyOf(cert) else { continue }
                let (rv, why) = IntelCollateral.verifyCRL(crl, k, nowMs)
                if why.isEmpty {
                    issuerIdx = i
                    revoked = rv
                    break
                }
                if lastReason == "no chain certificate verifies it" || lastReason.contains("signature does not verify") { lastReason = why }
            }
            guard issuerIdx >= 0, let rev = revoked else { return "CRL #\(ci) rejected: \(lastReason)" }
            covered.insert(issuerIdx)
            for i in 0..<(chain.count - 1) where i + 1 == issuerIdx && rev.contains(Cert.serialHex(chain[i])) {
                return "chain certificate '\(Nvidia.subjectLine(chain[i]))' is revoked"
            }
        }
        for need in requireIssuers {
            if !covered.contains(where: { Cert.nameText(chain[$0].rawSubject).contains(need) }) { return "no verified CRL issued by a certificate matching '\(need)'" }
        }
        return ""
    }

    // ---- firmware policy ----

    static func isDecVersion(_ v: String) -> Bool {
        let parts = v.split(separator: ".", omittingEmptySubsequences: false)
        return !parts.isEmpty && parts.allSatisfy { !$0.isEmpty && $0.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }
    }

    static func isHexVersion(_ v: String) -> Bool {
        let parts = v.split(separator: ".", omittingEmptySubsequences: false)
        return !parts.isEmpty && parts.allSatisfy { (1...4).contains($0.utf8.count) && $0.utf8.allSatisfy { ACrypto.nibble($0) != nil } }
    }

    static func parseVersion(_ v: String, _ radix: Int) -> [Double]? {
        if !(radix == 16 ? isHexVersion(v) : isDecVersion(v)) { return nil }
        var out: [Double] = []
        for p in v.split(separator: ".", omittingEmptySubsequences: false) {
            if let n = UInt64(p, radix: radix) {
                out.append(Double(n))
            } else if radix == 10, let f = Double(p) {
                out.append(f)
            } else {
                return nil
            }
        }
        return out
    }

    static func cmpVersion(_ a: [Double], _ b: [Double]) -> Int {
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            let d = x - y
            if d != 0 { return d < 0 ? -1 : 1 }
        }
        return 0
    }

    struct FirmwarePolicy {
        var minD: [Double]?
        var minV: [Double]?
        var denyD: [[Double]] = []
        var denyV: [[Double]] = []
        var minDText = "", minVText = ""

        init(_ fw: JObject) throws {
            func need(_ v: String, _ radix: Int, _ what: String) throws -> [Double] {
                guard let p = RIM.parseVersion(v, radix) else { throw AttestError("nvidiaCollateralHook: malformed \(what) '\(v)'") }
                return p
            }
            if let s = fw["minDriverVersion"]?.asString, !s.isEmpty {
                minD = try need(s, 10, "minDriverVersion")
                minDText = s
            }
            if let s = fw["minVbiosVersion"]?.asString, !s.isEmpty {
                minV = try need(s, 16, "minVbiosVersion")
                minVText = s
            }
            if case let .array(a)? = fw["denyDriverVersions"] { for x in a { if let s = x.asString { denyD.append(try need(s, 10, "denyDriverVersions entry")) } } }
            if case let .array(a)? = fw["denyVbiosVersions"] { for x in a { if let s = x.asString { denyV.append(try need(s, 16, "denyVbiosVersions entry")) } } }
        }

        func check(_ ids: NvidiaRimIDs) -> String {
            guard let d = RIM.parseVersion(ids.driverVersion, 10) else { return "driver version '\(ids.driverVersion)' in the GPU report is not parseable" }
            guard let v = RIM.parseVersion(ids.vbiosVersion, 16) else { return "VBIOS version '\(ids.vbiosVersion)' in the GPU report is not parseable" }
            if let m = minD, RIM.cmpVersion(d, m) < 0 { return "driver \(ids.driverVersion) is below the minimum \(minDText)" }
            if let m = minV, RIM.cmpVersion(v, m) < 0 { return "VBIOS \(ids.vbiosVersion) is below the minimum \(minVText)" }
            for x in denyD where RIM.cmpVersion(d, x) == 0 { return "driver \(ids.driverVersion) is on the deny list" }
            for x in denyV where RIM.cmpVersion(v, x) == 0 { return "VBIOS \(ids.vbiosVersion) is on the deny list" }
            return ""
        }
    }
}

/// The post-verification collateral check of the NVIDIA verifier. The collateral it reads is what the evidence carries.
final class NvidiaHook {
    let rimPins: [String]
    let revocation: String?
    let requireCrls: Bool
    let requireIssuers: [String]
    let firmware: RIM.FirmwarePolicy?

    init(_ col: JObject) throws {
        let requireCrls = col["requireCrls"] != .bool(false)
        guard let pins = Attest.asStrList(col["rimRootSpkiSha256"]), !pins.isEmpty else { throw AttestError("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root") }
        var fw: RIM.FirmwarePolicy?
        if let f = col["firmware"]?.asObject { fw = try RIM.FirmwarePolicy(f) }
        self.requireCrls = requireCrls
        rimPins = pins
        firmware = fw
        revocation = col["revocation"]?.asString
        var ri: [String] = []
        if case let .array(a)? = col["requireCrlIssuers"] { for x in a { if let s = x.asString { ri.append(s) } } }
        requireIssuers = ri
    }

    func strings(_ v: JSONValue?) -> [String] {
        guard case let .array(a)? = v else { return [] }
        return a.compactMap { $0.asString }
    }

    /// The hook proper: the failure reason, or "" when the collateral holds. `c` is the collateral the evidence carries (nil: none).
    func run(_ c: JObject?, _ rep: SpdmReport, _ chain: [AttCert], _ nowMs: Int64) -> String {
        guard let ids = RIM.idsForReport(rep) else { return "GPU report does not carry the opaque fields needed to name its RIMs" }
        let leaf = chain[0]
        let subject = Cert.nameText(leaf.rawSubject)
        if !Self.chipInSubject(subject, ids.chip) {
            return "device leaf subject '\(subject.replacingOccurrences(of: "\n", with: ", "))' is not a \(ids.chip) device certificate (chip family mismatch)"
        }
        if let fw = firmware {
            let why = fw.check(ids)
            if !why.isEmpty { return "firmware policy: " + why }
        }
        guard let col = c else { return "no RIM collateral supplied for this report" }
        let driverRim = col["driverRimXml"]?.asString ?? "", vbiosRim = col["vbiosRimXml"]?.asString ?? ""
        let crls = strings(col["crls"]).map { Attest.nodeB64($0) }
        let ocsp = strings(col["ocsp"]).map { Attest.nodeB64($0) }
        let (dOpt, dwhy) = RIM.verify(driverRim, rimPins, nowMs)
        let (vOpt, vwhy) = RIM.verify(vbiosRim, rimPins, nowMs)
        guard let d = dOpt else { return "driver RIM: " + dwhy }
        guard let v = vOpt else { return "VBIOS RIM: " + vwhy }
        if d.product != ids.chip { return "driver RIM product '\(d.product)' does not match the GPU chip '\(ids.chip)' (wrong-family manifest)" }
        if v.product != ids.chip { return "VBIOS RIM product '\(v.product)' does not match the GPU chip '\(ids.chip)' (wrong-family manifest)" }
        if d.version != ids.driverVersion { return "driver RIM version '\(d.version)' does not match the report's driver '\(ids.driverVersion)'" }
        if v.version.replacingOccurrences(of: ".", with: "").uppercased() != ids.vbiosVersion.replacingOccurrences(of: ".", with: "").uppercased() {
            return "VBIOS RIM version '\(v.version)' does not match the report's VBIOS '\(ids.vbiosVersion)'"
        }
        let cmp = RIM.compareReportToRims(rep, d, v)
        if !cmp.isEmpty { return cmp }
        var mode = "crl"
        if let r = revocation { mode = r } else if !requireCrls { mode = "" }
        if !crls.isEmpty || mode == "crl" || mode == "both" {
            let why = RIM.checkChainRevocation(chain, crls, nowMs, requireIssuers)
            if !why.isEmpty { return "revocation: " + why }
        }
        if !ocsp.isEmpty || mode == "ocsp" || mode == "both" {
            let why = OCSP.checkChain(chain, ocsp, nowMs)
            if !why.isEmpty { return "revocation (OCSP): " + why }
        }
        return ""
    }

    /// `(^|[^A-Za-z0-9])CHIP([^A-Za-z0-9]|$)`
    static func chipInSubject(_ subject: String, _ chip: String) -> Bool {
        let s = Array(subject.utf8), c = Array(chip.utf8)
        func alnum(_ b: UInt8) -> Bool { (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) }
        if c.isEmpty || s.count < c.count { return false }
        var i = 0
        while i + c.count <= s.count {
            if Array(s[i..<(i + c.count)]) == c && (i == 0 || !alnum(s[i - 1])) && (i + c.count == s.count || !alnum(s[i + c.count])) { return true }
            i += 1
        }
        return false
    }
}
