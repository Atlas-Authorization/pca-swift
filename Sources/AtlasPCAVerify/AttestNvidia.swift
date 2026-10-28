import Foundation
import CryptoKit

// NVIDIA GPU confidential-computing attestation (Hopper / Blackwell): the SPDM 1.1 GET_MEASUREMENTS transcript signed by the GPU's
// device-identity key, the device certificate chain pinned to the NVIDIA Device Identity CA, the PCA challenge bound through the
// SPDM request nonce, pinned measurement blocks, and the optional collateral hook (signed RIMs, CRLs, OCSP and a firmware policy).
// Same checks, order and reason text as the reference verifier. Classical (ECDSA-P384 / SHA-384); no network I/O.

struct SpdmMeasurement {
    var index: Int
    var digest: [UInt8]
}

struct SpdmReport {
    var requestVersion = 0
    var responseVersion = 0
    var requestNonce: [UInt8] = []
    var measurements: [SpdmMeasurement] = []
    var opaque: [Int: [UInt8]] = [:]
    var signature: [UInt8] = []
    var signedBytes: [UInt8] = []
}

enum Nvidia {
    static let REQ_LEN = 37, NONCE_LEN = 32, SIG_LEN = 96, MAX_CHAIN = 5
    static let OPAQUE_DRIVER_VERSION = 3, OPAQUE_VBIOS_VERSION = 6, OPAQUE_CHIP_INFO = 35

    static func le16(_ b: [UInt8], _ o: Int) -> Int { Int(b[o]) | Int(b[o + 1]) << 8 }

    /// Parses a request||response transcript; it fails on any structural problem.
    /// SPDM 1.1+ is the first version with the signed GET_MEASUREMENTS layout parsed here; request and response must agree. Returns the failure reason or nil.
    static func versionProblem(_ rep: SpdmReport) -> String? {
        if rep.requestVersion < 0x11 || rep.responseVersion != rep.requestVersion {
            return "SPDM version 0x\(String(rep.requestVersion, radix: 16))/0x\(String(rep.responseVersion, radix: 16)) is not an accepted GET_MEASUREMENTS version"
        }
        return nil
    }

    static func parseSpdm(_ b: [UInt8]) throws -> SpdmReport {
        if b.count < REQ_LEN + 8 + NONCE_LEN + 2 + SIG_LEN { throw AttestError("parseNvidiaSpdmEvidence: transcript too short (\(b.count))") }
        if b[1] != 0xe0 { throw AttestError("parseNvidiaSpdmEvidence: request code 0x\(String(b[1], radix: 16)) is not GET_MEASUREMENTS") }
        var rep = SpdmReport()
        rep.requestNonce = Array(b[4..<(4 + NONCE_LEN)])
        rep.requestVersion = Int(b[0])
        let r = Array(b[REQ_LEN...])
        rep.responseVersion = Int(r[0])
        if r[1] != 0x60 { throw AttestError("parseNvidiaSpdmEvidence: response code is not MEASUREMENTS") }
        let numBlocks = Int(r[4])
        let recLen = Int(r[5]) | Int(r[6]) << 8 | Int(r[7]) << 16
        var o = 8
        if o + recLen + NONCE_LEN + 2 + SIG_LEN > r.count { throw AttestError("parseNvidiaSpdmEvidence: measurement record length overruns transcript") }
        let recEnd = o + recLen
        while o < recEnd {
            if o + 4 > recEnd { throw AttestError("parseNvidiaSpdmEvidence: truncated measurement block header") }
            let index = Int(r[o])
            let size = le16(r, o + 2)
            let bodyStart = o + 4
            if bodyStart + size > recEnd || size < 3 { throw AttestError("parseNvidiaSpdmEvidence: measurement block overruns record") }
            let vsize = le16(r, bodyStart + 1)
            if 3 + vsize > size { throw AttestError("parseNvidiaSpdmEvidence: DMTF value overruns measurement block") }
            rep.measurements.append(SpdmMeasurement(index: index, digest: Array(r[(bodyStart + 3)..<(bodyStart + 3 + vsize)])))
            o = bodyStart + size
        }
        if rep.measurements.count != numBlocks { throw AttestError("parseNvidiaSpdmEvidence: header says \(numBlocks) blocks, parsed \(rep.measurements.count)") }
        o += NONCE_LEN
        let opaqueLen = le16(r, o)
        o += 2
        if o + opaqueLen + SIG_LEN != r.count { throw AttestError("parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript") }
        let opaqueEnd = o + opaqueLen
        while o < opaqueEnd {
            if o + 4 > opaqueEnd { throw AttestError("parseNvidiaSpdmEvidence: truncated opaque TLV header") }
            let t = le16(r, o)
            let l = le16(r, o + 2)
            o += 4
            if o + l > opaqueEnd { throw AttestError("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data") }
            rep.opaque[t] = Array(r[o..<(o + l)])
            o += l
        }
        rep.signature = Array(r[(r.count - SIG_LEN)...])
        rep.signedBytes = Array(b[0..<(b.count - SIG_LEN)])
        return rep
    }

    /// String.prototype.slice for an ASCII string (negative indices count from the end).
    static func jsSlice(_ s: String, _ from: Int, _ to: Int) -> String {
        let u = Array(s.utf8)
        let n = u.count
        func norm(_ i0: Int) -> Int {
            var i = i0
            if i < 0 {
                i += n
                if i < 0 { i = 0 }
            }
            return min(i, n)
        }
        let a = norm(from), b = norm(to)
        return a >= b ? "" : String(decoding: u[a..<b], as: UTF8.self)
    }

    /// NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex ("96.00.9f.00.04").
    static func formatVbiosVersion(_ raw: [UInt8]) -> String {
        let hx = ACrypto.hex(Array(raw.reversed()))
        let half = hx.utf8.count / 2
        let temp = Array((jsSlice(hx, half, hx.utf8.count) + jsSlice(hx, half - 2, half)).utf8)
        var parts: [String] = []
        var i = 0
        while i < temp.count {
            parts.append(String(decoding: temp[i..<min(i + 2, temp.count)], as: UTF8.self))
            i += 2
        }
        return parts.joined(separator: ".")
    }

    /// Node's X509Certificate.ca: BasicConstraints CA:TRUE, and keyCertSign when keyUsage is present.
    static func certIsCA(_ c: AttCert) -> Bool {
        guard let info = try? DER.readCertRoleInfo(c.raw) else { return false }
        return info.hasBasicConstraints && info.ca && (!info.hasKeyUsage || info.keyCertSign)
    }

    static func subjectLine(_ c: AttCert) -> String { Cert.nameText(c.rawSubject).replacingOccurrences(of: "\n", with: ", ") }

    static func msg(_ e: Error) -> String { (e as? AttestError)?.message ?? "invalid" }

    /// The device chain (leaf first): every link signed, every issuer a CA, every certificate valid at nowMs, an ECDSA P-384 key
    /// throughout, the root self-signed and pinned by SPKI SHA-256.
    static func verifyDeviceChain(_ pemText: String, _ pins: [String], _ nowMs: Int64) -> ([AttCert]?, String) {
        let blocks = Cert.pemBlocks(pemText)
        if blocks.isEmpty { return (nil, "device chain unparseable: parsePemChain: no certificates found") }
        if blocks.count > MAX_CHAIN { return (nil, "device chain unparseable: parsePemChain: chain longer than \(MAX_CHAIN)") }
        var chain: [AttCert] = []
        for b in blocks {
            do { chain.append(try Cert.fromPEM(b)) } catch { return (nil, "device chain unparseable: " + msg(error)) }
        }
        for (i, c) in chain.enumerated() {
            if !DER.derValidAt(c.raw, nowMs, 0) { return (nil, "device chain cert #\(i) is outside its validity window") }
            guard let k = try? Cert.keyOf(c), k.typ == "ec", k.curve == "secp384r1" else { return (nil, "device chain cert #\(i) is not an ECDSA P-384 key") }
        }
        for i in 0..<(chain.count - 1) {
            let issuer = chain[i + 1]
            if !certIsCA(issuer) { return (nil, "device chain cert #\(i + 1) issues a certificate but is not a CA") }
            if !Cert.sigOKBy(chain[i], issuer) { return (nil, "device chain link #\(i) signature does not verify under its issuer") }
        }
        let root = chain[chain.count - 1]
        if !certIsCA(root) || !Cert.sigOKBy(root, root) { return (nil, "device chain root is not a self-signed CA") }
        guard let rk = try? Cert.keyOf(root) else { return (nil, "device chain root is not a self-signed CA") }
        if !pins.contains(where: { $0.lowercased() == rk.spkiSHA256 }) { return (nil, "chain root is not a pinned NVIDIA root") }
        return (chain, "")
    }

    /// Number(s) for a measurement-block key.
    static func jsNumberFromString(_ s: String) -> (Double, Bool) {
        let t = Attest.jsTrim(s)
        if t.isEmpty { return (0, true) }
        if let f = Double(t) { return (f, true) }
        return (0, false)
    }
}

final class NvidiaVerifier: HardwareAttestationVerifier {
    struct Want {
        var index: Int
        var digest: String
    }

    let pins: [String]
    let want: [Want]
    let leafSub: String
    let hook: NvidiaHook?

    init(_ cfg: JObject) throws {
        var h: NvidiaHook?
        if let col = cfg["collateral"]?.asObject { h = try NvidiaHook(col) }
        guard let p = Attest.asStrList(cfg["rootSpkiSha256"]), !p.isEmpty else {
            throw AttestError("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")
        }
        let pol = cfg["policy"]?.asObject ?? [:]
        let meas = pol["measurements"]?.asObject ?? [:]
        if meas.isEmpty && h == nil {
            throw AttestError("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)")
        }
        struct Entry {
            var key: String
            var idx: Double
            var num: Bool
            var dig: String
        }
        var entries: [Entry] = []
        for (k, d) in meas {
            let (f, ok) = Nvidia.jsNumberFromString(k.s)
            entries.append(Entry(key: k.s, idx: f, num: ok, dig: AmdVerifier.jsAnyString(d).lowercased()))
        }
        entries.sort { a, b in a.idx != b.idx ? a.idx < b.idx : IV.utf8Less(a.key, b.key) }
        var w: [Want] = []
        for e in entries {
            if !e.num || e.idx != e.idx.rounded(.towardZero) || e.idx < 0 || e.idx > 255 { throw AttestError("createNvidiaSpdmVerifier: measurement index out of range") }
            w.append(Want(index: Int(e.idx), digest: e.dig))
        }
        pins = p
        want = w
        leafSub = pol["leafSubjectIncludes"]?.asString ?? ""
        hook = h
    }

    func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult {
        let ev = evidence?.asObject
        guard let evidenceBytes = Attest.evBytes(ev, "evidence"), let chainPem = Attest.evString(ev, "certChainPem") else { return .fail("no NVIDIA GPU evidence for this action") }
        let (chainOpt, why) = Nvidia.verifyDeviceChain(chainPem, pins, nowMs)
        guard let chain = chainOpt else { return .fail(why) }
        let leaf = chain[0]
        if !leafSub.isEmpty && !Cert.nameText(leaf.rawSubject).contains(leafSub) { return .fail("device leaf subject does not contain '\(leafSub)'") }
        let rep: SpdmReport
        do { rep = try Nvidia.parseSpdm(evidenceBytes) } catch { return .fail("GPU attestation report parse failed: " + Nvidia.msg(error)) }
        if let vp = Nvidia.versionProblem(rep) { return .fail(vp) }
        guard let lk = try? Cert.keyOf(leaf), lk.typ == "ec",
              ACrypto.ecVerify(curve: lk.ecName, point: lk.point, hash: .sha384, message: rep.signedBytes, raw: rep.signature) else {
            return .fail("GPU attestation report signature does not verify under the device identity key")
        }
        guard let exp = expected else { return .fail("no expected attestation binding supplied") }
        let rawB = Attest.bindingBytes(exp)
        guard let raw = rawB.bytes else { return .fail("binding not constructible: " + rawB.error) }
        if rep.requestNonce != ACrypto.sha256(raw) { return .fail("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)") }
        var byIndex: [Int: SpdmMeasurement] = [:]
        for m in rep.measurements { byIndex[m.index] = m }
        for w in want {
            guard let m = byIndex[w.index] else { return .fail("measurement block \(w.index) missing from report") }
            if ACrypto.hex(m.digest) != w.digest { return .fail("measurement block \(w.index) does not match the pinned digest") }
        }
        if let h = hook {
            let col = ev?["collateral"]?.asObject
            let r = h.run(col, rep, chain, nowMs)
            if !r.isEmpty { return .fail(r) }
        }
        let sorted = rep.measurements.enumerated().sorted { a, b in a.element.index != b.element.index ? a.element.index < b.element.index : a.offset < b.offset }.map { $0.element }
        var all: [UInt8] = []
        for m in sorted { all += m.digest }
        var host: [String: String] = [
            "attestation_type": "nvidia-gpu-cc",
            "gpu_measurements_sha384": ACrypto.hex(ACrypto.sha384(all)),
            "leaf_subject": Cert.nameText(leaf.rawSubject).replacingOccurrences(of: "\n", with: ", "),
        ]
        if let drv = rep.opaque[Nvidia.OPAQUE_DRIVER_VERSION] {
            var d = drv
            while let l = d.last, l == 0 { d.removeLast() }
            host["driver_version"] = String(decoding: d, as: UTF8.self)
        }
        if let vb = rep.opaque[Nvidia.OPAQUE_VBIOS_VERSION] { host["vbios_version"] = Nvidia.formatVbiosVersion(vb) }
        return HardwareResult(ok: true, bound: true, measured: Attest.newMeasured("", ""), hostAsserted: host)
    }
}
