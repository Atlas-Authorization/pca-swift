import Foundation

// AMD SEV-SNP: genuine ATTESTATION_REPORT verification (ECDSA-P384 report signature under the VCEK, VCEK -> ASK -> ARK chain to the
// pinned ARK of the configured family, VCEK <-> report binding, policy) with the same checks, order and reason text as the
// reference verifier. Classical (ECDSA-P384 / RSA-PSS); no network I/O.

/// BigInt(v) of a JSON policy floor: an exact unsigned 64-bit value, or beyond it ("huge": every report is below it).
struct BigLimit {
    var value: UInt64 = 0
    var huge = false
    var negative = false

    /// Is the report's u64 below this limit?
    func above(_ report: UInt64) -> Bool {
        if negative { return false }
        return huge || report < value
    }
}

final class AmdVerifier: HardwareAttestationVerifier {
    static let ARK_SPKI_SHA384: [String: String] = [
        "milan": "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
        "genoa": "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
        "turin": "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
    ]

    // ATTESTATION_REPORT layout (AMD SEV-SNP ABI): offsets, all integers little-endian.
    static let OFF_GUEST_SVN = 0x004, OFF_POLICY = 0x008, OFF_VMPL = 0x030, OFF_SIG_ALGO = 0x034, OFF_REPORT_DATA = 0x050
    static let OFF_MEASUREMENT = 0x090, OFF_HOST_DATA = 0x0c0, OFF_REPORTED_TCB = 0x180, OFF_CHIP_ID = 0x1a0
    static let OFF_COMMITTED_TCB = 0x1e0, OFF_LAUNCH_TCB = 0x1f0, OFF_SIGNED_END = 0x2a0, OFF_SIG_R = 0x2a0, OFF_SIG_S = 0x2e8
    static let REPORT_LEN = 0x4a0
    static let POLICY_DEBUG_BIT: UInt64 = 1 << 19

    struct Report {
        var guestSvn: UInt32 = 0
        var policy: UInt64 = 0
        var vmpl: UInt32 = 0
        var sigAlgo: UInt32 = 0
        var reportedTcb: UInt64 = 0
        var committedTcb: UInt64 = 0
        var launchTcb: UInt64 = 0
        var reportData: [UInt8] = []
        var measurement: [UInt8] = []
        var hostData: [UInt8] = []
        var chipID: [UInt8] = []
        var signed: [UInt8] = []
        var sigR: [UInt8] = []
        var sigS: [UInt8] = []
    }

    static func le(_ b: [UInt8], _ o: Int, _ n: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in (0..<n).reversed() { v = v << 8 | UInt64(b[o + i]) }
        return v
    }

    static func parseReport(_ b: [UInt8]) throws -> Report {
        let minLen = OFF_SIG_S + 72
        if b.count < minLen { throw AttestError("parseSevSnpReport: report too short (\(b.count) < \(minLen))") }
        var r = Report()
        r.guestSvn = UInt32(le(b, OFF_GUEST_SVN, 4))
        r.policy = le(b, OFF_POLICY, 8)
        r.vmpl = UInt32(le(b, OFF_VMPL, 4))
        r.sigAlgo = UInt32(le(b, OFF_SIG_ALGO, 4))
        r.reportedTcb = le(b, OFF_REPORTED_TCB, 8)
        r.committedTcb = le(b, OFF_COMMITTED_TCB, 8)
        r.launchTcb = le(b, OFF_LAUNCH_TCB, 8)
        r.reportData = Array(b[OFF_REPORT_DATA..<(OFF_REPORT_DATA + 64)])
        r.measurement = Array(b[OFF_MEASUREMENT..<(OFF_MEASUREMENT + 48)])
        r.hostData = Array(b[OFF_HOST_DATA..<(OFF_HOST_DATA + 32)])
        r.chipID = Array(b[OFF_CHIP_ID..<(OFF_CHIP_ID + 64)])
        r.signed = Array(b[0..<OFF_SIGNED_END])
        r.sigR = Array(b[OFF_SIG_R..<(OFF_SIG_R + 72)])
        r.sigS = Array(b[OFF_SIG_S..<(OFF_SIG_S + 72)])
        return r
    }

    /// ECDSA-P384 / SHA-384 over the signed region under the VCEK; AMD stores r and s little-endian.
    static func verifySignature(_ r: Report, point: [UInt8]) -> Bool {
        let rr = Array(r.sigR[0..<48].reversed()), ss = Array(r.sigS[0..<48].reversed())
        if r.sigR[48...].contains(where: { $0 != 0 }) || r.sigS[48...].contains(where: { $0 != 0 }) { return false }
        return ACrypto.ecVerify(curve: "P-384", point: point, hash: .sha384, message: r.signed, raw: rr + ss)
    }

    static let OID_HWID = "1.3.6.1.4.1.3704.1.4"
    static let OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
    static let OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
    static let OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
    static let OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
    static let HWID_LEN = 64

    /// An SPL extension value: one minimal DER INTEGER 0..255. (value, failure text).
    static func decodeSpl(_ v: [UInt8]) -> (Int, String) {
        if v.count < 3 || v[0] != 0x02 { return (0, "is not a DER INTEGER") }
        let l = Int(v[1])
        if l < 1 || l > 2 || v.count != 2 + l { return (0, "has a wrong-length INTEGER") }
        let c0 = v[2]
        if c0 & 0x80 != 0 { return (0, "is negative") }
        if l == 2 {
            if c0 != 0x00 { return (0, "is out of range (> 255)") }
            if v[3] & 0x80 == 0 { return (0, "is a non-minimal INTEGER") }
            return (Int(v[3]), "")
        }
        return (Int(c0), "")
    }

    /// Binds the VCEK body to the report: hwID == chip_id and the four SPLs == the REPORTED_TCB bytes.
    static func checkVcekReportBinding(_ vcekTbs: [UInt8], _ r: Report) -> String {
        let exts: DER.ExtTable
        do { exts = try DER.parseTbsExtensions(vcekTbs) } catch { return "VCEK extensions malformed: " + msg(error) }
        guard let hw = exts.get(OID_HWID) else { return "VCEK certificate has no CHIP_ID (hwID) extension" }
        if hw.critical { return "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)" }
        if hw.value.count != HWID_LEN { return "VCEK CHIP_ID (hwID) extension is \(hw.value.count) bytes, expected \(HWID_LEN)" }
        if !ACrypto.eq(hw.value, r.chipID) { return "VCEK CHIP_ID does not match report chip_id" }
        func byteAt(_ i: UInt64) -> Int { Int((r.reportedTcb >> (8 * i)) & 0xff) }
        let pairs: [(String, String, Int)] = [(OID_BL_SPL, "bootloader", byteAt(0)), (OID_TEE_SPL, "tee", byteAt(1)), (OID_SNP_SPL, "snp", byteAt(6)), (OID_UCODE_SPL, "microcode", byteAt(7))]
        for (oid, name, want) in pairs {
            guard let ext = exts.get(oid) else { return "VCEK certificate has no \(name) SPL extension" }
            if ext.critical { return "VCEK \(name) SPL extension is marked critical (the AMD profile is non-critical)" }
            let (got, why) = decodeSpl(ext.value)
            if !why.isEmpty { return "VCEK \(name) SPL extension \(why)" }
            if got != want { return "VCEK \(name) SPL \(got) does not match report reported_tcb (\(want)) — TCB downgrade?" }
        }
        return ""
    }

    static func msg(_ e: Error) -> String { (e as? AttestError)?.message ?? "invalid" }

    struct ChainResult {
        var reason = ""
        var point: [UInt8]?
        var tbs: [UInt8]?
    }

    /// VCEK -> ASK -> ARK with the ARK pinned. The failure reason, or the VCEK key point and tbs.
    static func verifyChain(_ vcekDer: [UInt8], _ askArkPem: String, _ pin: String, _ nowMs: Int64, _ clockSkew: JSONValue?) -> ChainResult {
        func thrown(_ e: Error) -> ChainResult { ChainResult(reason: "AMD chain verification error: " + msg(e)) }
        func fail(_ r: String) -> ChainResult { ChainResult(reason: r) }
        var skew = 0.0
        if let cs = clockSkew, !cs.isNull {
            guard let f = Attest.asFinite(cs), f >= 0 else { return fail("clockSkewMs must be a non-negative number") }
            skew = f
        }
        let vcek: AttCert
        do { vcek = try Cert.parseDER(vcekDer) } catch { return thrown(error) }
        let pems = Cert.pemBlocks(askArkPem)
        if pems.count != 2 { return fail("ASK+ARK chain must contain exactly two certificates (ASK then ARK)") }
        let ask: AttCert, ark: AttCert
        do { ask = try Cert.fromPEM(pems[0]) } catch { return thrown(error) }
        do { ark = try Cert.fromPEM(pems[1]) } catch { return thrown(error) }
        if !Cert.selfIssued(ark) || !Cert.sigOKBy(ark, ark) { return fail("second certificate of the chain is not a self-signed ARK (chain out of order?)") }
        if Cert.selfIssued(ask) { return fail("first certificate of the chain is self-signed, not an ASK (chain out of order?)") }
        if ask.rawSubject != vcek.rawIssuer { return fail("ASK subject does not match the VCEK issuer") }
        let arkKey: CertKey
        do { arkKey = try Cert.keyOf(ark) } catch { return thrown(error) }
        if arkKey.spkiSHA384 != pin.lowercased() { return fail("ARK does not match the pinned AMD trust anchor") }
        if ask.rawIssuer != ark.rawSubject || !Cert.sigOKBy(ask, ark) { return fail("ASK is not signed by ARK") }
        if !Cert.sigOKBy(vcek, ask) { return fail("VCEK is not signed by ASK") }

        let labels = ["VCEK", "ASK", "ARK"]
        let ders = [vcekDer, ask.raw, ark.raw]
        let roleErr = DER.checkChainRoles(ders)
        if !roleErr.isEmpty { return fail("AMD chain role check failed: " + roleErr) }
        for (i, der) in ders.enumerated() {
            let label = labels[i]
            let exts: DER.ExtTable
            do { exts = try DER.parseCertExtensions(der) } catch { return thrown(error) }
            for oid in exts.oids {
                if let e = exts.m[oid], e.critical, !DER.RECOGNISED_CRITICAL.contains(oid) { return fail("\(label) certificate has an unrecognised critical extension \(oid)") }
            }
            if label != "VCEK" {
                guard let bc = exts.get("2.5.29.19"), bc.critical else { return fail("\(label) certificate BasicConstraints is not marked critical") }
            }
            let (from, to) = DER.derValidity(der)
            guard let f = from, let t = to else { return fail("\(label) certificate validity is unparseable") }
            if Double(nowMs) + skew < Double(f) { return fail("\(label) certificate is not yet valid") }
            if Double(nowMs) - skew > Double(t) { return fail("\(label) certificate has expired") }
        }
        let vk: CertKey
        do { vk = try Cert.keyOf(vcek) } catch { return thrown(error) }
        if vk.typ != "ec" || vk.curve != "secp384r1" {
            return thrown(AttestError("VCEK is not EC secp384r1 (got \(vk.typ)/\(vk.curve.isEmpty ? "undefined" : vk.curve))"))
        }
        let point: [UInt8]
        do { point = try Cert.ecPoint(vk, "P-384") } catch { return thrown(error) }
        let tbs: [UInt8]
        do { tbs = try DER.tbsOfCertificate(vcekDer) } catch { return thrown(error) }
        return ChainResult(reason: "", point: point, tbs: tbs)
    }

    // ---- policy ----

    struct Policy {
        var measurements: [String] = []
        var hostData: [String] = []
        var chipIDs: [String] = []
        var allowDebug = false
        var requireEcdsaP384 = true
        var minGuestSvn: Double?
        var minReportedTcb: BigLimit?
        var minCommittedTcb: BigLimit?
        var minLaunchTcb: BigLimit?
        var requireVmpl: JSONValue?

        func check(_ r: Report) -> String {
            if requireEcdsaP384 && r.sigAlgo != 1 { return "unexpected signature_algo \(r.sigAlgo)" }
            if !allowDebug && r.policy & AmdVerifier.POLICY_DEBUG_BIT != 0 { return "guest policy has the DEBUG bit set (host can inspect the guest)" }
            if let m = minGuestSvn, Double(r.guestSvn) < m { return "guest_svn \(r.guestSvn) below minimum \(Attest.jsNumString(m))" }
            if let m = minReportedTcb, m.above(r.reportedTcb) { return "reported_tcb below minimum (rollback?)" }
            if let m = minCommittedTcb, m.above(r.committedTcb) { return "committed_tcb below minimum (rollback?)" }
            if let m = minLaunchTcb, m.above(r.launchTcb) { return "launch_tcb below minimum" }
            switch requireVmpl {
            case nil, .null?:
                if r.vmpl != 0 { return "vmpl \(r.vmpl) is not the required 0" }
            case let .string(want)?:
                if want != "any" { return "vmpl \(r.vmpl) is not the required \(want)" }
            case let want?:
                guard let f = Attest.asFinite(want), Double(r.vmpl) == f else { return "vmpl \(r.vmpl) is not the required \(AmdVerifier.jsAnyString(want))" }
            }
            if !measurements.isEmpty && !measurements.contains(ACrypto.hex(r.measurement)) { return "measurement not in policy allowlist" }
            if !hostData.isEmpty && !hostData.contains(ACrypto.hex(r.hostData)) { return "host_data not in policy allowlist" }
            if !chipIDs.isEmpty && !chipIDs.contains(ACrypto.hex(r.chipID)) { return "chip_id not in policy allowlist" }
            return ""
        }
    }

    static func jsAnyString(_ v: JSONValue) -> String {
        switch v {
        case let .string(s): return s
        case let .bool(b): return b ? "true" : "false"
        case let .int(i): return String(i)
        case let .double(d): return Attest.jsNumString(d)
        default: return IntentV2.jsString(v)
        }
    }

    /// BigInt(v) for a JSON value; the error text is the reference's.
    static func parseJSBigInt(_ v: JSONValue?) throws -> BigLimit {
        switch v {
        case nil, .null?: throw AttestError("Cannot convert null to a BigInt")
        case let .bool(b)?: return BigLimit(value: b ? 1 : 0)
        case let .string(t)?:
            let s = Attest.jsTrim(t)
            if s.isEmpty { return BigLimit() }
            var base = 10
            var body = Array(s.utf8)
            if body.count > 2 && body[0] == 0x30 {
                switch body[1] {
                case 0x78, 0x58: base = 16; body = Array(body[2...])
                case 0x6f, 0x4f: base = 8; body = Array(body[2...])
                case 0x62, 0x42: base = 2; body = Array(body[2...])
                default: break
                }
            }
            var neg = false
            if base == 10, let f = body.first, f == 0x2b || f == 0x2d {
                neg = f == 0x2d
                body.removeFirst()
            }
            if body.isEmpty { throw AttestError("Cannot convert \(t) to a BigInt") }
            var out = BigLimit()
            out.negative = neg
            for c in body {
                guard let nb = ACrypto.nibble(c), Int(nb) < base else { throw AttestError("Cannot convert \(t) to a BigInt") }
                let (m, o1) = out.value.multipliedReportingOverflow(by: UInt64(base))
                let (a, o2) = m.addingReportingOverflow(UInt64(nb))
                if o1 || o2 { out.huge = true } else { out.value = a }
            }
            if out.huge { out.value = UInt64.max }
            if out.value == 0 && !out.huge { out.negative = false }
            return out
        case let .int(i)?:
            return i < 0 ? BigLimit(value: 0, huge: false, negative: true) : BigLimit(value: UInt64(i))
        case let .double(d)?:
            if !d.isFinite || d != d.rounded(.towardZero) { throw AttestError("The number \(Attest.jsNumString(d)) cannot be converted to a BigInt because it is not an integer") }
            if d < 0 { return BigLimit(value: 0, huge: false, negative: true) }
            if d >= 18_446_744_073_709_551_616.0 { return BigLimit(value: UInt64.max, huge: true) }
            return BigLimit(value: UInt64(d))
        default: throw AttestError("Cannot convert value to a BigInt")
        }
    }

    // ---- the verifier ----

    let family: String
    let pin: String
    let binding: String
    let policy: Policy
    let skew: JSONValue?

    init(_ cfg: JObject) throws {
        let pol = cfg["policy"]?.asObject ?? [:]
        var p = Policy()
        p.requireEcdsaP384 = pol["requireEcdsaP384"] != .bool(false)
        p.allowDebug = pol["allowDebug"] == .bool(true)
        p.requireVmpl = pol["requireVmpl"]
        // the wire config carries the u64 floors as decimal strings: converted before the constructor runs
        if pol["minReportedTcb"] != nil { p.minReportedTcb = try Self.parseJSBigInt(pol["minReportedTcb"]) }
        if pol["minCommittedTcb"] != nil { p.minCommittedTcb = try Self.parseJSBigInt(pol["minCommittedTcb"]) }
        if pol["minLaunchTcb"] != nil { p.minLaunchTcb = try Self.parseJSBigInt(pol["minLaunchTcb"]) }
        let fam = cfg["family"]?.asString ?? ""
        guard var pin = Self.ARK_SPKI_SHA384[fam] else { throw AttestError("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'") }
        if let o = cfg["trustAnchorArkSpkiSha384"]?.asString { pin = o } // conformance harness only: replaces the built-in pin
        let binding = cfg["binding"]?.asString ?? ""
        if binding != "report-data" && binding != "azure-runtime-data" { throw AttestError("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'") }
        guard let ms = Attest.asStrList(pol["measurements"]), !ms.isEmpty else {
            throw AttestError("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
        }
        p.measurements = Attest.lowerAll(ms)
        if let l = Attest.asStrList(pol["hostData"]) { p.hostData = Attest.lowerAll(l) }
        if let l = Attest.asStrList(pol["chipIds"]) { p.chipIDs = Attest.lowerAll(l) }
        if let v = Attest.asFinite(pol["minGuestSvn"]) { p.minGuestSvn = v }
        self.family = fam
        self.pin = pin
        self.binding = binding
        self.policy = p
        self.skew = cfg["clockSkewMs"]
    }

    /// verifyGenuineSevSnpReport: the failure reason, or the parsed report.
    func verifyReport(_ raw: [UInt8], _ vcekDer: [UInt8], _ askArkPem: String, _ nowMs: Int64, _ expected: AttestationBinding?) -> (String, Report?) {
        let rep: Report
        do { rep = try Self.parseReport(raw) } catch { return ("report parse failed: " + Self.msg(error), nil) }
        if raw.count != Self.REPORT_LEN { return ("report length \(raw.count) is not the canonical \(Self.REPORT_LEN)", nil) }
        func nonZero(_ b: ArraySlice<UInt8>) -> Bool { b.contains { $0 != 0 } }
        if nonZero(raw[(Self.OFF_SIG_S + 72)...]) || nonZero(raw[(Self.OFF_SIG_R + 48)..<(Self.OFF_SIG_R + 72)]) || nonZero(raw[(Self.OFF_SIG_S + 48)..<(Self.OFF_SIG_S + 72)]) {
            return ("report signature block has non-zero reserved bytes", nil)
        }
        let chain = Self.verifyChain(vcekDer, askArkPem, pin, nowMs, skew)
        guard chain.reason.isEmpty, let point = chain.point, let tbs = chain.tbs else { return ("cert chain invalid: " + chain.reason, nil) }
        if !Self.verifySignature(rep, point: point) { return ("report signature does not verify under VCEK", nil) }
        let bindErr = Self.checkVcekReportBinding(tbs, rep)
        if !bindErr.isEmpty { return (bindErr, nil) }
        if let e = expected {
            let want = Attest.bindingBytes(e)
            guard let wb = want.bytes else { return ("genuine verification error (fail closed): " + want.error, nil) }
            if !ACrypto.eq(wb, rep.reportData) { return ("report_data does not bind holder/grant/epoch/nonce", nil) }
        }
        let pol = policy.check(rep)
        if !pol.isEmpty { return (pol, nil) }
        return ("", rep)
    }

    func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult {
        let ev = evidence?.asObject
        guard let report = Attest.evBytes(ev, "report"), let vcek = Attest.evBytes(ev, "vcekDer"), let askArk = Attest.evString(ev, "askArkPem") else {
            return .fail("no AMD SEV-SNP evidence for this action")
        }
        guard let exp = expected else { return .fail("no expected attestation binding supplied") }
        let direct = binding == "report-data"
        let (reason, repOpt) = verifyReport(report, vcek, askArk, nowMs, direct ? exp : nil)
        guard let rep = repOpt else { return .fail("SEV-SNP report invalid: " + reason) }
        if !direct {
            guard let rd = Attest.evBytes(ev, "runtimeData") else { return .fail("azure-runtime-data binding needs the runtime-data JSON bytes") }
            let why = Attest.checkAzureRuntimeDataBinding(rep.reportData, rd, exp)
            if !why.isEmpty { return .fail(why) }
        }
        return HardwareResult(ok: true, bound: true, measured: Attest.newMeasured(ACrypto.hex(rep.measurement), ACrypto.hex(rep.chipID)),
                              hostAsserted: ["attestation_type": "amd-sev-snp", "family": family, "measurement": ACrypto.hex(rep.measurement)])
    }
}
