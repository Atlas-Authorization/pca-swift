import Foundation
import CryptoKit
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// AMD SEV-SNP report helpers: the full ATTESTATION_REPORT parser (1184 bytes, little-endian), the ECDSA P-384 / SHA-384 report signature over bytes
/// [0, 0x2a0), the VCEK certificate helpers and the CHIP_ID / TCB binding, the policy gate, the default identity derivation, the whole-report verifier
/// over the pinned AMD chain, and the KDS VCEK fetch over an injected transport. Classical (ECDSA P-384, RSA); no hardware is needed for any of it.
public enum PCASevSnp {
    /// `signature_algo` 1: ECDSA with P-384 and SHA-384.
    public static let SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384: UInt32 = 1
    /// Bit 19 of the guest policy: the host may inspect the guest.
    public static let SEV_SNP_POLICY_DEBUG_BIT: UInt64 = 1 << 19
    /// SHA-384 of the Milan ARK's SubjectPublicKeyInfo (lower-case hex): the built-in trust anchor of that family.
    public static let AMD_MILAN_ARK_SPKI_SHA384 = AmdVerifier.ARK_SPKI_SHA384["milan"]!

    private static let REPORT_LEN = 0x4a0

    public static func toHex(_ bytes: [UInt8]) -> String { ACrypto.hex(bytes) }

    /// Every `-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----` block of a text, unchanged (non-overlapping, shortest match).
    public static func splitPemCertificates(_ pem: String) -> [String] { Cert.pemBlocks(pem) }

    // MARK: the report

    public struct Version: Equatable { public var major: UInt8; public var minor: UInt8; public var build: UInt8 }

    /// A parsed ATTESTATION_REPORT: every field of the layout, the signed region and the raw bytes.
    public struct Report: Equatable {
        public var version: UInt32
        public var guestSvn: UInt32
        public var policy: UInt64
        public var familyId: [UInt8]
        public var imageId: [UInt8]
        public var vmpl: UInt32
        public var signatureAlgo: UInt32
        public var currentTcb: UInt64
        public var platformInfo: UInt64
        public var reportData: [UInt8]
        public var measurement: [UInt8]
        public var hostData: [UInt8]
        public var idKeyDigest: [UInt8]
        public var authorKeyDigest: [UInt8]
        public var reportId: [UInt8]
        public var reportIdMa: [UInt8]
        public var reportedTcb: UInt64
        public var cpuidFamId: UInt8
        public var cpuidModId: UInt8
        public var cpuidStep: UInt8
        public var chipId: [UInt8]
        public var committedTcb: UInt64
        public var currentVersion: Version
        public var committedVersion: Version
        public var launchTcb: UInt64
        public var launchMitVector: UInt64
        public var currentMitVector: UInt64
        /// The 72-byte little-endian signature scalars (P-384 uses the low 48 bytes).
        public var signatureR: [UInt8]
        public var signatureS: [UInt8]
        /// Bytes [0, 0x2a0): what the VCEK signed.
        public var signed: [UInt8]
        public var raw: [UInt8]
    }

    /// Parses a report; throws below 0x2e8 + 72 = 816 bytes (a longer buffer is accepted: the canonical length is the verifier's rule).
    public static func parseSevSnpReport(_ b: [UInt8]) throws -> Report {
        let minLen = 0x2e8 + 72
        if b.count < minLen { throw JSError("parseSevSnpReport: report too short (\(b.count) < \(minLen))") }
        func s(_ o: Int, _ n: Int) -> [UInt8] { Array(b[o..<(o + n)]) }
        func ver(_ major: Int, _ minor: Int, _ build: Int) -> Version { Version(major: b[major], minor: b[minor], build: b[build]) }
        return Report(version: AmdVerifier.u32(b, 0x000), guestSvn: AmdVerifier.u32(b, 0x004), policy: AmdVerifier.u64(b, 0x008), familyId: s(0x010, 16), imageId: s(0x020, 16),
                      vmpl: AmdVerifier.u32(b, 0x030), signatureAlgo: AmdVerifier.u32(b, 0x034), currentTcb: AmdVerifier.u64(b, 0x038), platformInfo: AmdVerifier.u64(b, 0x040),
                      reportData: s(0x050, 64), measurement: s(0x090, 48), hostData: s(0x0c0, 32), idKeyDigest: s(0x0e0, 48), authorKeyDigest: s(0x110, 48),
                      reportId: s(0x140, 32), reportIdMa: s(0x160, 32), reportedTcb: AmdVerifier.u64(b, 0x180), cpuidFamId: b[0x188], cpuidModId: b[0x189], cpuidStep: b[0x18a],
                      chipId: s(0x1a0, 64), committedTcb: AmdVerifier.u64(b, 0x1e0), currentVersion: ver(0x1ea, 0x1e9, 0x1e8), committedVersion: ver(0x1ee, 0x1ed, 0x1ec),
                      launchTcb: AmdVerifier.u64(b, 0x1f0), launchMitVector: AmdVerifier.u64(b, 0x1f8), currentMitVector: AmdVerifier.u64(b, 0x200),
                      signatureR: s(0x2a0, 72), signatureS: s(0x2e8, 72), signed: s(0, 0x2a0), raw: b)
    }

    // MARK: the signature

    // The order of the P-384 group, big endian.
    private static let ORDER: [UInt8] = ACrypto.unhex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973")!

    /// The big-endian 48-byte scalar of a 72-byte little-endian field, or nil when it is zero or not below the group order.
    private static func scalar(_ le: [UInt8]) -> [UInt8]? {
        guard le.count == 72, !le[48...].contains(where: { $0 != 0 }) else { return nil }
        let be = Array(le[0..<48].reversed())
        guard be.contains(where: { $0 != 0 }), be.lexicographicallyPrecedes(ORDER) else { return nil }
        return be
    }

    /// `r || s` as 96 big-endian bytes from the report's little-endian fields (only the value matters). Throws when either is zero or not below the order.
    public static func sevSnpSignatureToCompact(r: [UInt8], s: [UInt8]) throws -> [UInt8] {
        guard let rr = scalar(r) else { throw JSError("sev-snp signature: r out of range") }
        guard let ss = scalar(s) else { throw JSError("sev-snp signature: s out of range") }
        return rr + ss
    }

    /// n - s, 48 bytes big endian (s below n).
    private static func negate(_ s: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 48)
        var borrow = 0
        for i in stride(from: 47, through: 0, by: -1) {
            var d = Int(ORDER[i]) - Int(s[i]) - borrow
            if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
            out[i] = UInt8(d)
        }
        return out
    }

    /// The uncompressed SEC1 point (97 bytes) of a P-384 key given as a 97-byte uncompressed or a 49-byte compressed point. Throws on an off-curve or
    /// malformed point.
    public static func ecdsaP384PublicKey(_ sec1: [UInt8]) throws -> [UInt8] {
        let key: P384.Signing.PublicKey
        switch (sec1.count, sec1.first) {
        case (97, 0x04?): key = try P384.Signing.PublicKey(x963Representation: Data(sec1))
        case (49, 0x02?), (49, 0x03?): key = try P384.Signing.PublicKey(compressedRepresentation: Data(sec1))
        default: throw JSError("invalid Point, expected length of 49, or uncompressed 97")
        }
        return Array(key.x963Representation)
    }

    /// ECDSA P-384 / SHA-384 over the signed region under the VCEK point; a high-S signature is ACCEPTED (AMD does not normalise it); never throws.
    public static func verifySevSnpReportSignature(_ report: Report, vcekPoint: [UInt8]) -> Bool {
        guard let r = scalar(report.signatureR), var s = scalar(report.signatureS) else { return false }
        // (r, s) verifies iff (r, n - s) does: verify the low-S form so that no platform verifier's low-S policy can reject an AMD signature
        if half.lexicographicallyPrecedes(s) { s = negate(s) }
        return ACrypto.ecVerify(curve: "P-384", point: vcekPoint, hash: .sha384, message: report.signed, raw: r + s)
    }

    // floor(n / 2), big endian
    private static let half: [UInt8] = {
        var out = [UInt8](repeating: 0, count: 48)
        var carry = 0
        for i in 0..<48 {
            let v = (carry << 8) | Int(ORDER[i])
            out[i] = UInt8(v >> 1)
            carry = v & 1
        }
        return out
    }()

    // MARK: the VCEK

    /// Binds the VCEK body (its tbsCertificate) to the report: hwID equals chip_id and the four SPLs equal the REPORTED_TCB bytes (bootloader 0, tee 1, snp 6,
    /// microcode 7). The reason of the first failure, or nil. A critical AMD extension is refused; the hwID is checked before the SPLs.
    public static func checkVcekReportBinding(_ vcekTbs: [UInt8], _ report: Report) -> String? {
        let r = AmdVerifier.checkVcekReportBinding(vcekTbs, chipID: report.chipId, reportedTcb: report.reportedTcb)
        return r.isEmpty ? nil : r
    }

    /// The tbsCertificate (header included) of a DER certificate. Throws on a non-SEQUENCE and on trailing bytes after the certificate.
    public static func extractTbsCertificate(_ certDer: [UInt8]) throws -> [UInt8] {
        do { return try DER.tbsOfCertificate(certDer) } catch { throw JSError(AmdVerifier.msg(error)) }
    }

    /// The VCEK's P-384 point and its tbsCertificate. Throws unless the certificate parses with no trailing bytes and its key is EC secp384r1.
    public static func extractVcekPublicKey(_ vcekDer: [UInt8]) throws -> (point: [UInt8], tbs: [UInt8]) {
        // bytes that are not a certificate at all are what the reference's PEM reader reports as having no start line
        let parsed: AttCert
        do { parsed = try Cert.parseDER(vcekDer) } catch { throw JSError("error:0480006C:PEM routines::no start line", code: "ERR_OSSL_PEM_NO_START_LINE") }
        do {
            let point = try AmdVerifier.vcekPoint(try Cert.keyOf(parsed))
            return (try ecdsaP384PublicKey(point), try DER.tbsOfCertificate(vcekDer))
        } catch { throw JSError(AmdVerifier.msg(error)) }
    }

    // MARK: the chain and the whole report

    /// The outcome of `verifyAmdCertChain`: the VCEK point and tbsCertificate on success.
    public struct ChainResult: Equatable {
        public var ok: Bool
        public var reason: String?
        public var vcekPoint: [UInt8]?
        public var vcekTbs: [UInt8]?
    }

    /// VCEK -> ASK -> ARK with the ARK pinned (`trustAnchorArkSpkiSha384`, default the Milan ARK), roles, critical extensions and validity at `nowMs`.
    public static func verifyAmdCertChain(vcekDer: [UInt8], askArkPem: String, trustAnchorArkSpkiSha384: String? = nil, nowMs: Int64, clockSkewMs: Double? = nil) -> ChainResult {
        let r = AmdVerifier.verifyChain(vcekDer, askArkPem, trustAnchorArkSpkiSha384 ?? AMD_MILAN_ARK_SPKI_SHA384, nowMs, clockSkewMs.map { StoreJ.num($0) })
        if !r.reason.isEmpty { return ChainResult(ok: false, reason: r.reason, vcekPoint: nil, vcekTbs: nil) }
        return ChainResult(ok: true, reason: nil, vcekPoint: r.point, vcekTbs: r.tbs)
    }

    /// What a report must satisfy beyond the signature. A list that is nil or empty does not gate. `requireVmpl`: a number, or "any"; absent means 0.
    public struct Policy {
        public var measurements: [String]?
        public var hostData: [String]?
        public var chipIds: [String]?
        /// True only: the host may inspect the guest.
        public var allowDebug: Bool
        /// False turns the signature-algorithm gate off.
        public var requireEcdsaP384: Bool
        public var minGuestSvn: Double?
        public var minReportedTcb: UInt64?
        public var minCommittedTcb: UInt64?
        public var minLaunchTcb: UInt64?
        public var requireVmpl: JSONValue?

        public init(measurements: [String]? = nil, hostData: [String]? = nil, chipIds: [String]? = nil, allowDebug: Bool = false, requireEcdsaP384: Bool = true,
                    minGuestSvn: Double? = nil, minReportedTcb: UInt64? = nil, minCommittedTcb: UInt64? = nil, minLaunchTcb: UInt64? = nil, requireVmpl: JSONValue? = nil) {
            self.measurements = measurements; self.hostData = hostData; self.chipIds = chipIds; self.allowDebug = allowDebug; self.requireEcdsaP384 = requireEcdsaP384
            self.minGuestSvn = minGuestSvn; self.minReportedTcb = minReportedTcb; self.minCommittedTcb = minCommittedTcb; self.minLaunchTcb = minLaunchTcb; self.requireVmpl = requireVmpl
        }
    }

    /// The reason the report fails the policy, or nil: algorithm, debug bit, guest SVN, the three TCB floors, VMPL, then the measurement, host data and
    /// chip id allowlists (compared lower-case).
    public static func checkSevSnpPolicy(_ report: Report, _ policy: Policy) -> String? {
        if policy.requireEcdsaP384 && report.signatureAlgo != SEV_SNP_SIG_ALGO_ECDSA_P384_SHA384 { return "unexpected signature_algo \(report.signatureAlgo)" }
        if !policy.allowDebug && report.policy & SEV_SNP_POLICY_DEBUG_BIT != 0 { return "guest policy has the DEBUG bit set (host can inspect the guest)" }
        if let m = policy.minGuestSvn, Double(report.guestSvn) < m { return "guest_svn \(report.guestSvn) below minimum \(JS.number(m))" }
        if let m = policy.minReportedTcb, report.reportedTcb < m { return "reported_tcb below minimum (rollback?)" }
        if let m = policy.minCommittedTcb, report.committedTcb < m { return "committed_tcb below minimum (rollback?)" }
        if let m = policy.minLaunchTcb, report.launchTcb < m { return "launch_tcb below minimum" }
        switch policy.requireVmpl {
        case nil, .null?:
            if report.vmpl != 0 { return "vmpl \(report.vmpl) is not the required 0" }
        case .string("any")?: break
        case let want?:
            if IV.num(want) != Double(report.vmpl) { return "vmpl \(report.vmpl) is not the required \(JS.toString(want))" }
        }
        if let l = policy.measurements, !l.isEmpty, !Attest.lowerAll(l).contains(toHex(report.measurement)) { return "measurement not in policy allowlist" }
        if let l = policy.hostData, !l.isEmpty, !Attest.lowerAll(l).contains(toHex(report.hostData)) { return "host_data not in policy allowlist" }
        if let l = policy.chipIds, !l.isEmpty, !Attest.lowerAll(l).contains(toHex(report.chipId)) { return "chip_id not in policy allowlist" }
        return nil
    }

    /// The default measured identity of a report: the launch measurement is the runtime measurement and the chip id the operator; SEV-SNP has no weights
    /// field, so the weights digest is HOST_DATA only when the caller says it is host-asserted (and is never marked hardware-measured).
    public static func makeDefaultDeriveIdentity(weightsFromHostData: Bool) -> (Report) -> JSONValue {
        { r in
            .object(["model_id": .string(""), "weights_digest": .string(weightsFromHostData ? toHex(r.hostData) : ""), "weights_measured": .bool(false),
                     "runtime_measurement": .string(toHex(r.measurement)), "operator": .string(toHex(r.chipId))])
        }
    }

    /// The outcome of `verifyGenuineSevSnpReport`.
    public struct GenuineResult {
        public var ok: Bool
        public var reason: String?
        public var report: Report?
        public var measured: JSONValue?
    }

    /// A genuine report: the canonical length and zero reserved bytes, the AMD chain, the signature under the VCEK, the VCEK <-> report binding, the
    /// report_data binding to `expected` (when given) and the policy (when given), in that order. Never throws.
    public static func verifyGenuineSevSnpReport(report raw: [UInt8], vcekDer: [UInt8], askArkPem: String, trustAnchorArkSpkiSha384: String? = nil, nowMs: Int64,
                                                 clockSkewMs: Double? = nil, expected: AttestationBinding? = nil, policy: Policy? = nil) -> GenuineResult {
        func fail(_ r: String) -> GenuineResult { GenuineResult(ok: false, reason: r, report: nil, measured: nil) }
        let report: Report
        do { report = try parseSevSnpReport(raw) } catch { return fail("report parse failed: \(AmdVerifier.msg(error))") }
        if raw.count != REPORT_LEN { return fail("report length \(raw.count) is not the canonical \(REPORT_LEN)") }
        if raw[(0x2e8 + 72)...].contains(where: { $0 != 0 }) || raw[(0x2a0 + 48)..<(0x2a0 + 72)].contains(where: { $0 != 0 }) || raw[(0x2e8 + 48)..<(0x2e8 + 72)].contains(where: { $0 != 0 }) {
            return fail("report signature block has non-zero reserved bytes")
        }
        let chain = verifyAmdCertChain(vcekDer: vcekDer, askArkPem: askArkPem, trustAnchorArkSpkiSha384: trustAnchorArkSpkiSha384, nowMs: nowMs, clockSkewMs: clockSkewMs)
        guard chain.ok, let point = chain.vcekPoint, let tbs = chain.vcekTbs else { return fail("cert chain invalid: \(chain.reason ?? "")") }
        if !verifySevSnpReportSignature(report, vcekPoint: point) { return fail("report signature does not verify under VCEK") }
        if let e = checkVcekReportBinding(tbs, report) { return fail(e) }
        if let e = expected {
            let want = Attest.bindingBytes(e)
            guard let wb = want.bytes else { return fail("genuine verification error (fail closed): \(want.error)") }
            if !ACrypto.eq(wb, report.reportData) { return fail("report_data does not bind holder/grant/epoch/nonce") }
        }
        if let p = policy, let e = checkSevSnpPolicy(report, p) { return fail(e) }
        return GenuineResult(ok: true, reason: nil, report: report, measured: makeDefaultDeriveIdentity(weightsFromHostData: false)(report))
    }

    // MARK: the KDS fetch

    /// What a KDS transport answers: the HTTP status and the body.
    public struct KdsResponse {
        public var status: Int
        public var body: [UInt8]
        public init(status: Int, body: [UInt8]) { self.status = status; self.body = body }
    }

    /// Fetches the VCEK of a chip and TCB from AMD's KDS: `<base>/<product>/<lower-case hex chip id>?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..` (base default
    /// `https://kdsintf.amd.com/vcek/v1`, product default Milan). A non-2xx status throws. `fetch` is the transport (default: a blocking URLSession GET).
    public static func fetchVcekFromKds(chipId: [UInt8], reportedTcb: UInt64, product: String? = nil, baseUrl: String? = nil,
                                        fetch: ((String) throws -> KdsResponse)? = nil) throws -> [UInt8] {
        let base = baseUrl ?? "https://kdsintf.amd.com/vcek/v1"
        func byteAt(_ i: UInt64) -> Int { Int((reportedTcb >> (8 * i)) & 0xff) }
        let url = "\(base)/\(product ?? "Milan")/\(toHex(chipId))?blSPL=\(byteAt(0))&teeSPL=\(byteAt(1))&snpSPL=\(byteAt(6))&ucodeSPL=\(byteAt(7))"
        let f = fetch ?? defaultFetch
        let res = try f(url)
        if !(200...299).contains(res.status) { throw JSError("KDS VCEK fetch failed: HTTP \(res.status) for \(url)") }
        return res.body
    }

    private static func defaultFetch(_ url: String) throws -> KdsResponse {
        guard let u = URL(string: url) else { throw JSError("fetchVcekFromKds: invalid URL") }
        final class Box: @unchecked Sendable { var v: Result<KdsResponse, Error> = .failure(JSError("KDS VCEK fetch failed: no response")) }
        let sem = DispatchSemaphore(value: 0), box = Box()
        URLSession.shared.dataTask(with: u) { data, resp, err in
            if let e = err { box.v = .failure(e) }
            else if let h = resp as? HTTPURLResponse { box.v = .success(KdsResponse(status: h.statusCode, body: [UInt8](data ?? Data()))) }
            sem.signal()
        }.resume()
        sem.wait()
        return try box.v.get()
    }
}
