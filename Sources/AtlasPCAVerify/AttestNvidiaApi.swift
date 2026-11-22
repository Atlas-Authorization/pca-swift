import Foundation
import CryptoKit

/// The per-function surface of the NVIDIA GPU confidential-computing attestation modules: the SPDM GET_MEASUREMENTS transcript parse, the device certificate chain against a pinned
/// root, the report signature, the PCA challenge, the RIM ids a report names, and the golden comparison. The whole-verifier path (the hardware verifier for `nvidia-gpu-spdm`) is
/// in AttestNvidia.swift; this exposes the pieces with the results the reference reports.
public enum PCAAttestNvidia {
    public static let NVIDIA_SPDM_SUITE = "nvidia-gpu-spdm-ecdsa-p384-sha384"
    public static let NVIDIA_OPAQUE: [(String, Int)] = [("CERT_ISSUER_NAME", 1), ("CERT_AUTHORITY_KEY_IDENTIFIER", 2), ("DRIVER_VERSION", 3), ("GPU_INFO", 4), ("SKU", 5), ("VBIOS_VERSION", 6),
                                                         ("MANUFACTURER_ID", 7), ("TAMPER_DETECTION", 8), ("MSRSCNT", 12), ("BOARD_ID", 14), ("FWID", 20), ("OPAQUE_DATA_VERSION", 34),
                                                         ("CHIP_INFO", 35), ("FEATURE_FLAG", 36)]
    public static let NVIDIA_RIM_BASE_URL = "https://rim.attestation.nvidia.com/v1/rim/"
    public static let NVIDIA_GH100_CRL_URLS = ["https://crl.ndis.nvidia.com/crl/l2-gh100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"]
    public static let NVIDIA_GB100_CRL_URLS = ["https://crl.ndis.nvidia.com/crl/l2-gb100.crl", "https://crl.ndis.nvidia.com/crl/l1-root.crl"]
    public static let NVIDIA_OCSP_URL = "http://ocsp.ndis.nvidia.com/"
    public static let NVIDIA_OCSP_DEFAULT_MAX_AGE_MS = 604_800_000

    /// A parsed transcript.
    public struct Report {
        public struct Measurement { public let index: Int; public let valueType: Int; public let digest: [UInt8] }
        public let version: Int, code: Int, param1: Int, param2: Int, slot: Int
        public let nonce: [UInt8]
        public let responseVersion: Int, responseCode: Int, numBlocks: Int
        public let measurements: [Measurement]
        public let responderNonce: [UInt8]
        public let opaque: [(type: Int, value: [UInt8])]
        public let signature: [UInt8]
        public let signedBytes: [UInt8]
    }

    static func report(_ r: SpdmReport) -> Report {
        Report(version: r.requestVersion, code: r.requestCode, param1: r.requestParam1, param2: r.requestParam2, slot: r.requestSlot, nonce: r.requestNonce, responseVersion: r.responseVersion,
               responseCode: r.responseCode, numBlocks: r.numBlocks, measurements: r.measurements.map { Report.Measurement(index: $0.index, valueType: $0.valueType, digest: $0.digest) },
               responderNonce: r.responderNonce, opaque: r.opaque.keys.sorted().map { ($0, r.opaque[$0]!) }, signature: r.signature, signedBytes: r.signedBytes)
    }

    /// Parses a request||response GET_MEASUREMENTS transcript; throws on any structural problem.
    public static func parseReport(_ bytes: [UInt8]) throws -> Report { report(try Nvidia.parseSpdm(bytes)) }

    /// NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex.
    public static func formatVbiosVersion(_ raw: [UInt8]) -> String { Nvidia.formatVbiosVersion(raw) }

    private static let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    /// OpenSSL's `ASN1_TIME_print` form of an instant (UTC, the day padded to two columns): `Oct 17 00:00:00 2020 GMT`.
    static func opensslTime(_ ms: Int64) -> String {
        var days = ms >= 0 ? ms / 86_400_000 : -((-ms + 86_399_999) / 86_400_000)
        let secs = (ms - days * 86_400_000) / 1000
        days += 719_468
        let era = (days >= 0 ? days : days - 146_096) / 146_097
        let doe = days - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let y = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        let year = m <= 2 ? y + 1 : y
        func two(_ n: Int64) -> String { n < 10 ? "0\(n)" : "\(n)" }
        return "\(months[Int(m) - 1]) \(d < 10 ? " " : "")\(d) \(two(secs / 3600)):\(two(secs % 3600 / 60)):\(two(secs % 60)) \(year) GMT"
    }

    /// `{subject, issuer, serial, notBefore, notAfter, spkiSha256, rawSha256, ca}` of a certificate, as Node's X509Certificate reports them.
    static func certSummary(_ c: AttCert) -> JSONValue {
        let (from, to) = DER.derValidity(c.raw)
        var serial = ACrypto.hex(c.serial).uppercased()
        while serial.hasPrefix("00") && serial.count > 2 { serial.removeFirst(2) }
        return .object(["subject": .string(Cert.nameText(c.rawSubject)), "issuer": .string(Cert.nameText(c.rawIssuer)), "serial": .string(serial),
                        "notBefore": .string(from.map { opensslTime($0) } ?? ""), "notAfter": .string(to.map { opensslTime($0) } ?? ""),
                        "spkiSha256": .string(ACrypto.hex(ACrypto.sha256(c.rawSPKI))), "rawSha256": .string(ACrypto.hex(ACrypto.sha256(c.raw))), "ca": .bool(Nvidia.certIsCA(c))])
    }

    /// The SHA-256 of a certificate's SubjectPublicKeyInfo, lowercase hex (the pin format for the root). Throws for text that is not a certificate.
    public static func spkiSha256Hex(_ certPem: String) throws -> String { ACrypto.hex(ACrypto.sha256(try Cert.fromPEM(certPem).rawSPKI)) }

    private static func chain(_ pem: String) throws -> [AttCert] {
        let blocks = Cert.pemBlocks(pem)
        if blocks.isEmpty { throw JSError("parsePemChain: no certificates found") }
        if blocks.count > Nvidia.MAX_CHAIN { throw JSError("parsePemChain: chain longer than \(Nvidia.MAX_CHAIN)") }
        return try blocks.map { try Cert.fromPEM($0) }
    }

    /// The certificates of a PEM bundle (leaf first), summarised; throws for none, more than five, or one that does not parse.
    public static func parsePemChain(_ pem: String) throws -> [JSONValue] { try chain(pem).map(certSummary) }

    /// `{ok: true, leaf, chain}` or `{ok: false, reason}`: every link signed, every issuer a CA, every certificate valid at `nowMs`, an ECDSA P-384 key throughout, the root
    /// self-signed and pinned by SPKI SHA-256.
    public static func verifyDeviceChain(_ pem: String, _ pins: [String], _ nowMs: Int64) -> JSONValue {
        let (c, why) = Nvidia.verifyDeviceChain(pem, pins, nowMs)
        guard let chain = c else { return .object(["ok": .bool(false), "reason": .string(why)]) }
        return .object(["ok": .bool(true), "leaf": certSummary(chain[0]), "chain": .array(chain.map(certSummary))])
    }

    /// Whether the signature of the parsed transcript verifies under the chain's leaf key; throws when either does not parse.
    public static func verifySpdmSignature(_ evidence: [UInt8], _ chainPem: String) throws -> Bool {
        let rep = try Nvidia.parseSpdm(evidence)
        guard let leaf = try chain(chainPem).first else { throw JSError("no certificate") }
        guard let lk = try? Cert.keyOf(leaf), lk.typ == "ec" else { return false }
        return ACrypto.ecVerify(curve: lk.ecName, point: lk.point, hash: .sha384, message: rep.signedBytes, raw: rep.signature)
    }

    /// The 32-byte SPDM challenge that carries the PCA binding: sha256(attestationBinding(expected)).
    public static func spdmChallenge(_ expected: JSONValue?) throws -> [UInt8] { ACrypto.sha256(try PCAAttestation.attestationBinding(expected)) }

    /// The RIM ids a (signed) report names, or nil when the report lacks what names them.
    public static func rimIds(_ bytes: [UInt8]) throws -> (chip: String, driver: String, vbios: String, driverVersion: String, vbiosVersion: String)? {
        guard let ids = RIM.idsForReport(try Nvidia.parseSpdm(bytes)) else { return nil }
        return (ids.chip, ids.driver, ids.vbios, ids.driverVersion, ids.vbiosVersion)
    }

    /// A RIM as the reference summarises it (`{tagId, product, version, golden: [...], signerSubject}`), read back from JSON.
    static func rim(_ v: JSONValue?) throws -> VerifiedRim {
        guard let v = v, v.isObject else { throw JSError("rim") }
        var golden: [Int: RimGolden] = [:]
        for g in v.get("golden")?.asArray ?? [] {
            guard let i = IV.safe(g.get("index")), let alt = IV.safe(g.get("alternatives")), let size = IV.safe(g.get("size")) else { throw JSError("golden") }
            golden[Int(i)] = RimGolden(index: Int(i), active: g.get("active") == .bool(true), alternatives: Int(alt), size: Int(size), hashes: (g.get("hashes")?.asArray ?? []).compactMap { $0.asString })
        }
        return VerifiedRim(product: v.get("product")?.asString ?? "", version: v.get("version")?.asString ?? "", golden: golden)
    }

    /// `{ok: true, checked}` or `{ok: false, reason, mismatches?}`: the report against the driver and VBIOS RIMs under NVIDIA's merge, alternatives and NVDEC0 rules.
    public static func compareReport(_ bytes: [UInt8], _ driver: JSONValue?, _ vbios: JSONValue?) throws -> JSONValue {
        let rep = try Nvidia.parseSpdm(bytes)
        let d = try rim(driver), v = try rim(vbios)
        func no(_ r: String, _ mm: [JSONValue]? = nil) -> JSONValue { PCAFrostNet.present([("ok", .bool(false)), ("reason", .string(r)), ("mismatches", mm.map { .array($0) })]) }
        var merged: [Int: (g: RimGolden, source: String)] = [:]
        for g in d.golden.values where g.active { merged[g.index] = (g, "driver") }
        for i in v.golden.keys.sorted() {
            guard let g = v.golden[i], g.active else { continue }
            if merged[g.index] != nil { return no("driver and VBIOS RIMs both have an active measurement at index \(g.index)") }
            merged[g.index] = (g, "vbios")
        }
        if merged.isEmpty { return no("RIMs carry no active golden measurements") }
        var runtime: [Int: [UInt8]] = [:]
        for m in rep.measurements { runtime[m.index - 1] = m.digest }
        if merged.count > runtime.count { return no("RIMs list more active measurements than the report carries") }
        var nvdecDisabled = false
        if let nv = rep.opaque[11], !nv.isEmpty, nv[0] == RIM.NVDEC0_OFF { nvdecDisabled = true }
        var mismatches: [JSONValue] = []
        var checked = 0
        for index in merged.keys.sorted() {
            let (g, source) = merged[index]!
            if index + 1 == RIM.NVDEC_BLOCK && nvdecDisabled { continue }
            checked += 1
            if let digest = runtime[index], digest.count == g.size, g.hashes.contains(ACrypto.hex(digest)) { continue }
            mismatches.append(.object(["index": .int(Int64(index)), "source": .string(source)]))
        }
        if !mismatches.isEmpty { return no("runtime measurements differ from the golden RIM values at \(mismatches.count) index(es)", mismatches) }
        return .object(["ok": .bool(true), "checked": .int(Int64(checked))])
    }

    // ---- RIMs, revocation, the collateral hook, the fetch helpers ----

    /// `{ok: true, rim: {tagId, product, version, golden, signerSubject}}` or `{ok: false, reason}` for a signed RIM under the pinned RIM roots.
    public static func verifyRim(_ xml: String, _ pins: [String], _ nowMs: Int64) -> JSONValue {
        let (r, why) = RIM.verify(xml, pins, nowMs)
        guard let rim = r else { return .object(["ok": .bool(false), "reason": .string(why)]) }
        let golden: [JSONValue] = rim.golden.values.sorted { $0.index < $1.index }.map {
            .object(["index": .int(Int64($0.index)), "active": .bool($0.active), "alternatives": .int(Int64($0.alternatives)), "size": .int(Int64($0.size)), "hashes": .array($0.hashes.map { .string($0) })])
        }
        return .object(["ok": .bool(true), "rim": .object(["tagId": .string(rim.tagId), "product": .string(rim.product), "version": .string(rim.version), "golden": .array(golden), "signerSubject": .string(rim.signerSubject)])])
    }

    /// `{ok: true, verifiedCrls}` or `{ok: false, reason}`: every CRL verifies under one chain certificate and is fresh, no chain certificate is listed by its issuer's CRL, each
    /// required issuer has a verified CRL, and the certificates `requireFor` names (`cdp` default, `all`, `none`, or chain indices) each have one from their issuer.
    public static func checkRevocation(_ chainPem: String, _ crls: [[UInt8]], _ nowMs: Int64, _ requireIssuers: [String], _ requireFor: JSONValue) throws -> JSONValue {
        let ch = try chain(chainPem)
        func no(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        var req: RIM.CrlRequirement = .cdp
        var invalid: String? = nil
        switch requireFor {
        case .string("all"): req = .all
        case .string("none"): req = .notRequired
        case let .array(a):
            var ix: [Int] = []
            for v in a {
                guard v.isNumber, let d = IV.num(v), d == d.rounded(), d >= 0, d < Double(ch.count - 1) else { invalid = invalid ?? "requireCrlFor index \(JS.toString(v)) is not a non-root chain certificate"; continue }
                ix.append(Int(d))
            }
            req = invalid == nil ? .indices(ix) : .notRequired
        default: break
        }
        let why = RIM.checkChainRevocation(ch, crls, nowMs, requireIssuers, req)
        if !why.isEmpty { return no(why) }
        if let i = invalid { return no(i) }
        return .object(["ok": .bool(true), "verifiedCrls": .int(Int64(crls.count))])
    }

    /// `{value: reason | null}` of the collateral hook: `opts` is the hook configuration (rimRootSpkiSha256, revocation, requireCrls, requireCrlIssuers, requireCrlFor, firmware), `bundle`
    /// the collateral the resolver returns (`{driverRimXml, vbiosRimXml, crls?, ocsp?}`, DER as base64url; nil: none). null: the hook accepted.
    public static func collateralHook(opts: JSONValue?, bundle: JSONValue?, evidence: [UInt8], chainPem: String, nowMs: Int64) throws -> JSONValue {
        guard let o = opts?.asObject else { throw JSError("collateral must be an object") }
        let hook = try NvidiaHook(o)
        let ch = try chain(chainPem)
        let rep = try Nvidia.parseSpdm(evidence)
        let why = hook.run(bundle?.asObject, rep, ch, nowMs)
        return .object(["value": why.isEmpty ? .null : .string(why)])
    }

    /// One HTTP exchange of an injected fetch.
    public struct HttpResponse { public let status: Int; public let body: [UInt8]; public init(status: Int, body: [UInt8]) { self.status = status; self.body = body } }
    public typealias Fetch = (_ url: String, _ method: String, _ contentType: String?, _ body: [UInt8]?) throws -> HttpResponse

    /// The text of the RIM NVIDIA's service holds under `id` (a name of `[A-Za-z0-9_.-]+`).
    public static func fetchRim(id: String, baseUrl: String? = nil, fetch: Fetch?) throws -> String {
        guard let f = fetch else { throw JSError("fetchNvidiaRim: no fetch implementation available") }
        let u = Array(id.utf8)
        if u.isEmpty || !u.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x5f || $0 == 0x2e || $0 == 0x2d }) {
            throw JSError("fetchNvidiaRim: invalid RIM id")
        }
        let res = try f((baseUrl ?? NVIDIA_RIM_BASE_URL) + id, "GET", nil, nil)
        if !(200..<300).contains(res.status) { throw JSError("RIM fetch failed: HTTP \(res.status) for \(id)") }
        guard let text = String(bytes: res.body, encoding: .utf8), let body = try? StrictJSON.parseLenient(text) else { throw JSError("Unexpected end of JSON input") }
        guard case let .string(rim)? = body.get("rim") else { throw JSError("RIM fetch: response has no rim field") }
        return String(decoding: Attest.nodeB64(rim), as: UTF8.self)
    }

    /// The bytes of a CRL.
    public static func fetchCrl(url: String, fetch: Fetch?) throws -> [UInt8] {
        guard let f = fetch else { throw JSError("fetchNvidiaCrl: no fetch implementation available") }
        let res = try f(url, "GET", nil, nil)
        if !(200..<300).contains(res.status) { throw JSError("CRL fetch failed: HTTP \(res.status) for \(url)") }
        return res.body
    }

    // ---- OCSP ----

    /// `Date.UTC(y, m, d, h, mi, s)` in milliseconds.
    static func utcMs(_ y: Int, _ m: Int, _ d: Int, _ h: Int, _ mi: Int, _ s: Int) -> Int64 {
        let yy = Int64(m <= 2 ? y - 1 : y)
        let era = (yy >= 0 ? yy : yy - 399) / 400
        let yoe = yy - era * 400
        let doy = Int64((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1)
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        return ((days * 24 + Int64(h)) * 60 + Int64(mi)) * 60_000 + Int64(s) * 1000
    }

    private static func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
        let n = body.count
        let len: [UInt8] = n < 128 ? [UInt8(n)] : n < 256 ? [0x81, UInt8(n)] : [0x82, UInt8(n >> 8), UInt8(n & 255)]
        return [tag] + len + body
    }

    /// The DER OCSPRequest for `cert` (issued by `issuer`): one CertID under `hash` (SHA-384 by default), with a nonce extension when `nonce` (1..32 bytes) is given.
    public static func ocspRequest(certPem: String, issuerPem: String, nonce: [UInt8]? = nil, hash: String? = nil) throws -> [UInt8] {
        let name = hash ?? "sha384"
        let oids: [String: [UInt8]] = ["sha1": [0x2b, 0x0e, 0x03, 0x02, 0x1a], "sha256": [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                                       "sha384": [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02], "sha512": [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]]
        // a hash with no OID is refused before anything is parsed: it never emits an empty OID
        guard oids[name] != nil else { throw JSError("unsupported CertID hash \(name)") }
        let cert = try Cert.fromPEM(certPem), issuer = try Cert.fromPEM(issuerPem)
        let digest: ([UInt8]) -> [UInt8]
        var oid: [UInt8]
        switch name {
        case "sha1": digest = { AHash.sha1.digest($0) }; oid = oids[name]!
        case "sha256": digest = { AHash.sha256.digest($0) }; oid = oids[name]!
        case "sha384": digest = { AHash.sha384.digest($0) }; oid = oids[name]!
        case "sha512": digest = { AHash.sha512.digest($0) }; oid = oids[name]!
        default: throw JSError("unsupported CertID hash \(name)")
        }
        let certId = tlv(0x30, tlv(0x30, tlv(0x06, oid) + [0x05, 0x00]) + tlv(0x04, digest(issuer.rawSubject)) + tlv(0x04, digest(try OCSP.spkiKeyBits(issuer))) + tlv(0x02, cert.serial))
        let request = tlv(0x30, certId) // Request ::= SEQUENCE { reqCert CertID }, then the requestList around it
        var tbs = tlv(0x30, tlv(0x30, request))
        if let n = nonce {
            if n.count < 1 || n.count > 32 { throw JSError("nonce must be 1..32 bytes") }
            let ext = tlv(0x30, tlv(0x06, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02]) + tlv(0x04, tlv(0x04, n)))
            tbs = tlv(0x30, tlv(0x30, request) + tlv(0xa2, tlv(0x30, ext)))
        }
        return tlv(0x30, tbs)
    }

    /// The OCSP responder URLs a certificate advertises (authorityInfoAccess, id-ad-ocsp, URI form).
    public static func ocspUrls(certPem: String) throws -> [String] { Cert.ocspServers(try Cert.fromPEM(certPem)) }

    /// Every GeneralizedTime and UTCTime inside a DER value is a well-formed DER time with in-range fields (no calendar roll-over); the contents of OCTET STRING and BIT STRING are never
    /// inspected. A value that does not parse is false.
    public static func asn1TimesWellFormed(_ der: [UInt8]) -> Bool {
        guard let n = try? OCSP.readNode(der, 0, der.count) else { return false }
        return OCSP.timesWellFormed(der, n)
    }

    /// One response for `chain[certIndex]` (issued by `chain[issuerIndex ?? certIndex + 1]`): `{ok: true, status, thisUpdate, nextUpdate?, producedAt, revokedAt?, revocationReason?, responder}`
    /// or `{ok: false, reason}`. Times are epoch milliseconds. A reason that starts `OCSP response rejected:` carries library text.
    public static func ocspVerify(_ response: [UInt8], chainPem: String, certIndex: JSONValue?, issuerIndex: JSONValue?, nowMs: Double, maxAgeMs: JSONValue? = nil, expectedNonce: [UInt8]? = nil,
                                  clockSkewMs: JSONValue? = nil) throws -> JSONValue {
        let ch = try chain(chainPem)
        func at(_ v: JSONValue?) -> AttCert? { IV.safe(v).flatMap { $0 == $0.rounded() && $0 >= 0 && Int($0) < ch.count ? ch[Int($0)] : nil } }
        var o = OcspOptions()
        if let m = JS.present(maxAgeMs), let d = IV.num(m) { o.maxAgeMs = d }
        if let k = JS.present(clockSkewMs), let d = IV.num(k) { o.clockSkewMs = d }
        o.expectedNonce = expectedNonce
        let ci = IV.safe(certIndex) ?? .nan
        let issuer = issuerIndex.flatMap { JS.present($0) } != nil ? at(issuerIndex) : at(.double(ci + 1))
        let r = OCSP.verifyResponse(response, at(certIndex), issuer, ch, Int64(nowMs), o)
        if !r.ok { return .object(["ok": .bool(false), "reason": .string(r.reason)]) }
        return PCAFrostNet.present([("ok", .bool(true)), ("status", .string(r.status)), ("thisUpdate", .int(r.thisUpdate)), ("nextUpdate", r.nextUpdate.map { .int($0) }), ("producedAt", .int(r.producedAt)),
                                    ("revokedAt", r.revokedAt.map { .int($0) }), ("revocationReason", r.revocationReason.map { .int(Int64($0)) }), ("responder", .string(r.responder))])
    }

    /// The device chain with OCSP responses: every response verifies for exactly one non-root certificate, none is revoked, and each certificate the policy requires has a GOOD response.
    /// `opts`: `requireGood` (`aia` default, `all`, or chain indices), `maxAgeMs`, `clockSkewMs`, `expectedNonces` (per chain index, null for none).
    public static func ocspChain(_ chainPem: String, _ responses: [[UInt8]], _ nowMs: Int64, _ opts: JSONValue?, expectedNonces: [[UInt8]?] = []) throws -> JSONValue {
        let ch = try chain(chainPem)
        var req: OCSP.RequireGood = .aia
        switch opts?.get("requireGood") {
        case .string("all")?: req = .all
        case let .array(a)?: req = .indices(a.map { IV.num($0) ?? .nan })
        default: break
        }
        let r = OCSP.checkChainFull(ch, responses, nowMs, requireGood: req, maxAgeMs: JS.present(opts?.get("maxAgeMs")).flatMap { IV.num($0) }, clockSkewMs: JS.present(opts?.get("clockSkewMs")).flatMap { IV.num($0) },
                                    expectedNonces: expectedNonces)
        var statuses: JSONValue? = nil
        if let st = r.statuses { var o: JObject = [:]; for (k, v) in st { o[JKey(String(k))] = .string(v) }; statuses = .object(o) }
        if !r.ok { return PCAFrostNet.present([("ok", .bool(false)), ("reason", .string(r.reason)), ("statuses", statuses)]) }
        return .object(["ok": .bool(true), "verifiedCrls": .int(0), "verifiedOcsp": .int(Int64(r.verified)), "statuses": statuses ?? .object([:])])
    }

    /// Builds the request, posts it to `url` (the NVIDIA responder by default) with the OCSP content type and returns the request and the response bytes.
    public static func fetchOcsp(certPem: String, issuerPem: String, url: String? = nil, nonce: [UInt8]? = nil, fetch: Fetch?) throws -> (request: [UInt8], response: [UInt8]) {
        guard let f = fetch else { throw JSError("fetchNvidiaOcsp: no fetch implementation available") }
        let request = try ocspRequest(certPem: certPem, issuerPem: issuerPem, nonce: nonce)
        let res = try f(url ?? NVIDIA_OCSP_URL, "POST", "application/ocsp-request", request)
        if !(200..<300).contains(res.status) { throw JSError("OCSP fetch failed: HTTP \(res.status)") }
        return (request, res.body)
    }
}
