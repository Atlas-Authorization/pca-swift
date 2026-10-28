import Foundation

// Offline Sigstore bundle verification for build provenance (track K9): a port of packages/pca-attest-eat/src/sigstore.ts.
//
// Verifies a Sigstore bundle (v0.2 / v0.3, keyless, a DSSE in-toto envelope) against a pinned `trusted_root.json` with no
// network: RFC 3161 timestamps (every one must verify) and the Rekor v1 SET as time sources; one Rekor v1 `dsse` 0.0.1 /
// `intoto` 0.0.2 or Rekor v2 `hashedrekord` 0.0.2 entry with an RFC 9162 inclusion proof to a checkpoint signed by the pinned
// log; the certificate path to a pinned Fulcio CA at every verified time; the embedded SCT when the root lists CT logs; the
// entry body naming this envelope; the DSSE signature; the Fulcio identity extensions; the in-toto Statement.
// `verifySigstoreBundle` then reads the SLSA v1 predicate into the facts `provenanceGate` checks.
//
// There is no Swift Sigstore library; this reuses the package's own DER / X.509 readers, CryptoKit ECDSA / Ed25519 and the
// pure-Swift RSA. Total: hostile input is a refusal (every reader is bounds-checked and throws), never a trap.

/// A parsed Sigstore `trusted_root.json`: transparency logs, CT logs, Fulcio CAs and timestamp authorities.
public struct SigstoreRoots {
    struct Log { let keyId: [UInt8]; let key: CertKey; let start: Int64; let end: Int64; let v2Name: String? }
    struct CA { let chain: [AttCert]; let start: Int64; let end: Int64 }
    let tlogs: [Log]
    let ctlogs: [Log]
    let cas: [CA]
    let tsas: [CA]
}

/// What a verified bundle establishes: the `core` object of sigstore-vectors.json, and the parsed Statement.
public struct SigstoreCoreResult {
    public let ok: Bool
    public let core: JSONValue
    public let statement: JSONValue
    public let code: String
    public let detail: String
}

/// `facts` (the `facts` member of a `provenanceGate` input) or a refusal.
public struct SigstoreResult {
    public let ok: Bool
    public let facts: JSONValue
    public let code: String
    public let detail: String
}

enum Sigstore {
    static let mediaTypes = ["application/vnd.dev.sigstore.bundle+json;version=0.2", "application/vnd.dev.sigstore.bundle+json;version=0.3", "application/vnd.dev.sigstore.bundle.v0.3+json"]
    static let intotoPayloadType = "application/vnd.in-toto+json"

    struct Fail: Error { let m: String; init(_ m: String) { self.m = m } }

    // ---------------------------------------------------------------- helpers

    static func b64(_ v: JSONValue?) throws -> [UInt8] {
        guard let s = v?.asString else { throw Fail("not base64") }
        return try b64s(s)
    }
    static func b64s(_ s: String) throws -> [UInt8] {
        let ok = s.utf8.count % 4 == 0 && s.utf8.allSatisfy { ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2b || $0 == 0x2f || $0 == 0x3d }
        let pad = s.utf8.reversed().prefix { $0 == 0x3d }.count
        guard ok, pad <= 2, !s.utf8.dropLast(pad).contains(0x3d), let d = Data(base64Encoded: s) else { throw Fail("not base64") }
        return Array(d)
    }
    static func obj(_ v: JSONValue?) -> JObject? { v?.asObject }

    /// `Date.parse` of the ISO-8601 instants a trusted root carries: `YYYY-MM-DDTHH:MM:SS[.fff…]Z`.
    static func isoMs(_ s: String) -> Int64? {
        let u = Array(s.utf8)
        guard u.count >= 20, u.last == 0x5a, u[4] == 0x2d, u[7] == 0x2d, u[10] == 0x54, u[13] == 0x3a, u[16] == 0x3a else { return nil }
        let d = { (i: Int, n: Int) -> Int? in DER.allDigits(u[i..<(i + n)]) ? DER.num(u[i..<(i + n)]) : nil }
        guard let y = d(0, 4), let mo = d(5, 2), let dd = d(8, 2), let h = d(11, 2), let mi = d(14, 2), let se = d(17, 2) else { return nil }
        var ms = 0
        if u.count > 20 {
            let f = u[19..<(u.count - 1)]
            guard f.first == 0x2e, f.count >= 2, DER.allDigits(f.dropFirst()) else { return nil }
            ms = DER.num(f.dropFirst().prefix(3)) * [100, 10, 1][min(f.count - 2, 2)]
        }
        return DER.epochMs(y, mo, dd, h, mi, se).map { $0 + Int64(ms) }
    }
    static func validity(_ v: JSONValue?) throws -> (Int64, Int64) {
        guard let s = v?.get("start")?.asString, let start = isoMs(s) else { throw Fail("validFor.start missing") }
        guard let e = v?.get("end"), let es = e.asString else { return (start, Int64.max) }
        guard let end = isoMs(es) else { throw Fail("validFor.end malformed") }
        return (start, end)
    }
    static func hostname(_ url: String) -> String? {
        guard let r = url.range(of: "://") else { return nil }
        var a = String(url[r.upperBound...].prefix { $0 != "/" && $0 != "?" && $0 != "#" })
        if let at = a.lastIndex(of: "@") { a = String(a[a.index(after: at)...]) }
        let h = a.hasPrefix("[") ? String(a.prefix { $0 != "]" }) + "]" : String(a.prefix { $0 != ":" })
        return h.isEmpty ? nil : h.lowercased()
    }

    // ---------------------------------------------------------------- trusted root

    static func pinnedLog(_ t: JSONValue, transparency: Bool) throws -> SigstoreRoots.Log? {
        guard let pk = t.get("publicKey"), pk.isObject, let lid = t.get("logId"), lid.isObject else { throw Fail("log entry malformed") }
        let der = try b64(pk.get("rawBytes"))
        let keyId = try b64(lid.get("keyId"))
        let (start, end) = try validity(pk.get("validFor"))
        switch pk.get("keyDetails")?.asString ?? "" {
        case "PKIX_ECDSA_P256_SHA_256":
            if ACrypto.sha256(der) != keyId { throw Fail("log id is not the SHA-256 of its key") }
            return .init(keyId: keyId, key: try Cert.keyOfSPKI(der), start: start, end: end, v2Name: nil)
        case "PKCS1_RSA_PKCS1V5" where !transparency:
            guard let rk = Cert.parsePKCS1(der) else { throw Fail("RSA key malformed") }
            let alg: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            let spki = enc(0x30, alg + enc(0x03, [0] + der))
            if ACrypto.sha256(spki) != keyId { throw Fail("log id is not the SHA-256 of its key") }
            var k = CertKey()
            k.typ = "rsa"; k.rsaN = rk.n; k.rsaE = rk.e; k.spki = spki
            return .init(keyId: keyId, key: k, start: start, end: end, v2Name: nil)
        case "PKIX_ED25519" where transparency:
            let k = try Cert.keyOfSPKI(der)
            let name = t.get("baseUrl")?.asString.flatMap(hostname) ?? ""
            if name.isEmpty || ACrypto.sha256(Array("\(name)\n".utf8) + [1] + k.ed) != keyId { throw Fail("log id is not the signed-note key hash of its key") }
            return .init(keyId: keyId, key: k, start: start, end: end, v2Name: name)
        default:
            return nil
        }
    }
    static func fullCert(_ der: [UInt8]) throws -> AttCert {
        let c = try Cert.parseDER(der)
        if c.raw != der { throw Fail("certificate is not one DER SEQUENCE") }
        return c
    }
    static func pinnedChain(_ c: JSONValue) throws -> SigstoreRoots.CA {
        guard let certs = c.get("certChain")?.get("certificates")?.asArray, !certs.isEmpty else { throw Fail("certificate authority entry malformed") }
        let (start, end) = try validity(c.get("validFor"))
        return .init(chain: try certs.map { try fullCert(try b64($0.get("rawBytes"))) }, start: start, end: end)
    }

    // ---------------------------------------------------------------- DER

    struct T: Equatable { let tag: UInt8; let start: Int; let body: Int; let end: Int }
    static func tlv(_ b: [UInt8], _ off: Int, _ limitIn: Int? = nil) throws -> T {
        let limit = min(limitIn ?? b.count, b.count)
        if off < 0 || off + 2 > limit { throw Fail("DER truncated") }
        let tag = b[off]
        if tag & 0x1f == 0x1f { throw Fail("DER multi-byte tag") }
        var len = Int(b[off + 1])
        var body = off + 2
        if len & 0x80 != 0 {
            let n = len & 0x7f
            if n == 0 || n > 4 || body + n > limit { throw Fail("DER length") }
            len = 0
            for i in 0..<n { len = len * 256 + Int(b[body + i]) }
            body += n
        }
        if len > limit - body { throw Fail("DER overrun") }
        return T(tag: tag, start: off, body: body, end: body + len)
    }
    static func kids(_ b: [UInt8], _ t: T) throws -> [T] {
        var out: [T] = []
        var o = t.body
        while o < t.end { let c = try tlv(b, o, t.end); out.append(c); o = c.end }
        return out
    }
    static func kid(_ b: [UInt8], _ t: T, _ i: Int) throws -> T {
        let k = try kids(b, t)
        guard i < k.count else { throw Fail("DER element missing") }
        return k[i]
    }
    static func at(_ k: [T], _ i: Int) throws -> T {
        guard i < k.count else { throw Fail("DER element missing") }
        return k[i]
    }
    static func oidText(_ b: [UInt8], _ t: T) throws -> String {
        if t.tag != 0x06 || t.end <= t.body { throw Fail("not an OID") }
        var parts: [UInt64] = []
        var v: UInt64 = 0
        for x in b[t.body..<t.end] {
            if v >> 56 != 0 { throw Fail("OID arc too large") }
            v = v * 128 + UInt64(x & 0x7f)
            if x & 0x80 == 0 { parts.append(v); v = 0 }
        }
        guard let first = parts.first else { throw Fail("not an OID") }
        let a = min(2, first / 40)
        return ([a, first - a * 40] + parts.dropFirst()).map(String.init).joined(separator: ".")
    }
    static func enc(_ tag: UInt8, _ c: [UInt8]) -> [UInt8] { Cert.lengthHeader(tag, c.count) + c }
    static func slice(_ b: [UInt8], _ t: T) -> [UInt8] { Array(b[t.body..<t.end]) }

    struct Ext { let oid: String; let value: [UInt8]; let t: T }
    struct Parsed { let der: [UInt8]; let tbsKids: [T]; let extsWrapper: T; let exts: [Ext]
        func ext(_ oid: String) -> Ext? { exts.first { $0.oid == oid } }
        func hasEku(_ eku: String) -> Bool {
            guard let e = ext("2.5.29.37"), let seq = try? tlv(e.value, 0), let ks = try? kids(e.value, seq) else { return false }
            return ks.contains { (try? oidText(e.value, $0)) == eku }
        }
    }
    static func parseCert(_ der: [UInt8]) throws -> Parsed {
        let cert = try tlv(der, 0)
        if cert.tag != 0x30 || cert.end != der.count { throw Fail("certificate is not one SEQUENCE") }
        let tbs = try kid(der, cert, 0)
        if tbs.tag != 0x30 { throw Fail("no TBSCertificate") }
        let tbsKids = try kids(der, tbs)
        guard let wrap = tbsKids.first(where: { $0.tag == 0xa3 }) else { throw Fail("no extensions") }
        let seq = try kid(der, wrap, 0)
        if seq.tag != 0x30 { throw Fail("extensions malformed") }
        var exts: [Ext] = []
        for e in try kids(der, seq) {
            let parts = try kids(der, e)
            guard let first = parts.first, let oct = parts.last, oct.tag == 0x04 else { throw Fail("extension value is not an OCTET STRING") }
            let oid = try oidText(der, first)
            if exts.contains(where: { $0.oid == oid }) { throw Fail("duplicate extension \(oid)") }
            exts.append(Ext(oid: oid, value: slice(der, oct), t: e))
        }
        return Parsed(der: der, tbsKids: tbsKids, extsWrapper: wrap, exts: exts)
    }
    static func utf8(_ b: [UInt8]) throws -> String {
        guard let s = String(bytes: b, encoding: .utf8) else { throw Fail("not UTF-8") }
        return s
    }
    /// Fulcio extension `.1.n`: raw UTF-8 for n <= 6, a DER UTF8String for n >= 8 (fulcio docs/oid-info.md).
    static func fulcioExt(_ c: Parsed, _ n: Int) throws -> String? {
        guard let e = c.ext("1.3.6.1.4.1.57264.1.\(n)") else { return nil }
        if n <= 6 { return try utf8(e.value) }
        let t = try tlv(e.value, 0)
        if t.tag != 0x0c || t.end != e.value.count { throw Fail("extension .1.\(n) is not a DER UTF8String") }
        return try utf8(slice(e.value, t))
    }
    /// Exactly one SAN, a URI or an email; anything else (OtherName, several names) is refused.
    static func sanIdentity(_ c: Parsed) throws -> String {
        guard let e = c.ext("2.5.29.17") else { throw Fail("no subjectAltName") }
        let seq = try tlv(e.value, 0)
        let names = try kids(e.value, seq)
        if seq.tag != 0x30 || names.count != 1 { throw Fail("subjectAltName must hold exactly one name") }
        if names[0].tag != 0x86 && names[0].tag != 0x81 { throw Fail("subjectAltName must be a URI or an email") }
        return try utf8(slice(e.value, names[0]))
    }

    // ---------------------------------------------------------------- certificates and signatures

    static func isCA(_ c: AttCert) -> Bool {
        guard let i = try? DER.readCertRoleInfo(c.raw) else { return false }
        return i.hasBasicConstraints && i.ca && (!i.hasKeyUsage || i.keyCertSign)
    }
    static func inside(_ c: AttCert, _ at: Int64) -> Bool {
        let (f, t) = DER.derValidity(c.raw)
        guard let f = f, let t = t else { return false }
        return f <= at && at <= t
    }
    static func issuedBy(_ c: AttCert, _ up: AttCert) -> Bool { c.rawIssuer == up.rawSubject && keyIdsMatch(c, up) && Cert.sigOKBy(c, up) }
    /// X509_check_issued: when `c` names an authority key id and `up` has a subject key id, they must be equal.
    static func keyIdsMatch(_ c: AttCert, _ up: AttCert) -> Bool {
        guard let akid = c.extValue("2.5.29.35"), let skid = up.extValue("2.5.29.14") else { return true }
        guard let seq = try? tlv(akid, 0) else { return false }
        if seq.tag != 0x30 || seq.body >= seq.end { return true }
        guard let k = try? tlv(akid, seq.body, seq.end) else { return false }
        if k.tag != 0x80 { return true }
        guard let sk = try? tlv(skid, 0) else { return false }
        return sk.tag != 0x04 || slice(akid, k) == slice(skid, sk)
    }
    /// Chain (leaf first, self-signed root last): issuer links, signatures, CA flags; every certificate valid at `at`.
    static func chainOk(_ chain: [AttCert], _ at: Int64) -> Bool {
        chain.indices.allSatisfy { i in
            let c = chain[i]
            return issuedBy(c, i + 1 < chain.count ? chain[i + 1] : c) && inside(c, at) && (i == 0 || isCA(c))
        }
    }
    /// Node's `crypto.verify(hash, data, key, sig)`: ECDSA (DER signature) or RSA PKCS#1 v1.5.
    static func verifyDer(_ k: CertKey, _ h: AHash, _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        switch k.typ {
        case "ec": return ACrypto.ecVerify(curve: k.ecName, point: k.point, hash: h, message: msg, der: sig)
        case "rsa": return ACrypto.rsaVerifyPKCS1(n: k.rsaN, e: k.rsaE, hash: h, message: msg, sig: sig)
        default: return false
        }
    }

    // ---------------------------------------------------------------- SCT (RFC 6962 3.2)

    static func verifySct(_ leaf: Parsed, _ issuer: AttCert, _ roots: SigstoreRoots) throws -> String? {
        guard let e = leaf.ext("1.3.6.1.4.1.11129.2.4.2") else { return "no embedded SCT" }
        let outer = try tlv(e.value, 0)
        if outer.tag != 0x04 { return "SCT list is not an OCTET STRING" }
        let list = slice(e.value, outer)
        func u16(_ b: [UInt8], _ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i + 1]) }
        if list.count < 2 || u16(list, 0) != list.count - 2 { return "SCT list length" }
        let der = leaf.der
        let extSeq = try kid(der, leaf.extsWrapper, 0)
        let kept = try kids(der, extSeq).filter { $0.start != e.t.start }.flatMap { Array(der[$0.start..<$0.end]) }
        let tbs = enc(0x30, leaf.tbsKids.flatMap { $0 == leaf.extsWrapper ? enc(0xa3, enc(0x30, kept)) : Array(der[$0.start..<$0.end]) })
        if tbs.count >= 1 << 24 { return "precertificate too large" }
        let issuerKeyHash = ACrypto.sha256(issuer.rawSPKI)
        var why = "no SCT from a pinned CT log"
        var o = 2
        while o < list.count {
            if o + 2 > list.count { return "SCT truncated" }
            let n = u16(list, o)
            let s = Array(list[(o + 2)..<min(o + 2 + n, list.count)])
            o += 2 + n
            if s.count != n || n < 47 { return "SCT truncated" }
            if s[0] != 0 { continue }
            let logId = Array(s[1..<33])
            let ts = s[33..<41].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            let extLen = u16(s, 41)
            let ext = Array(s[43..<min(43 + extLen, s.count)])
            var p = 43 + extLen
            if p + 4 > s.count { return "SCT truncated" }
            let (hashAlg, sigAlg, sigLen) = (s[p], s[p + 1], u16(s, p + 2))
            let sig = Array(s[(p + 4)..<min(p + 4 + sigLen, s.count)])
            p += 4 + sigLen
            if p != s.count || sig.count != sigLen { return "SCT malformed" }
            guard let log = roots.ctlogs.first(where: { $0.keyId == logId }) else { continue }
            if hashAlg != 4 || (sigAlg != 3 && sigAlg != 1) { why = "SCT is not SHA-256 with ECDSA or RSA"; continue }
            if ts > UInt64(Int64.max) || Int64(ts) < log.start || Int64(ts) > log.end { why = "SCT log key not valid at its timestamp"; continue }
            var signed: [UInt8] = [0, 0]
            signed += (0..<8).map { UInt8(truncatingIfNeeded: ts >> (56 - 8 * UInt64($0))) }
            signed += [0, 1] + issuerKeyHash
            signed += [UInt8(truncatingIfNeeded: tbs.count >> 16), UInt8(truncatingIfNeeded: tbs.count >> 8), UInt8(truncatingIfNeeded: tbs.count)] + tbs
            signed += [UInt8(truncatingIfNeeded: ext.count >> 8), UInt8(truncatingIfNeeded: ext.count)] + ext
            if verifyDer(log.key, .sha256, signed, sig) { return nil }
            why = "SCT signature invalid"
        }
        return why
    }

    // ---------------------------------------------------------------- RFC 3161 timestamps

    static func digestOf(_ b: [UInt8], _ t: T) throws -> AHash {
        switch try oidText(b, try kid(b, t, 0)) {
        case "2.16.840.1.101.3.4.2.1": return .sha256
        case "2.16.840.1.101.3.4.2.2": return .sha384
        case "2.16.840.1.101.3.4.2.3": return .sha512
        default: throw Fail("unsupported digest algorithm")
        }
    }
    static func generalizedTime(_ b: [UInt8], _ t: T) throws -> Int64 {
        if t.tag != 0x18 { throw Fail("genTime is not a GeneralizedTime") }
        let s = slice(b, t)
        guard s.count >= 15, s.last == 0x5a, DER.allDigits(s[0..<14]) else { throw Fail("genTime malformed") }
        let frac = s[14..<(s.count - 1)]
        var ms: Int64 = 0
        if !frac.isEmpty {
            let d = frac.dropFirst()
            guard frac.first == 0x2e, !d.isEmpty, d.count <= 9, DER.allDigits(d), let x = Double("0." + String(decoding: d, as: UTF8.self)) else { throw Fail("genTime malformed") }
            ms = Int64((x * 1000).rounded(.down)) // the reference's Math.floor(Number(`0.${frac}`) * 1000)
        }
        let n = { (i: Int, l: Int) in DER.num(s[i..<(i + l)]) }
        guard let base = DER.epochMs(n(0, 4), n(4, 2), n(6, 2), n(8, 2), n(10, 2), n(12, 2)) else { throw Fail("genTime malformed") }
        return base + ms
    }

    static func verifyRfc3161(_ token: [UInt8], _ data: [UInt8], _ tsas: [SigstoreRoots.CA]) throws -> Int64 {
        var ci = try tlv(token, 0)
        if ci.end != token.count || ci.tag != 0x30 { throw Fail("timestamp is not one SEQUENCE") }
        var parts = try kids(token, ci)
        let p0 = try at(parts, 0)
        if p0.tag == 0x30, p0.end - p0.body >= 3, token[try kid(token, p0, 0).start] == 0x02 {
            // TimeStampResp: status (granted 0 or grantedWithMods 1), then the token
            let status = slice(token, try kid(token, p0, 0))
            if !(status.count == 1 && (status[0] == 0 || status[0] == 1)) { throw Fail("timestamp status is not granted") }
            ci = try at(parts, 1)
            parts = try kids(token, ci)
        }
        guard parts.count >= 2, try oidText(token, parts[0]) == "1.2.840.113549.1.7.2", parts[1].tag == 0xa0 else { throw Fail("not CMS SignedData") }
        let sdk = try kids(token, try kid(token, parts[1], 0))
        guard let encap = sdk.enumerated().first(where: { $0.offset > 1 && $0.element.tag == 0x30 })?.element else { throw Fail("no encapContentInfo") }
        let ek = try kids(token, encap)
        guard ek.count >= 2, try oidText(token, ek[0]) == "1.2.840.113549.1.9.16.1.4", ek[1].tag == 0xa0 else { throw Fail("content is not TSTInfo") }
        let octet = try kid(token, ek[1], 0)
        if octet.tag != 0x04 { throw Fail("TSTInfo is not an OCTET STRING") }
        let tst = slice(token, octet)
        let tk = try kids(tst, try tlv(tst, 0))
        let mi = try kids(tst, try at(tk, 2))
        let miAlg = try digestOf(tst, try at(mi, 0))
        if miAlg.digest(data) != slice(tst, try at(mi, 1)) { throw Fail("messageImprint is not the hash of the signature") }
        let genTime = try generalizedTime(tst, try at(tk, 4))
        guard let signerInfos = sdk.last, signerInfos.tag == 0x31 else { throw Fail("no signerInfos") }
        let sis = try kids(token, signerInfos)
        if sis.count != 1 { throw Fail("exactly one SignerInfo is required") }
        let si = try kids(token, sis[0])
        let dAlg = try digestOf(token, try at(si, 2))
        let attrs = try at(si, 3)
        if attrs.tag != 0xa0 { throw Fail("signed attributes are required") }
        var ctOk = false, mdOk = false
        for a in try kids(token, attrs) {
            let ak = try kids(token, a)
            let vals = try kids(token, try at(ak, 1))
            let o = try oidText(token, try at(ak, 0))
            if vals.count != 1 { throw Fail("an attribute must have one value") }
            if o == "1.2.840.113549.1.9.3" { ctOk = try oidText(token, vals[0]) == "1.2.840.113549.1.9.16.1.4" }
            if o == "1.2.840.113549.1.9.4" { mdOk = dAlg.digest(tst) == slice(token, vals[0]) }
        }
        if !ctOk || !mdOk { throw Fail("signed attributes do not commit to the TSTInfo") }
        let signedAttrs = [0x31] + Array(token[(attrs.start + 1)..<attrs.end])
        let sigT = try at(si, 5)
        if sigT.tag != 0x04 { throw Fail("signature is not an OCTET STRING") }
        let sig = slice(token, sigT)
        for tsa in tsas {
            if genTime < tsa.start || genTime > tsa.end { continue }
            let leaf = tsa.chain[0]
            guard let p = try? parseCert(leaf.raw), p.hasEku("1.3.6.1.5.5.7.3.8") else { continue }
            guard let k = try? Cert.keyOf(leaf), verifyDer(k, dAlg, signedAttrs, sig) else { continue }
            if !chainOk(tsa.chain, genTime) { continue }
            return genTime
        }
        throw Fail("no pinned timestamp authority signed it (valid at its time)")
    }

    // ---------------------------------------------------------------- Rekor

    static func verifyCheckpoint(_ text: String, _ log: SigstoreRoots.Log, _ size: Int64, _ root: [UInt8]) throws -> String? {
        guard let cut = text.range(of: "\n\n") else { return "checkpoint has no signature block" }
        let body = String(text[..<cut.lowerBound]) + "\n"
        let lines = body.components(separatedBy: "\n")
        if lines.count < 4 || lines[0].isEmpty { return "checkpoint body too short or without an origin" }
        let sz = lines[1]
        if sz.isEmpty || sz.hasPrefix("0") || !sz.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) || sz != String(size) { return "checkpoint size differs from the proof" }
        if try b64s(lines[2]) != root { return "checkpoint root differs from the proof" }
        for l in text[cut.upperBound...].components(separatedBy: "\n") {
            guard l.hasPrefix("\u{2014} ") else { continue }
            let rest = l.dropFirst(2)
            guard let sp = rest.firstIndex(of: " ") else { continue }
            let name = String(rest[..<sp]), sig64 = String(rest[rest.index(after: sp)...])
            let b64chars = sig64.utf8.allSatisfy { ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2b || $0 == 0x2f || $0 == 0x3d }
            if name.isEmpty || name.contains(where: { $0.isWhitespace }) || sig64.isEmpty || !b64chars { continue }
            let raw = try b64s(sig64)
            if raw.count < 5 || Array(raw[0..<4]) != Array(log.keyId.prefix(4)) { continue }
            if let n = log.v2Name, n != name { continue }
            let sig = Array(raw[4...])
            let ok = log.v2Name != nil ? (log.key.typ == "ed25519" && ACrypto.ed25519Verify(pub: log.key.ed, message: Array(body.utf8), sig: sig)) : verifyDer(log.key, .sha256, Array(body.utf8), sig)
            if ok { return nil }
        }
        return "no checkpoint signature by the pinned log key"
    }

    static func decInt(_ v: JSONValue?) throws -> Int64 {
        guard let s = v?.asString, !s.isEmpty, s.utf8.count <= 16, s.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), s == "0" || !s.hasPrefix("0"), let n = Int64(s), n <= Canonical.MAX_SAFE else {
            throw Fail("not a decimal integer string")
        }
        return n
    }

    static func pae(_ payloadType: String, _ payload: [UInt8]) -> [UInt8] {
        Array("DSSEv1 \(payloadType.utf8.count) \(payloadType) \(payload.count) ".utf8) + payload
    }

    static func pemDer(_ pem: String) throws -> [UInt8] {
        let begin = "-----BEGIN CERTIFICATE-----\n", end = "-----END CERTIFICATE-----"
        guard pem.hasPrefix(begin) else { return [] }
        var r = String(pem.dropFirst(begin.count))
        if r.hasSuffix("\n") { r.removeLast() }
        guard r.hasSuffix(end) else { return [] }
        let mid = String(r.dropLast(end.count))
        guard !mid.isEmpty, mid.utf8.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2b || $0 == 0x2f || $0 == 0x3d || $0 == 0x0a }) else { return [] }
        return try b64s(mid.replacingOccurrences(of: "\n", with: ""))
    }

    /// `String(v)` for the members the reference interpolates.
    static func jsString(_ v: JSONValue?) -> String {
        switch v {
        case .none: return "undefined"
        case let .some(.string(s)): return s
        case .some(.null): return "null"
        case let .some(.bool(b)): return String(b)
        case let .some(.int(i)): return String(i)
        default: return "[object]"
        }
    }

    // ---------------------------------------------------------------- the verifier

    struct Refusal: Error { let code: String; let detail: String }

    static func core(_ bundle: JSONValue, _ o: SigstoreRoots, _ stage: inout String) throws -> (JSONValue, JSONValue) {
        func no(_ c: String, _ d: String) -> Refusal { Refusal(code: c, detail: d) }
        guard bundle.isObject, let vm = bundle.get("verificationMaterial"), vm.isObject else { throw no("malformed", "not a bundle") }
        let mt = bundle.get("mediaType")?.asString ?? ""
        if !mediaTypes.contains(mt) { throw no("media_type", "unsupported media type \(mt)") }
        let v03 = mt != mediaTypes[0]
        let certRaw = v03 ? vm.get("certificate")?.get("rawBytes") : vm.get("x509CertificateChain")?.get("certificates")?.asArray?.first?.get("rawBytes")
        guard let certRaw = certRaw else { throw no("not_keyless", "no Fulcio certificate (public-key bundles are not supported)") }
        guard let env = bundle.get("dsseEnvelope"), env.isObject, bundle.get("messageSignature") == nil else { throw no("envelope", "not a DSSE bundle") }
        if env.get("payloadType")?.asString != intotoPayloadType { throw no("envelope", "payloadType is not application/vnd.in-toto+json") }
        guard let sigs = env.get("signatures")?.asArray, sigs.count == 1, sigs[0].isObject else { throw no("envelope", "a DSSE envelope must carry exactly one signature") }
        let payload = try b64(env.get("payload"))
        let dsseSig = try b64(sigs[0].get("sig"))
        let paeBytes = pae(intotoPayloadType, payload)
        stage = "cert_parse"
        let leafDer = try b64(certRaw)
        let leaf = try fullCert(leafDer)
        let pc = try parseCert(leafDer)
        let leafKey = try Cert.keyOf(leaf)
        let alg: AHash? = leafKey.typ != "ec" ? nil : leafKey.ecName == "P-256" ? .sha256 : leafKey.ecName == "P-384" ? .sha384 : nil

        // ---- the log entry and its log
        stage = "tlog_count"
        guard let entries = vm.get("tlogEntries")?.asArray, entries.count == 1, let t = entries.first, t.isObject else { throw no("tlog_count", "exactly one transparency log entry is required") }
        stage = "tlog_kind"
        let kvo = t.get("kindVersion")
        let kv: String = kvo?.isObject == true ? "\(jsString(kvo?.get("kind")))/\(jsString(kvo?.get("version")))" : ""
        if !["dsse/0.0.1", "intoto/0.0.2", "hashedrekord/0.0.2"].contains(kv) { throw no("tlog_kind", "unsupported entry \(kv)") }
        let v2 = kv == "hashedrekord/0.0.2"
        stage = "tlog_key"
        let keyId = try b64(t.get("logId")?.get("keyId"))
        guard let log = o.tlogs.first(where: { $0.keyId == keyId }) else { throw no("tlog_key", "the entry names a log the verifier did not pin") }
        if v2 != (log.v2Name != nil) { throw no("tlog_key", "the entry type does not match the log version") }
        let logIndex = try decInt(t.get("logIndex"))
        let body = try b64(t.get("canonicalizedBody"))

        // ---- time first: every RFC 3161 timestamp must verify; a Rekor v1 SET must verify when present
        stage = "tsa"
        var times: [Int64] = []
        for ts in vm.get("timestampVerificationData")?.get("rfc3161Timestamps")?.asArray ?? [] {
            times.append(try verifyRfc3161(try b64(ts.get("signedTimestamp")), dsseSig, o.tsas))
        }
        let tsaCount = times.count
        var set = false
        if !v2, let ip = t.get("inclusionPromise"), ip.isObject {
            stage = "tlog_set"
            let integrated = try decInt(t.get("integratedTime"))
            guard let bodyStr = t.get("canonicalizedBody")?.asString else { throw Fail("no body") }
            let msg = "{\"body\":\"\(bodyStr)\",\"integratedTime\":\(integrated),\"logID\":\"\(ACrypto.hex(keyId))\",\"logIndex\":\(logIndex)}"
            if !verifyDer(log.key, .sha256, Array(msg.utf8), try b64(ip.get("signedEntryTimestamp"))) { throw no("tlog_set", "signed entry timestamp invalid") }
            times.append(integrated * 1000)
            set = true
        }
        if times.isEmpty { throw no("no_verified_time", "no verified time: no RFC 3161 timestamp and no Rekor v1 signed entry timestamp") }
        if times.contains(where: { $0 < log.start || $0 > log.end }) { throw no("tlog_key", "the log key was not valid at a signing time") }

        // ---- inclusion
        stage = "tlog_inclusion"
        guard let ip = t.get("inclusionProof"), ip.isObject, let hashes = ip.get("hashes")?.asArray, let cp = ip.get("checkpoint"), cp.isObject else { throw no("tlog_inclusion", "no inclusion proof") }
        let root = try b64(ip.get("rootHash"))
        let size = try decInt(ip.get("treeSize"))
        let proof = try hashes.map { try b64($0) }
        if !PCA.verifyRfc9162Inclusion(leafHash: PCA.rfc9162LeafHash(body), index: try decInt(ip.get("logIndex")), size: size, proof: proof, root: root) {
            throw no("tlog_inclusion", "the inclusion proof does not lead to the root")
        }
        stage = "tlog_checkpoint"
        if let e = try verifyCheckpoint(jsString(cp.get("envelope")), log, size, root) { throw no("tlog_checkpoint", e) }

        // ---- certificate path at every verified time (hybrid model), CT
        stage = "cert_chain"
        let ca = o.cas.first { ca in
            times.allSatisfy { $0 >= ca.start && $0 <= ca.end } && issuedBy(leaf, ca.chain[0]) && times.allSatisfy { chainOk(ca.chain, $0) } && ca.chain.allSatisfy(isCA)
        }
        guard let issuer = ca?.chain[0] else { throw no("cert_chain", "no pinned CA issued the certificate, valid at every signing time") }
        if isCA(leaf) { throw no("cert_chain", "the leaf is a CA certificate") }
        if !times.allSatisfy({ inside(leaf, $0) }) { throw no("cert_time", "the certificate was not valid at a signing time") }
        if !pc.hasEku("1.3.6.1.5.5.7.3.3") { throw no("cert_eku", "the certificate lacks the code-signing EKU") }
        if !o.ctlogs.isEmpty {
            stage = "sct"
            if let e = try verifySct(pc, issuer, o) { throw no("sct", e) }
        }

        // ---- the entry body names this envelope
        stage = "tlog_body"
        let eb = try StrictJSON.parseLenient(String(decoding: body, as: UTF8.self))
        let spec = eb.get("spec")?.isObject == true ? eb.get("spec") : nil
        if "\(jsString(eb.get("kind")))/\(jsString(eb.get("apiVersion")))" != kv { throw no("tlog_body", "the entry body is not the kind the bundle names") }
        let payloadSha = ACrypto.hex(ACrypto.sha256(payload))
        func phOk(_ ph: JSONValue?) -> Bool { ph?.get("algorithm")?.asString == "sha256" && ph?.get("value")?.asString == payloadSha }
        func oneSig(_ v: JSONValue?) -> JSONValue? { v?.asArray.flatMap { $0.count == 1 && $0[0].isObject ? $0[0] : nil } }
        func pemOf(_ v: JSONValue?) throws -> [UInt8] { try pemDer(String(decoding: try b64(v), as: UTF8.self)) }
        if kv == "dsse/0.0.1" {
            if !phOk(spec?.get("payloadHash")) { throw no("tlog_body", "the entry names another payload") }
            guard let s = oneSig(spec?.get("signatures")) else { throw no("tlog_body", "the entry must name exactly one signature") }
            if try b64(s.get("signature")) != dsseSig { throw no("tlog_body", "the entry names another signature") }
            if try pemOf(s.get("verifier")) != leafDer { throw no("tlog_body", "the entry names another certificate") }
        } else if kv == "intoto/0.0.2" {
            // Rekor intoto 0.0.2 stores the envelope signature and payload base64 twice, and the key as base64 PEM
            let c = spec?.get("content")
            if !phOk(c?.get("payloadHash")) { throw no("tlog_body", "the entry names another payload") }
            guard let s = oneSig(c?.get("envelope")?.get("signatures")) else { throw no("tlog_body", "the entry must name exactly one signature") }
            let inner = String(String.UnicodeScalarView(try b64(s.get("sig")).map { Unicode.Scalar($0) }))
            if try b64s(inner) != dsseSig { throw no("tlog_body", "the entry names another signature") }
            if try pemOf(s.get("publicKey")) != leafDer { throw no("tlog_body", "the entry names another certificate") }
        } else {
            // Rekor v2 hashedrekord over DSSE: digest = Hash(PAE), content = the envelope signature, verifier = the leaf
            let h = spec?.get("hashedRekordV002")
            let data = h?.get("data")
            let hash: AHash?
            switch data?.get("algorithm")?.asString {
            case "SHA2_256": hash = .sha256
            case "SHA2_384": hash = .sha384
            case "SHA2_512": hash = .sha512
            default: hash = nil
            }
            guard let hash = hash, hash == alg else { throw no("tlog_body", "the entry digest algorithm is not the signing key's") }
            if try b64(data?.get("digest")) != hash.digest(paeBytes) { throw no("tlog_body", "the entry names another envelope") }
            if try b64(h?.get("signature")?.get("content")) != dsseSig { throw no("tlog_body", "the entry names another signature") }
            if try b64(h?.get("signature")?.get("verifier")?.get("x509Certificate")?.get("rawBytes")) != leafDer { throw no("tlog_body", "the entry names another certificate") }
        }

        // ---- DSSE signature
        stage = "signature"
        guard let a = alg else { throw no("signature", "unsupported leaf key type") }
        if !verifyDer(leafKey, a, paeBytes, dsseSig) { throw no("signature", "DSSE signature invalid") }

        // ---- identity
        stage = "identity"
        let identity = try sanIdentity(pc)
        let issV2 = try fulcioExt(pc, 8), issV1 = try fulcioExt(pc, 1)
        if let x = issV2, let y = issV1, x != y { throw no("identity", "the two issuer extensions disagree") }
        guard let issuer = issV2 ?? issV1, !issuer.isEmpty else { throw no("identity", "no OIDC issuer extension") }
        let sourceRepo = try fulcioExt(pc, 12), sourceDigest = try fulcioExt(pc, 13), sourceRef = try fulcioExt(pc, 14)

        // ---- statement
        stage = "statement"
        let st = try StrictJSON.parseLenient(try utf8(payload))
        if st.get("_type")?.asString != PCA.INTOTO_STATEMENT_V1 { throw no("statement", "not an in-toto Statement v1") }
        guard let subs = st.get("subject")?.asArray, !subs.isEmpty else { throw no("statement", "no subject") }
        var subjects: [JSONValue] = []
        for s in subs {
            for a in ["sha256", "sha512"] {
                if let d = s.get("digest")?.get(a)?.asString { subjects.append(.object(["alg": .string(a), "digest": .string(d)])) }
            }
        }
        if subjects.isEmpty || subjects.count > 64 { throw no("statement", "no sha256/sha512 subject digest (or more than 64)") }
        guard let pt = st.get("predicateType")?.asString else { throw no("statement", "no predicateType") }
        var c: JObject = [
            "identity": .string(identity), "oidc_issuer": .string(issuer), "predicate_type": .string(pt), "subjects": .array(subjects),
            "signed_time": .int(Int64((Double(times.min() ?? 0) / 1000).rounded(.down))), "rekor_log_index": .int(logIndex), "rekor": .string(v2 ? "v2" : "v1"),
            "timestamps": .object(["tsa": .int(Int64(tsaCount)), "set": .bool(set)]),
        ]
        if let x = sourceRepo { c["source_repo"] = .string(x) }
        if let x = sourceRef { c["source_ref"] = .string(x) }
        if let x = sourceDigest { c["source_digest"] = .string(x) }
        return (.object(c), st)
    }
}

extension PCA {
    /// Parse a Sigstore `trusted_root.json` (`application/vnd.dev.sigstore.trustedroot+json;version=0.1`). A root with no CT log
    /// means its owner does not require SCTs; otherwise an SCT from a pinned CT log is required. Throws on anything malformed.
    public static func parseSigstoreTrustedRoot(_ json: JSONValue) throws -> SigstoreRoots {
        guard json.get("mediaType")?.asString == "application/vnd.dev.sigstore.trustedroot+json;version=0.1" else { throw AttestError("not a trusted root v0.1") }
        do {
            let arr = { (k: String) in json.get(k)?.asArray ?? [] }
            let tlogs = try arr("tlogs").compactMap { try Sigstore.pinnedLog($0, transparency: true) }
            let ctlogs = try arr("ctlogs").compactMap { try Sigstore.pinnedLog($0, transparency: false) }
            let cas = try arr("certificateAuthorities").map(Sigstore.pinnedChain)
            let tsas = try arr("timestampAuthorities").map(Sigstore.pinnedChain)
            if tlogs.isEmpty || cas.isEmpty { throw AttestError("a trusted root needs a transparency log and a CA") }
            return SigstoreRoots(tlogs: tlogs, ctlogs: ctlogs, cas: cas, tsas: tsas)
        } catch let e as Sigstore.Fail {
            throw AttestError(e.m)
        }
    }

    /// Verify a Sigstore bundle carrying a DSSE in-toto statement against pinned roots. Never throws; every refusal has a code.
    public static func verifySigstoreBundleCore(_ bundle: JSONValue, roots: SigstoreRoots) -> SigstoreCoreResult {
        var stage = "malformed"
        do {
            let (core, st) = try Sigstore.core(bundle, roots, &stage)
            return SigstoreCoreResult(ok: true, core: core, statement: st, code: "", detail: "")
        } catch let r as Sigstore.Refusal {
            return SigstoreCoreResult(ok: false, core: .null, statement: .null, code: r.code, detail: r.detail)
        } catch {
            let m = (error as? Sigstore.Fail)?.m ?? (error as? AttestError)?.message ?? "\(error)"
            return SigstoreCoreResult(ok: false, core: .null, statement: .null, code: stage, detail: "fail closed: \(m)")
        }
    }

    /// `verifySigstoreBundleCore`, then the SLSA v1 predicate: the facts `provenanceGate` checks.
    public static func verifySigstoreBundle(_ bundle: JSONValue, roots: SigstoreRoots) -> SigstoreResult {
        let r = verifySigstoreBundleCore(bundle, roots: roots)
        if !r.ok { return SigstoreResult(ok: false, facts: .null, code: r.code, detail: r.detail) }
        let st = r.statement, c = r.core
        func pred(_ d: String) -> SigstoreResult { SigstoreResult(ok: false, facts: .null, code: "predicate", detail: d) }
        if st.get("predicateType")?.asString != SLSA_PROVENANCE_V1 { return pred("predicate is not SLSA provenance v1") }
        let bd = st.get("predicate")?.get("buildDefinition")
        guard let buildType = bd?.get("buildType")?.asString, let builderId = st.get("predicate")?.get("runDetails")?.get("builder")?.get("id")?.asString,
              bd?.get("externalParameters")?.isObject == true else { return pred("buildType, externalParameters and builder.id are required (SLSA Build L1)") }
        var f: JObject = [
            "v": .int(1), "predicate_type": .string(SLSA_PROVENANCE_V1), "build_type": .string(buildType), "builder_id": .string(builderId),
            "subjects": c.get("subjects") ?? .null, "identity": c.get("identity") ?? .null, "oidc_issuer": c.get("oidc_issuer") ?? .null,
            "integrated_time": c.get("signed_time") ?? .null, "rekor_log_index": c.get("rekor_log_index") ?? .null,
        ]
        for k in ["source_repo", "source_ref", "source_digest"] { if let v = c.get(k) { f[JKey(k)] = v } }
        if let dep0 = bd?.get("resolvedDependencies")?.asArray?.first, dep0.isObject, let uri = dep0.get("uri")?.asString {
            var ps: JObject = ["uri": .string(uri)]
            if let g = dep0.get("digest")?.get("gitCommit")?.asString { ps["git_commit"] = .string(g) }
            f["provenance_source"] = .object(ps)
        }
        return SigstoreResult(ok: true, facts: .object(f), code: "", detail: "")
    }
}
