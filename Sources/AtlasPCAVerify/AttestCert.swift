import Foundation
import CryptoKit

// Certificates as the reference's X.509 engine (OpenSSL through node:crypto) reads them. A platform parser refuses a certificate
// for many reasons OpenSSL does not (a trailing byte after a DER certificate, a non-minimal length, a duplicated or ill-formed
// extension, a second extensions block), and those are precisely the inputs on which the strict readers of the attestation
// verifiers must give their own, specific answer. So a certificate is parsed here with the structure checks of the OpenSSL
// template decoder (nothing more), the strict rules are applied afterwards by the readers of AttestDER.swift, and the platform
// crypto is used only for what it is good at: signature verification.

enum OSSL {
    static let wrongTag = "error:068000A8:asn1 encoding routines::wrong tag"
    static let nested = "error:0688010A:asn1 encoding routines::nested asn1 error"
    static let bits = "error:0680007D:asn1 encoding routines::invalid bit string bits left"
    static let object = "error:0688010A:asn1 encoding routines::invalid object encoding"
    static let unsupported = "error:1E08010C:DECODER routines::unsupported"
}

struct LenientExt {
    var oid: String
    var critical: Bool
    var value: [UInt8]
}

/// A parsed certificate: the raw parts the verifiers compare, and the parameters of its signature.
struct AttCert {
    var raw: [UInt8] = []        // the certificate as DER (outer length in minimal form)
    var rawTBS: [UInt8] = []     // tbsCertificate, header included
    var rawIssuer: [UInt8] = []
    var rawSubject: [UInt8] = []
    var rawSPKI: [UInt8] = []
    var serial: [UInt8] = []     // the INTEGER content
    var sigOID = ""
    var sigParams: [UInt8]?      // the parameters element of the signature algorithm, header included (nil: absent)
    var signature: [UInt8] = []  // the signature BIT STRING content without the unused-bits octet
    var exts: [LenientExt] = []

    func extValue(_ oid: String) -> [UInt8]? { exts.first { $0.oid == oid }?.value }
}

struct CertElem {
    var tag: UInt8
    var hdr: Int
    var start: Int
    var end: Int
}

/// A certificate's public key with the details the rules ask about (Node's asymmetricKeyType / namedCurve).
struct CertKey {
    var typ: String = "unknown"   // "ec", "rsa", "rsa-pss", "ed25519", ...
    var curve: String = ""        // OpenSSL curve name for "ec"
    var ecName: String = ""       // "P-256" / "P-384" / "P-521" / "P-224" for "ec"
    var point: [UInt8] = []       // uncompressed SEC1 point for "ec"
    var rsaN: [UInt8] = []
    var rsaE: [UInt8] = []
    var ed: [UInt8] = []
    var spki: [UInt8] = []        // DER SubjectPublicKeyInfo

    var spkiSHA256: String { ACrypto.hex(ACrypto.sha256(spki)) }
    var spkiSHA384: String { ACrypto.hex(ACrypto.sha384(spki)) }
}

enum Cert {
    static func readElem(_ b: [UInt8], _ off: Int, _ limit: Int, _ tag: UInt8 = 0) throws -> CertElem {
        if off >= limit { throw AttestError("error:0680007B:asn1 encoding routines::not enough data") }
        let t: DerTlv
        do { t = try DER.tlvAt(b, off, limit: limit) } catch { throw AttestError(OSSL.nested) }
        if tag != 0 && t.tag != tag { throw AttestError(OSSL.wrongTag) }
        return CertElem(tag: t.tag, hdr: off, start: t.start, end: t.end)
    }

    static func kids(_ b: [UInt8], _ e: CertElem) throws -> [CertElem] {
        var out: [CertElem] = []
        var p = e.start
        while p < e.end {
            let k = try readElem(b, p, e.end)
            out.append(k)
            p = k.end
        }
        return out
    }

    /// The OpenSSL object-identifier content check: not empty, no arc starting with 0x80, no dangling continuation.
    static func validOID(_ b: [UInt8], _ e: CertElem) -> Bool {
        if e.tag != 0x06 || e.end <= e.start || b[e.end - 1] & 0x80 != 0 { return false }
        for i in e.start..<e.end where b[i] == 0x80 && (i == e.start || b[i - 1] & 0x80 == 0) { return false }
        return true
    }

    /// AlgorithmIdentifier: SEQUENCE { OID, parameters ANY OPTIONAL }.
    static func algID(_ b: [UInt8], _ e: CertElem) throws -> (oid: String, params: [UInt8]?) {
        let ks = try kids(b, e)
        if ks.isEmpty || ks.count > 2 || !validOID(b, ks[0]) { throw AttestError(OSSL.nested) }
        let dotted: String
        do { dotted = try DER.oidToDotted(b, DerTlv(tag: ks[0].tag, start: ks[0].start, end: ks[0].end)) } catch { throw AttestError(OSSL.object) }
        var params: [UInt8]?
        if ks.count == 2 { params = Array(b[ks[1].hdr..<ks[1].end]) }
        return (dotted, params)
    }

    static func checkBitString(_ b: [UInt8], _ e: CertElem) throws {
        if e.tag != 0x03 || e.end - e.start < 1 { throw AttestError(OSSL.wrongTag) }
        if b[e.start] > 7 { throw AttestError(OSSL.bits) }
    }

    static let nameValueTags: Set<UInt8> = [0x0c, 0x12, 0x13, 0x14, 0x16, 0x1c, 0x1e, 0x03, 0x30]

    /// A Name: SEQUENCE OF SET OF SEQUENCE { OID, string }.
    static func checkName(_ b: [UInt8], _ e: CertElem) throws {
        for rdn in try kids(b, e) {
            if rdn.tag != 0x31 { throw AttestError(OSSL.wrongTag) }
            for atv in try kids(b, rdn) {
                if atv.tag != 0x30 { throw AttestError(OSSL.wrongTag) }
                let kv = try kids(b, atv)
                if kv.count != 2 || !validOID(b, kv[0]) || !nameValueTags.contains(kv[1].tag) { throw AttestError(OSSL.nested) }
            }
        }
    }

    /// Parse a DER certificate like d2i_X509: its structure is checked, trailing bytes after it are ignored.
    static func parseDER(_ der: [UInt8]) throws -> AttCert {
        let outer = try readElem(der, 0, der.count, 0x30)
        let tbs = try readElem(der, outer.start, outer.end, 0x30)
        let alg = try readElem(der, tbs.end, outer.end, 0x30)
        let sig = try readElem(der, alg.end, outer.end, 0x03)
        if sig.end != outer.end { throw AttestError(OSSL.nested) }
        try checkBitString(der, sig)
        var c = AttCert()
        c.rawTBS = Array(der[tbs.hdr..<tbs.end])
        c.signature = Array(der[(sig.start + 1)..<sig.end])
        let a0 = try algID(der, alg)
        c.sigOID = a0.oid
        c.sigParams = a0.params

        var p = tbs.start
        if p < tbs.end && der[p] == 0xa0 {
            let v = try readElem(der, p, tbs.end, 0xa0)
            let versionInt = try readElem(der, v.start, v.end, 0x02)
            if versionInt.end != v.end { throw AttestError(OSSL.nested) }
            p = v.end
        }
        let serial = try readElem(der, p, tbs.end, 0x02)
        if serial.end == serial.start { throw AttestError("error:0688010A:asn1 encoding routines::illegal zero content") }
        c.serial = Array(der[serial.start..<serial.end])
        p = serial.end
        let inner = try readElem(der, p, tbs.end, 0x30) // signature algorithm
        _ = try algID(der, inner)
        p = inner.end
        let issuer = try readElem(der, p, tbs.end, 0x30)
        try checkName(der, issuer)
        c.rawIssuer = Array(der[issuer.hdr..<issuer.end])
        p = issuer.end
        let validity = try readElem(der, p, tbs.end, 0x30)
        let times = try kids(der, validity)
        if times.count != 2 || (times[0].tag != 0x17 && times[0].tag != 0x18) || (times[1].tag != 0x17 && times[1].tag != 0x18) { throw AttestError(OSSL.nested) }
        p = validity.end
        let subject = try readElem(der, p, tbs.end, 0x30)
        try checkName(der, subject)
        c.rawSubject = Array(der[subject.hdr..<subject.end])
        p = subject.end
        let spki = try readElem(der, p, tbs.end, 0x30)
        let sk = try kids(der, spki)
        if sk.count != 2 || sk[0].tag != 0x30 { throw AttestError(OSSL.nested) }
        _ = try algID(der, sk[0])
        try checkBitString(der, sk[1])
        c.rawSPKI = Array(der[spki.hdr..<spki.end])
        p = spki.end
        for uid: UInt8 in [0x81, 0x82] where p < tbs.end && der[p] == uid {
            let u = try readElem(der, p, tbs.end, uid)
            p = u.end
        }
        if p < tbs.end && der[p] == 0xa3 {
            let wrap = try readElem(der, p, tbs.end, 0xa3)
            let seq = try readElem(der, wrap.start, wrap.end, 0x30)
            if seq.end != wrap.end { throw AttestError(OSSL.nested) }
            for e in try kids(der, seq) {
                if e.tag != 0x30 { throw AttestError(OSSL.wrongTag) }
                let parts = try kids(der, e)
                if parts.count < 2 || parts.count > 3 || !validOID(der, parts[0]) { throw AttestError(OSSL.nested) }
                let oid: String
                do { oid = try DER.oidToDotted(der, DerTlv(tag: parts[0].tag, start: parts[0].start, end: parts[0].end)) } catch { throw AttestError(OSSL.object) }
                var critical = false
                var next = 1
                if parts.count == 3 {
                    if parts[1].tag != 0x01 || parts[1].end - parts[1].start != 1 { throw AttestError(OSSL.nested) }
                    critical = der[parts[1].start] != 0
                    next = 2
                }
                if parts[next].tag != 0x04 { throw AttestError(OSSL.wrongTag) }
                c.exts.append(LenientExt(oid: oid, critical: critical, value: Array(der[parts[next].start..<parts[next].end])))
            }
            p = wrap.end
        }
        if p != tbs.end { throw AttestError(OSSL.nested) }
        // the certificate as DER: the outer length in its minimal form, the content as supplied
        c.raw = lengthHeader(0x30, outer.end - outer.start) + Array(der[outer.start..<outer.end])
        return c
    }

    static func lengthHeader(_ tag: UInt8, _ n: Int) -> [UInt8] {
        if n < 0x80 { return [tag, UInt8(n)] }
        if n < 0x100 { return [tag, 0x81, UInt8(n)] }
        if n < 0x10000 { return [tag, 0x82, UInt8(n >> 8), UInt8(n & 0xff)] }
        if n < 0x1000000 { return [tag, 0x83, UInt8(n >> 16), UInt8(n >> 8 & 0xff), UInt8(n & 0xff)] }
        return [tag, 0x84, UInt8(n >> 24 & 0xff), UInt8(n >> 16 & 0xff), UInt8(n >> 8 & 0xff), UInt8(n & 0xff)]
    }

    // ---- PEM ----

    static let BEGIN = "-----BEGIN CERTIFICATE-----"
    static let END = "-----END CERTIFICATE-----"

    /// Every `-----BEGIN CERTIFICATE-----` ... `-----END CERTIFICATE-----` block of a text (non-overlapping, shortest match).
    static func pemBlocks(_ text: String) -> [String] {
        var out: [String] = []
        var rest = Substring(text)
        while let b = rest.range(of: BEGIN) {
            guard let e = rest.range(of: END, range: b.upperBound..<rest.endIndex) else { break }
            out.append(String(rest[b.lowerBound..<e.upperBound]))
            rest = rest[e.upperBound...]
        }
        return out
    }

    /// The first certificate block of a PEM text (PEM_read_bio_X509_AUX: bytes after the certificate inside the block are an error).
    static func fromPEM(_ text: String) throws -> AttCert {
        guard let block = pemBlocks(text).first else { throw AttestError("error:0480006C:PEM routines::no start line") }
        let body = block.dropFirst(BEGIN.count).dropLast(END.count)
        var stripped = ""
        for ch in body.unicodeScalars where ch != " " && ch != "\t" && ch != "\r" && ch != "\n" { stripped.unicodeScalars.append(ch) }
        guard let der = Attest.base64Std(stripped) else { throw AttestError(OSSL.unsupported) }
        let c = try parseDER(der)
        let outer = try readElem(der, 0, der.count, 0x30)
        if outer.end != der.count { throw AttestError(OSSL.nested) }
        return c
    }

    /// The bytes of the first PEM block of any type (`pem.Decode`); nil when there is none or its body is not base64.
    static func pemDecodeFirst(_ text: String) -> [UInt8]? {
        guard let b = text.range(of: "-----BEGIN ") else { return nil }
        let rest = text[b.upperBound...]
        guard let hdrEnd = rest.range(of: "-----"), let e = rest.range(of: "-----END ", range: hdrEnd.upperBound..<rest.endIndex) else { return nil }
        var body = ""
        for ch in rest[hdrEnd.upperBound..<e.lowerBound].unicodeScalars where ch != " " && ch != "\t" && ch != "\r" && ch != "\n" { body.unicodeScalars.append(ch) }
        return Attest.base64Std(body)
    }

    static func selfIssued(_ c: AttCert) -> Bool { c.rawSubject == c.rawIssuer }

    /// The serial number as lowercase hex without leading zeros.
    static func serialHex(_ c: AttCert) -> String { String(ACrypto.hex(c.serial).drop { $0 == "0" }) }

    // ---- keys and signatures ----

    static let OID_RSA = "1.2.840.113549.1.1.1"
    static let OID_RSA_PSS = "1.2.840.113549.1.1.10"
    static let OID_EC = "1.2.840.10045.2.1"
    static let OID_ED25519 = "1.3.101.112"

    /// A minimal DER INTEGER's magnitude (positive only), as Go's encoding/asn1 reads it.
    static func positiveInteger(_ b: [UInt8], _ e: CertElem) -> [UInt8]? {
        let c = Array(b[e.start..<e.end])
        if e.tag != 0x02 || c.isEmpty { return nil }
        if c.count > 1 && ((c[0] == 0 && c[1] & 0x80 == 0) || (c[0] == 0xff && c[1] & 0x80 != 0)) { return nil }
        if c[0] & 0x80 != 0 { return nil }
        let mag = Array(c.drop { $0 == 0 })
        return mag.isEmpty ? nil : mag
    }

    /// x509.ParsePKCS1PublicKey: SEQUENCE { INTEGER n, INTEGER e }, DER, positive, no trailing data.
    static func parsePKCS1(_ bits: [UInt8]) -> (n: [UInt8], e: [UInt8])? {
        guard let seq = try? readElem(bits, 0, bits.count, 0x30), seq.end == bits.count, let ks = try? kids(bits, seq), ks.count == 2,
              let n = positiveInteger(bits, ks[0]), let e = positiveInteger(bits, ks[1]) else { return nil }
        return (n, e)
    }

    static func curveName(_ oid: String) -> (ec: String, openssl: String)? {
        switch oid {
        case "1.2.840.10045.3.1.7": return ("P-256", "prime256v1")
        case "1.3.132.0.34": return ("P-384", "secp384r1")
        case "1.3.132.0.35": return ("P-521", "secp521r1")
        case "1.3.132.0.33": return ("P-224", "secp224r1")
        default: return nil
        }
    }

    /// The certificate's subject public key. An RSASSA-PSS key is read from its SubjectPublicKeyInfo as the RSAPublicKey it carries.
    static func keyOf(_ c: AttCert) throws -> CertKey { try keyOfSPKI(c.rawSPKI) }

    /// The public key of a DER SubjectPublicKeyInfo.
    static func keyOfSPKI(_ rawSPKI: [UInt8]) throws -> CertKey {
        let spki = try readElem(rawSPKI, 0, rawSPKI.count, 0x30)
        if spki.end != rawSPKI.count { throw AttestError(OSSL.unsupported) }
        let ks = try kids(rawSPKI, spki)
        if ks.count != 2 { throw AttestError(OSSL.nested) }
        let a = try algID(rawSPKI, ks[0])
        if ks[1].tag != 0x03 || ks[1].end - ks[1].start < 1 { throw AttestError(OSSL.wrongTag) }
        let bits = Array(rawSPKI[(ks[1].start + 1)..<ks[1].end])
        var k = CertKey()
        k.spki = rawSPKI
        switch a.oid {
        case OID_RSA, OID_RSA_PSS:
            guard let rk = parsePKCS1(bits) else { throw AttestError(OSSL.unsupported) }
            k.typ = a.oid == OID_RSA_PSS ? "rsa-pss" : "rsa"
            k.rsaN = rk.n
            k.rsaE = rk.e
            return k
        case OID_EC:
            guard rawSPKI[ks[1].start] == 0, let params = a.params, let pe = try? readElem(params, 0, params.count, 0x06),
                  let oid = try? DER.oidToDotted(params, DerTlv(tag: pe.tag, start: pe.start, end: pe.end)), let cn = curveName(oid) else {
                throw AttestError(OSSL.unsupported)
            }
            if !ACrypto.ecPointValid(curve: cn.ec, point: bits) { throw AttestError(OSSL.unsupported) }
            k.typ = "ec"
            k.curve = cn.openssl
            k.ecName = cn.ec
            k.point = bits
            return k
        case OID_ED25519:
            guard a.params == nil, rawSPKI[ks[1].start] == 0, bits.count == 32 else { throw AttestError(OSSL.unsupported) }
            k.typ = "ed25519"
            k.ed = bits
            return k
        default:
            throw AttestError(OSSL.unsupported)
        }
    }

    static let SIG_HASHES: [String: AHash] = [
        "1.2.840.10045.4.3.2": .sha256, "1.2.840.10045.4.3.3": .sha384, "1.2.840.10045.4.3.4": .sha512,
        "1.2.840.113549.1.1.11": .sha256, "1.2.840.113549.1.1.12": .sha384, "1.2.840.113549.1.1.13": .sha512,
    ]

    static let HASH_OIDS: [String: AHash] = [
        "2.16.840.1.101.3.4.2.1": .sha256, "2.16.840.1.101.3.4.2.2": .sha384, "2.16.840.1.101.3.4.2.3": .sha512, "1.3.14.3.2.26": .sha1,
    ]

    static func smallInt(_ b: [UInt8], _ e: CertElem) -> Int? {
        let c = Array(b[e.start..<e.end]).drop { $0 == 0 }
        if c.count > 3 || (e.end > e.start && b[e.start] & 0x80 != 0) { return nil }
        return c.reduce(0) { $0 << 8 | Int($1) }
    }

    /// RSASSA-PSS-params: the hash, the salt length, and whether the profile is one this verifier checks (MGF1 over the same hash,
    /// trailer field 1).
    static func pssParams(_ raw: [UInt8]?) -> (hash: AHash, salt: Int, ok: Bool) {
        guard let raw = raw, !raw.isEmpty else { return (.sha1, 20, true) }
        guard let seq = try? readElem(raw, 0, raw.count, 0x30), let ks = try? kids(raw, seq) else { return (.sha1, 0, false) }
        var h = AHash.sha1
        var salt = 20
        var mgfHash = AHash.sha1
        for k in ks {
            guard let inner = try? kids(raw, k), inner.count == 1 else { return (.sha1, 0, false) }
            switch k.tag {
            case 0xa0:
                guard let a = try? algID(raw, inner[0]), let hh = HASH_OIDS[a.oid] else { return (.sha1, 0, false) }
                h = hh
            case 0xa1:
                guard let a = try? algID(raw, inner[0]), a.oid == "1.2.840.113549.1.1.8", let params = a.params,
                      let pe = try? readElem(params, 0, params.count, 0x30), let ha = try? algID(params, pe), let mh = HASH_OIDS[ha.oid] else { return (.sha1, 0, false) }
                mgfHash = mh
            case 0xa2, 0xa3:
                guard inner[0].tag == 0x02, let v = smallInt(raw, inner[0]), v <= 1 << 20 else { return (.sha1, 0, false) }
                if k.tag == 0xa2 { salt = v } else if v != 1 { return (.sha1, 0, false) }
            default:
                return (.sha1, 0, false)
            }
        }
        return (h, salt, mgfHash == h)
    }

    /// X509Certificate.verify(publicKey): the certificate's signature under the key (no name or role checks).
    static func sigOK(_ child: AttCert, _ k: CertKey) -> Bool {
        if child.sigOID == OID_ED25519 { return k.typ == "ed25519" && ACrypto.ed25519Verify(pub: k.ed, message: child.rawTBS, sig: child.signature) }
        if child.sigOID == OID_RSA_PSS {
            let p = pssParams(child.sigParams)
            guard k.typ == "rsa" || k.typ == "rsa-pss", p.ok else { return false }
            return ACrypto.rsaVerifyPSS(n: k.rsaN, e: k.rsaE, hash: p.hash, message: child.rawTBS, sig: child.signature, saltLength: p.salt)
        }
        guard let h = SIG_HASHES[child.sigOID] else { return false }
        switch k.typ {
        case "ec":
            return child.sigOID.hasPrefix("1.2.840.10045.4.3.") && ACrypto.ecVerify(curve: k.ecName, point: k.point, hash: h, message: child.rawTBS, der: child.signature)
        case "rsa", "rsa-pss":
            return child.sigOID.hasPrefix("1.2.840.113549.1.1.") && ACrypto.rsaVerifyPKCS1(n: k.rsaN, e: k.rsaE, hash: h, message: child.rawTBS, sig: child.signature)
        default:
            return false
        }
    }

    /// `sigOK` under the subject key of `parent` (false when that key cannot be read).
    static func sigOKBy(_ child: AttCert, _ parent: AttCert) -> Bool {
        guard let k = try? keyOf(parent) else { return false }
        return sigOK(child, k)
    }

    /// The uncompressed SEC1 point of an EC key on exactly the named curve (P-256 or P-384).
    static func ecPoint(_ k: CertKey, _ curveName: String) throws -> [UInt8] {
        if k.typ != "ec" { throw AttestError("public key is not EC (got \(k.typ))") }
        if k.ecName != curveName { throw AttestError("public key is not on \(curveName) (got \(k.ecName))") }
        return k.point
    }

    // ---- extensions read by helpers (lenient: the strict readers judge the table) ----

    /// The OCSP responder URLs of the Authority Information Access extension.
    static func ocspServers(_ c: AttCert) -> [String] {
        guard let v = c.extValue("1.3.6.1.5.5.7.1.1"), let seq = try? readElem(v, 0, v.count, 0x30), let descs = try? kids(v, seq) else { return [] }
        var out: [String] = []
        for d in descs {
            guard let parts = try? kids(v, d), parts.count == 2, parts[0].tag == 0x06,
                  let method = try? DER.oidToDotted(v, DerTlv(tag: parts[0].tag, start: parts[0].start, end: parts[0].end)),
                  method == "1.3.6.1.5.5.7.48.1", parts[1].tag == 0x86 else { continue }
            out.append(String(decoding: v[parts[1].start..<parts[1].end], as: UTF8.self))
        }
        return out
    }

    /// The extended key usage extension lists id-kp-OCSPSigning.
    static func hasOCSPSigningEKU(_ c: AttCert) -> Bool {
        guard let v = c.extValue("2.5.29.37"), let seq = try? readElem(v, 0, v.count, 0x30), let purposes = try? kids(v, seq) else { return false }
        for p in purposes {
            if let oid = try? DER.oidToDotted(v, DerTlv(tag: p.tag, start: p.start, end: p.end)), oid == "1.3.6.1.5.5.7.3.9" { return true }
        }
        return false
    }

    // ---- certificate names (OpenSSL's multi-line rendering) ----

    static let DN_SHORT: [String: String] = [
        "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
        "2.5.4.5": "serialNumber", "2.5.4.9": "street", "2.5.4.17": "postalCode", "2.5.4.4": "SN", "2.5.4.42": "GN",
        "2.5.4.12": "title", "2.5.4.46": "dnQualifier", "1.2.840.113549.1.9.1": "emailAddress",
        "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
    ]

    static func escapeDNValue(_ s: String) -> String {
        var out = ""
        let rs = Array(s.unicodeScalars)
        for (i, r) in rs.enumerated() {
            if r == "," || r == "+" || r == "\"" || r == "\\" || r == "<" || r == ">" || r == ";" {
                out += "\\"
                out.unicodeScalars.append(r)
            } else if (i == 0 && (r == " " || r == "#")) || (i == rs.count - 1 && r == " ") {
                out += "\\"
                out.unicodeScalars.append(r)
            } else if r.value < 0x20 || r.value == 0x7f {
                out += "\\" + String(format: "%02X", r.value)
            } else {
                out.unicodeScalars.append(r)
            }
        }
        return out
    }

    /// An attribute value the way Go's asn1 decoder returns a string: validated per tag; nil where it would be an error.
    static func nameString(_ tag: UInt8, _ v: [UInt8]) -> String? {
        switch tag {
        case 0x0c: return String(validatingUTF8CString: v)
        case 0x13:
            let ok = v.allSatisfy { b in
                (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b == 0x20 || b == 0x27 || b == 0x28 || b == 0x29
                    || b == 0x2b || b == 0x2c || b == 0x2d || b == 0x2e || b == 0x2f || b == 0x3a || b == 0x3d || b == 0x3f || b == 0x2a || b == 0x26
            }
            return ok ? String(decoding: v, as: UTF8.self) : nil
        case 0x16: return v.allSatisfy { $0 < 0x80 } ? String(decoding: v, as: UTF8.self) : nil
        case 0x12: return v.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x20 } ? String(decoding: v, as: UTF8.self) : nil
        case 0x14: return String(decoding: v, as: UTF8.self)
        case 0x1e:
            if v.count % 2 != 0 { return nil }
            var u: [UInt16] = []
            var i = 0
            while i < v.count {
                u.append(UInt16(v[i]) << 8 | UInt16(v[i + 1]))
                i += 2
            }
            return String(decoding: u, as: UTF16.self)
        default: return nil
        }
    }

    /// A DER Name the way Node renders a certificate subject / issuer: one "KEY=value" per attribute, in encoded order, joined by
    /// newlines. "" when it does not decode.
    static func nameText(_ raw: [UInt8]) -> String {
        guard let seq = try? readElem(raw, 0, raw.count, 0x30), seq.end == raw.count, let rdns = try? kids(raw, seq) else { return "" }
        var lines: [String] = []
        for set in rdns {
            guard set.tag == 0x31, let atvs = try? kids(raw, set) else { return "" }
            var parts: [String] = []
            for atv in atvs {
                guard atv.tag == 0x30, let kv = try? kids(raw, atv), kv.count == 2,
                      var key = try? DER.oidToDotted(raw, DerTlv(tag: kv[0].tag, start: kv[0].start, end: kv[0].end)),
                      let val = nameString(kv[1].tag, Array(raw[kv[1].start..<kv[1].end])) else { return "" }
                if let sn = DN_SHORT[key] { key = sn }
                parts.append(key + "=" + escapeDNValue(val))
            }
            lines.append(parts.joined(separator: " + "))
        }
        return lines.joined(separator: "\n")
    }
}

extension String {
    /// UTF-8 text from bytes; nil when they are not valid UTF-8.
    init?(validatingUTF8CString v: [UInt8]) {
        guard let s = String(bytes: v, encoding: .utf8) else { return nil }
        self = s
    }
}
