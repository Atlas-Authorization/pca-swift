import Foundation
import CryptoKit

/// Per-run identity material for the TLS mesh: one P-256 key and self-signed X.509 certificate per node. The key and the signature are
/// CryptoKit's; the certificate is assembled from a fixed DER template (version 3, ecdsa-with-SHA256, CN only, no extensions), so no X.509 stack is
/// needed. Keys come from the system CSPRNG, or deterministically from a caller seed (tests only: nothing is ever committed). Only the PUBLIC
/// certificates are exchanged and pinned.
public enum NetCerts {
    /// A node identity: PKCS#8 private key PEM and X.509 certificate PEM.
    public struct Identity {
        public let keyPem: String
        public let certPem: String
        public init(keyPem: String, certPem: String) { self.keyPem = keyPem; self.certPem = certPem }
    }

    public struct NetCertError: Error, CustomStringConvertible {
        public let description: String
        init(_ m: String) { description = m }
    }

    private static func tlv(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
        var len: [UInt8]
        if body.count < 128 { len = [UInt8(body.count)] } else {
            var b: [UInt8] = []
            var n = body.count
            while n > 0 { b.insert(UInt8(n & 0xff), at: 0); n >>= 8 }
            len = [0x80 | UInt8(b.count)] + b
        }
        return [tag] + len + body
    }

    private static let sigAlg: [UInt8] = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] // ecdsa-with-SHA256

    private static func name(_ cn: String) -> [UInt8] {
        let cnValue: [UInt8] = tlv(0x0c, Array(cn.utf8))
        let attr: [UInt8] = tlv(0x30, [0x06, 0x03, 0x55, 0x04, 0x03] + cnValue)
        return tlv(0x30, tlv(0x31, attr))
    }

    private static func utc(_ d: Date) -> [UInt8] {
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        let p = c.dateComponents([.year, .month, .day, .hour, .minute, .second], from: d)
        let text = String(format: "%02d%02d%02d%02d%02d%02dZ", (p.year ?? 2000) % 100, p.month ?? 1, p.day ?? 1, p.hour ?? 0, p.minute ?? 0, p.second ?? 0)
        return tlv(0x17, Array(text.utf8))
    }

    public static func pem(_ label: String, _ der: [UInt8]) -> String {
        let b64 = Array(Data(der).base64EncodedString().utf8)
        var lines: [String] = []
        var i = 0
        while i < b64.count {
            let j = min(i + 64, b64.count)
            lines.append(String(decoding: b64[i..<j], as: UTF8.self))
            i = j
        }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----\n"
    }

    /// The DER bytes of the first PEM block with `label`; throws when it is not one.
    public static func unpem(_ pem: String, _ label: String) throws -> [UInt8] {
        let head = "-----BEGIN \(label)-----", tail = "-----END \(label)-----"
        guard let a = pem.range(of: head), let b = pem.range(of: tail, range: a.upperBound..<pem.endIndex) else { throw NetCertError("not a \(label) PEM") }
        let body = String(pem[a.upperBound..<b.lowerBound].filter { !$0.isWhitespace })
        guard !body.isEmpty, let d = Data(base64Encoded: body) else { throw NetCertError("not a \(label) PEM") }
        return [UInt8](d)
    }

    /// Generate an identity for `cn`, valid from one hour ago for two days. `seed` (tests only) derives the key deterministically.
    public static func generate(cn: String, seed: [UInt8]? = nil, now: Date = Date()) throws -> Identity {
        guard cn.range(of: "^[A-Za-z0-9._-]{1,64}$", options: .regularExpression) != nil else { throw NetCertError("bad common name") }
        let key: P256.Signing.PrivateKey
        if let seed = seed {
            var ctr: UInt8 = 0
            var k: P256.Signing.PrivateKey? = nil
            while k == nil && ctr < 255 {
                k = try? P256.Signing.PrivateKey(rawRepresentation: Data(NetUtil.sha256([NetUtil.utf8("atlas-pca-mpc/test-identity"), seed, [ctr]])))
                ctr += 1
            }
            guard let kk = k else { throw NetCertError("cannot derive a key from the seed") }
            key = kk
        } else {
            key = P256.Signing.PrivateKey()
        }
        var serial = NetUtil.random(8)
        serial[0] = (serial[0] & 0x7f) | 0x01
        let subject = name(cn)
        let notBefore: [UInt8] = utc(now.addingTimeInterval(-3600))
        let notAfter: [UInt8] = utc(now.addingTimeInterval(2 * 86400))
        let validity: [UInt8] = tlv(0x30, notBefore + notAfter)
        // built in steps: one long `+` chain is more than the Linux compiler type-checks in reasonable time
        var tbsBody: [UInt8] = [0xa0, 0x03, 0x02, 0x01, 0x02]
        tbsBody += tlv(0x02, serial)
        tbsBody += sigAlg
        tbsBody += subject
        tbsBody += validity
        tbsBody += subject
        tbsBody += [UInt8](key.publicKey.derRepresentation)
        let tbs = tlv(0x30, tbsBody)
        let sig = [UInt8](try key.signature(for: Data(tbs)).derRepresentation)
        let sigBits: [UInt8] = tlv(0x03, [0x00] + sig)
        let cert = tlv(0x30, tbs + sigAlg + sigBits)
        return Identity(keyPem: key.pemRepresentation, certPem: pem("CERTIFICATE", cert))
    }

    /// SHA-256 (lowercase hex) of the certificate's DER bytes: the pin.
    public static func fingerprint(der: [UInt8]) -> String { NetUtil.hex(NetUtil.sha256([der])) }

    public static func fingerprint(certPem: String) throws -> String { fingerprint(der: try unpem(certPem, "CERTIFICATE")) }

    // MARK: DER reading (just enough to reach the SubjectPublicKeyInfo of a certificate)

    private static func read(_ b: [UInt8], _ off: Int) throws -> (tag: UInt8, start: Int, end: Int) {
        guard off + 2 <= b.count else { throw NetCertError("truncated DER") }
        let tag = b[off]
        var len = Int(b[off + 1])
        var p = off + 2
        if len & 0x80 != 0 {
            let n = len & 0x7f
            guard n >= 1 && n <= 3, p + n <= b.count else { throw NetCertError("bad DER length") }
            len = 0
            for i in 0..<n { len = len << 8 | Int(b[p + i]) }
            p += n
        }
        guard p + len <= b.count else { throw NetCertError("truncated DER") }
        return (tag, p, p + len)
    }

    /// The P-256 public key of a PEM certificate.
    public static func publicKey(certPem: String) throws -> P256.Signing.PublicKey {
        let der = try unpem(certPem, "CERTIFICATE")
        let cert = try read(der, 0)
        guard cert.tag == 0x30 else { throw NetCertError("not a certificate") }
        let tbs = try read(der, cert.start)
        guard tbs.tag == 0x30 else { throw NetCertError("not a certificate") }
        var off = tbs.start
        if try read(der, off).tag == 0xa0 { off = try read(der, off).end } // explicit version
        for _ in 0..<5 { off = try read(der, off).end } // serial, signature, issuer, validity, subject
        let spki = try read(der, off)
        guard spki.tag == 0x30 else { throw NetCertError("no public key") }
        return try P256.Signing.PublicKey(derRepresentation: Data(der[off..<spki.end]))
    }

    private static func utcValue(_ b: [UInt8], _ tag: UInt8) throws -> Date {
        let t = String(decoding: b, as: UTF8.self)
        let digits = tag == 0x18 ? 14 : 12
        guard t.hasSuffix("Z"), t.count == digits + 1, t.dropLast().allSatisfy({ $0.isASCII && $0.isNumber }) else { throw NetCertError("bad certificate time") }
        let n = t.dropLast().compactMap { Int(String($0)) }
        func two(_ i: Int) -> Int { n[i] * 10 + n[i + 1] }
        var year = tag == 0x18 ? two(0) * 100 + two(2) : (two(0) >= 50 ? 1900 + two(0) : 2000 + two(0))
        let o = tag == 0x18 ? 4 : 2
        if tag != 0x18 && year < 1950 { year = 2000 + two(0) }
        var c = Calendar(identifier: .gregorian)
        c.timeZone = TimeZone(identifier: "UTC")!
        guard let d = c.date(from: DateComponents(year: year, month: two(o), day: two(o + 2), hour: two(o + 4), minute: two(o + 6), second: two(o + 8))) else { throw NetCertError("bad certificate time") }
        return d
    }

    /// The validity window of a PEM certificate: (notBefore, notAfter).
    public static func validity(certPem: String) throws -> (notBefore: Date, notAfter: Date) {
        let der = try unpem(certPem, "CERTIFICATE")
        let cert = try read(der, 0)
        let tbs = try read(der, cert.start)
        var off = tbs.start
        if try read(der, off).tag == 0xa0 { off = try read(der, off).end }
        for _ in 0..<3 { off = try read(der, off).end } // serial, signature, issuer
        let v = try read(der, off)
        guard v.tag == 0x30 else { throw NetCertError("no validity") }
        let a = try read(der, v.start)
        let b = try read(der, a.end)
        guard a.tag == 0x17 || a.tag == 0x18, b.tag == 0x17 || b.tag == 0x18 else { throw NetCertError("bad certificate time") }
        return (try utcValue(Array(der[a.start..<a.end]), a.tag), try utcValue(Array(der[b.start..<b.end]), b.tag))
    }
}
