import Foundation

/// The SPIFFE / SPIRE workload-identity bridge (the reference @atlasauth/pca-spiffe): SPIFFE ID parsing, JWT-SVID and X.509-SVID
/// verification, the SVID -> PCA holder binding, trust-bundle and revocation caches that fail closed, and SPIFFE evidence for
/// blueprint admission. Every refusal is a JSError: the reference's SpiffeError code, or for a JOSE refusal the code the reference
/// library reports (ERR_JWT_EXPIRED, ERR_JWS_SIGNATURE_VERIFICATION_FAILED, ...).
public enum PCASpiffe {
    public static let CODES: Set<String> = [
        "malformed_spiffe_id", "empty_trust_domain", "trust_domain_too_long", "invalid_trust_domain", "invalid_path", "id_too_long",
        "missing_audience", "missing_exp", "malformed_token", "invalid_subject", "trust_domain_mismatch", "no_uri_san", "multiple_uri_san",
        "invalid_holder_key", "unverified_svid", "missing_trust_domain", "holder_binding_failed", "malformed_certificate", "leaf_is_ca",
        "leaf_no_digital_signature", "leaf_cert_sign", "leaf_crl_sign", "leaf_root_path", "unsupported_critical_extension",
        "forbidden_algorithm", "invalid_typ", "chain_empty", "chain_trust_domain_mismatch", "chain_signature", "chain_not_ca",
        "chain_no_key_cert_sign", "chain_path_len", "chain_expired", "chain_untrusted_root", "chain_too_long", "trust_bundle_unavailable",
        "trust_bundle_invalid", "svid_revoked", "chain_revoked", "revocation_unavailable",
    ]

    static func err(_ code: String, _ msg: String) -> JSError { JSError(msg, code: code) }

    /// A SpiffeError of the reference (a JSError carrying one of its codes).
    static func isSpiffeError(_ e: Error) -> JSError? {
        guard let j = e as? JSError, let c = j.code, CODES.contains(c) else { return nil }
        return j
    }

    static func message(_ e: Error) -> String { (e as? JSError)?.message ?? (e as? AttestError).map { "\($0)" } ?? "\(e)" }

    // ---- SPIFFE ID ----

    public struct SpiffeId: Equatable {
        public let id: String
        public let trustDomain: String
        /// With the leading "/"; "" for a bare trust-domain ID.
        public let path: String
        public var json: JSONValue { .object(["id": .string(id), "trustDomain": .string(trustDomain), "path": .string(path)]) }
    }

    static let SCHEME = "spiffe://"
    static let MAX_ID = 2048, MAX_TD = 255

    static func allIn(_ s: String, upper: Bool) -> Bool {
        !s.isEmpty && s.unicodeScalars.allSatisfy { c in
            switch c {
            case "a"..."z", "0"..."9", ".", "_", "-": return true
            case "A"..."Z": return upper
            default: return false
            }
        }
    }

    /// spiffe://<trust-domain>/<path>: lowercase scheme, a trust domain over [a-z0-9._-] of at most 255 units, path segments over
    /// [a-zA-Z0-9._-] with no empty, "." or ".." segment and no trailing slash, at most 2048 units in all (UTF-16 units).
    public static func parseSpiffeId(_ s: String) throws -> SpiffeId {
        if s.isEmpty { throw err("malformed_spiffe_id", "SPIFFE ID must be a non-empty string") }
        if JS.length(s) > MAX_ID { throw err("id_too_long", "SPIFFE ID exceeds \(MAX_ID) bytes") }
        // scalar views throughout: a combining mark must not merge with "/" as a Character would
        let u = Array(s.unicodeScalars), scheme = Array(SCHEME.unicodeScalars)
        guard u.starts(with: scheme) else { throw err("malformed_spiffe_id", "SPIFFE ID must begin with \"\(SCHEME)\"") }
        let rest = u.dropFirst(scheme.count)
        let slash = rest.firstIndex(of: "/")
        let tdU = slash.map { rest[..<$0] } ?? rest, pathU = slash.map { rest[$0...] } ?? []
        let str: (ArraySlice<Unicode.Scalar>) -> String = { String(String.UnicodeScalarView($0)) }
        let td = str(tdU), path = str(pathU)
        if td.isEmpty { throw err("empty_trust_domain", "SPIFFE ID has an empty trust domain") }
        if JS.length(td) > MAX_TD { throw err("trust_domain_too_long", "trust domain exceeds \(MAX_TD) bytes") }
        if !allIn(td, upper: false) { throw err("invalid_trust_domain", "trust domain \"\(td)\" must be lowercase and contain only [a-z0-9._-]") }
        if !pathU.isEmpty {
            if pathU.last == "/" { throw err("invalid_path", "SPIFFE ID path must not end with a trailing slash") }
            for segU in pathU.split(separator: "/", omittingEmptySubsequences: false).dropFirst() {
                let seg = str(segU)
                if seg.isEmpty { throw err("invalid_path", "SPIFFE ID path must not contain an empty segment") }
                if segU.elementsEqual(["."]) || segU.elementsEqual([".", "."]) { throw err("invalid_path", "SPIFFE ID path must not contain a \".\" or \"..\" segment") }
                if !allIn(seg, upper: true) { throw err("invalid_path", "SPIFFE ID path segment \"\(seg)\" contains an invalid character") }
            }
        }
        return SpiffeId(id: SCHEME + td + path, trustDomain: td, path: path)
    }

    // ---- the X.509 facts the SVID rules need, read from DER ----

    struct Tlv { var tag: UInt8; var start: Int; var end: Int }

    static func readTlv(_ b: [UInt8], _ off: Int, _ limit: Int) throws -> Tlv {
        if off + 2 > limit { throw JSError("der: truncated header") }
        let tag = b[off]
        if tag & 0x1f == 0x1f { throw JSError("der: high-tag-number form is not supported") }
        var n = Int(b[off + 1])
        var p = off + 2
        if n & 0x80 != 0 {
            let k = n & 0x7f
            if k == 0 || k > 4 { throw JSError("der: unsupported length form") }
            if p + k > limit { throw JSError("der: truncated length") }
            n = 0
            for i in 0..<k { n = n * 256 + Int(b[p + i]) }
            p += k
        }
        if p + n > limit { throw JSError("der: content exceeds container") }
        return Tlv(tag: tag, start: p, end: p + n)
    }

    static func children(_ b: [UInt8], _ parent: Tlv) throws -> [Tlv] {
        var out: [Tlv] = []
        var off = parent.start
        while off < parent.end {
            let t = try readTlv(b, off, parent.end)
            out.append(t)
            off = t.end
        }
        return out
    }

    /// Extensions understood well enough to ignore when marked critical.
    static let KNOWN_CRITICAL: Set<String> = ["551d0f", "551d11", "551d13", "551d25", "551d0e", "551d23"]

    struct Facts {
        var isCA = false
        var pathLen: Double? = nil
        var keyUsagePresent = false, digitalSignature = false, keyCertSign = false, crlSign = false
        var uriSANs: [String] = [], unknownCritical: [String] = []
        /// A BOOLEAN that is not one byte long (the reference's certificate parser refuses the certificate).
        var badBoolean = false
    }

    static func readCertFacts(_ der: [UInt8]) throws -> Facts {
        let cert = try readTlv(der, 0, der.count)
        if cert.tag != 0x30 || cert.end != der.count { throw JSError("der: certificate is not a single SEQUENCE") }
        guard let tbs = try children(der, cert).first, tbs.tag == 0x30 else { throw JSError("der: missing tbsCertificate") }
        var f = Facts()
        guard let wrap = try children(der, tbs).first(where: { $0.tag == 0xa3 }) else { return f }
        guard let extSeq = try children(der, wrap).first, extSeq.tag == 0x30 else { throw JSError("der: malformed extensions") }
        let at: (Int) -> Int = { $0 >= 0 && $0 < der.count ? Int(der[$0]) : -1 } // a JavaScript out-of-range read is undefined
        var seen: Set<String> = []
        for ext in try children(der, extSeq) {
            let parts = try children(der, ext)
            guard let o = parts.first, o.tag == 0x06 else { throw JSError("der: malformed extension") }
            let oid = ACrypto.hex(Array(der[o.start..<o.end]))
            if !seen.insert(oid).inserted { throw JSError("der: duplicate extension") }
            if parts.count == 3 && parts[1].tag == 0x01 && parts[1].end - parts[1].start != 1 { f.badBoolean = true }
            let critical = parts.count == 3 && parts[1].tag == 0x01 && at(parts[1].start) == 0xff
            let v = parts[parts.count - 1]
            if v.tag != 0x04 { throw JSError("der: malformed extension value") }
            if critical && !KNOWN_CRITICAL.contains(oid) { f.unknownCritical.append(oid) }
            let inner = try readTlv(der, v.start, v.end)
            switch oid {
            case "551d13":
                for c in try children(der, inner) {
                    if c.tag == 0x01 {
                        if c.end - c.start != 1 { f.badBoolean = true }
                        f.isCA = at(c.start) == 0xff
                    } else if c.tag == 0x02 {
                        var n = 0.0
                        for i in c.start..<c.end { n = n * 256 + Double(der[i]) }
                        f.pathLen = n
                    }
                }
            case "551d0f":
                if inner.tag != 0x03 || inner.end - inner.start < 2 { throw JSError("der: malformed keyUsage") }
                let b0 = der[inner.start + 1]
                f.keyUsagePresent = true
                f.digitalSignature = b0 & 0x80 != 0
                f.keyCertSign = b0 & 0x04 != 0
                f.crlSign = b0 & 0x02 != 0
            case "551d11":
                for gn in try children(der, inner) where gn.tag == 0x86 {
                    f.uriSANs.append(String(String.UnicodeScalarView(der[gn.start..<gn.end].map { Unicode.Scalar($0) })))
                }
            default: break
            }
        }
        return f
    }

    // ---- certificates ----

    /// A certificate as the reference reads one: PEM text (its first CERTIFICATE block), or bytes (PEM when they hold a PEM block,
    /// otherwise DER; bytes after a DER certificate are not part of it).
    public enum CertInput {
        case pem(String)
        case der([UInt8])
    }

    static func latin1(_ b: [UInt8]) -> String { String(String.UnicodeScalarView(b.map { Unicode.Scalar($0) })) }

    static func toCert(_ x: CertInput) throws -> AttCert {
        do {
            switch x {
            case let .pem(s): return try Cert.fromPEM(s)
            case let .der(b):
                let t = latin1(b)
                return t.contains("-----BEGIN") ? try Cert.fromPEM(t) : try Cert.parseDER(b)
            }
        } catch {
            throw err("malformed_certificate", "cannot parse certificate: \(message(error))")
        }
    }

    static func certsOf(_ x: CertInput) throws -> [AttCert] {
        guard case let .pem(s) = x else { return [try toCert(x)] }
        let blocks = Cert.pemBlocks(s)
        if blocks.isEmpty { throw err("malformed_certificate", "no PEM certificate found") }
        return try blocks.map { try toCert(.pem($0)) }
    }

    static func factsOf(_ c: AttCert) throws -> Facts {
        let f: Facts
        do { f = try readCertFacts(c.raw) } catch {
            throw err("malformed_certificate", "cannot read certificate extensions: \(message(error))")
        }
        if f.badBoolean { throw err("malformed_certificate", "cannot parse certificate: malformed BOOLEAN") }
        return f
    }

    /// The X509-SVID leaf rules (section 4.3).
    static func validateLeaf(_ c: AttCert) throws -> SpiffeId {
        let f = try factsOf(c)
        if !f.unknownCritical.isEmpty {
            throw err("unsupported_critical_extension", "certificate has an unsupported critical extension (\(f.unknownCritical.joined(separator: ", ")))")
        }
        if f.uriSANs.isEmpty { throw err("no_uri_san", "X.509-SVID certificate has no URI SAN") }
        if f.uriSANs.count > 1 { throw err("multiple_uri_san", "X.509-SVID certificate must have exactly one URI SAN, found \(f.uriSANs.count)") }
        let id = try parseSpiffeId(f.uriSANs[0])
        if id.path.isEmpty { throw err("leaf_root_path", "X.509-SVID leaf SPIFFE ID must have a non-root path") }
        if f.isCA { throw err("leaf_is_ca", "leaf certificate must not have the CA flag set to true") }
        if !f.digitalSignature { throw err("leaf_no_digital_signature", "leaf certificate must have 'digitalSignature' set as key usage") }
        if f.keyCertSign { throw err("leaf_cert_sign", "leaf certificate must not have 'keyCertSign' set as key usage") }
        if f.crlSign { throw err("leaf_crl_sign", "leaf certificate must not have 'cRLSign' set as key usage") }
        return id
    }

    static func validateSigner(_ c: AttCert, _ label: String) throws -> Facts {
        let f = try factsOf(c)
        if !f.unknownCritical.isEmpty {
            throw err("unsupported_critical_extension", "\(label) has an unsupported critical extension (\(f.unknownCritical.joined(separator: ", ")))")
        }
        if !f.isCA { throw err("chain_not_ca", "\(label) must have the CA flag set to true") }
        if !f.keyUsagePresent || !f.keyCertSign { throw err("chain_no_key_cert_sign", "\(label) must have 'keyCertSign' set as key usage") }
        return f
    }

    static func signedBy(_ c: AttCert, _ issuer: AttCert) -> Bool { Cert.checkIssued(c, issuer) && Cert.sigOKBy(c, issuer) }

    /// Uppercase hex, even length (as node:crypto prints serialNumber).
    static func serialHex(_ c: AttCert) -> String {
        var h = String(ACrypto.hex(c.serial).drop { $0 == "0" }).uppercased()
        if h.count % 2 == 1 { h = "0" + h }
        return h.isEmpty ? "00" : h
    }

    static func fingerprint256(_ c: AttCert) -> String {
        let h = Array(ACrypto.hex(ACrypto.sha256(c.raw)).uppercased())
        return stride(from: 0, to: h.count, by: 2).map { String(h[$0..<$0 + 2]) }.joined(separator: ":")
    }

    // ---- X.509-SVID ----

    /// A parsed X.509-SVID (only verifyX509Svid makes one that svidToHolder accepts). publicKeyDer is the base64url SPKI.
    public struct X509Svid {
        public let spiffeId: SpiffeId
        public let publicKeyDer: String
        let cert: AttCert
        let verified: Bool
    }

    /// A revocation check: sees one subject object, returns true when revoked; a throw is revocation_unavailable.
    public typealias RevocationCheck = (JObject) throws -> Bool

    public struct VerifyX509Options {
        public var trustDomain: String
        /// The trust-bundle authorities.
        public var roots: [CertInput]
        /// Epoch ms; nil = the wall clock.
        public var nowMs: Double? = nil
        public var maxChainLength: Int? = nil
        /// Runs last, for every certificate of the chain (leaf at position 0): {spiffeId, serialNumber, fingerprint256, position, isLeaf}.
        public var revocation: RevocationCheck? = nil
        public init(trustDomain: String, roots: [CertInput]) { self.trustDomain = trustDomain; self.roots = roots }
    }

    /// Parses an X.509-SVID and applies the leaf rules. It does NOT check the chain, validity or revocation: svidToHolder refuses it.
    public static func parseX509Svid(_ cert: CertInput) throws -> X509Svid {
        let c = try toCert(cert)
        let id = try validateLeaf(c)
        return X509Svid(spiffeId: id, publicKeyDer: Base64URLStrict.encode(c.rawSPKI), cert: c, verified: false)
    }

    /// Verifies an X.509-SVID against a trust bundle (X509-SVID section 4): the leaf rules, the trust domain, the validity of every
    /// certificate, CA / keyCertSign / pathLenConstraint of every signer, each certificate issued and signed by the next, a chain
    /// ending at (or signed by) an authority in roots; then revocation. chain is leaf first (a PEM item may hold several certificates).
    public static func verifyX509Svid(_ chain: [CertInput], _ o: VerifyX509Options) throws -> X509Svid {
        let items = try chain.flatMap { try certsOf($0) }
        if items.isEmpty { throw err("chain_empty", "certificate chain is empty") }
        if items.count > (o.maxChainLength ?? 8) { throw err("chain_too_long", "certificate chain is too long") }
        let leaf = items[0]
        let id = try validateLeaf(leaf)
        if id.trustDomain != o.trustDomain {
            throw err("chain_trust_domain_mismatch", "SPIFFE ID trust domain '\(id.trustDomain)' is not '\(o.trustDomain)'")
        }
        let roots = try o.roots.flatMap { try certsOf($0) }
        if roots.isEmpty { throw err("chain_untrusted_root", "trust bundle has no X.509 authorities") }
        let nowMs = Int64((o.nowMs ?? Date().timeIntervalSince1970 * 1000).rounded(.down))
        for c in items where !DER.derValidAt(c.raw, nowMs, 0) {
            throw err("chain_expired", "a certificate in the chain is not within its validity period")
        }
        // structure first: every signer is a CA with keyCertSign and a satisfied pathLenConstraint
        for i in items.indices.dropFirst() {
            let f = try validateSigner(items[i], "signing certificate #\(i)")
            if let p = f.pathLen, Double(i - 1) > p { throw err("chain_path_len", "signing certificate #\(i) pathLenConstraint exceeded") }
        }
        for i in 0..<(items.count - 1) where !signedBy(items[i], items[i + 1]) {
            throw err("chain_signature", "certificate #\(i) is not signed by certificate #\(i + 1)")
        }
        let isRoot: (AttCert) -> Bool = { c in roots.contains { $0.raw == c.raw } }
        let top = items[items.count - 1]
        if items.count == 1 && isRoot(leaf) { throw err("chain_untrusted_root", "a leaf certificate cannot be its own trust anchor") }
        if !(items.count > 1 && isRoot(top)) {
            guard let signer = roots.first(where: { signedBy(top, $0) }) else {
                throw err("chain_untrusted_root", "the chain does not lead to an authority in the trust bundle")
            }
            if !DER.derValidAt(signer.raw, nowMs, 0) { throw err("chain_expired", "the trust bundle authority is not within its validity period") }
            let f = try validateSigner(signer, "trust bundle authority")
            if let p = f.pathLen, Double(items.count - 1) > p { throw err("chain_path_len", "trust bundle authority pathLenConstraint exceeded") }
        }
        if let check = o.revocation {
            for (i, c) in items.enumerated() {
                let subject: JObject = ["spiffeId": .string(id.id), "serialNumber": .string(serialHex(c)), "fingerprint256": .string(fingerprint256(c)),
                                        "position": .int(Int64(i)), "isLeaf": .bool(i == 0)]
                let revoked: Bool
                do { revoked = try check(subject) } catch {
                    throw err("revocation_unavailable", "revocation check failed: \(message(error))")
                }
                if revoked && i == 0 { throw err("svid_revoked", "X.509-SVID for \(id.id) is revoked") }
                if revoked { throw err("chain_revoked", "signing certificate #\(i) of the chain is revoked") }
            }
        }
        return X509Svid(spiffeId: id, publicKeyDer: Base64URLStrict.encode(leaf.rawSPKI), cert: leaf, verified: true)
    }

    // ---- JWT-SVID ----

    /// The signature algorithms the JWT-SVID specification allows.
    public static let JWT_SVID_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]

    /// A verified JWT-SVID (only verifyJwtSvid makes one).
    public struct JwtSvid {
        public let spiffeId: SpiffeId
        public let claims: JObject
        /// The aud claim as a list ([] when absent).
        public let audience: JSONValue
        public let expiresAt: JSONValue
    }

    /// Resolves the verification key for a protected header and its (allowed) alg.
    public typealias KeyResolver = (_ header: JObject, _ alg: String) throws -> Jose.Key

    public struct VerifyJwtOptions {
        public var audience: [String]
        public var key: KeyResolver?
        public var trustDomain: String
        /// Unix seconds; nil = the wall clock.
        public var currentSec: Double? = nil
        /// nil = JWT_SVID_ALGORITHMS ("none" and HS* are always refused).
        public var algorithms: [String]? = nil
        /// Seconds (a number) or a period string such as "30s" / "2 minutes"; nil = 0.
        public var clockTolerance: JSONValue? = nil
        /// Runs last: {spiffeId, jti?, expiresAt, tokenHash}.
        public var revocation: RevocationCheck? = nil
        public init(audience: [String], key: KeyResolver?, trustDomain: String) { self.audience = audience; self.key = key; self.trustDomain = trustDomain }
    }

    static let PERIOD = try! NSRegularExpression(pattern: "^([+-])? ?([0-9]+|[0-9]+\\.[0-9]+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$", options: [.caseInsensitive])

    /// The reference library's clockTolerance: a number of seconds, or a period string.
    static func toleranceSecs(_ v: JSONValue?) throws -> Double {
        guard let v = v else { return 0 }
        if case let .string(s) = v {
            let ns = s as NSString
            guard let m = PERIOD.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { throw JSError("Invalid time period format") }
            let g: (Int) -> String? = { m.range(at: $0).location == NSNotFound ? nil : ns.substring(with: m.range(at: $0)) }
            if g(4) != nil && g(1) != nil { throw JSError("Invalid time period format") }
            let n = Double(g(2)!) ?? 0
            let u = g(3)!.lowercased()
            let mult: Double = u.hasPrefix("s") ? 1 : u.hasPrefix("m") ? 60 : u.hasPrefix("h") ? 3600 : u.hasPrefix("d") ? 86400 : u.hasPrefix("w") ? 604800 : 31557600
            let r = (n * mult + 0.5).rounded(.down)
            return g(1) == "-" || g(4)?.lowercased() == "ago" ? -r : r
        }
        guard v.isNumber, let n = IV.num(v) else { throw JSError("Invalid clockTolerance option type") }
        return n
    }

    /// Verifies a JWT-SVID: the canonical-spelling gate, the signature under key, the mandatory aud, exp / nbf, typ (JWT or JOSE when
    /// present), a SPIFFE sub pinned to trustDomain, then revocation.
    public static func verifyJwtSvid(_ token: String, _ o: VerifyJwtOptions) throws -> JwtSvid {
        if o.trustDomain.isEmpty {
            throw err("missing_trust_domain", "verifyJwtSvid requires `trustDomain` (an unpinned JWT-SVID would accept any trust domain the key signs for)")
        }
        if o.audience.isEmpty || o.audience.contains(where: { $0.isEmpty }) {
            throw err("missing_audience", "verifyJwtSvid requires a non-empty audience (JWT-SVID aud is mandatory)")
        }
        let algs = o.algorithms ?? JWT_SVID_ALGORITHMS
        let bad = algs.first { $0 == "none" || $0.uppercased().hasPrefix("HS") }
        if bad != nil || algs.isEmpty { throw err("forbidden_algorithm", "JWT-SVIDs must not use \(bad ?? "an empty algorithm list")") }
        let tol = try toleranceSecs(o.clockTolerance)
        // an invalid clock or a non-finite tolerance makes every exp/nbf comparison pass
        if let cs = o.currentSec, !cs.isFinite { throw err("malformed_token", "verifyJwtSvid: currentDate must be a valid Date") }
        if let ct = o.clockTolerance, ct.isNumber, !(tol.isFinite && tol >= 0) { throw err("malformed_token", "verifyJwtSvid: clockTolerance must be a finite number >= 0") }
        let c: Jose.CanonicalJws
        do { c = try Jose.assertCanonicalCompactJws(.string(token)) } catch { throw err("malformed_token", message(error)) }
        guard let resolve = o.key else { throw JSError("verifyJwtSvid requires a verification key") }
        let alg = try Jose.checkProtectedHeader(c.header, algorithms: algs)
        let key = try resolve(c.header, alg)
        let sig = try Jose.decodeCanonicalBase64url(c.segments[2])
        if !Jose.verifySignature(alg: alg, key: key, input: Array((c.segments[0] + "." + c.segments[1]).utf8), sig: sig) {
            throw JSError("signature verification failed", code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED")
        }
        try Jose.rejectUnencodedPayload(c.header)
        var vo = Jose.VerifyOptions()
        vo.audience = o.audience
        vo.clockTolerance = tol
        vo.now = (o.currentSec ?? Date().timeIntervalSince1970).rounded(.down)
        let payload = c.payload!
        try Jose.validateClaims(header: c.header, payload: payload, vo)
        if let typ = c.header["typ"], typ != .string("JWT"), typ != .string("JOSE") {
            throw err("invalid_typ", "JWT-SVID header typ must be JWT or JOSE, got '\(JS.toString(typ))'")
        }
        guard let exp = payload["exp"], exp.isNumber else { throw err("missing_exp", "JWT-SVID is missing the required \"exp\" claim") }
        guard let sub = payload["sub"]?.asString else { throw err("invalid_subject", "JWT-SVID \"sub\" must be a string SPIFFE ID") }
        let id: SpiffeId
        do { id = try parseSpiffeId(sub) } catch { throw err("invalid_subject", "JWT-SVID \"sub\" is not a valid SPIFFE ID: \(message(error))") }
        if id.trustDomain != o.trustDomain {
            throw err("trust_domain_mismatch", "JWT-SVID trust domain \"\(id.trustDomain)\" does not match expected \"\(o.trustDomain)\"")
        }
        let aud: JSONValue
        switch payload["aud"] {
        case nil: aud = .array([])
        case let .string(s)?: aud = .array([.string(s)])
        case let a?: aud = a
        }
        if let check = o.revocation {
            var s: JObject = ["spiffeId": .string(id.id), "expiresAt": exp, "tokenHash": .string(Base64URLStrict.encode(ACrypto.sha256(Array(token.utf8))))]
            if case let .string(j)? = payload["jti"] { s["jti"] = .string(j) }
            let revoked: Bool
            do { revoked = try check(s) } catch { throw err("revocation_unavailable", "revocation check failed: \(message(error))") }
            if revoked { throw err("svid_revoked", "JWT-SVID for \(id.id) is revoked") }
        }
        return JwtSvid(spiffeId: id, claims: payload, audience: aud, expiresAt: exp)
    }

    // ---- SPIFFE ID <-> PCA agent-holder identity ----

    public enum Svid {
        case x509(X509Svid)
        case jwt(JwtSvid)
    }

    public struct Holder: Equatable {
        public let holder: String
        public let spiffeId: String
        public let trustDomain: String
        public let path: String
        public var json: JSONValue {
            .object(["holder": .string(holder), "spiffeId": .string(spiffeId), "trustDomain": .string(trustDomain), "path": .string(path)])
        }
    }

    /// A holder key: base64url text or 32 raw bytes.
    public enum HolderKey {
        case b64u(String)
        case raw([UInt8])
    }

    public struct BindOptions {
        /// A base64url signature by the X.509-SVID key over holderBindingMessage (ECDSA as IEEE P1363 with SHA-256, SHA-384 for
        /// P-384; RSA PKCS#1 v1.5 SHA-256), required when the holder is not the SVID's own Ed25519 key.
        public var proof: String? = nil
        /// Admits a JWT-SVID without a matching cnf.jwk: set it ONLY when the holder key is authenticated by other means.
        public var acceptUnboundJwtHolder = false
        public init(proof: String? = nil, acceptUnboundJwtHolder: Bool = false) { self.proof = proof; self.acceptUnboundJwtHolder = acceptUnboundJwtHolder }
    }

    static func normalizeHolderKey(_ k: HolderKey) throws -> String {
        switch k {
        case let .raw(b):
            if b.count != 32 { throw err("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key") }
            return Base64URLStrict.encode(b)
        case let .b64u(s):
            guard let b = Base64URLStrict.decode(s, length: 32) else {
                throw err("invalid_holder_key", "holder key must be a 32-byte Ed25519 public key encoded as base64url")
            }
            return Base64URLStrict.encode(b)
        }
    }

    /// The domain-separated message a workload signs with its SVID key to bind a PCA holder key to its SPIFFE ID.
    public static func holderBindingMessage(_ spiffeId: String, _ holder: String) -> [UInt8] {
        Array("pca-spiffe-holder-binding-v1\n\(spiffeId)\n\(holder)".utf8)
    }

    static func proofOK(_ c: AttCert, _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
        guard let k = try? Cert.keyOf(c) else { return false }
        switch k.typ {
        case "ed25519": return ACrypto.ed25519Verify(pub: k.ed, message: msg, sig: sig)
        case "ec": return ACrypto.ecVerify(curve: k.ecName, point: k.point, hash: k.ecName == "P-384" ? .sha384 : .sha256, message: msg, raw: sig)
        case "rsa": return ACrypto.rsaKeyOK(n: k.rsaN, e: k.rsaE) && ACrypto.rsaVerifyPKCS1(n: k.rsaN, e: k.rsaE, hash: .sha256, message: msg, sig: sig)
        default: return false
        }
    }

    /// Binds a VERIFIED SVID (what verifyJwtSvid / verifyX509Svid returned; anything else, nil included, is unverified_svid) to a PCA
    /// holder. An X.509-SVID with an Ed25519 key: the holder IS that key unless another is given with o.proof. A JWT-SVID: its cnf.jwk
    /// must be the holder unless o.acceptUnboundJwtHolder.
    public static func svidToHolder(_ svid: Svid?, _ holderKey: HolderKey? = nil, _ o: BindOptions = BindOptions()) throws -> Holder {
        let unverified = err("unverified_svid", "svidToHolder needs the result of verifyJwtSvid / verifyX509Svid (a string, a parsed-only SVID or a hand-built object is not accepted)")
        let id: SpiffeId
        let holder: String
        switch svid {
        case let .x509(s)?:
            guard s.verified else { throw unverified }
            id = s.spiffeId
            let certEd: String? = (try? Cert.keyOf(s.cert)).flatMap { $0.typ == "ed25519" ? Base64URLStrict.encode($0.ed) : nil }
            if let hk = holderKey {
                holder = try normalizeHolderKey(hk)
                if certEd != holder {
                    guard let proof = o.proof else {
                        throw err("holder_binding_failed", "the holder key is not the SVID key: opts.proof (a signature by the SVID key over holderBindingMessage) is required")
                    }
                    guard let sig = Base64URLStrict.decode(proof), proofOK(s.cert, holderBindingMessage(id.id, holder), sig) else {
                        throw err("holder_binding_failed", "opts.proof does not verify under the X.509-SVID key")
                    }
                }
            } else {
                guard let ed = certEd else {
                    throw err("invalid_holder_key", "the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof")
                }
                holder = try normalizeHolderKey(.b64u(ed))
            }
        case let .jwt(s)?:
            id = s.spiffeId
            guard let hk = holderKey else { throw err("invalid_holder_key", "a JWT-SVID has no key of its own: pass holderKey") }
            holder = try normalizeHolderKey(hk)
            let jwk = s.claims["cnf"]?.get("jwk")
            let bound = jwk?.get("kty") == .string("OKP") && jwk?.get("crv") == .string("Ed25519") && jwk?.get("x") == .string(holder)
            if !bound && !o.acceptUnboundJwtHolder {
                throw err("holder_binding_failed", "the JWT-SVID carries no cnf.jwk equal to the holder key (set acceptUnboundJwtHolder only if the key is authenticated by other means)")
            }
        case nil:
            throw unverified
        }
        return Holder(holder: holder, spiffeId: id.id, trustDomain: id.trustDomain, path: id.path)
    }

    /// The validated, canonical SPIFFE ID a holder was bridged from.
    public static func holderToSpiffeId(_ spiffeId: String) throws -> String { try parseSpiffeId(spiffeId).id }

    /// The SPIFFE ID the spiffe_bound caveat compares: the identity of a VERIFIED SVID, only when it is bound to leafHolder.
    public static func spiffeIdForHolder(_ svid: Svid?, _ leafHolder: String, _ o: BindOptions = BindOptions()) throws -> String {
        let h = try svidToHolder(svid, .b64u(leafHolder), o)
        if h.holder != leafHolder { throw err("holder_binding_failed", "the SVID is not bound to the PCActn leaf holder") }
        return h.spiffeId
    }

    /// A discharge-issuer pin for a workload: its own Ed25519 X.509-SVID key and SPIFFE ID, class "workload".
    public static func workloadDischargePin(_ label: String, _ svid: X509Svid) throws -> JObject {
        let h = try svidToHolder(.x509(svid))
        return ["label": .string(label), "class": .string("workload"), "pk": .string(h.holder), "spiffe_id": .string(h.spiffeId)]
    }

    // ---- trust-bundle and revocation caches (fail closed) ----

    /// Returns the fetched value; nil = undefined. May throw.
    public typealias Fetch = () throws -> JSONValue?

    static func checkWindows(_ refreshMs: Double, _ maxStaleMs: Double, _ code: String) throws {
        if !(refreshMs.isFinite && refreshMs > 0) || !(maxStaleMs.isFinite && maxStaleMs >= refreshMs) {
            throw err(code, "refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)")
        }
    }

    static func wallMs() -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }

    /// A trust-bundle cache that fails closed: before the first successful fetch, or more than maxStaleMs after the last one, every
    /// call refuses (trust_bundle_unavailable when the fetch failed, trust_bundle_invalid when the bundle had no authorities). The
    /// fetched bundle is its JSON object form {"jwks": {"keys": [...]}, "x509Authorities": [PEM, ...]}; a refresh REPLACES it.
    public final class TrustBundleSource {
        let fetch: Fetch
        let refreshMs: Double, maxStaleMs: Double
        let now: () -> Double
        var good: (bundle: JObject, at: Double)?
        var lastFailure: JSError?
        let lock = NSLock()

        public init(fetch: @escaping Fetch, refreshMs: Double, maxStaleMs: Double, now: (() -> Double)? = nil) throws {
            try checkWindows(refreshMs, maxStaleMs, "trust_bundle_unavailable")
            self.fetch = fetch
            self.refreshMs = refreshMs
            self.maxStaleMs = maxStaleMs
            self.now = now ?? wallMs
        }

        static func nonEmptyList(_ v: JSONValue?) -> Bool { !(v?.asArray?.isEmpty ?? true) }

        func refresh() {
            do {
                let b = try fetch()
                guard let m = b?.asObject else { throw err("trust_bundle_invalid", "fetched trust bundle has no authorities") }
                // the reference reads .keys of it: a failed fetch, not an invalid bundle
                if m["jwks"] == .null { throw JSError("Cannot read properties of null (reading 'keys')") }
                if !Self.nonEmptyList(m["jwks"]?.get("keys")) && !Self.nonEmptyList(m["x509Authorities"]) {
                    throw err("trust_bundle_invalid", "fetched trust bundle has no authorities")
                }
                good = (m, now())
                lastFailure = nil
            } catch {
                lastFailure = isSpiffeError(error) ?? err("trust_bundle_unavailable", "trust bundle fetch failed: \(message(error))")
            }
        }

        func current() throws -> JObject {
            lock.lock(); defer { lock.unlock() }
            if good == nil || !(now() - good!.at < refreshMs) { refresh() }
            guard let g = good, (now() - g.at).isFinite, now() - g.at <= maxStaleMs else {
                throw lastFailure ?? err("trust_bundle_unavailable", "no trust bundle available")
            }
            return g.bundle
        }

        /// The key resolver for VerifyJwtOptions.key.
        public func jwtKey(_ header: JObject, _ alg: String = "") throws -> Jose.Key {
            guard let jwks = try current()["jwks"] else { throw err("trust_bundle_invalid", "trust bundle has no JWT authorities") }
            guard let keys = jwks.get("keys")?.asArray else { throw JSError("Cannot read properties of undefined (reading 'length')") }
            if keys.isEmpty { throw err("trust_bundle_invalid", "trust bundle has no JWT authorities") }
            return try OidcLocalJwks(jwks).select(header).key
        }

        /// The authorities for VerifyX509Options.roots (as fetched: PEM text, or {"$bytes"} DER).
        public func x509Roots() throws -> [JSONValue] {
            guard let roots = try current()["x509Authorities"] else { throw err("trust_bundle_invalid", "trust bundle has no X.509 authorities") }
            switch roots {
            case let .array(a) where !a.isEmpty: return a
            case let .string(s) where !s.isEmpty: return s.map { .string(String($0)) } // the reference spreads it
            case .array, .string: throw err("trust_bundle_invalid", "trust bundle has no X.509 authorities")
            default: throw JSError("roots is not iterable")
            }
        }
    }

    /// A revocation snapshot cache that fails closed, in the shape of TrustBundleSource. The list is its JSON object form, optional
    /// string lists fingerprints, serials, spiffeIds, jtis and tokenHashes. x509 uses the cached snapshot (call ensureFresh first);
    /// jwt refreshes when due. Both are RevocationChecks.
    public final class RevocationSource {
        struct Snapshot { var fingerprints, serials, spiffeIds, jtis, tokenHashes: Set<String> }
        let fetch: Fetch
        let refreshMs: Double, maxStaleMs: Double
        let now: () -> Double
        var good: (snap: Snapshot, at: Double)?
        var lastFailure: JSError?
        let lock = NSLock()

        public init(fetch: @escaping Fetch, refreshMs: Double, maxStaleMs: Double, now: (() -> Double)? = nil) throws {
            try checkWindows(refreshMs, maxStaleMs, "revocation_unavailable")
            self.fetch = fetch
            self.refreshMs = refreshMs
            self.maxStaleMs = maxStaleMs
            self.now = now ?? wallMs
        }

        static func normHex(_ s: String) -> String { s.replacingOccurrences(of: ":", with: "").uppercased() }
        static func normSerial(_ s: String) -> String {
            let h = normHex(s)
            let t = String(h.drop { $0 == "0" })
            return t.isEmpty && !h.isEmpty ? "0" : t
        }

        static func snapshot(_ v: JSONValue?) throws -> Snapshot {
            guard let m = v?.asObject else { throw err("revocation_unavailable", "revocation list must be an object") }
            func list(_ k: String, _ norm: (String) -> String = { $0 }) throws -> Set<String> {
                guard let x = m[JKey(k)] else { return [] }
                guard let a = x.asArray, a.allSatisfy({ $0.asString != nil }) else {
                    throw err("revocation_unavailable", "revocation list field \"\(k)\" must be an array of strings")
                }
                return Set(a.compactMap { $0.asString }.map(norm))
            }
            return Snapshot(fingerprints: try list("fingerprints", normHex), serials: try list("serials", normSerial),
                            spiffeIds: try list("spiffeIds"), jtis: try list("jtis"), tokenHashes: try list("tokenHashes"))
        }

        func run() {
            do {
                good = (try Self.snapshot(try fetch()), now())
                lastFailure = nil
            } catch {
                lastFailure = isSpiffeError(error) ?? err("revocation_unavailable", "revocation fetch failed: \(message(error))")
            }
        }

        func usable() throws -> Snapshot {
            guard let g = good, (now() - g.at).isFinite, now() - g.at <= maxStaleMs else {
                throw lastFailure ?? err("revocation_unavailable", "no revocation snapshot available")
            }
            return g.snap
        }

        func fresh() throws -> Snapshot {
            if good == nil || !(now() - good!.at < refreshMs) { run() }
            return try usable()
        }

        /// Fetches now; refuses when the fetch fails or returns a malformed list (the previous snapshot stays).
        public func refresh() throws {
            lock.lock(); defer { lock.unlock() }
            run()
            if let f = lastFailure { throw f }
        }

        /// Fetches when the snapshot is older than refreshMs; refuses when no snapshot younger than maxStaleMs exists after.
        public func ensureFresh() throws {
            lock.lock(); defer { lock.unlock() }
            _ = try fresh()
        }

        /// A VerifyX509Options.revocation check over the cached snapshot.
        public func x509(_ s: JObject) throws -> Bool {
            lock.lock(); defer { lock.unlock() }
            let snap = try usable()
            return snap.fingerprints.contains(Self.normHex(JS.toString(s["fingerprint256"]))) || snap.serials.contains(Self.normSerial(JS.toString(s["serialNumber"])))
                || snap.spiffeIds.contains(JS.toString(s["spiffeId"]))
        }

        /// A VerifyJwtOptions.revocation check; refreshes the snapshot when due.
        public func jwt(_ s: JObject) throws -> Bool {
            lock.lock(); defer { lock.unlock() }
            let snap = try fresh()
            return snap.spiffeIds.contains(JS.toString(s["spiffeId"])) || (s["jti"].map { snap.jtis.contains(JS.toString($0)) } ?? false)
                || snap.tokenHashes.contains(JS.toString(s["tokenHash"]))
        }
    }

    // ---- evidence for blueprint admission ----

    public enum Evidence {
        case x509(chain: [CertInput], verify: VerifyX509Options, bind: BindOptions)
        case jwt(token: String, verify: VerifyJwtOptions, bind: BindOptions)
    }

    /// Admits a workload under its verified SPIFFE ID: the SVID is verified, then bound to the INSTANCE KEY. Anything unverifiable,
    /// unbound or bound to another key is {ok: false, bound: false, reason}.
    public static func spiffeAdmissionEvidence(_ e: Evidence, _ instanceKey: String) -> JSONValue {
        do {
            let svid: Svid, bind: BindOptions
            switch e {
            case let .x509(chain, v, b): svid = .x509(try verifyX509Svid(chain, v)); bind = b
            case let .jwt(token, v, b): svid = .jwt(try verifyJwtSvid(token, v)); bind = b
            }
            let h = try svidToHolder(svid, .b64u(instanceKey), bind)
            if h.holder != instanceKey { return .object(["ok": .bool(false), "bound": .bool(false), "reason": .string("SVID is bound to a different key")]) }
            return .object(["ok": .bool(true), "bound": .bool(true), "identity": .object(["spiffe_id": .string(h.spiffeId)])])
        } catch {
            return .object(["ok": .bool(false), "bound": .bool(false), "reason": .string((error as? JSError)?.code ?? "Error")])
        }
    }
}
