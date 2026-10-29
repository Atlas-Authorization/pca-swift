import Foundation

// Strict DER readers shared by the hardware-attestation chain verifiers (the native counterpart of the strict X.509 helpers and
// the validity reader of @atlasauth/pca). The CA-role rules need the raw extension table and the validity instants without
// normalisation, so the rules are enforced from a small, strict walk of the certificate's own DER. Messages are the
// reference's, byte for byte.

struct AttestError: Error {
    let message: String
    init(_ m: String) { message = m }
}

struct DerTlv {
    var tag: UInt8
    var start: Int // content [start, end)
    var end: Int
}

enum DER {
    /// One definite-length element at `off` (inside `limit`). Minimal lengths only, no multi-byte tags.
    static func readTlvStrict(_ b: [UInt8], _ off: Int, _ limit: Int) throws -> DerTlv {
        let limit = min(limit, b.count)
        if off < 0 || off + 2 > limit { throw AttestError("DER: truncated header") }
        let tag = b[off]
        if tag & 0x1f == 0x1f { throw AttestError("DER: multi-byte tags are not supported") }
        var l = Int(b[off + 1])
        var p = off + 2
        if l & 0x80 != 0 {
            let n = l & 0x7f
            if n == 0 || n > 3 { throw AttestError("DER: unsupported length form") }
            if p + n > limit { throw AttestError("DER: truncated length") }
            l = 0
            if n > 1 && b[p] == 0 { throw AttestError("DER: non-minimal length (leading zero)") }
            for i in 0..<n { l = l << 8 | Int(b[p + i]) }
            if l < 0x80 { throw AttestError("DER: non-minimal length (long form below 128)") }
            p += n
        }
        if p + l > limit { throw AttestError("DER: element overruns its parent") }
        return DerTlv(tag: tag, start: p, end: p + l)
    }

    /// A lenient element reader (a long length of up to 4 octets, no minimality rule).
    static func tlvAt(_ der: [UInt8], _ off: Int) throws -> DerTlv {
        if off < 0 || off + 2 > der.count { throw AttestError("truncated") }
        let tag = der[off]
        var l = Int(der[off + 1])
        var start = off + 2
        if l & 0x80 != 0 {
            let n = l & 0x7f
            if n == 0 || n > 4 || start + n > der.count { throw AttestError("bad length") }
            l = 0
            for i in 0..<n { l = l * 256 + Int(der[start + i]) }
            start += n
        }
        let end = start + l
        if end > der.count { throw AttestError("truncated") }
        return DerTlv(tag: tag, start: start, end: end)
    }

    /// The same, inside an explicit limit (`tlvAt(b[:limit], off)`).
    static func tlvAt(_ der: [UInt8], _ off: Int, limit: Int) throws -> DerTlv {
        if limit >= der.count { return try tlvAt(der, off) }
        return try tlvAt(Array(der[0..<max(0, limit)]), off)
    }

    // ---- CA-role information ----

    struct RoleInfo {
        var hasBasicConstraints = false
        var ca = false
        var pathLen = -1
        var hasKeyUsage = false
        var keyCertSign = false
    }

    static let OID_BASIC_CONSTRAINTS: [UInt8] = [0x55, 0x1d, 0x13]
    static let OID_KEY_USAGE: [UInt8] = [0x55, 0x1d, 0x0f]

    static func oidEquals(_ b: [UInt8], _ t: DerTlv, _ want: [UInt8]) -> Bool {
        if t.tag != 0x06 || t.end - t.start != want.count { return false }
        for i in 0..<want.count where b[t.start + i] != want[i] { return false }
        return true
    }

    /// BasicConstraints and keyUsage of a DER certificate; throws on a malformed or duplicated extension.
    static func readCertRoleInfo(_ cert: [UInt8]) throws -> RoleInfo {
        var info = RoleInfo()
        let outer = try readTlvStrict(cert, 0, cert.count)
        if outer.tag != 0x30 { throw AttestError("certificate is not a DER SEQUENCE") }
        if outer.end != cert.count { throw AttestError("trailing bytes after the certificate") }
        let tbs = try readTlvStrict(cert, outer.start, outer.end)
        if tbs.tag != 0x30 { throw AttestError("certificate has no tbsCertificate") }
        var p = tbs.start
        while p < tbs.end {
            let el = try readTlvStrict(cert, p, tbs.end)
            p = el.end
            if el.tag != 0xa3 { continue }
            let seq = try readTlvStrict(cert, el.start, el.end)
            if seq.tag != 0x30 { throw AttestError("extensions is not a SEQUENCE") }
            var q = seq.start
            while q < seq.end {
                let ext = try readTlvStrict(cert, q, seq.end)
                q = ext.end
                if ext.tag != 0x30 { throw AttestError("extension is not a SEQUENCE") }
                let id = try readTlvStrict(cert, ext.start, ext.end)
                var r = id.end
                var next = try readTlvStrict(cert, r, ext.end)
                if next.tag == 0x01 {
                    r = next.end
                    next = try readTlvStrict(cert, r, ext.end)
                }
                if next.tag != 0x04 { throw AttestError("extension value is not an OCTET STRING") }
                if oidEquals(cert, id, OID_BASIC_CONSTRAINTS) {
                    if info.hasBasicConstraints { throw AttestError("duplicate BasicConstraints extension") }
                    info.hasBasicConstraints = true
                    let bc = try readTlvStrict(cert, next.start, next.end)
                    if bc.tag != 0x30 { throw AttestError("BasicConstraints is not a SEQUENCE") }
                    var c = bc.start
                    if c < bc.end {
                        let first = try readTlvStrict(cert, c, bc.end)
                        if first.tag == 0x01 {
                            if first.end - first.start != 1 { throw AttestError("BasicConstraints cA is not one byte") }
                            info.ca = cert[first.start] != 0
                            c = first.end
                        }
                    }
                    if c < bc.end {
                        let pl = try readTlvStrict(cert, c, bc.end)
                        if pl.tag != 0x02 || pl.end - pl.start < 1 || pl.end - pl.start > 2 || cert[pl.start] & 0x80 != 0 {
                            throw AttestError("BasicConstraints pathLenConstraint malformed")
                        }
                        var n = 0
                        for i in pl.start..<pl.end { n = n << 8 | Int(cert[i]) }
                        info.pathLen = n
                        c = pl.end
                    }
                    if c != bc.end { throw AttestError("BasicConstraints has trailing data") }
                } else if oidEquals(cert, id, OID_KEY_USAGE) {
                    if info.hasKeyUsage { throw AttestError("duplicate keyUsage extension") }
                    info.hasKeyUsage = true
                    let bs = try readTlvStrict(cert, next.start, next.end)
                    if bs.tag != 0x03 || bs.end - bs.start < 2 { throw AttestError("keyUsage is not a BIT STRING") }
                    if cert[bs.start] > 7 { throw AttestError("keyUsage BIT STRING has more than 7 unused bits") }
                    info.keyCertSign = cert[bs.start + 1] & 0x04 != 0
                }
            }
        }
        return info
    }

    // ---- the extension table ----

    struct CertExt {
        var critical: Bool
        var value: [UInt8]
    }

    /// Extensions in encounter order (the reference iterates a Map).
    struct ExtTable {
        var oids: [String] = []
        var m: [String: CertExt] = [:]
        func get(_ oid: String) -> CertExt? { m[oid] }
    }

    /// Decimal digits (most significant first) of a base-128 number given as its 7-bit groups.
    static func decimalOfBase128(_ groups: [UInt8]) -> [UInt8] {
        var digits: [UInt8] = [0]
        for g in groups {
            var carry = Int(g)
            var i = digits.count - 1
            while i >= 0 {
                let v = Int(digits[i]) * 128 + carry
                digits[i] = UInt8(v % 10)
                carry = v / 10
                i -= 1
            }
            while carry > 0 {
                digits.insert(UInt8(carry % 10), at: 0)
                carry /= 10
            }
        }
        while digits.count > 1 && digits[0] == 0 { digits.removeFirst() }
        return digits
    }

    static func decString(_ d: [UInt8]) -> String { String(decoding: d.map { $0 + 0x30 }, as: UTF8.self) }

    /// d - n (n < 1000, d >= n) on decimal digits.
    static func decSub(_ d: [UInt8], _ n: Int) -> [UInt8] {
        var lsd = d.reversed().map { Int($0) }
        var carry = n
        var i = 0
        while carry > 0 && i < lsd.count {
            var v = lsd[i] - carry % 10
            carry /= 10
            if v < 0 {
                v += 10
                carry += 1
            }
            lsd[i] = v
            i += 1
        }
        var out = lsd.reversed().map { UInt8($0) }
        while out.count > 1 && out[0] == 0 { out.removeFirst() }
        return out
    }

    static func oidToDotted(_ b: [UInt8], _ t: DerTlv) throws -> String {
        if t.tag != 0x06 || t.end <= t.start { throw AttestError("extension OID is malformed") }
        var arcs: [[UInt8]] = []
        var cur: [UInt8] = []
        var open = false
        for i in t.start..<t.end {
            let by = b[i]
            if !open && by == 0x80 { throw AttestError("extension OID has a non-minimal arc") }
            cur.append(by & 0x7f)
            open = by & 0x80 != 0
            if !open {
                arcs.append(decimalOfBase128(cur))
                cur = []
            }
        }
        if open { throw AttestError("extension OID is truncated") }
        let first = arcs[0]
        var parts: [String] = []
        if first.count <= 3, let v = Int(decString(first)) {
            if v < 40 { parts = ["0", String(v)] } else if v < 80 { parts = ["1", String(v - 40)] } else { parts = ["2", String(v - 80)] }
        } else {
            parts = ["2", decString(decSub(first, 80))]
        }
        for a in arcs.dropFirst() { parts.append(decString(a)) }
        return parts.joined(separator: ".")
    }

    /// The strict extension table of a tbsCertificate (the DER SEQUENCE including its header), keyed by dotted OID. Fails closed on a
    /// malformed element, a duplicate extension, more than one [3] block, a non-DER critical flag, trailing bytes, or an empty
    /// Extensions block.
    static func parseTbsExtensions(_ tbsDer: [UInt8]) throws -> ExtTable {
        let tbs = try readTlvStrict(tbsDer, 0, tbsDer.count)
        if tbs.tag != 0x30 { throw AttestError("tbsCertificate is not a SEQUENCE") }
        if tbs.end != tbsDer.count { throw AttestError("trailing bytes after tbsCertificate") }
        var out = ExtTable()
        var seen = false
        var blockEnd = -1
        var p = tbs.start
        while p < tbs.end {
            let el = try readTlvStrict(tbsDer, p, tbs.end)
            p = el.end
            if el.tag != 0xa3 { continue }
            if seen { throw AttestError("duplicate [3] extensions block") }
            seen = true
            blockEnd = el.end
            let seq = try readTlvStrict(tbsDer, el.start, el.end)
            if seq.tag != 0x30 { throw AttestError("extensions is not a SEQUENCE") }
            if seq.end != el.end { throw AttestError("trailing bytes after the Extensions SEQUENCE") }
            if seq.start == seq.end { throw AttestError("empty Extensions SEQUENCE") }
            var q = seq.start
            while q < seq.end {
                let ext = try readTlvStrict(tbsDer, q, seq.end)
                q = ext.end
                if ext.tag != 0x30 { throw AttestError("extension is not a SEQUENCE") }
                let id = try readTlvStrict(tbsDer, ext.start, ext.end)
                let dotted = try oidToDotted(tbsDer, id)
                var r = id.end
                var next = try readTlvStrict(tbsDer, r, ext.end)
                var critical = false
                if next.tag == 0x01 {
                    if next.end - next.start != 1 || tbsDer[next.start] != 0xff { throw AttestError("extension \(dotted) has a non-DER critical flag") }
                    critical = true
                    r = next.end
                    next = try readTlvStrict(tbsDer, r, ext.end)
                }
                if next.tag != 0x04 { throw AttestError("extension \(dotted) value is not an OCTET STRING") }
                if next.end != ext.end { throw AttestError("extension \(dotted) has trailing bytes") }
                if out.m[dotted] != nil { throw AttestError("duplicate extension \(dotted)") }
                out.oids.append(dotted)
                out.m[dotted] = CertExt(critical: critical, value: Array(tbsDer[next.start..<next.end]))
            }
        }
        if seen && blockEnd != tbs.end { throw AttestError("extensions block is not the last TBS element") }
        return out
    }

    /// The tbsCertificate bytes (header included) of a DER certificate; trailing bytes are refused.
    static func tbsOfCertificate(_ cert: [UInt8]) throws -> [UInt8] {
        let outer = try readTlvStrict(cert, 0, cert.count)
        if outer.tag != 0x30 { throw AttestError("certificate is not a DER SEQUENCE") }
        if outer.end != cert.count { throw AttestError("trailing bytes after the certificate") }
        let tbs = try readTlvStrict(cert, outer.start, outer.end)
        if tbs.tag != 0x30 { throw AttestError("certificate has no tbsCertificate") }
        return Array(cert[outer.start..<tbs.end])
    }

    static func parseCertExtensions(_ cert: [UInt8]) throws -> ExtTable {
        try parseTbsExtensions(try tbsOfCertificate(cert))
    }

    /// The only critical extensions the attestation chain verifiers understand.
    static let RECOGNISED_CRITICAL: Set<String> = ["2.5.29.19", "2.5.29.15"]

    /// The first critical extension OID the verifier does not recognise (RFC 5280 4.2), or nil.
    static func unrecognisedCriticalExtension(_ cert: [UInt8], _ recognised: Set<String>? = nil) throws -> String? {
        let rec = recognised ?? RECOGNISED_CRITICAL
        let t = try parseCertExtensions(cert)
        for oid in t.oids {
            if let e = t.m[oid], e.critical, !rec.contains(oid) { return oid }
        }
        return nil
    }

    /// The CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). The failure reason, or "" when the chain is fine.
    static func checkChainRoles(_ ordered: [[UInt8]]) -> String {
        let n = ordered.count
        for i in 0..<n {
            let info: RoleInfo
            do { info = try readCertRoleInfo(ordered[i]) } catch { return "certificate extension parse failed: " + ((error as? AttestError)?.message ?? "invalid") }
            if i == 0 && n > 1 {
                if info.ca { return "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)" }
                continue
            }
            if i == 0 { continue }
            if !info.hasBasicConstraints { return "issuer certificate at depth \(i) has no BasicConstraints (not a CA)" }
            if !info.ca { return "issuer certificate at depth \(i) is not a CA (BasicConstraints CA:FALSE)" }
            if info.hasKeyUsage && !info.keyCertSign { return "issuer certificate at depth \(i) keyUsage lacks keyCertSign" }
            if info.pathLen >= 0 && info.pathLen < i - 1 {
                return "issuer certificate at depth \(i) pathLenConstraint \(info.pathLen) is exceeded (\(i - 1) intermediate(s) below)"
            }
        }
        return ""
    }

    // ---- validity (read from the certificate's own DER) ----

    /// An epoch-millisecond instant, or nil (the reference's NaN).
    typealias Instant = Int64?

    static func isLeap(_ y: Int) -> Bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

    static func daysInMonth(_ y: Int, _ m: Int) -> Int {
        switch m {
        case 1, 3, 5, 7, 8, 10, 12: return 31
        case 4, 6, 9, 11: return 30
        default: return isLeap(y) ? 29 : 28
        }
    }

    /// Epoch milliseconds of a civil UTC instant; nil when a field is out of range (no roll-over).
    static func epochMs(_ y: Int, _ mo: Int, _ d: Int, _ h: Int, _ mi: Int, _ s: Int) -> Int64? {
        if mo < 1 || mo > 12 || d < 1 || d > daysInMonth(y, mo) || h < 0 || h > 23 || mi < 0 || mi > 59 || s < 0 || s > 59 { return nil }
        let yy = Int64(mo <= 2 ? y - 1 : y)
        let era = (yy >= 0 ? yy : yy - 399) / 400
        let yoe = yy - era * 400
        let mp = Int64((mo + 9) % 12)
        let doy = (153 * mp + 2) / 5 + Int64(d) - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        return (days * 86_400 + Int64(h) * 3_600 + Int64(mi) * 60 + Int64(s)) * 1000
    }

    static func allDigits(_ u: ArraySlice<UInt8>) -> Bool { !u.isEmpty && u.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }

    static func num(_ u: ArraySlice<UInt8>) -> Int { u.reduce(0) { $0 * 10 + Int($1 - 0x30) } }

    /// The strict RFC 5280 Time: tag 0x17 UTCTime YYMMDDHHMMSSZ (YY >= 50 is 19YY) or tag 0x18 GeneralizedTime YYYYMMDDHHMMSSZ,
    /// every field in range, no roll-over.
    static func parseDerTime(_ tag: Int, _ text: [UInt8]) -> Instant {
        var y = 0
        var rest: ArraySlice<UInt8>
        if tag == 0x17 && text.count == 13 {
            if !allDigits(text[0..<12]) || text[12] != 0x5a { return nil }
            let yy = num(text[0..<2])
            y = yy >= 50 ? 1900 + yy : 2000 + yy
            rest = text[2..<12]
        } else if tag == 0x18 && text.count == 15 {
            if !allDigits(text[0..<14]) || text[14] != 0x5a { return nil }
            y = num(text[0..<4])
            rest = text[4..<14]
        } else {
            return nil
        }
        let b = rest.startIndex
        return epochMs(y, num(rest[b..<(b + 2)]), num(rest[(b + 2)..<(b + 4)]), num(rest[(b + 4)..<(b + 6)]), num(rest[(b + 6)..<(b + 8)]), num(rest[(b + 8)..<(b + 10)]))
    }

    /// The validity window of a DER certificate (Certificate -> tbsCertificate -> validity); nil bounds when malformed.
    static func derValidity(_ der: [UInt8]) -> (from: Instant, to: Instant) {
        guard let cert = try? tlvAt(der, 0), cert.tag == 0x30, let tbs = try? tlvAt(der, cert.start), tbs.tag == 0x30 else { return (nil, nil) }
        var off = tbs.start
        guard var el = try? tlvAt(der, off) else { return (nil, nil) }
        if el.tag == 0xa0 {
            off = el.end
            guard let e2 = try? tlvAt(der, off) else { return (nil, nil) }
            el = e2
        }
        if el.tag != 0x02 { return (nil, nil) } // serialNumber
        guard let sigAlg = try? tlvAt(der, el.end), sigAlg.tag == 0x30 else { return (nil, nil) }
        guard let issuer = try? tlvAt(der, sigAlg.end), issuer.tag == 0x30 else { return (nil, nil) }
        guard let validity = try? tlvAt(der, issuer.end), validity.tag == 0x30, validity.end <= tbs.end else { return (nil, nil) }
        guard let nb = try? tlvAt(der, validity.start), let na = try? tlvAt(der, nb.end), na.end == validity.end else { return (nil, nil) }
        return (parseDerTime(Int(nb.tag), Array(der[nb.start..<nb.end])), parseDerTime(Int(na.tag), Array(der[na.start..<na.end])))
    }

    /// True iff both bounds parse and from - skew <= nowMs <= to + skew (fail closed on an unparseable bound).
    static func derValidAt(_ der: [UInt8], _ nowMs: Int64, _ skewMs: Int64) -> Bool {
        let (from, to) = derValidity(der)
        guard let f = from, let t = to else { return false }
        return nowMs &+ skewMs >= f && nowMs &- skewMs <= t
    }

    /// `derValidAt` with a fractional skew (milliseconds).
    static func derValidAtF(_ der: [UInt8], _ nowMs: Int64, _ skewMs: Double) -> Bool {
        let (from, to) = derValidity(der)
        guard let f = from, let t = to else { return false }
        return Double(nowMs) + skewMs >= Double(f) && Double(nowMs) - skewMs <= Double(t)
    }
}
