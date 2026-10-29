import Foundation

// Compact-JWS plumbing shared by the Azure MAA and Google Confidential Space verifiers: the canonical base64url gate, the parsed
// token and the signature checks (ES256 and RS256) under a certificate or JWK key; plus the wording of the reference's
// JSON.parse failures (the token verifiers embed the engine's message for a malformed segment in their reason).

struct JwtParsed {
    var alg = ""
    var kid = ""
    var hasKid = false
    var x5c: [String] = []
    var hasX5c = false
    var payload: JObject = [:]
    var signingInput: [UInt8] = []
    var signature: [UInt8] = []
}

enum DERB {
    static func len(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        if n < 0x100 { return [0x81, UInt8(n)] }
        if n < 0x10000 { return [0x82, UInt8(n >> 8), UInt8(n & 0xff)] }
        return [0x83, UInt8(n >> 16 & 0xff), UInt8(n >> 8 & 0xff), UInt8(n & 0xff)]
    }

    static func tlv(_ tag: UInt8, _ c: [UInt8]) -> [UInt8] { [tag] + len(c.count) + c }

    /// A positive INTEGER from its big-endian magnitude.
    static func int(_ mag: [UInt8]) -> [UInt8] {
        let m = Array(mag.drop { $0 == 0 })
        let body = m.isEmpty ? [0] : (m[0] & 0x80 != 0 ? [0] + m : m)
        return tlv(0x02, body)
    }
}

enum JWS {
    /// One strictly canonical unpadded base64url segment (one spelling per value).
    static func decodeCanonical(_ seg: String) -> (bytes: [UInt8]?, error: String) {
        let u = Array(seg.utf8)
        for c in u where !((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c == 0x2d || c == 0x5f) {
            return (nil, "non-canonical compact JWS: bad-character")
        }
        if u.count % 4 == 1 { return (nil, "non-canonical compact JWS: non-canonical-base64url (impossible length)") }
        guard let b = Base64URLStrict.decode(seg) else { return (nil, "non-canonical compact JWS: non-canonical-base64url") }
        return (b, "")
    }

    /// The message to report for a header or payload segment that did not decode or parse.
    static func segmentError(_ h: String, _ p: String) -> String {
        for seg in [h, p] {
            let d = decodeCanonical(seg)
            guard let b = d.bytes else { return d.error }
            if Attest.jsonLenient(b) == nil {
                let msg = V8JSON.error(String(decoding: b, as: UTF8.self))
                return msg.isEmpty ? "invalid JSON" : msg
            }
        }
        return "invalid JSON"
    }

    /// Parse a compact JWS into header fields, payload and signing input; it verifies nothing. `prefix` is the reference parser's
    /// name (it leads every message).
    static func parse(_ token: String, _ prefix: String) throws -> JwtParsed {
        if token.isEmpty { throw AttestError("\(prefix): empty token") }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false).map { String($0) }
        if parts.count != 3 { throw AttestError("\(prefix): a compact JWS has exactly three dot-separated parts") }
        let h = parts[0], p = parts[1], s = parts[2]
        if h.isEmpty || p.isEmpty || s.isEmpty { throw AttestError("\(prefix): empty JWS segment") }
        var headerObj: JSONValue?
        var payloadObj: JSONValue?
        let hb = decodeCanonical(h)
        if let b = hb.bytes { headerObj = Attest.jsonLenient(b) }
        var ok = headerObj != nil
        if ok {
            let pb = decodeCanonical(p)
            if let b = pb.bytes { payloadObj = Attest.jsonLenient(b) }
            ok = payloadObj != nil
        }
        if !ok { throw AttestError("\(prefix): malformed JSON segment: \(segmentError(h, p))") }
        guard case let .object(hdr)? = headerObj else { throw AttestError("\(prefix): header is not a JSON object") }
        guard case let .object(payload)? = payloadObj else { throw AttestError("\(prefix): payload is not a JSON object") }
        let alg = hdr["alg"]?.asString ?? ""
        if alg.isEmpty { throw AttestError("\(prefix): header has no alg") }
        var out = JwtParsed()
        out.alg = alg
        out.payload = payload
        out.signingInput = Array((h + "." + p).utf8)
        if let kid = hdr["kid"]?.asString {
            out.kid = kid
            out.hasKid = true
        }
        if let l = Attest.asStrList(hdr["x5c"]) {
            out.x5c = l
            out.hasX5c = true
        }
        let sg = decodeCanonical(s)
        guard let sig = sg.bytes else { throw AttestError("\(prefix): malformed signature segment: \(sg.error)") }
        out.signature = sig
        return out
    }

    /// The kty / crv of a key's JWK export ("undefined" for a key type without a curve).
    static func ktyCrv(_ k: CertKey) -> (kty: String, crv: String) {
        switch k.typ {
        case "ec": return ("EC", k.ecName)
        case "rsa", "rsa-pss": return ("RSA", "undefined")
        case "ed25519": return ("OKP", "Ed25519")
        default: return (k.typ, "undefined")
        }
    }

    /// A raw r||s ES256 signature over the signing input under a P-256 key.
    static func es256OK(_ sig: [UInt8], _ input: [UInt8], _ k: CertKey) -> Bool {
        k.typ == "ec" && k.ecName == "P-256" && sig.count == 64 && ACrypto.ecVerify(curve: "P-256", point: k.point, hash: .sha256, message: input, raw: sig)
    }

    /// An RSASSA-PKCS1-v1_5 / SHA-256 signature under an RSA key.
    static func rs256OK(_ sig: [UInt8], _ input: [UInt8], _ k: CertKey) -> Bool {
        (k.typ == "rsa" || k.typ == "rsa-pss") && ACrypto.rsaVerifyPKCS1(n: k.rsaN, e: k.rsaE, hash: .sha256, message: input, sig: sig)
    }

    /// A public RSA key from base64url n / e.
    static func jwkRSAKey(_ n: String, _ e: String) throws -> CertKey {
        let nb = Array(Attest.nodeB64(n).drop { $0 == 0 }), eb = Array(Attest.nodeB64(e).drop { $0 == 0 })
        if nb.isEmpty || eb.isEmpty || eb.count > 4 { throw AttestError(OSSL.unsupported) }
        let ev = eb.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        if ev < 3 || ev > 1 << 31 - 1 { throw AttestError(OSSL.unsupported) }
        var k = CertKey()
        k.typ = "rsa"
        k.rsaN = nb
        k.rsaE = eb
        let rsaOID: [UInt8] = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
        let alg = DERB.tlv(0x30, rsaOID + [0x05, 0x00])
        let pk = DERB.tlv(0x30, DERB.int(nb) + DERB.int(eb))
        k.spki = DERB.tlv(0x30, alg + DERB.tlv(0x03, [0x00] + pk))
        return k
    }

    /// A public EC key from crv / x / y (on-curve points only).
    static func jwkECKey(_ crv: String, _ x: String, _ y: String) throws -> CertKey {
        let name: String, size: Int, curveOID: [UInt8], openssl: String
        switch crv {
        case "P-256": (name, size, curveOID, openssl) = ("P-256", 32, [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07], "prime256v1")
        case "P-384": (name, size, curveOID, openssl) = ("P-384", 48, [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], "secp384r1")
        case "P-521": (name, size, curveOID, openssl) = ("P-521", 66, [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], "secp521r1")
        default: throw AttestError(OSSL.unsupported)
        }
        let xb = Array(Attest.nodeB64(x).drop { $0 == 0 }), yb = Array(Attest.nodeB64(y).drop { $0 == 0 })
        if xb.count > size || yb.count > size { throw AttestError(OSSL.unsupported) }
        let point: [UInt8] = [0x04] + [UInt8](repeating: 0, count: size - xb.count) + xb + [UInt8](repeating: 0, count: size - yb.count) + yb
        if !ACrypto.ecPointValid(curve: name, point: point) { throw AttestError(OSSL.unsupported) }
        var k = CertKey()
        k.typ = "ec"
        k.curve = openssl
        k.ecName = name
        k.point = point
        let ecOID: [UInt8] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
        k.spki = DERB.tlv(0x30, DERB.tlv(0x30, ecOID + curveOID) + DERB.tlv(0x03, [0x00] + point))
        return k
    }
}

/// The wording of the reference's JSON.parse failures: `error` validates a document with the grammar of JSON.parse and, when it is
/// not valid, returns the message V8 reports for it ("" for a valid document). Only the reason text depends on this; whether a
/// segment parses never does.
struct V8JSON {
    var src: [UInt16]
    var pos = 0
    var err = ""

    static func error(_ text: String) -> String {
        var p = V8JSON(src: Array(text.utf16))
        p.value()
        if !p.err.isEmpty { return p.err }
        p.ws()
        if p.pos < p.src.count { p.fail("Unexpected non-whitespace character after JSON at position %ld (line %ld column %ld)", p.pos) }
        return p.err
    }

    func location(_ pos: Int) -> (Int, Int) {
        var line = 1
        var last = -1
        var i = 0
        while i < pos && i < src.count {
            let c = src[i]
            if c == 0x0a || (c == 0x0d && !(i + 1 < src.count && src[i + 1] == 0x0a)) {
                line += 1
                last = i
            }
            i += 1
        }
        return (line, pos - last)
    }

    /// Records the message; its format takes position, line and column.
    mutating func fail(_ format: String, _ pos: Int) {
        if !err.isEmpty { return }
        let (line, col) = location(pos)
        err = String(format: format, pos, line, col)
    }

    mutating func failExpected(_ what: String, _ pos: Int) { fail(what + " in JSON at position %ld (line %ld column %ld)", pos) }

    mutating func unexpectedEnd() { if err.isEmpty { err = "Unexpected end of JSON input" } }

    func text(_ a: Int, _ b: Int) -> String { String(decoding: Array(src[a..<b]), as: UTF16.self) }

    mutating func unexpectedToken(_ pos: Int) {
        if !err.isEmpty { return }
        let whole = text(0, src.count)
        if whole == "NaN" || whole == "Infinity" || whole == "undefined" || whole == "[object Object]" {
            err = "\"\(whole)\" is not valid JSON"
            return
        }
        let ctx = 10
        let tok = text(pos, pos + 1)
        let n = src.count
        if n < ctx * 2 + 1 {
            err = "Unexpected token '\(tok)', \"\(whole)\" is not valid JSON"
        } else if pos < ctx {
            err = "Unexpected token '\(tok)', \"\(text(0, pos + ctx))\"... is not valid JSON"
        } else if pos < n - ctx {
            err = "Unexpected token '\(tok)', ...\"\(text(pos - ctx, pos + ctx))\"... is not valid JSON"
        } else {
            err = "Unexpected token '\(tok)', ...\"\(text(pos - ctx, n))\" is not valid JSON"
        }
    }

    mutating func ws() {
        while pos < src.count {
            switch src[pos] {
            case 0x20, 0x09, 0x0a, 0x0d: pos += 1
            default: return
            }
        }
    }

    func peek() -> Int { pos >= src.count ? -1 : Int(src[pos]) }

    mutating func value() {
        ws()
        if !err.isEmpty { return }
        let c = peek()
        if c < 0 { unexpectedEnd() }
        else if c == 0x22 { str() }
        else if c == 0x7b { object() }
        else if c == 0x5b { array() }
        else if c == 0x2d || (c >= 0x30 && c <= 0x39) { number() }
        else if c == 0x74 { literal("true") }
        else if c == 0x66 { literal("false") }
        else if c == 0x6e { literal("null") }
        else { unexpectedToken(pos) }
    }

    mutating func literal(_ word: String) {
        for w in word.utf16 {
            if pos >= src.count {
                unexpectedEnd()
                return
            }
            if src[pos] != w {
                unexpectedToken(pos)
                return
            }
            pos += 1
        }
    }

    func isDigit(_ c: Int) -> Bool { c >= 0x30 && c <= 0x39 }

    mutating func number() {
        if peek() == 0x2d {
            pos += 1
            if !isDigit(peek()) {
                failExpected("No number after minus sign", pos)
                return
            }
        }
        if peek() == 0x30 {
            pos += 1
            if isDigit(peek()) {
                fail("Unexpected number in JSON at position %ld (line %ld column %ld)", pos)
                return
            }
        } else {
            while isDigit(peek()) { pos += 1 }
        }
        if peek() == 0x2e {
            pos += 1
            if !isDigit(peek()) {
                failExpected("Unterminated fractional number", pos)
                return
            }
            while isDigit(peek()) { pos += 1 }
        }
        let c = peek()
        if c == 0x65 || c == 0x45 {
            pos += 1
            let s = peek()
            if s == 0x2b || s == 0x2d { pos += 1 }
            if !isDigit(peek()) {
                failExpected("Exponent part is missing a number", pos)
                return
            }
            while isDigit(peek()) { pos += 1 }
        }
    }

    mutating func str() {
        pos += 1 // opening quote
        while true {
            let c = peek()
            if c < 0 {
                failExpected("Unterminated string", pos)
                return
            } else if c == 0x22 {
                pos += 1
                return
            } else if c < 0x20 {
                failExpected("Bad control character in string literal", pos)
                return
            } else if c == 0x5c {
                pos += 1
                let e = peek()
                switch e {
                case 0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74: pos += 1
                case 0x75:
                    pos += 1
                    for _ in 0..<4 {
                        let h = peek()
                        if !(isDigit(h) || (h >= 0x61 && h <= 0x66) || (h >= 0x41 && h <= 0x46)) {
                            failExpected("Bad Unicode escape", pos)
                            return
                        }
                        pos += 1
                    }
                case -1:
                    failExpected("Unterminated string", pos)
                    return
                default:
                    failExpected("Bad escaped character", pos)
                    return
                }
            } else {
                pos += 1
            }
        }
    }

    mutating func object() {
        pos += 1 // {
        ws()
        if peek() == 0x7d {
            pos += 1
            return
        }
        if peek() != 0x22 {
            failExpected("Expected property name or '}'", pos)
            return
        }
        while true {
            str()
            if !err.isEmpty { return }
            ws()
            if peek() != 0x3a {
                failExpected("Expected ':' after property name", pos)
                return
            }
            pos += 1
            value()
            if !err.isEmpty { return }
            ws()
            let c = peek()
            if c == 0x2c {
                pos += 1
                ws()
                if peek() != 0x22 {
                    failExpected("Expected double-quoted property name", pos)
                    return
                }
            } else if c == 0x7d {
                pos += 1
                return
            } else {
                failExpected("Expected ',' or '}' after property value", pos)
                return
            }
        }
    }

    mutating func array() {
        pos += 1 // [
        ws()
        if peek() == 0x5d {
            pos += 1
            return
        }
        while true {
            value()
            if !err.isEmpty { return }
            ws()
            let c = peek()
            if c == 0x2c {
                pos += 1
            } else if c == 0x5d {
                pos += 1
                return
            } else {
                failExpected("Expected ',' or ']' after array element", pos)
                return
            }
        }
    }
}
