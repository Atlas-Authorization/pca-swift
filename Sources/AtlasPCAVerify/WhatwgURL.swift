import Foundation

/// The parts of an absolute URL the protocol bridges read, parsed the way the WHATWG URL standard (the reference's platform
/// `URL` class) parses them: scheme, serialized host[:port], pathname (dot segments resolved, percent-encoded), search and origin.
/// nil when the platform class would refuse the text.
/// shortcut: a non-ASCII host is refused unless AtlasPCAAda registered a UTS 46 domain-to-ASCII (fail closed), and file: drive letters are not
/// special-cased; upgrade when a caller needs them.
public struct WhatwgURL: Equatable {
    public let scheme: String
    /// host[:port] (the port only when it is not the scheme's default).
    public let host: String
    public let pathname: String
    /// protocol//host + pathname (no query, no fragment).
    public let htu: String
    /// scheme://host for a special scheme.
    public let origin: String?
    /// "" or "?..." for a special scheme.
    public let search: String?

    static let special: [String: Int] = ["ftp": 21, "file": -1, "http": 80, "https": 443, "ws": 80, "wss": 443]

    static func pct(_ s: [Unicode.Scalar], extra: String, controlsOnly: Bool = false) -> String {
        var out = ""
        for ch in s {
            let o = ch.value
            if o < 0x20 || o > 0x7E || (!controlsOnly && (o == 0x20 || extra.unicodeScalars.contains(ch))) {
                for b in String(ch).utf8 { out += String(format: "%%%02X", b) }
            } else {
                out.unicodeScalars.append(ch)
            }
        }
        return out
    }

    static func hexVal(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x37
        case 0x61...0x66: return c - 0x57
        default: return nil
        }
    }

    static func pctDecode(_ s: [Unicode.Scalar]) -> [UInt8] {
        let raw = Array(String(String.UnicodeScalarView(s)).utf8)
        var out: [UInt8] = []
        var i = 0
        while i < raw.count {
            if raw[i] == 0x25, i + 2 < raw.count, let h = hexVal(raw[i + 1]), let l = hexVal(raw[i + 2]) {
                out.append(h << 4 | l); i += 3
            } else { out.append(raw[i]); i += 1 }
        }
        return out
    }

    /// One IPv4 part: decimal, 0x hex or leading-0 octal; saturates (any oversized part fails the range check anyway).
    static func ipv4Number(_ p: [Unicode.Scalar]) -> UInt64? {
        if p.isEmpty { return nil }
        var part = p[...], radix: UInt64 = 10
        if p.count >= 2, p[0] == "0", p[1] == "x" || p[1] == "X" { part = p[2...]; radix = 16 }
        else if p.count >= 2, p[0] == "0" { part = p[1...]; radix = 8 }
        if part.isEmpty { return 0 }
        var v: UInt64 = 0
        for c in part {
            guard c.isASCII, let d = hexVal(UInt8(c.value)), UInt64(d) < radix else { return nil }
            let (m, o1) = v.multipliedReportingOverflow(by: radix)
            let (a, o2) = m.addingReportingOverflow(UInt64(d))
            v = (o1 || o2) ? UInt64.max : a
        }
        return v
    }

    static func dotParts(_ host: [Unicode.Scalar]) -> [[Unicode.Scalar]] { host.split(separator: ".", omittingEmptySubsequences: false).map(Array.init) }

    static func endsInNumber(_ host: [Unicode.Scalar]) -> Bool {
        var parts = dotParts(host)
        if parts.last?.isEmpty == true {
            if parts.count == 1 { return false }
            parts.removeLast()
        }
        guard let last = parts.last, !last.isEmpty else { return false }
        return last.allSatisfy { $0.value >= 0x30 && $0.value <= 0x39 } || ipv4Number(last) != nil
    }

    static func parseIPv4(_ host: [Unicode.Scalar]) -> String? {
        var parts = dotParts(host)
        if parts.last?.isEmpty == true && parts.count > 1 { parts.removeLast() }
        if parts.count > 4 { return nil }
        var nums: [UInt64] = []
        for p in parts { guard let n = ipv4Number(p) else { return nil }; nums.append(n) }
        if nums.dropLast().contains(where: { $0 > 255 }) { return nil }
        let limit = UInt64(1) << (8 * UInt64(5 - nums.count))
        if nums[nums.count - 1] >= limit { return nil }
        var v = nums[nums.count - 1]
        for (i, n) in nums.dropLast().enumerated() { v += n << (8 * UInt64(3 - i)) }
        return [24, 16, 8, 0].map { String((v >> UInt64($0)) & 255) }.joined(separator: ".")
    }

    /// The WHATWG IPv6 parser (16-bit pieces), nil on failure.
    static func parseIPv6(_ s: [Unicode.Scalar]) -> [UInt16]? {
        var a = [UInt16](repeating: 0, count: 8)
        var piece = 0, compress: Int? = nil, p = 0
        func c(_ i: Int) -> Unicode.Scalar? { i < s.count ? s[i] : nil }
        if c(p) == ":" {
            if c(p + 1) != ":" { return nil }
            p += 2; piece += 1; compress = piece
        }
        while let ch = c(p) {
            if piece == 8 { return nil }
            if ch == ":" {
                if compress != nil { return nil }
                p += 1; piece += 1; compress = piece; continue
            }
            var value: UInt32 = 0, length = 0
            while length < 4, let x = c(p), x.isASCII, let d = hexVal(UInt8(x.value)) { value = value * 16 + UInt32(d); p += 1; length += 1 }
            if c(p) == "." {
                if length == 0 { return nil }
                p -= length
                if piece > 6 { return nil }
                var seen = 0
                while c(p) != nil {
                    var v4: UInt32? = nil
                    if seen > 0 {
                        if c(p) == ".", seen < 4 { p += 1 } else { return nil }
                    }
                    guard let d0 = c(p), d0.value >= 0x30, d0.value <= 0x39 else { return nil }
                    while let d = c(p), d.value >= 0x30, d.value <= 0x39 {
                        let n = d.value - 0x30
                        if v4 == nil { v4 = n } else if v4 == 0 { return nil } else { v4 = v4! * 10 + n }
                        if v4! > 255 { return nil }
                        p += 1
                    }
                    _ = d0
                    a[piece] = UInt16(truncatingIfNeeded: UInt32(a[piece]) * 0x100 + v4!)
                    seen += 1
                    if seen == 2 || seen == 4 { piece += 1 }
                }
                if seen != 4 { return nil }
                break
            } else if c(p) == ":" {
                p += 1
                if c(p) == nil { return nil }
            } else if c(p) != nil { return nil }
            a[piece] = UInt16(value); piece += 1
        }
        if let cp = compress {
            var swaps = piece - cp
            piece = 7
            while piece != 0 && swaps > 0 { a.swapAt(piece, cp + swaps - 1); piece -= 1; swaps -= 1 }
        } else if piece != 8 { return nil }
        return a
    }

    static func serializeIPv6(_ h: [UInt16]) -> String {
        var best = -1, bestLen = 1, i = 0
        while i < 8 {
            if h[i] == 0 {
                var j = i
                while j < 8 && h[j] == 0 { j += 1 }
                if j - i > bestLen { best = i; bestLen = j - i }
                i = j
            } else { i += 1 }
        }
        var out = ""
        i = 0
        while i < 8 {
            if i == best { out += i == 0 ? "::" : ":"; i += bestLen; continue }
            out += String(h[i], radix: 16) + (i == 7 ? "" : ":")
            i += 1
        }
        return "[" + out + "]"
    }

    static func parseHost(_ t: [Unicode.Scalar], special: Bool) -> String? {
        if t.first == "[" {
            guard t.last == "]", t.count >= 2, !t.contains("%") else { return nil }
            return parseIPv6(Array(t[1..<(t.count - 1)])).map(serializeIPv6)
        }
        if !special {
            let forbidden: Set<Unicode.Scalar> = ["\u{0}", "\t", "\n", "\r", " ", "#", "/", "<", ">", "?", "@", "[", "\\", "]", "^", "|"]
            return t.contains(where: forbidden.contains) ? nil : pct(t, extra: "", controlsOnly: true)
        }
        var domainText = String(decoding: pctDecode(t), as: UTF8.self)
        if !domainText.unicodeScalars.allSatisfy({ $0.isASCII }) {
            // IDNA only through a registered UTS 46 implementation (AtlasPCAAda); otherwise the host is refused
            guard let toAscii = PCAExtraCrypto.domainToASCII, let a = toAscii(domainText), !a.isEmpty, a.unicodeScalars.allSatisfy({ $0.isASCII }) else { return nil }
            domainText = a
        }
        let domain = Array(domainText.lowercased().unicodeScalars)
        let forbidden: Set<Unicode.Scalar> = ["#", "%", "/", ":", "<", ">", "?", "@", "[", "\\", "]", "^", "|"]
        if domain.isEmpty || domain.contains(where: { $0.value <= 0x20 || $0.value == 0x7F || forbidden.contains($0) }) { return nil }
        if endsInNumber(domain) { return parseIPv4(domain) }
        return String(String.UnicodeScalarView(domain))
    }

    static func isSlash(_ c: Unicode.Scalar, _ special: Bool) -> Bool { c == "/" || (special && c == "\\") }

    public static func parse(_ input: String) -> WhatwgURL? {
        var s = Array(input.unicodeScalars)
        while let f = s.first, f.value <= 0x20 { s.removeFirst() }
        while let l = s.last, l.value <= 0x20 { s.removeLast() }
        s.removeAll { $0 == "\t" || $0 == "\n" || $0 == "\r" }
        guard let f = s.first, f.isASCII, f.properties.isAlphabetic else { return nil }
        var k = 1
        while k < s.count, s[k].isASCII, s[k].properties.isAlphabetic || (s[k].value >= 0x30 && s[k].value <= 0x39) || s[k] == "+" || s[k] == "-" || s[k] == "." { k += 1 }
        guard k < s.count, s[k] == ":" else { return nil }
        let scheme = String(String.UnicodeScalarView(s[0..<k])).lowercased()
        var rest = Array(s[(k + 1)...])
        let sp = Self.special[scheme] != nil
        let file = scheme == "file"
        if let h = rest.firstIndex(of: "#") { rest = Array(rest[..<h]) }
        var query: [Unicode.Scalar]? = nil
        if let q = rest.firstIndex(of: "?") { query = Array(rest[(q + 1)...]); rest = Array(rest[..<q]) }

        var authority: [Unicode.Scalar]? = nil, path: [Unicode.Scalar] = [], hasCred = false, hostport: [Unicode.Scalar] = []
        func afterAt(_ a: [Unicode.Scalar]) -> [Unicode.Scalar] { a.lastIndex(of: "@").map { Array(a[($0 + 1)...]) } ?? a }
        if sp && !file {
            while let c = rest.first, c == "/" || c == "\\" { rest.removeFirst() }
            let cut = rest.firstIndex(where: { $0 == "/" || $0 == "\\" })
            authority = cut.map { Array(rest[..<$0]) } ?? rest
            path = cut.map { Array(rest[$0...]) } ?? []
            hasCred = authority!.contains("@")
            hostport = afterAt(authority!)
        } else if rest.count >= 2 && ((rest[0] == "/" && rest[1] == "/") || (file && isSlash(rest[0], true) && isSlash(rest[1], true))) {
            let body = Array(rest[2...])
            let cut = body.firstIndex(where: { isSlash($0, sp) })
            authority = cut.map { Array(body[..<$0]) } ?? body
            path = cut.map { Array(body[$0...]) } ?? []
            hasCred = authority!.contains("@") && !file
            hostport = file ? authority! : afterAt(authority!)
        } else if sp {   // file: without an authority
            authority = []
            path = rest
            if let c = path.first, c == "/" || c == "\\" { path[0] = "/" }
        } else {
            path = rest
        }

        var host = "", port: Int? = nil
        if authority != nil {
            var htxt: [Unicode.Scalar], ptxt: [Unicode.Scalar]?
            if hostport.first == "[" {
                guard let end = hostport.firstIndex(of: "]") else { return nil }
                htxt = Array(hostport[...end])
                let after = Array(hostport[(end + 1)...])
                if !after.isEmpty && after.first != ":" { return nil }
                ptxt = after.isEmpty ? nil : Array(after.dropFirst())
            } else if let colon = hostport.firstIndex(of: ":") {
                htxt = Array(hostport[..<colon]); ptxt = Array(hostport[(colon + 1)...])
            } else {
                htxt = hostport; ptxt = nil
            }
            if let pt = ptxt, !pt.isEmpty {
                guard pt.allSatisfy({ $0.value >= 0x30 && $0.value <= 0x39 }) else { return nil }
                let digits = pt.drop { $0 == "0" }
                guard digits.count <= 5, let n = Int(String(String.UnicodeScalarView(digits.isEmpty ? ["0"] : Array(digits)))), n <= 65535 else { return nil }
                port = Self.special[scheme] == n ? nil : n
            }
            if sp && !file && htxt.isEmpty { return nil }
            if hasCred && htxt.isEmpty && ptxt == nil && hostport.isEmpty { return nil }
            if htxt.isEmpty && (!sp || file) {
                host = ""
            } else {
                guard let ph = parseHost(htxt, special: sp) else { return nil }
                host = (file && ph == "localhost") ? "" : ph
            }
        }
        let hp = host + (port.map { ":\($0)" } ?? "")
        let pathname: String
        if authority == nil {
            pathname = pct(path, extra: "", controlsOnly: true)
        } else {
            let norm = sp ? path.map { $0 == "\\" ? "/" : $0 } : path
            let segs = norm.isEmpty ? [] : Array(norm.split(separator: "/", omittingEmptySubsequences: false).dropFirst().map(Array.init))
            var out: [String] = []
            for (i, seg) in segs.enumerated() {
                let last = i == segs.count - 1
                let low = String(String.UnicodeScalarView(seg)).lowercased()
                if low == ".." || low == ".%2e" || low == "%2e." || low == "%2e%2e" {
                    if !out.isEmpty { out.removeLast() }
                    if last { out.append("") }
                } else if low == "." || low == "%2e" {
                    if last { out.append("") }
                } else {
                    out.append(pct(seg, extra: "\"<>`{}?"))
                }
            }
            pathname = "/" + out.joined(separator: "/")
        }
        let search: String? = sp ? ((query?.isEmpty == false) ? "?" + pct(query!, extra: "\"<>'") : "") : nil
        return WhatwgURL(scheme: scheme, host: hp, pathname: pathname, htu: "\(scheme)://\(hp)\(pathname)",
                         origin: sp ? "\(scheme)://\(hp)" : nil, search: search)
    }
}
