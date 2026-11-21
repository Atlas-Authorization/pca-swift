import Foundation

/// Egress admission: default deny; a request is allowed only by matching a template admitted from a verified operation. The caller
/// moves the bytes (an HTTP proxy, a network namespace); this is the decision, with the SSRF address check it needs.
extension PCASandbox {
    // MARK: IP literals

    /// A dotted-decimal IPv4 address (four decimal octets, no leading zeros), as `net.isIPv4`.
    static func ipv4(_ s: String) -> [UInt8]? {
        let parts = s.utf8.split(separator: 0x2E, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out: [UInt8] = []
        for p in parts {
            guard !p.isEmpty, p.count <= 3, p.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), !(p.count > 1 && p.first == 0x30), let n = Int(String(decoding: p, as: UTF8.self)), n <= 255 else { return nil }
            out.append(UInt8(n))
        }
        return out
    }

    private static func hexGroup(_ t: ArraySlice<UInt8>) -> UInt16? {
        guard (1...4).contains(t.count) else { return nil }
        var v: UInt16 = 0
        for c in t {
            let d: UInt16
            switch c {
            case 0x30...0x39: d = UInt16(c - 0x30)
            case 0x41...0x46: d = UInt16(c - 0x41 + 10)
            case 0x61...0x66: d = UInt16(c - 0x61 + 10)
            default: return nil
            }
            v = v << 4 | d
        }
        return v
    }

    /// An IPv6 literal with an optional `%zone`, as `net.isIPv6` reads it: its eight 16-bit groups and whether a zone was present.
    static func ipv6(_ s: String) -> (groups: [UInt16], zone: Bool)? {
        var addr = Array(s.utf8)
        var zone = false
        if let pct = addr.firstIndex(of: 0x25) {
            let z = addr[(pct + 1)...]
            guard !z.isEmpty, z.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x2D || $0 == 0x2E || $0 == 0x3A }) else { return nil }
            zone = true
            addr = Array(addr[..<pct])
        }
        guard addr.allSatisfy({ $0 < 0x80 }) else { return nil }
        var dc: Int?
        if addr.count >= 2 {
            for i in 0..<(addr.count - 1) where addr[i] == 0x3A && addr[i + 1] == 0x3A {
                if dc != nil { return nil }
                dc = i
            }
        }
        func tokens(_ t: ArraySlice<UInt8>) -> [ArraySlice<UInt8>]? {
            if t.isEmpty { return [] }
            let parts = t.split(separator: 0x3A, omittingEmptySubsequences: false)
            return parts.contains(where: { $0.isEmpty }) ? nil : parts
        }
        func groups(_ toks: [ArraySlice<UInt8>], lastMayBeV4: Bool) -> [UInt16]? {
            var out: [UInt16] = []
            for (i, t) in toks.enumerated() {
                if t.contains(0x2E) {
                    guard lastMayBeV4, i == toks.count - 1, let v = ipv4(String(decoding: t, as: UTF8.self)) else { return nil }
                    out.append(UInt16(v[0]) << 8 | UInt16(v[1]))
                    out.append(UInt16(v[2]) << 8 | UInt16(v[3]))
                } else {
                    guard let g = hexGroup(t) else { return nil }
                    out.append(g)
                }
            }
            return out
        }
        if let d = dc {
            guard let ht = tokens(addr[..<d]), let tt = tokens(addr[(d + 2)...]), let h = groups(ht, lastMayBeV4: false), let t = groups(tt, lastMayBeV4: true), h.count + t.count <= 7 else { return nil }
            return (h + [UInt16](repeating: 0, count: 8 - h.count - t.count) + t, zone)
        }
        guard let tt = tokens(addr[...]), let g = groups(tt, lastMayBeV4: true), g.count == 8 else { return nil }
        return (g, zone)
    }

    /// `net.isIP(host) != 0`.
    static func isIP(_ host: String) -> Bool { ipv4(host) != nil || ipv6(host) != nil }

    private static func privateV4(_ a: Int, _ b: Int) -> Bool {
        a == 0 || a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127) || a >= 224
    }

    /// Loopback, link-local, private, CGNAT, multicast, reserved and unspecified addresses, classified on the PARSED address, not its
    /// spelling. IPv6: only global unicast (2000::/3) is public; an IPv4-mapped, IPv4-compatible or NAT64 (64:ff9b::/96) address follows
    /// its embedded IPv4 address; a zoned address is link-scoped, so private. Anything that is not an IP literal counts as private.
    public static func isPrivateAddress(_ ip: String) -> Bool {
        if let v = ipv4(ip) { return privateV4(Int(v[0]), Int(v[1])) }
        guard !ip.contains("%"), let w = ipv6(ip)?.groups else { return true }
        let zero80 = w[0..<5].allSatisfy { $0 == 0 }
        let nat64 = w[0] == 0x64 && w[1] == 0xFF9B && w[2] == 0 && w[3] == 0 && w[4] == 0 && w[5] == 0
        if (zero80 && (w[5] == 0 || w[5] == 0xFFFF)) || nat64 { return privateV4(Int(w[6] >> 8), Int(w[6] & 0xFF)) }
        return w[0] < 0x2000 || w[0] >= 0x4000
    }

    // MARK: policy

    /// The one outbound request an authorized operation maps to. Exact host, exact port, exact method; the path is exact unless
    /// `pathPrefix`; the query must equal `query` (nil = no query). A request with a body must match `bodySha256` (base64url); a
    /// request without a template body hash may not carry a body. `tunnel` admits a CONNECT to host:port instead (host-and-port grain).
    public struct EgressTemplate {
        public var method: String
        public var scheme: String
        public var host: String
        public var port: Int?
        public var path: String
        public var pathPrefix = false
        public var query: String?
        public var bodySha256: String?
        public var tunnel = false
        public init(method: String, scheme: String, host: String, port: Int? = nil, path: String, pathPrefix: Bool = false, query: String? = nil, bodySha256: String? = nil, tunnel: Bool = false) {
            self.method = method
            self.scheme = scheme
            self.host = host
            self.port = port
            self.path = path
            self.pathPrefix = pathPrefix
            self.query = query
            self.bodySha256 = bodySha256
            self.tunnel = tunnel
        }
    }

    public struct EgressRequest {
        public var method: String
        /// An absolute URL for a plain request; `host:port` for CONNECT.
        public var url: String
        public var body: [UInt8]
        public init(method: String, url: String, body: [UInt8] = []) {
            self.method = method
            self.url = url
            self.body = body
        }
    }

    public struct EgressDecision {
        public var allow: Bool
        public var opId = ""
        public var reason = ""
        public var admission: (verb: String, resource: String, paramsDigest: String)?
    }

    public static func sha256b64u(_ b: [UInt8]) -> String { Base64URLStrict.encode(Canonical.sha256(b)) }

    private static func isHostName(_ h: String) -> Bool {
        let labels = h.utf8.split(separator: 0x2E, omittingEmptySubsequences: false)
        func alnum(_ c: UInt8) -> Bool { (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x7A) }
        return !labels.isEmpty && labels.allSatisfy { l in
            l.count >= 1 && l.count <= 63 && alnum(l.first!) && alnum(l.last!) && l.allSatisfy { alnum($0) || $0 == 0x2D }
        }
    }

    private static let defaultPort = ["http": 80, "https": 443]

    fileprivate struct Admission {
        var opId: String
        var op: PCA.Operation
        var template: EgressTemplate
        var port: Int
        var uses: Double
        var expiresAt: Double
    }

    /// Default deny. The only way a request is allowed is by matching a template admitted from a verified operation.
    public final class EgressPolicy {
        fileprivate var admissions: [Admission] = []
        private let now: () -> Double

        public init(now: (() -> Double)? = nil) {
            self.now = now ?? { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
        }

        /// Admit the request that `operation` maps to. Throws unless `grant` allows exactly `operation` and the template is well formed.
        public func admit(_ grant: Grant, _ operation: PCA.Operation, toRequest: (PCA.Operation) -> EgressTemplate?, uses: Double? = nil, expiresAt: Double? = nil) throws {
            guard grant.authorizes(operation) else { throw SandboxError("not_authorized: result does not allow exactly this operation") }
            guard let t = toRequest(operation) else { throw SandboxError("no_egress_for_operation") }
            guard PCASandbox.isIP(t.host) || PCASandbox.isHostName(t.host), IV.same(t.host, t.host.lowercased()) else { throw SandboxError("bad_template_host") }
            guard t.scheme == "http" || t.scheme == "https" else { throw SandboxError("bad_template_scheme") }
            let port = t.port ?? PCASandbox.defaultPort[t.scheme]!
            guard port >= 1, port <= 65535 else { throw SandboxError("bad_template_port") }
            guard !t.method.isEmpty, t.method.unicodeScalars.allSatisfy({ $0.value >= 0x41 && $0.value <= 0x5A }) else { throw SandboxError("bad_template_method") }
            let lower = t.path.lowercased()
            guard t.path.hasPrefix("/"), !t.path.contains("?"), !t.path.contains("#"), !t.path.contains("\\"),
                  !lower.contains("%2e"), !lower.contains("%2f"), !lower.contains("%5c"),
                  !t.path.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == "." || $0 == ".." }) else { throw SandboxError("bad_template_path") }
            let u = uses ?? 1
            guard PCASandbox.isInteger(u), u >= 1 else { throw SandboxError("bad_uses") }
            admissions.append(Admission(opId: grant.operation?.id ?? "", op: operation, template: t, port: port, uses: u, expiresAt: expiresAt ?? .infinity))
        }

        /// Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason.
        public func claim(_ req: EgressRequest) -> EgressDecision {
            guard let parsed = PCASandbox.parseTarget(req) else { return EgressDecision(allow: false, reason: "not_absolute_url") }
            if let r = parsed.reason { return EgressDecision(allow: false, reason: r) }
            var why = "no_admission"
            let method = req.method.uppercased()
            for i in admissions.indices {
                let a = admissions[i], t = a.template
                if parsed.connect != t.tunnel { continue }
                if !parsed.connect && !IV.same(t.method, method) { continue }
                if !parsed.connect && parsed.scheme != t.scheme { continue }
                if parsed.host != t.host || parsed.port != a.port { continue }
                if !parsed.connect {
                    if t.pathPrefix {
                        let prefix = t.path.hasSuffix("/") ? t.path : t.path + "/"
                        if !(IV.same(parsed.path, t.path) || IV.startsWith(parsed.path, prefix)) { continue }
                    } else if !IV.same(parsed.path, t.path) { continue }
                    if !IV.same(parsed.query, t.query ?? "") { why = "query_mismatch"; continue }
                    if !req.body.isEmpty, t.bodySha256 == nil || PCASandbox.sha256b64u(req.body) != t.bodySha256! { why = "body_mismatch"; continue }
                    if req.body.isEmpty, let h = t.bodySha256, h != PCASandbox.sha256b64u([]) { why = "body_mismatch"; continue }
                }
                if a.uses < 1 || !(now().isFinite && now() < a.expiresAt) { why = "spent"; continue } // reported only when the request would otherwise have matched
                admissions[i].uses -= 1
                guard let d = IV.strictHash(a.op.params) else { continue }
                return EgressDecision(allow: true, opId: a.opId, admission: (a.op.verb, a.op.resource, d))
            }
            return EgressDecision(allow: false, reason: why)
        }
    }

    struct Target {
        var reason: String?
        var connect = false
        var scheme = ""
        var host = ""
        var port = 0
        var path = ""
        var query = ""
    }

    /// The target of a request as the admissions are matched: `host:port` for CONNECT, else an absolute http(s) URL with no userinfo or
    /// fragment and no encoded dots, slashes or backslashes in the path (refused, never decoded). nil = not an absolute URL.
    static func parseTarget(_ req: EgressRequest) -> Target? {
        if req.method.uppercased() == "CONNECT" {
            // ^([a-z0-9.-]+|\[[0-9a-f:]+\]):(\d{1,5})$ (case-insensitive)
            let u = Array(req.url.utf8)
            guard let colon = u.lastIndex(of: 0x3A) else { return Target(reason: "bad_connect_target") }
            let hostPart = Array(u[..<colon]), portPart = u[(colon + 1)...]
            func hex(_ c: UInt8) -> Bool { (c >= 0x30 && c <= 0x39) || (c | 0x20 >= 0x61 && c | 0x20 <= 0x66) }
            func name(_ c: UInt8) -> Bool { (c >= 0x30 && c <= 0x39) || (c | 0x20 >= 0x61 && c | 0x20 <= 0x7A) || c == 0x2E || c == 0x2D }
            let bracket = hostPart.count >= 3 && hostPart.first == 0x5B && hostPart.last == 0x5D && hostPart.dropFirst().dropLast().allSatisfy { hex($0) || $0 == 0x3A }
            let plain = !hostPart.isEmpty && hostPart.allSatisfy(name)
            guard (1...5).contains(portPart.count), portPart.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), bracket || plain,
                  let port = Int(String(decoding: portPart, as: UTF8.self)) else { return Target(reason: "bad_connect_target") }
            let h = String(decoding: bracket ? Array(hostPart.dropFirst().dropLast()) : hostPart, as: UTF8.self).lowercased()
            return Target(connect: true, scheme: "https", host: h, port: port)
        }
        guard let u = WhatwgURL.parse(req.url) else { return nil }
        guard u.scheme == "http" || u.scheme == "https" else { return Target(reason: "bad_url") }
        let extras = WhatwgURL.userinfoAndFragment(req.url)
        if extras.userinfo || extras.fragment { return Target(reason: "bad_url") }
        let lp = u.pathname.lowercased()
        if lp.contains("%2e") || lp.contains("%2f") || lp.contains("%5c") || lp.contains("\\") { return Target(reason: "encoded_path") }
        let hp = u.hostnameAndPort
        let q = u.search ?? ""
        return Target(connect: false, scheme: u.scheme, host: hp.hostname.lowercased(), port: hp.port ?? defaultPort[u.scheme]!, path: u.pathname, query: q.hasPrefix("?") ? String(q.dropFirst()) : q)
    }
}
