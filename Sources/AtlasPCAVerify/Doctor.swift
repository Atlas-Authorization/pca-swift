import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// pca-doctor (reference: @atlasauth/pca-doctor): checks a live PCA deployment's assumptions. Clock skew against a reference from HTTP `Date`
/// headers (with the one-second resolution and the round trip as uncertainty), the trusted-proxy settings against the stated hop count and a
/// live probe with forged forwarding headers, the verifier's suite and post-quantum pin configuration, root-caveat enforcement of the
/// installed library, and the verifier's required checks. Every text that leaves the doctor goes through `scrubText`. Results are ordered
/// JSON trees (`PCASchema.Node`) so the text and `--json` output follow the reference's member order.
///
/// shortcut: the replay-store checks (atomicity, durability) need a store adapter and the conformance kit; without an adapter they are
/// skipped like the reference, with one a failed check names the limit. The root-caveat probe runs through an injected `LoadedPca` (the
/// Swift library is the one installed, so a host passes the probe of its own grant machinery); the default loader fails closed.
public enum PCADoctor {
    public typealias N = PCASchema.Node

    // MARK: constants

    public static let CHECK_GROUPS = ["clock", "store", "proxy", "suites", "caveats"]
    public static let DEFAULT_REFERENCE_URL = "https://www.google.com/generate_204"
    public static let ROOT_CAVEAT_MIN_VERSION = "0.4.1"
    public static let DEFAULT_REQUIRED = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]
    static let MAX_SKEW_MS = 60_000.0
    /// The closed suite registry in the reference's order; every suite but the first needs a post-quantum key.
    static let registry = ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65", "slh-dsa-sha2-128f",
                           "hybrid-ed25519-slh-dsa-sha2-128f", "ml-dsa-87", "hybrid-ed25519-ml-dsa-87", "slh-dsa-sha2-256s",
                           "hybrid-ed25519-slh-dsa-sha2-256s", "fn-dsa-512", "less-cat1", "hybrid-ed25519-less-cat1", "fn-dsa-1024"]

    public static let SUITES_REMEDIATION = "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. ['ed25519'] or ['hybrid-ed25519-ml-dsa-65']."
    public static let PQ_REMEDIATION = "Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this)."
    public static let CLOCK_REMEDIATION = "Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a nonce early or reject fresh actions."
    public static let PROXY_REMEDIATION = "Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy's bucket."
    public static let ATOMICITY_REMEDIATION = "Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>."
    public static let DURABILITY_REMEDIATION = "Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single process whose lifetime covers the action lifetime."
    public static let CAVEAT_REMEDIATION = "Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application."

    public static let USAGE = """
    pca-doctor [--url <deployment>] [options]

      --url URL              the live deployment (base URL of the API that verifies PCActns)
      --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it
      --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks
      --store-option k=v     passed to the adapter factory (repeatable)
      --reference URL|local  clock reference (default https://www.google.com/generate_204)
      --max-skew-ms N        clock fail threshold (default 60000)
      --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count
      --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)
      --only a,b | --skip a,b   check groups: clock, store, proxy, suites, caveats
      --no-probe             do not send forged forwarding headers to the deployment
      --strict               warnings fail too
      --json                 machine-readable output

    Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,
         PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.
    """

    // MARK: ordered-tree helpers

    static func s(_ x: String) -> N { .str(x) }
    static func num(_ x: Double) -> N { .num(x) }
    static func obj(_ pairs: [(String, N?)]) -> N { .obj(pairs.compactMap { p in p.1.map { (key: p.0, value: $0) } }) }
    static func arr(_ xs: [String]) -> N { .arr(xs.map { .str($0) }) }
    static func jsNum(_ d: Double) -> String { IntentV2.jsString(.double(d)) }

    /// `a?.b?.c`: nil for an absent member and for a non-object on the way (null counts as a value only at the end).
    static func at(_ n: N?, _ path: String...) -> N? {
        var cur = n
        for (i, k) in path.enumerated() {
            guard let c = cur else { return nil }
            if case .null = c { return i == path.count ? c : nil }
            guard case .obj = c else { return nil }
            cur = c.member(k)
        }
        return cur
    }

    /// `String(x)`: null is "null" (inside an array join it is the empty string).
    static func jsStr(_ n: N) -> String { if case .null = n { return "null" }; return PCASchema.text(n) }

    static func numberOf(_ n: N?) -> Double? { if case let .num(d)? = n { return d }; return nil }
    static func stringOf(_ n: N?) -> String? { if case let .str(x)? = n { return x }; return nil }
    static func isUndefined(_ n: N?) -> Bool { n == nil }

    static func check(_ id: String, _ status: String, _ detail: String, remediation: String? = nil, observed: N? = nil) -> N {
        obj([("id", s(id)), ("status", s(status)), ("detail", s(detail)), ("remediation", remediation.map { s($0) }), ("observed", observed)])
    }

    /// JS `Number(text)` of a string.
    static func number(_ t: String) -> Double { IV.jsNumber(t) }
    static func isInteger(_ d: Double) -> Bool { d.isFinite && d.rounded(.towardZero) == d }
    static func isNegZero(_ d: Double) -> Bool { d == 0 && d.sign == .minus }

    /// `x.toFixed(1)` for a non-negative x (ties go up, as the reference's).
    static func fixed1(_ x: Double) -> String {
        let t = x * 4
        if t.rounded() == t && (x * 2).rounded() != x * 2 { return String(format: "%.1f", x + 0.05) }
        return String(format: "%.1f", x)
    }

    // MARK: scrubbing

    // JavaScript `\s`, spelled with escapes so no invisible character is left to the source file
    private static let spaceSet = #"\t\n\u000B\u000C\r\u0020\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF"#
    private static let S = "[" + spaceSet + "]"
    private static let notAfterWord = "(?<![A-Za-z0-9_])"
    private static func ci(_ w: String) -> String { w.map { c in c.isASCII && c.isLetter ? "[\(c.lowercased())\(c.uppercased())]" : String(c) }.joined() }
    private static func re(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: p) }
    private static let jwt = re(notAfterWord + #"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"#)
    private static let authorization = re(notAfterWord + "(" + ci("authorization") + "[\"']?" + S + "*[:=]" + S + "*)" + "[^\\n\"']*")
    private static let scheme = re(notAfterWord + "(" + ci("Bearer") + "|" + ci("Basic") + "|" + ci("Token") + ")" + S + "+[A-Za-z0-9_.~+/=-]{6,}")
    private static let userinfo = re("([A-Za-z][A-Za-z0-9+.-]*://)[^" + spaceSet + "/@]*:[^" + spaceSet + "/@]*@")
    private static let pair = re(notAfterWord + "((?:" + ["token", "secret", "password", "passwd", "pwd"].map(ci).joined(separator: "|")
        + "|" + ci("api") + "[_-]?" + ci("key") + "|" + ["key", "signature", "sig", "credential", "auth", "sslpassword"].map(ci).joined(separator: "|")
        + ")[\"']?" + S + "*[:=]" + S + "*)(\"[^\"]*\"|'[^']*'|[^" + spaceSet + "\"'&,;]+)")
    private static let longRun = re("[A-Za-z0-9_-]{40,}")

    private static func sub(_ s: String, _ r: NSRegularExpression, _ f: (NSTextCheckingResult, NSString) -> String) -> String {
        let ns = s as NSString
        var out = "", last = 0
        for m in r.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
            out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            out += f(m, ns)
            last = m.range.location + m.range.length
        }
        return out + ns.substring(from: last)
    }

    /// Removes credentials from text the doctor prints: URL userinfo, `token=` / `password=` pairs, bearer credentials, JWTs and long token
    /// runs; cut to 600 UTF-16 units (a cut that would split a surrogate pair drops the lone half: a Swift String cannot hold one).
    public static func scrubText(_ text: String) -> String {
        var t = sub(text, jwt) { _, _ in "[redacted]" }
        t = sub(t, authorization) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]" }
        t = sub(t, scheme) { m, ns in ns.substring(with: m.range(at: 1)) + " [redacted]" }
        t = sub(t, userinfo) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]@" }
        t = sub(t, pair) { m, ns in ns.substring(with: m.range(at: 1)) + "[redacted]" }
        t = sub(t, longRun) { _, _ in "[redacted]" }
        let ns = t as NSString
        guard ns.length > 600 else { return t }
        var n = 600
        if UTF16.isLeadSurrogate(ns.character(at: n - 1)) { n -= 1 }
        return ns.substring(to: n) + "..."
    }

    /// `String(value)` then `scrubText` (the reference coerces a non-string).
    public static func scrubText(_ v: JSONValue) -> String { scrubText(IntentV2.jsString(v)) }

    /// Scrubs every string inside a JSON-like value (to depth 8; deeper values are left as they are).
    public static func scrubDeep(_ v: JSONValue, _ depth: Int = 0) -> JSONValue {
        switch v {
        case let .string(x): return .string(scrubText(x))
        case let .array(a): return depth > 8 ? v : .array(a.map { scrubDeep($0, depth + 1) })
        case let .object(o): return depth > 8 ? v : .object(o.mapValues { scrubDeep($0, depth + 1) })
        default: return v
        }
    }

    static func scrub(_ n: N, _ depth: Int = 0) -> N {
        switch n {
        case let .str(x): return .str(scrubText(x))
        case let .arr(a): return depth > 8 ? n : .arr(a.map { scrub($0, depth + 1) })
        case let .obj(m): return depth > 8 ? n : .obj(m.map { (key: $0.key, value: scrub($0.value, depth + 1)) })
        default: return n
        }
    }

    // MARK: clock

    /// One response of the injected network: the headers the doctor reads.
    public struct FetchResponse {
        public var date: String?
        public var rateLimitRemaining: String?
        public init(date: String? = nil, rateLimitRemaining: String? = nil) { self.date = date; self.rateLimitRemaining = rateLimitRemaining }
    }
    /// (method, url, request headers, timeout ms) -> response; throws on a network failure.
    public typealias FetchLike = (String, String, [String: String], Double) throws -> FetchResponse

    /// `Date.parse` of the formats a Date header takes (RFC 9110 IMF-fixdate and its legacy forms, ISO 8601); nil where JS gives NaN.
    /// shortcut: a date without a zone is refused (JS would read it in local time).
    public static func parseDate(_ text: String) -> Double? {
        let t = Attest.jsTrim(text)
        func daysFromCivil(_ y0: Int, _ m: Int, _ d: Int) -> Int {
            let y = m <= 2 ? y0 - 1 : y0
            let era = (y >= 0 ? y : y - 399) / 400
            let yoe = y - era * 400
            let doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
            return era * 146097 + doe - 719468
        }
        func epoch(_ y: Int, _ mo: Int, _ d: Int, _ h: Int, _ mi: Int, _ sec: Double, _ offMin: Int) -> Double? {
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
            let dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
            guard (1...12).contains(mo), d >= 1, d <= dim[mo - 1], (0...23).contains(h), (0...59).contains(mi), sec >= 0, sec < 60 else { return nil }
            return Double(daysFromCivil(y, mo, d)) * 86_400_000 + Double(h) * 3_600_000 + Double(mi) * 60_000 + (sec * 1000).rounded() - Double(offMin) * 60_000
        }
        let ns = t as NSString
        // ISO 8601: YYYY-MM-DDTHH:mm[:ss[.sss]](Z|+hh:mm)
        let iso = try! NSRegularExpression(pattern: "^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\\.([0-9]{1,9}))?)?(Z|[+-][0-9]{2}:[0-9]{2})$")
        if let m = iso.firstMatch(in: t, range: NSRange(location: 0, length: ns.length)) {
            func g(_ i: Int) -> String? { m.range(at: i).location == NSNotFound ? nil : ns.substring(with: m.range(at: i)) }
            let frac = g(7).flatMap { Double("0." + $0) } ?? 0
            var off = 0
            if let z = g(8), z != "Z" {
                off = (z.hasPrefix("-") ? -1 : 1) * (Int(z.dropFirst().prefix(2))! * 60 + Int(z.suffix(2))!)
            }
            return epoch(Int(g(1)!)!, Int(g(2)!)!, Int(g(3)!)!, Int(g(4)!)!, Int(g(5)!)!, Double(g(6) ?? "0")! + frac, off)
        }
        // [Www, ]DD Mon YYYY HH:MM[:SS] (GMT|UTC|UT|Z|+hhmm)
        let rfc = try! NSRegularExpression(pattern: "^(?:[A-Za-z]+,?[ \\t]+)?([0-9]{1,2})[ \\t]+([A-Za-z]{3,})[ \\t]+([0-9]{4})[ \\t]+([0-9]{2}):([0-9]{2})(?::([0-9]{2}))?[ \\t]*(GMT|UTC|UT|Z|[+-][0-9]{4})$")
        if let m = rfc.firstMatch(in: t, range: NSRange(location: 0, length: ns.length)) {
            func g(_ i: Int) -> String? { m.range(at: i).location == NSNotFound ? nil : ns.substring(with: m.range(at: i)) }
            let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
            guard let mo = months.firstIndex(of: String(g(2)!.lowercased().prefix(3))) else { return nil }
            var off = 0
            if let z = g(7), z.hasPrefix("+") || z.hasPrefix("-") { off = (z.hasPrefix("-") ? -1 : 1) * (Int(z.dropFirst().prefix(2))! * 60 + Int(z.suffix(2))!) }
            return epoch(Int(g(3)!)!, mo + 1, Int(g(1)!)!, Int(g(4)!)!, Int(g(5)!)!, Double(g(6) ?? "0")!, off)
        }
        return nil
    }

    /// One reading of a server's clock relative to `now()` from its Date header: (offsetMs, uncertaintyMs) or an error text.
    public static func readDate(_ url: String, _ fetch: FetchLike, _ now: () -> Double, _ timeoutMs: Double) -> (offsetMs: Double, uncertaintyMs: Double)? {
        if case let .reading(o, u) = read(url, fetch, now, timeoutMs) { return (o, u) }
        return nil
    }

    enum Reading { case reading(Double, Double), failed(String) }

    static func read(_ url: String, _ fetch: FetchLike, _ now: () -> Double, _ timeoutMs: Double) -> Reading {
        let t0 = now()
        let res: FetchResponse
        do { res = try fetch("HEAD", url, [:], timeoutMs) } catch { return .failed("request failed: \(message(error))") }
        let t1 = now()
        guard let date = res.date else { return .failed("no Date header") }
        guard let d = parseDate(date), d.isFinite else { return .failed("unparseable Date header '\(date)'") }
        return .reading(d + 500 - (t0 + t1) / 2, 500 + (t1 - t0) / 2)
    }

    /// The `readDate` result as the reference's JSON.
    public static func readDateJSON(_ url: String, _ fetch: FetchLike, _ now: () -> Double, _ timeoutMs: Double) -> N {
        switch read(url, fetch, now, timeoutMs) {
        case let .reading(o, u): return obj([("offsetMs", num(o)), ("uncertaintyMs", num(u))])
        case let .failed(e): return obj([("error", s(e))])
        }
    }

    static func message(_ e: Error) -> String { (e as? JSError)?.message ?? "\(e)" }

    static func sSkew(_ ms: Double) -> String { "\(ms >= 0 ? "+" : "-")\(fixed1(abs(ms) / 1000)) s" }

    public static func checkClock(_ cfg: N, fetch: FetchLike, now: (() -> Double)? = nil) -> N {
        let clock = now ?? { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
        guard let url = at(cfg, "url"), url.truthy else { return check("clock", "skip", "no deployment URL given (--url)") }
        let urlText = PCASchema.text(url)
        let max = numberOf(at(cfg, "clock", "maxSkewMs")) ?? MAX_SKEW_MS
        let warnAt = max * (numberOf(at(cfg, "clock", "warnFraction")) ?? 0.25)
        let timeout = numberOf(at(cfg, "clock", "timeoutMs")) ?? 10_000
        let dep: (Double, Double)
        switch read(urlText, fetch, clock, timeout) {
        case let .failed(e):
            return check("clock", "warn", "cannot observe the deployment's clock at \(urlText): \(e)",
                         remediation: "Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. \(CLOCK_REMEDIATION)")
        case let .reading(o, u): dep = (o, u)
        }
        let refUrl = stringOf(at(cfg, "clock", "referenceUrl")) ?? DEFAULT_REFERENCE_URL
        var ref: (Double, Double) = (0, 0)
        var refName = "this machine's clock"
        var refNote = ""
        if refUrl != "local" {
            switch read(refUrl, fetch, clock, timeout) {
            case let .failed(e): refNote = " (reference \(refUrl) unusable: \(e); compared with this machine's clock instead)"
            case let .reading(o, u): ref = (o, u); refName = refUrl
            }
        }
        let skew = dep.0 - ref.0
        let unc = dep.1 + ref.1
        let lower = abs(skew) - unc, upper = abs(skew) + unc
        // a skew, uncertainty or threshold that is not a number (NaN, an infinite clock reading) can show nothing: fail, never pass
        let measurable = lower.isFinite && upper.isFinite && !max.isNaN && !warnAt.isNaN
        let status = !measurable ? "fail" : (lower > max ? "fail" : (abs(skew) > warnAt || upper > max ? "warn" : "pass"))
        let detail = "deployment clock \(sSkew(skew)) relative to \(refName)\(refNote) (+-\(fixed1(unc / 1000)) s: Date has 1 s resolution, plus round trips); "
            + "fail beyond \(jsNum(max / 1000)) s, warn above \(jsNum(warnAt / 1000)) s. The Date header is written by whatever answers the request (a CDN or proxy may set it)."
        return check("clock", status, detail, remediation: status == "pass" ? nil : CLOCK_REMEDIATION,
                     observed: obj([("skewMs", num(skew)), ("uncertaintyMs", num(unc)), ("maxSkewMs", num(max)), ("warnAtMs", num(warnAt)), ("reference", s(refName))]))
    }

    // MARK: proxy

    public static func checkProxyConfig(_ cfg: N) -> N {
        let p = at(cfg, "proxy")
        guard let nv = at(p, "trustedProxyCount") else {
            return check("proxy.config", "skip", "TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)")
        }
        let header = at(p, "header").map { jsStr($0) } ?? "x-forwarded-for"
        func fail(_ d: String) -> N { check("proxy.config", "fail", d, remediation: PROXY_REMEDIATION) }
        let shown = jsStr(nv)
        guard case let .num(n) = nv, isInteger(n), n >= 0, !isNegZero(n), n <= 16 else { return fail("TRUSTED_PROXY_COUNT=\(shown) is not an integer in 0..16") }
        if header == "x-real-ip" && n == 0 { return fail("TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)") }
        guard let hopsNode = at(p, "hops") else {
            return check("proxy.config", n == 0 ? "pass" : "warn",
                         "TRUSTED_PROXY_COUNT=\(jsNum(n)) (\(header)); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared",
                         remediation: n == 0 ? nil : PROXY_REMEDIATION)
        }
        let hops = numberOf(hopsNode) ?? .nan
        let hs = jsStr(hopsNode)
        if n > hops { return fail("TRUSTED_PROXY_COUNT=\(jsNum(n)) is larger than the \(hs) proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra \(header) entries") }
        if n < hops {
            return check("proxy.config", "warn", "TRUSTED_PROXY_COUNT=\(jsNum(n)) is smaller than the \(hs) proxies in front of the API: clients are keyed by a proxy's address and share its bucket", remediation: PROXY_REMEDIATION)
        }
        return check("proxy.config", "pass", "TRUSTED_PROXY_COUNT=\(jsNum(n)) (\(header)) matches the stated \(hs) appending proxies")
    }

    /// mulberry32, the reference's seeded generator.
    public static func mulberry32(_ seed: UInt32) -> () -> Double {
        var a = seed
        return {
            a = a &+ 0x6d2b79f5
            var t = a
            t = (t ^ (t >> 15)) &* (t | 1)
            t ^= t &+ ((t ^ (t >> 7)) &* (t | 61))
            return Double(t ^ (t >> 14)) / 4294967296
        }
    }

    /// A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client.
    public static func testNetIp(_ rand: () -> Double) -> String {
        let net = rand() < 0.5 ? "198.51.100" : "203.0.113"
        return "\(net).\(1 + Int((rand() * 254).rounded(.down)))"
    }

    /// Forged values for all three headers at once (the server trusts at most one of them), in the reference's member order.
    public static func forgedHeaders(_ rand: () -> Double) -> [(String, String)] {
        let chain = (0..<17).map { _ in testNetIp(rand) }
        return [("x-forwarded-for", chain.joined(separator: ", ")), ("forwarded", chain.map { "for=\($0)" }.joined(separator: ", ")), ("x-real-ip", testNetIp(rand))]
    }

    /// `new URL(path, base).href` for an http(s) base; nil where the platform class throws.
    static func resolveHref(_ path: String, base: String) -> String? {
        guard let b = WhatwgURL.parse(base), let origin = b.origin else { return nil }
        let target = path.contains("://") ? path : origin + (path.hasPrefix("/") ? "" : "/") + path
        guard let u = WhatwgURL.parse(target) else { return nil }
        return u.htu + (u.search ?? "")
    }

    static func remaining(_ fetch: FetchLike, _ url: String, _ headers: [String: String], _ timeoutMs: Double) throws -> Double? {
        let r = try fetch("GET", url, headers, timeoutMs)
        guard let v = r.rateLimitRemaining else { return nil }
        let n = number(v)
        return n.isFinite ? n : nil
    }

    public static func checkProxyProbe(_ cfg: N, fetch: FetchLike, rand: (() -> Double)? = nil) throws -> N {
        let id = "proxy.probe"
        guard let url = at(cfg, "url"), url.truthy else { return check(id, "skip", "no deployment URL given (--url)") }
        if case .bool(false)? = at(cfg, "proxy", "probe") { return check(id, "skip", "disabled (--no-probe)") }
        let probePath = at(cfg, "proxy", "probePath").map { PCASchema.text($0) } ?? "/v1/pca/suites"
        guard let href = resolveHref(probePath, base: PCASchema.text(url)) else { throw JSError("Invalid URL", code: "ERR_INVALID_URL") }
        let t = numberOf(at(cfg, "clock", "timeoutMs")) ?? 10_000
        let r = rand ?? { Double.random(in: 0..<1) }
        var seq: [Double?]
        do {
            let a = try remaining(fetch, href, [:], t)
            let b = try remaining(fetch, href, [:], t)
            let f = try remaining(fetch, href, Dictionary(uniqueKeysWithValues: forgedHeaders(r)), t)
            let c = try remaining(fetch, href, [:], t)
            seq = [a, b, f, c]
        } catch {
            return check(id, "warn", "probe request to \(href) failed: \(message(error))", remediation: "Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.")
        }
        let observed = obj([("url", s(href)), ("remaining", .arr(seq.map { $0.map { num($0) } ?? .null }))])
        if seq.contains(where: { $0 == nil }) {
            return check(id, "skip", "not observable remotely: \(href) does not return a RateLimit-Remaining header on every response", observed: observed)
        }
        let a = seq[0]!, b = seq[1]!, f = seq[2]!, c = seq[3]!
        if !(b < a && c < b) {
            return check(id, "warn", "inconclusive: the plain requests' bucket did not drain monotonically (\(jsNum(a)), \(jsNum(b)), then \(jsNum(c))): a window rollover, a shared bucket or concurrent traffic. Re-run.", observed: observed)
        }
        if f > b {
            return check(id, "fail", "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining \(jsNum(f)), while the plain requests' bucket was at \(jsNum(b))): the deployment trusts client-written forwarding entries",
                         remediation: PROXY_REMEDIATION, observed: observed)
        }
        return check(id, "pass", "forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining \(jsNum(a)), \(jsNum(b)), forged \(jsNum(f)), \(jsNum(c))). A count that is too LOW is not observable from one client.", observed: observed)
    }

    // MARK: suites

    static func isB64u(_ x: String, exactly: Int? = nil) -> Bool {
        let u = Array(x.utf16)
        guard !u.isEmpty, exactly.map({ u.count == $0 }) ?? true else { return false }
        return u.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F || $0 == 0x2D }
    }

    static func isPq(_ alg: N) -> Bool { if case let .str(x) = alg { return x != "ed25519" && registry.contains(x) }; return false }

    public static func checkAllowedSuites(_ cfg: N) -> N {
        let id = "suites.allowed"
        guard let v = at(cfg, "verifier"), v.truthy else { return check(id, "skip", "no verifier configuration given (config verifier.*)") }
        guard let list = v.member("allowedSuites") else {
            return check(id, "warn", "allowedSuites is unset: every registered suite is accepted (\(registry.count): \(registry.joined(separator: ", ")))", remediation: SUITES_REMEDIATION)
        }
        guard case let .arr(items) = list, !items.isEmpty else {
            return check(id, "fail", "allowedSuites is empty or not a list: no PCActn can verify", remediation: SUITES_REMEDIATION)
        }
        let unknown = items.filter { if case let .str(x) = $0 { return !registry.contains(x) }; return true }
        if !unknown.isEmpty {
            return check(id, "fail", "allowedSuites names suite(s) outside the registry: \(unknown.map { jsStr($0) }.joined(separator: ", ")) (known: \(registry.joined(separator: ", ")))", remediation: SUITES_REMEDIATION)
        }
        return check(id, "pass", "allowedSuites = \(items.map { PCASchema.text($0) }.joined(separator: ", "))")
    }

    public static func checkPqBinding(_ cfg: N) throws -> N {
        let id = "suites.pq-binding"
        guard let v = at(cfg, "verifier"), v.truthy else { return check(id, "skip", "no verifier configuration given (config verifier.*)") }
        func fail(_ d: String) -> N { check(id, "fail", d, remediation: PQ_REMEDIATION) }
        if case .bool(true)? = v.member("allowUnboundPq") {
            return fail("allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key")
        }
        var pinCount: Int?
        if let pins = v.member("pqPins") {
            guard case let .obj(entries) = pins else { return fail("pqPins is not an object of { ed25519 identity: pq public key }") }
            let bad = entries.filter { !isB64u($0.key, exactly: 43) || stringOf($0.value).map { !isB64u($0) } ?? true }
            if !bad.isEmpty {
                return fail("pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): \(bad.map { $0.key }.joined(separator: ", "))")
            }
            pinCount = entries.count
        }
        let suites: [N]
        switch v.member("allowedSuites") {
        case nil, .null?: suites = registry.map { .str($0) }
        case let .arr(a)?: suites = a
        default: throw JSError("(v.allowedSuites ?? Object.keys(SIG_SUITES)).filter is not a function")
        }
        let pq = suites.filter(isPq)
        if pq.isEmpty { return check(id, "pass", "no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)") }
        let pinned = (pinCount ?? 0) > 0
        let names = pq.map { PCASchema.text($0) }.joined(separator: ", ")
        if !pinned, !(v.member("trustedRoot") == .bool(true)) {
            return check(id, "warn", "post-quantum suite(s) accepted (\(names)) with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned", remediation: PQ_REMEDIATION)
        }
        return check(id, "pass", "PQ suites (\(names)) are bound: \(pinned ? "\(pinCount!) pin(s)" : "stored trustedRoot"); allowUnboundPq off")
    }

    // MARK: root caveats and enforcement

    /// The installed library as the doctor probes it.
    public struct LoadedPca {
        public var version: String
        public var path: String
        /// Decides a payment of `amount` USD under a root grant carrying `rootCaveat`: (allowed, reasons). May throw.
        public var probe: (JObject, Double) throws -> (allowed: Bool, reasons: [String])
        public init(version: String, path: String, probe: @escaping (JObject, Double) throws -> (allowed: Bool, reasons: [String])) {
            self.version = version; self.path = path; self.probe = probe
        }
    }

    /// -1 / 0 / 1 for a < b / = / > over major.minor.patch (pre-release tags ignored); NaN parts compare as -1.
    public static func compareVersion(_ a: String, _ b: String) -> Int {
        func parts(_ t: String) -> [Double] {
            let pieces = t.split(omittingEmptySubsequences: false) { $0 == "." || $0 == "+" || $0 == "-" }.map(String.init)
            return pieces.prefix(3).map { number($0) }
        }
        let pa = parts(a), pb = parts(b)
        for i in 0..<3 {
            let x = i < pa.count && pa[i].isFinite ? pa[i] : -1
            let y = i < pb.count && pb[i].isFinite ? pb[i] : -1
            if x != y { return x < y ? -1 : 1 }
        }
        return 0
    }

    public static func checkRootCaveats(_ cfg: N, loadPca: (String?) throws -> LoadedPca) -> N {
        let id = "caveats.root"
        let dir = stringOf(at(cfg, "verifier", "pcaDir"))
        let pca: LoadedPca
        do { pca = try loadPca(dir) } catch {
            return check(id, "fail", "cannot load @atlasauth/pca\(dir.map { " from \($0)" } ?? ""): \(message(error))", remediation: CAVEAT_REMEDIATION)
        }
        let whereText = "@atlasauth/pca \(pca.version) at \(pca.path)"
        if compareVersion(pca.version, ROOT_CAVEAT_MIN_VERSION) < 0 {
            return check(id, "fail", "\(whereText): root caveats outside the envelope are NOT enforced before \(ROOT_CAVEAT_MIN_VERSION) (legacy behaviour)", remediation: CAVEAT_REMEDIATION)
        }
        let over: (allowed: Bool, reasons: [String]), under: (allowed: Bool, reasons: [String]), unknown: (allowed: Bool, reasons: [String])
        do {
            over = try pca.probe(["type": .string("max_spend"), "usd": .int(100)], 150)
            under = try pca.probe(["type": .string("max_spend"), "usd": .int(100)], 50)
            unknown = try pca.probe(["type": .string("pca-doctor-unknown-caveat")], 50)
        } catch {
            return check(id, "fail", "\(whereText): the enforcement probe could not run: \(message(error))", remediation: CAVEAT_REMEDIATION)
        }
        func d(_ x: (allowed: Bool, reasons: [String])) -> N { obj([("allowed", .bool(x.allowed)), ("reasons", arr(x.reasons))]) }
        let observed = obj([("version", s(pca.version)), ("over", d(over)), ("under", d(under)), ("unknown", d(unknown))])
        if over.allowed || unknown.allowed {
            return check(id, "fail", "\(whereText): a root caveat was NOT enforced (\(over.allowed ? "max_spend 100 allowed a 150 payment" : "an unknown root caveat type was allowed"))", remediation: CAVEAT_REMEDIATION, observed: observed)
        }
        if !under.allowed {
            return check(id, "warn", "\(whereText): inconclusive: the control payment within the root max_spend was denied too (\(under.reasons.joined(separator: "; ")))", observed: observed)
        }
        return check(id, "pass", "\(whereText): root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)", observed: observed)
    }

    public static func checkEnforcement(_ cfg: N) throws -> N {
        let id = "verifier.enforcement"
        guard let v = at(cfg, "verifier"), v.truthy else { return check(id, "skip", "no verifier configuration given (config verifier.*)") }
        if v.member("insecureAllowUnenforced") == .bool(true) {
            return check(id, "fail", "requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny", remediation: "Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).")
        }
        var require: [String]?
        if let r = v.member("require") {
            guard case let .arr(items) = r else { throw JSError("Cannot read properties of \(r.isNull ? "null" : "a non-list") (reading 'includes')") }
            let have = items.map { PCASchema.stringify($0) }
            let missing = DEFAULT_REQUIRED.filter { !have.contains(PCASchema.stringify(.str($0))) }
            if !missing.isEmpty {
                return check(id, "warn", "the require list drops default check(s): \(missing.joined(separator: ", "))", remediation: "Keep every default required check (\(DEFAULT_REQUIRED.joined(separator: ", "))) and add to it.")
            }
            require = items.map { PCASchema.text($0) }
        }
        return check(id, "pass", require.map { "require = \($0.joined(separator: ", "))" } ?? "default required checks; insecureAllowUnenforced off")
    }

    // MARK: configuration

    public static func configProblems(_ cfg: N) -> [String] {
        var out: [String] = []
        func pos(_ name: String, _ v: N?, int: Bool = false) {
            guard let v = v else { return }
            if case let .num(d) = v, d.isFinite, d > 0, !(int && !isInteger(d)) { return }
            out.append("\(name) must be a positive \(int ? "integer" : "number")")
        }
        func nonneg(_ name: String, _ v: N?) {
            guard let v = v else { return }
            if case let .num(d) = v, isInteger(d), d >= 0, !isNegZero(d) { return }
            out.append("\(name) must be a non-negative integer")
        }
        pos("clock.maxSkewMs", at(cfg, "clock", "maxSkewMs"))
        pos("clock.timeoutMs", at(cfg, "clock", "timeoutMs"))
        if let wf = at(cfg, "clock", "warnFraction") {
            if case let .num(d) = wf, d > 0, d <= 1 {} else { out.append("clock.warnFraction must be a number in (0, 1]") }
        }
        pos("store.concurrency", at(cfg, "store", "concurrency"), int: true)
        pos("store.rounds", at(cfg, "store", "rounds"), int: true)
        nonneg("proxy.trustedProxyCount", at(cfg, "proxy", "trustedProxyCount"))
        nonneg("proxy.hops", at(cfg, "proxy", "hops"))
        if let u = at(cfg, "url") {
            if let parsed = WhatwgURL.parse(PCASchema.text(u)) { if parsed.scheme != "https" && parsed.scheme != "http" { out.append("url must be an http(s) URL") } }
            else { out.append("url is not a valid URL") }
        }
        return out
    }

    /// The doctor's environment variables (as the API and the guides name them). Throws the reference's messages.
    public static func configFromEnv(_ env: [String: String]) throws -> N {
        var top: [(String, N)] = []
        if let u = env["PCA_DOCTOR_URL"], !u.isEmpty { top.append(("url", s(u))) }
        if let r = env["PCA_DOCTOR_REFERENCE_URL"], !r.isEmpty { top.append(("clock", obj([("referenceUrl", s(r))]))) }
        if let st = env["PCA_DOCTOR_STORE"], !st.isEmpty { top.append(("store", obj([("adapter", s(st))]))) }
        var proxy: [(String, N?)] = []
        func int(_ name: String, _ v: String) throws -> Double? {
            if v.isEmpty { return nil }
            let n = number(v)
            guard isInteger(n), n >= 0, !isNegZero(n) else { throw JSError("\(name) must be a non-negative integer") }
            return n
        }
        if let v = env["TRUSTED_PROXY_COUNT"] { proxy.append(("trustedProxyCount", try int("TRUSTED_PROXY_COUNT", v).map { num($0) })) }
        if let h = env["TRUSTED_PROXY_HEADER"], !h.isEmpty {
            let l = h.lowercased()
            guard ["x-forwarded-for", "forwarded", "x-real-ip"].contains(l) else { throw JSError("TRUSTED_PROXY_HEADER must be one of x-forwarded-for, forwarded, x-real-ip") }
            proxy.append(("header", s(l)))
        }
        if let v = env["PCA_TRUSTED_PROXY_HOPS"] { proxy.append(("hops", try int("PCA_TRUSTED_PROXY_HOPS", v).map { num($0) })) }
        if !proxy.isEmpty { top.append(("proxy", obj(proxy))) }
        var verifier: [(String, N?)] = []
        if let list = env["PCA_ALLOWED_SUITES"] {
            verifier.append(("allowedSuites", arr(list.split(separator: ",", omittingEmptySubsequences: false).map { Attest.jsTrim(String($0)) }.filter { !$0.isEmpty })))
        }
        if let raw = env["PCA_PQ_PINS"], !raw.isEmpty {
            guard let pins = try? PCASchema.parse(raw) else { throw JSError("PCA_PQ_PINS is not valid JSON") } // never echo the value
            guard case let .obj(entries) = pins, entries.allSatisfy({ stringOf($0.value) != nil }) else { throw JSError("PCA_PQ_PINS must be a JSON object of issuer -> public key strings") }
            verifier.append(("pqPins", pins))
        }
        if let b = env["PCA_ALLOW_UNBOUND_PQ"] {
            let l = b.lowercased()
            verifier.append(("allowUnboundPq", .bool(["1", "true", "yes", "on"].contains(l))))
        }
        if !verifier.isEmpty { top.append(("verifier", obj(verifier))) }
        return .obj(top.map { (key: $0.0, value: $0.1) })
    }

    /// Two-level merge: later sources win per field inside each section.
    public static func mergeConfig(_ cs: [N]) throws -> N {
        var out: [(key: String, value: N)] = []
        for c in cs {
            guard case let .obj(entries) = c else { continue }
            for (k, val) in entries {
                if k == "__proto__" || k == "constructor" || k == "prototype" { throw JSError("config key \"\(k)\" is not allowed") }
                var merged = val
                if case let .obj(add) = val {
                    var base: [(key: String, value: N)] = []
                    if let i = out.firstIndex(where: { $0.key == k }) {
                        switch out[i].value {
                        case let .obj(m): base = m
                        case let .str(x): base = x.utf16.enumerated().map { (key: String($0.offset), value: N.str(String(utf16CodeUnits: [$0.element], count: 1))) }
                        case let .arr(a): base = a.enumerated().map { (key: String($0.offset), value: $0.element) }
                        default: break
                        }
                    }
                    for (ak, av) in add { if let j = base.firstIndex(where: { $0.key == ak }) { base[j].value = av } else { base.append((ak, av)) } }
                    merged = .obj(base)
                }
                if let i = out.firstIndex(where: { $0.key == k }) { out[i].value = merged } else { out.append((k, merged)) }
            }
        }
        return .obj(out)
    }

    // MARK: running

    public struct Deps {
        public var fetch: FetchLike?
        public var now: (() -> Double)?
        public var rand: (() -> Double)?
        public var loadPca: ((String?) throws -> LoadedPca)?
        public init(fetch: FetchLike? = nil, now: (() -> Double)? = nil, rand: (() -> Double)? = nil, loadPca: ((String?) throws -> LoadedPca)? = nil) {
            self.fetch = fetch; self.now = now; self.rand = rand; self.loadPca = loadPca
        }
    }

    static func guarded(_ id: String, _ run: () throws -> [N]) -> [N] {
        do { return try run() } catch {
            return [check(id, "fail", "\(id) could not run: \(scrubText(message(error)))", remediation: "Fix the configuration or the dependency named above and run the doctor again.")]
        }
    }

    /// The replay-store checks need an adapter; without one they are skipped like the reference.
    public static func checkStore(_ cfg: N) -> [N] {
        guard let spec = at(cfg, "store", "adapter"), spec.truthy else {
            let d = "no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely"
            return [check("store.atomicity", "skip", d), check("store.durability", "skip", d)]
        }
        return [check("store.atomicity", "fail", "cannot load the store adapter \(PCASchema.text(spec)): store adapters are not loadable in this runtime",
                      remediation: "Point --store at a module exporting a store adapter (see the store conformance kit guide).")]
    }

    public static func runDoctor(_ cfg: N, only: [String]? = nil, deps: Deps = Deps()) -> [N] {
        let problems = configProblems(cfg)
        if !problems.isEmpty {
            return problems.map { check("config", "fail", scrubText("invalid configuration: \($0)"), remediation: "Correct the setting; no check was run.") }
        }
        let groups = only ?? CHECK_GROUPS
        let fetch: FetchLike = deps.fetch ?? liveFetch
        let load: (String?) throws -> LoadedPca = deps.loadPca ?? { _ in throw JSError("no installed library probe is configured in this runtime") }
        var out: [N] = []
        if groups.contains("clock") { out += guarded("clock") { [checkClock(cfg, fetch: fetch, now: deps.now)] } }
        if groups.contains("store") { out += guarded("store") { checkStore(cfg) } }
        if groups.contains("proxy") {
            out += guarded("proxy.config") { [checkProxyConfig(cfg)] }
            out += guarded("proxy.probe") { [try checkProxyProbe(cfg, fetch: fetch, rand: deps.rand)] }
        }
        if groups.contains("suites") {
            out += guarded("suites.allowed") { [checkAllowedSuites(cfg)] }
            out += guarded("suites.pq") { [try checkPqBinding(cfg)] }
        }
        if groups.contains("caveats") {
            out += guarded("caveats.root") { [checkRootCaveats(cfg, loadPca: load)] }
            out += guarded("caveats.enforcement") { [try checkEnforcement(cfg)] }
        }
        return out.map { scrub($0) }
    }

    /// The verdict: fail if any check failed; warn if any warned (fail under strict); else pass. A run in which nothing was checked is a fail.
    public static func verdictOf(_ results: [N], strict: Bool = false) -> String {
        func status(_ r: N) -> String { stringOf(r.member("status")) ?? "" }
        if !results.contains(where: { status($0) != "skip" }) { return "fail" }
        if results.contains(where: { status($0) == "fail" }) { return "fail" }
        if results.contains(where: { status($0) == "warn" }) { return strict ? "fail" : "warn" }
        return "pass"
    }

    static func padEnd(_ x: String, _ n: Int) -> String { x + String(repeating: " ", count: Swift.max(0, n - x.utf16.count)) }

    public static func formatResults(_ results: [N], target: String?, strict: Bool = false) -> String {
        var lines = ["pca-doctor\(target.map { $0.isEmpty ? "" : ": \($0)" } ?? "")"]
        for r in results {
            let st = (stringOf(r.member("status")) ?? "").uppercased()
            lines.append("  \(padEnd(st, 4))  \(padEnd(stringOf(r.member("id")) ?? "", 20)) \(stringOf(r.member("detail")) ?? "")")
            if let f = r.member("remediation"), f.truthy { lines.append("  \(padEnd("", 4))  \(padEnd("", 20)) fix: \(PCASchema.text(f))") }
        }
        func count(_ st: String) -> Int { results.filter { stringOf($0.member("status")) == st }.count }
        if !results.contains(where: { stringOf($0.member("status")) != "skip" }) {
            lines.append("  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified")
        }
        lines.append("Summary: \(count("pass")) pass, \(count("warn")) warn, \(count("fail")) fail, \(count("skip")) skip -> \(verdictOf(results, strict: strict).uppercased())")
        return lines.joined(separator: "\n")
    }

    /// `JSON.stringify(value, null, 2)` of an ordered tree.
    public static func prettyJSON(_ n: N, _ indent: String = "") -> String {
        let inner = indent + "  "
        switch n {
        case let .arr(a): return a.isEmpty ? "[]" : "[\n" + a.map { inner + prettyJSON($0, inner) }.joined(separator: ",\n") + "\n" + indent + "]"
        case let .obj(m): return m.isEmpty ? "{}" : "{\n" + m.map { inner + PCASchema.quote($0.key) + ": " + prettyJSON($0.value, inner) }.joined(separator: ",\n") + "\n" + indent + "}"
        default: return PCASchema.stringify(n)
        }
    }

    // MARK: command line

    public struct Args {
        public var config: String?
        public var flags: N = .obj([])
        public var only: [String] = CHECK_GROUPS
        public var json = false, strict = false, help = false
    }

    static func setMember(_ n: inout N, _ section: String?, _ key: String, _ value: N?) {
        guard case var .obj(top) = n else { return }
        func put(_ m: inout [(key: String, value: N)], _ k: String, _ v: N?) {
            if let v = v { if let i = m.firstIndex(where: { $0.key == k }) { m[i].value = v } else { m.append((k, v)) } }
            else if !m.contains(where: { $0.key == k }) { /* an undefined value leaves the member absent */ }
        }
        guard let sec = section else { put(&top, key, value); n = .obj(top); return }
        var inner: [(key: String, value: N)] = []
        if let i = top.firstIndex(where: { $0.key == sec }), case let .obj(m) = top[i].value { inner = m }
        put(&inner, key, value)
        if let i = top.firstIndex(where: { $0.key == sec }) { top[i].value = .obj(inner) } else { top.append((sec, .obj(inner))) }
        n = .obj(top)
    }

    public static func parseDoctorArgs(_ argv: [String]) throws -> Args {
        var a = Args()
        func groups(_ flag: String, _ v: String?) throws -> [String] {
            let g = (v ?? "").split(separator: ",", omittingEmptySubsequences: true).map(String.init)
            let bad = g.filter { !CHECK_GROUPS.contains($0) }
            if !bad.isEmpty || g.isEmpty { throw JSError("\(flag): unknown check group(s) \(bad.isEmpty ? "(none given)" : bad.joined(separator: ", "))") }
            return g
        }
        func numberArg(_ flag: String, _ v: String?) throws -> N {
            let n = v.map { number($0) } ?? .nan
            guard let v = v, !v.isEmpty, n.isFinite else { throw JSError("\(flag) needs a number") }
            return num(n)
        }
        var i = 0
        func next() -> String? { i += 1; return i < argv.count ? argv[i] : nil }
        while i < argv.count {
            let k = argv[i]
            switch k {
            case "--url": setMember(&a.flags, nil, "url", next().map { s($0) })
            case "--config": a.config = next()
            case "--store": setMember(&a.flags, "store", "adapter", next().map { s($0) })
            case "--store-option":
                let kv = next() ?? ""
                guard let eq = kv.firstIndex(of: "="), kv.distance(from: kv.startIndex, to: eq) >= 1 else { throw JSError("--store-option needs k=v") }
                var opts: [(key: String, value: N)] = []
                if case let .obj(top) = a.flags, let st = top.first(where: { $0.key == "store" }), case let .obj(sm) = st.value, let o = sm.first(where: { $0.key == "options" }), case let .obj(om) = o.value { opts = om }
                let key = String(kv[..<eq]), val = String(kv[kv.index(after: eq)...])
                if let j = opts.firstIndex(where: { $0.key == key }) { opts[j].value = s(val) } else { opts.append((key, s(val))) }
                setMember(&a.flags, "store", "options", .obj(opts))
            case "--reference": setMember(&a.flags, "clock", "referenceUrl", next().map { s($0) })
            case "--max-skew-ms": setMember(&a.flags, "clock", "maxSkewMs", try numberArg(k, next()))
            case "--trusted-proxy-count": setMember(&a.flags, "proxy", "trustedProxyCount", try numberArg(k, next()))
            case "--proxy-header":
                let h = (next() ?? "").lowercased()
                guard ["x-forwarded-for", "forwarded", "x-real-ip"].contains(h) else { throw JSError("--proxy-header must be x-forwarded-for, forwarded or x-real-ip") }
                setMember(&a.flags, "proxy", "header", s(h))
            case "--proxy-hops": setMember(&a.flags, "proxy", "hops", try numberArg(k, next()))
            case "--no-probe": setMember(&a.flags, "proxy", "probe", .bool(false))
            case "--pca-dir": setMember(&a.flags, "verifier", "pcaDir", next().map { s($0) })
            case "--only": a.only = try groups(k, next())
            case "--skip":
                let sk = try groups(k, next())
                a.only = a.only.filter { !sk.contains($0) }
            case "--strict": a.strict = true
            case "--json": a.json = true
            case "-h", "--help": a.help = true
            default: throw JSError("unknown argument \(k)")
            }
            i += 1
        }
        return a
    }

    /// A JSON config file (a JS module config is not loadable here).
    public static func loadConfigFile(_ path: String) throws -> N {
        guard path.hasSuffix(".json") else { throw JSError("only JSON config files are loadable in this runtime: \(path)") }
        guard let data = FileManager.default.contents(atPath: path) else { throw JSError("cannot read \(path)") }
        return try PCASchema.parse(String(decoding: data, as: UTF8.self))
    }

    /// Runs the command line: prints through `print` / `printErr` and returns the exit code (1 on any fail, 2 on usage errors).
    public static func main(_ argv: [String], env: [String: String] = ProcessInfo.processInfo.environment, deps: Deps = Deps(),
                            print: (String) -> Void, printErr: (String) -> Void) -> Int {
        let a: Args
        let cfg: N
        do {
            a = try parseDoctorArgs(argv)
            if a.help { print(USAGE); return 0 }
            cfg = try mergeConfig([try a.config.map { try loadConfigFile($0) } ?? .obj([]), try configFromEnv(env), a.flags])
        } catch {
            printErr("\(scrubText(message(error)))\n\n\(USAGE)")
            return 2
        }
        let results = runDoctor(cfg, only: a.only, deps: deps)
        let verdict = verdictOf(results, strict: a.strict)
        let target = at(cfg, "url")
        if a.json {
            print(prettyJSON(obj([("target", target ?? .null), ("verdict", s(verdict)), ("results", .arr(results))])))
        } else {
            print(formatResults(results, target: target.flatMap { $0.truthy ? PCASchema.text($0) : nil }, strict: a.strict))
        }
        return verdict == "fail" ? 1 : 0
    }

    // MARK: network

    /// The live network client: HEAD for a Date header (redirects are not followed) and GET for the probe path.
    public static func liveFetch(_ method: String, _ url: String, _ headers: [String: String], _ timeoutMs: Double) throws -> FetchResponse {
        guard let u = URL(string: url), let scheme = u.scheme, scheme == "http" || scheme == "https" else { throw JSError("Invalid URL", code: "ERR_INVALID_URL") }
        var req = URLRequest(url: u, timeoutInterval: timeoutMs / 1000)
        req.httpMethod = method
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        final class NoRedirect: NSObject, URLSessionTaskDelegate {
            func urlSession(_ s: URLSession, task: URLSessionTask, willPerformHTTPRedirection r: HTTPURLResponse, newRequest: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
        }
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
        let sem = DispatchSemaphore(value: 0)
        var result: Result<FetchResponse, Error> = .failure(JSError("no response"))
        session.dataTask(with: req) { _, resp, err in
            if let e = err { result = .failure(e) }
            else if let h = resp as? HTTPURLResponse {
                result = .success(FetchResponse(date: h.value(forHTTPHeaderField: "Date"), rateLimitRemaining: h.value(forHTTPHeaderField: "RateLimit-Remaining")))
            }
            sem.signal()
        }.resume()
        sem.wait()
        session.finishTasksAndInvalidate()
        return try result.get()
    }
}
