import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Persists the per-issuer key state `{v: 1, issuer, fetchedAtMs, anchors: [{spki, kind, notBeforeMs, notAfterMs, firstSeenMs}]}`.
public protocol PCAMaaKeyStateStore: AnyObject {
    func get(_ issuer: String) throws -> JSONValue?
    func set(_ issuer: String, _ state: JSONValue) throws
}


/// Trust in Azure MAA token-signing keys: the guarded certs fetch (https origins only, size and redirect limits, an injected transport), JWKS evaluation
/// (x5c chains to pinned roots or intermediates, or genuine self-signed keys named by the issuer URL), a rotation-safe trust store (memory or an atomic
/// key/value store) with re-pinning under a release-signed manifest, multi-vantage corroboration, and the built-in release-signed pins. Keys, states and
/// results are the language-neutral JSON of the wire; every failure is closed. The trust object is synchronous.
public enum PCAMaaKeys {
    public static let BUILTIN_CHAIN_LEAF_CN = ["Microsoft Azure Attestation 2020"]
    public static var BUILTIN_MAA_PINS_ISSUER_ID: String { MaaPinsData.issuerId }
    /// The built-in pins issuer (id to `{alg, keys}`): what verifies the shipped pin manifest.
    public static var BUILTIN_MAA_PINS_ISSUER_KEYS: JSONValue { .object([JKey(MaaPinsData.issuerId): issuerKey]) }
    private static var issuerKey: JSONValue { (try? StrictJSON.parseLenient(MaaPinsData.issuerKeyJSON)) ?? .null }

    private static let HOUR: Double = 3_600_000
    private static let DAY: Double = 24 * 3_600_000
    private static let MAX_JWKS_KEYS = 32, MAX_X5C = 8, MAX_X5C_B64 = 131_072

    private static func err(_ m: String) -> JSError { JSError(m) }
    private static func msg(_ e: Error) -> String { (e as? JSError)?.message ?? (e as? AttestError)?.message ?? "\(e)" }
    private static func ms(_ d: Double) -> JSONValue { StoreJ.num(d) }
    private static func isInt(_ v: JSONValue?) -> Double? { IV.num(v).flatMap { $0.isFinite && $0.rounded() == $0 && abs($0) <= IV.MAX_SAFE ? $0 : nil } }
    private static func strings(_ v: JSONValue?) -> [String]? { v?.asArray.map { $0.compactMap { $0.asString } } }
    private static func jsSorted(_ a: [String]) -> [String] { a.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) } }

    /// `^https:\/\/[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`
    static func issuerUrl(_ s: String?) -> Bool {
        guard let s = s, s.unicodeScalars.starts(with: "https://".unicodeScalars) else { return false }
        let rest = Array(s.unicodeScalars.dropFirst(8))
        func alnum(_ c: Unicode.Scalar) -> Bool { (c.value >= 48 && c.value <= 57) || (c.value >= 97 && c.value <= 122) }
        var i = 0
        while i < rest.count, alnum(rest[i]) || rest[i] == "." || rest[i] == "-" { i += 1 }
        guard let f = rest[0..<i].first, let l = rest[0..<i].last, alnum(f), alnum(l) else { return false }
        let tail = rest[i...]
        if tail.isEmpty { return true }
        return tail.first == ":" && (1...5).contains(tail.count - 1) && tail.dropFirst().allSatisfy { $0.value >= 48 && $0.value <= 57 }
    }

    private static func hex64(_ s: String?) -> Bool {
        guard let u = s?.unicodeScalars else { return false }
        return u.count == 64 && u.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102) }
    }

    // MARK: policy

    /// The built-in pins a policy uses: none, the shipped ones, or a caller's signed source `{manifest, issuerKeys, minVersion?}`.
    public enum BuiltinPins { case disabled, shipped, source(JSONValue) }

    public struct Policy {
        public var trustedIssuers: [String]
        public var ttlMs: Double?
        public var maxStaleMs: Double?
        public var maxNewKeysPerFetch: Double?
        public var maxInitialKeys: Double?
        public var maxKeyAgeMs: Double?
        public var requireOverlap: Bool?
        public var allowTrustOnFirstUse: Bool?
        public var initialPins: [String: [String]]?
        public var chainRootSpkiSha256: [String]?
        public var chainIntermediateSpkiSha256: [String]?
        public var builtinPins: BuiltinPins
        public var chainLeafCn: [String]?
        public var clockSkewMs: Double?
        public var fetchTimeoutMs: Double?
        public var maxBodyBytes: Double?
        public init(trustedIssuers: [String], ttlMs: Double? = nil, maxStaleMs: Double? = nil, maxNewKeysPerFetch: Double? = nil, maxInitialKeys: Double? = nil, maxKeyAgeMs: Double? = nil,
                    requireOverlap: Bool? = nil, allowTrustOnFirstUse: Bool? = nil, initialPins: [String: [String]]? = nil, chainRootSpkiSha256: [String]? = nil,
                    chainIntermediateSpkiSha256: [String]? = nil, builtinPins: BuiltinPins = .shipped, chainLeafCn: [String]? = nil, clockSkewMs: Double? = nil,
                    fetchTimeoutMs: Double? = nil, maxBodyBytes: Double? = nil) {
            self.trustedIssuers = trustedIssuers; self.ttlMs = ttlMs; self.maxStaleMs = maxStaleMs; self.maxNewKeysPerFetch = maxNewKeysPerFetch; self.maxInitialKeys = maxInitialKeys
            self.maxKeyAgeMs = maxKeyAgeMs; self.requireOverlap = requireOverlap; self.allowTrustOnFirstUse = allowTrustOnFirstUse; self.initialPins = initialPins
            self.chainRootSpkiSha256 = chainRootSpkiSha256; self.chainIntermediateSpkiSha256 = chainIntermediateSpkiSha256; self.builtinPins = builtinPins; self.chainLeafCn = chainLeafCn
            self.clockSkewMs = clockSkewMs; self.fetchTimeoutMs = fetchTimeoutMs; self.maxBodyBytes = maxBodyBytes
        }
    }

    // MARK: the built-in pins

    private static let MAX_LIFETIME_MS: Double = 400 * 24 * 3_600_000
    private static let MIN_VANTAGES: Double = 3

    /// Verifies the release-signed pin manifest (the shipped one, or `source = {manifest, issuerKeys, minVersion?}`) and returns its pins at `nowMs`:
    /// `{ok: true, version, digest, expiresAt, maaSigningSpkis, revokedSigningSpkis, maaChainRootSpkis, maaChainIntermediateSpkis, vantages, method}` or
    /// `{ok: false, reason}`. The manifest must carry one corroboration entry of at least three vantages, signing pins and the chain pins.
    public static func loadBuiltinMaaPins(nowMs: Double, source: JSONValue? = nil) -> JSONValue {
        func no(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        do {
            guard nowMs.isFinite, nowMs.rounded() == nowMs, abs(nowMs) <= IV.MAX_SAFE else { return no("nowMs must be an integer") }
            let manifest: JSONValue?, issuerKeys: JSONValue, minVersion: JSONValue?
            if let s = source {
                manifest = s.get("manifest"); issuerKeys = s.get("issuerKeys") ?? .null; minVersion = s.get("minVersion")
            } else {
                manifest = try StrictJSON.parseLenient(MaaPinsData.manifestJSON); issuerKeys = BUILTIN_MAA_PINS_ISSUER_KEYS; minVersion = .int(Int64(MaaPinsData.minVersion))
            }
            // the manifest is judged at its own notBefore (when it carries one), so only the release window below depends on the clock
            let at = JS.present(manifest?.get("body")?.get("notBefore")).map { IV.num($0) ?? .nan } ?? nowMs
            let v0 = PCAAttestAllowlist.verifyAllowlistManifest(manifest, PCAAttestAllowlist.VerifyOptions(
                issuerKeys: issuerKeys, nowMs: at, minVersion: JS.present(minVersion) ?? .int(1), maxLifetimeMs: StoreJ.num(MAX_LIFETIME_MS)))
            if v0.get("ok") != .bool(true) { return no("\(v0.get("code")?.asString ?? ""): \(v0.get("reason")?.asString ?? "")") }
            let body = v0.get("body")!
            let notBefore = IV.num(body.get("notBefore"))!, expiresAt = IV.num(body.get("expiresAt"))!
            let p = try PCAAttestAllowlist.projectAllowlist(v0, nowMs: notBefore)
            let corr = p.get("corroboration")?.asArray ?? []
            guard corr.count == 1 else { return no("manifest must carry exactly one attest-corroboration entry") }
            let label = corr[0].get("label")?.asString ?? ""
            // ^vantages=([0-9]+);method=(.*)$
            let u = Array(label.unicodeScalars)
            let head = Array("vantages=".unicodeScalars)
            var vantages: Double = 0
            var method = ""
            var matched = false
            if u.count > head.count, Array(u[0..<head.count]) == head {
                var i = head.count
                let start = i
                while i < u.count, u[i].value >= 48 && u[i].value <= 57 { i += 1 }
                let mid = Array(";method=".unicodeScalars)
                if i > start, i + mid.count <= u.count, Array(u[i..<(i + mid.count)]) == mid {
                    let tail = String(String.UnicodeScalarView(u[(i + mid.count)...]))
                    if !tail.unicodeScalars.contains(where: { $0 == "\n" || $0 == "\r" || $0.value == 0x2028 || $0.value == 0x2029 }) {
                        matched = true
                        vantages = IV.jsNumber(String(String.UnicodeScalarView(u[start..<i])))
                        method = tail
                    }
                }
            }
            if !matched || vantages < MIN_VANTAGES { return no("corroboration records \(JS.number(matched ? vantages : 0)) vantages < required \(JS.number(MIN_VANTAGES))") }
            if (p.get("maaSigningSpkis")?.asObject ?? [:]).isEmpty { return no("manifest pins no MAA signing key") }
            if (p.get("maaChainRootSpkis")?.asArray ?? []).isEmpty || (p.get("maaChainIntermediateSpkis")?.asArray ?? []).isEmpty {
                return no("manifest lacks the Microsoft chain root / intermediate pins")
            }
            var revoked = JObject()
            for r in p.get("revoked")?.asArray ?? [] where r.get("kind")?.asString == "maa-signing-spki" {
                let l = JKey(r.get("label")?.asString ?? "")
                revoked[l] = .array((revoked[l]?.asArray ?? []) + [r.get("value") ?? .null])
            }
            if !(nowMs >= notBefore) { return no("built-in pins are not yet valid (clock behind the release)") }
            if !(nowMs <= expiresAt) { return no("built-in pins expired; update the package or pass explicit initialPins") }
            return .object(["ok": .bool(true), "version": v0.get("version") ?? .null, "digest": v0.get("digest") ?? .null, "expiresAt": body.get("expiresAt") ?? .null,
                            "maaSigningSpkis": p.get("maaSigningSpkis") ?? .object([:]), "revokedSigningSpkis": .object(revoked), "maaChainRootSpkis": p.get("maaChainRootSpkis") ?? .array([]),
                            "maaChainIntermediateSpkis": p.get("maaChainIntermediateSpkis") ?? .array([]), "vantages": StoreJ.num(vantages), "method": .string(method)])
        } catch {
            return no(msg(error))
        }
    }

    // MARK: the guarded certs fetch

    /// What the transport answered: the status, the final URL (when it knows one), the declared `content-length` text and the body.
    public struct Response {
        public var status: Int
        public var url: String?
        public var contentLength: String?
        public var body: [UInt8]
        public init(status: Int, url: String? = nil, contentLength: String? = nil, body: [UInt8]) { self.status = status; self.url = url; self.contentLength = contentLength; self.body = body }
    }

    /// The injected transport: a GET of `url` that must refuse redirects. (Default: a URLSession GET that does not follow them.)
    public typealias Fetch = (String) throws -> Response

    private final class NoRedirect: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    }

    /// A blocking GET with `timeoutMs`, never following a redirect.
    public static func defaultFetch(timeoutMs: Double) -> Fetch {
        { url in
            guard let u = URL(string: url) else { throw JSError("MAA certs fetch: invalid URL") }
            var req = URLRequest(url: u)
            req.timeoutInterval = timeoutMs / 1000
            req.setValue("application/json", forHTTPHeaderField: "accept")
            final class Box: @unchecked Sendable { var v: Result<Response, Error> = .failure(JSError("MAA certs fetch failed: no response")) }
            let sem = DispatchSemaphore(value: 0), box = Box()
            let session = URLSession(configuration: .ephemeral, delegate: NoRedirect(), delegateQueue: nil)
            session.dataTask(with: req) { data, resp, e in
                if let e = e { box.v = .failure(e) }
                else if let h = resp as? HTTPURLResponse {
                    box.v = .success(Response(status: h.statusCode, url: h.url?.absoluteString, contentLength: h.value(forHTTPHeaderField: "content-length"), body: [UInt8](data ?? Data())))
                }
                sem.signal()
            }.resume()
            sem.wait()
            session.invalidateAndCancel()
            return try box.v.get()
        }
    }

    private static func parseJwks(_ x: JSONValue) throws -> JSONValue {
        guard case let .array(raw)? = x.get("keys") else { throw err("MAA certs: response has no keys array") }
        if raw.count > MAX_JWKS_KEYS { throw err("MAA certs: too many keys") }
        var keys: [JSONValue] = []
        for k in raw {
            guard k.isObject else { throw err("MAA certs: malformed key entry") }
            guard case let .array(x5c)? = k.get("x5c"), !x5c.isEmpty, x5c.count <= MAX_X5C,
                  x5c.allSatisfy({ if case let .string(s) = $0 { return !s.isEmpty && s.utf16.count <= MAX_X5C_B64 } else { return false } }) else { throw err("MAA certs: key without a well-formed x5c") }
            var o: JObject = ["x5c": .array(x5c)]
            for f in ["kid", "kty", "alg"] { if case .string? = k.get(f), let v = k.get(f) { o[JKey(f)] = v } }
            keys.append(.object(o))
        }
        return .object(["keys": .array(keys)])
    }

    /// Fetches `<issuer>/certs` through `fetch` and returns the checked JWKS `{keys: [{kid?, kty?, alg?, x5c}]}`. Throws on an issuer that is not an https
    /// origin, a non-2xx status, a response URL that differs from the request, a body over `maxBytes` (default 1 MiB) or declared larger, a body that is not
    /// UTF-8 JSON, more than 32 keys or a key without a well-formed x5c (1 to 8 non-empty strings of at most 131072 characters).
    public static func fetchMaaCerts(_ issuer: String, fetch: Fetch? = nil, timeoutMs: Double? = nil, maxBytes: Double? = nil) throws -> JSONValue {
        guard issuerUrl(issuer) else { throw err("fetchMaaCerts: issuer must be an https origin URL (no path, no trailing slash)") }
        let timeout = timeoutMs ?? 10_000, limit = maxBytes ?? 1_048_576
        let url = issuer + "/certs"
        let res = try (fetch ?? defaultFetch(timeoutMs: timeout))(url)
        if !(200...299).contains(res.status) { throw err("MAA certs fetch failed: HTTP \(res.status)") }
        if let u = res.url, !u.isEmpty, u != url { throw err("MAA certs fetch: response URL differs from the request (redirect)") }
        let declared = IV.jsNumber(res.contentLength ?? "0")
        if declared.isFinite, declared > limit { throw err("MAA certs response exceeds the size limit") }
        if Double(res.body.count) > limit { throw err("MAA certs response exceeds the size limit") }
        var bytes = res.body
        if bytes.starts(with: [0xef, 0xbb, 0xbf]) { bytes.removeFirst(3) } // TextDecoder drops one leading BOM
        guard let text = String(validatingUTF8CString: bytes), let parsed = try? StrictJSON.parseLenient(text) else { throw err("MAA certs response is not valid UTF-8 JSON") }
        return try parseJwks(parsed)
    }

    // MARK: JWKS evaluation

    private static func soleCn(_ subject: String) -> String? {
        let lines = subject.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
        guard lines.count == 1, lines[0].unicodeScalars.starts(with: "CN=".unicodeScalars) else { return nil }
        let v = String(lines[0].dropFirst(3))
        // `.` of the reference's pattern does not match a line terminator
        return v.unicodeScalars.contains(where: { $0 == "\r" || $0.value == 0x2028 || $0.value == 0x2029 }) ? nil : v
    }

    private static func leafCn(_ subject: String) -> String? {
        for l in subject.split(separator: "\n", omittingEmptySubsequences: false) where l.unicodeScalars.starts(with: "CN=".unicodeScalars) { return String(l.dropFirst(3)) }
        return nil
    }

    private static func keyStrengthError(_ c: AttCert) throws -> String? {
        let k = try Cert.keyOf(c)
        if k.typ == "rsa" {
            let bits = BigNat(bytes: k.rsaN).bitLength
            if !(bits >= 2048 && bits <= 8192) { return "RSA key size \(bits) outside 2048..8192" }
            return ACrypto.rsaKeyOK(n: k.rsaN, e: k.rsaE) ? nil : "RSA public exponent must be odd, at least 3 and at most 32 bits"
        }
        if k.typ == "ec" { return ["prime256v1", "secp384r1", "secp521r1"].contains(k.curve) ? nil : "EC curve '\(k.curve)' not allowed" }
        return "key type '\(k.typ)' not allowed"
    }

    private static func selfIssuedText(_ c: AttCert) -> Bool { Cert.nameText(c.rawIssuer) == Cert.nameText(c.rawSubject) }

    private struct Anchor { var spki: String; var kind: String; var from: Double; var to: Double }

    /// Evaluates a JWKS against the issuer and policy at `nowMs`: `{accepted: [{spki, kind, notBeforeMs, notAfterMs}], rejected: [{kid, reason}]}`. A
    /// single-certificate key must be a genuine self-signed certificate whose sole subject CN is the issuer URL (no wildcard, not older than the maximum
    /// age). A chained key needs the pinned root (and a pinned intermediate when any is configured) and an allowed leaf CN, and is accepted as the pinned
    /// anchor. Every certificate must be inside its validity window and of an allowed key type and strength.
    public static func evaluateMaaJwks(_ jwks: JSONValue?, issuer: String, policy: Policy, nowMs: Double) -> JSONValue {
        let skew = policy.clockSkewMs ?? 60_000, maxAge = policy.maxKeyAgeMs ?? 400 * DAY
        let roots = Set((policy.chainRootSpkiSha256 ?? []).map { $0.lowercased() }), inters = Set((policy.chainIntermediateSpkiSha256 ?? []).map { $0.lowercased() })
        var accepted: [Anchor] = []
        var rejected: [JSONValue] = []
        func put(_ a: Anchor) { if let i = accepted.firstIndex(where: { $0.spki == a.spki }) { accepted[i] = a } else { accepted.append(a) } }
        let keys = jwks?.get("keys")?.asArray ?? []
        for (i, key) in keys.enumerated() {
            let kid: JSONValue = JS.present(key.get("kid")) ?? .string("#\(i)")
            func no(_ r: String) { rejected.append(.object(["kid": kid, "reason": .string(r)])) }
            do {
                if !(nowMs.isFinite && skew.isFinite) { throw err("clock and skew must be finite") }
                guard case let .array(x5c)? = key.get("x5c"), !x5c.isEmpty else { no("no x5c"); continue }
                var certs: [AttCert] = []
                for e in x5c {
                    guard case let .string(b64) = e else { throw err("The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.") }
                    certs.append(try Cert.parseDER(Attest.nodeB64(b64)))
                }
                let leaf = certs[0]
                func validity(_ c: AttCert) -> (from: Double, to: Double)? {
                    let v = DER.derValidity(c.raw)
                    guard let f = v.from, let t = v.to else { return nil }
                    return (Double(f), Double(t))
                }
                for (j, c) in certs.enumerated() {
                    guard let v = validity(c) else { throw err("cert \(j): unparsable validity") }
                    if !(nowMs + skew >= v.from) { throw err("cert \(j): not yet valid") }
                    if !(nowMs - skew <= v.to) { throw err("cert \(j): expired") }
                }
                let lv = validity(leaf)!
                if let strength = try keyStrengthError(leaf) { throw err(strength) }
                let leafSubject = Cert.nameText(leaf.rawSubject)
                if certs.count == 1 {
                    if !(nowMs - lv.from <= maxAge) { throw err("key older than maxKeyAgeMs") }
                    guard let cn = soleCn(leafSubject) else { throw err("subject is not a single CN") }
                    if cn.contains("*") { throw err("wildcard CN rejected") }
                    if !IV.same(cn, issuer) { throw err("subject CN does not equal the issuer URL") }
                    if !selfIssuedText(leaf) || !Cert.sigOKBy(leaf, leaf) { throw err("not a genuine self-signed cert") }
                    put(Anchor(spki: try Cert.keyOf(leaf).spkiSHA256, kind: "self-signed", from: lv.from, to: lv.to))
                    continue
                }
                if roots.isEmpty { throw err("chained key ignored (no chainRootSpkiSha256 configured)") }
                for j in 0..<(certs.count - 1) where !Cert.sigOKBy(certs[j], certs[j + 1]) { throw err("chain link \(j) is not signed by the next cert") }
                let profile = DER.strictChainError(certs.map { $0.raw })
                if !profile.isEmpty { throw err("chain profile: \(profile)") }
                let top = certs[certs.count - 1]
                if !selfIssuedText(top) || !Cert.sigOKBy(top, top) { throw err("chain does not end in a self-signed root") }
                let rootSpki = try Cert.keyOf(top).spkiSHA256
                if !roots.contains(rootSpki) { throw err("chain root is not pinned") }
                if let allowed = policy.chainLeafCn, !allowed.contains(where: { IV.same($0, leafCn(leafSubject) ?? "\u{0}") }) { throw err("chained leaf CN not allowed") }
                let top2 = validity(top)!
                var anchorSpki = rootSpki, kind = "chained-root", anchorFrom = top2.from, anchorTo = top2.to
                if !inters.isEmpty {
                    guard let mid = try certs[1..<(certs.count - 1)].first(where: { inters.contains(try Cert.keyOf($0).spkiSHA256) }) else { throw err("chain does not pass through a pinned intermediate") }
                    let mv = validity(mid)!
                    anchorSpki = try Cert.keyOf(mid).spkiSHA256; kind = "chained-intermediate"; anchorFrom = mv.from; anchorTo = mv.to
                }
                let prev = accepted.first { $0.spki == anchorSpki }
                put(Anchor(spki: anchorSpki, kind: kind, from: prev.map { Swift.min($0.from, anchorFrom) } ?? anchorFrom, to: Swift.min(anchorTo, Swift.max(prev?.to ?? 0, lv.to))))
            } catch {
                no(msg(error))
            }
        }
        return .object(["accepted": .array(accepted.map { .object(["spki": .string($0.spki), "kind": .string($0.kind), "notBeforeMs": ms($0.from), "notAfterMs": ms($0.to)]) }), "rejected": .array(rejected)])
    }

    // MARK: the key-state store

    public typealias KeyStateStore = PCAMaaKeyStateStore

    /// The in-memory store (a state is stored as a copy).
    public final class MemoryKeyStateStore: KeyStateStore {
        private var m: [[UInt16]: JSONValue] = [:]
        private var order: [String] = []
        private let lock = NSLock()
        public init() {}
        public func get(_ issuer: String) -> JSONValue? { lock.lock(); defer { lock.unlock() }; return m[Array(issuer.utf16)] }
        public func set(_ issuer: String, _ state: JSONValue) {
            lock.lock(); defer { lock.unlock() }
            if m.updateValue(state, forKey: Array(issuer.utf16)) == nil { order.append(issuer) }
        }
        /// The final state of every issuer.
        public func snapshot() -> JSONValue {
            lock.lock(); defer { lock.unlock() }
            var o = JObject()
            for i in order { o[JKey(i)] = m[Array(i.utf16)] }
            return .object(o)
        }
    }

    /// A store over an atomic key/value store (key `maa-keys/<issuer>`); a newer persisted state is never replaced by an older one.
    public final class DurableKeyStateStore: KeyStateStore {
        private let kv: AtomicKV
        public init(_ kv: AtomicKV) { self.kv = kv }
        public func get(_ issuer: String) throws -> JSONValue? { try kv.get("maa-keys/" + issuer) }
        public func set(_ issuer: String, _ state: JSONValue) throws {
            try kv.update("maa-keys/" + issuer) { prev in
                if let p = prev, let ps = PCAMaaKeys.parseState(p, issuer), let pf = IV.num(ps.get("fetchedAtMs")), let nf = IV.num(state.get("fetchedAtMs")), pf > nf { return nil }
                return state
            }
        }
    }

    static func parseState(_ x: JSONValue?, _ issuer: String) -> JSONValue? {
        guard let s = x?.asObject, s["v"].flatMap({ IV.num($0) }) == 1, IV.same(s["issuer"]?.asString, issuer), let f = isIntNotNegZero(s["fetchedAtMs"]), case let .array(anchors)? = s["anchors"] else { return nil }
        var out: [JSONValue] = []
        for a in anchors {
            guard let r = a.asObject, hex64(r["spki"]?.asString), let kind = r["kind"]?.asString, ["self-signed", "chained-root", "chained-intermediate"].contains(kind),
                  isIntNotNegZero(r["notBeforeMs"]) != nil, isIntNotNegZero(r["notAfterMs"]) != nil, isIntNotNegZero(r["firstSeenMs"]) != nil else { return nil }
            out.append(.object(["spki": r["spki"]!, "kind": .string(kind), "notBeforeMs": r["notBeforeMs"]!, "notAfterMs": r["notAfterMs"]!, "firstSeenMs": r["firstSeenMs"]!]))
        }
        return .object(["v": .int(1), "issuer": .string(issuer), "fetchedAtMs": StoreJ.num(f), "anchors": .array(out)])
    }

    private static func isIntNotNegZero(_ v: JSONValue?) -> Double? { isInt(v).flatMap { !($0 == 0 && $0.sign == .minus) ? $0 : nil } }

    // MARK: the trust object

    /// What a signed re-pin brings: the manifest and the options to verify it with (everything but `nowMs`).
    public struct Repin {
        public var manifest: JSONValue?
        public var verify: JSONValue
        public init(manifest: JSONValue?, verify: JSONValue) { self.manifest = manifest; self.verify = verify }
    }

    public final class Trust {
        let policy: Policy
        let store: KeyStateStore
        let fetch: Fetch
        let trusted: Set<[UInt16]>

        init(policy: Policy, store: KeyStateStore, fetch: @escaping Fetch) {
            self.policy = policy; self.store = store; self.fetch = fetch
            trusted = Set(policy.trustedIssuers.map { Array($0.utf16) })
        }

        /// The trust anchors (the signing-key SPKI fingerprints) for `issuer` at `nowMs`: `{ok: true, trustAnchors: {rootSpkiSha256}, source, anchors, newKeys,
        /// removedKeys, rejected}` or `{ok: false, code, reason}`. A fresh cache is used as is; otherwise the certs are fetched and evaluated, and a new key
        /// set must overlap the previous one (or a built-in or re-pinned key), bring few new keys and, on first use, be pinned (no trust on first use unless
        /// the policy allows it). On a failed fetch the cache serves until it is older than `maxStaleMs`.
        public func getTrustAnchors(_ issuer: String, nowMs: Double, repin: Repin? = nil) -> JSONValue {
            func fail(_ code: String, _ reason: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(code), "reason": .string(reason)]) }
            do {
                let ttl = policy.ttlMs ?? PCAMaaKeys.HOUR, maxStale = policy.maxStaleMs ?? PCAMaaKeys.DAY, maxNew = policy.maxNewKeysPerFetch ?? 2, maxInitial = policy.maxInitialKeys ?? 8
                let skew = policy.clockSkewMs ?? 60_000, requireOverlap = policy.requireOverlap ?? true
                if !trusted.contains(Array(issuer.utf16)) { return fail("untrusted-issuer", "issuer is not in policy.trustedIssuers") }
                guard nowMs.isFinite, nowMs.rounded() == nowMs, abs(nowMs) <= IV.MAX_SAFE else { return fail("clock-regression", "nowMs must be an integer") }

                var approved = Set<String>(), denied = Set<String>()
                if let r = repin {
                    var o = r.verify
                    guard case var .object(vo) = o else { return fail("repin-invalid", "malformed: verify options") }
                    vo["nowMs"] = StoreJ.num(nowMs)
                    o = .object(vo)
                    let v = PCAAttestAllowlist.verifyAllowlistManifest(r.manifest, PCAAttestAllowlist.VerifyOptions(
                        issuerKeys: o.get("issuerKeys") ?? .null, nowMs: nowMs, minVersion: o.get("minVersion"), lastSeenVersion: o.get("lastSeenVersion"), lastSeenDigest: o.get("lastSeenDigest"),
                        clockSkewMs: o.get("clockSkewMs"), maxLifetimeMs: o.get("maxLifetimeMs")))
                    if v.get("ok") != .bool(true) { return fail("repin-invalid", "\(v.get("code")?.asString ?? ""): \(v.get("reason")?.asString ?? "")") }
                    let p = try PCAAttestAllowlist.projectAllowlist(v, nowMs: nowMs)
                    approved = Set((p.get("maaSigningSpkis")?.get(issuer)?.asArray ?? []).compactMap { $0.asString })
                    for r in p.get("revoked")?.asArray ?? [] where r.get("kind")?.asString == "maa-signing-spki" && IV.same(r.get("label")?.asString, issuer) { if let v = r.get("value")?.asString { denied.insert(v) } }
                }
                var effPolicy = policy
                var builtinBaseline: [String] = []
                var builtinReason: String?
                var disabled = false
                var source: JSONValue? = nil
                switch policy.builtinPins { case .disabled: disabled = true; case .shipped: break; case let .source(s): source = s }
                if !disabled {
                    let b = PCAMaaKeys.loadBuiltinMaaPins(nowMs: nowMs, source: source)
                    if b.get("ok") == .bool(true) {
                        builtinBaseline = (b.get("maaSigningSpkis")?.get(issuer)?.asArray ?? []).compactMap { $0.asString }
                        for r in (b.get("revokedSigningSpkis")?.get(issuer)?.asArray ?? []).compactMap({ $0.asString }) { denied.insert(r) }
                        effPolicy.chainRootSpkiSha256 = policy.chainRootSpkiSha256 ?? (b.get("maaChainRootSpkis")?.asArray ?? []).compactMap { $0.asString }
                        effPolicy.chainIntermediateSpkiSha256 = policy.chainIntermediateSpkiSha256 ?? (b.get("maaChainIntermediateSpkis")?.asArray ?? []).compactMap { $0.asString }
                        effPolicy.chainLeafCn = policy.chainLeafCn ?? BUILTIN_CHAIN_LEAF_CN
                        if !builtinBaseline.isEmpty { builtinBaseline += (b.get("maaChainIntermediateSpkis")?.asArray ?? []).compactMap { $0.asString } }
                    } else { builtinReason = b.get("reason")?.asString }
                }
                func allow(_ a: [JSONValue]) -> [JSONValue] { a.filter { !denied.contains($0.get("spki")?.asString ?? "") } }
                func live(_ a: [JSONValue]) -> [JSONValue] {
                    a.filter { r in nowMs - skew <= (IV.num(r.get("notAfterMs")) ?? .nan) && nowMs + skew >= (IV.num(r.get("notBeforeMs")) ?? .nan) }
                }
                func build(_ src: String, _ anchors: [JSONValue], _ newKeys: [String], _ removed: [String], _ rejected: [JSONValue]) -> JSONValue {
                    let spkis = jsSorted(Array(Set(anchors.compactMap { $0.get("spki")?.asString })))
                    if spkis.isEmpty { return fail("no-valid-keys", "no unexpired, un-revoked signing keys remain") }
                    return .object(["ok": .bool(true), "trustAnchors": .object(["rootSpkiSha256": .array(spkis.map { .string($0) })]), "source": .string(src), "anchors": .array(anchors),
                                    "newKeys": .array(newKeys.map { .string($0) }), "removedKeys": .array(removed.map { .string($0) }), "rejected": .array(rejected)])
                }

                var state: JSONValue?
                if let raw = try store.get(issuer) {
                    guard let parsed = PCAMaaKeys.parseState(raw, issuer) else { return fail("corrupt-state", "persisted MAA key state failed validation") }
                    state = parsed
                    if !(nowMs >= IV.num(parsed.get("fetchedAtMs"))! - skew) { return fail("clock-regression", "clock is behind the last persisted fetch time") }
                }
                let stateAnchors = state?.get("anchors")?.asArray ?? []
                let fetchedAt = state.flatMap { IV.num($0.get("fetchedAtMs")) }
                if let s = state, let fa = fetchedAt, nowMs - fa < ttl, nowMs >= fa {
                    _ = s
                    let a = allow(live(stateAnchors))
                    if !a.isEmpty { return build("cache", a, [], [], []) }
                }

                let jwks: JSONValue
                do { jwks = try PCAMaaKeys.fetchMaaCerts(issuer, fetch: fetch, timeoutMs: policy.fetchTimeoutMs, maxBytes: policy.maxBodyBytes) } catch {
                    let why = PCAMaaKeys.msg(error)
                    guard let fa = fetchedAt else { return fail("fetch-failed", "\(why); no cached key set") }
                    if !(nowMs - fa <= maxStale) { return fail("stale-exceeded", "\(why); cached set is older than maxStaleMs") }
                    let a = allow(live(stateAnchors))
                    if a.isEmpty { return fail("stale-exceeded", "\(why); every cached key has expired or been revoked") }
                    return build("stale-cache", a, [], [], [])
                }

                let ev = PCAMaaKeys.evaluateMaaJwks(jwks, issuer: issuer, policy: effPolicy, nowMs: nowMs)
                let evRejected = ev.get("rejected")?.asArray ?? []
                let accepted = (ev.get("accepted")?.asArray ?? []).filter { !denied.contains($0.get("spki")?.asString ?? "") }
                if accepted.isEmpty {
                    let why = evRejected.map { "\($0.get("kid").map { JS.toString($0) } ?? ""): \($0.get("reason")?.asString ?? "")" }.joined(separator: "; ")
                    return fail("no-valid-keys", "no JWKS key passed validation (\(why.isEmpty ? "empty JWKS" : why))")
                }

                var baseline = Set<String>(), baselineOrder: [String] = []
                func addBaseline(_ s: String) { if baseline.insert(s).inserted { baselineOrder.append(s) } }
                if state != nil { for a in live(stateAnchors) { if let s = a.get("spki")?.asString { addBaseline(s) } } }
                else {
                    for p in policy.initialPins?[issuer] ?? [] { addBaseline(p.lowercased()) }
                    for p in builtinBaseline { addBaseline(p) }
                }
                for p in builtinBaseline { approved.insert(p) }
                let acceptedList = accepted.compactMap { $0.get("spki")?.asString }
                var acceptedSet = Set<String>(), acceptedUnique: [String] = []
                for s in acceptedList where acceptedSet.insert(s).inserted { acceptedUnique.append(s) }
                let approvedHere = acceptedUnique.filter { approved.contains($0) }
                let unapprovedNew = acceptedUnique.filter { !baseline.contains($0) && !approved.contains($0) }
                if baseline.isEmpty {
                    if approvedHere.isEmpty && policy.allowTrustOnFirstUse != true {
                        if let r = builtinReason { return fail("builtin-pins-invalid", "built-in pins unusable (\(r)); no persisted state, no initialPins, no signed re-pin; refusing trust-on-first-use") }
                        return fail("no-baseline", "no persisted state, no built-in pin for this issuer, no initialPins and no signed re-pin: refusing trust-on-first-use")
                    }
                    if Double(acceptedSet.count) > maxInitial && approvedHere.count < acceptedSet.count { return fail("too-many-new-keys", "initial set of \(acceptedSet.count) keys exceeds maxInitialKeys") }
                } else {
                    if Double(unapprovedNew.count) > maxNew { return fail("too-many-new-keys", "\(unapprovedNew.count) new keys exceed maxNewKeysPerFetch=\(JS.number(maxNew))") }
                    let overlap = acceptedUnique.contains { baseline.contains($0) } || !approvedHere.isEmpty
                    if requireOverlap && !overlap { return fail("no-overlap", "the new key set shares no key with the previous set and is not covered by a signed re-pin") }
                }

                var firstSeen: [String: JSONValue] = [:]
                for a in stateAnchors { if let s = a.get("spki")?.asString { firstSeen[s] = a.get("firstSeenMs") } }
                let records: [JSONValue] = accepted.map { a in
                    var o = a.asObject ?? [:]
                    o["firstSeenMs"] = firstSeen[a.get("spki")?.asString ?? ""] ?? StoreJ.num(nowMs)
                    return .object(o)
                }
                let fetchedAtMs = fetchedAt.map { Swift.max($0, nowMs) } ?? nowMs
                try store.set(issuer, .object(["v": .int(1), "issuer": .string(issuer), "fetchedAtMs": StoreJ.num(fetchedAtMs), "anchors": .array(records)]))
                let newKeys = records.compactMap { $0.get("spki")?.asString }.filter { !baseline.contains($0) }
                let removed = baselineOrder.filter { !acceptedSet.contains($0) }
                return build("fetched", records, newKeys, removed, evRejected)
            } catch {
                return fail("fetch-failed", PCAMaaKeys.msg(error))
            }
        }
    }

    /// The trust object over a policy, a store and a transport. Throws on a policy without trusted issuers or with one that is not an https origin.
    public static func createMaaKeyTrust(policy: Policy, store: KeyStateStore, fetch: Fetch? = nil) throws -> Trust {
        if policy.trustedIssuers.isEmpty || !policy.trustedIssuers.allSatisfy({ issuerUrl($0) }) {
            throw err("createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs")
        }
        // an infinite or NaN window would admit every expired key or stale cache; a count or max-stale may be +Infinity (no cap) but never NaN
        let ttl = policy.ttlMs ?? HOUR, skew = policy.clockSkewMs ?? 60_000
        if !(ttl.isFinite && skew.isFinite) || [policy.maxStaleMs ?? DAY, policy.maxNewKeysPerFetch ?? 2, policy.maxInitialKeys ?? 8].contains(where: { $0.isNaN }) {
            throw err("createMaaKeyTrust: ttlMs and clockSkewMs must be finite; maxStaleMs and the key-count limits must not be NaN")
        }
        return Trust(policy: policy, store: store, fetch: fetch ?? defaultFetch(timeoutMs: policy.fetchTimeoutMs ?? 10_000))
    }

    // MARK: corroboration

    /// Requires `k` (at least 2) distinct vantages to have observed the SAME set of valid signing keys for the issuer: `{ok: true, issuer, spkis, vantages, k}` or
    /// `{ok: false, code, reason}` (`malformed`, `insufficient-vantages`, `vantage-disagreement`, `no-valid-keys`). `sets` is `[{vantage, issuer, jwks}]`.
    public static func corroborateMaaKeySets(_ sets: JSONValue?, k: Double, issuer: String, nowMs: Double, policy: Policy? = nil) -> JSONValue {
        func bad(_ code: String, _ r: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(code), "reason": .string(r)]) }
        guard k.isFinite, k.rounded() == k, abs(k) <= IV.MAX_SAFE, k >= 2 else { return bad("malformed", "k must be an integer >= 2") }
        guard issuerUrl(issuer), nowMs.isFinite, nowMs.rounded() == nowMs, abs(nowMs) <= IV.MAX_SAFE else { return bad("malformed", "issuer/nowMs invalid") }
        guard case let .array(list)? = sets else { return bad("malformed", "sets must be an array") }
        var pol = policy ?? Policy(trustedIssuers: [issuer], builtinPins: .disabled)
        pol.trustedIssuers = [issuer]
        var byVantage: [(String, String)] = []
        for o in list {
            guard let v = o.get("vantage")?.asString, !v.isEmpty, v.utf16.count <= 100 else { return bad("malformed", "vantage label must be a non-empty string") }
            if !IV.same(o.get("issuer")?.asString, issuer) { return bad("malformed", "observation from '\(v)' is for a different issuer") }
            let ev = evaluateMaaJwks(o.get("jwks"), issuer: issuer, policy: pol, nowMs: nowMs)
            let acc = ev.get("accepted")?.asArray ?? []
            if acc.isEmpty {
                let why = (ev.get("rejected")?.asArray ?? []).compactMap { $0.get("reason")?.asString }.joined(separator: "; ")
                return bad("no-valid-keys", "vantage '\(v)' observed no valid key (\(why.isEmpty ? "empty" : why))")
            }
            let fp = jsSorted(acc.compactMap { $0.get("spki")?.asString }).joined(separator: ",")
            if let i = byVantage.firstIndex(where: { IV.same($0.0, v) }) {
                if !IV.same(byVantage[i].1, fp) { return bad("vantage-disagreement", "vantage '\(v)' supplied two different key sets") }
            } else { byVantage.append((v, fp)) }
        }
        if Double(byVantage.count) < k { return bad("insufficient-vantages", "\(byVantage.count) distinct vantage(s) < k=\(JS.number(k))") }
        var distinct: [String] = []
        for (_, f) in byVantage where !distinct.contains(where: { IV.same($0, f) }) { distinct.append(f) }
        if distinct.count != 1 {
            return bad("vantage-disagreement", "vantages disagree: " + byVantage.map { "\($0.0)=" + $0.1.split(separator: ",").map { String($0.prefix(8)) }.joined(separator: "+") }.joined(separator: " | "))
        }
        return .object(["ok": .bool(true), "issuer": .string(issuer), "spkis": .array(distinct[0].split(separator: ",").map { .string(String($0)) }), "vantages": .array(jsSorted(byVantage.map { $0.0 }).map { .string($0) }), "k": StoreJ.num(k)])
    }
}
