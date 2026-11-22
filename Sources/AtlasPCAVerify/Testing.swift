import Foundation

/// The testing kit of the reference (@atlasauth/pca-testing): the acceptance-matrix constants and route mapping shared by the resource-server
/// adapters, a "fake" verifier (the real core verifier rooted at the PCActn's own grant, accepting the PCActn's own audience by default),
/// assertions over it, a tamper helper, and an in-memory state store. Nothing here authorizes anything: `fakeVerify` is the unchanged core
/// verifier, so a swapped verb or a mutated parameter is caught as in production.
public enum PCATesting {
    public static let ADAPTER_ACCEPTANCE_AUDIENCE = "payments-rs"

    public struct AcceptanceOutcome: Equatable { public let status: Int; public let handlerRan: Bool; public let bound: Bool }

    public static let ADAPTER_ACCEPTANCE_EXPECTED: [(name: String, outcome: AcceptanceOutcome)] = [
        ("over_limit_predicate", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
        ("over_limit_max_spend", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
        ("body_differs", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
        ("other_operation", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
        ("escalate_unanswered", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
        ("missing_revocation", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
        ("missing_store", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
        ("valid_first", AcceptanceOutcome(status: 200, handlerRan: true, bound: true)),
        ("replay_second", AcceptanceOutcome(status: 403, handlerRan: false, bound: false)),
    ]

    static let base = "adapter.invalid"

    /// The pathname of `url` resolved against `http://adapter.invalid` (the WHATWG URL parser's reading); nil where the platform class
    /// would throw "Invalid URL".
    /// shortcut: built on the absolute-URL reader (WhatwgURL), so IDN hosts are refused and a `file:` reference without slashes is read as
    /// `file:///...`; upgrade with a full relative-reference parser if a caller needs the remaining corners.
    static func pathname(_ input: String) -> String? {
        var s = Array(input.unicodeScalars)
        while let f = s.first, f.value <= 0x20 { s.removeFirst() }
        while let l = s.last, l.value <= 0x20 { s.removeLast() }
        s.removeAll { $0 == "\t" || $0 == "\n" || $0 == "\r" }
        let text = String(String.UnicodeScalarView(s))
        func slash(_ c: Unicode.Scalar) -> Bool { c == "/" || c == "\\" }
        func relative(_ r: [Unicode.Scalar]) -> String? {
            if r.count >= 2 && slash(r[0]) && slash(r[1]) { return WhatwgURL.parse("http:" + String(String.UnicodeScalarView(r)))?.pathname }
            if let c = r.first, slash(c) { return WhatwgURL.parse("http://\(base)/" + String(String.UnicodeScalarView(r.dropFirst())))?.pathname }
            if r.isEmpty || r[0] == "?" || r[0] == "#" { return "/" }
            return WhatwgURL.parse("http://\(base)/" + String(String.UnicodeScalarView(r)))?.pathname
        }
        // a scheme: ASCII alpha, then alnum + - . , then ':'
        var k = 1
        if let f = s.first, f.isASCII, f.properties.isAlphabetic {
            while k < s.count, s[k].isASCII, s[k].properties.isAlphabetic || (s[k].value >= 0x30 && s[k].value <= 0x39) || s[k] == "+" || s[k] == "-" || s[k] == "." { k += 1 }
            if k < s.count, s[k] == ":" {
                let scheme = String(String.UnicodeScalarView(s[0..<k])).lowercased()
                let rest = Array(s[(k + 1)...])
                if scheme == "http" { return rest.count >= 2 && rest[0] == "/" && rest[1] == "/" ? WhatwgURL.parse(text)?.pathname : relative(rest) }
                if scheme == "file", let c = rest.first, !slash(c) { return WhatwgURL.parse("file:///" + String(String.UnicodeScalarView(rest)))?.pathname }
                return WhatwgURL.parse(text)?.pathname
            }
        }
        return relative(s)
    }

    /// The server's mapping from request to operation: a route table on method + path, the JSON body as params. Throws where the reference's URL
    /// parser throws; nil for anything that is not a route or whose body is not an object.
    public static func acceptanceOperation(_ req: JSONValue) throws -> JSONValue? {
        var path = ""
        if let u = req.get("url")?.asString {
            guard let p = pathname(u) else { throw JSError("Invalid URL") }
            path = p
        }
        let method = req.get("method").map { IntentV2.jsString($0) } ?? "undefined"
        let route: (verb: String, resource: String)?
        switch method.uppercased() + " " + path {
        case "POST /payments": route = ("payments.send", "payments")
        case "POST /refunds": route = ("payments.refund", "payments")
        default: route = nil
        }
        guard let r = route, let body = req.get("body"), body.isObject else { return nil }
        return .object(["verb": .string(r.verb), "resource": .string(r.resource), "params": body])
    }

    // MARK: fake verifier

    public struct FakeVerifyOptions {
        /// nil (key absent): the PCActn's own aud. `.some(nil)`: opt out of the audience check. `.some(x)`: that audience.
        public var audience: String??
        public var now: Int64?
        public var grant: JSONValue?
        public init(audience: String?? = nil, now: Int64? = nil, grant: JSONValue? = nil) { self.audience = audience; self.now = now; self.grant = grant }
    }

    /// The real core verifier rooted at `opts.grant` or the PCActn's own chain root, with the plan-root check skipped (a test double).
    /// Throws where the reference throws (no grant to root the check at).
    public static func fakeVerify(_ pcactn: JSONValue, _ opts: FakeVerifyOptions = FakeVerifyOptions()) throws -> PCA.Verdict {
        guard pcactn.isObject else { throw JSError("Cannot read properties of a non-object (reading 'cap_chain')") }
        let root = pcactn.get("cap_chain")?.asArray?.first
        guard let grant = opts.grant ?? root else { throw JSError("fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant") }
        let audience: PCA.Audience
        if let a = opts.audience { audience = a.map { PCA.Audience.id($0) } ?? PCA.Audience.any }
        else if let aud = pcactn.get("aud")?.asString { audience = .id(aud) } else { audience = .unset }
        let now = opts.now ?? Int64(Date().timeIntervalSince1970 * 1000)
        return PCA.verify(pcactn: pcactn, grant: grant, now: now, audience: audience, insecureSkipPlanRootCheck: true, grantFromArtifact: opts.grant == nil)
    }

    static func failing(_ v: PCA.Verdict) -> [String] { v.checks.filter { !$0.value }.map { $0.key }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) } }

    /// Throws naming the failing checks when the PCActn is denied.
    @discardableResult
    public static func expectVerifies(_ pcactn: JSONValue, _ opts: FakeVerifyOptions = FakeVerifyOptions()) throws -> PCA.Verdict {
        let r = try fakeVerify(pcactn, opts)
        if !r.allow { throw JSError("expectVerifies: PCActn was denied. failing checks: [\(failing(r).joined(separator: ", "))]" + (r.reason.isEmpty ? "" : " \u{2014} \(r.reason)")) }
        return r
    }

    /// The inverse: throws when the PCActn verifies.
    @discardableResult
    public static func expectDenied(_ pcactn: JSONValue, _ opts: FakeVerifyOptions = FakeVerifyOptions()) throws -> PCA.Verdict {
        let r = try fakeVerify(pcactn, opts)
        if r.allow { throw JSError("expectDenied: PCActn verified but was expected to be denied") }
        return r
    }

    // MARK: tamper

    /// Decodes an encoded PCActn with the strict profile, lets `mutate` corrupt the top-level object, then re-encodes it (as JSON text, strict
    /// profile again, canonical form) so a test can assert the corruption is caught.
    public static func tamper(_ encoded: String, _ mutate: (inout JObject) throws -> Void) throws -> String {
        if encoded.utf8.count > PCA.MAX_ARTIFACT_BYTES { throw JSError(PCA.ARTIFACT_SIZE_REASON) }
        guard case var .object(rec) = try StrictJSON.parse(encoded) else { throw JSError("decodePCActn: not an object") }
        try mutate(&rec)
        let text = JS.stringify(.object(rec))
        if text.utf8.count > PCA.MAX_ARTIFACT_BYTES { throw JSError(PCA.ARTIFACT_SIZE_REASON) }
        guard case let .object(back) = try StrictJSON.parse(text) else { throw JSError("decodePCActn: not an object") }
        return Canonical.canonicalize(.object(back))
    }

    // MARK: in-memory state store

    /// A per-holder state map in memory (nothing persists beyond the process); not thread-safe.
    public final class MemoryStateStore {
        private var m: [JKey: JSONValue] = [:]
        public init() {}
        public func get(_ key: String) -> JSONValue? { m[JKey(key)] }
        public func put(_ key: String, _ state: JSONValue) { m[JKey(key)] = state }
    }

    public static func memoryStateStore() -> MemoryStateStore { MemoryStateStore() }
}
