import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Resource-server discovery (`.well-known/pca-configuration`): the OIDC-discovery analog for Proof-Carrying Authority. A resource server publishes a
/// small JSON document describing how to talk PCA to it (its audience id, the signature suites it accepts, the header it reads the PCActn from, the
/// freshness and step-up endpoints, the intent block, the obligation kinds it performs); a client fetches it once and auto-configures. The document is
/// public, non-secret configuration. A malformed document throws (fail closed).
public enum PCADiscovery {
    public static let WELL_KNOWN_PCA_PATH = "/.well-known/pca-configuration"
    static let INTENT_MEMBERS = ["versions", "actions_uri", "schema_keys", "question_relay", "tiers", "evidence_uri"]
    static let DEFAULT_SUITES = ["ed25519", "ml-dsa-65", "hybrid-ed25519-ml-dsa-65"]
    static let DEFAULT_REQUIRED = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"]

    private static func bad(_ m: String) -> JSError { JSError("parseDiscoveryDocument: \(m)") }
    private static func strs(_ v: [String]) -> JSONValue { .array(v.map { .string($0) }) }
    private static func isStrings(_ v: JSONValue?) -> Bool { JS.isStringArray(v) }

    /// Validate an `intent` discovery block (versions, actions_uri, schema_keys, question_relay, tiers, evidence_uri); anything malformed throws.
    public static func parseDiscoveryIntent(_ v: JSONValue?) throws -> JSONValue {
        guard let o = v?.asObject else { throw bad("intent must be an object") }
        for k in JS.keyOrder(o) where !INTENT_MEMBERS.contains(where: { IV.same($0, k.s) }) { throw bad("intent has unknown member '\(k.s)'") }
        guard let vs = o["versions"]?.asArray, !vs.isEmpty, vs.allSatisfy({ IV.num($0) == 1 || IV.num($0) == 2 }) else { throw bad("intent.versions must list 1 and/or 2") }
        var out: [(String, JSONValue)] = [("versions", .array(vs))]
        for k in ["actions_uri", "evidence_uri"] {
            if let x = o[JKey(k)] {
                guard let s = x.asString, !s.isEmpty else { throw bad("intent.\(k) must be a non-empty string") }
                out.append((k, .string(s)))
            }
        }
        if let sk = o["schema_keys"] {
            guard let list = sk.asArray else { throw bad("intent.schema_keys must be an array") }
            var keys: [JSONValue] = []
            for x in list {
                guard let e = x.asObject, let kid = e["kid"]?.asString, let alg = e["alg"]?.asString, let pk = e["pk"]?.asString, e["pq_pk"].map({ $0.asString != nil }) ?? true else {
                    throw bad("intent.schema_keys entries are {kid, alg, pk, pq_pk?}")
                }
                var k: [(String, JSONValue)] = [("kid", .string(kid)), ("alg", .string(alg)), ("pk", .string(pk))]
                if let q = e["pq_pk"] { k.append(("pq_pk", q)) }
                keys.append(PCAApprovalChannels.obj(k))
            }
            out.append(("schema_keys", .array(keys)))
        }
        if let q = o["question_relay"] {
            guard case .bool = q else { throw bad("intent.question_relay must be a boolean") }
            out.append(("question_relay", q))
        }
        if let t = o["tiers"] {
            guard let to = t.asObject else { throw bad("intent.tiers must be an object") }
            for n in to.values {
                guard let d = IV.num(n), d.rounded() == d, d >= 0, !IV.isNegZero(d), d <= 4 else { throw bad("intent.tiers values must be integers 0..4") }
            }
            out.append(("tiers", t))
        }
        return PCAApprovalChannels.obj(out)
    }

    /// Build a well-formed discovery document from options (`audience`, `signatureSuites`, `pcaVersions`, `actionHeader`, `requiredChecks`, `endpoints`,
    /// `trustedRoots`, `metadata`, `intent`, `obligationsSupported`). Throws on an empty audience.
    public static func buildDiscoveryDocument(_ opts: JSONValue) throws -> JSONValue {
        guard let aud = opts.get("audience")?.asString, !aud.isEmpty else { throw JSError("buildDiscoveryDocument: audience is required") }
        func opt(_ k: String) -> JSONValue? { JS.present(opts.get(k)) }
        var d: [(String, JSONValue)] = [
            ("audience", .string(aud)), ("pca_versions", opt("pcaVersions") ?? .array([.int(2)])), ("signature_suites", opt("signatureSuites") ?? strs(DEFAULT_SUITES)),
            ("action_header", opt("actionHeader") ?? .string("PCA-Action")), ("required_checks", opt("requiredChecks") ?? strs(DEFAULT_REQUIRED)),
        ]
        if let e = opt("endpoints") { d.append(("endpoints", e)) }
        if let t = opt("trustedRoots") { d.append(("trusted_roots", t)) }
        if let m = opt("metadata") { d.append(("metadata", m)) }
        if let i = opt("intent") { d.append(("intent", try parseDiscoveryIntent(i))) }
        if let o = opt("obligationsSupported") { d.append(("obligations_supported", .array(try JS.spread(o)))) }
        return PCAApprovalChannels.obj(d)
    }

    /// Validate and narrow an untrusted value into a discovery document. Throws on anything malformed.
    public static func parseDiscoveryDocument(_ value: JSONValue?) throws -> JSONValue {
        guard let value = value, value.isObject || value.isArray else { throw bad("not an object") } // an array is an object to the reference: it fails on the first member
        let v = value.asObject ?? [:]
        guard let aud = v["audience"]?.asString, !aud.isEmpty else { throw bad("missing audience") }
        guard let vers = v["pca_versions"]?.asArray, vers.allSatisfy({ $0.isNumber }) else { throw bad("pca_versions must be a number[]") }
        guard isStrings(v["signature_suites"]) else { throw bad("signature_suites must be a string[]") }
        guard let hdr = v["action_header"]?.asString, !hdr.isEmpty else { throw bad("missing action_header") }
        var doc: [(String, JSONValue)] = [("audience", .string(aud)), ("pca_versions", .array(vers)), ("signature_suites", v["signature_suites"]!), ("action_header", .string(hdr))]
        if isStrings(v["required_checks"]) { doc.append(("required_checks", v["required_checks"]!)) }
        if let e = v["endpoints"], e.isObject || e.isArray { doc.append(("endpoints", e)) }
        if isStrings(v["trusted_roots"]) { doc.append(("trusted_roots", v["trusted_roots"]!)) }
        if let m = v["metadata"], m.isObject || m.isArray { doc.append(("metadata", m)) }
        if let i = v["intent"] { doc.append(("intent", try parseDiscoveryIntent(i))) }
        if let o = v["obligations_supported"] {
            guard isStrings(o) else { throw bad("obligations_supported must be a string[]") }
            doc.append(("obligations_supported", o))
        }
        return PCAApprovalChannels.obj(doc)
    }

    /// True iff this server (per its discovery document) accepts the signature suite.
    public static func acceptsSuite(_ doc: JSONValue?, _ suite: String) -> Bool {
        doc?.get("signature_suites")?.asArray?.contains { $0 == .string(suite) } ?? false
    }

    /// A fetch answer: `ok` (2xx), the status and the parsed JSON body.
    public struct Reply {
        public let ok: Bool
        public let status: Int
        public let json: JSONValue?
        public init(ok: Bool, status: Int, json: JSONValue?) { self.ok = ok; self.status = status; self.json = json }
    }

    /// The transport of `fetchDiscovery`: a GET of `url` with `headers`.
    public typealias Fetch = (_ url: String, _ headers: [String: String]) throws -> Reply

    /// The default transport: a blocking GET over URLSession, the body parsed with the strict JSON profile.
    public static let defaultFetch: Fetch = { url, headers in
        guard let u = URL(string: url) else { throw JSError("fetchDiscovery: invalid url") }
        var req = URLRequest(url: u)
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        final class Box: @unchecked Sendable { var data: Data?; var status: Int?; var err: Error? }
        let box = Box(), sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { d, r, e in box.data = d; box.status = (r as? HTTPURLResponse)?.statusCode; box.err = e; sem.signal() }.resume()
        sem.wait()
        if let e = box.err { throw e }
        guard let status = box.status else { throw JSError("fetchDiscovery: no http response") }
        let ok = (200...299).contains(status)
        guard ok else { return Reply(ok: false, status: status, json: nil) }
        guard let d = box.data, let text = String(data: d, encoding: .utf8), let json = JSONValue.parse(text) else { throw JSError("fetchDiscovery: the body is not strict JSON") }
        return Reply(ok: true, status: status, json: json)
    }

    /// Fetch and parse a resource server's discovery document. `baseUrl` is the server origin (trailing slashes are dropped); the well-known path is
    /// appended. Throws on a non-2xx answer or a malformed document.
    public static func fetchDiscovery(_ baseUrl: String, fetch: Fetch? = nil) throws -> JSONValue {
        var base = baseUrl
        while base.hasSuffix("/") { base.removeLast() }
        let url = base + WELL_KNOWN_PCA_PATH
        let res = try (fetch ?? defaultFetch)(url, ["accept": "application/json"])
        if !res.ok { throw JSError("fetchDiscovery: \(url) returned \(res.status)") }
        return try parseDiscoveryDocument(res.json)
    }
}
