import Foundation

/// The shared strict-artifact helpers of the intent layer: the name and path patterns, the scalar and bounded-string predicates, closed member sets, the
/// signed-artifact message, signing and pinned verification under any registered suite, content references and own-property parameter paths. Artifacts are
/// the language-neutral JSON of the wire; native JSON has no prototypes, so the reference's prototype checks reduce to the forbidden-segment rule.
public enum PCAIntentArtifacts {
    /// Source text of the patterns.
    public static let INTENT_NAME_RE = "^[a-z][a-z0-9_]{0,63}$"
    public static let DATA_CLASS_RE = "^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*$"
    public static let PARAM_SEGMENT_RE = "^[A-Za-z0-9_-]{1,64}$"
    public static let SUITE_MEMBERS = ["alg", "pq_pk", "pq_sig"]
    private static let FORBIDDEN = ["__proto__", "constructor", "prototype"]
    private static let PREFIX = "action.params."

    private static func err(_ m: String) -> JSError { JSError(m) }

    /// `^[A-Za-z0-9_-]{1,64}$` and not `__proto__`, `constructor` or `prototype` (the argument is read as the reference's `RegExp.test` reads it: as its string form).
    public static func isPathSegment(_ v: JSONValue?) -> Bool {
        let s = JS.toString(v)
        let u = Array(s.unicodeScalars)
        guard (1...64).contains(u.count), u.allSatisfy({ ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0.value == 45 || $0.value == 95 }) else { return false }
        return !FORBIDDEN.contains { IV.same($0, s) }
    }

    /// A JSON object that is not an array.
    public static func isPlainObject(_ v: JSONValue?) -> Bool { v?.isObject ?? false }

    /// A safe integer that is not negative zero.
    public static func isSafeInt(_ v: JSONValue?) -> Bool {
        guard let v = v, v.isNumber, v.safeInt != nil else { return false }
        if case let .double(d) = v, d == 0, d.sign == .minus { return false }
        return true
    }

    public static func isClock(_ v: JSONValue?) -> Bool { isSafeInt(v) }

    /// The UTF-8 byte length of a string.
    public static func utf8Len(_ s: String) -> Int { s.utf8.count }

    /// A non-empty string of at most `max` UTF-8 bytes.
    public static func isBoundedString(_ v: JSONValue?, _ max: Double) -> Bool {
        guard case let .string(s)? = v, !s.isEmpty else { return false }
        return Double(utf8Len(s)) <= max
    }

    /// A canonical base64url string of exactly 32 bytes.
    public static func isDigest(_ v: JSONValue?) -> Bool {
        guard case let .string(s)? = v else { return false }
        return Base64URLStrict.isValid(s, length: 32)
    }

    /// A string, a boolean or a safe integer.
    public static func isScalar(_ v: JSONValue?) -> Bool {
        switch v { case .string?, .bool?: return true; default: return isSafeInt(v) }
    }

    /// `typeof a === typeof b && a === b`: same JSON type and equal (two nulls are equal, containers never are, NaN is not).
    public static func scalarEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.string(x)?, .string(y)?): return IV.same(x, y)
        case let (.bool(x)?, .bool(y)?): return x == y
        case (.null?, .null?): return true
        case let (x?, y?) where x.isNumber && y.isNumber: return IV.num(x) == IV.num(y)
        default: return false
        }
    }

    /// The first unknown member (`unknown member '<where>.<k>'`, in the object's JavaScript key order) or missing required member of an object, or nil.
    public static func closedMembers(_ o: JObject, required: [String], optional: [String]? = nil, where whereAt: String? = nil) -> String? {
        let w = whereAt ?? "object", opt = optional ?? []
        for k in JS.keyOrder(o) where !required.contains(where: { IV.same($0, k.s) }) && !opt.contains(where: { IV.same($0, k.s) }) { return "unknown member '\(w).\(k.s)'" }
        for k in required where o[JKey(k)] == nil { return "missing member '\(w).\(k)'" }
        return nil
    }

    /// An absent pinned post-quantum key, or a non-empty string.
    public static func pinPqOk(_ v: JSONValue?) -> Bool {
        guard let v = v else { return true }
        if case let .string(s) = v { return !s.isEmpty }
        return false
    }

    /// Why an artifact's suite members are not acceptable, or nil: the alg is a registered suite, `pq_pk` and `pq_sig` are strings, and an ed25519 artifact
    /// carries neither.
    public static func artifactSuiteError(_ a: JSONValue?) -> String? {
        guard let o = a?.asObject else { return "artifact must be an object" }
        if let e = IV.suiteError(o["alg"]) { return e }
        for k in ["pq_pk", "pq_sig"] { if let v = o[JKey(k)], v.asString == nil { return "\(k) must be a string" } }
        if IV.sigAlg(o["alg"]) == "ed25519" && (o["pq_pk"] != nil || o["pq_sig"] != nil) { return "an ed25519 artifact must not carry pq_pk / pq_sig" }
        return nil
    }

    /// The signed message of an artifact: `domain || strictCanonical(artifact without sig and pq_sig)`. Throws outside the strict profile.
    public static func artifactMessage(_ domain: String, _ artifact: JSONValue) throws -> [UInt8] {
        guard case var .object(o) = artifact else { throw err("artifact must be an object") }
        o["sig"] = nil
        o["pq_sig"] = nil
        return try PCAIntentKit.message(domain, .object(o))
    }

    /// The body plus its signature members under `key` (a non-ed25519 suite also binds `alg` and `pq_pk`): `{...body, [alg, pq_pk,] sig, [pq_sig]}`.
    public static func signArtifact(_ domain: String, _ body: JSONValue, key: PCASuiteKey) throws -> JSONValue {
        guard case var .object(full) = body else { throw err("body must be an object") }
        if key.alg != "ed25519" {
            full["alg"] = .string(key.alg)
            full["pq_pk"] = key.pqPk.map { .string($0) } ?? .null
        }
        let parts = try key.sign(try artifactMessage(domain, .object(full)))
        full["sig"] = .string(parts.sig)
        if let q = parts.pqSig { full["pq_sig"] = .string(q) }
        return .object(full)
    }

    /// Verifies an artifact against a pinned signer: `pin` is the Ed25519 key (a string) or `{pk, pq_pk?}`; a post-quantum half verifies only under the
    /// pinned `pq_pk`. Never throws.
    public static func verifyArtifactSig(_ domain: String, _ artifact: JSONValue, pin: JSONValue) -> Bool {
        guard let a = artifact.asObject, case .string? = a["sig"] else { return false }
        let pk: String?, pq: String?
        if case let .string(s) = pin { pk = s; pq = nil } else { pk = pin.get("pk")?.asString; pq = pin.get("pq_pk")?.asString }
        guard let key = pk, let msg = try? artifactMessage(domain, artifact) else { return false }
        var pins: JObject? = nil
        if let q = pq { pins = [JKey(key): .string(q)] }
        return PCAIntentKit.verifyPinnedSuite(a["alg"], a["alg"] != nil, key, a["pq_pk"], msg, a["sig"], a["pq_sig"], pins ?? [:])
    }

    /// base64url(sha256(strict canonical `{d: refDomain, <slot>: artifact}`)).
    public static func artifactRef(_ refDomain: String, _ slot: String, _ artifact: JSONValue) throws -> String {
        // `{ d: refDomain, [slot]: artifact }`: a slot named `d` replaces the domain member (a dictionary literal with two equal keys would trap)
        var body: JObject = ["d": .string(refDomain)]
        body[JKey(slot)] = artifact
        return Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(.object(body))))
    }

    /// The base64url Ed25519 public key of a 32-byte secret.
    public static func publicKeyB64u(_ secret: [UInt8]) -> String { Base64URLStrict.encode(Ed25519Deterministic.publicKey(seed: secret)) }

    /// Reads a dotted parameter path (`action.params.a.b`) through own members only: `{found, value?}`.
    public static func resolveParamPath(_ params: JSONValue?, _ path: JSONValue?) -> (found: Bool, value: JSONValue?) {
        guard case let .string(p)? = path, p.unicodeScalars.starts(with: PREFIX.unicodeScalars) else { return (false, nil) }
        var cur = params
        for seg in p.dropFirst(PREFIX.count).split(separator: ".", omittingEmptySubsequences: false) {
            guard isPathSegment(.string(String(seg))), case let .object(o)? = cur, let next = o[JKey(String(seg))] else { return (false, nil) }
            cur = next
        }
        return (true, cur)
    }

    /// `action.params.` followed by one to eight path segments.
    public static func isParamPath(_ path: JSONValue?) -> Bool {
        guard case let .string(p)? = path, p.unicodeScalars.starts(with: PREFIX.unicodeScalars) else { return false }
        let segs = p.dropFirst(PREFIX.count).split(separator: ".", omittingEmptySubsequences: false)
        return (1...8).contains(segs.count) && segs.allSatisfy { isPathSegment(.string(String($0))) }
    }

    /// An own member of an object, or nil (a missing member and a null are both absent).
    public static func ownGet(_ o: JSONValue?, _ key: String) -> JSONValue? { o?.get(key) }

    /// Sets `value` at a dotted path, creating the objects on the way. It never overwrites an existing member, never walks through a scalar, an array or a
    /// null, and refuses a `__proto__` segment; the root is returned unchanged on a refusal.
    public static func setNested(_ root: JObject, _ path: String, _ value: JSONValue) -> (ok: Bool, root: JObject) {
        let segs = path.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        if segs.contains(where: { IV.same($0, "__proto__") }) { return (false, root) }
        func put(_ o: JObject, _ i: Int) -> JObject? {
            var out = o
            let k = JKey(segs[i])
            if i == segs.count - 1 { if out[k] != nil { return nil }; out[k] = value; return out }
            switch out[k] {
            case nil: guard let n = put([:], i + 1) else { return nil }; out[k] = .object(n)
            case let .object(inner)?: guard let n = put(inner, i + 1) else { return nil }; out[k] = .object(n)
            default: return nil
            }
            return out
        }
        if let n = put(root, 0) { return (true, n) }
        return (false, root)
    }
}
