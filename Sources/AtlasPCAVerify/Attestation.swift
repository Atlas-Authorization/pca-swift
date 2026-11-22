import Foundation

/// A single-use store of server-issued nonces. `consume` MUST be atomic: true for the first call with a nonce, false for every later one.
public protocol PCAAttestationNonceStore: AnyObject {
    func consume(_ nonce: String) -> Bool
}

/// A TEE attestation verifier: root the evidence in the vendor chain, check the measurement registers, confirm the quote binds the expected nonce
/// and return the measured identity. It resolves its own evidence from the document and the context. A throw is a refusal.
public protocol PCAAttestationHardwareVerifier {
    func verify(document: JSONValue, ctx: JSONValue, nowMs: Double, expected: JSONValue) throws -> PCAAttestation.HardwareResult
}

/// The software attestation layer: the report-data binding, the dev attestor and its documents, the document registry, the bounded single-use nonce
/// store and the nonce entropy gate, the agent-binding match, `verifyAttestation` and its hook, the multi-root (threshold over independent roots)
/// verifier and the evidence anchor in the transparency ledger. Documents, contexts and bindings are the language-neutral JSON of the wire (a context
/// carries `pcactn` and `grant`). Every failure is closed with the reference's reason. The verifier and the hook are synchronous (a hardware verifier
/// that needs the network blocks its caller). The legacy opt-out `allowUnboundPq` does not exist here: a pure post-quantum or hybrid document verifies
/// only under a pinned key.
public enum PCAAttestation {
    /// Domain separator of the report-data binding hash.
    public static let ATTEST_BIND_DOMAIN = "atlas-pca/attest-bind/v1\u{0}"
    /// Hard ceiling (ms) on the age of a server-issued attestation nonce at verification time.
    public static let MAX_ATTESTATION_AGE_MS: Double = 5 * 60_000
    /// How long (ms) the in-memory store remembers a consumed nonce by default: 12 times the quote-age ceiling.
    public static let DEFAULT_NONCE_RETENTION_MS: Double = 60 * 60 * 1000
    /// Minimum entropy (bytes) of a server-issued attestation nonce: 128 bits.
    public static let MIN_ATTESTATION_NONCE_BYTES = 16
    /// Domain separator of the anchored attestation-evidence digest.
    public static let ATTEST_ANCHOR_DOMAIN = "atlas-pca/attest-anchor/v1\u{0}"

    static let DOC_DOMAIN = "atlas-pca/attest/v1\u{0}"

    // MARK: small JS-faithful helpers

    private static func same(_ a: String?, _ b: String?) -> Bool { IV.same(a, b) }

    private static func nowMs() -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }

    private static func msg(_ e: Error) -> String { (e as? JSError)?.message ?? (e as? CustomStringConvertible)?.description ?? "unknown" }

    private static func isSafeInt(_ d: Double) -> Bool { d.isFinite && d.rounded() == d && abs(d) <= IV.MAX_SAFE }

    /// `Number(x)` for the JSON values a numeric option can hold.
    static func toNumber(_ v: JSONValue?) -> Double {
        switch v {
        case nil: return .nan
        case .null?: return 0
        case let .bool(b)?: return b ? 1 : 0
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        case let .string(s)?: return IV.jsNumber(s)
        case let .array(a)?: return a.isEmpty ? 0 : (a.count == 1 ? toNumber(a[0]) : .nan)
        case .object?: return .nan
        }
    }

    private static func hashStrict(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }

    // MARK: the binding

    /// What the SERVER expects an attestation to be bound to; `json` is the wire form `verifyAttestation` takes.
    public struct ExpectedBinding: Equatable {
        public var holderPub: String
        public var grantRef: String
        public var epoch: Double
        public var nonce: String
        /// Server-recorded issue time of `nonce`, epoch ms; hardware mode derives freshness from it.
        public var nonceIssuedAt: Double?
        public init(holderPub: String, grantRef: String, epoch: Double, nonce: String, nonceIssuedAt: Double? = nil) {
            self.holderPub = holderPub; self.grantRef = grantRef; self.epoch = epoch; self.nonce = nonce; self.nonceIssuedAt = nonceIssuedAt
        }
        public var json: JSONValue {
            var o: JObject = ["holderPub": .string(holderPub), "grantRef": .string(grantRef), "epoch": StoreJ.num(epoch), "nonce": .string(nonce)]
            if let t = nonceIssuedAt { o["nonceIssuedAt"] = StoreJ.num(t) }
            return .object(o)
        }
    }

    /// The 64-byte report-data value `SHA-512(domain || lp(holderPub) || lp(grantRef) || u64be(epoch) || lp(nonce))` (`lp` = u32be length || UTF-8).
    /// Throws on an empty or non-string field, or an epoch that is not a non-negative safe integer.
    public static func attestationBinding(_ exp: JSONValue?) throws -> [UInt8] {
        let b = AttestationBinding(holderPub: exp?.get("holderPub")?.asString ?? "", grantRef: exp?.get("grantRef")?.asString ?? "",
                                   epoch: IV.num(exp?.get("epoch")) ?? .nan, nonce: exp?.get("nonce")?.asString ?? "")
        let r = Attest.bindingBytes(b)
        guard let bytes = r.bytes else { throw JSError(r.error) }
        return bytes
    }

    /// `attestationBinding` as base64url (what a software document carries in `binding`).
    public static func attestationBindingB64u(_ exp: JSONValue?) throws -> String { Base64URLStrict.encode(try attestationBinding(exp)) }

    /// base64url(sha256(strict canonical form of the document)): a content address of a full signed quote.
    public static func attestationDigest(_ doc: JSONValue) throws -> String { try hashStrict(doc) }

    // MARK: the dev attestor

    /// Signs software-mode documents for development and CI: a self-asserted identity, not a hardware root.
    public struct DevAttestor {
        /// The base64url Ed25519 key a verifier lists in `trustedAttestorKeys`.
        public let publicKey: String
        let key: PCASuiteKey

        /// Signs a software-mode document over the claims `{model_id, weights_digest, runtime_measurement, operator, nonce, issued_at, expires_at}`
        /// plus the optional `system_prompt_digest`, `tool_manifest_digest` and (all three together) `holder_pub`, `grant_ref`, `epoch`, which bind it.
        /// The suite and the attestor's post-quantum key are signed into the body.
        public func attest(_ claims: JSONValue) throws -> JSONValue {
            var body = JObject()
            for k in ["model_id", "weights_digest", "runtime_measurement", "operator", "nonce", "issued_at", "expires_at"] {
                guard let v = claims.get(k) else { throw JSError("canonicalize: unsupported type undefined") }
                body[JKey(k)] = v
            }
            body["attestor"] = .string(publicKey)
            body["mode"] = .string("software")
            // additive: the optional digests are carried only when supplied, so a document without them signs as it always did
            for k in ["system_prompt_digest", "tool_manifest_digest"] { if let v = claims.get(k) { body[JKey(k)] = v } }
            if let h = claims.get("holder_pub"), let g = claims.get("grant_ref"), let e = claims.get("epoch") {
                body["binding"] = .string(try attestationBindingB64u(.object(["holderPub": h, "grantRef": g, "epoch": e, "nonce": body["nonce"] ?? .null])))
            }
            return .object(try PCAIntentKit.signSuite(body, key) { try PCAIntentKit.message(DOC_DOMAIN, .object($0)) })
        }
    }

    /// An attestor over `key` (an Ed25519 identity, optionally with a post-quantum suite).
    public static func createDevAttestor(_ key: PCASuiteKey) throws -> DevAttestor {
        guard let ed = key.ed else { throw JSError("createDevAttestor: needs an Ed25519 identity key") }
        return DevAttestor(publicKey: Base64URLStrict.encode(ed.pub), key: key)
    }

    // MARK: the registry

    private static func ctxQuoteDigest(_ ctx: JSONValue?) -> String? { ctx?.get("pcactn")?.get("attestation")?.get("quote_digest")?.asString }

    /// A resolver over known-good documents: the document whose `nonce` equals the PCActn's `attestation.quote_digest` (a later duplicate for a nonce
    /// replaces an earlier one). A document without a string nonce is ignored.
    public static func attestationRegistry(_ docs: [JSONValue]) -> (JSONValue) -> JSONValue? {
        var by: [[UInt16]: JSONValue] = [:]
        for d in docs { if let n = d.get("nonce")?.asString { by[Array(n.utf16)] = d } }
        let frozen = by
        return { ctx in ctxQuoteDigest(ctx).flatMap { frozen[Array($0.utf16)] } }
    }

    // MARK: the nonce store and the entropy gate

    public typealias NonceStore = PCAAttestationNonceStore

    /// The in-memory single-process store. A consumed nonce is never re-accepted inside its retention window; a store full of retained nonces refuses
    /// new ones (fail closed) rather than evict a live one, because evicting re-opens replay for exactly that nonce.
    public final class MemoryNonceStore: NonceStore {
        private let max: Int
        private let retention: Double
        private let clock: () -> Double
        private var seen: [[UInt16]: Double] = [:]
        private var order: [[UInt16]] = [] // insertion order == time order
        private let lock = NSLock()

        /// `max` must be a positive integer (a store that retains nothing gives no replay protection) and `retentionMs` a positive integer (default one
        /// hour; it must exceed the longest time a quote can still pass the nonce-age check). `now` is the clock in integer epoch ms; any other reading
        /// refuses the nonce.
        public init(max: Double = 100_000, retentionMs: Double? = nil, now: (() -> Double)? = nil) throws {
            guard PCAAttestation.isSafeInt(max), max >= 1 else {
                throw JSError("memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)")
            }
            let r = retentionMs ?? PCAAttestation.DEFAULT_NONCE_RETENTION_MS
            guard PCAAttestation.isSafeInt(r), r > 0 else { throw JSError("memoryNonceStore: retentionMs must be a positive integer (ms)") }
            self.max = Int(max)
            self.retention = r
            self.clock = now ?? { PCAAttestation.nowMs() }
        }

        public func consume(_ nonce: String) -> Bool {
            lock.lock(); defer { lock.unlock() }
            let t = clock()
            guard PCAAttestation.isSafeInt(t) else { return false } // integer epoch ms only; anything else fails closed
            let k = Array(nonce.utf16)
            if let at = seen[k] {
                if t - at < retention { return false } // retained: a replay
                seen[k] = nil // aged out of retention: treated as new (the freshness check refuses such a quote anyway)
                order.removeAll { $0 == k }
            }
            if seen.count >= max {
                // make room ONLY from entries that aged out of retention; never evict a live one
                while let first = order.first, let at = seen[first], t - at >= retention {
                    seen[first] = nil
                    order.removeFirst()
                }
                if seen.count >= max { return false } // full of live nonces: fail closed
            }
            seen[k] = t
            order.append(k)
            return true
        }
    }

    /// Whether `nonce` plausibly carries at least `minBytes` bytes of entropy (never below 16): hex (at least twice that many digits) or base64url (at
    /// least 4/3 that many characters) with at least 8 distinct characters. A syntactic floor only: the server must still draw nonces from a CSPRNG.
    /// `minBytes` is coerced like the reference's `Math.max(minBytes, 16)`.
    public static func nonceEntropyOk(_ nonce: JSONValue?, _ minBytes: JSONValue? = nil) -> Bool {
        guard case let .string(s)? = nonce else { return false }
        let need = minBytes == nil ? Double(MIN_ATTESTATION_NONCE_BYTES) : (toNumber(minBytes).isNaN ? .nan : Swift.max(toNumber(minBytes), Double(MIN_ATTESTATION_NONCE_BYTES)))
        let u = Array(s.unicodeScalars.map { $0.value })
        func isHex(_ c: UInt32) -> Bool { (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102) }
        func isB64(_ c: UInt32) -> Bool { (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c == 45 || c == 95 }
        let hex = !u.isEmpty && u.allSatisfy(isHex), b64 = !u.isEmpty && u.allSatisfy(isB64)
        if !hex && !b64 { return false }
        let bytes = hex ? Double(u.count) / 2 : Double((u.count * 3) / 4)
        if bytes < need { return false }
        return Set(u).count >= 8
    }

    // MARK: the agent-binding match

    /// True iff the grant's `agent_binding` constrains anything (an attestation is then REQUIRED).
    public static func requiresAttestation(_ binding: JSONValue?) -> Bool { PCA.requiresAttestation(binding) }

    /// True iff the document's nonce is the one the PCActn declares in `attestation.quote_digest`.
    public static func nonceBinds(_ doc: JSONValue?, _ ctx: JSONValue?) -> Bool {
        guard let n = doc?.get("nonce")?.asString, let q = ctxQuoteDigest(ctx) else { return false }
        return same(n, q)
    }

    /// SameValueZero on the primitives a JSON allowlist holds (objects never match).
    private static func sameValue(_ a: JSONValue, _ b: JSONValue) -> Bool {
        switch (a, b) {
        case let (.string(x), .string(y)): return IV.same(x, y)
        case (.null, .null): return true
        case let (.bool(x), .bool(y)): return x == y
        default:
            guard let x = IV.num(a), let y = IV.num(b) else { return false }
            return x == y || (x.isNaN && y.isNaN)
        }
    }

    /// The measured SVN of a canonical decimal runtime measurement ("0" or no leading zero, ASCII digits, a safe integer), else nil.
    private static func measuredSvn(_ v: JSONValue?) -> UInt64? {
        guard case let .string(s)? = v else { return nil }
        let u = Array(s.unicodeScalars.map { $0.value })
        guard !u.isEmpty, u.allSatisfy({ $0 >= 48 && $0 <= 57 }), u.count == 1 || u[0] != 48, u.count <= 19, let n = UInt64(s), n <= UInt64(Canonical.MAX_SAFE) else { return nil }
        return n
    }

    /// `{svn: n}` with exactly that one member and n a non-negative safe integer JSON number (not -0).
    private static func svnBound(_ v: JSONValue) -> Double? {
        guard case let .object(o) = v, o.count == 1, let n = IV.num(o["svn"]), isSafeInt(n), n >= 0, !(n == 0 && n.sign == .minus) else { return nil }
        return n
    }

    /// Matches an established identity against the grant's `agent_binding`: the reason of the first failure (model, min_measurement, operator,
    /// measured weights, weights, system prompt, tool manifest), or nil. A pinned digest the identity does not carry fails closed; a malformed
    /// `min_measurement` fails closed. Throws on a null identity.
    public static func matchAgentBinding(_ identity: JSONValue?, _ binding: JSONValue?) throws -> String? {
        guard let id = identity, !id.isNull else { throw JSError("Cannot read properties of \(identity == nil ? "undefined" : "null") (reading 'model_id')") }
        let b = binding?.asObject ?? [:]
        func list(_ k: String) -> [JSONValue] { if case let .array(a)? = b[JKey(k)], !a.isEmpty { return a }; return [] }
        func inList(_ l: [JSONValue], _ v: JSONValue?) -> Bool { guard let v = v else { return false }; return l.contains { sameValue($0, v) } }

        let models = list("model_allowlist")
        if !models.isEmpty && !inList(models, id.get("model_id")) { return "model_id \(JS.toString(id.get("model_id"))) not in model_allowlist" }

        if let mm = b["min_measurement"], !ToolSchema.eqs(mm, "") {
            if case let .string(want) = mm {
                if !same(id.get("runtime_measurement")?.asString, want) { return "runtime_measurement does not match required min_measurement" }
            } else if let bound = svnBound(mm) {
                let shown = JS.toString(.int(Int64(bound)))
                guard let got = measuredSvn(id.get("runtime_measurement")) else {
                    return "runtime_measurement \(JS.toString(id.get("runtime_measurement"))) is not an integer SVN (required min svn \(shown))"
                }
                if Double(got) < bound { return "runtime_measurement svn \(got) is below required min svn \(shown)" }
            } else {
                return "min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)"
            }
        }

        if case let .string(op)? = b["operator"], !op.isEmpty, !same(id.get("operator")?.asString, op) {
            return "operator \(JS.toString(id.get("operator"))) is not the bound operator"
        }
        if b["require_measured_weights"] == .bool(true) && id.get("weights_measured") != .bool(true) {
            return "weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)"
        }
        let weights = list("weights_allowlist")
        if !weights.isEmpty && !inList(weights, id.get("weights_digest")) { return "weights_digest not in weights_allowlist (model swap / fine-tune?)" }
        let prompts = list("system_prompt_allowlist")
        if !prompts.isEmpty && !(id.get("system_prompt_digest")?.asString != nil && inList(prompts, id.get("system_prompt_digest"))) {
            return "system_prompt_digest not in system_prompt_allowlist (instructions changed / prompt injection?)"
        }
        let tools = list("tool_manifest_allowlist")
        if !tools.isEmpty && !(id.get("tool_manifest_digest")?.asString != nil && inList(tools, id.get("tool_manifest_digest"))) {
            return "tool_manifest_digest not in tool_manifest_allowlist (tools changed?)"
        }
        return nil
    }

    // MARK: hardware verifiers

    /// What a hardware (or multi-root) attestation verifier reports. `measured` is the HARDWARE-measured identity, which is what the agent binding is
    /// matched against (never the document's self-asserted fields). `bound` must be true only after the verifier confirmed the quote's bound value equals
    /// `attestationBinding(expected)`.
    public struct HardwareResult {
        public var ok: Bool
        public var reason: String?
        public var measured: JSONValue?
        public var bound: Bool?
        /// Fields that are HOST-asserted (not silicon-attested), surfaced for audit only.
        public var hostAsserted: [String: String]?
        /// The verifier answered with something that is not a result at all (a failed root in a multi-root policy).
        public var malformed: Bool

        public init(ok: Bool, reason: String? = nil, measured: JSONValue? = nil, bound: Bool? = nil, hostAsserted: [String: String]? = nil, malformed: Bool = false) {
            self.ok = ok; self.reason = reason; self.measured = measured; self.bound = bound; self.hostAsserted = hostAsserted; self.malformed = malformed
        }

        public static let notAResult = HardwareResult(ok: false, malformed: true)

        /// The result as the reference writes it.
        public var json: JSONValue {
            var o: JObject = ["ok": .bool(ok)]
            if let r = reason { o["reason"] = .string(r) }
            if let m = measured { o["measured"] = m }
            if let b = bound { o["bound"] = .bool(b) }
            if let h = hostAsserted { o["hostAsserted"] = .object(h.reduce(into: JObject()) { $0[JKey($1.key)] = .string($1.value) }) }
            return .object(o)
        }
    }

    public typealias HardwareVerifier = PCAAttestationHardwareVerifier

    /// A closure as a `HardwareVerifier`.
    public struct HardwareFunc: HardwareVerifier {
        let f: (JSONValue, JSONValue, Double, JSONValue) throws -> HardwareResult
        public init(_ f: @escaping (JSONValue, JSONValue, Double, JSONValue) throws -> HardwareResult) { self.f = f }
        public func verify(document: JSONValue, ctx: JSONValue, nowMs: Double, expected: JSONValue) throws -> HardwareResult { try f(document, ctx, nowMs, expected) }
    }

    // MARK: verification

    /// The outcome of `verifyAttestation`: `present` = a document was supplied; `bound` = it was authenticated AND its quote is bound to holder, grant,
    /// epoch and nonce. A server must fail closed when `requiresAttestation(agent_binding)` and not `bound`.
    public struct Verdict: Equatable {
        public var ok: Bool
        public var present: Bool
        public var bound: Bool
        public var reason: String?
        public var identity: JSONValue?

        public var json: JSONValue {
            var o: JObject = ["ok": .bool(ok), "present": .bool(present), "bound": .bool(bound)]
            if let r = reason { o["reason"] = .string(r) }
            if let i = identity { o["identity"] = i }
            return .object(o)
        }
    }

    public struct VerifyInput {
        /// nil: none supplied.
        public var document: JSONValue?
        /// `{pcactn: {grant_ref, attestation: {epoch, quote_digest}, cap_chain?}, grant}`.
        public var ctx: JSONValue
        /// The server-supplied expected binding (`ExpectedBinding.json`; `nonceIssuedAt` is the server's record of when it issued the nonce).
        public var expected: JSONValue
        public var nowMs: Double
        public var trustedAttestorKeys: [String]
        /// Post-quantum key pins of the software attestors (the attestor's Ed25519 key to its ML-DSA key): required for a pure or hybrid document.
        public var pqPins: [String: String]?
        public var hardwareVerifier: HardwareVerifier?
        public var maxNonceAgeMs: Double?
        public var clockSkewMs: Double?

        public init(document: JSONValue?, ctx: JSONValue, expected: JSONValue, nowMs: Double, trustedAttestorKeys: [String], pqPins: [String: String]? = nil,
                    hardwareVerifier: HardwareVerifier? = nil, maxNonceAgeMs: Double? = nil, clockSkewMs: Double? = nil) {
            self.document = document; self.ctx = ctx; self.expected = expected; self.nowMs = nowMs; self.trustedAttestorKeys = trustedAttestorKeys
            self.pqPins = pqPins; self.hardwareVerifier = hardwareVerifier; self.maxNonceAgeMs = maxNonceAgeMs; self.clockSkewMs = clockSkewMs
        }
    }

    private static func nonceAgeReason(_ issued: JSONValue?, _ now: Double, _ skew: Double, _ maxAge: Double) -> String? {
        guard let t = IV.num(issued), t.isFinite else { return "server nonce issue time unknown (cannot establish freshness)" }
        if !(now.isFinite && skew.isFinite && now + skew >= t) { return "nonce issued in the future" }
        if !(now - t <= maxAge + skew) { return "attestation nonce expired (stale quote)" }
        return nil
    }

    /// Verifies a document against the server-supplied expected binding and returns the first failure, in the reference's order: the document is
    /// present; the binding is constructible; the PCActn's grant_ref, attestation epoch and quote_digest match the expectation; the document nonce is the
    /// server nonce; the hardware requirements; then, with a hardware verifier, the nonce age and the verifier's ok, bound and measured identity, or, in
    /// software mode, the mode, the trusted attestor, the suite, the signature, the binding, the validity window and the nonce age when known; finally
    /// the agent-binding match on the established identity. It never throws: any error is a closed verdict.
    public static func verifyAttestation(_ i: VerifyInput) -> Verdict {
        let doc = i.document
        let present: Bool = { switch doc { case .object?, .array?: return true; default: return false } }()
        func fail(_ r: String) -> Verdict { Verdict(ok: false, present: present, bound: false, reason: r, identity: nil) }
        do {
            // an unreadable clock would make every window and nonce-age comparison false, i.e. pass: refuse
            guard i.nowMs.isFinite else { return fail("verifier clock is not a finite time (fail closed)") }
            let skew = (i.clockSkewMs.map { $0.isFinite } ?? false) ? Swift.max(0, i.clockSkewMs!) : 0
            let maxAge = Swift.min((i.maxNonceAgeMs.map { $0.isFinite && $0 > 0 } ?? false) ? i.maxNonceAgeMs! : MAX_ATTESTATION_AGE_MS, MAX_ATTESTATION_AGE_MS)
            let hasHw = i.hardwareVerifier != nil

            guard present, let d = doc else { return fail("no attestation document for this action") }
            let wantBinding: String
            do { wantBinding = try attestationBindingB64u(i.expected) } catch { return fail("attestation binding not constructible: \(msg(error))") }
            let expNonce = i.expected.get("nonce")?.asString ?? ""
            let pc = i.ctx.get("pcactn"), att = pc?.get("attestation")
            guard let g = pc?.get("grant_ref")?.asString, same(g, i.expected.get("grantRef")?.asString) else {
                return fail("attestation binding: PCActn grant_ref differs from expected grant")
            }
            guard let ep = IV.num(att?.get("epoch")), let want = IV.num(i.expected.get("epoch")), ep == want else {
                return fail("attestation binding: PCActn attestation epoch differs from expected epoch")
            }
            guard let q = att?.get("quote_digest")?.asString, same(q, expNonce) else { return fail("attestation nonce does not bind to this PCActn") }
            guard let dn = d.get("nonce")?.asString, same(dn, expNonce) else { return fail("attestation nonce does not match the server-issued nonce") }
            let ab = PCA.readEnvelope(i.ctx.get("grant") ?? .null)?.get("agent_binding")
            let requireHw = ab?.get("require_hardware") == .bool(true)
            if requireHw && !hasHw { return fail("agent_binding.require_hardware: no hardware verifier is configured (fail closed)") }
            if requireHw && d.get("mode") != .string("hardware") { return fail("agent_binding.require_hardware: attestation document is not hardware-rooted (software mode)") }

            let identity: JSONValue
            if let hwv = i.hardwareVerifier {
                if let r = nonceAgeReason(i.expected.get("nonceIssuedAt"), i.nowMs, skew, maxAge) { return fail(r) }
                let hw = try hwv.verify(document: d, ctx: i.ctx, nowMs: i.nowMs, expected: i.expected)
                if !hw.ok { return fail("hardware attestation rejected: \(hw.reason ?? "invalid")") }
                if hw.bound != true { return fail("hardware verifier did not confirm report_data binding") }
                guard let m = hw.measured, JS.truthy(m) else { return fail("hardware verifier returned no measured identity") }
                identity = m
            } else {
                if d.get("mode") != .string("software") { return fail("document mode \(JS.toString(d.get("mode"))) needs a hardwareVerifier") }
                guard let attestor = d.get("attestor")?.asString, i.trustedAttestorKeys.contains(where: { same($0, attestor) }) else { return fail("attestor key is not trusted") }
                let algPresent = d.get("alg") != nil
                guard PCAIntentKit.suiteName(d.get("alg"), algPresent) != nil else { return fail("attestation declares an unknown signature alg") }
                var sigOk = false
                if case let .string(sig)? = d.get("sig") {
                    var body = d.asObject ?? [:]
                    body["sig"] = nil
                    body["pq_sig"] = nil
                    let m = try PCAIntentKit.message(DOC_DOMAIN, .object(body))
                    var pins: JObject? = nil
                    if let p = i.pqPins { var o = JObject(); for (k, v) in p { o[JKey(k)] = .string(v) }; pins = o }
                    sigOk = PCAIntentKit.verifyPinnedSuite(d.get("alg"), algPresent, attestor, d.get("pq_pk"), m, .string(sig), d.get("pq_sig"), pins)
                }
                if !sigOk { return fail("attestation signature does not verify") }
                guard let b = d.get("binding")?.asString, !b.isEmpty else { return fail("attestation is not bound (binding absent)") }
                if !same(b, wantBinding) { return fail("attestation binding mismatch (holder/grant/epoch/nonce)") }
                guard let iat = IV.num(d.get("issued_at")), iat.isFinite, let exp = IV.num(d.get("expires_at")), exp.isFinite, exp >= iat else {
                    return fail("malformed attestation validity window")
                }
                if !(i.nowMs.isFinite && skew.isFinite && i.nowMs + skew >= iat) { return fail("attestation not yet valid") }
                if !(i.nowMs - skew <= exp) { return fail("attestation expired") }
                if IV.num(i.expected.get("nonceIssuedAt")) != nil, let r = nonceAgeReason(i.expected.get("nonceIssuedAt"), i.nowMs, skew, maxAge) { return fail(r) }
                var o = JObject()
                for k in ["model_id", "weights_digest", "runtime_measurement", "operator"] { if let v = d.get(k) { o[JKey(k)] = v } }
                for k in ["system_prompt_digest", "tool_manifest_digest"] { if case .string? = d.get(k), let v = d.get(k) { o[JKey(k)] = v } }
                identity = .object(o)
            }
            if let reason = try matchAgentBinding(identity, ab) { return fail(reason) }
            return Verdict(ok: true, present: true, bound: true, reason: nil, identity: identity)
        } catch {
            return fail("attestation verification error (fail closed): \(msg(error))")
        }
    }

    // MARK: the hook

    /// The hook's verdict: always enforced; `present` and `bound` let a server fail closed when `agent_binding` is non-empty.
    public struct HookResult: Equatable {
        public var enforced: Bool
        public var ok: Bool
        public var reason: String?
        public var present: Bool
        public var bound: Bool

        public var json: JSONValue {
            var o: JObject = ["enforced": .bool(enforced), "ok": .bool(ok), "present": .bool(present), "bound": .bool(bound)]
            if let r = reason, !r.isEmpty { o["reason"] = .string(r) }
            return .object(o)
        }
    }

    public struct VerifierOptions {
        /// Consumes the nonce ONCE, only after the attestation verified and is bound (a replay is refused). Without it the library only checks the
        /// nonce's age: the integrator's `expectedBinding` must then consume the nonce itself.
        public var nonceStore: NonceStore?
        /// Minimum nonce entropy in bytes (default and floor 16). Not applied under `insecureSelfDeclaredNonce`.
        public var minNonceBytes: JSONValue?
        public var trustedAttestorKeys: [String]
        public var pqPins: [String: String]?
        /// Supplied: hardware mode; authenticity is delegated to it instead of the signature.
        public var hardwareVerifier: HardwareVerifier?
        /// Finds the document of an action (default: none).
        public var resolveDocument: ((JSONValue) -> JSONValue?)?
        /// The server-issued binding of an action (holder, grant and epoch from the verified PCActn, the nonce from the server's store); nil fails closed.
        public var expectedBinding: ((JSONValue) throws -> JSONValue?)?
        /// LOUD OPT-OUT (legacy and dev only): derive the binding from the PCActn itself, its self-declared `quote_digest` as the nonce. Replay
        /// protection is void.
        public var insecureSelfDeclaredNonce: Bool
        public var maxNonceAgeMs: Double?
        public var clockSkewMs: Double?
        /// The clock in epoch ms (default the wall clock).
        public var now: (() -> Double)?

        public init(trustedAttestorKeys: [String], nonceStore: NonceStore? = nil, minNonceBytes: JSONValue? = nil, pqPins: [String: String]? = nil,
                    hardwareVerifier: HardwareVerifier? = nil, resolveDocument: ((JSONValue) -> JSONValue?)? = nil,
                    expectedBinding: ((JSONValue) throws -> JSONValue?)? = nil, insecureSelfDeclaredNonce: Bool = false, maxNonceAgeMs: Double? = nil,
                    clockSkewMs: Double? = nil, now: (() -> Double)? = nil) {
            self.trustedAttestorKeys = trustedAttestorKeys; self.nonceStore = nonceStore; self.minNonceBytes = minNonceBytes; self.pqPins = pqPins
            self.hardwareVerifier = hardwareVerifier; self.resolveDocument = resolveDocument; self.expectedBinding = expectedBinding
            self.insecureSelfDeclaredNonce = insecureSelfDeclaredNonce; self.maxNonceAgeMs = maxNonceAgeMs; self.clockSkewMs = clockSkewMs; self.now = now
        }
    }

    /// The attestation hook built by `createAttestationVerifier`. Its assurance label comes from the configuration, never from the document: software
    /// mode is `software`; hardware mode is what the hardware verifier declares (unlabelled: `unknown`); the self-declared-nonce opt-out is `unknown`.
    public final class Verifier: AssuranceLabeled {
        private let o: VerifierOptions
        public let assuranceLabel: AssuranceLabel

        init(_ o: VerifierOptions) {
            self.o = o
            if o.insecureSelfDeclaredNonce {
                assuranceLabel = AssuranceLabel(level: "unknown", vendor: "insecure-self-declared-nonce")
            } else if let h = o.hardwareVerifier {
                assuranceLabel = PCA.labelOf(h) ?? AssuranceLabel(level: "unknown")
            } else {
                assuranceLabel = AssuranceLabel(level: "software")
            }
        }

        /// Runs the hook for one action context. Never throws.
        public func verify(_ ctx: JSONValue) -> HookResult {
            func fin(_ v: Verdict) -> HookResult { HookResult(enforced: true, ok: v.ok, reason: v.reason, present: v.present, bound: v.bound) }
            func bad(_ present: Bool, _ r: String) -> HookResult { fin(Verdict(ok: false, present: present, bound: false, reason: r, identity: nil)) }
            do {
                let document = o.resolveDocument?(ctx)
                let hasDoc: Bool = { switch document { case .object?, .array?: return true; default: return false } }()
                var expected: JSONValue?
                if let eb = o.expectedBinding {
                    expected = try eb(ctx)
                } else if o.insecureSelfDeclaredNonce {
                    let pc = ctx.get("pcactn"), att = pc?.get("attestation")
                    var leaf: JSONValue? = ctx.get("grant")
                    if case let .array(chain)? = pc?.get("cap_chain"), let last = chain.last { leaf = last }
                    var e = JObject()
                    e["holderPub"] = .string(leaf?.get("holder")?.asString ?? "")
                    if let g = pc?.get("grant_ref") { e["grantRef"] = g }
                    if let x = att?.get("epoch") { e["epoch"] = x }
                    if let x = att?.get("quote_digest") { e["nonce"] = x }
                    expected = .object(e)
                }
                guard let exp = expected, JS.truthy(exp) else { return bad(hasDoc, "no server-issued attestation nonce/binding available (fail closed)") }
                if !o.insecureSelfDeclaredNonce && !PCAAttestation.nonceEntropyOk(exp.get("nonce"), o.minNonceBytes) {
                    return bad(hasDoc, "attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)")
                }
                let verdict = PCAAttestation.verifyAttestation(VerifyInput(
                    document: document, ctx: ctx, expected: exp, nowMs: (o.now ?? { PCAAttestation.nowMs() })(), trustedAttestorKeys: o.trustedAttestorKeys, pqPins: o.pqPins,
                    hardwareVerifier: o.hardwareVerifier, maxNonceAgeMs: o.maxNonceAgeMs, clockSkewMs: o.clockSkewMs))
                if verdict.ok && verdict.bound, let store = o.nonceStore {
                    // the single-use consume runs only for a verified, bound attestation: a nonce is never burnt by a refused one
                    guard let n = exp.get("nonce")?.asString, store.consume(n) else { return bad(verdict.present, "attestation nonce already consumed (replay)") }
                }
                return fin(verdict)
            } catch {
                return bad(false, "attestation verification error (fail closed): \(PCAAttestation.msg(error))")
            }
        }

        public func callAsFunction(_ ctx: JSONValue) -> HookResult { verify(ctx) }
    }

    /// Builds the hook over `verifyAttestation`. With neither `expectedBinding` nor the loud `insecureSelfDeclaredNonce` opt-out it fails closed.
    public static func createAttestationVerifier(_ o: VerifierOptions) -> Verifier { Verifier(o) }

    // MARK: multi-root N-of-M

    /// One independent attestation root of a multi-root policy: a stable id (de-duplication and audit), its verifier, whether it MUST verify, and an
    /// audit-only suite label.
    public struct Root {
        public var id: String
        public var verifier: HardwareVerifier
        public var required: Bool
        public var suite: String?
        public init(id: String, verifier: HardwareVerifier, required: Bool = false, suite: String? = nil) {
            self.id = id; self.verifier = verifier; self.required = required; self.suite = suite
        }
    }

    private static let identFields = ["model_id", "weights_digest", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest"]

    /// A `HardwareVerifier` that requires corroboration from at least `threshold` independent roots. Every root runs against the same action; a
    /// required root that did not verify (ok, bound, measured) denies naming the root; fewer than `threshold` verified roots denies; corroborating roots
    /// whose measured identities contradict deny; otherwise the reconciled identity is returned bound.
    public final class MultiRootVerifier: HardwareVerifier, AssuranceLabeled {
        let roots: [Root]
        let threshold: Int
        public let assuranceLabel: AssuranceLabel

        init(roots: [Root], threshold: Int) {
            self.roots = roots
            self.threshold = threshold
            // the fewest hardware roots any accepted quorum can contain
            assuranceLabel = AssuranceLabel(level: PCA.multiRootLevel(roots.map { AttestationRoot(verifier: $0.verifier, required: $0.required) }, threshold: threshold),
                                            vendor: "multi-root:" + roots.map { $0.id }.joined(separator: "+"))
        }

        public func verify(document: JSONValue, ctx: JSONValue, nowMs: Double, expected: JSONValue) throws -> HardwareResult {
            var passed: [(idx: Int, m: JSONValue)] = []
            var host: [String: String] = [:]
            for (i, r) in roots.enumerated() {
                var res: HardwareResult
                do { res = try r.verifier.verify(document: document, ctx: ctx, nowMs: nowMs, expected: expected) } catch {
                    res = HardwareResult(ok: false, reason: "root '\(r.id)' threw (fail closed): \(PCAAttestation.msg(error))")
                }
                if res.ok && res.bound == true, let m = res.measured, JS.truthy(m) {
                    passed.append((i, m))
                    for (k, v) in res.hostAsserted ?? [:] { host["\(r.id).\(k)"] = v }
                } else if r.required {
                    let why = res.malformed ? "root '\(r.id)' returned a malformed result (fail closed)" : (res.reason ?? "invalid")
                    return HardwareResult(ok: false, reason: "required attestation root '\(r.id)' failed: \(why)")
                }
            }
            if passed.count < threshold {
                return HardwareResult(ok: false, reason: "multi-root attestation below threshold (\(passed.count)/\(threshold) independent roots corroborated)")
            }
            // reconcile the corroborating identities field by field: a non-empty string a root states must agree with every other root that states it
            var chosen = [String](repeating: "", count: PCAAttestation.identFields.count)
            for (f, name) in PCAAttestation.identFields.enumerated() {
                var who = -1
                for p in passed {
                    guard case let .string(v)? = p.m.get(name), !v.isEmpty else { continue }
                    if chosen[f].isEmpty { chosen[f] = v; who = p.idx }
                    else if !IV.same(chosen[f], v) {
                        return HardwareResult(ok: false, reason: "multi-root attestation identity conflict: roots '\(roots[who].id)' and '\(roots[p.idx].id)' disagree on \(name)")
                    }
                }
            }
            var m: JObject = ["model_id": .string(chosen[0]), "weights_digest": .string(chosen[1]), "runtime_measurement": .string(chosen[2]), "operator": .string(chosen[3])]
            // weights are measured only when a root that measured them carries the chosen digest
            var measured = false
            for p in passed where !chosen[1].isEmpty && p.m.get("weights_measured") == .bool(true) {
                if case let .string(w)? = p.m.get("weights_digest"), IV.same(w, chosen[1]) { measured = true }
            }
            m["weights_measured"] = .bool(measured)
            if !chosen[4].isEmpty { m["system_prompt_digest"] = .string(chosen[4]) }
            if !chosen[5].isEmpty { m["tool_manifest_digest"] = .string(chosen[5]) }
            return HardwareResult(ok: true, measured: .object(m), bound: true, hostAsserted: host.isEmpty ? nil : host)
        }
    }

    /// Builds the multi-root verifier. Throws on no roots, a threshold that is not an integer in `[1, roots.count]`, an empty id or a duplicate id.
    public static func createMultiRootVerifier(roots: [Root], threshold: Double) throws -> MultiRootVerifier {
        if roots.isEmpty { throw JSError("createMultiRootVerifier: at least one attestation root is required") }
        guard threshold.isFinite, threshold.rounded() == threshold, threshold >= 1, threshold <= Double(roots.count) else {
            throw JSError("createMultiRootVerifier: threshold must be an integer in [1, roots.length]")
        }
        var ids = Set<[UInt16]>()
        for r in roots {
            if r.id.isEmpty { throw JSError("createMultiRootVerifier: each root needs a non-empty id") }
            if !ids.insert(Array(r.id.utf16)).inserted { throw JSError("createMultiRootVerifier: duplicate root id '\(r.id)'") }
        }
        return MultiRootVerifier(roots: roots, threshold: Int(threshold))
    }

    // MARK: accountability anchoring

    /// The canonical, domain-separated digest of a verified attestation (`{identity, binding, rootIds?, suite?, verifiedAt}`): the commitment leaf
    /// appended to the transparency ledger. It binds the measured identity AND the holder, grant, epoch and nonce. Throws where the strict canonical
    /// form does.
    public static func attestationEvidenceDigest(_ ev: JSONValue) throws -> String {
        func need(_ v: JSONValue?) throws -> JSONValue { guard let v = v else { throw JSError("canonicalize: unsupported type undefined") }; return v }
        func orEmpty(_ v: JSONValue?) -> JSONValue { JS.present(v) ?? .string("") }
        let id = ev.get("identity"), bind = ev.get("binding")
        var roots: [[UInt16]] = []
        switch ev.get("rootIds") {
        case nil, .null?: break
        case let .array(a)?: roots = a.map { Array(JS.toString($0).utf16) }
        default: throw JSError("rootIds is not iterable")
        }
        roots.sort { $0.lexicographicallyPrecedes($1) }
        let body: JSONValue = .object([
            "domain": .string(ATTEST_ANCHOR_DOMAIN), "holder": try need(bind?.get("holderPub")), "grant": try need(bind?.get("grantRef")),
            "epoch": try need(bind?.get("epoch")), "nonce": try need(bind?.get("nonce")),
            "model_id": try need(id?.get("model_id")), "weights_digest": try need(id?.get("weights_digest")),
            "weights_measured": .bool(id?.get("weights_measured") == .bool(true)),
            "runtime_measurement": try need(id?.get("runtime_measurement")), "operator": try need(id?.get("operator")),
            "system_prompt_digest": orEmpty(id?.get("system_prompt_digest")), "tool_manifest_digest": orEmpty(id?.get("tool_manifest_digest")),
            "roots": .array(roots.map { .string(String(decoding: $0, as: UTF16.self)) }), "suite": orEmpty(ev.get("suite")), "verified_at": try need(ev.get("verifiedAt")),
        ])
        return try hashStrict(body)
    }

    public struct AnchorOptions {
        /// The transparency ledger to anchor into.
        public var ledger: PCATransparencyLedger?
        /// Signs the resulting tree head; with a post-quantum suite the record is post-quantum accountable. Without it the commitment is still appended
        /// but no tree head is produced (allowed only when `required` is false).
        public var guardian: PCASuiteKey?
        public var instanceId: String?
        /// The clock for the head timestamp (default the wall clock).
        public var now: (() -> Double)?
        /// Anchoring MUST fully succeed (ledger present, commitment appended, head signed) or throw.
        public var required: Bool
        public init(ledger: PCATransparencyLedger?, guardian: PCASuiteKey? = nil, instanceId: String? = nil, now: (() -> Double)? = nil, required: Bool = false) {
            self.ledger = ledger; self.guardian = guardian; self.instanceId = instanceId; self.now = now; self.required = required
        }
    }

    /// Anchors a VERIFIED attestation into the transparency ledger for after-the-fact accountability: appends its evidence digest as an opaque commitment
    /// and, with a guardian key, signs the resulting tree head. Returns `{index, commit, sth?}`. Fails closed when `required`.
    public static func anchorAttestationEvidence(_ ev: JSONValue, _ o: AnchorOptions) throws -> JSONValue {
        func fail(_ m: String) -> JSError { JSError("attestation anchoring (fail closed): \(m)") }
        guard let ledger = o.ledger else { throw fail("no transparency ledger available") }
        if o.required && o.guardian == nil { throw fail("required anchoring needs a guardian secret to sign the tree head") }
        let commit = try attestationEvidenceDigest(ev)
        let prevRoot = ledger.head().get("root") ?? .string("")
        let index = try ledger.appendCommitment(commit).index
        let head = ledger.head()
        var out: JObject = ["index": .int(Int64(index)), "commit": .string(commit)]
        if let g = o.guardian {
            let now = (o.now ?? { PCAAttestation.nowMs() })()
            do {
                out["sth"] = try Ledger.signTreeHead(g, .object([
                    "instance_id": .string(o.instanceId ?? ""), "principal": .string(ledger.principal), "size": head.get("size") ?? .int(0),
                    "root": head.get("root") ?? .string(""), "prev_root": prevRoot, "timestamp": StoreJ.num(now)]))
            } catch {
                if o.required { throw fail("tree-head signing failed: \(msg(error))") }
            }
        }
        return .object(out)
    }
}

extension Ledger {
    /// Signs a tree head `{instance_id, principal, size, root, prev_root, timestamp}` as the guardian `key` (the suite and its post-quantum key are
    /// signed into the body); the result carries the head, `guardian` (the base64url Ed25519 identity) and the signature members.
    public static func signTreeHead(_ key: PCASuiteKey, _ head: JSONValue) throws -> JSONValue {
        guard let ed = key.ed else { throw JSError("signer needs an Ed25519 identity key") }
        var body = JObject()
        for k in ["instance_id", "principal", "size", "root", "prev_root", "timestamp"] {
            guard let v = head.get(k) else { throw JSError("canonicalize: unsupported type undefined") }
            body[JKey(k)] = v
        }
        var signed = try PCAIntentKit.signSuite(body, key) { try PCAIntentKit.message(STH_DOMAIN, .object($0)) }
        signed["guardian"] = .string(Base64URLStrict.encode(ed.pub))
        return .object(signed)
    }
}
