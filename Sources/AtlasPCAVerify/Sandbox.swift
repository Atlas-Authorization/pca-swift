import Foundation

/// The sandbox package: runtime classes, the receipt hash chain, the capability handle table, signed runtime claims, the OS policy
/// compiler and its profile generators, and the egress admission policy. The WebAssembly host, the component host and the HTTP
/// forward proxy are not part of this SDK (they need a runtime it does not carry); the egress policy decides, the caller moves bytes.
public enum PCASandbox {
    /// Runtime classes, weakest first. The class is a claim by the host operator, recorded in every receipt.
    public static let RUNTIME_CLASSES = ["none", "os_confined", "egress_default_deny", "wasi_no_ambient"]
    public static let GENESIS = "genesis"
    public static let IMPORT_MODULE = "pca:act"
    public static let ALLOWED_IMPORTS = ["invoke", "handle_count", "handle_verb"]
    public static let RUNTIME_CLAIM_DOMAIN = RuntimeClaim.DOMAIN

    /// Negative return codes of a handle use (the WASM ABI returns them as i32).
    public static let USE_ERR: [(String, Int)] = [("unknown_handle", -1), ("spent", -2), ("out_too_small", -3), ("bad_memory", -4), ("executor_error", -5), ("no_executor", -6)]

    /// True only when both names are known and `attested` is at least `required`. An unknown name never satisfies.
    public static func satisfiesRuntimeClass(_ attested: String, _ required: String) -> Bool {
        guard let a = RUNTIME_CLASSES.firstIndex(where: { IV.same($0, attested) }), let r = RUNTIME_CLASSES.firstIndex(where: { IV.same($0, required) }) else { return false }
        return a >= r
    }

    /// What an authorization produced: whether it allowed, and the operation it bound.
    public struct Grant {
        public var allow: Bool
        public var operation: PCA.AuthorizedOperation?
        public init(allow: Bool, operation: PCA.AuthorizedOperation? = nil) {
            self.allow = allow
            self.operation = operation
        }
        public init(_ r: PCA.AuthorizeResult) { self.init(allow: r.allow, operation: r.operation) }
        func authorizes(_ op: PCA.Operation) -> Bool { PCA.isAuthorizedFor(allow: allow, bound: operation, operation: op) }
    }

    public struct SandboxError: Error, CustomStringConvertible {
        public let description: String
        init(_ d: String) { description = d }
    }

    /// A JS number as a JSON value (an integral value is an integer).
    static func num(_ d: Double) -> JSONValue {
        if d.isFinite, d.rounded(.towardZero) == d, abs(d) <= IV.MAX_SAFE { return .int(Int64(d)) }
        return .double(d)
    }

    static func isInteger(_ d: Double) -> Bool { d.isFinite && d.rounded(.towardZero) == d }

    // MARK: receipts

    /// Append-only hash chain of use receipts: every handle use and every egress decision, refusals included. An entry is a JSON object
    /// `{v, seq, prev, at, runtime_class, ...body, digest, sig?}` (the body's own members win over the first five, like the reference).
    public final class ReceiptLog {
        public private(set) var entries: [JSONValue] = []
        private let now: () -> Double
        private let sign: ((String) -> String)?

        public init(now: (() -> Double)? = nil, sign: ((String) -> String)? = nil) {
            self.now = now ?? { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
            self.sign = sign
        }

        /// Throws (and records nothing) when the receipt is not strictly canonicalizable (a non-integer or non-finite number, ...).
        @discardableResult
        public func append(_ runtimeClass: String, _ body: JObject) throws -> JSONValue {
            var u: JObject = [
                "v": .int(1), "seq": .int(Int64(entries.count)),
                "prev": .string(entries.last?.get("digest")?.asString ?? PCASandbox.GENESIS),
                "at": PCASandbox.num(now()), "runtime_class": .string(runtimeClass),
            ]
            for (k, v) in body { u[k] = v }
            guard let digest = IV.strictHash(.object(u)) else { throw SandboxError("receipt is not canonicalizable") }
            u["digest"] = .string(digest)
            if let s = sign { u["sig"] = .string(s(digest)) }
            let r = JSONValue.object(u)
            entries.append(r)
            return r
        }

        func record(_ rc: String, kind: String, subject: JObject, outcome: String, reason: String) throws {
            try append(rc, ["kind": .string(kind), "subject": .object(subject), "outcome": .string(outcome), "reason": .string(reason)])
        }
    }

    static func subject(opId: String, verb: String, resource: String, paramsDigest: String) -> JObject {
        ["op_id": .string(opId), "verb": .string(verb), "resource": .string(resource), "params_digest": .string(paramsDigest)]
    }

    /// Recompute the chain: `{ok: true}` or `{ok: false, at, reason}` for a bad digest, a broken link, a gap, a reorder or (with
    /// `verifySig`) a bad signature. Throws, like the reference, for a non-array or an entry that is null or not canonicalizable.
    public static func verifyReceiptChain(_ receipts: JSONValue, verifySig: ((String, String) -> Bool)? = nil) throws -> JSONValue {
        guard let list = receipts.asArray else { throw SandboxError("receipts is not an array") }
        func bad(_ i: Int, _ r: String) -> JSONValue { .object(["ok": .bool(false), "at": .int(Int64(i)), "reason": .string(r)]) }
        var prev = PCASandbox.GENESIS
        for (i, r) in list.enumerated() {
            if r.isNull { throw SandboxError("receipt is null") }
            guard let o = r.asObject, IV.num(o[JKey("v")]) == 1, IV.num(o[JKey("seq")]) == Double(i) else { return bad(i, "bad_seq") }
            guard let p = o[JKey("prev")]?.asString, IV.same(p, prev) else { return bad(i, "broken_link") }
            var rest = o
            rest[JKey("digest")] = nil
            rest[JKey("sig")] = nil
            guard let h = IV.strictHash(.object(rest)) else { throw SandboxError("receipt is not canonicalizable") }
            guard let d = o[JKey("digest")]?.asString, IV.same(h, d) else { return bad(i, "bad_digest") }
            if let v = verifySig {
                guard let s = o[JKey("sig")]?.asString, v(d, s) else { return bad(i, "bad_sig") }
            }
            prev = d
        }
        return .object(["ok": .bool(true)])
    }

    // MARK: runtime claims

    /// Sign a runtime claim `{class, passport_digest, evidence_digest, iat, exp}` as `attestor` (the base64url of `publicKey`). Signed
    /// bytes: `domain || strictCanonical(claim without sig)`, Ed25519 (RFC 8032, deterministic). Throws for a seed that is not 32 bytes or a
    /// claim that is not strictly canonicalizable; it does not judge the claim (`verifiedRuntimeClass` does).
    public static func signRuntimeClaim(seed: [UInt8], publicKey: [UInt8], _ c: JObject) throws -> JSONValue {
        guard seed.count == 32 else { throw SandboxError("an Ed25519 seed is 32 bytes") }
        var u: JObject = ["v": .int(1)]
        for (k, v) in c { u[k] = v }
        u["attestor"] = .string(Base64URLStrict.encode(publicKey))
        guard let msg = IV.message(RUNTIME_CLAIM_DOMAIN, .object(u)) else { throw SandboxError("claim is not canonicalizable") }
        u["sig"] = .string(Base64URLStrict.encode(Ed25519Deterministic.sign(seed: seed, msg)))
        return .object(u)
    }

    /// The class the claim proves, or `none` for anything missing, unsigned, unpinned, expired, for another passport, over unverified
    /// evidence or malformed. `trust` is `{pinnedAttestors: [string], passportDigest: string, verifiedEvidenceDigests: [string], now}`;
    /// a trust object missing a member, or holding one of the wrong type, proves nothing.
    public static func verifiedRuntimeClass(_ claim: JSONValue?, trust: JSONValue?) -> String {
        guard let t = trust?.asObject,
              let pins = t[JKey("pinnedAttestors")]?.asArray, pins.allSatisfy({ $0.asString != nil }),
              let pd = t[JKey("passportDigest")]?.asString,
              let ev = t[JKey("verifiedEvidenceDigests")]?.asArray, ev.allSatisfy({ $0.asString != nil }),
              IV.nonNeg(t[JKey("now")]) != nil else { return "none" }
        return RuntimeClaim.verifiedClass(claim, pinnedAttestors: pins.compactMap { $0.asString }, passportDigest: pd,
                                          verifiedEvidence: ev.compactMap { $0.asString }, now: t[JKey("now")])
    }

    /// hashCanonical of the signed passport a claim is about. Throws for a value the strict canonical form refuses.
    public static func passportDigest(_ signedPassport: JSONValue) throws -> String {
        guard let d = IV.strictHash(signedPassport) else { throw SandboxError("not canonicalizable") }
        return d
    }

    /// The digest a claim's `evidence_digest` must equal for this attestation document.
    public static func evidenceDigest(_ document: JSONValue) throws -> String { try passportDigest(document) }

    // MARK: handles

    /// What a tool may do with a handle: run the one authorized operation. The executor gets the signed params, never the guest's.
    /// Returning nil (something that is not bytes) or throwing is an `executor_error`.
    public typealias Executor = (PCA.Operation) throws -> [UInt8]?

    public enum UseFailure: String { case unknown_handle, spent, out_too_small, bad_memory, executor_error, no_executor }
    public enum UseResult: Equatable {
        case ok([UInt8])
        case failed(UseFailure)
    }

    private final class Slot {
        var op: PCA.Operation
        let paramsDigest: String
        let opId: String
        var uses: Double
        var expiresAt: Double
        var revoked = false
        var children: [Int] = []
        init(op: PCA.Operation, paramsDigest: String, opId: String, uses: Double, expiresAt: Double) {
            self.op = op
            self.paramsDigest = paramsDigest
            self.opId = opId
            self.uses = uses
            self.expiresAt = expiresAt
        }
    }

    /// A per-sandbox capability table: indices are small integers (1-based) meaningful only inside one table, like file descriptors. A
    /// slot exists only because a verified authorization allowed exactly that operation; derivation is monotone (a child holds only what
    /// the parent gave up); revoking a slot revokes everything derived from it.
    public final class HandleTable {
        public let runtimeClass: String
        private let log: ReceiptLog
        private let executors: [String: Executor]
        private let now: () -> Double
        private var slots: [Slot] = []

        public init(runtimeClass: String, log: ReceiptLog, executors: [String: Executor], now: (() -> Double)? = nil) {
            self.runtimeClass = runtimeClass
            self.log = log
            self.executors = executors
            self.now = now ?? { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
        }

        /// Mint a handle for the operation `grant` allowed. Throws (fail closed) if the grant does not allow exactly `operation`, the table
        /// is below `requires`, or `uses` is not an integer in 1...1_000_000 (default 1).
        public func mint(_ grant: Grant, _ operation: PCA.Operation, uses: Double? = nil, expiresAt: Double? = nil, requires: String? = nil) throws -> Int {
            if let r = requires, !PCASandbox.satisfiesRuntimeClass(runtimeClass, r) { throw SandboxError("runtime_class_too_weak: table is \(runtimeClass), grant requires \(r)") }
            guard grant.authorizes(operation), let bound = grant.operation, let digest = IV.strictHash(operation.params) else { throw SandboxError("not_authorized: result does not allow exactly this operation") }
            let u = uses ?? 1
            guard PCASandbox.isInteger(u), u >= 1, u <= 1_000_000 else { throw SandboxError("bad_uses") }
            slots.append(Slot(op: operation, paramsDigest: digest, opId: bound.id, uses: u, expiresAt: expiresAt ?? .infinity))
            return slots.count
        }

        /// Derive a narrower handle: takes `uses` from the parent (never more than it has) and an expiry no later than the parent's.
        public func attenuate(_ index: Double, uses: Double? = nil, expiresAt: Double? = nil) throws -> Int {
            guard let p = live(index) else { throw SandboxError("unknown_handle") }
            let u = uses ?? p.uses
            guard PCASandbox.isInteger(u), u >= 1, u <= p.uses else { throw SandboxError("attenuate_widens") }
            let e = expiresAt ?? p.expiresAt
            guard e <= p.expiresAt else { throw SandboxError("attenuate_widens") }
            p.uses -= u
            slots.append(Slot(op: p.op, paramsDigest: p.paramsDigest, opId: p.opId, uses: u, expiresAt: e))
            let child = slots.count
            p.children.append(child)
            return child
        }

        /// Revoke a handle and, transitively, every handle derived from it.
        public func revoke(_ index: Double) {
            guard let s = slot(index), !s.revoked else { return }
            s.revoked = true
            for c in s.children { revoke(Double(c)) }
        }

        public var size: Int { slots.count }

        /// The verb a handle carries, for a tool deciding which handle to use.
        public func verbOf(_ index: Double) -> String? { slot(index)?.op.verb }

        /// Use a handle: run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs and
        /// stays consumed if it throws (a failed side effect needs a new authorization, not a retry on the old one).
        public func use(_ index: Double) throws -> UseResult {
            guard let s = slot(index) else {
                try log.record(runtimeClass, kind: "handle_use", subject: PCASandbox.subject(opId: "", verb: "", resource: "", paramsDigest: ""), outcome: "refused", reason: "unknown_handle")
                return .failed(.unknown_handle)
            }
            guard let l = live(index) else { return try finish(s, .failed(.spent)) }
            guard let exec = executors[s.op.verb] else { return try finish(s, .failed(.no_executor)) }
            l.uses -= 1
            if let bytes = try? exec(s.op) { return try finish(s, .ok(bytes)) }
            return try finish(s, .failed(.executor_error))
        }

        private func finish(_ s: Slot, _ r: UseResult) throws -> UseResult {
            let outcome: String, reason: String
            switch r {
            case .ok: (outcome, reason) = ("ok", "used")
            case let .failed(f): (outcome, reason) = (f == .executor_error ? "error" : "refused", f.rawValue)
            }
            try log.record(runtimeClass, kind: "handle_use", subject: PCASandbox.subject(opId: s.opId, verb: s.op.verb, resource: s.op.resource, paramsDigest: s.paramsDigest), outcome: outcome, reason: reason)
            return r
        }

        private func slot(_ index: Double) -> Slot? {
            guard PCASandbox.isInteger(index), index >= 1, index <= Double(slots.count) else { return nil }
            return slots[Int(index) - 1]
        }

        private func live(_ index: Double) -> Slot? {
            guard let s = slot(index), !s.revoked, s.uses > 0, now().isFinite, now() < s.expiresAt else { return nil }
            return s
        }
    }
}
