import Foundation

/// The rest of the pure A2A binding surface of pca-a2a (a2a-auth.ts, a2a-receipt.ts, ext-uri.ts): the signed task-update receipt and its carriers, the Agent
/// Card extension declaration and its reader, the AUTH_REQUIRED mapping (status, answer message, parked need), the push gate and the anti-enumeration error.
/// The checks that need the full PCActn verifier (`verifyA2ATask`, `resumeAuthRequired`, `verifyA2ADelegation`, the middleware) are the ordinary verifier's job.
extension A2a {
    public static let PCA_A2A_EXTENSION_URI = "https://atlasauth.net/a2a/ext/pca/v2"
    public static let RECEIPT_KEY = PCA_A2A_EXTENSION_URI + "#receipt"
    public static let NEED_KEY = PCA_A2A_EXTENSION_URI + "#need"
    public static let TASK_STATE_AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"
    public static let TASK_STATE_INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
    static let A2A_RECEIPT_REF_DOMAIN = "atlas-pca/a2a-receipt-ref/v1"
    public static let A2A_RECEIPT_DOMAIN = RECEIPT_DOMAIN

    /// AUTH_REQUIRED in the 1.0 enum spelling; the pre-1.0 `auth-required` is also read, never written.
    public static func isAuthRequired(_ state: JSONValue?) -> Bool {
        guard let s = state?.asString else { return false }
        return s == TASK_STATE_AUTH_REQUIRED || s == "auth-required"
    }

    /// Does `next` (capability ids, root first) extend `prev`? Attenuation only appends hops, so the earlier chain must be a prefix.
    // The reference takes any JS value for a chain: these are its `length` / index / `every` semantics on a decoded value.
    private static func jsLength(_ v: JSONValue?) throws -> Double? {
        switch v {
        case nil: throw JSError("Cannot read properties of undefined (reading 'length')")
        case .null?: throw JSError("Cannot read properties of null (reading 'length')")
        case let .array(a)?: return Double(a.count)
        case let .string(x)?: return Double(x.utf16.count)
        case let .object(o)?: return o["length"].flatMap { IV.num($0) }
        default: return nil
        }
    }
    private static func jsIndex(_ v: JSONValue?, _ i: Int) -> JSONValue? {
        switch v {
        case let .array(a)?: return i >= 0 && i < a.count ? a[i] : nil
        case let .string(x)?:
            let u = Array(x.utf16)
            return i >= 0 && i < u.count ? .string(String(utf16CodeUnits: [u[i]], count: 1)) : nil
        case let .object(o)?: return o[JKey(String(i))]
        default: return nil
        }
    }
    private static func jsStrictEq(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (x?, y?):
            if x.isObject || x.isArray || y.isObject || y.isArray { return false }
            if x.isNumber && y.isNumber { return IV.num(x) == IV.num(y) }
            return x == y
        default: return false
        }
    }
    /// `chainExtends` over any decoded values: `next.length >= prev.length && prev.every((id, k) => next[k] === id)`.
    public static func chainExtends(_ prev: JSONValue?, _ next: JSONValue?) throws -> Bool {
        let nl = try jsLength(next), pl = try jsLength(prev)
        guard let n = nl, let p = pl, n >= p else { return false }
        guard case let .array(a)? = prev else { throw JSError("prev.every is not a function") }
        for (k, id) in a.enumerated() where !jsStrictEq(jsIndex(next, k), id) { return false }
        return true
    }
    /// `checkChainExtension` over any decoded value: `{ok: true}` or `{ok: false, failedHop, reason}`; a null / undefined chains list throws.
    public static func checkChainExtension(_ chains: JSONValue?) throws -> JSONValue {
        let n = try jsLength(chains) ?? Double.nan
        var i = 0
        while Double(i) < n {
            let ids = jsIndex(chains, i)
            guard case let .array(a)? = ids, !a.isEmpty else { return .object(["ok": .bool(false), "failedHop": .int(Int64(i)), "reason": .string("no_chain")]) }
            if let prev = i > 0 ? jsIndex(chains, i - 1) : nil, !(try chainExtends(prev, ids)) {
                return .object(["ok": .bool(false), "failedHop": .int(Int64(i)), "reason": .string("chain_does_not_extend_previous_hop")])
            }
            i += 1
        }
        return .object(["ok": .bool(true)])
    }

    public static func chainExtends(_ prev: [String], _ next: [String]) -> Bool { next.count >= prev.count && Array(next.prefix(prev.count)) == prev }

    /// The one error A2A servers return for "no such task" and "not yours" alike.
    public static func uniformTaskNotFound() -> JSONValue { .object(["code": .string("TaskNotFoundError"), "message": .string("task not found")]) }

    // ---- receipts ----

    /// The content address the next receipt cites as `prev`; alias of `receiptDigest`.
    public static func verifyTaskReceipt(_ v: JSONValue?, signer: String) -> Bool { verifyReceipt(v, signer: signer) }

    /// Sign a receipt. `prev` is the previous receipt of the same task (nil for the first). Throws on malformed input or a task id mismatch.
    public static func signTaskReceipt(_ secret: PCAEdKey, taskId: String, state: String, chainIds: [String], issuedAt: Int64, prev: JSONValue? = nil) throws -> JSONValue {
        guard !taskId.isEmpty, IV.u16(taskId) <= 256, STATES.contains(state), issuedAt >= 0, !chainIds.isEmpty else { throw PCAProducerError("signTaskReceipt: malformed input") }
        var seq: Int64 = 0
        var prevDigest: JSONValue = .null
        if let p = prev {
            guard p.get("task_id")?.asString == taskId, !TERMINAL.contains(p.get("state")?.asString ?? ""), let ps = IV.nonNeg(p.get("seq")) else {
                throw PCAProducerError("signTaskReceipt: prev is for another task or already terminal")
            }
            seq = ps + 1
            prevDigest = .string(receiptDigest(p))
        }
        var body: JObject = ["v": .int(1), "task_id": .string(taskId), "state": .string(state), "seq": .int(seq), "prev": prevDigest,
                             "chain": .string(PcaGrant.chainDigest(chainIds)), "issued_at": .int(issuedAt), "signer": .string(secret.id)]
        body["sig"] = .string(try PCAIssue.signBody(secret, domain: RECEIPT_DOMAIN, body: .object(body)))
        return .object(body)
    }

    /// Put a receipt on a status update or message metadata (returns a copy).
    public static func attachReceipt(_ carrier: JSONValue, _ r: JSONValue) throws -> JSONValue {
        // `carrier.metadata` of null is a TypeError in the reference
        if carrier == .null { throw JSError("Cannot read properties of null (reading 'metadata')") }
        var o = carrier.asObject ?? [:]
        var md = o["metadata"]?.asObject ?? [:]
        md[JKey(RECEIPT_KEY)] = r
        o["metadata"] = .object(md)
        return .object(o)
    }

    /// The receipt carried by a push/stream payload (`statusUpdate.metadata`, `task.metadata`, `message.metadata`), or nil. Unverified.
    public static func receiptOfPayload(_ payload: JSONValue?) -> JSONValue? {
        guard let p = payload?.asObject else { return nil }
        for k in ["statusUpdate", "task", "message"] {
            if let md = p[JKey(k)]?.asObject?["metadata"]?.asObject, let r = md[JKey(RECEIPT_KEY)] { return r }
        }
        return nil
    }

    // ---- Agent Card extension ----

    /// The `AgentExtension` object (A2A 4.4.4) to put in `capabilities.extensions`.
    public static func pcaExtensionDeclaration(_ params: JObject, required: Bool = true) -> JSONValue {
        .object(["uri": .string(PCA_A2A_EXTENSION_URI), "description": .string("Per-action proofs of authority (PCActn) on tasks and messages"),
                 "required": .bool(required), "params": .object(params)])
    }

    /// Read and validate the PCA extension from an Agent Card: `{ok: true, required, params, grants}` or `{ok: false, code}`. A malformed declaration is a refusal.
    public static func readPcaExtension(_ card: JSONValue?) -> JSONValue {
        func fail(_ c: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(c)]) }
        guard let exts = card?.get("capabilities")?.get("extensions")?.asArray else { return fail("not_declared") }
        let found = exts.filter { $0.asObject != nil && $0.get("uri")?.asString == PCA_A2A_EXTENSION_URI }
        if found.isEmpty { return fail("not_declared") }
        if found.count > 1 { return fail("bad_declaration") } // two declarations disagree: refuse
        let e = found[0]
        if let r = e.get("required"), case .bool = r {} else if e.get("required") != nil { return fail("bad_declaration") }
        guard let p = e.get("params")?.asObject, p.keys.allSatisfy({ ["aud", "suites", "grants", "policy_digest"].contains($0.s) }),
              let aud = p["aud"]?.asString, !aud.isEmpty, IV.u16(aud) <= 512 else { return fail("bad_params") }
        if let s = p["suites"] {
            guard let a = s.asArray, a.count <= 16, a.allSatisfy({ $0.asString.map { !$0.isEmpty && IV.u16($0) <= 64 } == true }) else { return fail("bad_params") }
        }
        if let d = p["policy_digest"] {
            guard let s = d.asString, !s.isEmpty, IV.u16(s) <= 128 else { return fail("bad_params") }
        }
        var grants: [JSONValue] = []
        if let g = p["grants"] {
            let parsed = PcaGrant.parse(g)
            if parsed.code != nil { return fail("bad_grants") }
            grants = parsed.details
        }
        return .object(["ok": .bool(true), "required": .bool(e.get("required") == .bool(true)), "params": .object(p), "grants": .array(grants)])
    }

    /// True iff the `A2A-Extensions` service parameter lists the PCA extension (exact URI match in a comma-separated list).
    public static func clientOptsIntoPca(_ header: JSONValue?) -> Bool {
        guard let h = header?.asString else { return false }
        return h.split(separator: ",", omittingEmptySubsequences: false).contains { part in
            // String.prototype.trim: the JS white-space set (U+FEFF in, U+0085 out), not Foundation's
            var u = Array(part.unicodeScalars)
            while let f = u.first, Attest.isJSSpace(f) { u.removeFirst() }
            while let l = u.last, Attest.isJSSpace(l) { u.removeLast() }
            var t = String.UnicodeScalarView(); t.append(contentsOf: u)
            return String(t) == PCA_A2A_EXTENSION_URI
        }
    }

    // ---- AUTH_REQUIRED mapping ----

    /// `encodePcaNeed`: validates, then base64url of the strict canonical JSON; throws on a malformed or oversized need.
    public static func encodePcaNeed(_ need: JSONValue) throws -> String {
        if let code = needError(need) { throw PCAProducerError("encodePcaNeed: malformed need (\(code))") }
        guard let c = IV.strictCanon(need) else { throw PCAProducerError("encodePcaNeed: malformed need (bad_shape)") }
        let enc = Base64URLStrict.encode(Array(c.utf8))
        if enc.utf8.count > 2048 { throw PCAProducerError("encodePcaNeed: the need is too large for a header") }
        return enc
    }

    /// The TaskStatus an agent sets to ask for authority; the typed need rides in the message metadata under the extension key.
    public static func authRequiredStatus(_ need: JSONValue, messageId: String, now: Double, text: String? = nil) throws -> JSONValue {
        let enc = try encodePcaNeed(need)
        let ts = try PCAIntentRender.isoString(now)
        let label = text ?? "Authority needed: \(need.get("verb")?.asString ?? "") on \(need.get("resource")?.asString ?? "")"
        let message: JObject = ["messageId": .string(messageId), "role": .string("agent"),
                                "parts": .array([.object(["kind": .string("text"), "text": .string(label)])]),
                                "extensions": .array([.string(PCA_A2A_EXTENSION_URI)]), "metadata": .object([JKey(NEED_KEY): .string(enc)])]
        return .object(["state": .string(TASK_STATE_AUTH_REQUIRED), "timestamp": .string(ts), "message": .object(message)])
    }

    /// The need parked in a task status message, decoded (nil when there is none).
    public static func readAuthRequiredNeed(_ task: JSONValue?) -> (need: JSONValue?, code: String?)? {
        guard let v = task?.get("status")?.get("message")?.get("metadata")?.get(NEED_KEY) else { return nil }
        return decodeNeed(v)
    }

    /// The answer message to put on the Task: a PCActn for exactly the parked need, plus the need's digest.
    public static func answerMessage(_ need: JSONValue, _ pcActn: JSONValue, messageId: String) -> JSONValue {
        .object(["role": .string("user"), "messageId": .string(messageId),
                 "parts": .array([.object(["kind": .string("text"), "text": .string("authority provided")])]),
                 "metadata": .object([JKey(PCA_A2A_EXTENSION_URI): pcActn, JKey(NEED_KEY): .string(needDigest(need))])])
    }
}
