import Foundation

/// Question delivery over the existing approval-channel transports (a webhook with an injected fetch, and email / sms / push through an
/// injected sender). A delivery only tells the principal's device that a question is waiting and hands it the SIGNED question: never a
/// rendered card, agent text, the map or p. Text surfaces use one fixed template. Native port of the TypeScript reference
/// (@atlasauth/pca-wallet, delivery.ts), plus the verifier side of the site-signed `pca-intent-required` v1 body the wallet consumes.
/// The transports are injected synchronous closures; with no fetch configured a webhook delivery reports "no fetch available" instead
/// of touching the network.
public enum PCAWalletDelivery {
    // ---- the site-signed question (pca-intent-required v1), verifier side ----

    static let SIG_MEMBERS = ["alg", "kid", "value", "pq_value"]

    /// Shape of a SIGNED `pca-intent-required` v1 body: nil when well formed.
    static func intentRequiredShapeError(_ b: JSONValue?) -> String? {
        guard case var .object(o)? = b else { return "not an object" }
        let sig = o["sig"]
        o["sig"] = nil
        if let e = PCASigners.intentRequiredShapeError(.object(o)) { return e }
        guard case let .object(s)? = sig else { return "sig must be {alg, kid, value, pq_value?}" }
        if let se = IV.suiteError(s["alg"]) { return "sig.alg: \(se)" }
        if let pq = s["pq_value"], pq.asString == nil { return "sig.pq_value must be a string" }
        if PCAWallet.keysOf(s).contains(where: { !IV.contains(SIG_MEMBERS, $0) }) || s["kid"]?.asString == nil || s["value"]?.asString == nil {
            return "sig must be {alg, kid, value, pq_value?}"
        }
        return nil
    }

    /// Verify a site-signed body against the site's discovery keys (the action schema's key list). The clock is REQUIRED: a `now` that
    /// is not a safe integer is refused, never coerced, so expiry can never be skipped. Returns {ok: true} or {ok: false, reason}.
    public static func verifyIntentRequired(_ b: JSONValue?, _ keys: JSONValue?, _ now: JSONValue?) -> JSONValue {
        func no(_ r: String) -> JSONValue { WJ.obj([("ok", .bool(false)), ("reason", .string(r))]) }
        guard let nowN = IV.safe(now) else { return no("the verifier clock is not a safe integer (fail closed)") }
        if let e = intentRequiredShapeError(b) { return no(e) }
        guard case let .object(body)? = b, let sig = body["sig"]?.asObject, let kid = sig["kid"]?.asString else { return no("malformed intent_required: not an object") }
        guard case let .array(ks)? = keys else { return no("the site keys must be an array") }
        guard let key = ks.compactMap({ $0.asObject }).first(where: { IV.same($0["kid"]?.asString, kid) }) else { return no("no site key with kid '\(kid)'") }
        if let kse = IV.suiteError(key["alg"]) { return no("site key: \(kse)") }
        guard let ka = IV.sigAlg(key["alg"]), ka == IV.sigAlg(sig["alg"]) else { return no("sig.alg does not match the pinned key suite") }
        var unsigned = body
        unsigned["sig"] = nil
        guard let msg = try? WJ.message(PCASigners.INTENT_REQUIRED_DOMAIN, .object(unsigned)) else { return no("malformed intent_required: canonicalize: lone surrogate in string") }
        let verdict: IV.SuiteVerdict
        if let pk = key["pk"]?.asString {
            verdict = IV.verifyPinned(alg: .string(ka), identity: pk, artifactPqPk: key["pq_pk"], msg: msg, sig: sig["value"], pqSig: sig["pq_value"],
                                      pin: key["pq_pk"].map { $0.asString ?? "" })
        } else { verdict = .invalid }
        switch verdict {
        case .valid: break
        case .unsupported: return no(IV.UNSUPPORTED_SUITE)
        case .invalid: return no("site signature invalid")
        }
        guard let exp = IV.num(body["expires_at"]), Double(nowN) <= exp else { return no("the question has expired") }
        return WJ.obj([("ok", .bool(true))])
    }

    // ---- notices ----

    /// A notice for a site-signed question. Throws when the signature or expiry does not verify (nothing unsigned leaves).
    public static func siteQuestionNotice(_ ir: JSONValue?, keys: JSONValue?, site: JSONValue?, now: JSONValue?, inboxUrl: JSONValue? = nil) throws -> JSONValue {
        let v = verifyIntentRequired(ir, keys, now)
        if v.get("ok") != .bool(true) { throw JSError("siteQuestionNotice: \(v.get("reason")?.asString ?? "")") }
        var out: JObject = ["type": .string("pca.intent.question"), "session": ir?.get("session") ?? .null, "question_id": ir?.get("question_id") ?? .null,
                            "friction": ir?.get("friction") ?? .null, "expires_at": ir?.get("expires_at") ?? .null, "intent_required": ir ?? .null]
        if let s = site { out["site"] = s }
        if let i = inboxUrl, JS.truthy(i) { out["inbox_url"] = i }
        return .object(out)
    }

    /// A notice for a wallet-originated question (clarification): ids only.
    public static func clarificationNotice(session: JSONValue?, questionId: JSONValue?, inboxUrl: JSONValue? = nil) -> JSONValue {
        var out: JObject = ["type": .string("pca.intent.clarification"), "session": session ?? .null, "question_id": questionId ?? .null]
        if let i = inboxUrl, JS.truthy(i) { out["inbox_url"] = i }
        return .object(out)
    }

    /// The fixed text of a text-surface notice.
    public static func questionText(_ notice: JSONValue?, siteName: JSONValue?) throws -> JSONValue {
        let isQ = WJ.isStr(notice?.get("type"), "pca.intent.question")
        var who = "Your agent"
        if isQ { let c = try PCAWalletCard.cleanText(siteName, 64); who = c.isEmpty ? "A site" : c }
        let subject = isQ ? "\(who) has a question about your request" : "\(who) needs a decision about your request"
        var link: String?
        if let inbox = notice?.get("inbox_url")?.asString, !inbox.isEmpty {
            link = inbox + (inbox.contains("?") ? "&" : "?") + "question=" + JS.encodeURIComponent(JS.toString(notice?.get("question_id")))
        }
        return WJ.obj([("subject", .string(subject)), ("text", .string([subject, "", link.map { "Open your wallet to answer: \($0)" } ?? "Open your wallet to answer."].joined(separator: "\n")))])
    }

    // ---- channels ----

    /// One delivery channel: `kind`, `enabled` and `notify(notice) -> delivery`.
    public struct QuestionChannel {
        public let kind: String
        public let enabled: Bool
        public let notify: (JSONValue) -> JSONValue
    }

    /// The injected webhook transport: `(url, {method, headers, body}) -> (ok, status)`; a throw is a failed delivery.
    public typealias FetchLike = (String, JSONValue) throws -> (ok: Bool, status: JSONValue)

    /// The notice as the JSON text a webhook carries: members in the reference's construction order.
    static func noticeJSON(_ n: JSONValue) -> String {
        JS.stringify(n, order: ["type", "session", "question_id", "site", "friction", "expires_at", "intent_required", "inbox_url",
                                "v", "kind", "map_digest", "schema", "pcactn_digest", "action_digest", "cell", "verb", "coords", "reason", "delivered_to", "sig",
                                "alg", "kid", "value", "pq_value"])
    }

    /// Webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question included.
    public static func questionWebhookChannel(url: String?, headers extra: JObject? = nil, fetch: FetchLike? = nil) -> QuestionChannel {
        let enabled = !(url ?? "").isEmpty
        var headers: JObject = ["content-type": .string("application/json")]
        for (k, v) in extra ?? [:] { headers[k] = v }
        let transport: FetchLike = fetch ?? { _, _ in throw JSError("no fetch available: pass a FetchLike transport") }
        return QuestionChannel(kind: "webhook", enabled: enabled) { notice in
            var base: JObject = ["kind": .string("webhook"), "questionId": notice.get("question_id") ?? .null, "payload": notice]
            guard enabled, let url = url else {
                base["delivered"] = .bool(false); base["reason"] = .string("webhook channel not configured")
                return .object(base)
            }
            do {
                let res = try transport(url, WJ.obj([("method", .string("POST")), ("headers", .object(headers)), ("body", .string(noticeJSON(notice)))]))
                base["status"] = res.status
                if res.ok { base["delivered"] = .bool(true) }
                else { base["delivered"] = .bool(false); base["reason"] = .string("webhook returned \(JS.toString(res.status))") }
            } catch {
                base["delivered"] = .bool(false)
                let m = (error as? JSError)?.message ?? ""
                base["reason"] = .string(m.isEmpty ? "webhook transport error" : m)
            }
            return .object(base)
        }
    }

    /// Email / SMS / push delivery through the per-instance sender port (fixed text only). `send` gets {subject, text}.
    public static func questionTextChannel(kind: String, siteName: JSONValue?, send: ((JSONValue) throws -> Void)? = nil) -> QuestionChannel {
        QuestionChannel(kind: kind, enabled: send != nil) { notice in
            var base: JObject = ["kind": .string(kind), "questionId": notice.get("question_id") ?? .null]
            do {
                let body = try questionText(notice, siteName: siteName)
                base["payload"] = body
                guard let send = send else {
                    base["delivered"] = .bool(false); base["reason"] = .string("\(kind) channel not configured")
                    return .object(base)
                }
                try send(body)
                base["delivered"] = .bool(true)
            } catch {
                base["delivered"] = .bool(false)
                let m = (error as? JSError)?.message ?? ""
                base["reason"] = .string(m.isEmpty ? "\(kind) send error" : m)
            }
            return .object(base)
        }
    }

    /// Fan a notice out to every enabled channel (disabled channels are skipped).
    public static func notifyAll(_ channels: [QuestionChannel], _ notice: JSONValue) -> [JSONValue] {
        channels.filter { $0.enabled }.map { $0.notify(notice) }
    }
}
