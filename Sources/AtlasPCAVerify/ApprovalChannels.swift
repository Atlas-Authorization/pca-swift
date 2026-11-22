import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Approval-notification channels for step-ups. `PCAApprovals` is the headless core; this is the channel layer: given a pending step-up request
/// (which carries its goal lineage and canonical render), each channel FORMATS a human-readable notification (action summary, the "because you
/// asked to ..." lineage, an approve / deny affordance or a link to the inbox) and DISPATCHES it over an injected transport. A channel that is
/// not configured reports `enabled == false` and never dispatches; a returned delivery never carries the webhook URL, token or signing secret;
/// nothing here logs. A channel only REPORTS a step-up the verifier already produced: it authorizes nothing.
public enum PCAApprovalChannels {
    /// The HTTP surface a channel needs, injected so channels stay offline-testable: POST `body`, answer the HTTP status. Throw on a transport failure.
    public typealias Transport = (_ url: String, _ headers: [String: String], _ body: String) throws -> Int
    /// Delivers a formatted text body (email, SMS, push); answers a channel-native message id (or nil), or throws.
    public typealias TextSender = (_ subject: String, _ text: String) throws -> String?

    /// A channel: `kind` is `slack`, `webhook`, `email`, `push` or `sms`; `notify` answers a delivery object.
    public protocol ApprovalChannel {
        var kind: String { get }
        /// True iff the channel is configured enough to deliver (the config gate).
        var enabled: Bool { get }
        /// Format the step-up for this channel and dispatch it. `ctx` is `{inboxUrl?, now?}`.
        func notify(_ request: JSONValue, _ ctx: JSONValue?) throws -> JSONValue
    }

    /// The default transport: a blocking POST over URLSession.
    public static let defaultTransport: Transport = { url, headers, body in
        guard let u = URL(string: url) else { throw JSError("invalid url") }
        var req = URLRequest(url: u)
        req.httpMethod = "POST"
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        req.httpBody = Data(body.utf8)
        final class Box: @unchecked Sendable { var status: Int?; var err: Error? }
        let box = Box(), sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { _, resp, err in box.status = (resp as? HTTPURLResponse)?.statusCode; box.err = err; sem.signal() }.resume()
        sem.wait()
        if let e = box.err { throw e }
        guard let s = box.status else { throw JSError("no http response") }
        return s
    }

    // ---- shared helpers ----

    /// An object whose members keep the written order (JS insertion order) when serialized.
    static func obj(_ pairs: [(String, JSONValue)]) -> JSONValue {
        var o = JObject()
        for (i, p) in pairs.enumerated() { o[JKey(p.0, ord: Int32(i + 1))] = p.1 }
        return .object(o)
    }

    private static func str(_ v: JSONValue?) -> String { JS.toString(v) }

    /// `Number.prototype.toFixed(2)` (exact decimal expansion, ties away from zero; printf rounds exact ties to even).
    static func toFixed2(_ r: Double) -> String {
        guard r.isFinite else { return JS.toString(.double(r)) }
        if abs(r) >= 1e21 { return JS.number(r) }
        let a = abs(r), scaled = a * 100
        let tie = scaled == scaled.rounded(.towardZero) + 0.5 && a * 8 == (a * 8).rounded() // a dyadic k/8 with an odd k: exactly representable tie
        let body = tie ? String(format: "%.2f", scaled.rounded(.up) / 100) : String(format: "%.2f", a)
        return (r < 0 && body != "0.00" ? "-" : "") + body
    }

    /// One-line action summary: `verb on resource (tier N, risk R)`.
    public static func actionSummary(_ request: JSONValue) -> String {
        let r = request.get("r").map { JS.toNumber($0) } ?? Double.nan
        return "\(str(request.get("verb"))) on \(str(request.get("resource"))) (tier \(str(request.get("tier"))), risk \(toFixed2(r)))"
    }

    /// The goal-lineage lines a human reads to understand WHY: the "because you asked to ..." sentence, the goal, authority and action chain,
    /// then the canonical render. Derived purely from the request.
    public static func lineageLines(_ request: JSONValue) throws -> [String] {
        guard let lin = request.get("lineage"), lin.isObject else { throw JSError("lineageLines: lineage required") }
        return [str(lin.get("because"))] + (try PCAApprovals.describeGoalLineage(lin)).map { str($0) } + (try renderLines(request))
    }

    private static func invisible(_ s: Unicode.Scalar) -> Bool {
        if s.value == 0x2028 || s.value == 0x2029 { return true }
        switch s.properties.generalCategory { case .control, .format: return true; default: return false }
    }

    /// The canonical render, one line per field (nothing omitted), the banner for an unreviewed action and the speakable binding words of H(R).
    /// Empty when the request carries no render. Every channel shows the same lines.
    public static func renderLines(_ request: JSONValue) throws -> [String] {
        guard let r = request.get("render"), let digest = request.get("renderDigest") else { return [] }
        guard r.isObject else { throw JSError("renderLines: render must be an object") }
        var out: [String] = []
        if r.get("unreviewed") == .bool(true) { out.append("UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.") }
        for f in try JS.spread(r.get("fields")) {
            var u = ""
            if let unit = f.get("unit"), unit.get("kind") == .string("money") { u = " \(str(unit.get("ccy"))) (minor units, exponent \(str(unit.get("exp"))))" }
            var shown = ""
            for s in JS.stringify(f.get("value") ?? .null).unicodeScalars { shown += invisible(s) ? "\\u{" + String(s.value, radix: 16) + "}" : String(s) }
            out.append("\(str(f.get("id"))) [\(str(f.get("class")))]: \(shown)\(u)")
        }
        guard let d = digest.asString, let words = Approval.bindingWords(d) else { throw JSError("renderLines: malformed render digest") }
        out.append("Match code: " + words)
        return out
    }

    /// Add query parameters before any `#fragment` (an approval link may carry its token in the fragment, which must stay last).
    static func appendQuery(_ url: String, _ params: [(String, String)]) -> String {
        let query = params.map { JS.encodeURIComponent($0.0) + "=" + JS.encodeURIComponent($0.1) }.joined(separator: "&")
        let u = Array(url.unicodeScalars)
        let hash = u.firstIndex(of: "#")
        let base = hash.map { String(String.UnicodeScalarView(u[..<$0])) } ?? url
        let fragment = hash.map { String(String.UnicodeScalarView(u[$0...])) } ?? ""
        return base + (base.contains("?") ? "&" : "?") + query + fragment
    }

    private static func inbox(_ ctx: JSONValue?) -> String? { ctx?.get("inboxUrl")?.asString.flatMap { $0.isEmpty ? nil : $0 } }

    private static func delivery(_ kind: String, _ request: JSONValue, _ delivered: Bool, _ payload: JSONValue, status: Int? = nil, reason: String? = nil) -> JSONValue {
        var p: [(String, JSONValue)] = [("kind", .string(kind)), ("requestId", request.get("id") ?? .null), ("delivered", .bool(delivered)), ("payload", payload)]
        if let s = status { p.append(("status", .int(Int64(s)))) }
        if let r = reason { p.append(("reason", .string(r))) }
        return obj(p)
    }

    private static func text(_ s: String) -> JSONValue { .string(s) }

    // ---- Slack (Block Kit over an incoming webhook) ----

    /// Build the Block Kit message for a step-up: action summary, goal lineage, approve / deny affordance.
    public static func buildSlackMessage(_ request: JSONValue, _ ctx: JSONValue? = nil) throws -> JSONValue {
        let id = str(request.get("id"))
        func button(_ label: String, _ url: String, _ style: String, _ action: String) -> JSONValue {
            obj([("type", text("button")), ("text", obj([("type", text("plain_text")), ("text", text(label)), ("emoji", .bool(true))])), ("url", text(url)),
                 ("style", text(style)), ("action_id", text(action))])
        }
        var blocks: [JSONValue] = [
            obj([("type", text("header")), ("text", obj([("type", text("plain_text")), ("text", text("Approval needed \u{B7} tier \(str(request.get("tier")))")), ("emoji", .bool(true))]))]),
            obj([("type", text("section")), ("text", obj([("type", text("mrkdwn")), ("text", text("*\(str(request.get("verb")))* on `\(str(request.get("resource")))`\n_\(str(request.get("reason")))_"))]))]),
            obj([("type", text("section")), ("text", obj([("type", text("mrkdwn")), ("text", text("*Why this is requested*\n" + (try lineageLines(request)).map { "\u{2022} \($0)" }.joined(separator: "\n")))]))]),
        ]
        if let url = inbox(ctx) {
            blocks.append(obj([("type", text("actions")), ("elements", .array([
                button("Approve", appendQuery(url, [("stepup", id), ("decision", "approve")]), "primary", "pca_approve"),
                button("Deny", appendQuery(url, [("stepup", id), ("decision", "deny")]), "danger", "pca_deny"),
            ]))]))
        } else {
            blocks.append(obj([("type", text("context")), ("elements", .array([obj([("type", text("mrkdwn")), ("text", text("Approve or deny step-up `\(id)` in your Atlas inbox."))])]))]))
        }
        return obj([("text", text("Approval needed: \(actionSummary(request))")), ("blocks", .array(blocks))])
    }

    private struct PostChannel: ApprovalChannel {
        let kind: String
        let url: String?
        let transport: Transport
        let extraHeaders: [String: String]
        let label: String
        let build: (JSONValue, JSONValue?) throws -> JSONValue
        var enabled: Bool { !(url ?? "").isEmpty }

        func notify(_ request: JSONValue, _ ctx: JSONValue?) throws -> JSONValue {
            let body = try build(request, ctx)
            guard enabled, let url = url else { return PCAApprovalChannels.delivery(kind, request, false, body, reason: "\(kind) channel not configured") }
            do {
                let headers = ["content-type": "application/json"].merging(extraHeaders) { _, new in new }
                let status = try transport(url, headers, JS.stringify(body))
                if (200...299).contains(status) { return PCAApprovalChannels.delivery(kind, request, true, body, status: status) }
                return PCAApprovalChannels.delivery(kind, request, false, body, status: status, reason: "\(label) returned \(status)")
            } catch {
                let m = (error as? JSError)?.message ?? "\(error)"
                return PCAApprovalChannels.delivery(kind, request, false, body, reason: m)
            }
        }
    }

    /// Slack approval channel. Disabled (and a no-op) unless a webhook URL is configured.
    public static func slackApprovalChannel(webhookUrl: String? = nil, transport: Transport? = nil) -> ApprovalChannel {
        PostChannel(kind: "slack", url: webhookUrl, transport: transport ?? defaultTransport, extraHeaders: [:], label: "slack webhook") { try buildSlackMessage($0, $1) }
    }

    // ---- webhook (JSON POST) ----

    /// The webhook body: the step-up plus its pre-formatted human summary and lineage.
    public static func buildWebhookBody(_ request: JSONValue, _ ctx: JSONValue? = nil) throws -> JSONValue {
        var p: [(String, JSONValue)] = [("type", text("pca.step_up.created")), ("stepup", request), ("summary", text(actionSummary(request))),
                                         ("lineage", .array(try lineageLines(request).map { text($0) }))]
        if let u = inbox(ctx) { p.append(("inbox_url", text(u))) }
        return obj(p)
    }

    /// Generic webhook approval channel: a JSON POST with optional extra headers (for example a caller-computed signature header). Disabled without a URL.
    public static func webhookApprovalChannel(url: String? = nil, transport: Transport? = nil, headers: [String: String] = [:]) -> ApprovalChannel {
        PostChannel(kind: "webhook", url: url, transport: transport ?? defaultTransport, extraHeaders: headers, label: "webhook") { try buildWebhookBody($0, $1) }
    }

    // ---- text channels (email / sms / push) ----

    /// The plain-text body `{subject, text}` shared by the email, SMS and push surfaces.
    public static func buildTextBody(_ request: JSONValue, _ ctx: JSONValue? = nil) throws -> JSONValue {
        var lines = [actionSummary(request), ""] + (try lineageLines(request))
        if let u = inbox(ctx) { lines += ["", "Approve or deny: " + appendQuery(u, [("stepup", str(request.get("id")))])] }
        return obj([("subject", text("Approval needed: \(str(request.get("verb"))) on \(str(request.get("resource")))")), ("text", text(lines.joined(separator: "\n")))])
    }

    private struct TextChannel: ApprovalChannel {
        let kind: String
        let send: TextSender?
        var enabled: Bool { send != nil }

        func notify(_ request: JSONValue, _ ctx: JSONValue?) throws -> JSONValue {
            let body = try PCAApprovalChannels.buildTextBody(request, ctx)
            guard let send = send else { return PCAApprovalChannels.delivery(kind, request, false, body, reason: "\(kind) channel not configured") }
            do {
                _ = try send(body.get("subject")?.asString ?? "", body.get("text")?.asString ?? "")
                return PCAApprovalChannels.delivery(kind, request, true, body)
            } catch {
                let m = (error as? JSError)?.message ?? "\(error)"
                return PCAApprovalChannels.delivery(kind, request, false, body, reason: m)
            }
        }
    }

    /// A text-formatter channel (`kind` is `email`, `sms` or `push`) over an injected sender. Disabled without one.
    public static func textApprovalChannel(_ kind: String, send: TextSender? = nil) throws -> ApprovalChannel {
        guard kind == "email" || kind == "sms" || kind == "push" else { throw JSError("textApprovalChannel: kind must be email, sms or push") }
        return TextChannel(kind: kind, send: send)
    }

    // ---- dispatcher ----

    /// Fans a step-up out to every ENABLED channel.
    public struct ApprovalDispatcher {
        public let channels: [ApprovalChannel]
        /// One delivery per enabled channel (a disabled channel is skipped).
        public func notifyAll(_ request: JSONValue, _ ctx: JSONValue? = nil) throws -> [JSONValue] {
            try channels.filter { $0.enabled }.map { try $0.notify(request, ctx) }
        }
    }

    /// Register a set of channels behind one dispatcher. Disabled channels are skipped at `notifyAll`.
    public static func createApprovalDispatcher(_ channels: [ApprovalChannel]) -> ApprovalDispatcher { ApprovalDispatcher(channels: channels) }
}
