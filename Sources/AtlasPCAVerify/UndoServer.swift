import Foundation

// The server-side helpers around the undo ledger: the veto relay over a hosted ledger, the notifier over the approval channels, the completeness check of a
// coordinator's configuration and the effect-reporting shim.
public enum PCAUndoServer {
    /// With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands).
    public static let UNDO_RELAY_GRACE_MS: Int64 = 60_000

    /// The undo service key's public half, for verifying tokens and receipts elsewhere (the hosted veto route).
    public static func undoSignerPublic(secret: [UInt8]) throws -> String { try PCAEdKey(seed: secret).id }

    /// The required components a coordinator configuration lacks (empty = complete): `store`, `engine`, `signerSecret` (32 bytes), `audience`,
    /// `resolveGrant`, `compensate`, `operations`, `notifier`, `alert`.
    public static func missingUndoComponents(store: UndoStore?, hasEngine: Bool, signerSecret: [UInt8]?, audience: String?, hasResolveGrant: Bool, hasCompensate: Bool,
                                             hasOperations: Bool, hasNotifier: Bool, hasAlert: Bool) -> [String] {
        var m: [String] = []
        if store == nil { m.append("store") }
        if !hasEngine { m.append("engine") }
        if signerSecret?.count != 32 { m.append("signerSecret") }
        if (audience ?? "").isEmpty { m.append("audience") }
        if !hasResolveGrant { m.append("resolveGrant") }
        if !hasCompensate { m.append("compensate") }
        if !hasOperations { m.append("operations") }
        if !hasNotifier { m.append("notifier") }
        if !hasAlert { m.append("alert") }
        return m
    }

    /// What `reportUndoEffect` needs of a coordinator.
    public protocol EffectSink {
        func recordEffect(_ id: String, result: JSONValue?) throws -> JSONValue
        func abort(_ id: String, reason: String) throws -> JSONValue
        func get(_ id: String) throws -> JSONValue?
    }

    /// Report how the operation behind an open window ended: `committed` records the effect, `failed` / `aborted` / `refused` abort the window, anything
    /// else (pending, uncertain) leaves it running (`finalizeDue` alerts if it closes without a report).
    public static func reportUndoEffect(_ undo: EffectSink, id: String, status: String, result: JSONValue? = nil) throws -> JSONValue {
        if status == "committed" { return try undo.recordEffect(id, result: result) }
        if status == "failed" || status == "aborted" || status == "refused" { return try undo.abort(id, reason: "effect_\(status)") }
        guard let r = try undo.get(id) else { throw UndoError("invalid", "no undo record \(id)") }
        return r
    }

    private static func iso(_ ms: Int64) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: Date(timeIntervalSince1970: Double(ms) / 1000))
    }

    /// An undo notifier over the approval channels (Slack, webhook, email, SMS, push). The notice `{kind, record, token?, render?}` becomes a step-up shaped
    /// message whose link is the one-click undo URL and whose render is the WYSIWYS render of the action. Answers `{delivered, reason?}`.
    public static func undoNotifierFromDispatcher(_ dispatcher: PCAApprovalChannels.ApprovalDispatcher, undoUrl: @escaping (_ token: String, _ id: String) -> String,
                                                  inboxUrl: String? = nil) -> (_ notice: JSONValue) -> JSONValue {
        return { n in
            let r = n.get("record") ?? .null
            let verb = JS.toString(r.get("action")?.get("verb")), resource = JS.toString(r.get("action")?.get("resource"))
            let until = iso(r.get("window_end")?.safeInt ?? 0)
            let kind = n.get("kind")?.asString ?? ""
            let reason: String
            switch kind {
            case "opened": reason = "Already done: \(verb) on \(resource). You can undo it until \(until)."
            case "vetoed": reason = "Undo started for \(verb) on \(resource)."
            case "compensated": reason = "Undone: \(verb) on \(resource)."
            case "compensation_failed": reason = "UNDO FAILED for \(verb) on \(resource): \(r.get("outcome")?.get("reason").map { JS.toString($0) } ?? "unknown"). An operator has been alerted."
            case "revoked": reason = "The agent's grant was revoked. \(verb) on \(resource) can still be undone until \(until)."
            default: reason = "Final: \(verb) on \(resource) can no longer be undone."
            }
            let id = JS.toString(r.get("id"))
            var req: [(String, JSONValue)] = [
                ("id", .string("undo:\(id):\(kind)")), ("verb", .string(verb)), ("resource", .string(resource)), ("tier", .int(3)), ("reason", .string(reason)), ("goalCommit", .string("")),
                ("lineage", PCAApprovalChannels.obj([("goalCommit", .string("")), ("goalVerified", .bool(false)),
                                                     ("chain", .array([PCAApprovalChannels.obj([("kind", .string("action")), ("label", .string("\(verb) \(resource)")),
                                                                                                 ("detail", .string("undo: \(JS.toString(r.get("compensation")?.get("verb")))"))])])),
                                                     ("because", .string(reason))])),
                ("r", .int(0)), ("requestedAt", r.get("opened_at") ?? .null),
            ]
            if let render = n.get("render"), let d = r.get("render_digest") { req.append(("render", render)); req.append(("renderDigest", d)) }
            let link: String? = kind == "opened" && n.get("token")?.asString != nil ? undoUrl(n.get("token")!.asString!, id) : inboxUrl
            do {
                let out = try dispatcher.notifyAll(PCAApprovalChannels.obj(req), link.map { .object(["inboxUrl": .string($0)]) })
                if out.contains(where: { $0.get("delivered") == .bool(true) }) { return .object(["delivered": .bool(true)]) }
                let why = out.map { "\(JS.toString($0.get("kind"))): \($0.get("reason").map { JS.toString($0) } ?? "not delivered")" }.joined(separator: "; ")
                return .object(["delivered": .bool(false), "reason": .string(why.isEmpty ? "no enabled channel" : why)])
            } catch {
                return .object(["delivered": .bool(false), "reason": .string("\(error)")])
            }
        }
    }

    /// A veto the principal made at a hosted relay: `{id, token, at}`.
    public struct RelayedVeto: Equatable {
        public let id: String
        public let token: String
        public let at: Int64
    }

    /// The transport of `hostedUndoVetoRelay`: GET `url` with `headers`; answers the status and the parsed JSON body.
    public typealias RelayFetch = (_ url: String, _ headers: [String: String]) throws -> (status: Int, json: JSONValue?)

    /// The relay over a hosted undo ledger: `GET {baseUrl}/v1/pca/undo/vetoes` with the instance secret key. A non-2xx answer or a malformed body throws (and so
    /// finalizes nothing).
    public static func hostedUndoVetoRelay(baseUrl: String, secretKey: String, limit: Int = 200, fetch: @escaping RelayFetch) -> () throws -> [RelayedVeto] {
        var base = baseUrl
        while base.hasSuffix("/") { base.removeLast() }
        return {
            let url = "\(base)/v1/pca/undo/vetoes?limit=\(Swift.min(200, Swift.max(1, limit)))"
            let res = try fetch(url, ["authorization": "Bearer \(secretKey)", "accept": "application/json"])
            guard (200...299).contains(res.status) else { throw UndoError("invalid", "the veto relay answered \(res.status)") }
            guard let data = res.json?.get("data")?.asArray else { throw UndoError("invalid", "the veto relay answered without a data list") }
            return try data.map { row in
                guard let id = row.get("record_id")?.asString, let tok = row.get("veto")?.get("token")?.asString, let at = row.get("veto")?.get("at"), at.isNumber else {
                    throw UndoError("invalid", "the veto relay answered a malformed entry")
                }
                return RelayedVeto(id: id, token: tok, at: at.safeInt ?? Int64(IV.num(at) ?? 0))
            }
        }
    }
}
