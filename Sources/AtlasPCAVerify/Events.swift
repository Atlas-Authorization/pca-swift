import Foundation
import CryptoKit

/// Step-up lifecycle events and signed webhooks: content-addressed events (the id is the digest of the fields, so an edited
/// event is refused on parse), the `PCA-Signature: t=<unix s>,v1=<hex HMAC-SHA256 of "t.payload">` header (secret >= 16 bytes,
/// several v1 values for key rotation, constant-time compare), and a delivery check that also consumes the event id once.
public enum PCAEvents {
    public static let EVENT_TYPES = ["step_up.created", "step_up.approved", "step_up.denied", "step_up.expired"]
    public static let MIN_SECRET_BYTES = 16
    static let MAX_HEADER_CHARS = 2048
    static let ORDER = ["type", "at", "grant_ref", "action", "verb", "resource", "tier", "actor", "id"]

    /// A webhook secret: its UTF-8 bytes or raw bytes.
    public enum Secret {
        case text(String)
        case bytes([UInt8])
        var key: [UInt8]? {
            let b: [UInt8]
            switch self { case let .text(s): b = Array(s.utf8); case let .bytes(x): b = x }
            return b.count >= MIN_SECRET_BYTES ? b : nil
        }
    }

    static func eventId(_ e: JObject) throws -> String {
        guard let action = e["action"]?.asObject else { throw JSError("canonicalize: unsupported type undefined") }
        var body: JObject = ["d": .string("atlas-pca/stepup-event/v1"), "action": .object(["verb": action["verb"] ?? .null, "resource": action["resource"] ?? .null])]
        for k in ["type", "at", "grant_ref", "tier"] {
            guard let v = e[JKey(k)] else { throw JSError("canonicalize: unsupported type undefined") }
            body[JKey(k)] = v
        }
        if action["verb"] == nil || action["resource"] == nil { throw JSError("canonicalize: unsupported type undefined") }
        if let a = e["actor"] { body["actor"] = a }
        guard let h = IV.strictHash(.object(body)) else { throw JSError("canonicalize: \(IV.strictCanonError(.object(body)) ?? "out of profile")") }
        return h
    }

    /// The fields every event carries, checked at build and serialize time (the reference's `checkEventFields`): fail closed on anything else.
    static func checkEventFields(_ who: String, _ e: JSONValue?, type: JSONValue? = nil, withId: Bool) throws {
        func bad(_ m: String) -> JSError { JSError("\(who): \(m)") }
        func wf(_ v: JSONValue?) -> Bool { if case let .string(s)? = v { return !Canonical.hasLoneSurrogate(s) }; return false }
        guard let o = e?.asObject else { throw bad("not an object") }
        let ty = type ?? o["type"]
        guard let t = ty?.asString, EVENT_TYPES.contains(t), let tier = o["tier"], tier.isNumber, let tn = IV.num(tier), tn == 2 || tn == 3 else { throw bad("unknown event type or tier") }
        if let at = o["at"], !(at.isNumber && (IV.num(at)?.isFinite ?? false)) { throw bad("at must be a finite number") }
        guard wf(o["grant_ref"]) else { throw bad("grant_ref must be a well-formed string") }
        guard let a = o["action"], a.isObject, wf(a.get("verb")), wf(a.get("resource")) else { throw bad("action must carry well-formed verb and resource strings") }
        if let actor = o["actor"], !wf(actor) { throw bad("actor must be a well-formed string") }
        if withId && !wf(o["id"]) { throw bad("id must be a well-formed string") }
    }

    /// The event with its content-address id. `data` = {at?, grant_ref, action: {verb, resource}, tier, actor?}; `at` defaults
    /// to now (ms). Throws where the reference does (a missing member, a value outside the canonical profile).
    public static func buildStepUpEvent(_ type: JSONValue, _ data: JSONValue?) throws -> JSONValue {
        guard let d = data?.asObject else { throw JSError("buildStepUpEvent: data must be an object") }
        try checkEventFields("buildStepUpEvent", .object(d), type: type, withId: false)
        guard let action = d["action"]?.asObject else { throw JSError("buildStepUpEvent: action must be an object") }
        var base: JObject = [
            "type": type,
            "at": JS.present(d["at"]) ?? .int(Int64(nowMs().rounded(.down))),
            "action": .object(action.filter { $0.key == "verb" || $0.key == "resource" }),
        ]
        if let g = d["grant_ref"] { base["grant_ref"] = g }
        if let t = d["tier"] { base["tier"] = t }
        if let a = d["actor"] { base["actor"] = a }
        base["id"] = .string(try eventId(base))
        return .object(base)
    }

    /// JSON.stringify of an event, in the builder's member order.
    public static func serializeEvent(_ e: JSONValue) throws -> String {
        try checkEventFields("serializeEvent", e, withId: true)
        guard let at = e.get("at"), at.isNumber, IV.num(at)?.isFinite ?? false else { throw JSError("serializeEvent: at must be a finite number") }
        return JS.stringify(e, order: ORDER)
    }

    /// Parse and check an event; throws (with the reference's message) on anything malformed or an id that is not the digest of
    /// the fields. Duplicate members are refused (the reference's JSON.parse keeps the last one).
    public static func parseEvent(_ text: JSONValue?) throws -> JSONValue {
        guard let s = text?.asString else { throw JSError("json: not a string") }
        let raw: JSONValue
        do { raw = IV.normalized(try StrictJSON.parseLenient(s)) } catch {
            // the reference parses a lone surrogate and then fails to canonicalize it
            if "\(error)".contains("lone surrogate") { throw JSError("canonicalize: lone surrogate in string") }
            throw JSError("json: \(error)")
        }
        // typeof [] === 'object': an array is an object with no members (its first refusal is the missing id)
        guard raw.isObject || raw.asArray != nil else { throw JSError("parseEvent: not an object") }
        let o = raw.asObject ?? [:]
        guard let id = JS.nonEmptyString(o["id"]) else { throw JSError("parseEvent: bad id") }
        guard let type = o["type"]?.asString, EVENT_TYPES.contains(type) else { throw JSError("parseEvent: bad type") }
        guard let at = o["at"], let atv = IV.num(at), atv.isFinite else { throw JSError("parseEvent: bad at") }
        guard let grant = o["grant_ref"]?.asString else { throw JSError("parseEvent: bad grant_ref") }
        guard let action = o["action"], action.isObject || action.isArray else { throw JSError("parseEvent: bad action") }
        guard let verb = action.get("verb")?.asString, let resource = action.get("resource")?.asString else { throw JSError("parseEvent: bad action fields") }
        let tierNum = IV.num(o["tier"])
        guard let tn = tierNum, (tn == 2 || tn == 3), !IV.isNegZero(tn) else { throw JSError("parseEvent: bad tier") }
        let actor = o["actor"]
        if let a = actor, a.asString == nil { throw JSError("parseEvent: bad actor") }
        var ev: JObject = ["id": .string(id), "type": .string(type), "at": at, "grant_ref": .string(grant),
                           "action": .object(["verb": .string(verb), "resource": .string(resource)]), "tier": .int(Int64(tn))]
        if let a = actor { ev["actor"] = a }
        if try eventId(ev) != id { throw JSError("parseEvent: id does not match the event content") }
        return .object(ev)
    }

    static func hmac(_ key: [UInt8], _ message: String) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: Data(message.utf8), using: SymmetricKey(data: key)))
    }

    static func hexBytes(_ s: String) -> [UInt8]? {
        let b = Array(s.utf8)
        if b.count % 2 != 0 { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(b.count / 2)
        var i = 0
        while i < b.count {
            guard let h = WhatwgURL.hexVal(b[i]), let l = WhatwgURL.hexVal(b[i + 1]) else { return nil }
            out.append(h << 4 | l); i += 2
        }
        return out
    }

    static func timingSafeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return false }
        var diff: UInt8 = 0
        for i in a.indices { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    static func parseSignatureHeader(_ h: JSONValue?) -> (t: Double, v1: [String])? {
        guard let s = h?.asString, JS.length(s) <= MAX_HEADER_CHARS else { return nil }
        var t: Double? = nil
        var v1: [String] = []
        for part in s.split(separator: ",", omittingEmptySubsequences: false) {
            guard let eq = part.firstIndex(of: "=") else { continue }
            let key = Attest.jsTrim(String(part[..<eq])), val = Attest.jsTrim(String(part[part.index(after: eq)...]))
            if key == "t" {
                let d = Array(val.utf8)
                guard !d.isEmpty, d.count <= 15, d.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) else { return nil }
                let n = Double(val)!
                if let prev = t, prev != n { return nil }
                t = n
            } else if key == "v1" {
                v1.append(val)
            }
        }
        guard let tt = t, !v1.isEmpty else { return nil }
        return (tt, v1)
    }

    /// Test seam: the clock every default `now` reads, in epoch ms (a replay of a corpus made under a frozen clock sets it for the cases that depend on it).
    nonisolated(unsafe) static var clockOverrideMs: Double?
    static func nowMs() -> Double { clockOverrideMs ?? Date().timeIntervalSince1970 * 1000 }
    static func nowSec() -> Double { (nowMs() / 1000).rounded(.down) }

    /// `t=<timestamp>,v1=<hex>`; `timestamp` defaults to now (unix seconds) and must be a non-negative safe integer.
    public static func signWebhook(_ secret: Secret, _ payload: String, timestamp: JSONValue? = nil) throws -> String {
        guard let key = secret.key else { throw JSError("signWebhook: the secret must be at least \(MIN_SECRET_BYTES) bytes") }
        let tv = JS.present(timestamp) ?? .double(nowSec())
        guard let t = tv.safeInt, t >= 0 else { throw JSError("signWebhook: timestamp must be a non-negative integer (unix seconds)") }
        return "t=\(t),v1=\(ACrypto.hex(hmac(key, "\(t).\(payload)")))"
    }

    /// True iff one of the header's v1 values is the HMAC of "t.payload" and |now - t| <= toleranceSec (default 300 s).
    public static func verifyWebhook(_ secret: Secret?, _ payload: String, _ header: JSONValue?, toleranceSec: JSONValue? = nil, now: JSONValue? = nil) -> Bool {
        guard let key = secret?.key, let parsed = parseSignatureHeader(header) else { return false }
        let tolV = JS.present(toleranceSec) ?? .int(300)
        let nowV = JS.present(now) ?? .double(nowSec())
        guard let tol = IV.num(tolV), tol.isFinite, tol >= 0, let n = IV.num(nowV), n.isFinite else { return false }
        if abs(n - parsed.t) > tol { return false }
        let expected = hmac(key, "\(JS.number(parsed.t)).\(payload)")
        var match = false
        for v in parsed.v1 {
            guard let provided = hexBytes(v) else { continue }
            if timingSafeEqual(expected, provided) { match = true } // no early exit
        }
        return match
    }

    /// The replay key of an event id (replayKey('pca-stepup-event/v1', id)).
    static func replayKey(_ namespace: String, _ parts: [String]) -> String {
        var buf: [UInt8] = []
        for p in [namespace] + parts {
            let b = Array(p.utf8)
            let n = UInt32(b.count)
            buf += [UInt8(n >> 24), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] + b
        }
        return namespace + ":" + Base64URLStrict.encode(Canonical.sha256(buf))
    }

    /// verifyDelivery: signature, event, and the event id consumed once in `replay` (required) until the header's t + tolerance.
    /// Returns {ok: true, event} or {ok: false, reason}.
    public static func verifyDelivery(_ secret: Secret?, _ payload: String, _ header: JSONValue?, replay: PCAStateStore?,
                                      toleranceSec: JSONValue? = nil, now: JSONValue? = nil) -> JSONValue {
        func no(_ r: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(r)]) }
        guard let store = replay else { return no("a replay store is required") }
        if !verifyWebhook(secret, payload, header, toleranceSec: toleranceSec, now: now) { return no("bad signature") }
        let event: JSONValue
        do { event = try parseEvent(.string(payload)) } catch { return no((error as? JSError)?.message ?? "\(error)") }
        let sig = parseSignatureHeader(header)!
        let nowS = IV.num(JS.present(now)) ?? nowSec()
        let tol = IV.num(JS.present(toleranceSec)) ?? 300
        let retain = ((sig.t + tol) * 1000 + 1).rounded(.up), nowMs = (nowS * 1000).rounded(.down)
        guard retain < 9.0e18, nowMs > -9.0e18, nowMs < 9.0e18 else { return no("replay store unavailable") }
        do {
            let first = try store.consumeOnce(key: replayKey("pca-stepup-event/v1", [event.get("id")!.asString!]), retainUntil: Int64(retain), now: Int64(nowMs))
            if !first { return no("replayed delivery") }
        } catch {
            return no("replay store unavailable")
        }
        return .object(["ok": .bool(true), "event": event])
    }

    public static func webhookHeaders(_ secret: Secret, _ payload: String, timestamp: JSONValue? = nil) throws -> JSONValue {
        .object(["PCA-Signature": .string(try signWebhook(secret, payload, timestamp: timestamp)), "content-type": .string("application/json")])
    }
}
