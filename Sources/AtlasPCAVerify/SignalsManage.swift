import Foundation

/// The SSF management API (OpenID SSF 1.0 §8.1): the transmitter configuration document and stream create / read / update /
/// replace / delete, status, subjects and verification, for the receiver `authenticate` names (the manage half of `PCASignals`).
extension PCASignals {
    /// Where stream records live. A record is a JSON object `{receiver, config, events_requested?, status, status_reason?,
    /// subjects, lastVerification?}`; the store keeps its own copy.
    public protocol StreamStore: AnyObject {
        func get(_ id: String) -> JSONValue?
        func put(_ id: String, _ record: JSONValue)
        func delete(_ id: String)
        func listByReceiver(_ receiver: JSONValue) -> [(id: String, record: JSONValue)]
    }

    /// An insertion-ordered in-memory `StreamStore`.
    public final class MemoryStreamStore: StreamStore {
        var m: [(id: String, record: JSONValue)] = []
        public init() {}
        public func get(_ id: String) -> JSONValue? { m.first { JKey($0.id) == JKey(id) }?.record }
        public func put(_ id: String, _ record: JSONValue) {
            if let i = m.firstIndex(where: { JKey($0.id) == JKey(id) }) { m[i].record = record } else { m.append((id, record)) }
        }
        public func delete(_ id: String) { m.removeAll { JKey($0.id) == JKey(id) } }
        public func listByReceiver(_ receiver: JSONValue) -> [(id: String, record: JSONValue)] {
            m.filter { PCARevoke.member($0.record, "receiver") == receiver }
        }
    }

    /// A fresh 12-byte base64url stream id (the default `newId`).
    public static func randomStreamId() -> String { Base64URLStrict.encode((0..<12).map { _ in UInt8.random(in: 0...255) }) }

    /// Options of the SSF management handler.
    public struct SsfManageOptions {
        public var store: StreamStore
        public var issuer: String
        public var eventsSupported: [String]
        /// Default: push and poll.
        public var deliveryMethods: [String]? = nil
        public var pollEndpoint: (String) -> String
        public var signingKey: PCAEdKey
        /// Hands a verification SET to the stream's delivery; an error is a 500.
        public var deliver: (JSONValue, String) throws -> Void
        /// Default 1.
        public var maxStreamsPerReceiver: Double? = nil
        /// Default 10000.
        public var maxSubjectsPerStream: Double? = nil
        public var now: () -> Double
        public var newId: () -> String

        public init(store: StreamStore, issuer: String, eventsSupported: [String], deliveryMethods: [String]? = nil, pollEndpoint: @escaping (String) -> String,
                    signingKey: PCAEdKey, deliver: @escaping (JSONValue, String) throws -> Void, maxStreamsPerReceiver: Double? = nil,
                    maxSubjectsPerStream: Double? = nil, now: @escaping () -> Double, newId: @escaping () -> String = PCASignals.randomStreamId) {
            self.store = store; self.issuer = issuer; self.eventsSupported = eventsSupported; self.deliveryMethods = deliveryMethods
            self.pollEndpoint = pollEndpoint; self.signingKey = signingKey; self.deliver = deliver; self.maxStreamsPerReceiver = maxStreamsPerReceiver
            self.maxSubjectsPerStream = maxSubjectsPerStream; self.now = now; self.newId = newId
        }
    }

    /// `transmitterMetadata`: the SSF transmitter configuration document.
    public static func transmitterMetadata(issuer: String, deliveryMethods: [String]?, base: String, jwksUri: String?) -> JSONValue {
        var m: JObject = ["spec_version": .string("1_0"), "issuer": .string(issuer)]
        if let j = jwksUri, !j.isEmpty { m["jwks_uri"] = .string(j) }
        m["delivery_methods_supported"] = .array((deliveryMethods ?? [DELIVERY_PUSH, DELIVERY_POLL]).map { .string($0) })
        for (k, p) in [("configuration_endpoint", "configuration"), ("status_endpoint", "status"), ("add_subject_endpoint", "add_subject"),
                       ("remove_subject_endpoint", "remove_subject"), ("verification_endpoint", "verification")] {
            m[JKey(k)] = .string("\(base)/ssf/\(p)")
        }
        m["default_subjects"] = .string("NONE")
        return .object(m)
    }

    private static func resp(_ status: Int64, _ body: JSONValue) -> JSONValue { .object(["status": .int(status), "body": body]) }
    private static func bad(_ m: String) -> JSONValue { resp(400, .object(["error": .string("invalid_request"), "description": .string(m)])) }
    private static func notFound() -> JSONValue { resp(404, .object(["error": .string("not_found")])) }
    private static func methodNotAllowed() -> JSONValue { resp(405, .object(["error": .string("method_not_allowed")])) }

    private struct Why: Error { let m: String }

    private static func eventsRequestedOk(_ v: JSONValue?) -> [String]? {
        guard let a = v?.asArray, !a.isEmpty else { return nil }
        var out: [String] = []
        for e in a { guard let s = nonEmptyStr(e) else { return nil }; out.append(s) }
        return out
    }

    private static func subjectKey(_ s: JSONValue?) -> String? {
        guard let m = s?.asObject, !(m["format"]?.asString ?? "").isEmpty else { return nil }
        return JS.stringify(.object(m))
    }

    private static func delivered(_ o: SsfManageOptions, _ requested: [String]?) -> [String] {
        guard let r = requested else { return o.eventsSupported }
        return o.eventsSupported.filter { r.contains($0) }
    }

    private static func deliveryFor(_ o: SsfManageOptions, _ id: String, _ d: JSONValue?) throws -> JSONValue {
        let methods = o.deliveryMethods ?? [DELIVERY_PUSH, DELIVERY_POLL]
        func poll() -> JSONValue { .object(["method": .string(DELIVERY_POLL), "endpoint_url": .string(o.pollEndpoint(id))]) }
        guard let d = d else {
            if !methods.contains(DELIVERY_POLL) { throw Why(m: "delivery is required: this transmitter does not support poll") }
            return poll()
        }
        guard let method = PCARevoke.member(d, "method")?.asString, methods.contains(method) else { throw Why(m: "delivery.method is not supported by this transmitter") }
        if method == DELIVERY_POLL { return poll() }
        guard let u = PCARevoke.member(d, "endpoint_url")?.asString, httpsUrlOk(u) else { throw Why(m: "push delivery needs an https endpoint_url") }
        return .object(["method": .string(DELIVERY_PUSH), "endpoint_url": .string(u)])
    }

    private static func buildConfig(_ o: SsfManageOptions, _ id: String, _ rcv: JSONValue, _ requested: [String]?, _ delivery: JSONValue, _ description: String?) -> JObject {
        var c: JObject = ["stream_id": .string(id), "iss": .string(o.issuer)]
        if let a = PCARevoke.member(rcv, "aud") { c["aud"] = a }
        c["events_supported"] = .array(o.eventsSupported.map { .string($0) })
        c["events_delivered"] = .array(delivered(o, requested).map { .string($0) })
        c["delivery"] = delivery
        if let d = description { c["description"] = .string(String(decoding: Array(d.utf16.prefix(256)), as: UTF16.self)) }
        return c
    }

    private static func own(_ o: SsfManageOptions, _ rcv: JSONValue, _ id: JSONValue?) -> JSONValue? {
        guard let s = id?.asString, let r = o.store.get(s) else { return nil }
        return PCARevoke.member(r, "receiver") == PCARevoke.member(rcv, "id") ? r : nil
    }

    private static func statusBody(_ id: String, _ s: JSONValue) -> JSONValue {
        var m: JObject = ["stream_id": .string(id), "status": PCARevoke.member(s, "status") ?? .null]
        if let r = PCARevoke.member(s, "status_reason") { m["reason"] = r }
        return .object(m)
    }

    private static func with(_ s: JSONValue, _ f: (inout JObject) -> Void) -> JSONValue {
        var m = s.asObject ?? [:]
        f(&m)
        return .object(m)
    }

    private static func route(_ o: SsfManageOptions, _ req: JSONValue?, _ rcv: JSONValue) throws -> JSONValue {
        func ty(_ m: String) -> JSError { JSError("Cannot read properties of undefined (reading '\(m)')") }
        guard let path = PCARevoke.member(req, "path")?.asString else { throw ty("split") }
        let seg = path.split(separator: "/", omittingEmptySubsequences: true).last.map(String.init) ?? ""
        let query = PCARevoke.member(req, "query")
        let qid = PCARevoke.member(query, "stream_id")
        let b = PCARevoke.member(req, "body").flatMap { $0.isObject ? $0 : nil }
        guard let method = PCARevoke.member(req, "method")?.asString else { throw ty("toUpperCase") }
        let m = method.uppercased()
        if !["configuration", "status", "add_subject", "remove_subject", "verification"].contains(seg) { return notFound() }
        let rid = PCARevoke.member(rcv, "id") ?? .null
        let receiverSupplied = ["events_requested", "delivery", "description"]
        let transmitterSupplied = ["stream_id", "iss", "aud", "events_supported", "events_delivered", "min_verification_interval"]

        if seg == "configuration" {
            if m == "POST" {
                guard let b = b else { return bad("a JSON object body is required") }
                for k in (b.asObject ?? [:]).keys.sorted() where !receiverSupplied.contains(k.s) { return bad("'\(k.s)' is not a receiver-supplied member") }
                var requested: [String]? = nil
                if let v = PCARevoke.member(b, "events_requested") {
                    guard let r = eventsRequestedOk(v) else { return bad("events_requested must be a non-empty array of event type URIs") }
                    requested = r
                }
                if let d = PCARevoke.member(b, "description"), d.asString == nil { return bad("description must be a string") }
                if Double(o.store.listByReceiver(rid).count) >= (o.maxStreamsPerReceiver ?? 1) {
                    return resp(409, .object(["error": .string("conflict"), "description": .string("this receiver already has the maximum number of streams")]))
                }
                let id = o.newId()
                let delivery: JSONValue
                do { delivery = try deliveryFor(o, id, PCARevoke.member(b, "delivery")) } catch let w as Why { return bad(w.m) }
                if delivered(o, requested).isEmpty { return bad("none of events_requested is supported by this transmitter") }
                let config = JSONValue.object(buildConfig(o, id, rcv, requested, delivery, PCARevoke.member(b, "description")?.asString))
                let problems = validateStreamConfig(config)
                if !problems.isEmpty { return bad(problems.joined(separator: "; ")) }
                var rec: JObject = ["receiver": rid, "config": config]
                if let r = requested { rec["events_requested"] = .array(r.map { .string($0) }) }
                rec["status"] = .string("enabled")
                rec["subjects"] = .object([:])
                o.store.put(id, .object(rec))
                return resp(201, config)
            }
            if m == "GET" {
                if qid == nil { return resp(200, .array(o.store.listByReceiver(rid).map { PCARevoke.member($0.record, "config") ?? .null })) }
                if let s = own(o, rcv, qid) { return resp(200, PCARevoke.member(s, "config") ?? .null) }
                return notFound()
            }
            if m == "PATCH" || m == "PUT" {
                guard let b = b else { return bad("a JSON object body is required") }
                let found = own(o, rcv, PCARevoke.member(b, "stream_id"))
                guard let sid = PCARevoke.member(b, "stream_id")?.asString else { return bad("stream_id is required") }
                guard var s = found else { return notFound() }
                for k in (b.asObject ?? [:]).keys.sorted() where !receiverSupplied.contains(k.s) && !transmitterSupplied.contains(k.s) { return bad("unknown member '\(k.s)'") }
                let config = PCARevoke.member(s, "config") ?? .null
                for k in transmitterSupplied {
                    guard let v = PCARevoke.member(b, k) else { continue }
                    let same = PCARevoke.member(config, k).map { JS.stringify(v) == JS.stringify($0) } ?? false
                    if !same { return bad("'\(k)' is transmitter-supplied and does not match") }
                }
                if let v = PCARevoke.member(b, "events_requested"), eventsRequestedOk(v) == nil { return bad("events_requested must be a non-empty array of event type URIs") }
                if let d = PCARevoke.member(b, "description"), d.asString == nil { return bad("description must be a string") }
                var delivery = PCARevoke.member(config, "delivery") ?? .null
                if PCARevoke.member(b, "delivery") != nil || m == "PUT" {
                    let d: JSONValue
                    do { d = try deliveryFor(o, sid, PCARevoke.member(b, "delivery")) } catch let w as Why { return bad(w.m) }
                    if PCARevoke.member(d, "method") != PCARevoke.member(delivery, "method") { return bad("delivery.method cannot be changed: create a new stream") }
                    delivery = d
                }
                let requested: [String]?
                if m == "PUT" { requested = eventsRequestedOk(PCARevoke.member(b, "events_requested")) }
                else if let er = PCARevoke.member(b, "events_requested") { requested = eventsRequestedOk(er) }
                else { requested = eventsRequestedOk(PCARevoke.member(s, "events_requested")) }
                let description: String?
                if m == "PUT" { description = PCARevoke.member(b, "description")?.asString }
                else if let d = PCARevoke.member(b, "description") { description = d.asString }
                else { description = PCARevoke.member(config, "description")?.asString }
                if delivered(o, requested).isEmpty { return bad("none of events_requested is supported by this transmitter") }
                var next = buildConfig(o, sid, rcv, requested, delivery, description)
                if let mi = PCARevoke.member(config, "min_verification_interval") { next["min_verification_interval"] = mi }
                let nextV = JSONValue.object(next)
                s = with(s) { sm in
                    sm["config"] = nextV
                    if let r = requested { sm["events_requested"] = .array(r.map { .string($0) }) } else { sm["events_requested"] = nil }
                }
                o.store.put(sid, s)
                return resp(200, nextV)
            }
            if m == "DELETE" {
                if own(o, rcv, qid) == nil { return notFound() }
                o.store.delete(qid?.asString ?? "")
                return .object(["status": .int(204)])
            }
            return methodNotAllowed()
        }

        if seg == "status" {
            if m == "GET" {
                if let s = own(o, rcv, qid) { return resp(200, statusBody(qid?.asString ?? "", s)) }
                return qid == nil ? bad("stream_id is required") : notFound()
            }
            if m == "POST" {
                guard let b = b, let sid = PCARevoke.member(b, "stream_id")?.asString else { return bad("stream_id is required") }
                guard let st = PCARevoke.member(b, "status")?.asString, STREAM_STATUSES.contains(st) else { return bad("status must be 'enabled', 'paused' or 'disabled'") }
                if let r = PCARevoke.member(b, "reason"), r.asString == nil { return bad("reason must be a string") }
                guard var s = own(o, rcv, PCARevoke.member(b, "stream_id")) else { return notFound() }
                s = with(s) { sm in
                    sm["status"] = .string(st)
                    sm["status_reason"] = PCARevoke.member(b, "reason")
                }
                let body = statusBody(sid, s)
                o.store.put(sid, s)
                return resp(200, body)
            }
            return methodNotAllowed()
        }

        if seg == "add_subject" || seg == "remove_subject" {
            if m != "POST" { return methodNotAllowed() }
            guard let b = b, let sid = PCARevoke.member(b, "stream_id")?.asString else { return bad("stream_id is required") }
            guard let key = subjectKey(PCARevoke.member(b, "subject")) else { return bad("subject must be a Subject Identifier object with a format") }
            if let v = PCARevoke.member(b, "verified"), case .bool = v {} else if PCARevoke.member(b, "verified") != nil { return bad("verified must be a boolean") }
            guard let s = own(o, rcv, PCARevoke.member(b, "stream_id")) else { return notFound() }
            var sub = PCARevoke.member(s, "subjects")?.asObject ?? [:]
            if seg == "add_subject" {
                if sub[JKey(key)] == nil && Double(sub.count) >= (o.maxSubjectsPerStream ?? 10_000) {
                    return resp(429, .object(["error": .string("too_many_requests"), "description": .string("subject limit reached")]))
                }
                if case let .bool(v)? = PCARevoke.member(b, "verified") { sub[JKey(key)] = .bool(v) } else { sub[JKey(key)] = .bool(true) }
                o.store.put(sid, with(s) { $0["subjects"] = .object(sub) })
                return .object(["status": .int(200)])
            }
            sub[JKey(key)] = nil
            o.store.put(sid, with(s) { $0["subjects"] = .object(sub) })
            return .object(["status": .int(204)])
        }

        // verification
        if m != "POST" { return methodNotAllowed() }
        guard let b = b else { return bad("a JSON object body is required") }
        guard var s = own(o, rcv, PCARevoke.member(b, "stream_id")) else {
            return PCARevoke.member(b, "stream_id")?.asString != nil ? notFound() : bad("stream_id is required")
        }
        if PCARevoke.member(s, "status") == .string("disabled") { return bad("the stream is disabled") }
        let sid = PCARevoke.member(b, "stream_id")?.asString ?? ""
        let config = PCARevoke.member(s, "config") ?? .null
        var view: [JKey: StreamEntry] = [JKey(PCARevoke.member(config, "stream_id")?.asString ?? ""): StreamEntry(config: config, lastVerification: number(PCARevoke.member(s, "lastVerification")))]
        var vreq: JObject = ["stream_id": .string(sid)]
        if let st = PCARevoke.member(b, "state") { vreq["state"] = st }
        let out = try handleVerificationRequest(&view, .object(vreq), o.now(), key: o.signingKey)
        let status = PCARevoke.member(out, "status").flatMap { number($0) }.map { Int64($0) } ?? 500
        if status != 204 {
            return .object(["status": .int(status), "body": .object(["error": .string(status == 429 ? "too_many_requests" : "invalid_request"), "description": PCARevoke.member(out, "error") ?? .null])])
        }
        s = with(s) { $0["lastVerification"] = numValue(o.now()) }
        o.store.put(PCARevoke.member(config, "stream_id")?.asString ?? "", s)
        try o.deliver(s, PCARevoke.member(out, "set")?.asString ?? "")
        return .object(["status": .int(204)])
    }

    /// The SSF management API (OpenID SSF 1.0 §8.1): stream create / read / update / replace / delete, status, subjects and
    /// verification, for the receiver `authenticate` names. `req` is `{method, path, query?, body?}`; the answer is
    /// `{status, body?}`. No receiver is 401; any internal failure (a malformed request object, a store or delivery error) is a
    /// 500 `server_error` and never leaks detail.
    public static func ssfManagementHandler(_ o: SsfManageOptions, _ req: JSONValue?, authenticate: (JSONValue?) throws -> JSONValue?) -> JSONValue {
        let rcv: JSONValue
        do {
            guard let r = try authenticate(req) else { return resp(401, .object(["error": .string("unauthenticated")])) }
            rcv = r
        } catch { return resp(500, .object(["error": .string("server_error")])) }
        do { return try route(o, req, rcv) } catch { return resp(500, .object(["error": .string("server_error")])) }
    }
}
