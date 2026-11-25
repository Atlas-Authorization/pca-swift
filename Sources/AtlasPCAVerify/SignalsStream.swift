import Foundation

/// SSF stream configuration checks, stream health, the verification request handler, the RFC 8936 poll queue, the RFC 8935 push
/// response and the CAEP level-change event builders (the stream half of `PCASignals`).
extension PCASignals {
    /// `validateStreamConfig`: the list of problems (empty = valid).
    public static func validateStreamConfig(_ c: JSONValue?) -> [String] {
        guard let o = c?.asObject else { return ["not an object"] }
        func nonEmpty(_ v: JSONValue?) -> Bool { nonEmptyStr(v) != nil }
        func strs(_ v: JSONValue?) -> [String]? {
            guard let a = v?.asArray else { return nil }
            var out: [String] = []
            for x in a { guard let s = nonEmptyStr(x) else { return nil }; out.append(s) }
            return out
        }
        var e: [String] = []
        if !nonEmpty(o["stream_id"]) { e.append("stream_id is required") }
        if !nonEmpty(o["iss"]) { e.append("iss is required") }
        let aud = o["aud"]
        if !(nonEmpty(aud) || (aud?.asArray.map { !$0.isEmpty && $0.allSatisfy { nonEmpty($0) } } ?? false)) { e.append("aud must be a non-empty string or array") }
        let delivered = strs(o["events_delivered"])
        if delivered == nil || delivered!.isEmpty { e.append("events_delivered must be a non-empty array of event type URIs") }
        let supported = strs(o["events_supported"])
        if o["events_supported"] != nil && supported == nil { e.append("events_supported must be an array of URIs") }
        if o["events_requested"] != nil, (strs(o["events_requested"]) ?? []).isEmpty { e.append("events_requested must be a non-empty array of URIs") }
        if let d = delivered, let s = supported, !d.allSatisfy({ s.contains($0) }) { e.append("events_delivered must be a subset of events_supported") }
        let d = o["delivery"].flatMap { JS.truthy($0) ? $0 : nil }
        let method = d.flatMap { PCARevoke.member($0, "method")?.asString }
        if let d = d, method == DELIVERY_PUSH || method == DELIVERY_POLL {
            if !(PCARevoke.member(d, "endpoint_url")?.asString.map(httpsUrlOk) ?? false) { e.append("delivery.endpoint_url must be an https URL") }
        } else {
            e.append("delivery.method must be the RFC 8935 or RFC 8936 URI")
        }
        if let m = o["min_verification_interval"], !(number(m).map(isSafeNonnegInt) ?? false) {
            e.append("min_verification_interval must be a non-negative integer (seconds)")
        }
        return e
    }

    /// Tunables of `StreamHealth` (nil = the default: 60 s verify timeout, 300 s verified window, 3 failures, 16 pending).
    public struct StreamHealthOptions {
        public var verifyTimeoutSec: Double? = nil
        public var verifiedWithinSec: Double? = nil
        public var failAfter: Double? = nil
        public var maxPending: Double? = nil
        public init() {}
        /// From the reference's option object (`verifyTimeoutSec`, `verifiedWithinSec`, `failAfter`, `maxPending`).
        public init(_ v: JSONValue?) {
            verifyTimeoutSec = PCASignals.number(PCARevoke.member(v, "verifyTimeoutSec"))
            verifiedWithinSec = PCASignals.number(PCARevoke.member(v, "verifiedWithinSec"))
            failAfter = PCASignals.number(PCARevoke.member(v, "failAfter"))
            maxPending = PCASignals.number(PCARevoke.member(v, "maxPending"))
        }
    }

    /// Health of one stream: status, last event / verification, pending verification states, consecutive timeouts.
    public final class StreamHealth {
        let minInterval: Double
        let o: StreamHealthOptions
        var status = "enabled"
        var lastEvent: Double? = nil, lastVerified: Double? = nil, lastRequested: Double? = nil
        var fails = 0, rejected = 0
        var pending: [JKey: Double] = [:]

        public init(_ config: JSONValue?, _ o: StreamHealthOptions = StreamHealthOptions()) {
            minInterval = PCASignals.number(PCARevoke.member(config, "min_verification_interval")) ?? 0
            self.o = o
        }

        public func setStatus(_ s: JSONValue?) throws {
            guard let x = s?.asString, STREAM_STATUSES.contains(x) else { throw JSError("unknown stream status") }
            status = x
        }

        public func recordEvent(_ now: Double) { lastEvent = max(lastEvent ?? 0, now) }

        func expire(_ now: Double) {
            let before = pending.count
            pending = pending.filter { now.isFinite && now <= $0.value }
            fails += before - pending.count
        }

        /// A fresh verification `state`, or nil when the stream is not enabled, a request came too soon, or too many are pending.
        public func requestVerification(_ now: Double) throws -> String? {
            if status != "enabled" { return nil }
            if let l = lastRequested, now - l < minInterval { return nil }
            expire(now)
            if Double(pending.count) >= (o.maxPending ?? 16) { return nil }
            let state = Base64URLStrict.encode((0..<16).map { _ in UInt8.random(in: 0...255) })
            pending[JKey(state)] = now + (o.verifyTimeoutSec ?? 60)
            lastRequested = now
            return state
        }

        /// Acknowledge a verification `state` (a non-string or unknown one is counted as rejected).
        public func ackVerification(_ state: JSONValue?, _ now: Double) -> Bool {
            expire(now)
            if let s = state?.asString, pending.removeValue(forKey: JKey(s)) != nil {
                lastVerified = now
                lastEvent = max(lastEvent ?? 0, now)
                fails = 0
                return true
            }
            rejected += 1
            return false
        }

        public func report(_ now: Double) -> JSONValue {
            expire(now)
            let within = o.verifiedWithinSec ?? 300
            let state: String
            var reason: String? = nil
            if status == "disabled" { state = "disabled"; reason = "stream is disabled: no events are transmitted or held" }
            else if status == "paused" { state = "paused"; reason = "stream is paused: events may be delayed" }
            else if Double(fails) >= (o.failAfter ?? 3) { state = "failing"; reason = "\(fails) consecutive verification requests timed out" }
            else if lastVerified == nil { state = "unverified"; reason = "no verification round trip has completed" }
            else if now - lastVerified! > within { state = "degraded"; reason = "last verified \(JS.number(now - lastVerified!))s ago, over \(JS.number(within))s" }
            else { state = "healthy" }
            var m: JObject = ["state": .string(state), "status": .string(status), "reasons": .array(reason.map { [.string($0)] } ?? []),
                              "pending_verifications": .int(Int64(pending.count)), "consecutive_verification_failures": .int(Int64(fails)),
                              "rejected_verifications": .int(Int64(rejected))]
            if let t = lastEvent { m["last_event_at"] = PCASignals.numValue(t) }
            if let t = lastVerified { m["last_verified_at"] = PCASignals.numValue(t) }
            return .object(m)
        }

        public func revocationFreshWithin(_ maxAgeSec: Double, _ now: Double) -> Bool {
            status == "enabled" && (lastVerified.map { now - $0 <= maxAgeSec } ?? false)
        }
    }

    /// A stream known to the transmitter: its `config` and the time of its last verification.
    public struct StreamEntry {
        public var config: JSONValue
        public var lastVerification: Double?
        public init(config: JSONValue, lastVerification: Double? = nil) { self.config = config; self.lastVerification = lastVerification }
    }

    /// `handleVerificationRequest`: a signed verification SET echoing the receiver's `state`, or `{status, error}`.
    /// `key == nil` models a missing key (the SET build fails, after the request was recorded, as in the reference).
    public static func handleVerificationRequest(_ streams: inout [JKey: StreamEntry], _ req: JSONValue?, _ now: Double, key: PCAEdKey?) throws -> JSONValue {
        let bad: JSONValue = .object(["status": .int(400), "error": .string("stream_id (string) is required; state must be a string")])
        guard let r = req?.asObject, let id = r["stream_id"]?.asString else { return bad }
        var state: String? = nil
        switch r["state"] {
        case nil: break
        case let .string(s)?: state = s
        default: return bad
        }
        guard var s = streams[JKey(id)] else { return .object(["status": .int(404), "error": .string("no such stream")]) }
        if s.config.isNull { throw JSError("Cannot read properties of undefined (reading 'min_verification_interval')") }
        let min = number(PCARevoke.member(s.config, "min_verification_interval")) ?? 0
        if let l = s.lastVerification, now - l < min { return .object(["status": .int(429), "error": .string("verification requested too soon")]) }
        s.lastVerification = now
        streams[JKey(id)] = s
        var args: JObject = ["events": .object([JKey(EV_VERIFICATION): state.map { .object(["state": .string($0)]) } ?? .object([:])])]
        for (to, from) in [("issuer", "iss"), ("audience", "aud"), ("subject", "stream_id")] {
            if let v = PCARevoke.member(s.config, from) { args[JKey(to)] = v }
        }
        guard let k = key else { throw JSError("Key for the EdDSA algorithm must be a key object") }
        return .object(["status": .int(204), "set": .string(try buildSET(.object(args), key: k))])
    }

    /// A poll-delivery queue (RFC 8936): enqueue SETs by `jti`, `poll` with acks and error reports.
    public final class PollQueue {
        var q: [(jti: String, set: String)] = []
        public private(set) var errors: [JSONValue] = []
        public init() {}

        /// A repeated `jti` replaces the token and keeps its place.
        public func enqueue(_ jti: String, _ set: String) {
            if let i = q.firstIndex(where: { JKey($0.jti) == JKey(jti) }) { q[i].set = set } else { q.append((jti, set)) }
        }

        public var depth: Int { q.count }

        @discardableResult
        func delete(_ jti: String) -> Bool {
            let n = q.count
            q.removeAll { JKey($0.jti) == JKey(jti) }
            return q.count != n
        }

        /// `poll({maxEvents?, ack?, setErrs?})` -> `{sets, moreAvailable?}`. A bad `maxEvents` is a RangeError; a null `setErrs`
        /// entry for a queued `jti` is a TypeError after that SET has been dropped, as in the reference.
        public func poll(_ req: JSONValue?) throws -> JSONValue {
            if req == nil || req == .null { throw JSError("Cannot read properties of null (reading 'maxEvents')") }
            if let m = PCARevoke.member(req, "maxEvents"), !(number(m).map(isSafeNonnegInt) ?? false) { throw JSError("maxEvents must be a non-negative integer") }
            switch PCARevoke.member(req, "ack") {
            case nil, .null?: break
            case let .array(a)?: for j in a.compactMap({ $0.asString }) { delete(j) }
            case let .string(s)?: for c in s.unicodeScalars { delete(String(c)) }
            default: throw JSError("req.ack is not iterable")
            }
            if let se = JS.present(PCARevoke.member(req, "setErrs")) {
                for (jti, e) in entries(se) where delete(jti) {
                    if e.isNull { throw JSError("Cannot read properties of null (reading 'err')") }
                    var m: JObject = ["jti": .string(jti)]
                    for k in ["err", "description"] { if let v = PCARevoke.member(e, k) { m[JKey(k)] = v } }
                    errors.append(.object(m))
                }
            }
            let max = number(PCARevoke.member(req, "maxEvents")) ?? .infinity
            var sets: JObject = [:]
            var n = 0
            for (jti, set) in q {
                if Double(n) >= max { break }
                sets[JKey(jti)] = .string(set)
                n += 1
            }
            var out: JObject = ["sets": .object(sets)]
            if q.count > n { out["moreAvailable"] = .bool(true) }
            return .object(out)
        }
    }

    /// `pushResponse(result)`: the RFC 8935 HTTP answer for a `receiveSET` result. A `null` result is a TypeError.
    public static func pushResponse(_ r: JSONValue?) throws -> JSONValue {
        guard let r = r, !r.isNull else { throw JSError("Cannot read properties of null (reading 'ok')") }
        if JS.truthy(PCARevoke.member(r, "ok")) { return .object(["status": .int(202)]) }
        let err: String
        switch PCARevoke.member(r, "code")?.asString {
        case "verify_failed": err = "invalid_key"
        case "misconfigured", "replay_store_error": err = "access_denied"
        default: err = "invalid_request"
        }
        var body: JObject = ["err": .string(err)]
        if let d = PCARevoke.member(r, "reason") { body["description"] = d }
        return .object(["status": .int(400), "body": .object(body)])
    }

    static func levelSET(_ a: JSONValue, _ ty: String, _ event: JSONValue?, _ key: PCAEdKey) throws -> String {
        var args: JObject = [:]
        if let i = PCARevoke.member(a, "issuer") { args["issuer"] = i }
        if let i = PCARevoke.member(a, "audience") { args["audience"] = i }
        // shortcut: an absent `event` yields an empty events map, which buildSET refuses (the reference signs an empty one)
        var ev: JObject = [:]
        if let e = event { ev[JKey(ty)] = e }
        args["events"] = .object(ev)
        return try buildSET(.object(args), key: key)
    }

    /// `riskLevelChangeSET({issuer, audience, event})` signed with `key`.
    public static func riskLevelChangeSET(_ a: JSONValue, key: PCAEdKey) throws -> String {
        try levelSET(a, EV_RISK_LEVEL_CHANGE, PCARevoke.member(a, "event"), key)
    }

    /// `assuranceLevelChangeSET({issuer, audience, event, order?})`: `change_direction` is derived from `order` (lowest to highest)
    /// when the event names a `previous_level` and no direction.
    public static func assuranceLevelChangeSET(_ a: JSONValue, key: PCAEdKey) throws -> String {
        var e = PCARevoke.member(a, "event") ?? .object([:])
        if var em = e.asObject, let order = PCARevoke.member(a, "order")?.asArray, em["previous_level"] != nil, em["change_direction"] == nil {
            func at(_ v: JSONValue?) -> Int? { v.flatMap { v in order.firstIndex(of: v) } }
            if let i = at(em["previous_level"]), let j = at(em["current_level"]), i != j { em["change_direction"] = .string(j > i ? "increase" : "decrease") }
            e = .object(em)
        }
        return try levelSET(a, EV_ASSURANCE_LEVEL_CHANGE, e, key)
    }
}
