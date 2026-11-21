import Foundation

/// Shared Signals Framework (SSF / CAEP) for PCA: build and verify Security Event Tokens (RFC 8417, EdDSA), the subscriber-side
/// revocation state, the replay-guarded receive path, standard CAEP / RISC revocations, the `authorize()` revocation adapters and
/// snapshot / restore. The SSF stream health / verification / poll queue (`SignalsStream.swift`) and the SSF management API
/// (`SignalsManage.swift`) extend this namespace.
///
/// JSON-valued like the other ported packages: options and events cross as `JSONValue` with the reference's member names; refusal
/// texts are the reference's own. Differences from the reference, all fail-closed or by construction:
/// - a key is a `PCAEdKey` (signing) or a public JWK (verifying);
/// - a revocation state is a class, so the reference's "state must come from createRevocationState()" check cannot fail;
/// - an `events` map given to `buildSET` as an array is refused (the reference builds a token its own verifier rejects);
/// - `clockTolerance` is a number of seconds (a duration string is refused);
/// - an event map has no wire order in `JSONValue`: events fold in the order index keys, the known PCA / CAEP / RISC types, then
///   the rest by code unit. Revocation is monotone (a set of keys with a max timestamp), so the order shows only in the order of a
///   snapshot's pairs and in which entries are applied before a malformed event aborts the fold.
public enum PCASignals {
    public static let SET_TYP = "secevent+jwt"
    public static let SET_ALG = "EdDSA"
    public static let SET_INMEMORY_MAX_ENTRIES: Double = 100_000
    public static let DELIVERY_PUSH = "urn:ietf:rfc:8935"
    public static let DELIVERY_POLL = "urn:ietf:rfc:8936"
    public static let STREAM_STATUSES = ["enabled", "paused", "disabled"]

    public static let EV_SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    public static let EV_CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change"
    public static let EV_GRANT_REVOKED = "https://atlasauth.net/caep/grant-revoked"
    public static let EV_KILL_SWITCH = "https://atlasauth.net/caep/kill-switch"
    public static let EV_INTENT_REVOKED = "https://atlasauth.net/caep/intent-revoked"
    public static let EV_VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification"
    public static let EV_RISK_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"
    public static let EV_ASSURANCE_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

    public static let RISC_SESSIONS_REVOKED = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
    public static let RISC_ACCOUNT_DISABLED = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
    public static let RISC_ACCOUNT_PURGED = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
    public static let RISC_CREDENTIAL_COMPROMISE = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"
    static let riscTypes = [RISC_SESSIONS_REVOKED, RISC_ACCOUNT_DISABLED, RISC_ACCOUNT_PURGED, RISC_CREDENTIAL_COMPROMISE]

    /// The package constants as one JSON object (`EVENT_TYPES`, `RISC_EVENT_TYPES`, the delivery URIs, ...).
    public static func constants() -> JSONValue {
        func s(_ v: String) -> JSONValue { .string(v) }
        return .object([
            "SET_TYP": s(SET_TYP), "SET_ALG": s(SET_ALG),
            "EVENT_TYPES": .object([
                "sessionRevoked": s(EV_SESSION_REVOKED), "credentialChange": s(EV_CREDENTIAL_CHANGE), "grantRevoked": s(EV_GRANT_REVOKED),
                "killSwitch": s(EV_KILL_SWITCH), "intentRevoked": s(EV_INTENT_REVOKED), "verification": s(EV_VERIFICATION),
                "riskLevelChange": s(EV_RISK_LEVEL_CHANGE), "assuranceLevelChange": s(EV_ASSURANCE_LEVEL_CHANGE),
            ]),
            "RISC_EVENT_TYPES": .object([
                "sessionsRevoked": s(RISC_SESSIONS_REVOKED), "accountDisabled": s(RISC_ACCOUNT_DISABLED),
                "accountPurged": s(RISC_ACCOUNT_PURGED), "credentialCompromise": s(RISC_CREDENTIAL_COMPROMISE),
            ]),
            "SET_INMEMORY_MAX_ENTRIES": .int(100_000), "DELIVERY_PUSH": s(DELIVERY_PUSH), "DELIVERY_POLL": s(DELIVERY_POLL),
            "STREAM_STATUSES": .array(STREAM_STATUSES.map(s)),
        ])
    }

    /// A refusal carrying the reference's `SignalsError.code` where it has one (`misconfigured`, `bad_snapshot`, `unmapped_subject`).
    static func plain(_ m: String) -> JSError { JSError(m) }
    static func coded(_ code: String, _ m: String) -> JSError { JSError(m, code: code) }

    // ------------------------------------------------------------------------------------------ JavaScript helpers

    /// JavaScript `\s` (WhiteSpace + LineTerminator).
    static func isJsWs(_ c: Unicode.Scalar) -> Bool {
        switch c.value {
        case 0x09...0x0d, 0x20, 0xa0, 0x1680, 0x2000...0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff: return true
        default: return false
        }
    }

    /// `/^https:\/\/[^\s]+$/`.
    static func httpsUrlOk(_ s: String) -> Bool {
        guard s.hasPrefix("https://") else { return false }
        let rest = s.unicodeScalars.dropFirst(8)
        return !rest.isEmpty && !rest.contains(where: isJsWs)
    }

    static func numValue(_ f: Double) -> JSONValue { PCARevoke.num(f) }

    /// `typeof x === 'number'` -> the number.
    static func number(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d
        default: return nil
        }
    }

    static func isSafeNonnegInt(_ f: Double) -> Bool {
        f.rounded() == f && abs(f) <= 9_007_199_254_740_991 && f >= 0 && !(f == 0 && f.sign == .minus)
    }

    static let knownOrder = [EV_GRANT_REVOKED, EV_KILL_SWITCH, EV_INTENT_REVOKED, EV_SESSION_REVOKED, EV_CREDENTIAL_CHANGE] + riscTypes

    /// `Object.entries(v)`: object members (index keys ascending, then the known event types, then the rest by code unit), array
    /// elements by index, string characters; anything else has none.
    static func entries(_ v: JSONValue?) -> [(String, JSONValue)] {
        switch v {
        case let .object(m)?:
            let idx = m.keys.compactMap { k in JS.indexKey(k.s).map { (k, $0) } }.sorted { $0.1 < $1.1 }.map { $0.0 }
            let rest = m.keys.filter { JS.indexKey($0.s) == nil }
            let known = knownOrder.map { JKey($0) }.filter { m[$0] != nil && JS.indexKey($0.s) == nil }
            let other = rest.filter { k in !knownOrder.contains(k.s) }.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }
            return (idx + known + other).map { ($0.s, m[$0]!) }
        case let .array(a)?: return a.enumerated().map { (String($0.offset), $0.element) }
        case let .string(s)?: return s.unicodeScalars.enumerated().map { (String($0.offset), .string(String($0.element))) }
        default: return []
        }
    }

    /// `Object.entries(parsed.events)`; a missing / null `events` (or a non-object `parsed`) is a TypeError.
    static func eventsOf(_ parsed: JSONValue?) throws -> [(String, JSONValue)] {
        guard let e = PCARevoke.nn(parsed, "events") else { throw plain("Cannot convert undefined or null to object") }
        return entries(e)
    }

    /// `typeof ev.event_timestamp === 'number' ? it : 0`; reading a member of `null` is a TypeError.
    static func eventTs(_ ev: JSONValue) throws -> Double {
        if ev.isNull { throw plain("Cannot read properties of null (reading 'event_timestamp')") }
        return number(PCARevoke.member(ev, "event_timestamp")) ?? 0
    }

    static func nonEmptyStr(_ v: JSONValue?) -> String? { v?.asString.flatMap { $0.isEmpty ? nil : $0 } }
    static func nowSec() -> Double { Date().timeIntervalSince1970.rounded(.down) }

    static func normTyp(_ t: String) -> String { Jose.normalizeTyp(t) }

    // ------------------------------------------------------------------------------------------ build / verify a SET

    /// `buildSET({events, issuer, audience, subject?, key})`: an EdDSA-signed SET (`typ: secevent+jwt`) with a random `jti` and the
    /// wall-clock `iat`. `args` carries `events` (non-empty object), `issuer`, `audience`, optional `subject`.
    public static func buildSET(_ args: JSONValue, key: PCAEdKey) throws -> String {
        guard let events = args.get("events")?.asObject, !events.isEmpty else {
            throw plain("buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)")
        }
        var p: JObject = ["events": .object(events)]
        let subject = args.get("subject")
        if let s = subject { p["sub_id"] = .object(["format": .string("opaque"), "id": s]) }
        if let i = args.get("issuer") { p["iss"] = i }
        p["iat"] = numValue(nowSec())
        p["jti"] = .string(UUID().uuidString.lowercased())
        if let a = args.get("audience") { p["aud"] = a }
        if let s = subject { p["sub"] = s }
        return try Jose.sign(header: .object(["alg": .string(SET_ALG), "typ": .string(SET_TYP)]), headerOrder: ["alg", "typ"],
                             payload: .object(p), payloadOrder: ["events", "sub_id", "iss", "iat", "jti", "aud", "sub"], signer: key.sign)
    }

    static func parseEvents(_ raw: JSONValue?) throws -> JSONValue {
        guard let m = raw?.asObject else { throw plain("SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)") }
        if m.isEmpty { throw plain("SET invalid: `events` claim is empty (RFC 8417 §2.2)") }
        for (k, v) in m where !v.isObject { throw plain("SET invalid: event payload for `\(k.s)` is not a JSON object (RFC 8417 §2.2)") }
        return .object(m)
    }

    /// An Ed25519 verification key from a public JWK (`{kty: OKP, crv: Ed25519, x}`); anything else is refused.
    static func ed25519Key(_ key: JSONValue?) throws -> Jose.Key {
        guard let k = key?.asObject, k["kty"]?.asString == "OKP", k["crv"]?.asString == "Ed25519", let xs = k["x"]?.asString,
              let x = Base64URLStrict.decode(xs, length: 32) else { throw plain("an Ed25519 public JWK is required") }
        return .ed25519(x)
    }

    /// `checkAudiencePresence` with the reference library's JavaScript semantics for an option that is not a string or array.
    static func audienceOk(_ aud: JSONValue?, _ opt: JSONValue) throws -> Bool {
        func eq(_ a: JSONValue, _ b: JSONValue) -> Bool { a == b && !a.isObject && !a.isArray }
        switch (aud, opt) {
        case let (.string(a)?, .string(o)): return a == o
        case let (a?, .array(o)) where a.asString != nil: return o.contains { eq($0, a) }
        case let (.array(a)?, .string(o)): return a.contains { $0.asString == o }
        case let (.array(a)?, .array(o)): return o.contains { x in a.contains { eq(x, $0) } }
        case (.string?, _): throw plain("audOption.includes is not a function")
        case (.array?, _): throw plain("audOption.some is not a function")
        default: return false
        }
    }

    /// `verifySET(set, key, opts)`: canonical compact JWS, EdDSA signature under the public JWK `key`, `typ`, `iss` / `aud` / time
    /// claims, then the SET shape. `opts` members: `issuer`, `audience`, `clockTolerance` (seconds), `currentDate` (epoch ms), `typ`,
    /// `requireTyp`. Returns `{events, iss, jti, sub?, payload}`. A `null` options value is a TypeError, as in the reference.
    public static func verifySET(_ set: JSONValue?, _ key: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        var o: JObject = [:]
        switch opts {
        case .null?: throw plain("Cannot read properties of null (reading 'issuer')")
        case let .object(m)?: o = m
        default: break
        }
        let jws = try Jose.assertCanonicalCompactJws(set)
        let now: Double
        if let cd = o["currentDate"] {
            guard let ms = number(cd) else { throw plain("Invalid time value") }
            now = (ms / 1000).rounded(.down)
        } else { now = nowSec() }
        var wantTyp: String? = SET_TYP
        if o["requireTyp"] == .bool(false) { wantTyp = nil }
        else {
            switch o["typ"] {
            case nil, .null?: break
            case let .string(s)?: wantTyp = s
            default: throw plain("typ must be a string")
            }
        }
        let alg = try Jose.checkProtectedHeader(jws.header, algorithms: [SET_ALG])
        let vkey = try ed25519Key(key)
        let sig = try Jose.decodeCanonicalBase64url(jws.segments[2])
        if !Jose.verifySignature(alg: alg, key: vkey, input: Array((jws.segments[0] + "." + jws.segments[1]).utf8), sig: sig) {
            throw JSError("signature verification failed", code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED")
        }
        try Jose.rejectUnencodedPayload(jws.header)
        guard let payload = jws.payload else { throw plain("JWT payload is not an object") }
        if let a = o["audience"] {
            if payload["aud"] == nil { throw plain("missing required \"aud\" claim") }
            if JS.truthy(a), !(try audienceOk(payload["aud"], a)) { throw plain("unexpected \"aud\" claim value") }
        }
        var tol = 0.0
        switch o["clockTolerance"] {
        case nil: break
        case let t?: guard let n = number(t) else { throw plain("clockTolerance must be a number of seconds") }; tol = n
        }
        func claimNum(_ k: String) throws -> Double? {
            guard let v = payload[JKey(k)] else { return nil }
            guard let n = number(v) else { throw plain("\"\(k)\" claim must be a number") }
            return n
        }
        _ = try claimNum("iat")
        if let nbf = try claimNum("nbf"), nbf > now + tol { throw plain("\"nbf\" claim timestamp check failed") }
        if let exp = try claimNum("exp"), exp <= now - tol { throw plain("\"exp\" claim timestamp check failed") }
        if let t = wantTyp, !t.isEmpty {
            guard let h = jws.header["typ"]?.asString, normTyp(h) == normTyp(t) else { throw plain("unexpected \"typ\" JWT header value") }
        }
        if let iv = o["issuer"] {
            if payload["iss"] == nil { throw plain("missing required \"iss\" claim") }
            if JS.truthy(iv) {
                let list = iv.asArray ?? [iv]
                if !list.contains(where: { !$0.isObject && !$0.isArray && $0 == payload["iss"] }) { throw plain("unexpected \"iss\" claim value") }
            }
        }
        guard let iss = payload["iss"]?.asString else { throw plain("SET invalid: missing or non-string `iss`") }
        guard let jti = payload["jti"]?.asString else { throw plain("SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)") }
        var out: JObject = ["events": try parseEvents(payload["events"]), "iss": .string(iss), "jti": .string(jti), "payload": .object(payload)]
        if let sub = payload["sub"], sub.asString != nil { out["sub"] = sub }
        return .object(out)
    }

    // ------------------------------------------------------------------------------------------ revocation state

    /// An insertion-ordered map from key to the max event timestamp seen (a JavaScript `Map<string, number>`).
    public struct TsMap {
        public private(set) var items: [(key: String, ts: Double)] = []
        private var index: [JKey: Int] = [:]
        public init() {}
        public func contains(_ k: String) -> Bool { index[JKey(k)] != nil }
        public func get(_ k: String) -> Double? { index[JKey(k)].map { items[$0].ts } }
        public var count: Int { items.count }
        /// Revocation is monotone: a key keeps the max timestamp seen and is never removed.
        public mutating func recordMax(_ k: String, _ ts: Double) {
            if let i = index[JKey(k)] { if ts > items[i].ts { items[i].ts = ts } }
            else { index[JKey(k)] = items.count; items.append((k, ts)) }
        }
        var pairs: JSONValue { .array(items.map { .array([.string($0.key), PCASignals.numValue($0.ts)]) }) }
    }

    /// Subscriber-side revocation state: revoked grants, killed agents, and (created on first use) revoked intent ids.
    public final class RevocationState {
        public var revokedGrants = TsMap()
        public var killedAgents = TsMap()
        public var revokedIntentIds: TsMap? = nil
        public init() {}
    }

    public static func createRevocationState() -> RevocationState { RevocationState() }

    /// `applySET`: fold a parsed SET into the state (max timestamp per key, monotone). A null event payload is a TypeError raised
    /// at that entry; entries before it stay applied, as in the reference.
    public static func applySET(_ state: RevocationState, _ parsed: JSONValue?) throws {
        for (ty, ev) in try eventsOf(parsed) {
            let ts = try eventTs(ev)
            if ty == EV_GRANT_REVOKED {
                if let g = nonEmptyStr(PCARevoke.member(ev, "grant_ref")) { state.revokedGrants.recordMax(g, ts) }
            } else if ty == EV_KILL_SWITCH {
                if let a = nonEmptyStr(PCARevoke.member(ev, "agent")) { state.killedAgents.recordMax(a, ts) }
                if let g = nonEmptyStr(PCARevoke.member(ev, "grant_ref")) { state.revokedGrants.recordMax(g, ts) }
            } else if ty == EV_INTENT_REVOKED {
                if let ids = PCARevoke.member(ev, "ids")?.asArray {
                    for id in ids.compactMap({ $0.asString }) where id.hasPrefix("pca-intent:") {
                        var m = state.revokedIntentIds ?? TsMap()
                        m.recordMax(id, ts)
                        state.revokedIntentIds = m
                    }
                }
            }
        }
    }

    public static func isIntentRevoked(_ state: RevocationState, _ id: String) -> Bool { state.revokedIntentIds?.contains(id) ?? false }

    public static func isRevoked(_ state: RevocationState, _ grantRef: String, _ agent: String? = nil) -> Bool {
        state.revokedGrants.contains(grantRef) || (agent.map { state.killedAgents.contains($0) } ?? false)
    }

    static func setTimestamp(_ p: JSONValue?) throws -> Double {
        var min = Double.infinity
        for (_, ev) in try eventsOf(p) {
            if ev.isNull { throw plain("Cannot read properties of null (reading 'event_timestamp')") }
            if let t = number(PCARevoke.member(ev, "event_timestamp")), t < min { min = t }
        }
        return min.isFinite ? min : 0
    }

    /// `streamProcessor`: fold SETs into `state` in ascending `event_timestamp` order (stable). `sets` must be an array (a string
    /// spreads to its characters, as in the reference; anything else is not iterable).
    public static func streamProcessor(_ sets: JSONValue?, _ state: RevocationState) throws {
        let items: [JSONValue]
        switch sets {
        case let .array(a)?: items = a
        case let .string(s)?: items = s.unicodeScalars.map { .string(String($0)) }
        default: throw plain("parsedSets is not iterable")
        }
        // a one-element sort never calls its comparator, so the timestamp is only read when there are two or more
        var keyed: [(ts: Double, at: Int, set: JSONValue)] = []
        for (i, it) in items.enumerated() { keyed.append((items.count > 1 ? try setTimestamp(it) : 0, i, it)) }
        keyed.sort { $0.ts != $1.ts ? $0.ts < $1.ts : $0.at < $1.at }
        for k in keyed { try applySET(state, k.set) }
    }

    // ------------------------------------------------------------------------------------------ replay store

    /// A `jti` replay store for received SETs. `addIfAbsent` must be atomic; an entry may be dropped once `now >= expires`.
    public protocol SetReplayStore: AnyObject {
        func addIfAbsent(_ jti: String, expiresAtSec: Double, nowSec: Double) throws -> Bool
    }

    /// Single-process, bounded store: when `maxEntries` live entries are held a further new `jti` is an error, never an eviction.
    public final class InMemorySetReplayStore: SetReplayStore {
        let max: Double
        var seen: [JKey: Double] = [:]
        private let lock = NSLock()
        init(max: Double) { self.max = max }
        public func addIfAbsent(_ jti: String, expiresAtSec: Double, nowSec: Double) throws -> Bool {
            lock.lock(); defer { lock.unlock() }
            let k = JKey(jti)
            let held = seen[k]
            if let h = held, !(nowSec.isFinite && nowSec >= h) { return false }
            if held == nil && Double(seen.count) >= max {
                seen = seen.filter { !(nowSec.isFinite && nowSec >= $0.value) }
                if Double(seen.count) >= max { throw plain("replay store is full") }
            }
            seen[k] = expiresAtSec
            return true
        }
    }

    /// `createInMemorySetReplayStore(opts)`: `opts` (nil = `{}`) may carry `maxEntries` (a positive integer; absent or null = 100000).
    public static func createInMemorySetReplayStore(_ opts: JSONValue? = nil) throws -> InMemorySetReplayStore {
        if opts == .null { throw plain("Cannot read properties of null (reading 'maxEntries')") }
        guard let m = JS.present(PCARevoke.member(opts, "maxEntries")) else { return InMemorySetReplayStore(max: SET_INMEMORY_MAX_ENTRIES) }
        guard let f = number(m), f.rounded() == f, f >= 1 else { throw coded("misconfigured", "maxEntries must be a positive integer") }
        return InMemorySetReplayStore(max: f)
    }

    /// `runSetReplayStoreConformance(make)`: the failed checks (empty = conformant). `make` returns a FRESH empty store each call. A
    /// store error propagates, as the reference's rejection does.
    public static func runSetReplayStoreConformance(_ make: () throws -> SetReplayStore) throws -> [String] {
        var failures: [String] = []
        func check(_ ok: Bool, _ name: String) { if !ok { failures.append(name) } }
        let s = try make()
        check(try s.addIfAbsent("a", expiresAtSec: 200, nowSec: 100), "first sight of a jti returns true")
        check(!(try s.addIfAbsent("a", expiresAtSec: 200, nowSec: 101)), "second sight of the same jti returns false")
        check(try s.addIfAbsent("b", expiresAtSec: 200, nowSec: 101), "a different jti is independent")
        check(!(try s.addIfAbsent("a", expiresAtSec: 200, nowSec: 199)), "still seen one second before expiry")
        let t = try make()
        _ = try t.addIfAbsent("c", expiresAtSec: 200, nowSec: 100)
        check(try t.addIfAbsent("c", expiresAtSec: 400, nowSec: 200), "an expired entry may be added again (nowSec >= expiresAtSec)")
        let u = try make()
        var wins = 0
        for _ in 0..<16 { if try u.addIfAbsent("race", expiresAtSec: 200, nowSec: 100) { wins += 1 } }
        check(wins == 1, "16 concurrent adds of one jti: exactly one wins (got \(wins))")
        return failures
    }

    // ------------------------------------------------------------------------------------------ standard revocations

    /// How standard events become revocation entries. `subjectToAgent` returns the agent id, or nil when the subject names no agent
    /// (a mapper that throws or returns a non-string is nil); the default maps an `opaque` subject's `id`.
    public struct StdOptions {
        public var subjectToAgent: ((JSONValue) -> String?)? = nil
        public var failOnUnmapped = false
        public init(subjectToAgent: ((JSONValue) -> String?)? = nil, failOnUnmapped: Bool = false) {
            self.subjectToAgent = subjectToAgent; self.failOnUnmapped = failOnUnmapped
        }
    }

    /// What `planStandardRevocations` decided.
    public struct StdPlan {
        public var agents: [(agent: String, ts: Double)] = []
        public var unmapped: [String] = []
        public func toValue() -> JSONValue {
            .object(["agents": .array(agents.map { .array([.string($0.agent), PCASignals.numValue($0.ts)]) }), "unmapped": .array(unmapped.map { .string($0) })])
        }
    }

    static func defaultSubjectToAgent(_ s: JSONValue) -> String? {
        PCARevoke.member(s, "format")?.asString == "opaque" ? nonEmptyStr(PCARevoke.member(s, "id")) : nil
    }

    static func isRevokingStandardEvent(_ ty: String, _ ev: JSONValue) throws -> Bool {
        if ty == EV_SESSION_REVOKED { return true }
        if ty == EV_CREDENTIAL_CHANGE {
            if ev.isNull { throw plain("Cannot read properties of null (reading 'change_type')") }
            return PCARevoke.member(ev, "change_type")?.asString != "create"
        }
        return riscTypes.contains(ty)
    }

    /// `planStandardRevocations`: which agents a verified SET's CAEP session-revoked / credential-change (any change but `create`)
    /// and RISC events revoke, without touching any state.
    public static func planStandardRevocations(_ parsed: JSONValue?, _ opts: StdOptions = StdOptions()) throws -> StdPlan {
        guard let payload = PCARevoke.nn(parsed, "payload") else { throw plain("Cannot read properties of undefined (reading 'sub_id')") }
        let setSubject = PCARevoke.member(payload, "sub_id").flatMap { $0.isObject ? $0 : nil }
        var plan = StdPlan()
        for (ty, ev) in try eventsOf(parsed) {
            if !(try isRevokingStandardEvent(ty, ev)) { continue }
            if ev.isNull { throw plain("Cannot read properties of null (reading 'subject')") }
            let own = PCARevoke.member(ev, "subject").flatMap { $0.isObject ? $0 : nil } ?? setSubject
            var agent: String? = nil
            if let o = own, PCARevoke.member(o, "format")?.asString != nil {
                agent = opts.subjectToAgent.map { $0(o) } ?? defaultSubjectToAgent(o)
            }
            if let a = agent, !a.isEmpty { plan.agents.append((a, number(PCARevoke.member(ev, "event_timestamp")) ?? 0)) }
            else {
                if opts.failOnUnmapped { throw coded("unmapped_subject", "event '\(ty)' names no mappable agent") }
                plan.unmapped.append(ty)
            }
        }
        return plan
    }

    static func applyStandardPlan(_ state: RevocationState, _ plan: StdPlan) {
        for (a, ts) in plan.agents { state.killedAgents.recordMax(a, ts) }
    }

    /// `applyStandardRevocations`: plan, then apply (monotone, max timestamp). Returns the plan that was applied.
    public static func applyStandardRevocations(_ state: RevocationState, _ parsed: JSONValue?, _ opts: StdOptions = StdOptions()) throws -> StdPlan {
        let plan = try planStandardRevocations(parsed, opts)
        applyStandardPlan(state, plan)
        return plan
    }

    // ------------------------------------------------------------------------------------------ receive

    /// The recommended receive path: size cap, canonical spelling, EdDSA signature, `typ`, `iss` and `aud`, `iat` freshness, the
    /// atomic `jti` replay guard, then the fold into `state`. Every refusal is a value `{ok: false, code, reason}`; a store that
    /// errors refuses too (`replay_store_error`) and the SET is not applied. `opts` members: `issuer`, `audience`, `maxAgeSec`
    /// (required), `clockSkewSec`, `nowSec`, `maxBytes`. A missing store or state is `misconfigured`.
    public static func receiveSET(_ set: JSONValue?, key: JSONValue?, opts: JSONValue?, store: SetReplayStore?, state: RevocationState?, std: StdOptions? = nil) -> JSONValue {
        func fails(_ code: String, _ reason: String) -> JSONValue { .object(["ok": .bool(false), "code": .string(code), "reason": .string(reason)]) }
        let maxAgeOpt = number(PCARevoke.member(opts, "maxAgeSec")).flatMap { $0 > 0 && $0.isFinite ? $0 : nil }
        guard let o = opts?.asObject, let store = store, let state = state, let maxAge = maxAgeOpt, o["issuer"] != nil, o["audience"] != nil else {
            return fails("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required")
        }
        var maxBytes = 16384.0
        if let mb = JS.present(o["maxBytes"]) { maxBytes = number(mb) ?? .nan }
        guard let s = set?.asString, Double(JS.length(s)) <= maxBytes else { return fails("oversize", "SET is not a string or exceeds maxBytes") }
        _ = s
        do { _ = try Jose.assertCanonicalCompactJws(set) } catch { return fails("malformed", (error as? JSError)?.message ?? "not a canonical compact JWS") }
        let now = number(o["nowSec"]) ?? nowSec()
        let vopts: JSONValue = .object(["issuer": o["issuer"]!, "audience": o["audience"]!, "currentDate": numValue(now * 1000)])
        let parsed: JSONValue
        do { parsed = try verifySET(set, key, vopts) } catch { return fails("verify_failed", (error as? JSError)?.message ?? "verification failed") }
        guard let iat = number(parsed.get("payload")?.get("iat")), iat.isFinite else { return fails("iat_missing", "SET has no numeric iat") }
        let skew = number(o["clockSkewSec"]) ?? 60
        if !(now.isFinite && skew.isFinite && iat <= now + skew) { return fails("iat_future", "SET iat is in the future") }
        if !(now - iat <= maxAge) { return fails("iat_stale", "SET is older than \(JS.number(maxAge))s") }
        var plan: StdPlan? = nil
        if let so = std {
            do { plan = try planStandardRevocations(parsed, so) } catch { return fails("unmapped_subject", (error as? JSError)?.message ?? "a revocation event could not be mapped to an agent") }
        }
        let jti = parsed.get("jti")?.asString ?? ""
        let fresh: Bool
        do { fresh = try store.addIfAbsent(jti, expiresAtSec: iat + maxAge + skew, nowSec: now) } catch { return fails("replay_store_error", (error as? JSError)?.message ?? "replay store failed") }
        if !fresh { return fails("replay", "jti '\(jti)' has already been received") }
        try? applySET(state, parsed)
        if let p = plan { applyStandardPlan(state, p) }
        return .object(["ok": .bool(true), "parsed": parsed])
    }

    // ------------------------------------------------------------------------------------------ authorize() adapters

    /// The agent id a kill-switch names for a verification context: nil when it cannot be determined; a throw is fail closed.
    /// Default: the PCActn's leaf holder.
    public typealias AgentOf = (_ pcactn: JSONValue, _ grant: JSONValue) throws -> String?

    static func leafHolderAgent(_ pcactn: JSONValue) throws -> String? {
        guard let chain = PCARevoke.nn(pcactn, "cap_chain") else { throw plain("Cannot read properties of undefined (reading 'length')") }
        return chain.asArray?.last.flatMap { PCARevoke.member($0, "holder")?.asString }
    }

    /// The reason a PCActn under `grant` is revoked by `state`, or nil when it is not. Anything undecidable is a reason.
    public static func revocationReason(_ state: RevocationState, _ pcactn: JSONValue, _ grant: JSONValue, _ agentOf: AgentOf? = nil) -> String? {
        if pcactn.isNull { return "revocation check error (fail closed)" }
        guard let r = nonEmptyStr(PCARevoke.member(pcactn, "grant_ref")) else { return "grant_ref is missing" }
        if state.revokedGrants.contains(r) { return "grant revoked by signal" }
        if let g = PCARevoke.member(grant, "id")?.asString, state.revokedGrants.contains(g) { return "grant revoked by signal" }
        let agent: String?
        do {
            if let f = agentOf { agent = try f(pcactn, grant) } else { agent = try leafHolderAgent(pcactn) }
        } catch { return "revocation check error (fail closed)" }
        guard let a = agent, !a.isEmpty else { return "agent could not be determined" }
        return state.killedAgents.contains(a) ? "agent killed by signal" : nil
    }

    /// The `hooks.revocation` result: always `enforced`; a revoked or undeterminable grant denies with its reason.
    public static func revocationHook(_ state: RevocationState, _ pcactn: JSONValue, _ grant: JSONValue, _ agentOf: AgentOf? = nil) -> JSONValue {
        if let r = revocationReason(state, pcactn, grant, agentOf) { return .object(["enforced": .bool(true), "ok": .bool(false), "reason": .string(r)]) }
        return .object(["enforced": .bool(true), "ok": .bool(true)])
    }

    /// `createIsRevoked`: true when revoked or when the answer cannot be determined (fail closed).
    public static func isRevokedAdapter(_ state: RevocationState, _ grant: JSONValue, _ pcactn: JSONValue, _ agentOf: AgentOf? = nil) -> Bool {
        revocationReason(state, pcactn, grant, agentOf) != nil
    }

    // ------------------------------------------------------------------------------------------ snapshot / restore

    /// A serialisable copy of the state, for the caller to persist after every accepted SET.
    public static func snapshotRevocationState(_ state: RevocationState) -> JSONValue {
        .object(["v": .int(1), "grants": state.revokedGrants.pairs, "agents": state.killedAgents.pairs, "intents": state.revokedIntentIds?.pairs ?? .array([])])
    }

    static func snapshotPairs(_ v: JSONValue?, _ what: String) throws -> [(String, Double)] {
        guard let a = v?.asArray else { throw coded("bad_snapshot", "\(what) is not an array") }
        return try a.map { p in
            guard let x = p.asArray, x.count == 2, let k = nonEmptyStr(x[0]), let t = number(x[1]) else {
                throw coded("bad_snapshot", "\(what) holds an entry that is not [string, number]")
            }
            return (k, t)
        }
    }

    /// `restoreRevocationState`: merge a snapshot into `into`. Strict: any shape error is `bad_snapshot` and `into` is untouched.
    /// Merging is monotone, so restoring never un-revokes anything.
    public static func restoreRevocationState(_ snapshot: JSONValue?, _ into: RevocationState) throws {
        guard let m = snapshot?.asObject, number(m["v"]) == 1 else { throw coded("bad_snapshot", "snapshot is not a version 1 object") }
        if let extra = m.keys.first(where: { !["v", "grants", "agents", "intents"].contains($0.s) }) { throw coded("bad_snapshot", "snapshot has unknown member '\(extra.s)'") }
        let grants = try snapshotPairs(m["grants"], "grants"), agents = try snapshotPairs(m["agents"], "agents"), intents = try snapshotPairs(m["intents"], "intents")
        for (k, t) in grants { into.revokedGrants.recordMax(k, t) }
        for (k, t) in agents { into.killedAgents.recordMax(k, t) }
        for (k, t) in intents {
            var map = into.revokedIntentIds ?? TsMap()
            map.recordMax(k, t)
            into.revokedIntentIds = map
        }
    }
}
