import Foundation

/// Revocation registry for PCA capability chains: point revocations (a cap id, a holder key, an issuer key), subtree
/// revocations (a cap-id path prefix), scheduled revocations (`notBefore`), the instant kill-switch, the fail-closed chain
/// check, `verifyWithRevocation` (core result AND not revoked) and the Shared-Signals / CAEP ingest bridge.
///
/// Entries are JSON objects in the reference's shape `{kind, value, prefix?, reason, revokedAt, notBefore?}`; inputs follow
/// JavaScript value semantics (`x ?? default`, `String(x)` keys) so the registry matches the reference exactly.
public enum PCARevoke {
    public static let sessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    public static let grantRevoked = "https://atlasauth.net/caep/grant-revoked"
    public static let killSwitch = "https://atlasauth.net/caep/kill-switch"

    /// `CAEP_EVENT_TYPES` of the reference.
    public static func caepEventTypes() -> JSONValue {
        .object(["sessionRevoked": .string(sessionRevoked), "grantRevoked": .string(grantRevoked), "killSwitch": .string(killSwitch)])
    }

    /// A member of an object; nil for a missing member and for any non-object.
    static func member(_ v: JSONValue?, _ k: String) -> JSONValue? { v?.asObject?[JKey(k)] }
    /// `v.k ?? ...`: absent or null is nil.
    static func nn(_ v: JSONValue?, _ k: String) -> JSONValue? { JS.present(member(v, k)) }
    /// A finite JS number.
    static func finite(_ v: JSONValue?) -> Double? {
        switch v {
        case let .int(i)?: return Double(i)
        case let .double(d)?: return d.isFinite ? d : nil
        default: return nil
        }
    }
    static func nowMs() -> Double { (Date().timeIntervalSince1970 * 1000).rounded(.down) }
    /// `Math.round`: halves round toward +infinity.
    static func jsRound(_ v: Double) -> Double { let f = v.rounded(.down); return v - f >= 0.5 ? f + 1 : f }
    static func num(_ f: Double) -> JSONValue { f.rounded() == f && abs(f) < 9_007_199_254_740_992 ? .int(Int64(f)) : .double(f) }
    static func nonEmpty(_ v: JSONValue?) -> JSONValue? { (v?.asString).flatMap { $0.isEmpty ? nil : v } }

    /// Is the entry in force at `now` (ms)? No `notBefore` always is; a non-finite clock or schedule fails closed (in force).
    public static func isActiveAt(_ entry: JSONValue, _ now: JSONValue?) -> Bool {
        guard let nb = member(entry, "notBefore") else { return true }
        guard let n = finite(now), let b = finite(nb) else { return true }
        return n >= b
    }

    /// A pluggable store keyed by `(kind, value)`; `add` replaces an existing entry in place. Any throw makes the check fail closed.
    public protocol Store: AnyObject {
        func add(_ entry: JSONValue) throws
        func remove(_ kind: String, _ value: String) throws -> Bool
        func get(_ kind: String, _ value: String) throws -> JSONValue?
        func all() throws -> [JSONValue]
        func clear() throws
    }

    /// Insertion-ordered in-memory store (a replaced entry keeps its position, as a JavaScript `Map` does).
    public final class InMemoryStore: Store {
        private var entries: [(key: [UInt8], value: JSONValue)] = []
        private let lock = NSLock()
        public init() {}
        static func storeKey(_ kind: String, _ value: String) -> [UInt8] { Array(kind.utf8) + [0] + Array(value.utf8) }
        public func add(_ entry: JSONValue) throws {
            let key = Self.storeKey(JS.toString(PCARevoke.member(entry, "kind")), JS.toString(PCARevoke.member(entry, "value")))
            lock.lock(); defer { lock.unlock() }
            if let i = entries.firstIndex(where: { $0.key == key }) { entries[i].value = entry } else { entries.append((key, entry)) }
        }
        public func remove(_ kind: String, _ value: String) throws -> Bool {
            let key = Self.storeKey(kind, value)
            lock.lock(); defer { lock.unlock() }
            let n = entries.count
            entries.removeAll { $0.key == key }
            return entries.count != n
        }
        public func get(_ kind: String, _ value: String) throws -> JSONValue? {
            let key = Self.storeKey(kind, value)
            lock.lock(); defer { lock.unlock() }
            return entries.first { $0.key == key }?.value
        }
        public func all() throws -> [JSONValue] { lock.lock(); defer { lock.unlock() }; return entries.map { $0.value } }
        public func clear() throws { lock.lock(); defer { lock.unlock() }; entries.removeAll() }
    }

    public final class Registry {
        public let store: Store
        public init(_ store: Store = InMemoryStore()) { self.store = store }

        /// Record a revocation (`{kind: cap|holder|issuer, value}` or `{kind: prefix, prefix: [cap ids]}`, plus `reason?`,
        /// `revokedAt?` (default now, ms), `notBefore?`). Returns the stored entry.
        @discardableResult
        public func revoke(_ input: JSONValue) throws -> JSONValue {
            if input.isNull { throw JSError("revoke: input is required") }
            let revokedAt = nn(input, "revokedAt") ?? num(nowMs())
            let reason = nn(input, "reason") ?? .string("")
            if finite(revokedAt) == nil { throw JSError("revoke: revokedAt must be a finite number") }
            let notBefore = member(input, "notBefore")
            if notBefore != nil && finite(notBefore) == nil { throw JSError("revoke: notBefore must be a finite number") }
            if reason.asString == nil { throw JSError("revoke: reason must be a string") }
            let kind = member(input, "kind")
            var e: JObject = [:]
            if kind?.asString == "prefix" {
                guard let p = member(input, "prefix")?.asArray, !p.isEmpty else { throw JSError("revoke: a prefix revocation requires a non-empty cap-id path") }
                // the path is serialized with ',': an element holding one would alias a different path
                if p.contains(where: { $0.asString.map { $0.isEmpty || $0.contains(",") } ?? true }) {
                    throw JSError("revoke: every prefix element must be a non-empty string without ','")
                }
                e["kind"] = .string("prefix")
                e["value"] = .string(JS.toString(.array(p)))
                e["prefix"] = .array(p)
            } else {
                guard let value = member(input, "value")?.asString, !value.isEmpty else {
                    throw JSError("revoke: a \(JS.toString(kind)) revocation requires a non-empty value")
                }
                if let k = kind { e["kind"] = k }
                e["value"] = .string(value)
            }
            e["reason"] = reason
            e["revokedAt"] = revokedAt
            if let nb = notBefore { e["notBefore"] = nb }
            let entry = JSONValue.object(e)
            try store.add(entry)
            return entry
        }

        /// Revoke a cap id (a string target) or a cap-id path prefix (an array target) and everything below it.
        @discardableResult
        public func revokeSubtree(_ target: JSONValue, _ opts: JSONValue? = nil) throws -> JSONValue {
            var input: JObject = target.isArray ? ["kind": .string("prefix"), "prefix": target] : ["kind": .string("cap"), "value": target]
            if let o = opts?.asObject { for (k, v) in o { input[k] = v } }
            return try revoke(.object(input))
        }

        /// Remove a revocation by key; false when there was none.
        public func unrevoke(_ key: JSONValue) throws -> Bool {
            if key.isNull { throw JSError("unrevoke: key is required") }
            let kind = member(key, "kind")
            if kind?.asString == "prefix" {
                guard let p = member(key, "prefix"), let a = p.asArray, !a.isEmpty else { return false }
                return try store.remove("prefix", JS.toString(p))
            }
            return try store.remove(JS.toString(kind), JS.toString(member(key, "value")))
        }

        public func list() throws -> [JSONValue] { try store.all() }
        public func lookup(_ kind: String, _ value: String) throws -> JSONValue? { try store.get(kind, value) }
        public func prefixes() throws -> [JSONValue] { try store.all().filter { member($0, "kind")?.asString == "prefix" } }
        public func clear() throws { try store.clear() }

        private func kill(_ kind: String, _ value: JSONValue, _ opts: JSONValue?, _ defaultReason: String) throws -> JSONValue {
            var input: JObject = ["kind": .string(kind), "value": value, "reason": nn(opts, "reason") ?? .string(defaultReason)]
            if let at = member(opts, "revokedAt") { input["revokedAt"] = at }
            return try revoke(.object(input))
        }

        /// Kill-switch: revoke every capability held by `holder`, instantly (no `notBefore`).
        @discardableResult
        public func killAgent(_ holder: JSONValue, _ opts: JSONValue? = nil) throws -> JSONValue { try kill("holder", holder, opts, "kill-switch: agent killed") }
        /// Kill-switch: revoke the subtree rooted at a capability id, instantly.
        @discardableResult
        public func killSubtree(_ root: JSONValue, _ opts: JSONValue? = nil) throws -> JSONValue { try kill("cap", root, opts, "kill-switch: subtree killed") }
    }

    private static func matchReason(_ e: JSONValue) -> String {
        let base = "\(JS.toString(member(e, "kind"))) \(JS.toString(member(e, "value"))) is revoked"
        if let r = member(e, "reason")?.asString, !r.isEmpty { return "\(base): \(r)" }
        return base
    }

    private static func hit(_ e: JSONValue) -> JSONValue { .object(["revoked": .bool(true), "matched": e, "reason": .string(matchReason(e))]) }

    private static func scan(_ chain: [JSONValue], _ reg: Registry, _ now: JSONValue) throws -> JSONValue {
        var ids: [JSONValue] = []
        for hop in chain {
            for kind in ["cap", "issuer", "holder"] {
                let key = member(hop, kind == "cap" ? "id" : kind)?.asString ?? ""
                if let e = try reg.lookup(kind, key), isActiveAt(e, now) { return hit(e) }
            }
            ids.append(member(hop, "id") ?? .null)
        }
        for e in try reg.prefixes() {
            if let p = member(e, "prefix")?.asArray, !p.isEmpty, ids.count >= p.count, zip(p, ids).allSatisfy({ $0 == $1 }), isActiveAt(e, now) { return hit(e) }
        }
        return .object(["revoked": .bool(false)])
    }

    /// Is any hop of the action's chain revoked (cap id, issuer, holder per hop root to leaf, then subtree prefixes)? Never throws
    /// and never reports "not revoked" because it could not look: a non-finite clock, a missing / empty chain, a hop without
    /// id / issuer / holder, or a store error all yield `revoked: true`.
    public static func checkRevocation(_ p: JSONValue?, _ reg: Registry, _ opts: JSONValue? = nil) -> JSONValue {
        func closed(_ why: String) -> JSONValue { .object(["revoked": .bool(true), "reason": .string("revocation check failed closed: \(why)")]) }
        let now = nn(opts, "now") ?? num(nowMs())
        if finite(now) == nil { return closed("clock is not a finite number") }
        guard let chain = member(p, "cap_chain")?.asArray, !chain.isEmpty else { return closed("the action carries no capability chain") }
        for hop in chain {
            for k in ["id", "issuer", "holder"] where (member(hop, k)?.asString ?? "").isEmpty { return closed("a chain hop has no \(k)") }
        }
        do { return try scan(chain, reg, now) } catch { return closed("the revocation store failed (Error)") }
    }

    /// The core verify result (`{allow, reason?}`) AND the revocation check: `{allow, coreAllow, revocation, reason?}`.
    public static func verifyWithRevocation(_ p: JSONValue?, _ core: JSONValue?, _ reg: Registry, _ opts: JSONValue? = nil) -> JSONValue {
        let coreAllow = member(core, "allow") == .bool(true)
        let revocation = checkRevocation(p, reg, opts)
        let revoked = revocation.get("revoked") == .bool(true)
        let allow = coreAllow && !revoked
        var out: JObject = ["allow": .bool(allow), "coreAllow": .bool(coreAllow), "revocation": revocation]
        if !allow {
            out["reason"] = !coreAllow ? (nn(core, "reason") ?? .string("core verification failed")) : (nn(revocation, "reason") ?? .string("revoked"))
        }
        return .object(out)
    }

    private static func revokedAtFrom(_ ts: JSONValue?) -> JSONValue { num(finite(ts).map { jsRound($0 * 1000) } ?? nowMs()) }

    /// Ingest a CAEP / Shared-Signals event (`{type, payload}`): grant-revoked -> cap, kill-switch -> holder (+ cap), anything else
    /// is read as session-revoked -> holder (`subject.holder ?? agent ?? id`). Returns the entries added.
    public static func ingestCaepEvent(_ event: JSONValue, _ reg: Registry) throws -> [JSONValue] {
        if event.isNull { throw JSError("ingestCaepEvent: event is required") }
        let ty = member(event, "type")?.asString
        guard let ev = nn(event, "payload") else { throw JSError("ingestCaepEvent: the event has no payload") }
        var added: [JSONValue] = []
        func reason(_ k: String, _ d: String) -> JSONValue { nn(ev, k) ?? .string(d) }
        if ty == grantRevoked {
            if let g = nonEmpty(member(ev, "grant_ref")) {
                added.append(try reg.revoke(.object(["kind": .string("cap"), "value": g, "reason": reason("reason", "CAEP grant-revoked"),
                                                     "revokedAt": revokedAtFrom(member(ev, "event_timestamp"))])))
            }
        } else if ty == killSwitch {
            let at = revokedAtFrom(member(ev, "event_timestamp"))
            if let a = nonEmpty(member(ev, "agent")) {
                added.append(try reg.killAgent(a, .object(["reason": reason("reason", "CAEP kill-switch"), "revokedAt": at])))
            }
            if let g = nonEmpty(member(ev, "grant_ref")) {
                added.append(try reg.revoke(.object(["kind": .string("cap"), "value": g, "reason": reason("reason", "CAEP kill-switch"), "revokedAt": at])))
            }
        } else {
            let subject = member(ev, "subject")
            if subject == .null { throw JSError("ingestCaepEvent: subject is null") }
            func field(_ k: String) -> JSONValue? { nonEmpty(member(subject, k)) }
            if let h = field("holder") ?? field("agent") ?? field("id") {
                let why = nn(ev, "reason_admin") ?? nn(ev, "reason_user") ?? .string("CAEP session-revoked")
                added.append(try reg.killAgent(h, .object(["reason": why, "revokedAt": revokedAtFrom(member(ev, "event_timestamp"))])))
            }
        }
        return added
    }
}
