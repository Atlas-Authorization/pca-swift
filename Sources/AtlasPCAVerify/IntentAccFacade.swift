import Foundation

/// The signing and digest half of the accumulator receipts and the sequencer key sets, and the small helpers around them: monitor states, distinct keys,
/// content addresses. A receipt is the sequencer's signed statement of one accumulator step; a key set is the root-signed list of the sequencer's signing keys.
public enum PCAIntentAcc {
    public static let ACC_AGGS = ["sum", "count", "distinct", "max"]
    public static let ACC_SCOPES = ["session", "principal", "org", "fleet"]
    public static let MONITOR_KINDS = ["requires_prior", "precedes", "never", "always", "responds_within"]
    public static let ACC_ID_RE = "^[A-Za-z0-9_]{1,64}$"
    public static let KID_RE = "^[A-Za-z0-9_.:-]{1,64}$"
    public static let MAX_SESSION_ACCUMULATORS = 16
    public static let MAX_SESSION_MONITORS = 16
    public static let MAX_MONITOR_WITHIN = 64
    public static let ACC_RECEIPT_DOMAIN = IntentAcc.RECEIPT_DOMAIN
    public static let ACC_RECEIPT_REF_DOMAIN = IntentAcc.RECEIPT_REF_DOMAIN
    public static let ACC_RECEIPT_CORE_DOMAIN = "atlas-pca/acc-receipt-core/v1"
    public static let ACC_RESERVE_DOMAIN = IntentAcc.RESERVE_DOMAIN
    public static let SEQUENCER_KEYS_DOMAIN = IntentAcc.SEQUENCER_KEYS_DOMAIN
    public static let SEQUENCER_KEYS_REF_DOMAIN = IntentAcc.SEQUENCER_KEYS_REF_DOMAIN
    public static let RECEIPT_SKEW_MS = 60_000
    public static let MAX_RECEIPT_LIFETIME_MS = 900_000
    public static let DEFAULT_MAX_RECEIPT_AGE_MS = 900_000
    public static let DEFAULT_MAX_KEYSET_AGE_MS = 3_600_000
    public static let EVENT_STATUSES = ["reserved", "committed", "released", "reverted"]
    public static let COUNTED_STATUSES = ["reserved", "committed"]

    /// The state set of a monitor; nil for an unknown kind.
    public static func monitorStates(_ m: JSONValue?) -> [String]? {
        guard let kind = m?.get("kind")?.asString, MONITOR_KINDS.contains(where: { IV.same($0, kind) }) else { return nil }
        return IntentAcc.monitorStates(m!)
    }

    /// `unmet`, `clean`, `ok` or `idle` by kind.
    public static func monitorInitialState(_ m: JSONValue?) -> String { IntentHistory.monitorInitialState(m?.asObject ?? [:]) }

    /// The strict canonical JSON text of a string or a safe integer; nil for anything else (or a string outside the strict profile).
    public static func distinctKey(_ x: JSONValue?) -> String? { IntentAcc.distinctKey(x) }

    /// The distinct strings in UTF-8 order.
    public static func sortedDistinct(_ keys: [String]) -> [String] {
        var out: [String] = []
        for k in keys where !out.contains(where: { IV.same($0, k) }) { out.append(k) }
        return out.sorted { IV.utf8Less($0, $1) }
    }

    private static func sign(_ domain: String, _ base: JObject, _ key: PCASuiteKey) throws -> JObject {
        var bound = base
        if key.alg != "ed25519" {
            bound["alg"] = .string(key.alg)
            bound["pq_pk"] = key.pqPk.map { .string($0) } ?? .null
        }
        guard let msg = IV.message(domain, .object(bound)) else { throw JSError("canonicalize: value out of profile") }
        let parts = try key.sign(msg)
        bound["sig"] = .string(parts.sig)
        if let q = parts.pqSig { bound["pq_sig"] = .string(q) }
        return bound
    }

    /// The sequencer's signed receipt of one accumulator step: the body plus `signer` (the secret's public key) and the suite members, refused unless it passes the
    /// receipt shape check. Arithmetic is not checked here (the verifier recomputes it).
    public static func signAccReceipt(_ body: JSONValue, key: PCASuiteKey, secret: [UInt8]) throws -> JSONValue {
        guard case var .object(b) = body else { throw JSError("body must be an object") }
        b["signer"] = .string(PCAIntentArtifacts.publicKeyB64u(secret))
        let out = try sign(IntentAcc.RECEIPT_DOMAIN, IntentAcc.receiptBody(b), key)
        if let bad = IntentAcc.receiptShapeError(.object(out)) { throw JSError("signAccReceipt: \(bad)") }
        return .object(out)
    }

    /// A receipt's signature under the expected signer; `pin` is `{pqPins: {signer: pqPk}}`. A post-quantum half verifies only under a pinned key.
    public static func verifyAccReceiptSignature(_ r: JSONValue?, expectedSigner: String, pin: JSONValue? = nil) -> Bool {
        guard let r = r else { return false }
        let pq = pin?.get("pqPins")?.get(expectedSigner)?.asString
        return IntentAcc.verifyReceiptSignature(r, expectedSigner: expectedSigner, pin: pq) == .valid
    }

    /// A receipt's content address.
    public static func accReceiptDigest(_ r: JSONValue) throws -> String {
        if let e = IV.strictCanonError(.object(["d": .string(IntentAcc.RECEIPT_REF_DOMAIN), "r": r])) { throw JSError(e) }
        guard let h = IntentAcc.receiptDigest(r) else { throw JSError("canonicalize: value out of profile") }
        return h
    }

    /// The receipt's log-leaf content: the receipt without its ledger position, key id, signer and signature fields.
    public static func accReceiptCoreDigest(_ r: JSONValue) throws -> String {
        var core: JObject = [:]
        for k in ["v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at"] { if let v = r.get(k) { core[JKey(k)] = v } }
        let v: JSONValue = .object(["d": .string(ACC_RECEIPT_CORE_DOMAIN), "r": .object(core)])
        if let e = IV.strictCanonError(v) { throw JSError(e) }
        guard let h = IV.strictHash(v) else { throw JSError("canonicalize: value out of profile") }
        return h
    }

    /// The root-signed list of the sequencer's signing keys (extra top-level members are dropped), refused unless it passes the key-set shape check.
    public static func signSequencerKeySet(_ body: JSONValue, key: PCASuiteKey, rootSecret: [UInt8]) throws -> JSONValue {
        guard case let .object(b) = body else { throw JSError("body must be an object") }
        var base: JObject = [:]
        for k in ["v", "kind"] { if let v = b[JKey(k)] { base[JKey(k)] = v } }
        base["sequencer"] = .string(PCAIntentArtifacts.publicKeyB64u(rootSecret))
        for k in ["version", "issued_at", "keys"] { if let v = b[JKey(k)] { base[JKey(k)] = v } }
        let out = try sign(IntentAcc.SEQUENCER_KEYS_DOMAIN, base, key)
        if let bad = IntentAcc.keySetShapeError(.object(out)) { throw JSError("signSequencerKeySet: \(bad)") }
        return .object(out)
    }

    /// A key set's signature under the pinned root (and the root's pinned post-quantum key).
    public static func verifySequencerKeySet(_ k: JSONValue?, root: String, rootPqPk: JSONValue? = nil) -> Bool {
        guard let k = k else { return false }
        return IntentAcc.verifyKeySet(k, root: root, rootPqPk: rootPqPk) == .valid
    }

    /// A key set's content address.
    public static func sequencerKeySetDigest(_ ks: JSONValue) throws -> String {
        let v: JSONValue = .object(["d": .string(IntentAcc.SEQUENCER_KEYS_REF_DOMAIN), "k": ks])
        if let e = IV.strictCanonError(v) { throw JSError(e) }
        guard let h = IV.strictHash(v) else { throw JSError("canonicalize: value out of profile") }
        return h
    }
}

/// One session's event log inside the store's lock.
public protocol PCAIntentSessionTx {
    func events() throws -> [JSONValue]
    func append(_ e: JSONValue) throws
    /// false when the event is not there.
    func setStatus(_ id: String, _ status: String) throws -> Bool
}

/// The host's session store: one lock per session. A restart that forgets the events resets every cap, so admission requires a store that says it is durable.
public protocol PCAIntentSessionStore {
    var durable: Bool? { get }
    func withSession<T>(_ session: String, _ fn: (PCAIntentSessionTx) throws -> T) throws -> T
}

public enum PCAIntentHistory {
    /// The pre-state of every site-local accumulator and the state of every monitor, from the session's history. An accumulator whose grouping key the candidate
    /// lacks is left out (the verifier fails that claim); a history that cannot be read throws (fail closed).
    public static func accContextFor(_ root: JSONValue?, _ history: [JSONValue], _ cand: JSONValue?, _ schema: JSONValue? = nil) throws -> JSONValue {
        guard let params = cand?.get("params")?.asObject else { throw JSError("accContextFor: the candidate params must be an object") }
        var state: JObject = [:], monitors: JObject = [:]
        for av in root?.get("accumulators")?.asArray ?? [] {
            guard let a = av.asObject, let id = a["id"]?.asString else { throw JSError("accContextFor: malformed accumulator") }
            if !IV.same(a["holder"]?.get("kind")?.asString, "site_local") { continue }
            if a["key"]?.asString != nil, IntentHistory.accKeyOf(a, params) == nil { continue }
            guard let pre = IntentHistory.accPreState(a, history, params, cand?.get("t"), schema) else { throw JSError("accPreState: the history is unreadable (fail closed)") }
            state[JKey(id)] = pre
        }
        for mv in root?.get("monitors")?.asArray ?? [] {
            guard let m = mv.asObject, let id = m["id"]?.asString else { throw JSError("accContextFor: malformed monitor") }
            monitors[JKey(id)] = .string(IntentHistory.monitorState(m, history))
        }
        return .object(["state": .object(state), "monitors": .object(monitors)])
    }

    /// Admission through the session store: reads the history, computes the pre-state, lets `verify` decide, and reserves the event only on an allow, all inside
    /// the store's lock. A store that does not say it is durable is refused unless `requireDurable` is false.
    public static func admitIntentAction<V>(store: PCAIntentSessionStore, session: String, root: JSONValue?, schema: JSONValue? = nil, event: JSONValue, requireDurable: Bool = true,
                                            verify: (JSONValue) throws -> V, allow: (V) -> Bool) throws -> V {
        if requireDurable && store.durable != true {
            throw JSError("admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore")
        }
        return try store.withSession(session) { tx in
            let acc = try accContextFor(root, try tx.events(), event, schema)
            let v = try verify(acc)
            if allow(v), case var .object(e) = event { e["status"] = .string("reserved"); try tx.append(.object(e)) }
            return v
        }
    }

    /// Settles an event as committed, released or reverted; false when it is not there.
    public static func settleIntentEvent(store: PCAIntentSessionStore, session: String, id: String, status: String) throws -> Bool {
        try store.withSession(session) { try $0.setStatus(id, status) }
    }
}
