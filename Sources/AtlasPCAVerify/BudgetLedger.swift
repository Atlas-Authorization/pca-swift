import Foundation

// Durable aggregate budgets: the `BudgetLedger` contract, the reference `KvBudgetLedger`, signed and anchored releases, and scoped admission.
//
// CLAIMED: NO OVERSPEND AT PRINCIPAL, ORG AND FLEET SCOPE, given a ledger that is linearizable per key and durable. An accumulator with
// `scope: principal | org | fleet` counts the events of EVERY session and delegated agent of that scope in ONE state keyed by the scope id, so N sessions
// share one cap and a split across sessions or agents buys nothing. A reservation counts as soon as it is made; the ledger refuses one whose post-value
// would pass the accumulator's `domain_max`, inside the same atomic step that records it.
//
// TWO PHASES, THREE STEPS: `reserve` (counted at once), `start` (recorded BEFORE the effect runs), then `commit` (the effect happened) or `release` (it did
// not; a signed event, `signRelease`, that can be anchored in a transparency log, `anchorRelease`). `expire` frees only a reservation that was never started:
// expiry needs no trusted clock. A release that never arrives only OVER-restricts. `admitAggregateAction` refuses (`not_durable`) a ledger whose `durable`
// is not true, and denies `scope_unbound` when the caller names no id for a scope the root uses. Events are objects `{id, verb, resource, params, t, status}`.

/// The aggregate budget ledger contract. Every answer is the reference's object: `{outcome, version, ...}`.
public protocol BudgetLedger: AnyObject {
    var durable: Bool { get }
    /// `{version, events}`.
    func snapshot(_ key: String) throws -> JSONValue
    func reserve(_ key: String, _ req: JSONValue) throws -> JSONValue
    func start(_ key: String, _ id: String) throws -> JSONValue
    func commit(_ key: String, _ id: String) throws -> JSONValue
    /// `evidence` is a signed release (`PCABudgetLedger.signRelease`) or nil: a release carries no evidence unless the caller supplies it.
    func release(_ key: String, _ id: String, _ evidence: JSONValue?) throws -> JSONValue
    func expire(_ key: String, _ now: JSONValue) throws -> JSONValue
}

public enum PCABudgetLedger {
    public static let PREFIX = "pca-budget-ledger/v1/"
    public static let RELEASE_DOMAIN = "atlas-pca/budget-release/v1\u{0}"
    static let RELEASE_REASONS = ["effect_failed", "effect_not_run", "denied_downstream", "rollback"]

    static func err(_ code: String, _ m: String) -> PCAStoreError { PCAStoreError(code, m) }

    /// A ledger key or id: 1 to 256 UTF-16 units, no control characters.
    static func idOk(_ v: JSONValue?) -> Bool { v?.asString.map(idOk) ?? false }
    static func idOk(_ s: String) -> Bool { s.utf16.count > 0 && s.utf16.count <= 256 && !s.unicodeScalars.contains { $0.value <= 0x1F } }

    /// The ledger key of a scope (`principal` | `org` | `fleet`) and its id. Injective: the id is percent-encoded.
    public static func scopeKey(_ scope: String, _ id: String) throws -> String {
        guard idOk(id) else { throw err("invalid", "a scope id is a non-empty string of at most 256 characters without control characters") }
        var out = scope + "/"
        let safe = Set("-_.!~*'()".utf8)
        for b in id.utf8 {
            if (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) || safe.contains(b) { out.append(Character(UnicodeScalar(b))) } else { out += String(format: "%%%02X", Int(b)) }
        }
        return out
    }

    // ---- signed, anchored releases ----

    static func releaseBody(_ r: JSONValue) -> JSONValue {
        var o: JObject = [:]
        for k in ["v", "key", "id", "reason", "at", "signer"] { o[JKey(k)] = r.get(k) ?? .null }
        return .object(o)
    }

    /// A signed statement by the releaser that a reservation's effect did NOT happen (`reason`: effect_failed, effect_not_run, denied_downstream or rollback).
    public static func signRelease(key: String, id: String, reason: String, at: JSONValue, secret: PCAEdKey) throws -> JSONValue {
        guard RELEASE_REASONS.contains(reason), let t = StoreJ.safe(at), idOk(key), idOk(id) else { throw PCAStoreError.range("signRelease: a malformed release") }
        let base: JSONValue = .object(["v": .int(1), "key": .string(key), "id": .string(id), "reason": .string(reason), "at": .int(t), "signer": .string(secret.id)])
        let msg = Canonical.utf8(RELEASE_DOMAIN) + (try Canonical.canonicalBytes(releaseBody(base)))
        var o = base.asObject ?? [:]
        o["sig"] = .string(Base64URLStrict.encode(try secret.sign(msg)))
        return .object(o)
    }

    /// True iff `r` is well formed and signed by `expectedSigner` over exactly its content. Never throws.
    public static func verifyRelease(_ r: JSONValue?, expectedSigner: JSONValue?) -> Bool {
        guard let r = r, r.isObject, IV.num(r.get("v")) == 1, let signer = expectedSigner?.asString, IV.same(r.get("signer")?.asString, signer),
              let reason = r.get("reason")?.asString, RELEASE_REASONS.contains(reason), StoreJ.safe(r.get("at")) != nil, idOk(r.get("key")), idOk(r.get("id")),
              let sig = r.get("sig")?.asString, Base64URLStrict.decode(sig, length: 64) != nil,
              let body = try? Canonical.canonicalBytes(releaseBody(r)) else { return false }
        return Ed25519Strict.verifyB64u(signer, Canonical.utf8(RELEASE_DOMAIN) + body, sig)
    }

    public static func releaseDigest(_ r: JSONValue) -> String { Canonical.hashCanonical(.object(["d": .string("atlas-pca/budget-release-ref/v1"), "r": r])) }

    /// The log leaf of a release.
    public static func releaseCommit(_ r: JSONValue) -> String { Canonical.hashCanonical(.object(["d": .string("atlas-pca/budget-release-leaf/v1"), "digest": .string(releaseDigest(r))])) }

    /// Anchor a signed release in a transparency log store (retries on a position conflict). Answers the leaf index.
    public static func anchorRelease(_ log: LedgerStore, _ r: JSONValue) throws -> Int {
        let commit = releaseCommit(r)
        for _ in 0..<64 {
            let size = try log.size()
            let o = try log.append(.int(Int64(size)), .array([.string(commit)]))
            let outcome = o.get("outcome")?.asString
            if outcome == "appended" || outcome == "replayed" { return size }
        }
        throw err("conflict_exhausted", "could not anchor the release: the log kept moving")
    }

    // ---- scoped admission ----

    /// The ledger key of an accumulator for this admission, or nil when it is session-scoped. Throws `scope_unbound`.
    public static func aggregateKeyOf(_ a: JSONValue, _ ids: JSONValue?) throws -> String? {
        guard let scope = a.get("scope")?.asString, scope != "session" else { return nil }
        guard let i = ids?.get(scope), !i.isNull else {
            throw err("scope_unbound", "accumulator \(a.get("id").map { JS.toString($0) } ?? "undefined") is \(scope)-scoped but no \(scope) id was given")
        }
        guard let s = i.asString else { throw err("invalid", "a scope id is a non-empty string of at most 256 characters without control characters") }
        return try scopeKey(scope, s)
    }

    static func contextState(_ accs: [JSONValue], _ history: [JSONValue], _ cand: JSONValue, _ schema: JSONValue?) throws -> [(String, JSONValue)] {
        var state: [(String, JSONValue)] = []
        let params = cand.get("params")?.asObject ?? [:]
        for a in accs {
            guard let ao = a.asObject, a.get("holder")?.get("kind")?.asString == "site_local" else { continue }
            if let k = ao["key"], !k.isNull, IntentHistory.accKeyOf(ao, params) == nil { continue } // the verifier fails the claim (missing key)
            guard let pre = IntentHistory.accPreState(ao, history, params, cand.get("t"), schema) else { throw JSError("unreadable history") }
            state.append((a.get("id")?.asString ?? "", pre))
        }
        return state
    }

    static func jsNum(_ v: JSONValue?) -> String { IV.num(v).map { JS.number($0) } ?? "undefined" }

    /// Admit one action against every non-session accumulator of the root, atomically per key: read each key's snapshot and compute the pre-states,
    /// `verify(state)` (the host's verifier; answers an object with `allow`), then on allow `reserve` in every key with the snapshot's version. A moved key
    /// repeats from the start; a key over its cap denies and releases what the earlier keys reserved. Refuses (throws `not_durable`) a ledger that is not
    /// durable. Answers `{admitted: true, verdict, reservations, state}` or `{admitted: false, reason, verdict?}`.
    public static func admitAggregateAction(_ ledger: BudgetLedger, ids: JSONValue?, accumulators: [JSONValue], schema: JSONValue? = nil, event: JSONValue,
                                            verify: (JSONValue) throws -> JSONValue, expiresAt: JSONValue? = nil, maxAttempts: Int? = nil) throws -> JSONValue {
        let scoped = accumulators.filter { a in if let s = a.get("scope"), !s.isNull, s.asString != "session" { return true }; return false }
        if !scoped.isEmpty && !ledger.durable { throw err("not_durable", "a principal, org or fleet aggregate needs a durable BudgetLedger (a restart would reset every cap)") }
        var byKey: [(String, [JSONValue])] = []
        do {
            for a in scoped {
                guard let k = try aggregateKeyOf(a, ids) else { continue }
                if let i = byKey.firstIndex(where: { $0.0 == k }) { byKey[i].1.append(a) } else { byKey.append((k, [a])) }
            }
        } catch let e as PCAStoreError where e.code == "scope_unbound" {
            return .object(["admitted": .bool(false), "reason": .string("scope_unbound: \(e)")])
        }
        let keys = byKey.map { $0.0 }.sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
        for _ in 0..<(maxAttempts ?? 256) {
            var snaps: [String: JSONValue] = [:]
            var state: [(String, JSONValue)] = []
            for k in keys {
                let s = try ledger.snapshot(k)
                snaps[k] = s
                for (id, v) in try contextState(byKey.first { $0.0 == k }?.1 ?? [], s.get("events")?.asArray ?? [], event, schema) {
                    if let i = state.firstIndex(where: { $0.0 == id }) { state[i].1 = v } else { state.append((id, v)) }
                }
            }
            var stateObj: JObject = [:]
            for (id, v) in state { stateObj[JKey(id)] = v }
            let verdict = try verify(.object(stateObj))
            if !StoreJ.truthy(verdict.get("allow")) {
                return .object(["admitted": .bool(false), "reason": .string("verifier denied"), "verdict": verdict])
            }
            var done: [JSONValue] = []
            var moved = false
            for k in keys {
                var req: JObject = ["event": event, "accumulators": .array(byKey.first { $0.0 == k }?.1 ?? []), "expectedVersion": snaps[k]?.get("version") ?? .null]
                if let s = schema, !s.isNull { req["schema"] = s }
                if let x = expiresAt, !x.isNull { req["expiresAt"] = x }
                let r = try ledger.reserve(k, .object(req))
                let outcome = r.get("outcome")?.asString
                if outcome == "reserved" || (outcome == "replayed" && r.get("status")?.asString == "reserved") {
                    done.append(.object(["key": .string(k), "id": event.get("id") ?? .null]))
                    continue
                }
                for d in done { _ = try ledger.release(d.get("key")?.asString ?? "", d.get("id")?.asString ?? "", nil) }
                if outcome == "conflict" { moved = true; break }
                let why: String
                if outcome == "over_cap" { why = "over_cap: \(r.get("acc").map { JS.toString($0) } ?? "undefined") would reach \(jsNum(r.get("post"))) (cap \(jsNum(r.get("cap"))))" }
                else if outcome == "replayed" { why = "already \(r.get("status").map { JS.toString($0) } ?? "undefined")" } else { why = outcome ?? "undefined" }
                return .object(["admitted": .bool(false), "reason": .string("aggregate: \(why)"), "verdict": verdict])
            }
            if !moved { return .object(["admitted": .bool(true), "verdict": verdict, "reservations": .array(done), "state": .object(stateObj)]) }
        }
        throw err("conflict_exhausted", "the aggregate kept moving under this admission")
    }

    /// BEFORE the effect: mark every reservation started (non-expirable). False when any is refused (released or expired in the meantime): the effect must NOT
    /// run then.
    public static func startAggregate(_ ledger: BudgetLedger, _ reservations: [JSONValue]) throws -> Bool {
        for r in reservations {
            let o = try ledger.start(r.get("key")?.asString ?? "", r.get("id")?.asString ?? "").get("outcome")?.asString
            if o != "settled" && o != "replayed" { return false }
        }
        return true
    }

    /// After the effect: `committed` (it happened) or `released` (it did not; a signed `evidence` is stored and can be anchored).
    public static func settleAggregate(_ ledger: BudgetLedger, _ reservations: [JSONValue], status: String, evidence: ((JSONValue) -> JSONValue?)? = nil) throws -> [JSONValue] {
        try reservations.map { r in
            let k = r.get("key")?.asString ?? "", id = r.get("id")?.asString ?? ""
            return status == "committed" ? try ledger.commit(k, id) : try ledger.release(k, id, evidence?(r))
        }
    }

    // ---- the pure document transitions ----

    struct Doc { var ver: Int64 = 0; var events: [JObject] = [] }

    static func decode(_ raw: JSONValue?) throws -> Doc {
        guard let r = raw, !r.isNull else { return Doc() }
        guard r.isObject, IV.num(r.get("v")) == 1, let ver = StoreJ.safe(r.get("ver")), let evs = r.get("events")?.asArray,
              evs.allSatisfy({ $0.isObject && $0.get("id")?.asString != nil }) else { throw err("store_corrupt", "budget document has the wrong shape") }
        return Doc(ver: ver, events: evs.compactMap { $0.asObject })
    }

    static func encode(_ d: Doc) -> JSONValue { .object(["v": .int(1), "ver": .int(d.ver), "events": .array(d.events.map { .object($0) })]) }

    private static func sameEvent(_ a: JObject, _ b: JSONValue) -> Bool {
        func k(_ g: (String) -> JSONValue?) -> String {
            Canonical.hashCanonical(.object(["id": g("id") ?? .null, "verb": g("verb") ?? .null, "resource": g("resource") ?? .null, "params": g("params") ?? .null, "t": g("t") ?? .null]))
        }
        return k { a[JKey($0)] } == k { b.get($0) }
    }

    private static func out(_ outcome: String, _ version: Int64, _ extra: JObject = [:]) -> JSONValue {
        var o: JObject = ["outcome": .string(outcome), "version": .int(version)]
        for (k, v) in extra { o[k] = v }
        return .object(o)
    }

    /// Reserve `req.event` in `doc` unless it would pass an accumulator's cap. The pure transition every store is this plus a per-key lock.
    static func reserveInDoc(_ doc: inout Doc, _ req: JSONValue) throws -> JSONValue {
        guard let e = req.get("event"), e.isObject, idOk(e.get("id")), e.get("verb")?.asString != nil, e.get("resource")?.asString != nil, StoreJ.safe(e.get("t")) != nil,
              e.get("params")?.isObject == true || e.get("params")?.isArray == true else { throw PCAStoreError.range("reserve: a malformed event") }
        guard let accs = req.get("accumulators")?.asArray else { throw PCAStoreError.range("reserve: accumulators must be an array") }
        let ev = req.get("expectedVersion"), ex = req.get("expiresAt")
        if let v = ev, !v.isNull, (StoreJ.safe(v) ?? -1) < 0 { throw PCAStoreError.range("reserve: expectedVersion must be a non-negative safe integer") }
        if let v = ex, !v.isNull, StoreJ.safe(v) == nil { throw PCAStoreError.range("reserve: expiresAt must be a safe integer") }
        let id = e.get("id")?.asString ?? ""
        if let prior = doc.events.first(where: { $0[JKey("id")]?.asString == id }) {
            return sameEvent(prior, e) ? out("replayed", doc.ver, ["status": prior[JKey("status")] ?? .null]) : out("id_conflict", doc.ver)
        }
        if let v = ev, !v.isNull, StoreJ.safe(v) != doc.ver { return out("conflict", doc.ver) }
        var post: JObject = [:]
        let verb = e.get("verb")?.asString ?? ""
        for a in accs {
            guard let ao = a.asObject, let cap = ao["domain_max"], !cap.isNull else {
                throw PCAStoreError.range("reserve: accumulator \(a.get("id").map { JS.toString($0) } ?? "undefined") has no domain_max (the cap)")
            }
            if !IntentAcc.selects(ao, verb, req.get("schema")) { continue }
            guard let params = e.get("params")?.asObject, let p = IntentHistory.accPost(ao, doc.events.map { .object($0) }, verb, params, e.get("t"), req.get("schema")) else {
                throw PCAStoreError("store_corrupt", "unreadable history")
            }
            if !(p.isFinite && p <= (IV.num(cap) ?? .nan)) { return out("over_cap", doc.ver, ["acc": ao["id"] ?? .null, "post": StoreJ.num(p), "cap": cap]) }
            post[JKey(ao["id"]?.asString ?? "")] = StoreJ.num(p)
        }
        var entry: JObject = ["id": e.get("id") ?? .null, "verb": e.get("verb") ?? .null, "resource": e.get("resource") ?? .null, "params": e.get("params") ?? .null,
                              "t": e.get("t") ?? .null, "status": .string("reserved")]
        if let x = ex, !x.isNull { entry["exp"] = x }
        doc.events.append(entry)
        doc.ver += 1
        return out("reserved", doc.ver, ["post": .object(post)])
    }

    private static func find(_ doc: Doc, _ id: String) -> Int? { doc.events.firstIndex { $0[JKey("id")]?.asString == id } }

    static func startInDoc(_ doc: inout Doc, _ id: String) -> JSONValue {
        guard let i = find(doc, id) else { return out("unknown", doc.ver) }
        let status = doc.events[i][JKey("status")]?.asString ?? ""
        if status == "released" { return out("refused", doc.ver, ["status": .string(status)]) }
        if doc.events[i][JKey("started")] == .bool(true) || status == "committed" { return out("replayed", doc.ver) }
        doc.events[i][JKey("started")] = .bool(true)
        doc.ver += 1
        return out("settled", doc.ver)
    }

    static func commitInDoc(_ doc: inout Doc, _ id: String) -> JSONValue {
        guard let i = find(doc, id) else { return out("unknown", doc.ver) }
        let status = doc.events[i][JKey("status")]?.asString ?? ""
        if status == "committed" { return out("replayed", doc.ver) }
        if status != "reserved" { return out("refused", doc.ver, ["status": .string(status)]) }
        doc.events[i][JKey("status")] = .string("committed")
        doc.ver += 1
        return out("settled", doc.ver)
    }

    static func releaseInDoc(_ doc: inout Doc, _ key: String, _ id: String, _ evidence: JSONValue?) throws -> JSONValue {
        guard let i = find(doc, id) else { return out("unknown", doc.ver) }
        let status = doc.events[i][JKey("status")]?.asString ?? ""
        if status == "released" { return out("replayed", doc.ver) }
        if status != "reserved" { return out("refused", doc.ver, ["status": .string(status)]) }
        let ev = (evidence?.isNull ?? true) ? nil : evidence
        if let x = ev, !(IV.same(x.get("key")?.asString, key) && IV.same(x.get("id")?.asString, id)) { throw PCAStoreError.range("release: the evidence is for another reservation") }
        doc.events[i][JKey("status")] = .string("released")
        if let x = ev, !(x.asObject?.isEmpty ?? false) { doc.events[i][JKey("rel")] = x }
        doc.ver += 1
        return out("settled", doc.ver)
    }

    static func expireInDoc(_ doc: inout Doc, _ nowV: JSONValue) throws -> JSONValue {
        guard let now = StoreJ.safe(nowV) else { throw PCAStoreError.range("expire: now must be a safe integer") }
        var released: [JSONValue] = []
        for i in doc.events.indices where doc.events[i][JKey("status")]?.asString == "reserved" && doc.events[i][JKey("started")] != .bool(true) {
            guard let exp = IV.num(doc.events[i][JKey("exp")]), exp <= Double(now) else { continue }
            doc.events[i][JKey("status")] = .string("released")
            doc.events[i][JKey("rel")] = .object(["reason": .string("expired"), "at": .int(now)])
            released.append(doc.events[i][JKey("id")] ?? .null)
        }
        if !released.isEmpty { doc.ver += 1 }
        return .object(["released": .array(released), "version": .int(doc.ver)])
    }
}

/// The reference budget ledger: one document per key in an atomic key-value store, so every operation is one atomic read-modify-write. `durable` is declared by
/// the caller (a key-value store cannot tell): true only for a persistent one.
public final class KvBudgetLedger: BudgetLedger, @unchecked Sendable {
    private let kv: AtomicKV
    public let durable: Bool

    public init(kv: AtomicKV, durable: Bool) { self.kv = kv; self.durable = durable }

    private func k(_ key: String) throws -> String {
        guard PCABudgetLedger.idOk(key) else { throw PCAStoreError.range("a ledger key is a non-empty string without control characters") }
        return PCABudgetLedger.PREFIX + key
    }

    private func txn(_ key: String, _ fn: (inout PCABudgetLedger.Doc) throws -> JSONValue, writes: (JSONValue) -> Bool) throws -> JSONValue {
        let full = try k(key)
        var out: JSONValue?
        var failure: Error?
        try kv.update(full) { prev in
            do {
                var d = try PCABudgetLedger.decode(prev)
                let r = try fn(&d)
                out = r
                return writes(r) ? PCABudgetLedger.encode(d) : nil
            } catch { failure = error; return nil }
        }
        if let f = failure { throw f }
        return out ?? .null
    }

    private static func settled(_ r: JSONValue) -> Bool { r.get("outcome")?.asString == "settled" }

    public func snapshot(_ key: String) throws -> JSONValue {
        let d = try PCABudgetLedger.decode(try kv.get(try k(key)))
        return .object(["version": .int(d.ver), "events": .array(d.events.map { .object($0) })])
    }

    public func reserve(_ key: String, _ req: JSONValue) throws -> JSONValue { try txn(key, { try PCABudgetLedger.reserveInDoc(&$0, req) }) { $0.get("outcome")?.asString == "reserved" } }
    public func start(_ key: String, _ id: String) throws -> JSONValue { try txn(key, { PCABudgetLedger.startInDoc(&$0, id) }, writes: KvBudgetLedger.settled) }
    public func commit(_ key: String, _ id: String) throws -> JSONValue { try txn(key, { PCABudgetLedger.commitInDoc(&$0, id) }, writes: KvBudgetLedger.settled) }
    public func release(_ key: String, _ id: String, _ evidence: JSONValue?) throws -> JSONValue {
        try txn(key, { try PCABudgetLedger.releaseInDoc(&$0, key, id, evidence) }, writes: KvBudgetLedger.settled)
    }
    public func expire(_ key: String, _ now: JSONValue) throws -> JSONValue {
        try txn(key, { try PCABudgetLedger.expireInDoc(&$0, now) }) { ($0.get("released")?.asArray?.count ?? 0) > 0 }
    }
}
