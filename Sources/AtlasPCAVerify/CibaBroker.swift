import Foundation

/// A versioned stored value; `version` counts successful writes (0 = absent, never stored).
public struct CibaVersioned: Sendable {
    public let version: Int
    public let value: JSONValue
    public init(version: Int, value: JSONValue) { self.version = version; self.value = value }
}

/// Persistence seam of the approval broker: a JSON key-value store with compare-and-set. `cas` writes only if the stored version
/// equals `expectedVersion` (0 = the key must be absent) and reports whether it wrote. Back it with a row version
/// (`UPDATE ... WHERE version = ?`) for several processes. A throw means "no approval" to the broker.
public protocol CibaApprovalStore: AnyObject {
    func get(_ key: String) throws -> CibaVersioned?
    func cas(_ key: String, _ expectedVersion: Int, _ value: JSONValue) throws -> Bool
}

/// A durable string key-value store with ONE primitive, compare-and-swap on a string (`expected` nil = the key must be absent).
/// Must be atomic across every process sharing it and durable before it returns; any failure throws.
public protocol CibaDurableKv: AnyObject {
    func get(_ key: String) throws -> String?
    func putIfEquals(_ key: String, _ expected: String?, _ next: String) throws -> Bool
}

/// The broker's view of a flow (status computed at read time, never a stale stored flag).
public struct CibaSession: Sendable {
    public enum Status: String, Sendable { case pending, approved, denied, expired }
    public let authReqId: String
    /// The CIBA auth request (`PCACiba.toCibaAuthRequest` output).
    public let request: JSONValue
    public let status: Status
    /// ms epoch.
    public let createdAt: Double
    public let expiresAt: Double
    public let decidedBy: String?
    public let decidedAt: Double?

    public var json: JSONValue {
        var o: JObject = [
            "auth_req_id": .string(authReqId), "request": request, "status": .string(status.rawValue),
            "createdAt": .double(createdAt), "expiresAt": .double(expiresAt),
        ]
        if let b = decidedBy { o["decidedBy"] = .string(b) }
        if let t = decidedAt { o["decidedAt"] = .double(t) }
        return .object(o)
    }
}

/// What the token endpoint gets back (CIBA Core 10.1 / 11): the session exactly once on approval, else the OAuth error and the
/// current minimum poll spacing in seconds (grown by 5 after `slow_down`).
public enum CibaTokenOutcome: Sendable {
    case ok(CibaSession)
    case error(String, interval: Int)

    public var json: JSONValue {
        switch self {
        case let .ok(s): return .object(["ok": .bool(true), "session": s.json])
        case let .error(e, i): return .object(["ok": .bool(false), "error": .string(e), "interval": .int(Int64(i))])
        }
    }
}

/// The CIBA approval broker over a `CibaApprovalStore`: `start` opens (or re-serves) a flow, `poll` is a side-effect-free status
/// read, `token` has token-endpoint semantics (interval / `slow_down`, single-use approval), `resolve` records the human's decision.
/// Every state change is one compare-and-set, so a restart or a second process cannot lose, double-apply or replay a decision.
///
/// `PCACibaBroker.memory()` is the in-process test double (no decision expiry); `PCACibaBroker.durable(store:)` is the production
/// shape (an approval is redeemable for `decisionTtlSec`, default 300). Both refuse an empty decider and never re-serve a consumed
/// approval on `start`.
public final class PCACibaBroker: @unchecked Sendable {
    public enum Decision: String, Sendable { case approve, deny }

    let store: CibaApprovalStore
    let clock: () -> Double
    let ttlMs: Double?
    let onComplete: ((CibaSession) throws -> Void)?
    /// The in-process double reports a notifier's failure to the caller (after the decision is recorded); the durable broker never lets a failing notifier hide the decision.
    let reportsNotifierFailure: Bool
    static let MAX_CAS_TRIES = 8

    public init(store: CibaApprovalStore, now: @escaping () -> Double = { Date().timeIntervalSince1970 * 1000 }, decisionTtlSec: Double?,
                onComplete: ((CibaSession) throws -> Void)? = nil, reportsNotifierFailure: Bool = false) throws {
        if let t = decisionTtlSec, !(t.isFinite && t > 0) { throw JSError("createDurableCibaBroker: decisionTtlSec must be a positive number") }
        self.store = store
        self.clock = now
        self.ttlMs = decisionTtlSec.map { $0 * 1000 }
        self.onComplete = onComplete
        self.reportsNotifierFailure = reportsNotifierFailure
    }

    /// In-process broker (test double): loses everything on restart; an approval does not expire.
    public static func memory(now: @escaping () -> Double = { Date().timeIntervalSince1970 * 1000 }, onComplete: ((CibaSession) throws -> Void)? = nil) -> PCACibaBroker {
        // a nil ttl never throws
        try! PCACibaBroker(store: CibaMemoryApprovalStore(), now: now, decisionTtlSec: nil, onComplete: onComplete, reportsNotifierFailure: true)
    }

    /// Durable broker over `store`.
    public static func durable(store: CibaApprovalStore, now: @escaping () -> Double = { Date().timeIntervalSince1970 * 1000 }, decisionTtlSec: Double = 300,
                               onComplete: ((CibaSession) throws -> Void)? = nil) throws -> PCACibaBroker {
        try PCACibaBroker(store: store, now: now, decisionTtlSec: decisionTtlSec, onComplete: onComplete)
    }

    struct Rec {
        var request: JSONValue
        var authReqId: String
        var createdAt: Double
        var expiresAt: Double
        var interval: Double
        var decision: Decision?
        var decidedBy: String?
        var decidedAt: Double?
        var lastPollAt: Double?
        var consumed = false

        init(request: JSONValue, authReqId: String, createdAt: Double, expiresAt: Double, interval: Double) {
            self.request = request
            self.authReqId = authReqId
            self.createdAt = createdAt
            self.expiresAt = expiresAt
            self.interval = interval
        }

        /// A stored record; anything malformed throws (fail closed).
        init(json v: JSONValue) throws {
            func fin(_ k: String) -> Double? { IV.num(v.get(k)).flatMap { $0.isFinite ? $0 : nil } }
            guard let req = v.get("request"), let id = req.get("auth_req_id")?.asString, let c = fin("createdAt"), let e = fin("expiresAt"),
                  let i = fin("interval") else { throw JSError("ciba: stored approval record is malformed") }
            self.init(request: req, authReqId: id, createdAt: c, expiresAt: e, interval: i)
            if let d = v.get("decision"), d != .null {
                guard let s = d.asString, let dd = Decision(rawValue: s), let at = fin("decidedAt") else { throw JSError("ciba: stored approval record is malformed") }
                decision = dd
                decidedAt = at
            }
            decidedBy = v.get("decidedBy")?.asString
            lastPollAt = fin("lastPollAt")
            consumed = v.get("consumed") == .bool(true)
        }

        var json: JSONValue {
            var o: JObject = ["request": request, "createdAt": .double(createdAt), "expiresAt": .double(expiresAt), "interval": .double(interval)]
            if let d = decision { o["decision"] = .string(d.rawValue) }
            if let b = decidedBy { o["decidedBy"] = .string(b) }
            if let t = decidedAt { o["decidedAt"] = .double(t) }
            if let t = lastPollAt { o["lastPollAt"] = .double(t) }
            if consumed { o["consumed"] = .bool(true) }
            return .object(o)
        }
    }

    func status(_ r: Rec, _ now: Double) -> CibaSession.Status {
        switch r.decision {
        case .deny?: return .denied
        case .approve?:
            if let ttl = ttlMs, !(now.isFinite && now < (r.decidedAt ?? 0) + ttl) { return .expired }
            return .approved
        case nil: return now.isFinite && now < r.expiresAt ? .pending : .expired
        }
    }

    func snap(_ r: Rec, _ now: Double) -> CibaSession {
        CibaSession(authReqId: r.authReqId, request: r.request, status: status(r, now), createdAt: r.createdAt, expiresAt: r.expiresAt,
                    decidedBy: r.decidedBy, decidedAt: r.decidedAt)
    }

    func load(_ id: String) throws -> (rec: Rec, version: Int)? {
        guard let v = try store.get("a:" + id) else { return nil }
        return (try Rec(json: v.value), v.version)
    }

    /// Read-modify-write with CAS retry; `fn` returns the new record (nil = no write) and the result.
    func mutate<T>(_ id: String, _ fn: (Rec?, Double) throws -> (Rec?, T)) throws -> T {
        for _ in 0..<Self.MAX_CAS_TRIES {
            let cur = try load(id)
            let (next, out) = try fn(cur?.rec, clock())
            guard let n = next else { return out }
            if try store.cas("a:" + id, cur?.version ?? 0, n.json) { return out }
        }
        throw JSError("ciba: approval store contention, gave up")
    }

    static func randomId() -> String {
        var g = SystemRandomNumberGenerator()
        return Base64URLStrict.encode((0..<20).map { _ in UInt8.random(in: 0...255, using: &g) })
    }

    /// Begin a backchannel flow (a fresh 160-bit random auth_req_id). A flow of the same step-up that is still pending, or approved
    /// and not yet redeemed, is returned instead: restarting it would discard a decision.
    public func start(_ stepUp: JSONValue, _ opts: JObject = [:]) throws -> JSONValue {
        let liveKey = "s:" + JS.toString(stepUp.get("id"))
        for _ in 0..<Self.MAX_CAS_TRIES {
            let now = clock()
            let idx = try store.get(liveKey)
            if let i = idx, let ex = try load(JS.toString(i.value)) {
                let st = status(ex.rec, now)
                if (st == .pending || st == .approved) && !ex.rec.consumed { return ex.rec.request }
            }
            var o = opts
            o["authReqId"] = .string(Self.randomId())
            let request = try PCACiba.toCibaAuthRequest(stepUp, o)
            guard let id = request.get("auth_req_id")?.asString, let exp = IV.num(request.get("requested_expiry")),
                  let interval = IV.num(request.get("interval")) else { throw JSError("ciba: malformed auth request") }
            let rec = Rec(request: request, authReqId: id, createdAt: now, expiresAt: now + exp * 1000, interval: interval)
            if !(try store.cas("a:" + id, 0, rec.json)) { continue }
            if try store.cas(liveKey, idx?.version ?? 0, .string(id)) { return request }
        }
        throw JSError("ciba: approval store contention, gave up")
    }

    /// POLL: the current status (a read; throws for an unknown id).
    public func poll(_ id: String) throws -> CibaSession.Status {
        guard let c = try load(id) else { throw JSError("ciba: unknown auth_req_id \(id)") }
        return status(c.rec, clock())
    }

    /// Token-endpoint semantics (CIBA Core 11): a request sooner than `interval` after the previous one gets `slow_down` (interval
    /// +5 s); an approval is redeemable once (a replay gets `invalid_grant`).
    public func token(_ id: String) throws -> CibaTokenOutcome {
        try mutate(id) { r, now in
            guard var r = r else { return (nil, .error("invalid_grant", interval: PCACiba.DEFAULT_INTERVAL_SEC)) }
            if r.consumed { return (nil, .error("invalid_grant", interval: Int(r.interval))) }
            let tooSoon = r.lastPollAt.map { now - $0 < r.interval * 1000 } ?? false
            r.lastPollAt = now
            if tooSoon {
                r.interval += 5
                return (r, .error("slow_down", interval: Int(r.interval)))
            }
            switch status(r, now) {
            case .pending: return (r, .error("authorization_pending", interval: Int(r.interval)))
            case .denied: return (r, .error("access_denied", interval: Int(r.interval)))
            case .expired: return (r, .error("expired_token", interval: Int(r.interval)))
            case .approved:
                r.consumed = true
                return (r, .ok(snap(r, now)))
            }
        }
    }

    /// The human acts out of band. `by` is the authenticated decider (required). Refused unless the flow is pending. Calls
    /// `onComplete` (PING/PUSH) after the decision is durably recorded.
    public func resolve(_ id: String, _ decision: Decision, by: String) throws -> CibaSession {
        if by.isEmpty { throw JSError("ciba: `by` (the authenticated decider) is required") }
        let s: CibaSession = try mutate(id) { r, now in
            guard var r = r else { throw JSError("ciba: unknown auth_req_id \(id)") }
            let cur = status(r, now)
            if cur != .pending { throw JSError("ciba: cannot resolve \(id) — already \(cur.rawValue)") }
            r.decision = decision
            r.decidedBy = by
            r.decidedAt = now
            return (r, snap(r, now))
        }
        if reportsNotifierFailure { try onComplete?(s) } else { _ = try? onComplete?(s) }
        return s
    }

    /// A session snapshot, or nil for an unknown id.
    public func get(_ id: String) throws -> CibaSession? {
        try load(id).map { snap($0.rec, clock()) }
    }
}

// MARK: - stores

/// Single-process approval store (test double; not durable).
public final class CibaMemoryApprovalStore: CibaApprovalStore, @unchecked Sendable {
    private var m: [String: CibaVersioned] = [:]
    private let lock = NSLock()
    public init() {}
    public func get(_ key: String) throws -> CibaVersioned? { lock.lock(); defer { lock.unlock() }; return m[key] }
    public func cas(_ key: String, _ expectedVersion: Int, _ value: JSONValue) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        if (m[key]?.version ?? 0) != expectedVersion { return false }
        m[key] = CibaVersioned(version: expectedVersion + 1, value: value)
        return true
    }
}

enum CibaFiles {
    /// Raw stored strings compare byte for byte (Swift String == is canonical equivalence).
    static func sameBytes(_ a: String?, _ b: String?) -> Bool { a.map { Array($0.utf8) } == b.map { Array($0.utf8) } }

    static func read(_ path: String) throws -> String? {
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        guard let d = FileManager.default.contents(atPath: path) else { throw JSError("ciba: cannot read \(path)") }
        return String(decoding: d, as: UTF8.self)
    }

    /// Writes `text` to a 0600 temp file, fsyncs it, and renames it over `path` (atomic replace).
    static func replace(_ path: String, _ text: String) throws {
        let tmp = "\(path).\(getpid()).tmp"
        let fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        if fd < 0 { throw JSError("ciba: cannot write \(tmp)") }
        let bytes = Array(text.utf8)
        var off = 0
        while off < bytes.count {
            let n = bytes[off...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if n <= 0 { close(fd); throw JSError("ciba: write failed") }
            off += n
        }
        let synced = fsync(fd) == 0
        close(fd)
        if !synced || rename(tmp, path) != 0 { throw JSError("ciba: cannot replace \(path)") }
    }

    static func versioned(_ raw: String) throws -> CibaVersioned {
        // JSON.parse (a repeated member keeps the last value); text that does not parse is its own refusal
        guard let v = try? StrictJSON.parseLenientLastWins(raw) else { throw JSError("ciba: stored approval record is not valid JSON", code: "corrupt_record") }
        guard let ver = v.get("version"), let n = PCACiba.safeInt(ver), ver.isNumber, n >= 1, let value = v.get("value") else {
            throw JSError("ciba: stored approval record has no valid version", code: "corrupt_record")
        }
        return CibaVersioned(version: n, value: value)
    }

    static func serialize(_ version: Int, _ value: JSONValue) -> String {
        // JSON.stringify({ version, value }): the members in that insertion order
        var o = JObject()
        o[o: "version"] = .int(Int64(version))
        o[o: "value"] = value
        return JS.stringify(.object(o))
    }
}

/// Durable reference store: one JSON file, replaced atomically on each write. Correct for ONE process at a time; use a database
/// store (or `CibaKvApprovalStore` over a shared KV) when several processes share the approvals. A corrupt file throws.
public final class CibaFileApprovalStore: CibaApprovalStore, @unchecked Sendable {
    let path: String
    private let lock = NSLock()
    public init(path: String) { self.path = path }

    func loadAll() throws -> JObject {
        guard let text = try CibaFiles.read(path) else { return [:] }
        guard let all = (try? StrictJSON.parseLenient(text))?.asObject else { throw JSError("ciba: approval store file is corrupt") }
        return all
    }

    public func get(_ key: String) throws -> CibaVersioned? {
        lock.lock(); defer { lock.unlock() }
        guard let e = try loadAll()[JKey(key)] else { return nil }
        guard let n = PCACiba.safeInt(e.get("version")), let v = e.get("value") else { throw JSError("ciba: approval store file is corrupt") }
        return CibaVersioned(version: n, value: v)
    }

    public func cas(_ key: String, _ expectedVersion: Int, _ value: JSONValue) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        var all = try loadAll()
        if (PCACiba.safeInt(all[JKey(key)]?.get("version")) ?? 0) != expectedVersion { return false }
        all[JKey(key)] = .object(["version": .int(Int64(expectedVersion + 1)), "value": value])
        try CibaFiles.replace(path, Canonical.canonicalize(.object(all)))
        return true
    }
}

/// An approval store over a `CibaDurableKv`: each key holds `{version, value}` JSON; `cas` re-reads the raw string, checks the
/// version and swaps only if the raw string is unchanged, so two processes racing on one version cannot both win. A stored value
/// that is not a valid versioned record throws (`corrupt_record`).
public final class CibaKvApprovalStore: CibaApprovalStore, @unchecked Sendable {
    let kv: CibaDurableKv
    public init(kv: CibaDurableKv) { self.kv = kv }
    public func get(_ key: String) throws -> CibaVersioned? { try kv.get(key).map(CibaFiles.versioned) }
    public func cas(_ key: String, _ expectedVersion: Int, _ value: JSONValue) throws -> Bool {
        let raw = try kv.get(key)
        let current = try raw.map { try CibaFiles.versioned($0).version } ?? 0
        if current != expectedVersion { return false }
        return try kv.putIfEquals(key, raw, CibaFiles.serialize(expectedVersion + 1, value))
    }
}

/// Single-process KV (test double; not durable).
public final class CibaMemoryKv: CibaDurableKv, @unchecked Sendable {
    private var m: [String: String] = [:]
    private let lock = NSLock()
    public init() {}
    public func get(_ key: String) throws -> String? { lock.lock(); defer { lock.unlock() }; return m[key] }
    public func putIfEquals(_ key: String, _ expected: String?, _ next: String) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        if !CibaFiles.sameBytes(m[key], expected) { return false }
        m[key] = next
        return true
    }
}

/// A KV on a directory, safe for several processes on ONE host: one file per key (named by the SHA-256 of the key, so no key
/// escapes the directory); each swap takes a per-key lock file (exclusive create), compares, writes a temp file, fsyncs and renames
/// it over the key. A process that dies holding the lock leaves it behind: later swaps on that key throw `lock_timeout` (fail
/// closed) until an operator removes the `.lock` file.
public final class CibaDirectoryKv: CibaDurableKv, @unchecked Sendable {
    let dir: String
    let timeoutMs: Double

    public init(dir: String, lockTimeoutMs: Double = 5000) throws {
        if !(lockTimeoutMs.isFinite && lockTimeoutMs > 0) { throw JSError("createDirectoryKv: lockTimeoutMs must be a positive number") }
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        self.dir = dir
        self.timeoutMs = lockTimeoutMs
    }

    func file(_ key: String) throws -> String {
        if key.isEmpty { throw JSError("ciba: store key must be a non-empty string", code: "bad_key") }
        let hex = Canonical.sha256(Array(key.utf8)).map { String(format: "%02x", $0) }.joined()
        return (dir as NSString).appendingPathComponent(hex)
    }

    public func get(_ key: String) throws -> String? { try CibaFiles.read(try file(key)) }

    public func putIfEquals(_ key: String, _ expected: String?, _ next: String) throws -> Bool {
        let f = try file(key)
        let lockPath = f + ".lock"
        let deadline = Date().timeIntervalSince1970 * 1000 + timeoutMs
        var fd: Int32 = -1
        while fd < 0 {
            fd = open(lockPath, O_WRONLY | O_CREAT | O_EXCL, 0o600)
            if fd >= 0 { break }
            if errno != EEXIST { throw JSError("ciba: cannot create the store lock") }
            if Date().timeIntervalSince1970 * 1000 >= deadline { throw JSError("ciba: could not take the store lock in time", code: "lock_timeout") }
            usleep(2000)
        }
        defer { close(fd); unlink(lockPath) }
        let current = try CibaFiles.read(f)
        if !CibaFiles.sameBytes(current, expected) { return false }
        try CibaFiles.replace(f, next)
        return true
    }
}
