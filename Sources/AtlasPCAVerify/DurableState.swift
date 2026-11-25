import Foundation
import CryptoKit
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// Crash-safe, tamper-evident, multi-process-safe persistent key/value state (the reference's `durable-state`; a faithful port: the on-disk format is the
// same, so a directory written by one lane opens in another). WHY: rollback protection for signed manifests and key sets is only as good as the persistence
// of "the highest thing I ever accepted".
//
// LAYOUT (a directory you own, mode 0700): `state.journal` (hash-chained records, one JSON object per line), `state.head` (seq + hash of the last record,
// written AFTER the journal), `state.lock.<g>` (the lock: immutable numbered generation files created atomically with link(2)), `state.fence*`
// (operator-recovery fences).
//
// GUARANTEES: every mutation is write-temp, fsync, rename, fsync(directory): a crash leaves the old or the new journal, never a torn one, and the head
// trails by at most one record (repaired by the next writer). No lost updates across processes: every mutation runs under the exclusive generation lock;
// a lock is taken over only from a PROVABLY dead holder on this host and PID namespace, never by age; the generation is re-checked right before every
// rename. A holder that is only PAUSED across `recoverDurableState` is fenced: every record and head carries the writer's generation, and the fence
// recovery wrote makes load refuse a late record from a released generation. Records are hash-chained (and HMAC-tagged with `hmacKey`); a corrupt,
// truncated or rolled-back state makes every operation throw DurableStateError, never silently starting empty; the ONLY way past is
// `recoverFromCorruption: true`, which quarantines the files (kept for forensics) and starts from genesis with `recovered` true.
//
// NOT GUARANTEED: ONE HOST and ONE PID namespace per directory (a holder on another host or in another namespace is never judged dead: waiters time out,
// fail closed); a LOCAL filesystem with working hard links (probed at open: `link-unsupported`); a stalled live holder blocks until it dies
// (`lock-timeout`); the journal is rewritten whole per mutation (small state) and compacted every `compactEvery` records.

/// A refusal of the durable state store: `code` is `invalid`, `corrupt`, `rollback`, `key-mismatch`, `lock-timeout`, `lock-lost`, `too-large`,
/// `link-unsupported` or `io`.
public struct DurableStateError: Error, Equatable, CustomStringConvertible {
    public let code: String
    public let message: String
    public init(_ code: String, _ message: String) { self.code = code; self.message = message }
    public var description: String { "\(code): \(message)" }
}

/// Who `recoverDurableState` is told held the lock: the `{host, pid, nonce}` recorded in the lock file EXACTLY, or `unreadable`.
public enum DurableExpectedHolder: Equatable {
    case unreadable
    case holder(host: String, pid: Double, nonce: String)
}

/// How to open a durable state directory (`PCADurableState.open`).
public struct DurableStateOptions {
    public var dir: String
    /// At least 32 bytes: every record and the head are HMAC-tagged with it.
    public var hmacKey: [UInt8]?
    public var recoverFromCorruption = false
    public var lockTimeoutMs: Double = 10_000
    public var compactEvery: Int = 256
    public var maxValueBytes: Int = 1_048_576
    /// The clock (ms) of record timestamps.
    public var now: (() -> Int64)?
    public init(dir: String, hmacKey: [UInt8]? = nil, recoverFromCorruption: Bool = false, lockTimeoutMs: Double = 10_000, compactEvery: Int = 256,
                maxValueBytes: Int = 1_048_576, now: (() -> Int64)? = nil) {
        self.dir = dir; self.hmacKey = hmacKey; self.recoverFromCorruption = recoverFromCorruption; self.lockTimeoutMs = lockTimeoutMs
        self.compactEvery = compactEvery; self.maxValueBytes = maxValueBytes; self.now = now
    }
}

/// The result of `recoverDurableState`: whether a lock was released, why not, and the lock file concerned.
public struct DurableRecoverResult: Equatable {
    public let released: Bool
    public let reason: String
    public let lockFile: String?
}

public enum PCADurableState {
    static let DOMAIN = "pca-durable-state/v1\n"
    static let GENESIS = String(repeating: "0", count: 64)
    static let MAX_KEY = 256
    static let FENCE_FILE = "state.fence"
    static let RECOVER_CRASH_ENV = "PCA_DURABLE_TEST_RECOVER_CRASH_AT"
    static let BOOT_ID: String = randomHex(12)

    /// Open (creating if needed) a durable state directory. Throws DurableStateError on corrupt / rolled-back state unless recovering.
    public static func open(_ o: DurableStateOptions) throws -> DurableState { try DurableState(o) }

    /// In-memory key/value store with the same atomic-update contract and no durability (tests / one process).
    public static func createMemoryDurableKv() -> MemoryAtomicKV { MemoryAtomicKV() }

    // ---- small helpers ----

    static func randomHex(_ n: Int) -> String {
        var g = SystemRandomNumberGenerator()
        return (0..<n).map { _ in String(format: "%02x", UInt8.random(in: 0...255, using: &g)) }.joined()
    }

    static func sha(_ s: String) -> String { hex(Canonical.sha256(Array(s.utf8))) }

    static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    static func js(_ v: JSONValue) -> String { JS.stringify(v) }

    static func obj(_ pairs: [(String, JSONValue)]) -> JSONValue { PCAApprovalChannels.obj(pairs) }

    static func nowReal() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    static func isHex64(_ v: JSONValue?) -> String? {
        guard let s = v?.asString, s.utf8.count == 64, s.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }) else { return nil }
        return s
    }

    static func safeInt(_ v: JSONValue?) -> Int64? { v?.safeInt }
    /// A safe integer that is not -0 (the reference refuses `Object.is(x, -0)` in a fence or head sequence and in a record time).
    static func safeIntNotNegZero(_ v: JSONValue?) -> Int64? {
        if let d = IV.num(v), d == 0, d.sign == .minus { return nil }
        return v?.safeInt
    }
    static func gen(_ v: JSONValue?) -> Int64? { v?.safeInt.flatMap { $0 >= 1 ? $0 : nil } }

    static func parseJSON(_ text: String) -> JSONValue? { try? StrictJSON.parseLenient(text) }

    static func readText(_ path: String) -> String? {
        guard let d = FileManager.default.contents(atPath: path) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    static func exists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }

    static func children(_ dir: String) -> [String] { (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] }

    static func errnoName() -> String { String(cString: strerror(errno)) }

    /// `fsync`, as hard as the platform lets it (macOS needs F_FULLFSYNC to reach the disk).
    static func syncFd(_ fd: Int32) {
        #if canImport(Darwin)
        if fcntl(fd, F_FULLFSYNC) == 0 { return }
        #endif
        _ = fsync(fd)
    }

    static func fsyncDir(_ dir: String) {
        let fd = Darwin_open(dir, O_RDONLY)
        if fd >= 0 { syncFd(fd); _ = close(fd) }
    }

    // `open` is shadowed by PCADurableState.open: reach the C function through this wrapper.
    static func Darwin_open(_ path: String, _ flags: Int32, _ mode: mode_t = 0) -> Int32 {
        #if canImport(Darwin)
        return Darwin.open(path, flags, mode)
        #else
        return Glibc.open(path, flags, mode)
        #endif
    }

    /// Create `path` exclusively (mode 0600), write `data`, fsync, close.
    static func writeNew(_ path: String, _ data: [UInt8]) throws {
        let fd = Darwin_open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw DurableStateError("io", "cannot create \(path): \(errnoName())") }
        defer { _ = close(fd) }
        var off = 0
        while off < data.count {
            let n = data[off...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if n <= 0 { if n < 0 && errno == EINTR { continue }; throw DurableStateError("io", "cannot write \(path): \(errnoName())") }
            off += n
        }
        syncFd(fd)
    }

    static func rename(_ a: String, _ b: String) throws {
        #if canImport(Darwin)
        let r = Darwin.rename(a, b)
        #else
        let r = Glibc.rename(a, b)
        #endif
        if r != 0 { throw DurableStateError("io", "cannot rename \(a): \(errnoName())") }
    }

    static func unlinkQuiet(_ p: String) { _ = unlink(p) }

    /// write-temp, fsync, `beforeRename`, rename, fsync(directory): the file is the old or the new one, never torn.
    static func atomicWrite(_ path: String, _ text: String, _ beforeRename: (() throws -> Void)? = nil) throws {
        let tmp = "\(path).tmp-\(getpid())-\(randomHex(6))"
        try writeNew(tmp, Array(text.utf8))
        if let b = beforeRename {
            do { try b() } catch { unlinkQuiet(tmp); throw error }
        }
        try rename(tmp, path)
        fsyncDir((path as NSString).deletingLastPathComponent)
    }

    static func pidAlive(_ pid: Double) -> Bool {
        guard pid.isFinite, pid > 0, pid < Double(Int32.max) else { return false }
        if kill(pid_t(pid), 0) == 0 { return true }
        return errno == EPERM
    }

    /// Process start time (field 22 of /proc/<pid>/stat), nil off Linux or when gone.
    static func procStart(_ pid: Double) -> String? {
        guard pid.isFinite, pid > 0, let st = readText("/proc/\(Int(pid))/stat"), let r = st.lastIndex(of: ")") else { return nil }
        let rest = st[(st.index(r, offsetBy: 2, limitedBy: st.endIndex) ?? st.endIndex)...].split(separator: " ", omittingEmptySubsequences: false)
        return rest.count > 19 ? String(rest[19]) : nil
    }

    static func myNs() -> String? { try? FileManager.default.destinationOfSymbolicLink(atPath: "/proc/self/ns/pid") }

    static func hostname() -> String {
        var buf = [CChar](repeating: 0, count: 256)
        return gethostname(&buf, buf.count - 1) == 0 ? String(cString: buf) : ProcessInfo.processInfo.hostName
    }

    /// Test-only SIGKILL of this process at a named step of operator recovery (PCA_DURABLE_TEST=1 and the env var both set).
    static func testCrashPoint(_ point: String) {
        let e = ProcessInfo.processInfo.environment
        if e["PCA_DURABLE_TEST"] == "1" && e[RECOVER_CRASH_ENV] == point { _ = kill(getpid(), SIGKILL) }
    }

    static func digits(_ s: Substring) -> Int64? { !s.isEmpty && s.utf8.allSatisfy { $0 >= 48 && $0 <= 57 } ? Int64(s) : nil }

    static func lockGen(_ name: String) -> Int64? { name.hasPrefix("state.lock.") ? digits(name.dropFirst("state.lock.".count)) : nil }

    /// `state.fence.<gen>-<hex>`.
    static func fenceEntry(_ name: String) -> Int64? {
        guard name.hasPrefix("state.fence.") else { return nil }
        let rest = name.dropFirst("state.fence.".count)
        guard let dash = rest.firstIndex(of: "-") else { return nil }
        let hexPart = rest[rest.index(after: dash)...]
        guard !hexPart.isEmpty, hexPart.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }) else { return nil }
        return digits(rest[..<dash])
    }

    static func fenceEntryFiles(_ dir: String) -> [(name: String, gen: Int64)] {
        children(dir).compactMap { n in fenceEntry(n).map { (n, $0) } }
    }

    struct Fence: Equatable { var gen: Int64; var seq: Int64; var h: String }

    static func parseFence(_ f: JSONValue?, _ whereAt: String) throws -> Fence {
        guard let o = f, o.isObject, let g = gen(o.get("gen")), let s = safeIntNotNegZero(o.get("seq")), s >= 0, let h = isHex64(o.get("h")) else {
            throw DurableStateError("corrupt", "\(whereAt) has an invalid entry")
        }
        return Fence(gen: g, seq: s, h: h)
    }

    static func readJSON(_ path: String, _ name: String) throws -> JSONValue {
        guard let t = readText(path), let v = parseJSON(t) else { throw DurableStateError("corrupt", "\(name) is not valid JSON") }
        return v
    }

    /// Every fence: the list in `state.fence` (absent = none) then each `state.fence.<gen>-<rand>` by generation. Malformed = corrupt.
    static func readFences(_ dir: String) throws -> [Fence] {
        var out: [Fence] = []
        let p = (dir as NSString).appendingPathComponent(FENCE_FILE)
        if exists(p) {
            let o = try readJSON(p, "state.fence")
            guard o.isObject, o.get("v")?.safeInt == 1, let list = o.get("fences")?.asArray else { throw DurableStateError("corrupt", "state.fence has an invalid shape") }
            for f in list { out.append(try parseFence(f, "state.fence")) }
        }
        for e in fenceEntryFiles(dir).sorted(by: { $0.gen != $1.gen ? $0.gen < $1.gen : $0.name.utf16.lexicographicallyPrecedes($1.name.utf16) }) {
            let o = try readJSON((dir as NSString).appendingPathComponent(e.name), e.name)
            guard o.isObject, o.get("v")?.safeInt == 1 else { throw DurableStateError("corrupt", "\(e.name) has an invalid shape") }
            let f = try parseFence(o.get("fence"), e.name)
            if f.gen != e.gen { throw DurableStateError("corrupt", "\(e.name) names generation \(e.gen) but holds \(f.gen)") }
            out.append(f)
        }
        return out
    }

    /// (seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros).
    static func journalTail(_ dir: String) -> (seq: Int64, h: String) {
        guard let t = readText((dir as NSString).appendingPathComponent("state.journal")) else { return (0, GENESIS) }
        let lines = t.split(separator: "\n", omittingEmptySubsequences: true)
        guard let last = lines.last, let o = parseJSON(String(last)), o.isObject, let s = safeInt(o.get("seq")), s >= 1, let h = isHex64(o.get("h")) else { return (0, GENESIS) }
        return (s, h)
    }

    /// The operator's CUT: every journal record after the tail seen NOW must come from a generation above `g`. Its own immutable file.
    static func writeFence(_ dir: String, _ g: Int64, _ beforeRename: (() throws -> Void)? = nil) throws {
        _ = try readFences(dir) // an unreadable fence set fails closed here too
        let t = journalTail(dir)
        let fence = obj([("gen", .int(g + 1)), ("seq", .int(t.seq)), ("h", .string(t.h)), ("from", .int(g)), ("t", .int(nowReal()))])
        try atomicWrite((dir as NSString).appendingPathComponent("\(FENCE_FILE).\(g + 1)-\(randomHex(6))"), js(obj([("v", .int(1)), ("fence", fence)])) + "\n", beforeRename)
    }

    enum LockClass {
        case unreadable
        case incomplete(JSONValue)
        case free
        case complete(JSONValue)
    }

    /// A holder record is COMPLETE only with a numeric pid, a host and a non-empty nonce.
    static func classifyLockFile(_ path: String) -> LockClass {
        guard let t = readText(path), let o = parseJSON(t), o.isObject || o.isArray else { return .unreadable }
        if o.isArray { return .incomplete(.object([:])) }
        if o.get("st")?.asString == "free" { return .free }
        if o.get("pid")?.isNumber == true, o.get("host")?.asString != nil, let n = o.get("nonce")?.asString, !n.isEmpty { return .complete(o) }
        return .incomplete(o)
    }

    /// Is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names one, else by hostname.
    static func holderAliveHere(_ b: JSONValue) -> Bool {
        guard b.get("pid")?.isNumber == true else { return false }
        let pid = JS.toNumber(b.get("pid"))
        let nsNow = myNs()
        let judgeable: Bool = b.get("ns")?.asString != nil ? (nsNow != nil && b.get("ns")?.asString == nsNow) : b.get("host")?.asString == hostname()
        if !judgeable || !pidAlive(pid) { return false }
        if let start = b.get("start")?.asString, let cur = procStart(pid), cur != start { return false } // the pid was reused by a different process
        return true
    }

    static func pidText(_ v: JSONValue?) -> String { JS.toString(v) }

    static func confirmHolder(_ c: LockClass, _ exp: DurableExpectedHolder, _ path: String) throws {
        switch c {
        case .free: break
        case .unreadable:
            if exp != .unreadable { throw DurableStateError("invalid", "\(path) is unreadable; pass expectedHolder: 'unreadable' to release it") }
        case let .incomplete(raw):
            if exp != .unreadable {
                throw DurableStateError("invalid", "\(path) has an incomplete holder record (\(String(js(raw).prefix(160)))); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it")
            }
            if holderAliveHere(raw) { throw DurableStateError("invalid", "the holder of \(path) (pid \(pidText(raw.get("pid")))) is alive in this PID namespace; refusing to release a live holder") }
        case let .complete(b):
            guard case let .holder(host, pid, nonce) = exp else {
                throw DurableStateError("invalid", "\(path) is readable (holder pid=\(pidText(b.get("pid"))) host=\(pidText(b.get("host")))); expectedHolder 'unreadable' does not match")
            }
            if b.get("host")?.asString != host || JS.toNumber(b.get("pid")) != pid || b.get("nonce")?.asString != nonce {
                throw DurableStateError("invalid", "expectedHolder does not match the holder recorded in \(path) (recorded pid=\(pidText(b.get("pid"))) host=\(pidText(b.get("host"))) nonce=\(pidText(b.get("nonce")))); nothing was changed")
            }
            if holderAliveHere(b) { throw DurableStateError("invalid", "the holder of \(path) (pid \(pidText(b.get("pid")))) is alive in this PID namespace; refusing to release a live holder") }
        }
    }

    /// Operator recovery for a lock whose holder cannot be judged dead automatically (another PID namespace, a changed hostname, an unreadable or
    /// incomplete top lock file, or a legacy single-file `state.lock`). Out of band: it takes the lock itself (generation g+1), cuts and FENCES the
    /// released generation, then appends a "free" generation g+2. `expectedHolder` is the recorded {host, pid, nonce} EXACTLY, or `unreadable`.
    public static func recover(dir: String, force: Bool = false, expectedHolder: DurableExpectedHolder?, legacyLock: Bool = false) throws -> DurableRecoverResult {
        if !force { throw DurableStateError("invalid", "recoverDurableState requires force: true") }
        guard let exp = expectedHolder else {
            throw DurableStateError("invalid", "expectedHolder must be {'host','pid','nonce'} as recorded in the lock file, or 'unreadable'")
        }
        if case let .holder(_, _, n) = exp, n.isEmpty { throw DurableStateError("invalid", "expectedHolder must be {'host','pid','nonce'} as recorded in the lock file, or 'unreadable'") }
        let g = children(dir).compactMap(lockGen).max() ?? 0
        let path = (dir as NSString).appendingPathComponent("state.lock.\(g)")
        let top: LockClass? = g == 0 ? nil : classifyLockFile(path)
        let legacyPath = (dir as NSString).appendingPathComponent("state.lock")
        func isFree(_ c: LockClass?) -> Bool { if case .free? = c { return true }; return false }
        if legacyLock {
            if let t = top, !isFree(t) {
                throw DurableStateError("invalid", "legacyLock: true, but the blocking lock is the generation lock \(path); call recoverDurableState without legacyLock")
            }
            if !exists(legacyPath) { return DurableRecoverResult(released: false, reason: "not-held", lockFile: nil) }
            let legacy = classifyLockFile(legacyPath)
            if isFree(legacy) { return DurableRecoverResult(released: false, reason: "not-held", lockFile: legacyPath) }
            try confirmHolder(legacy, exp, legacyPath)
            try writeFence(dir, g)
            try rename(legacyPath, (dir as NSString).appendingPathComponent("state.lock.legacy-recovered-\(nowReal())-\(randomHex(3))"))
            fsyncDir(dir)
            return DurableRecoverResult(released: true, reason: "released", lockFile: legacyPath)
        }
        if top == nil || isFree(top) {
            if exists(legacyPath) {
                let lb = classifyLockFile(legacyPath)
                let who: String
                switch lb {
                case let .complete(b): who = "holder pid=\(pidText(b.get("pid"))) host=\(pidText(b.get("host"))) nonce=\(pidText(b.get("nonce")))"
                case .unreadable: who = "unreadable holder record"
                case .incomplete: who = "incomplete holder record"
                case .free: who = "free holder record"
                }
                throw DurableStateError("invalid", "the blocking lock is the legacy single-file \(legacyPath) (\(who)); after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')")
            }
            return top == nil ? DurableRecoverResult(released: false, reason: "not-held", lockFile: nil) : DurableRecoverResult(released: false, reason: "not-held", lockFile: path)
        }
        try confirmHolder(top!, exp, path)
        // in this order (formal/tla/DurableFence.tla): TAKE generation g+1 (marked `recovering`), CUT + FENCE under it, RELEASE as g+2 free
        func linkBody(_ gen: Int64, _ body: JSONValue, _ crashPoint: String) throws {
            let tmp = (dir as NSString).appendingPathComponent("state.lock.tmp-\(getpid())-\(randomHex(6))")
            try writeNew(tmp, Array(js(body).utf8))
            testCrashPoint(crashPoint)
            defer { unlinkQuiet(tmp) }
            if link(tmp, (dir as NSString).appendingPathComponent("state.lock.\(gen)")) != 0 {
                if errno == EEXIST { throw DurableStateError("invalid", "\(path) was superseded while recovering; re-read the lock state and retry") }
                throw DurableStateError("io", "cannot link the lock: \(errnoName())")
            }
        }
        let ns = myNs()
        testCrashPoint("before-lock")
        let start = procStart(Double(getpid()))
        var body: [(String, JSONValue)] = [("st", .string("held")), ("pid", .int(Int64(getpid()))), ("host", .string(hostname())), ("nonce", .string(randomHex(12))), ("boot", .string(BOOT_ID))]
        if let n = ns { body.append(("ns", .string(n))) }
        if let s = start { body.append(("start", .string(s))) }
        body.append(("recovering", .int(g)))
        body.append(("t", .int(nowReal())))
        try linkBody(g + 1, obj(body), "after-lock-temp")
        testCrashPoint("after-lock")
        try writeFence(dir, g) { testCrashPoint("after-fence-temp") }
        testCrashPoint("after-fence")
        try linkBody(g + 2, obj([("st", .string("free")), ("t", .int(nowReal())), ("recoveredFrom", .int(g))]), "after-release-temp")
        testCrashPoint("after-release")
        return DurableRecoverResult(released: true, reason: "released", lockFile: path)
    }
}

/// Operator recovery for a lock whose holder cannot be judged dead automatically (see `PCADurableState.recover`).
public func recoverDurableState(dir: String, force: Bool = false, expectedHolder: DurableExpectedHolder? = nil, legacyLock: Bool = false) throws -> DurableRecoverResult {
    try PCADurableState.recover(dir: dir, force: force, expectedHolder: expectedHolder, legacyLock: legacyLock)
}

/// Open (creating if needed) a durable state directory (see `PCADurableState.open`).
public func openDurableState(_ o: DurableStateOptions) throws -> DurableState { try PCADurableState.open(o) }

/// A durable state directory handle. Build with `openDurableState`. It is an `AtomicKV` (and lists its keys), so the replay store, the operation store and
/// the undo ledger run over it unchanged.
public final class DurableState: ListableAtomicKV, @unchecked Sendable {
    typealias P = PCADurableState

    struct Rec {
        var seq: Int64
        var prev: String
        var op: String
        var payload: String
        var ts: Int64
        var gen: Int64?
        var h: String
        var mac: String?
    }

    struct Head {
        var seq: Int64
        var h: String
        var gen: Int64?
        var mac: String?
    }

    struct Loaded {
        var recs: [Rec]
        var state: [String: String]
        var head: Head?
    }

    public private(set) var recovered = false
    private let dir: String
    private let key: [UInt8]?
    private let recoverOpt: Bool
    private let lockTimeout: Double
    private let compactEvery: Int
    private let maxValue: Int
    private let nowFn: () -> Int64
    private let journalPath: String
    private let headPath: String
    private var seen: (seq: Int64, hash: String) = (0, P.GENESIS)
    private var heldNonce: String?
    private var myGen: Int64 = -1
    private let myNsId: String?
    private let myStart: String?
    private let mutex = NSRecursiveLock()

    init(_ o: DurableStateOptions) throws {
        guard !o.dir.isEmpty else { throw DurableStateError("invalid", "dir is required") }
        if let k = o.hmacKey, k.count < 32 { throw DurableStateError("invalid", "hmacKey must be at least 32 bytes") }
        dir = o.dir
        key = o.hmacKey
        recoverOpt = o.recoverFromCorruption
        lockTimeout = o.lockTimeoutMs
        compactEvery = Swift.max(2, o.compactEvery)
        maxValue = o.maxValueBytes
        nowFn = o.now ?? { PCADurableState.nowReal() }
        journalPath = (o.dir as NSString).appendingPathComponent("state.journal")
        headPath = (o.dir as NSString).appendingPathComponent("state.head")
        myNsId = P.myNs()
        myStart = P.procStart(Double(getpid()))
        try? FileManager.default.createDirectory(atPath: o.dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        _ = chmod(o.dir, 0o700) // not ours to chmod: ignored
        try probeLinks()
        try withLock {
            let l = try loadOrRecover()
            observe(l)
            if let last = l.recs.last, l.head == nil || l.head!.seq != last.seq { try writeHead(last) }
        }
    }

    /// Highest chain position this handle has observed.
    public func position() -> (seq: Int64, hash: String) { seen }

    /// Verify the chain from disk now; throws DurableStateError on any problem.
    @discardableResult
    public func verify() throws -> (seq: Int64, hash: String) {
        try withLock {
            observe(try load())
            return seen
        }
    }

    public func get(_ k: String) throws -> JSONValue? {
        try checkKey(k)
        return try withLock {
            let l = try load()
            observe(l)
            return l.state[k].flatMap { P.parseJSON($0) }
        }
    }

    /// Whether the key holds a value right now (a stored JSON null counts). Takes the lock itself, which advances the lock generation: a replay that must match the
    /// reference's generations reads presence together with the value (`getPresent`, `updateValuePresent`) instead.
    func hasKey(_ k: String) throws -> Bool { try withLock { try load().state[k] != nil } }

    /// `get` and whether the key holds a value (a stored JSON null counts), under the one lock `get` takes.
    func getPresent(_ k: String) throws -> (value: JSONValue?, present: Bool) {
        try checkKey(k)
        return try withLock {
            let l = try load()
            observe(l)
            let t = l.state[k]
            return (t.flatMap { P.parseJSON($0) }, t != nil)
        }
    }

    public func keys() throws -> [String] {
        try withLock {
            let l = try load()
            observe(l)
            return l.state.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
        }
    }

    /// Unconditional write (still serialised and hash-chained). Prefer `update` for monotone state.
    public func set(_ k: String, _ value: JSONValue) throws {
        try checkKey(k)
        let vj = try encode(value)
        try withLock {
            let l = try load()
            if let last = l.recs.last, l.head == nil || l.head!.seq != last.seq { try writeHead(last) }
            try commit(l, k, vj)
        }
    }

    /// Atomic read-modify-write: `f` gets the current value (nil when absent) and returns the next value, or nil to leave the key unchanged. Runs under the
    /// cross-process lock and must be quick. Returns the value now stored.
    @discardableResult
    public func updateValue(_ k: String, _ f: (JSONValue?) -> JSONValue?) throws -> JSONValue? { try updateValuePresent(k, f).value }

    /// `updateValue` and whether the key holds a value afterwards, under the same single lock.
    func updateValuePresent(_ k: String, _ f: (JSONValue?) -> JSONValue?) throws -> (value: JSONValue?, present: Bool) {
        try checkKey(k)
        return try withLock {
            let l = try load()
            if let last = l.recs.last, l.head == nil || l.head!.seq != last.seq { try writeHead(last) }
            let cur = l.state[k]
            let curV = cur.flatMap { P.parseJSON($0) }
            guard let nxt = f(curV) else { return (curV, cur != nil) }
            let vj = try encode(nxt)
            if vj != cur { try commit(l, k, vj) }
            return (P.parseJSON(vj), true)
        }
    }

    /// `AtomicKV.update`.
    public func update(_ k: String, _ f: (JSONValue?) -> JSONValue?) throws { _ = try updateValue(k, f) }

    // ---- hashing and shape checks ----

    private func macOf(_ msg: String) -> String {
        P.hex(Array(HMAC<SHA256>.authenticationCode(for: Data(msg.utf8), using: SymmetricKey(data: key ?? []))))
    }

    private func macEq(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var d: UInt8 = 0
        for i in 0..<x.count { d |= x[i] ^ y[i] }
        return d == 0
    }

    private func recHash(seq: Int64, prev: String, op: String, payload: String, ts: Int64, gen: Int64?) -> String {
        var arr: [JSONValue] = [.int(seq), .string(prev), .string(op), .string(payload), .int(ts)]
        if let g = gen { arr.append(.int(g)) }
        return P.sha(P.DOMAIN + P.js(.array(arr)))
    }

    private func headMsg(_ seq: Int64, _ h: String, _ gen: Int64?) -> String { gen == nil ? "head\n\(seq)\n\(h)" : "head\n\(seq)\n\(h)\n\(gen!)" }

    private func encode(_ value: JSONValue) throws -> String {
        let s = P.js(value)
        if s.utf16.count > maxValue { throw DurableStateError("too-large", "value exceeds maxValueBytes=\(maxValue)") }
        return s
    }

    private func checkKey(_ k: String) throws {
        if k.isEmpty || k.utf16.count > P.MAX_KEY || k.contains("\n") { throw DurableStateError("invalid", "key must be 1..256 chars without newlines") }
    }

    private func readHead() throws -> Head? {
        guard P.exists(headPath) else { return nil }
        guard let t = P.readText(headPath), let o = P.parseJSON(t) else { throw DurableStateError("corrupt", "state.head is not valid JSON") }
        guard o.isObject, let seq = P.safeIntNotNegZero(o.get("seq")), seq >= 0, let h = P.isHex64(o.get("h")), o.asObject?[JKey("gen")] == nil || P.gen(o.get("gen")) != nil else {
            throw DurableStateError("corrupt", "state.head has an invalid shape")
        }
        let head = Head(seq: seq, h: h, gen: o.asObject?[JKey("gen")] != nil ? P.gen(o.get("gen")) : nil, mac: o.get("mac")?.asString)
        if key != nil, head.mac == nil || !macEq(head.mac!, macOf(headMsg(head.seq, head.h, head.gen))) {
            throw DurableStateError("key-mismatch", "state.head MAC does not verify (wrong key or forged head)")
        }
        return head
    }

    private func parseLine(_ line: String, _ i: Int) throws -> Rec {
        guard let o = P.parseJSON(line) else { throw DurableStateError("corrupt", "journal line \(i + 1) is not valid JSON") }
        let hasGen = o.asObject?[JKey("gen")] != nil
        guard o.isObject, let seq = P.safeInt(o.get("seq")), let prev = P.isHex64(o.get("prev")), let op = o.get("op")?.asString, op == "set" || op == "checkpoint",
              let payload = o.get("payload")?.asString, let ts = P.safeIntNotNegZero(o.get("ts")), let h = P.isHex64(o.get("h")), !hasGen || P.gen(o.get("gen")) != nil else {
            throw DurableStateError("corrupt", "journal line \(i + 1) has an invalid shape")
        }
        return Rec(seq: seq, prev: prev, op: op, payload: payload, ts: ts, gen: hasGen ? P.gen(o.get("gen")) : nil, h: h, mac: o.get("mac")?.asString)
    }

    private func recJSON(_ r: Rec) -> JSONValue {
        var p: [(String, JSONValue)] = [("seq", .int(r.seq)), ("prev", .string(r.prev)), ("op", .string(r.op)), ("payload", .string(r.payload)), ("ts", .int(r.ts))]
        if let g = r.gen { p.append(("gen", .int(g))) }
        p.append(("h", .string(r.h)))
        if let m = r.mac { p.append(("mac", .string(m))) }
        return P.obj(p)
    }

    // ---- load ----

    func load() throws -> Loaded {
        let head = try readHead()
        let fences = try P.readFences(dir)
        guard P.exists(journalPath) else {
            if let h = head, h.seq > 0 { throw DurableStateError("rollback", "state.journal is missing but state.head records seq \(h.seq)") }
            if let cut = fences.first(where: { $0.seq > 0 }) { throw DurableStateError("rollback", "state.journal is missing but operator recovery cut it at seq \(cut.seq)") }
            if seen.seq > 0 { throw DurableStateError("rollback", "state was deleted while open") }
            return Loaded(recs: [], state: [:], head: head)
        }
        guard let text = P.readText(journalPath) else { throw DurableStateError("corrupt", "journal line 1 is not valid JSON") }
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.last == "" else { throw DurableStateError("corrupt", "journal does not end with a newline (torn or truncated)") }
        lines.removeLast()
        var recs: [Rec] = []
        var state: [String: String] = [:]
        var prevHash = P.GENESIS
        var prevSeq: Int64 = 0
        var prevGen: Int64 = 0
        for (i, line) in lines.enumerated() {
            let rec = try parseLine(line, i)
            if i == 0 {
                if rec.op == "set" && (rec.seq != 1 || rec.prev != P.GENESIS) { throw DurableStateError("corrupt", "journal does not start at genesis") }
                if rec.op == "checkpoint" && rec.seq < 1 { throw DurableStateError("corrupt", "bad checkpoint seq") }
            } else {
                if rec.seq != prevSeq + 1 { throw DurableStateError("corrupt", "journal line \(i + 1): sequence gap") }
                if rec.prev != prevHash { throw DurableStateError("corrupt", "journal line \(i + 1): hash chain broken") }
            }
            if recHash(seq: rec.seq, prev: rec.prev, op: rec.op, payload: rec.payload, ts: rec.ts, gen: rec.gen) != rec.h {
                throw DurableStateError("corrupt", "journal line \(i + 1): record hash mismatch (edited)")
            }
            if key != nil {
                if rec.mac == nil || !macEq(rec.mac!, macOf(rec.h)) { throw DurableStateError("key-mismatch", "journal line \(i + 1): MAC does not verify (wrong key or forged record)") }
            } else if rec.mac != nil {
                throw DurableStateError("key-mismatch", "journal is MAC-tagged but no hmacKey was supplied")
            }
            let rg = rec.gen ?? 0
            if rg < prevGen {
                throw DurableStateError("corrupt", "journal line \(i + 1) (seq \(rec.seq)) was written by lock generation \(rg), older than generation \(prevGen) of an earlier record: a stale writer's record (refused)")
            }
            for f in fences where rec.seq > f.seq && rg < f.gen {
                throw DurableStateError("corrupt", "journal line \(i + 1) (seq \(rec.seq)) was written by lock generation \(rg), but operator recovery fenced generations below \(f.gen) after seq \(f.seq): a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)")
            }
            prevGen = rg
            if rec.op == "checkpoint" {
                guard let entries = P.parseJSON(rec.payload) else { throw DurableStateError("corrupt", "checkpoint payload is not JSON") }
                guard let arr = entries.asArray else { throw DurableStateError("corrupt", "checkpoint payload is not an array") }
                state.removeAll()
                for e in arr {
                    guard let pair = e.asArray, pair.count == 2, let k = pair[0].asString, let v = pair[1].asString else { throw DurableStateError("corrupt", "checkpoint entry is malformed") }
                    state[k] = v
                }
            } else {
                guard let nl = rec.payload.firstIndex(of: "\n"), nl != rec.payload.startIndex else { throw DurableStateError("corrupt", "journal line \(i + 1): malformed payload") }
                state[String(rec.payload[..<nl])] = String(rec.payload[rec.payload.index(after: nl)...])
            }
            recs.append(rec)
            prevHash = rec.h
            prevSeq = rec.seq
        }
        let last = recs.last
        let lastSeq = last?.seq ?? 0
        for f in fences {
            if lastSeq < f.seq { throw DurableStateError("rollback", "journal is at seq \(lastSeq) but operator recovery cut it at seq \(f.seq) (truncation, or a stale writer replaced it)") }
            if f.seq > 0, let atCut = recs.first(where: { $0.seq == f.seq }), atCut.h != f.h {
                throw DurableStateError("corrupt", "journal record at seq \(f.seq) is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)")
            }
        }
        if let head = head {
            let hg = head.gen ?? 0
            if lastSeq < head.seq { throw DurableStateError("rollback", "journal is at seq \(lastSeq) but state.head recorded seq \(head.seq) (truncation or older copy)") }
            if let l = last, (l.gen ?? 0) < hg, lastSeq == head.seq + 1 || (lastSeq == head.seq && l.h != head.h) {
                throw DurableStateError("corrupt", "journal tail (seq \(lastSeq)) was written by lock generation \(l.gen ?? 0), older than generation \(hg) that wrote state.head: a stale writer replaced the journal (refused)")
            }
            let staleHead = lastSeq > head.seq + 1 && fences.contains(where: { hg < $0.gen && head.seq <= $0.seq && lastSeq > $0.seq }) && recs.contains(where: { $0.seq == head.seq && $0.h == head.h })
            if lastSeq > head.seq + 1 && !staleHead { throw DurableStateError("corrupt", "journal (seq \(lastSeq)) is more than one record ahead of state.head (seq \(head.seq))") }
            if let l = last {
                if lastSeq == head.seq && l.h != head.h { throw DurableStateError("corrupt", "journal tail does not match state.head") }
                if lastSeq == head.seq + 1 && l.prev != head.h { throw DurableStateError("corrupt", "journal tail is not chained from state.head") }
            }
        } else if lastSeq > 1 {
            throw DurableStateError("rollback", "state.head is missing but the journal is at seq \(lastSeq)")
        }
        if let l = last {
            if l.seq < seen.seq { throw DurableStateError("rollback", "state moved backwards from seq \(seen.seq) to \(l.seq) while open") }
            if l.seq == seen.seq && l.h != seen.hash { throw DurableStateError("rollback", "state forked at seq \(l.seq) while open") }
        } else if seen.seq > 0 {
            throw DurableStateError("rollback", "state was emptied while open")
        }
        return Loaded(recs: recs, state: state, head: head)
    }

    private func quarantine() throws {
        let tag = "\(nowFn())-\(P.randomHex(3))"
        try assertLockHeld() // a writer that lost the lock must not move a newer holder's files aside
        let fencePath = (dir as NSString).appendingPathComponent(P.FENCE_FILE)
        let oldEntries = P.fenceEntryFiles(dir)
        if P.exists(fencePath) || !oldEntries.isEmpty {
            if P.exists(fencePath), link(fencePath, "\(fencePath).quarantine-\(tag)") != 0 { throw DurableStateError("io", "cannot keep the old fence file: \(P.errnoName())") }
            let f = P.obj([("gen", .int(myGen)), ("seq", .int(0)), ("h", .string(P.GENESIS)), ("from", .int(myGen - 1)), ("t", .int(nowFn()))])
            try P.atomicWrite(fencePath, P.js(P.obj([("v", .int(1)), ("fences", .array([f]))])) + "\n")
            for e in oldEntries { try P.rename((dir as NSString).appendingPathComponent(e.name), (dir as NSString).appendingPathComponent("\(e.name).quarantine-\(tag)")) }
        }
        for p in [journalPath, headPath] where P.exists(p) { try P.rename(p, "\(p).quarantine-\(tag)") }
        P.fsyncDir(dir)
        seen = (0, P.GENESIS)
        recovered = true
    }

    private func loadOrRecover() throws -> Loaded {
        do { return try load() } catch let e as DurableStateError {
            if !recoverOpt { throw e }
            try quarantine()
            return try load()
        }
    }

    private func observe(_ l: Loaded) {
        if let last = l.recs.last, last.seq >= seen.seq { seen = (last.seq, last.h) }
    }

    // ---- the lock: immutable numbered generation files (formal/tla/DurableLockGen.tla) ----

    private func lockFile(_ g: Int64) -> String { (dir as NSString).appendingPathComponent("state.lock.\(g)") }
    private var legacyLock: String { (dir as NSString).appendingPathComponent("state.lock") }

    struct LockBody {
        var st: String
        var pid: Double?
        var host: String?
        var nonce: String?
        var start: String?
        var ns: String?
        var boot: String?
        var recovering: Int64?
    }

    private func readBody(_ path: String) -> LockBody? {
        // typeof [] === 'object': an array is a record with no members (an incomplete holder), anything else that is not an object is unreadable
        guard let t = P.readText(path), let o = P.parseJSON(t), o.isObject || o.asArray != nil else { return nil }
        var b = LockBody(st: o.get("st")?.asString == "free" ? "free" : "held")
        if o.get("pid")?.isNumber == true { b.pid = JS.toNumber(o.get("pid")) }
        b.host = o.get("host")?.asString; b.nonce = o.get("nonce")?.asString; b.start = o.get("start")?.asString; b.ns = o.get("ns")?.asString; b.boot = o.get("boot")?.asString
        b.recovering = P.safeInt(o.get("recovering"))
        return b
    }

    /// Highest numbered generation: (g, body) (g = 0 and no body when there is none; body nil = unreadable).
    private func topLock() -> (Int64, LockBody?) {
        let g = P.children(dir).compactMap(P.lockGen).max() ?? -1
        return g >= 1 ? (g, readBody(lockFile(g))) : (0, nil)
    }

    private func holderDead(_ b: LockBody?, _ legacyAgeMs: Int64) -> Bool {
        guard let b = b else { return legacyAgeMs > 1000 } // an unreadable legacy file (torn by an old version) older than 1 s
        if b.host != P.hostname() || b.pid == nil { return false } // another host: cannot judge, never break
        if let ns = b.ns, ns != myNsId { return false } // another PID namespace: cannot judge, never break
        if !P.pidAlive(b.pid!) { return true }
        if let s = b.start, let cur = P.procStart(b.pid!), cur != s { return true } // the pid was reused by a different process
        return false
    }

    /// Create generation g atomically with its body. false = somebody else created it first.
    private func createGen(_ g: Int64, _ body: JSONValue) throws -> Bool {
        let tmp = (dir as NSString).appendingPathComponent("state.lock.tmp-\(getpid())-\(P.randomHex(6))")
        var o = body.asObject ?? [:]
        o[JKey("t", ord: Int32(o.count + 1))] = .int(PCADurableState.nowReal())
        try P.writeNew(tmp, Array(P.js(.object(o)).utf8))
        defer { P.unlinkQuiet(tmp) }
        if link(tmp, lockFile(g)) == 0 { return true }
        if errno == EEXIST { return false }
        throw DurableStateError("invalid", "the state directory's filesystem cannot create the lock atomically (link: \(P.errnoName()))")
    }

    private func gcLocks(_ keepFrom: Int64) {
        for f in P.children(dir) {
            if let g = P.lockGen(f) {
                if g < keepFrom { P.unlinkQuiet((dir as NSString).appendingPathComponent(f)) }
            } else if f.hasPrefix("state.lock.tmp-") {
                let rest = f.dropFirst("state.lock.tmp-".count)
                if let dash = rest.firstIndex(of: "-"), let pid = P.digits(rest[..<dash]), pid > 0, !P.pidAlive(Double(pid)) { P.unlinkQuiet((dir as NSString).appendingPathComponent(f)) }
            }
        }
    }

    /// Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics.
    private func probeLinks() throws {
        let a = (dir as NSString).appendingPathComponent("state.probe-\(getpid())-\(P.randomHex(6))")
        let b = a + ".lnk"
        defer { P.unlinkQuiet(a); P.unlinkQuiet(b) }
        func fail(_ why: String) -> DurableStateError {
            DurableStateError("link-unsupported", "the state directory's filesystem does not provide working hard links with exclusive-create semantics (\(why)); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE")
        }
        do { try P.writeNew(a, Array("probe".utf8)) } catch { throw fail("\(error)") }
        if link(a, b) != 0 { throw fail(P.errnoName()) }
        if link(a, b) == 0 || errno != EEXIST { throw fail("link(2) is not atomic/exclusive here") }
        var st = stat()
        if stat(a, &st) != 0 || st.st_nlink != 2 { throw fail("link(2) is not atomic/exclusive here") }
    }

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        mutex.lock()
        defer { mutex.unlock() }
        return try withLockLocked(body)
    }

    private func withLockLocked<T>(_ body: () throws -> T) throws -> T {
        let nonce = P.randomHex(12)
        var mustFence = false
        let deadline = Double(P.nowReal()) + lockTimeout
        while true {
            let (topG, topBody) = topLock()
            var legacyBlocks = false
            if P.exists(legacyLock) {
                let attrs = try? FileManager.default.attributesOfItem(atPath: legacyLock)
                let mtime = attrs?[.modificationDate] as? Date
                let age = mtime.map { P.nowReal() - Int64($0.timeIntervalSince1970 * 1000) } ?? 0
                legacyBlocks = !holderDead(readBody(legacyLock), age)
            }
            let free = topG == 0 || topBody?.st == "free"
            if !legacyBlocks && (free || holderDead(topBody, 0)) {
                let recovering: Int64? = free ? nil : topBody?.recovering
                var b: [(String, JSONValue)] = [("st", .string("held")), ("pid", .int(Int64(getpid()))), ("host", .string(P.hostname())), ("nonce", .string(nonce)), ("boot", .string(P.BOOT_ID))]
                if let n = myNsId { b.append(("ns", .string(n))) }
                if let s = myStart { b.append(("start", .string(s))) }
                if let r = recovering { b.append(("recovering", .int(r))) }
                if try createGen(topG + 1, P.obj(b)) {
                    if topLock().0 != topG + 1 { continue } // a stale creator's re-created generation is buried below the real top: not a lock
                    myGen = topG + 1
                    mustFence = recovering != nil
                    break
                }
                continue // lost the race for that generation: look again immediately
            }
            if !(Double(P.nowReal()) <= deadline) {
                func desc(_ b: LockBody?) -> String {
                    guard let b = b else { return "an unreadable holder record" }
                    if b.pid == nil || b.host == nil || (b.nonce ?? "").isEmpty {
                        return "an incomplete holder record (pid=\(b.pid.map { JS.number($0) } ?? "?") host=\(b.host ?? "?") nonce=\((b.nonce ?? "").isEmpty ? "?" : b.nonce!)); release it with expectedHolder: 'unreadable'"
                    }
                    return "holder pid=\(JS.number(b.pid!)) host=\(b.host!) nonce=\(b.nonce!)\(b.ns != nil && b.ns != myNsId ? " (another PID namespace)" : "")"
                }
                if legacyBlocks && (free || holderDead(topBody, 0)) {
                    throw DurableStateError("lock-timeout", "could not acquire the state lock in \(dir) within \(JS.number(lockTimeout)) ms; blocked by \(legacyLock) (legacy single-file lock of an older version; \(desc(readBody(legacyLock)))). If that holder is provably gone, an operator can release it with recoverDurableState(dir:, force: true, legacyLock: true, expectedHolder:) after confirming the holder is dead")
                }
                throw DurableStateError("lock-timeout", "could not acquire the state lock in \(dir) within \(JS.number(lockTimeout)) ms; blocked by \(lockFile(topG)) (\(desc(topBody))). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState(dir:, force: true, expectedHolder:) after confirming the holder is dead")
            }
            usleep(UInt32(5_000 + Int.random(in: 0..<15_000)))
        }
        heldNonce = nonce
        gcLocks(myGen - 16)
        defer {
            heldNonce = nil
            if (try? createGen(myGen + 1, P.obj([("st", .string("free"))]))) != nil { gcLocks(myGen - 15) } // a live holder is never superseded, so this cannot lose a race
        }
        if mustFence {
            // the recovery we took over may have died before (or after) writing its fence: cut and fence now, under OUR generation, before loading
            P.testCrashPoint("takeover-after-lock")
            try P.writeFence(dir, myGen - 1) { P.testCrashPoint("takeover-after-fence-temp") }
        }
        return try body()
    }

    /// Immediately before EVERY rename this writer makes: this handle's generation must still be the highest and must still name us.
    private func assertLockHeld(_ outcome: String = "nothing was written") throws {
        let (g, body) = topLock()
        if heldNonce != nil, g == myGen, let b = body, b.st == "held", b.nonce == heldNonce { return }
        throw DurableStateError("lock-lost", "the state lock is no longer held by this writer (generation \(myGen), highest \(g) \(body.map { $0.st } ?? "unreadable")); \(outcome)")
    }

    private func commit(_ l: Loaded, _ key_: String, _ valueJson: String) throws {
        let last = l.recs.last
        let seq = (last?.seq ?? 0) + 1
        let prev = last?.h ?? P.GENESIS
        func sealed(op: String, payload: String) -> Rec {
            let ts = nowFn()
            var r = Rec(seq: seq, prev: prev, op: op, payload: payload, ts: ts, gen: myGen, h: "", mac: nil)
            r.h = recHash(seq: seq, prev: prev, op: op, payload: payload, ts: ts, gen: myGen)
            if key != nil { r.mac = macOf(r.h) }
            return r
        }
        var all = l.recs + [sealed(op: "set", payload: "\(key_)\n\(valueJson)")]
        if all.count > compactEvery {
            // compact: ONE checkpoint at the same seq the new record would have, chained from the current tail, carrying the full state
            var nxt = l.state
            nxt[key_] = valueJson
            let entries = nxt.sorted { $0.key.utf16.lexicographicallyPrecedes($1.key.utf16) }.map { JSONValue.array([.string($0.key), .string($0.value)]) }
            all = [sealed(op: "checkpoint", payload: P.js(.array(entries)))]
        }
        let tail = all[all.count - 1]
        // journal first (atomic), head second (atomic): a crash between leaves the head one record behind (repaired by the next writer)
        try P.atomicWrite(journalPath, all.map { P.js(recJSON($0)) }.joined(separator: "\n") + "\n") {
            try self.assertLockHeld()
            P.testCrashPoint("after-temp-write") // test only: the temp journal is on disk, the rename has not happened
        }
        P.testCrashPoint("after-journal-rename") // test only: the journal is renamed into place, the head is not written
        try writeHead(tail, "the journal record (seq \(tail.seq)) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)")
        seen = (tail.seq, tail.h)
    }

    /// Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal.
    private func writeHead(_ tail: Rec, _ outcome: String = "nothing was written") throws {
        var p: [(String, JSONValue)] = [("seq", .int(tail.seq)), ("h", .string(tail.h)), ("gen", .int(myGen))]
        if key != nil { p.append(("mac", .string(macOf(headMsg(tail.seq, tail.h, myGen))))) }
        try P.atomicWrite(headPath, P.js(P.obj(p)) + "\n") { try self.assertLockHeld(outcome) }
    }
}
