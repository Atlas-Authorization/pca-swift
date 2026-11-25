import Foundation

/// Conformance for PCA transparency-log stores (ledger-conformance.ts). A ledger store keeps the commits of an append-only log and its signed checkpoints. What it
/// must get right: positions are assigned exactly once (compare-and-swap on the length, so two writers never take one index and the log never has holes), a
/// batch lands entirely or not at all, retrying a committed batch is a replay, checkpoints never move backwards and never point past the log, acknowledged writes
/// survive a restart or a crash, and a write in flight at a crash is either wholly there or wholly absent. Each check is one such claim, driven against YOUR store
/// through a `LedgerStoreAdapter`.
extension PCAStoreConformance {
    public struct LedgerStoreHandle {
        public var store: any LedgerStore
        /// Another client on the SAME backend (the first stays usable).
        public var reopen: () throws -> any LedgerStore
        /// Optional: kill the backend abruptly, then return a client on whatever survived.
        public var crash: (() throws -> any LedgerStore)?
        public var close: (() -> Void)?
        public init(store: any LedgerStore, reopen: @escaping () throws -> any LedgerStore, crash: (() throws -> any LedgerStore)? = nil, close: (() -> Void)? = nil) {
            self.store = store; self.reopen = reopen; self.crash = crash; self.close = close
        }
    }

    public struct LedgerStoreAdapter {
        public var name: String
        /// Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported.
        public var durable: Bool?
        public var create: () throws -> LedgerStoreHandle
        public init(name: String, durable: Bool? = nil, create: @escaping () throws -> LedgerStoreHandle) { self.name = name; self.durable = durable; self.create = create }
    }

    public typealias LedgerCheck = ProfileCheck<LedgerStoreHandle>
    public typealias LedgerConformanceReport = ProfileReport

    private static func cm(_ i: Int) -> String { "commit-\(i)-" + String(repeating: "x", count: 30) }
    private static func cp(_ size: Int, _ root: String? = nil, _ prev: String = "") -> JSONValue {
        scJ(#"{"sth":{"instance_id":"i","principal":"p","size":\#(size),"root":"\#(root ?? "root-\(size)")","prev_root":"\#(prev)","timestamp":1,"guardian":"g","sig":"s"}}"#)
    }
    private static func range(_ a: Int, _ b: Int) -> [String] { (a..<b).map(cm) }
    private static func arr(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }
    private static func n(_ i: Int) -> JSONValue { .int(Int64(i)) }
    private static func all(_ s: any LedgerStore) throws -> [String] { try s.read(n(0), n(try s.size())) }
    private static func lOut(_ outcome: String, size: Int? = nil, count: Int? = nil) -> JSONValue {
        var o: JObject = ["outcome": .string(outcome)]
        if let s = size { o["size"] = n(s) }
        if let c = count { o["count"] = n(c) }
        return .object(o)
    }
    private static func appendOut(_ s: any LedgerStore, _ expected: Int, _ commits: [String]) throws -> JSONValue { try s.append(n(expected), arr(commits)) }
    private static func outcomeOf(_ v: JSONValue) -> String { v.get("outcome")?.asString ?? "" }
    private static func sizes(_ cps: [JSONValue]) -> [Double] { cps.map { IV.num($0.get("sth")?.get("size")) ?? -1 } }

    /// A writer that retries until its commit is in, the way a real client does.
    private static func appendRetrying(_ s: any LedgerStore, _ commit: String) -> Int {
        for _ in 0..<100_000 {
            guard let size = try? s.size(), let r = try? s.append(n(size), arr([commit])) else { return -1 }
            if ["appended", "replayed"].contains(outcomeOf(r)) { return size }
        }
        return -1
    }

    public static let LEDGER_CHECKS: [LedgerCheck] = [
        LedgerCheck("empty-store-is-empty", "a new store has no entries and no checkpoints, and reads of the empty range succeed") { h in
            try scIs(try h.store.size(), 0)
            try scIs(try h.store.read(n(0), n(0)), [])
            try scIs(try h.store.checkpointCount(), 0)
            try scIs(try h.store.checkpoints(n(0)).count, 0)
        },
        LedgerCheck("append-assigns-the-next-position", "an append at the current length adds its commits in order at exactly those positions") { h in
            try scEq(try appendOut(h.store, 0, [cm(0)]), lOut("appended", size: 1))
            try scEq(try appendOut(h.store, 1, [cm(1), cm(2)]), lOut("appended", size: 3))
            try scIs(try h.store.read(n(0), n(3)), range(0, 3))
            try scIs(try h.store.read(n(1), n(3)), range(1, 3))
            try scIs(try h.store.read(n(3), n(3)), [])
        },
        LedgerCheck("append-at-another-position-conflicts-without-trace", "an append whose expected length is not the current length conflicts, reports the real length, and writes nothing") { h in
            _ = try appendOut(h.store, 0, range(0, 3))
            try scEq(try appendOut(h.store, 5, [cm(9)]), lOut("conflict", size: 3))
            try scEq(try appendOut(h.store, 2, [cm(9)]), lOut("conflict", size: 3))
            try scIs(try all(h.store), range(0, 3))
        },
        LedgerCheck("append-retry-is-a-replay", "repeating a batch already stored at that position is a replay (a prefix of it too); a different batch there conflicts") { h in
            _ = try appendOut(h.store, 0, range(0, 3))
            try scEq(try appendOut(h.store, 0, range(0, 3)), lOut("replayed", size: 3))
            try scEq(try appendOut(h.store, 1, range(1, 3)), lOut("replayed", size: 3))
            try scEq(try appendOut(h.store, 0, [cm(0), "other"]), lOut("conflict", size: 3))
            try scEq(try appendOut(h.store, 2, [cm(2), cm(3)]), lOut("conflict", size: 3))
            try scIs(try all(h.store), range(0, 3))
        },
        LedgerCheck("invalid-input-is-refused", "empty batches, empty or non-string commits and a bad expected length throw and write nothing") { h in
            _ = try appendOut(h.store, 0, [cm(0)])
            let bad: [JSONValue] = [.array([]), scJ(#"[""]"#), .array([.string(cm(1)), .int(7)]), .string("x")]
            for b in bad { try scThrowsRange("append \(JS.stringify(b))") { _ = try h.store.append(n(1), b) } }
            for e in [JSONValue.int(-1), .double(1.5), .double(.nan)] { try scThrowsRange("append at \(JS.stringify(e))") { _ = try h.store.append(e, arr([cm(1)])) } }
            try scIs(try all(h.store), [cm(0)])
            for (f, t) in [(JSONValue.int(-1), JSONValue.int(1)), (.int(1), .int(0)), (.int(0), .int(2)), (.double(0.5), .int(1))] {
                try scThrowsRange("read \(JS.stringify(f))..\(JS.stringify(t))") { _ = try h.store.read(f, t) }
            }
        },
        LedgerCheck("commit-strings-are-stored-exactly", "unicode, quotes, separators and long commits come back byte for byte") { h in
            let odd = ["a\"b\\c", "gr\u{e4}nt-\u{1F512}- -\u{1}", String(repeating: "x", count: 5000), "__proto__", " leading and trailing "]
            _ = try appendOut(h.store, 0, odd)
            try scIs(try all(h.store), odd)
        },
        LedgerCheck("racing-appends-at-one-position-have-one-winner",
                    "clients appending at the same expected length: exactly one is appended, none is lost or duplicated, the log is the winner batch") { h in
            var clients: [any LedgerStore] = [h.store]
            for _ in 0..<3 { clients.append(try h.reopen()) }
            let r = scRace((0..<8).map { i -> () -> JSONValue in { (try? appendOut(clients[i % 4], 0, [cm(100 + i)])) ?? .null } })
            try scIs(r.filter { outcomeOf($0) == "appended" }.count, 1)
            try scIs(r.filter { outcomeOf($0) == "conflict" }.count, 7)
            let log = try all(h.store)
            try scIs(log.count, 1)
            try scNeed(range(100, 108).contains(log[0]), "the log holds a commit nobody appended")
        },
        LedgerCheck("racing-writers-with-retry-fill-every-position-once",
                    "sixteen writers each retrying until their commit is in: positions are unique, there are no holes, every commit is present exactly once") { h in
            var clients: [any LedgerStore] = [h.store]
            for _ in 0..<2 { clients.append(try h.reopen()) }
            let idx = scRace((0..<16).map { i -> () -> Int in { appendRetrying(clients[i % 3], cm(200 + i)) } })
            try scIs(Set(idx).count, 16)
            try scIs(idx.sorted(), Array(0..<16))
            let log = try all(h.store)
            try scIs(log.sorted(), range(200, 216).sorted())
            for (i, p) in idx.enumerated() { try scIs(log[p], cm(200 + i)) }
        },
        LedgerCheck("a-batch-is-all-or-nothing", "a batch that conflicts leaves none of its commits behind, and a batch that lands lands every commit") { h in
            _ = try appendOut(h.store, 0, range(0, 2))
            try scIs(outcomeOf(try appendOut(h.store, 5, range(10, 14))), "conflict")
            try scIs(try all(h.store), range(0, 2))
            try scEq(try appendOut(h.store, 2, range(10, 14)), lOut("appended", size: 6))
            try scIs(try all(h.store), range(0, 2) + range(10, 14))
        },
        LedgerCheck("checkpoints-append-by-count-and-replay", "a checkpoint appends at the exact count; the same one again is a replay; another at that position conflicts") { h in
            _ = try appendOut(h.store, 0, range(0, 6))
            try scEq(try h.store.appendCheckpoint(n(0), cp(2)), lOut("appended", count: 1))
            try scEq(try h.store.appendCheckpoint(n(0), cp(2)), lOut("replayed", count: 1))
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(0), cp(3))), "conflict")
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(2), cp(3))), "conflict")
            try scEq(try h.store.appendCheckpoint(n(1), cp(5, "root-5", "root-2")), lOut("appended", count: 2))
            try scEqD(sizes(try h.store.checkpoints(n(0))), [2, 5])
            try scEqD(sizes(try h.store.checkpoints(n(1))), [5])
            try scIs(try h.store.checkpointCount(), 2)
        },
        LedgerCheck("checkpoints-stay-inside-the-log-and-never-go-back",
                    "a checkpoint beyond the end of the log, below the previous one, or equal in size with another root is refused") { h in
            _ = try appendOut(h.store, 0, range(0, 4))
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(0), cp(5))), "conflict")
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(0), cp(3))), "appended")
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(1), cp(2))), "conflict")
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(1), cp(3, "other-root"))), "conflict")
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(1), cp(3))), "appended") // equal size, same root: allowed
            try scIs(outcomeOf(try h.store.appendCheckpoint(n(2), .null)), "conflict")
            try scIs(try h.store.checkpointCount(), 2)
        },
        LedgerCheck("racing-checkpoints-have-one-winner", "checkpoints racing for one position: exactly one lands") { h in
            _ = try appendOut(h.store, 0, range(0, 6))
            let other = try h.reopen()
            let a = h.store
            let r = try scRaceTry([{ try a.appendCheckpoint(n(0), cp(2)) }, { try other.appendCheckpoint(n(0), cp(3)) },
                                   { try a.appendCheckpoint(n(0), cp(4)) }, { try other.appendCheckpoint(n(0), cp(5)) }])
            try scIs(r.filter { outcomeOf($0) == "appended" }.count, 1)
            try scIs(try h.store.checkpointCount(), 1)
        },
        LedgerCheck("reads-are-snapshots", "mutating what a read returned cannot change the store") { h in
            _ = try appendOut(h.store, 0, range(0, 3))
            _ = try h.store.appendCheckpoint(n(0), cp(2))
            var log = try h.store.read(n(0), n(3))
            log[0] = "mutated" // the returned array is a copy: changing it is all a caller can do
            var c = try h.store.checkpoints(n(0))
            c[0] = .null
            try scIs(try all(h.store), range(0, 3))
            try scEqD(sizes(try h.store.checkpoints(n(0))), [2])
        },
        LedgerCheck("state-survives-reopen", "every acknowledged append and checkpoint is visible to a new client after the backend restarts", needs: "durable") { h in
            _ = try appendOut(h.store, 0, range(0, 5))
            _ = try h.store.appendCheckpoint(n(0), cp(3))
            _ = try appendOut(h.store, 5, range(5, 7))
            let back = try h.reopen()
            try scIs(try all(back), range(0, 7))
            try scEq(JSONValue.array(try back.checkpoints(n(0))), .array([cp(3)]))
            try scEq(try appendOut(back, 7, [cm(7)]), lOut("appended", size: 8))
        },
        LedgerCheck("acknowledged-writes-survive-a-crash",
                    "after an abrupt kill every acknowledged write is present and the log is a prefix of what was written: no holes, no partial batch", needs: "crash") { h in
            _ = try appendOut(h.store, 0, range(0, 3))
            _ = try h.store.appendCheckpoint(n(0), cp(2))
            let s = h.store
            scFireAndForget { _ = try? appendOut(s, 3, range(3, 7)) }
            let back = try h.crash!()
            let log = try all(back)
            try scNeed(log.count == 3 || log.count == 7, "log has \(log.count) entries") // the batch of four is whole or absent
            try scIs(log, range(0, log.count))
            try scEq(JSONValue.array(try back.checkpoints(n(0))), .array([cp(2)]))
            try scEq(try appendOut(back, 3, range(3, 7)), lOut(log.count == 3 ? "appended" : "replayed", size: 7))
            try scIs(try all(back), range(0, 7))
        },
    ]

    /// Run the ledger checks (only those named in `only` when given) against fresh handles from the adapter.
    public static func runLedgerStoreConformance(_ adapter: LedgerStoreAdapter, only: [String]? = nil) throws -> LedgerConformanceReport {
        try runProfile(LEDGER_CHECKS, adapter: adapter.name, durable: adapter.durable, only: only, create: adapter.create, canCrash: { $0.crash != nil }, close: { $0.close?() })
    }

    /// The text report: a header line, then one line per check (the first line of a failure's detail).
    public static func formatLedgerReport(_ r: LedgerConformanceReport) -> String { formatProfile("ledger store", r) }

    // MARK: reference adapters

    /// GOOD, in process: the reference store over an in-memory kv. Not durable (declared).
    public static func memoryLedgerStoreAdapter() -> LedgerStoreAdapter {
        LedgerStoreAdapter(name: "KvLedgerStore over an in-memory kv", durable: false) {
            let kv = PCADurableState.createMemoryDurableKv()
            return LedgerStoreHandle(store: KvLedgerStore(kv: kv), reopen: { KvLedgerStore(kv: kv) })
        }
    }

    /// GOOD, durable: the reference store over the crash-safe file state (`openDurableState`), one handle per client.
    public static func durableLedgerStoreAdapter(dir: String? = nil) -> LedgerStoreAdapter {
        LedgerStoreAdapter(name: "KvLedgerStore over durable-state files", durable: true) {
            let d = dir ?? scTempDir("pca-ledgersc-")
            let open: () throws -> any LedgerStore = { KvLedgerStore(kv: try openDurableState(DurableStateOptions(dir: d, lockTimeoutMs: 30_000))) }
            return LedgerStoreHandle(store: try open(), reopen: open, crash: open)
        }
    }

    enum LedgerDefect { case noCas, partialBatch, lostUpdate, amnesia, checkpointRegress, noReplay }

    private final class DefectiveLedger: LedgerStore, @unchecked Sendable {
        final class Book: @unchecked Sendable { let lock = NSLock(); var doc = KvLedgerStore.Doc() }
        let book: Book
        let defect: LedgerDefect
        init(_ b: Book, _ d: LedgerDefect) { book = b; defect = d }

        func size() throws -> Int { book.lock.lock(); defer { book.lock.unlock() }; return book.doc.commits.count }

        func read(_ from: JSONValue, _ to: JSONValue) throws -> [String] {
            book.lock.lock(); defer { book.lock.unlock() }
            guard let f = StoreJ.safe(from), let t = StoreJ.safe(to), f >= 0, f <= t, t <= Int64(book.doc.commits.count) else { throw PCAStoreError.range("read") }
            return Array(book.doc.commits[Int(f)..<Int(t)])
        }

        func append(_ expected: JSONValue, _ commits: JSONValue) throws -> JSONValue {
            guard let e = StoreJ.safe(expected), e >= 0, let cs = commits.asArray, !cs.isEmpty, cs.allSatisfy(KvLedgerStore.isCommit) else { throw PCAStoreError.range("append") }
            let strs = cs.compactMap { $0.asString }
            book.lock.lock()
            if defect == .noCas {
                defer { book.lock.unlock() }
                book.doc.commits.append(contentsOf: strs)
                return .object(["outcome": .string("appended"), "size": .int(Int64(book.doc.commits.count))])
            }
            if defect == .partialBatch && e != Int64(book.doc.commits.count) {
                defer { book.lock.unlock() }
                book.doc.commits.append(strs[0])
                return .object(["outcome": .string("conflict"), "size": .int(Int64(book.doc.commits.count))])
            }
            var work = book.doc
            if defect == .lostUpdate { book.lock.unlock(); Thread.sleep(forTimeInterval: 0.001); book.lock.lock() }
            defer { book.lock.unlock() }
            let out = try KvLedgerStore.appendToDoc(&work, expected, commits)
            let o = out.get("outcome")?.asString
            if o == "appended" { book.doc = work }
            if defect == .noReplay && o == "replayed" { return .object(["outcome": .string("conflict"), "size": out.get("size") ?? .null]) }
            return out
        }

        func checkpointCount() throws -> Int { book.lock.lock(); defer { book.lock.unlock() }; return book.doc.checkpoints.count }

        func checkpoints(_ from: JSONValue) throws -> [JSONValue] {
            book.lock.lock(); defer { book.lock.unlock() }
            // Array.prototype.slice(from): no validation; a negative start counts from the end, anything else is clamped
            let count = book.doc.checkpoints.count
            let rel = (IV.num(from) ?? 0).rounded(.towardZero)
            let start = rel.isNaN ? 0 : rel < 0 ? Swift.max(Double(count) + rel, 0) : Swift.min(rel, Double(count))
            return Array(book.doc.checkpoints[Int(start)...])
        }

        func appendCheckpoint(_ expected: JSONValue, _ c: JSONValue) throws -> JSONValue {
            book.lock.lock(); defer { book.lock.unlock() }
            let count = book.doc.checkpoints.count
            let conflict = { (why: String) -> JSONValue in .object(["outcome": .string("conflict"), "count": .int(Int64(count)), "reason": .string(why)]) }
            if defect == .checkpointRegress, StoreJ.safe(expected) == Int64(count), JS.truthy(c.get("sth")) {
                book.doc.checkpoints.append(c)
                return .object(["outcome": .string("appended"), "count": .int(Int64(count + 1))])
            }
            guard StoreJ.safe(expected) == Int64(count) else { return conflict("position") }
            // the reference compares the raw values: a size that is not a number is neither above the log nor below the previous checkpoint
            guard let sth = c.get("sth"), JS.truthy(sth) else { return conflict("invalid") }
            let size = IV.num(sth.get("size")) ?? .nan
            if size > Double(book.doc.commits.count) { return conflict("invalid") }
            if let last = book.doc.checkpoints.last?.get("sth"), JS.truthy(last) {
                let ls = IV.num(last.get("size")) ?? .nan
                if size < ls || (StoreJ.same(sth.get("size"), last.get("size")) && !StoreJ.same(sth.get("root"), last.get("root"))) { return conflict("invalid") }
            }
            book.doc.checkpoints.append(c)
            return .object(["outcome": .string("appended"), "count": .int(Int64(count + 1))])
        }
    }

    private static func defectiveLedger(_ name: String, _ d: LedgerDefect) -> LedgerStoreAdapter {
        LedgerStoreAdapter(name: name, durable: true) {
            let book = DefectiveLedger.Book()
            let again: () throws -> any LedgerStore = { if d == .amnesia { book.lock.lock(); book.doc = KvLedgerStore.Doc(); book.lock.unlock() }; return DefectiveLedger(book, d) }
            return LedgerStoreHandle(store: DefectiveLedger(book, d), reopen: again, crash: again)
        }
    }

    public static func noCasLedgerStoreAdapter() -> LedgerStoreAdapter { defectiveLedger("BAD no compare-and-swap (appends at the tail whatever the caller saw)", .noCas) }
    public static func partialBatchLedgerStoreAdapter() -> LedgerStoreAdapter { defectiveLedger("BAD partial batch (a conflicting batch leaves its first commit behind)", .partialBatch) }
    public static func lostUpdateLedgerStoreAdapter() -> LedgerStoreAdapter { defectiveLedger("BAD lost update (read, await, write)", .lostUpdate) }
    public static func amnesiaLedgerStoreAdapter() -> LedgerStoreAdapter { defectiveLedger("BAD amnesia (claims durability, forgets on reopen)", .amnesia) }
    public static func checkpointRegressLedgerStoreAdapter() -> LedgerStoreAdapter { defectiveLedger("BAD checkpoint regression (accepts a checkpoint below the previous one)", .checkpointRegress) }
    public static func noReplayLedgerStoreAdapter() -> LedgerStoreAdapter { defectiveLedger("BAD no idempotence (a retried batch conflicts)", .noReplay) }

    public static let LEDGER_REFERENCE_ADAPTERS: [String: () -> LedgerStoreAdapter] = [
        "ledger-memory": memoryLedgerStoreAdapter,
        "ledger-durable-file": { durableLedgerStoreAdapter() },
        "bad-ledger-no-cas": noCasLedgerStoreAdapter,
        "bad-ledger-partial-batch": partialBatchLedgerStoreAdapter,
        "bad-ledger-lost-update": lostUpdateLedgerStoreAdapter,
        "bad-ledger-amnesia": amnesiaLedgerStoreAdapter,
        "bad-ledger-checkpoint-regress": checkpointRegressLedgerStoreAdapter,
        "bad-ledger-no-replay": noReplayLedgerStoreAdapter,
    ]
}
