import Foundation

/// Conformance for aggregate budget stores (budget-conformance.ts). A budget ledger keeps, per scope key (a principal, an org, a fleet), the reservations of every
/// session and agent of that scope. What it must get right: a reservation counts at once and the cap is enforced in the same atomic step that records it
/// (concurrent clients can never pass it), the same reservation again is a replay, a compare-and-swap on the version has one winner, a release frees budget only
/// for a reservation that exists and was not committed, a commit never revives a release, keys are independent, and acknowledged writes survive a restart or
/// crash. Each check is one such claim, driven against YOUR ledger through a `BudgetLedgerAdapter`.
extension PCAStoreConformance {
    public struct BudgetLedgerHandle {
        public var ledger: any BudgetLedger
        /// Another client on the SAME backend (the first stays usable).
        public var reopen: () throws -> any BudgetLedger
        /// Optional: kill the backend abruptly, then return a client on whatever survived.
        public var crash: (() throws -> any BudgetLedger)?
        public var close: (() -> Void)?
        /// Set by the runner: the adapter's declared durability, so a check can compare it with the ledger's own claim.
        public var adapterDurable: Bool?
        public init(ledger: any BudgetLedger, reopen: @escaping () throws -> any BudgetLedger, crash: (() throws -> any BudgetLedger)? = nil, close: (() -> Void)? = nil) {
            self.ledger = ledger; self.reopen = reopen; self.crash = crash; self.close = close
        }
    }

    public struct BudgetLedgerAdapter {
        public var name: String
        /// Default true. Declare false ONLY for an in-process ledger; its `durable` must then be false too, and the durability checks are skipped and reported.
        public var durable: Bool?
        public var create: () throws -> BudgetLedgerHandle
        public init(name: String, durable: Bool? = nil, create: @escaping () throws -> BudgetLedgerHandle) { self.name = name; self.durable = durable; self.create = create }
    }

    public typealias BudgetCheck = ProfileCheck<BudgetLedgerHandle>
    public typealias BudgetConformanceReport = ProfileReport

    private static let CAP = 200
    private static let K = "principal/alice"
    private static let K2 = "principal/bob"

    /// The `spend` accumulator; `drop` removes members, `over` replaces or adds them (JSON text of the value).
    private static func spend(over: [String: String] = [:], drop: [String] = []) -> JSONValue {
        var o = scJ(#"{"id":"spend","agg":"sum","val":"action.params.amount","sel":{"verbs":["pay"]},"win":{"kind":"task"},"key":null,"domain_max":\#(CAP),"holder":{"kind":"site_local"},"scope":"principal"}"#).asObject ?? [:]
        for (k, v) in over { o[JKey(k)] = scJ(v) }
        for k in drop { o[JKey(k)] = nil }
        return .object(o)
    }

    private static func ev(_ id: String, _ amount: Int, _ t: Int = 1000) -> JSONValue {
        scJ(#"{"id":"\#(id)","verb":"pay","resource":"r","params":{"amount":\#(amount)},"t":\#(t)}"#)
    }

    private static func req(_ id: String, _ amount: Int, expectedVersion: Int? = nil, expiresAt: Int? = nil) -> JSONValue {
        var o: JObject = ["event": ev(id, amount), "accumulators": .array([spend()])]
        if let v = expectedVersion { o["expectedVersion"] = .int(Int64(v)) }
        if let x = expiresAt { o["expiresAt"] = .int(Int64(x)) }
        return .object(o)
    }

    private static func bEvents(_ l: any BudgetLedger, _ key: String = K) throws -> [JSONValue] { try l.snapshot(key).get("events")?.asArray ?? [] }
    private static func bVersion(_ l: any BudgetLedger, _ key: String = K) throws -> JSONValue { try l.snapshot(key).get("version") ?? .null }
    private static func reservedTotal(_ l: any BudgetLedger, _ key: String = K) throws -> Double {
        try bEvents(l, key).filter { $0.get("status")?.asString != "released" }.reduce(0) { $0 + (IV.num($1.get("params")?.get("amount")) ?? 0) }
    }
    private static func bOut(_ v: JSONValue) -> String { v.get("outcome")?.asString ?? "" }
    private static func bRes(_ l: any BudgetLedger, _ id: String, _ amount: Int, _ ex: Int? = nil, _ exp: Int? = nil, key: String = K) throws -> String {
        bOut(try l.reserve(key, req(id, amount, expectedVersion: ex, expiresAt: exp)))
    }
    private static func releaseMk(_ id: String) -> JSONValue { scJ(#"{"v":1,"key":"\#(K)","id":"\#(id)","reason":"effect_failed","at":5,"signer":"s","sig":"x"}"#) }
    private static func ids(_ ev: [JSONValue]) -> [String] { ev.compactMap { $0.get("id")?.asString } }

    public static let BUDGET_CHECKS: [BudgetCheck] = [
        BudgetCheck("empty-key-is-empty", "a key nobody reserved on has version 0 and no events") { h in
            try scEq(try h.ledger.snapshot(K), scJ(#"{"version":0,"events":[]}"#))
        },
        BudgetCheck("reservation-counts-at-once-and-cap-is-inclusive",
                    "a reservation counts as soon as it is made; one that would pass the cap is refused with the post-value, one that reaches it exactly is admitted") { h in
            let a = try h.ledger.reserve(K, req("a", 150))
            try scIs(bOut(a), "reserved")
            try scEq(a.get("post"), scJ(#"{"spend":150}"#))
            let b = try h.ledger.reserve(K, req("b", 51))
            try scEq(JSONValue.array([b.get("acc") ?? .null, b.get("post") ?? .null, b.get("cap") ?? .null]), scJ(#"["spend",201,200]"#), "over-cap refusal \(JS.stringify(b))")
            try scIs(try bRes(h.ledger, "c", 50), "reserved")
            try scIs(try reservedTotal(h.ledger), Double(CAP))
        },
        BudgetCheck("a-refusal-writes-nothing", "an over-cap reservation leaves no event and does not move the version") { h in
            _ = try h.ledger.reserve(K, req("a", 150))
            let before = try h.ledger.snapshot(K)
            try scIs(try bRes(h.ledger, "b", 60), "over_cap")
            try scEq(try h.ledger.snapshot(K), before)
        },
        BudgetCheck("reserve-retry-is-a-replay", "the same event again is a replay that changes nothing and does not count twice; another event under the same id conflicts") { h in
            let first = try h.ledger.reserve(K, req("a", 150))
            try scEq(try h.ledger.reserve(K, req("a", 150)), .object(["outcome": .string("replayed"), "version": first.get("version") ?? .null, "status": .string("reserved")]))
            try scIs(try bRes(h.ledger, "a", 10), "id_conflict")
            try scIs(try reservedTotal(h.ledger), 150)
            try scIs(try bRes(h.ledger, "b", 50), "reserved")
        },
        BudgetCheck("expected-version-is-compare-and-swap",
                    "a reservation naming a stale version conflicts and writes nothing; the current version succeeds; a replay wins over a stale version") { h in
            try scIs(try bRes(h.ledger, "a", 10, 0), "reserved")
            try scEq(try h.ledger.reserve(K, req("b", 10, expectedVersion: 0)), scJ(#"{"outcome":"conflict","version":1}"#))
            try scIs(try bEvents(h.ledger).count, 1)
            try scIs(try bRes(h.ledger, "b", 10, 1), "reserved")
            try scIs(try bRes(h.ledger, "a", 10, 0), "replayed")
        },
        BudgetCheck("racing-reserves-never-pass-the-cap",
                    "forty reservations of 30 racing from four clients against a cap of 200: exactly six land, the total is never above the cap, none is lost or counted twice") { h in
            var clients: [any BudgetLedger] = [h.ledger]
            for _ in 0..<3 { clients.append(try h.reopen()) }
            let rs = scRace((0..<40).map { i -> () -> String in { (try? bRes(clients[i % 4], "r\(i)", 30)) ?? "error" } })
            try scIs(rs.filter { $0 == "reserved" }.count, 6)
            try scIs(rs.filter { $0 == "over_cap" }.count, 34)
            try scIs(try reservedTotal(h.ledger), 180)
            try scIs(Set(ids(try bEvents(h.ledger))).count, 6)
        },
        BudgetCheck("racing-reserves-at-one-version-have-one-winner", "clients reserving with the same expected version: exactly one lands, the others conflict") { h in
            var clients: [any BudgetLedger] = [h.ledger]
            for _ in 0..<2 { clients.append(try h.reopen()) }
            let rs = scRace((0..<9).map { i -> () -> String in { (try? bRes(clients[i % 3], "v\(i)", 1, 0)) ?? "error" } })
            try scIs(rs.filter { $0 == "reserved" }.count, 1)
            try scIs(rs.filter { $0 == "conflict" }.count, 8)
            try scIs(try bEvents(h.ledger).count, 1)
        },
        BudgetCheck("racing-writers-with-retry-fill-the-cap-exactly", "twenty writers of 10 each retrying on conflict against a cap of 200: all twenty land, the twenty-first is refused") { h in
            var clients: [any BudgetLedger] = [h.ledger]
            for _ in 0..<2 { clients.append(try h.reopen()) }
            func one(_ c: any BudgetLedger, _ i: Int) -> String {
                for _ in 0..<100_000 {
                    guard let s = try? c.snapshot(K), let v = s.get("version"), let r = try? c.reserve(K, req("w\(i)", 10, expectedVersion: Int(IV.num(v) ?? 0))) else { return "error" }
                    if bOut(r) != "conflict" { return bOut(r) }
                }
                return "gave up"
            }
            let out = scRace((0..<20).map { i -> () -> String in { one(clients[i % 3], i) } })
            try scNeed(out.allSatisfy { $0 == "reserved" }, out.joined(separator: ","))
            try scIs(try reservedTotal(h.ledger), Double(CAP))
            try scIs(try bRes(h.ledger, "extra", 1), "over_cap")
        },
        BudgetCheck("settle-rules", "commit and release settle only a reservation, are idempotent, and refuse the opposite settlement; an unknown id changes nothing") { h in
            _ = try h.ledger.reserve(K, req("a", 10))
            _ = try h.ledger.reserve(K, req("b", 10))
            try scIs(bOut(try h.ledger.commit(K, "ghost")), "unknown")
            try scIs(bOut(try h.ledger.release(K, "ghost", nil)), "unknown")
            try scIs(bOut(try h.ledger.commit(K, "a")), "settled")
            try scIs(bOut(try h.ledger.commit(K, "a")), "replayed")
            let r1 = try h.ledger.release(K, "a", nil)
            try scIs(bOut(r1) == "refused" ? r1.get("status")?.asString : bOut(r1), "committed")
            try scIs(bOut(try h.ledger.release(K, "b", nil)), "settled")
            try scIs(bOut(try h.ledger.release(K, "b", nil)), "replayed")
            let c1 = try h.ledger.commit(K, "b")
            try scIs(bOut(c1) == "refused" ? c1.get("status")?.asString : bOut(c1), "released")
            try scIs(try bEvents(h.ledger).compactMap { $0.get("status")?.asString }, ["committed", "released"])
        },
        BudgetCheck("release-frees-budget-and-commit-keeps-it", "a released reservation no longer counts; a committed one still does; an open one keeps counting until settled") { h in
            _ = try h.ledger.reserve(K, req("a", 100))
            _ = try h.ledger.reserve(K, req("b", 100))
            try scIs(try bRes(h.ledger, "c", 1), "over_cap")
            _ = try h.ledger.release(K, "a", nil)
            _ = try h.ledger.commit(K, "b")
            try scIs(try bRes(h.ledger, "d", 100), "reserved")
            try scIs(try bRes(h.ledger, "e", 1), "over_cap")
        },
        BudgetCheck("release-without-reserve-credits-nothing", "releasing an id that was never reserved does not create headroom, now or after the id is reserved later") { h in
            try scIs(bOut(try h.ledger.release(K, "ghost", nil)), "unknown")
            try scIs(try bRes(h.ledger, "a", 201), "over_cap")
            try scIs(try bRes(h.ledger, "ghost", 200), "reserved")
            try scIs(try bRes(h.ledger, "b", 1), "over_cap")
        },
        BudgetCheck("a-late-commit-cannot-overspend", "after a reservation was released and its budget reused, committing it is refused, so the committed total never passes the cap") { h in
            _ = try h.ledger.reserve(K, req("a", 200))
            _ = try h.ledger.release(K, "a", nil)
            _ = try h.ledger.reserve(K, req("b", 200))
            try scIs(bOut(try h.ledger.commit(K, "a")), "refused")
            _ = try h.ledger.commit(K, "b")
            try scIs(try bEvents(h.ledger).filter { $0.get("status")?.asString == "committed" }.count, 1)
        },
        BudgetCheck("expiry-releases-only-open-reservations-past-their-deadline",
                    "expire frees a reservation at or after its deadline, never an earlier one, never a committed, started or deadline-less one, and a late commit or start of it is refused") { h in
            _ = try h.ledger.reserve(K, req("a", 40, expiresAt: 500))
            _ = try h.ledger.reserve(K, req("b", 40, expiresAt: 500))
            _ = try h.ledger.reserve(K, req("c", 40))
            _ = try h.ledger.reserve(K, req("d", 40, expiresAt: 500))
            _ = try h.ledger.commit(K, "b")
            _ = try h.ledger.start(K, "d")
            try scEq(try h.ledger.expire(K, .int(499)).get("released"), .array([]))
            try scEq(try h.ledger.expire(K, .int(500)).get("released"), scJ(#"["a"]"#))
            try scEq(try h.ledger.expire(K, .int(10_000)).get("released"), .array([]))
            try scIs(try reservedTotal(h.ledger), 120)
            try scIs(bOut(try h.ledger.commit(K, "a")), "refused")
            try scIs(bOut(try h.ledger.start(K, "a")), "refused")
        },
        BudgetCheck("start-rules",
                    "start marks an open reservation non-expirable and is idempotent; an unknown id changes nothing; a started one can still be committed, or released (the effect did not happen); a released one cannot start") { h in
            _ = try h.ledger.reserve(K, req("a", 10, expiresAt: 5))
            _ = try h.ledger.reserve(K, req("b", 10))
            _ = try h.ledger.reserve(K, req("c", 10))
            let v = try bVersion(h.ledger)
            try scIs(bOut(try h.ledger.start(K, "ghost")), "unknown")
            try scEq(try bVersion(h.ledger), v)
            try scIs(bOut(try h.ledger.start(K, "a")), "settled")
            try scIs(bOut(try h.ledger.start(K, "a")), "replayed")
            try scEq(try h.ledger.expire(K, .int(100)).get("released"), .array([]))
            try scIs(bOut(try h.ledger.commit(K, "a")), "settled")
            try scIs(bOut(try h.ledger.start(K, "a")), "replayed")
            _ = try h.ledger.start(K, "b")
            try scIs(bOut(try h.ledger.release(K, "b", nil)), "settled")
            let s = try h.ledger.start(K, "b")
            try scIs(bOut(s) == "refused" ? s.get("status")?.asString : bOut(s), "released")
            try scNeed(try bEvents(h.ledger).first { $0.get("id")?.asString == "c" }?.get("started") == nil, "an untouched reservation must not be marked started")
        },
        BudgetCheck("keys-are-independent", "two keys have their own caps, versions and events") { h in
            _ = try h.ledger.reserve(K, req("a", 200))
            try scIs(try bRes(h.ledger, "a", 200, key: K2), "reserved")
            try scIs(try bRes(h.ledger, "b", 1), "over_cap")
            try scIs(ids(try bEvents(h.ledger, K2)), ["a"])
            try scEq(try bVersion(h.ledger, K2), .int(1))
        },
        BudgetCheck("windows-reset-the-count", "a period window counts only the events of the period of the new event") { h in
            let w: JSONValue = .array([spend(over: ["win": #"{"kind":"period","ms":1000,"t0":0}"#])])
            func r(_ id: String, _ amount: Int, _ t: Int) throws -> String { bOut(try h.ledger.reserve(K, .object(["event": ev(id, amount, t), "accumulators": w]))) }
            try scIs(try r("a", 200, 100), "reserved")
            try scIs(try r("b", 1, 900), "over_cap")
            try scIs(try r("c", 200, 1100), "reserved")
        },
        BudgetCheck("release-evidence-is-stored-and-bound",
                    "evidence for the reservation is kept with the released event; evidence for another reservation is refused and the reservation stays open") { h in
            _ = try h.ledger.reserve(K, req("a", 10))
            try scThrowsRange("evidence for another reservation") { _ = try h.ledger.release(K, "a", releaseMk("other")) }
            try scEq(try bEvents(h.ledger).first?.get("status"), .string("reserved"))
            try scIs(bOut(try h.ledger.release(K, "a", releaseMk("a"))), "settled")
            try scEq(try bEvents(h.ledger).first?.get("rel"), releaseMk("a"))
        },
        BudgetCheck("invalid-input-is-refused", "a malformed event or request throws and writes nothing") { h in
            var badEvents: [JSONValue] = [ev("", 1)]
            var t = ev("x", 1).asObject ?? [:]; t["t"] = .double(0.5); badEvents.append(.object(t))
            var vb = ev("x", 1).asObject ?? [:]; vb["verb"] = .int(7); badEvents.append(.object(vb))
            for bad in badEvents { try scThrowsRange("malformed event") { _ = try h.ledger.reserve(K, .object(["event": bad, "accumulators": .array([spend()])])) } }
            try scThrowsRange("expectedVersion -1") { _ = try h.ledger.reserve(K, req("x", 1, expectedVersion: -1)) }
            try scThrowsRange("no cap") { _ = try h.ledger.reserve(K, .object(["event": ev("x", 1), "accumulators": .array([spend(drop: ["domain_max"])])])) }
            try scEq(try h.ledger.snapshot(K), scJ(#"{"version":0,"events":[]}"#))
        },
        BudgetCheck("snapshots-are-copies", "mutating what a snapshot returned cannot change the ledger") { h in
            _ = try h.ledger.reserve(K, req("a", 10))
            var s = try h.ledger.snapshot(K).asObject ?? [:]
            s["events"] = .array([]) // a snapshot is a value: changing it is all a caller can do
            try scEq(try bEvents(h.ledger).first?.get("status"), .string("reserved"))
        },
        BudgetCheck("durable-claim-matches-the-adapter",
                    "a ledger says durable: true exactly when its adapter declares durability, so a volatile ledger can never satisfy the non-session refusal") { h in
            try scNeed(h.ledger.durable == (h.adapterDurable != false), "ledger.durable=\(h.ledger.durable) but the adapter declares durable=\(h.adapterDurable != false)")
        },
        BudgetCheck("state-survives-reopen", "every acknowledged reserve, commit and release is visible to a new client after the backend restarts, and the cap still holds", needs: "durable") { h in
            _ = try h.ledger.reserve(K, req("a", 150))
            _ = try h.ledger.reserve(K, req("b", 50))
            _ = try h.ledger.commit(K, "a")
            _ = try h.ledger.release(K, "b", nil)
            let back = try h.reopen()
            try scEq(JSONValue.array(try bEvents(back).map { .array([$0.get("id") ?? .null, $0.get("status") ?? .null]) }), scJ(#"[["a","committed"],["b","released"]]"#))
            try scIs(try bRes(back, "c", 51), "over_cap")
            try scIs(try bRes(back, "c", 50), "reserved")
        },
        BudgetCheck("acknowledged-writes-survive-a-crash", "after an abrupt kill every acknowledged reservation still counts, so a crash can only over-restrict, never reset a cap", needs: "crash") { h in
            _ = try h.ledger.reserve(K, req("a", 200))
            let l = h.ledger
            scFireAndForget { _ = try? l.reserve(K, req("b", 0)) }
            let back = try h.crash!()
            try scIs(try bRes(back, "c", 1), "over_cap")
            try scEq(try bEvents(back).first?.get("id"), .string("a"))
        },
    ]

    /// Run the budget checks (only those named in `only` when given) against fresh handles from the adapter.
    public static func runBudgetLedgerConformance(_ adapter: BudgetLedgerAdapter, only: [String]? = nil) throws -> BudgetConformanceReport {
        try runProfile(BUDGET_CHECKS, adapter: adapter.name, durable: adapter.durable, only: only, create: adapter.create, canCrash: { $0.crash != nil }, close: { $0.close?() },
                   prepare: { $0.adapterDurable = adapter.durable })
    }

    /// The text report: a header line, then one line per check (the first line of a failure's detail).
    public static func formatBudgetReport(_ r: BudgetConformanceReport) -> String { formatProfile("budget ledger", r) }

    // MARK: reference adapters

    /// GOOD, in process: the reference ledger over an in-memory kv. Not durable (declared).
    public static func memoryBudgetLedgerAdapter() -> BudgetLedgerAdapter {
        BudgetLedgerAdapter(name: "KvBudgetLedger over an in-memory kv", durable: false) {
            let kv = PCADurableState.createMemoryDurableKv()
            return BudgetLedgerHandle(ledger: KvBudgetLedger(kv: kv, durable: false), reopen: { KvBudgetLedger(kv: kv, durable: false) })
        }
    }

    /// GOOD, durable: the reference ledger over the crash-safe file state (`openDurableState`), one handle per client.
    public static func durableBudgetLedgerAdapter(dir: String? = nil) -> BudgetLedgerAdapter {
        BudgetLedgerAdapter(name: "KvBudgetLedger over durable-state files", durable: true) {
            let d = dir ?? scTempDir("pca-budgetsc-")
            let open: () throws -> any BudgetLedger = { KvBudgetLedger(kv: try openDurableState(DurableStateOptions(dir: d, lockTimeoutMs: 30_000)), durable: true) }
            return BudgetLedgerHandle(ledger: try open(), reopen: open, crash: open)
        }
    }

    enum BudgetDefect { case expireStarted, noCap, noCas, lostUpdate, amnesia, releaseUnreserved, releaseCommitted, lateCommit, noReplay, sharedKeys, expireCommitted, volatileClaimsDurable }

    /// A document ledger with a switchable defect, for the positive controls (each reproduces a real mistake).
    private final class DefectiveBudget: BudgetLedger, @unchecked Sendable {
        final class Books: @unchecked Sendable { let lock = NSLock(); var docs: [String: PCABudgetLedger.Doc] = [:] }
        typealias D = PCABudgetLedger
        let books: Books
        let defect: BudgetDefect
        /// Every defective ledger claims durability; `volatileClaimsDurable` is declared volatile by its adapter.
        var durable: Bool { true }
        init(_ b: Books, _ d: BudgetDefect) { books = b; defect = d }

        private func dk(_ key: String) -> String { defect == .sharedKeys ? "*" : key }
        private func doc(_ key: String) -> PCABudgetLedger.Doc { books.docs[dk(key)] ?? PCABudgetLedger.Doc() }
        private func put(_ key: String, _ d: PCABudgetLedger.Doc) { books.docs[dk(key)] = d }
        private func settled(_ v: Int64) -> JSONValue { .object(["outcome": .string("settled"), "version": .int(v)]) }

        func snapshot(_ key: String) throws -> JSONValue {
            books.lock.lock(); defer { books.lock.unlock() }
            let d = doc(key)
            return .object(["version": .int(d.ver), "events": .array(d.events.map { .object($0) })])
        }

        func reserve(_ key: String, _ r: JSONValue) throws -> JSONValue {
            books.lock.lock()
            var d = doc(key)
            if defect == .lostUpdate { books.lock.unlock(); Thread.sleep(forTimeInterval: 0.001); books.lock.lock() } // the copy goes stale across the pause
            defer { books.lock.unlock() }
            var rr = r.asObject ?? [:]
            if defect == .noCas { rr["expectedVersion"] = nil }
            if defect == .noCap {
                rr["accumulators"] = .array((r.get("accumulators")?.asArray ?? []).map { a in
                    var o = a.asObject ?? [:]; o["domain_max"] = .int(Canonical.MAX_SAFE); return .object(o)
                })
            }
            let id = r.get("event")?.get("id")?.asString ?? ""
            if defect == .noReplay, var dup = d.events.first(where: { $0[JKey("id")]?.asString == id }) {
                dup["id"] = .string(id + "#dup")
                d.events.append(dup)
                d.ver += 1
                put(key, d)
                return .object(["outcome": .string("reserved"), "version": .int(d.ver), "post": .object([:])])
            }
            let out = try PCABudgetLedger.reserveInDoc(&d, .object(rr))
            put(key, d)
            return out
        }

        func start(_ key: String, _ id: String) throws -> JSONValue {
            books.lock.lock(); defer { books.lock.unlock() }
            var d = doc(key)
            let out = PCABudgetLedger.startInDoc(&d, id)
            put(key, d)
            return out
        }

        func commit(_ key: String, _ id: String) throws -> JSONValue {
            books.lock.lock(); defer { books.lock.unlock() }
            var d = doc(key)
            if defect == .lateCommit, let i = d.events.firstIndex(where: { $0[JKey("id")]?.asString == id }), d.events[i][JKey("status")]?.asString == "released" {
                d.events[i][JKey("status")] = .string("committed")
                d.ver += 1
                put(key, d)
                return settled(d.ver)
            }
            let out = PCABudgetLedger.commitInDoc(&d, id)
            put(key, d)
            return out
        }

        func release(_ key: String, _ id: String, _ evidence: JSONValue?) throws -> JSONValue {
            books.lock.lock(); defer { books.lock.unlock() }
            var d = doc(key)
            let i = d.events.firstIndex { $0[JKey("id")]?.asString == id }
            if defect == .releaseUnreserved && i == nil {
                d.events.append(["id": .string(id), "verb": .string("pay"), "resource": .string("r"), "params": .object(["amount": .int(Int64(-CAP))]), "t": .int(0), "status": .string("committed")])
                d.ver += 1
                put(key, d)
                return settled(d.ver)
            }
            if defect == .releaseCommitted, let j = i, d.events[j][JKey("status")]?.asString == "committed" {
                d.events[j][JKey("status")] = .string("released")
                d.ver += 1
                put(key, d)
                return settled(d.ver)
            }
            let out = try PCABudgetLedger.releaseInDoc(&d, key, id, evidence)
            put(key, d)
            return out
        }

        func expire(_ key: String, _ now: JSONValue) throws -> JSONValue {
            books.lock.lock(); defer { books.lock.unlock() }
            var d = doc(key)
            if defect == .expireCommitted || defect == .expireStarted {
                let t = IV.num(now) ?? .nan
                var released: [JSONValue] = []
                for i in d.events.indices {
                    guard let exp = IV.num(d.events[i][JKey("exp")]), exp <= t else { continue }
                    let status = d.events[i][JKey("status")]?.asString
                    if defect == .expireCommitted ? status != "released" : status == "reserved" {
                        d.events[i][JKey("status")] = .string("released")
                        released.append(d.events[i][JKey("id")] ?? .null)
                    }
                }
                if !released.isEmpty { d.ver += 1 }
                put(key, d)
                return .object(["released": .array(released), "version": .int(d.ver)])
            }
            let out = try PCABudgetLedger.expireInDoc(&d, now)
            put(key, d)
            return out
        }
    }

    private static func defectiveBudget(_ name: String, _ d: BudgetDefect) -> BudgetLedgerAdapter {
        BudgetLedgerAdapter(name: name, durable: d != .volatileClaimsDurable) {
            let books = DefectiveBudget.Books()
            let again: () throws -> any BudgetLedger = { if d == .amnesia { books.lock.lock(); books.docs = [:]; books.lock.unlock() }; return DefectiveBudget(books, d) }
            return BudgetLedgerHandle(ledger: DefectiveBudget(books, d), reopen: again, crash: again)
        }
    }

    public static func noCapBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD no cap check (records every reservation)", .noCap) }
    public static func noCasBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD no compare-and-swap (ignores expectedVersion)", .noCas) }
    public static func lostUpdateBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD lost update (read, await, write)", .lostUpdate) }
    public static func amnesiaBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD amnesia (claims durability, forgets on reopen)", .amnesia) }
    public static func releaseUnreservedBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD release without reserve (credits budget for an unknown id)", .releaseUnreserved) }
    public static func releaseCommittedBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD release of a committed event (frees spent budget)", .releaseCommitted) }
    public static func lateCommitBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD late commit (a released reservation can be committed again)", .lateCommit) }
    public static func noReplayBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD no idempotence (a retried reservation counts twice)", .noReplay) }
    public static func sharedKeysBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD one state for every key (keys leak into each other)", .sharedKeys) }
    public static func expireCommittedBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD expiry releases committed events", .expireCommitted) }
    public static func expireStartedBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD expiry releases started reservations (an effect that ran stops counting)", .expireStarted) }
    public static func volatileClaimsDurableBudgetLedgerAdapter() -> BudgetLedgerAdapter { defectiveBudget("BAD in-process ledger that claims durable: true", .volatileClaimsDurable) }

    public static let BUDGET_REFERENCE_ADAPTERS: [String: () -> BudgetLedgerAdapter] = [
        "budget-memory": memoryBudgetLedgerAdapter,
        "budget-durable-file": { durableBudgetLedgerAdapter() },
        "bad-budget-no-cap": noCapBudgetLedgerAdapter,
        "bad-budget-no-cas": noCasBudgetLedgerAdapter,
        "bad-budget-lost-update": lostUpdateBudgetLedgerAdapter,
        "bad-budget-amnesia": amnesiaBudgetLedgerAdapter,
        "bad-budget-release-unreserved": releaseUnreservedBudgetLedgerAdapter,
        "bad-budget-release-committed": releaseCommittedBudgetLedgerAdapter,
        "bad-budget-late-commit": lateCommitBudgetLedgerAdapter,
        "bad-budget-no-replay": noReplayBudgetLedgerAdapter,
        "bad-budget-shared-keys": sharedKeysBudgetLedgerAdapter,
        "bad-budget-expire-committed": expireCommittedBudgetLedgerAdapter,
        "bad-budget-expire-started": expireStartedBudgetLedgerAdapter,
        "bad-budget-volatile-claims-durable": volatileClaimsDurableBudgetLedgerAdapter,
    ]
}
