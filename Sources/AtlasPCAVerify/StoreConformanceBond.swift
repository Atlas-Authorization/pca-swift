import Foundation

/// Conformance for PCA bond-settlement stores (bond-conformance.ts). A bond store keeps INTERNAL ACCOUNTING for the optimistic path (escrow, depositors,
/// challengers, treasury); no money moves. What it must get right is atomicity and idempotence: a transition (open, release, slash) applies in full or not at
/// all, a retry of a committed transition returns the stored record and moves nothing, two racing transitions on one bond have exactly one winner, and an
/// acknowledged commit survives a restart or a crash. Each check is one such claim, driven against YOUR store through a `BondStoreAdapter`.
extension PCAStoreConformance {
    public struct BondStoreHandle {
        public var store: any BondStore
        /// Another client on the SAME backend (the first stays usable).
        public var reopen: () throws -> any BondStore
        /// Optional: kill the backend abruptly, then return a client on whatever survived.
        public var crash: (() throws -> any BondStore)?
        public var close: (() -> Void)?
        public init(store: any BondStore, reopen: @escaping () throws -> any BondStore, crash: (() throws -> any BondStore)? = nil, close: (() -> Void)? = nil) {
            self.store = store; self.reopen = reopen; self.crash = crash; self.close = close
        }
    }

    public struct BondStoreAdapter {
        public var name: String
        /// Default true. Declare false ONLY for an in-process store; the durability checks are then skipped and reported.
        public var durable: Bool?
        public var create: () throws -> BondStoreHandle
        public init(name: String, durable: Bool? = nil, create: @escaping () throws -> BondStoreHandle) { self.name = name; self.durable = durable; self.create = create }
    }

    public typealias BondCheck = ProfileCheck<BondStoreHandle>
    public typealias BondConformanceReport = ProfileReport

    // MARK: plan builders (the store never verifies signatures; records are opaque to it)

    private static func bRec(_ id: String, _ action: String, _ amount: Int, _ from: String, _ to: String, _ evidence: String = "", split: Bool = false) -> JSONValue {
        let sp = split
            ? #","split":{"amount":\#(amount),"challengerReward":\#(amount / 2),"victimCompensation":0,"treasuryRemainder":\#(amount / 2),"challengerAccount":"chal","victimAccount":"pool","treasuryAccount":"treasury"}"#
            : ""
        return scJ(#"{"claimId":"\#(id)","action":"\#(action)","amount":\#(amount),"from":"\#(from)","to":"\#(to)","at":1,"evidenceDigest":"\#(evidence)"\#(sp),"sig":"sig"}"#)
    }

    private static func bPlan(_ id: String, _ expect: String, _ next: String, open: String? = nil, moves: String, record: JSONValue) -> JSONValue {
        var o = scJ(#"{"claimId":"\#(id)","expect":"\#(expect)","next":"\#(next)"\#(open.map { #","open":"# + $0 } ?? ""),"moves":\#(moves)}"#).asObject ?? [:]
        o["record"] = record
        return .object(o)
    }

    private static func openPlan(_ id: String, _ dep: String, _ amount: Int, maxClaims: Int = 100, maxAmount: Int = 1_000_000_000) -> JSONValue {
        bPlan(id, "none", "open", open: #"{"amount":\#(amount),"depositor":"\#(dep)","maxOpenClaims":\#(maxClaims),"maxOpenAmount":\#(maxAmount)}"#,
              moves: #"[{"account":"\#(dep)","op":"debit","amount":\#(amount)},{"account":"escrow","op":"credit","amount":\#(amount)}]"#, record: bRec(id, "open", amount, dep, "escrow"))
    }

    private static func releasePlan(_ id: String, _ dep: String, _ amount: Int) -> JSONValue {
        bPlan(id, "open", "released", moves: #"[{"account":"escrow","op":"debit","amount":\#(amount)},{"account":"\#(dep)","op":"credit","amount":\#(amount)}]"#,
              record: bRec(id, "release", amount, "escrow", dep))
    }

    private static func slashPlan(_ id: String, _ amount: Int, _ evidence: String = "ev") -> JSONValue {
        bPlan(id, "open", "slashed",
              moves: #"[{"account":"escrow","op":"debit","amount":\#(amount)},{"account":"chal","op":"credit","amount":\#(amount / 2)},{"account":"treasury","op":"credit","amount":\#(amount / 2)}]"#,
              record: bRec(id, "slash", amount, "escrow", "treasury", evidence, split: true))
    }

    private static func withKey(_ v: JSONValue, _ k: String, _ x: JSONValue) -> JSONValue { var o = v.asObject ?? [:]; o[JKey(k)] = x; return .object(o) }

    private static func at(_ n: Int) -> JSONValue { .int(Int64(n)) }

    private static func bal(_ s: any BondStore, _ accounts: String...) throws -> [Double] {
        try accounts.map { IV.num(try s.read("", $0).get("balances")?.asArray?.first?.asArray?.last) ?? 0 }
    }
    private static func bondStatus(_ s: any BondStore, _ id: String) throws -> String { try s.read(id, nil).get("bond")?.get("status")?.asString ?? "none" }
    private static func highWater(_ s: any BondStore, _ id: String = "") throws -> JSONValue { try s.read(id, nil).get("highWater") ?? .null }
    private static func total(_ s: any BondStore) throws -> Double { try bal(s, "alice", "bob", "escrow", "chal", "treasury").reduce(0, +) }
    private static func outcome(_ v: JSONValue) -> String { v.get("outcome")?.asString ?? "" }
    private static func commitOut(_ s: any BondStore, _ plan: JSONValue, _ at: JSONValue) throws -> String { outcome(try s.commit(plan, at)) }
    private static func recordCount(_ s: any BondStore, _ id: String) throws -> Int { try s.read(id, nil).get("bond")?.get("records")?.asArray?.count ?? 0 }
    private static func deposit(_ s: any BondStore, _ a: String, _ n: Double) throws -> Double { try s.deposit(.string(a), .double(n)) }

    // MARK: the checks

    public static let BOND_CHECKS: [BondCheck] = [
        BondCheck("empty-store-reads-empty",
                  "an unknown bond reads as absent, an unknown account as balance 0, and the time high-water mark starts at 0") { h in
            try scEq(try h.store.read("nope", "alice"), scJ(#"{"balances":[["alice",0]],"openTotals":{"count":0,"sum":0},"highWater":0}"#))
        },
        BondCheck("deposit-validates-and-accumulates", "deposit credits exactly, returns the new balance, and refuses a non-positive, non-finite or unnamed deposit") { h in
            try scIs(try deposit(h.store, "alice", 2.5), 2.5)
            try scIs(try deposit(h.store, "alice", 0.5), 3)
            for bad in [0.0, -1, Double.nan, Double.infinity] { try scThrows("deposit \(bad)") { _ = try deposit(h.store, "alice", bad) } }
            try scThrows("unnamed deposit") { _ = try deposit(h.store, "", 1) }
            try scEqD(try bal(h.store, "alice"), [3])
        },
        BondCheck("open-is-atomic-and-recorded", "an open moves the collateral, stores the row with its record, and raises the high-water mark, all together") { h in
            _ = try deposit(h.store, "alice", 100)
            let plan = openPlan("b1", "alice", 60)
            try scEq(try h.store.commit(plan, at(500)), .object(["outcome": .string("committed"), "record": plan.get("record") ?? .null]))
            let snap = try h.store.read("b1", "alice")
            let row: JSONValue = .object(["claimId": .string("b1"), "amount": at(60), "depositor": .string("alice"), "status": .string("open"), "records": .array([plan.get("record") ?? .null])])
            try scEq(snap, .object(["bond": row, "balances": scJ(#"[["alice",40]]"#), "openTotals": scJ(#"{"count":1,"sum":60}"#), "highWater": at(500)]))
            try scEqD(try bal(h.store, "escrow"), [60])
        },
        BondCheck("open-overdraft-refused-without-trace", "an open the depositor cannot fund is a conflict and leaves balances, bonds and the high-water mark untouched") { h in
            _ = try deposit(h.store, "alice", 10)
            try scIs(try commitOut(h.store, openPlan("b1", "alice", 60), at(900)), "conflict")
            try scEq(try h.store.read("b1", "alice"), scJ(#"{"balances":[["alice",10]],"openTotals":{"count":0,"sum":0},"highWater":0}"#))
            try scEqD(try bal(h.store, "escrow"), [0])
        },
        BondCheck("open-retry-is-replayed-and-different-terms-conflict", "committing the same open again returns the stored record and moves nothing; other terms for that bond conflict") { h in
            _ = try deposit(h.store, "alice", 100)
            let plan = openPlan("b1", "alice", 60)
            _ = try h.store.commit(plan, at(1))
            try scEq(try h.store.commit(plan, at(2)), .object(["outcome": .string("replayed"), "record": plan.get("record") ?? .null]))
            try scIs(try commitOut(h.store, openPlan("b1", "alice", 61), at(3)), "conflict")
            try scIs(try commitOut(h.store, openPlan("b1", "bob", 60), at(3)), "conflict")
            try scEqD(try bal(h.store, "alice", "escrow"), [40, 60])
            try scIs(try recordCount(h.store, "b1"), 1)
        },
        BondCheck("open-caps-are-rechecked-at-commit", "the per-depositor open-claim and open-amount caps hold inside the store, whatever the planner saw") { h in
            _ = try deposit(h.store, "alice", 100)
            func o(_ id: String, _ n: Int) -> JSONValue { openPlan(id, "alice", n, maxClaims: 2, maxAmount: 50) }
            try scIs(try commitOut(h.store, o("c1", 30), at(1)), "committed")
            try scIs(try commitOut(h.store, o("c2", 21), at(1)), "conflict") // 30 + 21 > 50
            try scIs(try commitOut(h.store, o("c3", 20), at(1)), "committed")
            try scIs(try commitOut(h.store, o("c4", 1), at(1)), "conflict") // third open claim
            try scEqD(try bal(h.store, "alice", "escrow"), [50, 50])
        },
        BondCheck("settle-applies-every-move-once", "a release and a slash apply all their balance moves, store the record, and conserve the total") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("r", "alice", 20), at(1))
            _ = try h.store.commit(openPlan("s", "alice", 40), at(1))
            let rel = releasePlan("r", "alice", 20), sl = slashPlan("s", 40)
            try scEq(try h.store.commit(rel, at(2)), .object(["outcome": .string("committed"), "record": rel.get("record") ?? .null]))
            try scEq(try h.store.commit(sl, at(3)), .object(["outcome": .string("committed"), "record": sl.get("record") ?? .null]))
            try scEqD(try bal(h.store, "alice", "escrow", "chal", "treasury"), [60, 0, 20, 20])
            try scIs(try total(h.store), 100)
            try scIs([try bondStatus(h.store, "r"), try bondStatus(h.store, "s")], ["released", "slashed"])
            try scEq(try h.store.read("s", nil).get("bond")?.get("records"), .array([openPlan("s", "alice", 40).get("record") ?? .null, sl.get("record") ?? .null]))
        },
        BondCheck("settle-needs-the-expected-phase", "settling an absent bond or from the wrong phase is a conflict that changes nothing, high-water mark included") { h in
            _ = try deposit(h.store, "alice", 100)
            try scIs(try commitOut(h.store, releasePlan("ghost", "alice", 5), at(9)), "conflict")
            _ = try h.store.commit(openPlan("b", "alice", 20), at(10))
            _ = try h.store.commit(releasePlan("b", "alice", 20), at(11))
            let before = (try bal(h.store, "alice", "escrow", "treasury", "chal"), try highWater(h.store, "b"))
            try scIs(try commitOut(h.store, slashPlan("b", 20), at(99)), "conflict")
            let after = (try bal(h.store, "alice", "escrow", "treasury", "chal"), try highWater(h.store, "b"))
            try scIs(after.0, before.0)
            try scEq(after.1, before.1)
            try scIs(try bondStatus(h.store, "b"), "released")
        },
        BondCheck("settle-overdraw-refused-without-trace", "a settlement whose debit would overdraw an account is refused whole: no credit lands, the phase does not change") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("b", "alice", 20), at(1))
            let greedy = withKey(slashPlan("b", 20), "moves", scJ(#"[{"account":"escrow","op":"debit","amount":21},{"account":"treasury","op":"credit","amount":21}]"#))
            try scIs(try commitOut(h.store, greedy, at(5)), "conflict")
            try scEqD(try bal(h.store, "escrow", "treasury"), [20, 0])
            try scIs(try bondStatus(h.store, "b"), "open")
        },
        BondCheck("settle-retry-returns-the-stored-record", "the same settlement again is replayed with the first record and moves nothing; the same action with other evidence conflicts") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("b", "alice", 40), at(1))
            let sl = slashPlan("b", 40, "ev-1")
            _ = try h.store.commit(sl, at(2))
            var other = sl.get("record")?.asObject ?? [:]
            other["at"] = at(77)
            other["sig"] = .string("other")
            let retry = withKey(slashPlan("b", 40, "ev-1"), "record", .object(other))
            try scEq(try h.store.commit(retry, at(3)), .object(["outcome": .string("replayed"), "record": sl.get("record") ?? .null]))
            try scIs(try commitOut(h.store, slashPlan("b", 40, "ev-2"), at(3)), "conflict")
            try scIs(try commitOut(h.store, releasePlan("b", "alice", 40), at(3)), "conflict")
            try scEqD(try bal(h.store, "alice", "escrow", "chal", "treasury"), [60, 0, 20, 20])
            try scIs(try recordCount(h.store, "b"), 2)
        },
        BondCheck("racing-identical-settles-commit-once", "eight clients racing the same release: one commits, seven are replays, funds move once") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("b", "alice", 40), at(1))
            var clients: [any BondStore] = [h.store]
            for _ in 0..<3 { clients.append(try h.reopen()) }
            let r = scRace((0..<8).map { i -> () -> JSONValue in { (try? clients[i % clients.count].commit(releasePlan("b", "alice", 40), at(10 + i))) ?? .null } })
            try scIs(r.map(outcome).sorted(), ["committed"] + Array(repeating: "replayed", count: 7))
            try scEqD(try bal(h.store, "alice", "escrow"), [100, 0])
            try scIs(try recordCount(h.store, "b"), 2)
        },
        BondCheck("racing-conflicting-settles-have-one-winner", "a release racing a slash on one bond: exactly one commits, the books show only the winner, the total is conserved") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("b", "alice", 40), at(1))
            let other = try h.reopen()
            let a = h.store
            let r = scRace([{ (try? a.commit(releasePlan("b", "alice", 40), at(5))) ?? .null }, { (try? other.commit(slashPlan("b", 40), at(5))) ?? .null },
                            { (try? a.commit(slashPlan("b", 40), at(5))) ?? .null }, { (try? other.commit(releasePlan("b", "alice", 40), at(5))) ?? .null }])
            try scIs(r.filter { outcome($0) == "committed" }.count, 1)
            try scIs(r.filter { ["conflict", "replayed"].contains(outcome($0)) }.count, 3)
            try scEqD(try bal(h.store, "alice", "escrow", "chal", "treasury"), try bondStatus(h.store, "b") == "released" ? [100, 0, 0, 0] : [60, 0, 20, 20])
            try scIs(try total(h.store), 100)
        },
        BondCheck("racing-opens-for-the-same-bond-commit-once", "concurrent identical opens collect the collateral once; a differing open loses") { h in
            _ = try deposit(h.store, "alice", 100)
            let other = try h.reopen()
            let a = h.store
            let r = try scRaceTry([{ try a.commit(openPlan("b", "alice", 60), at(1)) }, { try other.commit(openPlan("b", "alice", 60), at(1)) },
                                   { try a.commit(openPlan("b", "alice", 60), at(1)) }, { try other.commit(openPlan("b", "alice", 50), at(1)) }])
            try scIs(r.filter { outcome($0) == "committed" }.count, 1)
            try scEqD(try bal(h.store, "alice", "escrow"), outcome(r[3]) == "committed" ? [50, 50] : [40, 60])
            try scIs(try total(h.store), 100)
        },
        BondCheck("racing-opens-cannot-overdraw", "concurrent opens by one depositor that together exceed the balance: the sum committed never exceeds what was deposited") { h in
            _ = try deposit(h.store, "alice", 100)
            let other = try h.reopen()
            let a = h.store
            let r = try scRaceTry((0..<6).map { i -> () throws -> JSONValue in { try (i % 2 == 1 ? a : other).commit(openPlan("b\(i)", "alice", 40), at(1)) } })
            try scIs(r.filter { outcome($0) == "committed" }.count, 2)
            try scEqD(try bal(h.store, "alice", "escrow"), [20, 80])
        },
        BondCheck("concurrent-deposits-lose-nothing", "sixteen racing deposits add up exactly") { h in
            let other = try h.reopen()
            let a = h.store
            _ = scRace((0..<16).map { i -> () -> Void in { _ = try? (i % 2 == 1 ? a : other).deposit(.string("alice"), .int(1)) } })
            try scEqD(try bal(h.store, "alice"), [16])
        },
        BondCheck("time-high-water-only-moves-forward", "the recorded time is the maximum of every committed observedAt; a smaller or non-finite one never lowers it") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("a", "alice", 10), at(100))
            _ = try h.store.commit(openPlan("b", "alice", 10), at(40))
            try scEq(try highWater(h.store), at(100))
            _ = try h.store.commit(openPlan("c", "alice", 10), .double(.nan))
            try scEq(try highWater(h.store), at(100))
            _ = try h.store.commit(openPlan("d", "alice", 10), at(101))
            try scEq(try highWater(h.store), at(101))
        },
        BondCheck("reads-are-snapshots", "mutating a returned snapshot cannot change the store") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("b", "alice", 10), at(1))
            var snap = try h.store.read("b", "alice").asObject ?? [:]
            snap["bond"] = .null // the returned value is a copy: changing it is all a caller can do
            snap["balances"] = .array([])
            let again = try h.store.read("b", "alice")
            try scEq(again.get("bond")?.get("amount"), at(10))
            try scIs(again.get("bond")?.get("records")?.asArray?.count, 1)
            try scEq(again.get("balances"), scJ(#"[["alice",90]]"#))
        },
        BondCheck("hostile-names-are-plain-keys", "claim and account names such as __proto__, constructor and toString behave like any other name") { h in
            for n in ["__proto__", "constructor", "toString", "hasOwnProperty"] {
                _ = try deposit(h.store, n, 50)
                try scNeed(try commitOut(h.store, openPlan(n, n, 20), at(1)) == "committed", n) // the message is the name, as in the reference
                try scNeed(try bal(h.store, n) == [30], n)
                try scNeed(try bondStatus(h.store, n) == "open", n)
            }
            try scIs(try bondStatus(h.store, "valueOf"), "none")
            try scEqD(try bal(h.store, "valueOf"), [0])
        },
        BondCheck("state-survives-reopen", "every acknowledged commit and deposit is visible to a new client after the backend restarts", needs: "durable") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("a", "alice", 40), at(7))
            _ = try h.store.commit(openPlan("b", "alice", 20), at(8))
            let sl = slashPlan("b", 20)
            _ = try h.store.commit(sl, at(9))
            let back = try h.reopen()
            let row: JSONValue = .object(["claimId": .string("b"), "amount": at(20), "depositor": .string("alice"), "status": .string("slashed"),
                                          "records": .array([openPlan("b", "alice", 20).get("record") ?? .null, sl.get("record") ?? .null])])
            try scEq(try back.read("b", "alice"), .object(["bond": row, "balances": scJ(#"[["alice",40]]"#), "openTotals": scJ(#"{"count":1,"sum":40}"#), "highWater": at(9)]))
            try scEqD(try bal(back, "escrow", "chal", "treasury"), [40, 10, 10])
            try scIs(try commitOut(back, sl, at(10)), "replayed")
        },
        BondCheck("acknowledged-commits-survive-a-crash",
                  "after an abrupt kill, every acknowledged transition is present, and a transition that was in flight is applied entirely or not at all", needs: "crash") { h in
            _ = try deposit(h.store, "alice", 100)
            _ = try h.store.commit(openPlan("a", "alice", 40), at(1))
            _ = try h.store.commit(openPlan("b", "alice", 30), at(2))
            let s = h.store
            scFireAndForget { _ = try? s.commit(slashPlan("b", 30), at(3)) }
            let back = try h.crash!()
            try scIs(try bondStatus(back, "a"), "open")
            let st = try bondStatus(back, "b")
            try scNeed(st == "open" || st == "slashed", "bond b is \(st)")
            try scEqD(try bal(back, "alice", "escrow", "chal", "treasury"), st == "slashed" ? [30, 40, 15, 15] : [30, 70, 0, 0])
            try scIs(try total(back), 100)
            try scIs(try commitOut(back, slashPlan("b", 30), at(4)), st == "slashed" ? "replayed" : "committed")
            try scEqD(try bal(back, "alice", "escrow", "chal", "treasury"), [30, 40, 15, 15])
        },
    ]

    /// Run the bond checks (only those named in `only` when given) against fresh handles from the adapter.
    public static func runBondStoreConformance(_ adapter: BondStoreAdapter, only: [String]? = nil) throws -> BondConformanceReport {
        try runProfile(BOND_CHECKS, adapter: adapter.name, durable: adapter.durable, only: only, create: adapter.create, canCrash: { $0.crash != nil }, close: { $0.close?() })
    }

    /// The text report: a header line, then one line per check (the first line of a failure's detail).
    public static func formatBondReport(_ r: BondConformanceReport) -> String { formatProfile("bond store", r) }

    // MARK: reference adapters

    /// GOOD, in process: the reference store over an in-memory kv. Not durable (declared).
    public static func memoryBondStoreAdapter() -> BondStoreAdapter {
        BondStoreAdapter(name: "KvBondStore over an in-memory kv", durable: false) {
            let kv = PCADurableState.createMemoryDurableKv()
            return BondStoreHandle(store: KvBondStore(kv: kv), reopen: { KvBondStore(kv: kv) })
        }
    }

    /// GOOD, durable: the reference store over the crash-safe file state (`openDurableState`), one handle per client.
    public static func durableBondStoreAdapter(dir: String? = nil) -> BondStoreAdapter {
        BondStoreAdapter(name: "KvBondStore over durable-state files", durable: true) {
            let d = dir ?? scTempDir("pca-bondsc-")
            let open: () throws -> any BondStore = { KvBondStore(kv: try openDurableState(DurableStateOptions(dir: d, lockTimeoutMs: 30_000))) }
            return BondStoreHandle(store: try open(), reopen: open, crash: open)
        }
    }

    enum BondDefect { case nonAtomic, noReplay, lostUpdate, amnesia, clockRewind }

    /// One book with a switchable defect, for the positive controls (each reproduces a real mistake).
    private final class DefectiveBond: BondStore, @unchecked Sendable {
        final class Book: @unchecked Sendable { let lock = NSLock(); var doc = KvBondStore.Doc() }
        let book: Book
        let defect: BondDefect
        init(_ b: Book, _ d: BondDefect) { book = b; defect = d }

        func read(_ claimId: String, _ depositor: String?) throws -> JSONValue {
            book.lock.lock(); defer { book.lock.unlock() }
            return KvBondStore.snapshot(book.doc, claimId, depositor)
        }

        func deposit(_ account: JSONValue, _ amount: JSONValue) throws -> Double {
            guard let a = StoreJ.nonEmpty(account), let n = StoreJ.fin(amount), n > 0 else { throw PCAStoreError.range("deposit") }
            if defect != .lostUpdate {
                book.lock.lock(); defer { book.lock.unlock() }
                book.doc.setBalance(a, book.doc.balance(a) + n)
                return book.doc.balance(a)
            }
            book.lock.lock(); var base = book.doc; book.lock.unlock()
            Thread.sleep(forTimeInterval: 0.001)
            base.setBalance(a, base.balance(a) + n)
            book.lock.lock(); book.doc = base; book.lock.unlock()
            return base.balance(a)
        }

        func commit(_ plan: JSONValue, _ observedAt: JSONValue) throws -> JSONValue {
            if defect == .nonAtomic { return nonAtomic(plan, observedAt) }
            if defect == .lostUpdate {
                book.lock.lock(); var work = book.doc; book.lock.unlock()
                Thread.sleep(forTimeInterval: 0.001)
                let out = try KvBondStore.commitPlan(&work, plan, observedAt)
                if out.get("outcome")?.asString == "committed" { book.lock.lock(); book.doc = work; book.lock.unlock() }
                return out
            }
            book.lock.lock(); defer { book.lock.unlock() }
            let out = try KvBondStore.commitPlan(&book.doc, plan, observedAt)
            let o = out.get("outcome")?.asString
            if defect == .noReplay && o == "replayed" { return .object(["outcome": .string("conflict"), "reason": .string("already applied"), "current": .string("open")]) }
            if defect == .clockRewind && o == "committed" { book.doc.highWater = IV.num(observedAt) ?? .nan }
            return out
        }

        /// Applies the balance moves first, then checks the phase: a conflict leaves the money moved.
        private func nonAtomic(_ plan: JSONValue, _ observedAt: JSONValue) -> JSONValue {
            book.lock.lock(); defer { book.lock.unlock() }
            let id = plan.get("claimId")?.asString ?? ""
            for m in plan.get("moves")?.asArray ?? [] {
                let acct = m.get("account")?.asString ?? "", amt = IV.num(m.get("amount")) ?? 0
                book.doc.setBalance(acct, book.doc.balance(acct) + (m.get("op")?.asString == "credit" ? amt : -amt))
            }
            let b = book.doc.bond(id)
            let expect = plan.get("expect")?.asString ?? ""
            if expect == "none" ? b != nil : (b == nil || b?.get("status")?.asString != expect) {
                return .object(["outcome": .string("conflict"), "reason": .string("phase"), "current": .string(b?.get("status")?.asString ?? "none")])
            }
            let record = plan.get("record") ?? .null
            if let op = plan.get("open"), !op.isNull {
                book.doc.setBond(.object(["claimId": .string(id), "amount": op.get("amount") ?? .null, "depositor": op.get("depositor") ?? .null, "status": .string("open"), "records": .array([record])]))
            } else if var row = b?.asObject {
                row["status"] = plan.get("next") ?? .null
                row["records"] = .array((row["records"]?.asArray ?? []) + [record])
                book.doc.setBond(.object(row))
            }
            let obs = IV.num(observedAt) ?? .nan
            book.doc.highWater = obs.isNaN || book.doc.highWater.isNaN ? .nan : Swift.max(book.doc.highWater, obs) // Math.max: NaN wins
            return .object(["outcome": .string("committed"), "record": record])
        }
    }

    private static func defectiveBond(_ name: String, _ d: BondDefect) -> BondStoreAdapter {
        BondStoreAdapter(name: name, durable: true) {
            let book = DefectiveBond.Book()
            let again: () throws -> any BondStore = { if d == .amnesia { book.lock.lock(); book.doc = KvBondStore.Doc(); book.lock.unlock() }; return DefectiveBond(book, d) }
            return BondStoreHandle(store: DefectiveBond(book, d), reopen: again, crash: again)
        }
    }

    public static func nonAtomicBondStoreAdapter() -> BondStoreAdapter { defectiveBond("BAD non-atomic (moves land before the phase check)", .nonAtomic) }
    public static func noReplayBondStoreAdapter() -> BondStoreAdapter { defectiveBond("BAD no idempotence (a retried transition conflicts)", .noReplay) }
    public static func lostUpdateBondStoreAdapter() -> BondStoreAdapter { defectiveBond("BAD lost update (read, await, write)", .lostUpdate) }
    public static func amnesiaBondStoreAdapter() -> BondStoreAdapter { defectiveBond("BAD amnesia (claims durability, forgets on reopen)", .amnesia) }
    public static func clockRewindBondStoreAdapter() -> BondStoreAdapter { defectiveBond("BAD clock rewind (high-water mark follows the last call)", .clockRewind) }

    /// Built-in adapters by name.
    public static let BOND_REFERENCE_ADAPTERS: [String: () -> BondStoreAdapter] = [
        "bond-memory": memoryBondStoreAdapter,
        "bond-durable-file": { durableBondStoreAdapter() },
        "bad-bond-non-atomic": nonAtomicBondStoreAdapter,
        "bad-bond-no-replay": noReplayBondStoreAdapter,
        "bad-bond-lost-update": lostUpdateBondStoreAdapter,
        "bad-bond-amnesia": amnesiaBondStoreAdapter,
        "bad-bond-clock-rewind": clockRewindBondStoreAdapter,
    ]
}
