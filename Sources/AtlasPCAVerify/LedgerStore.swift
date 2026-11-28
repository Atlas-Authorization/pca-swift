import Foundation

/// The typed failure of the durable stores (the ledger store, the bond store, the budget ledger and the settlement ledger). `code` is stable and the
/// description is `"<code>: <text>"`; an argument error (the reference's RangeError) has the code `RangeError` and only the text.
public struct PCAStoreError: Error, Equatable, CustomStringConvertible {
    public let code: String
    public let message: String
    public init(_ code: String, _ message: String) { self.code = code; self.message = message }
    public var description: String { code == "RangeError" ? message : "\(code): \(message)" }
    /// An argument outside its range: the caller's bug, never a store state.
    public static func range(_ message: String) -> PCAStoreError { PCAStoreError("RangeError", message) }

    /// The stable code of any error: its code for a store error, `Error` otherwise.
    public static func codeOf(_ e: Error) -> String { (e as? PCAStoreError)?.code ?? "Error" }
    static func text(_ e: Error) -> String { (e as? CustomStringConvertible)?.description ?? "\(e)" }
}

enum StoreJ {
    /// A JSON number that is an integer in the safe range (never a bool).
    static func safe(_ v: JSONValue?) -> Int64? { v?.safeInt }
    /// `Object.is(v, -0)`.
    static func isNegativeZero(_ v: JSONValue?) -> Bool { IV.num(v).map { $0 == 0 && $0.sign == .minus } ?? false }
    static func nonEmpty(_ v: JSONValue?) -> String? { if let s = v?.asString, !s.isEmpty { return s }; return nil }
    /// A finite JSON number.
    static func fin(_ v: JSONValue?) -> Double? { IV.num(v).flatMap { $0.isFinite ? $0 : nil } }
    static func num(_ d: Double) -> JSONValue { PCAFacade.jsNum(d) }
    /// Python truthiness of a JSON value (the reference's `if x`).
    static func truthy(_ v: JSONValue?) -> Bool {
        switch v {
        case nil, .some(.null): return false
        case let .some(.bool(b)): return b
        case let .some(.int(i)): return i != 0
        case let .some(.double(d)): return d != 0
        case let .some(.string(s)): return !s.isEmpty
        case let .some(.array(a)): return !a.isEmpty
        case let .some(.object(o)): return !o.isEmpty
        }
    }
    static func same(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case (.some(.null), nil), (nil, .some(.null)): return true
        case let (x?, y?): return Canonical.hashCanonical(x) == Canonical.hashCanonical(y)
        default: return false
        }
    }
}

/// An RFC 9162 transparency log over opaque commitments (the issuing side of the proofs the verifiers in `Ledger` check).
public final class PCATransparencyLedger {
    public let principal: String
    private var commitList: [String] = []
    private var hashes: [[UInt8]] = []

    public init(principal: String = "") { self.principal = principal }

    public static func fromCommits(_ commits: [String], principal: String = "") -> PCATransparencyLedger {
        let t = PCATransparencyLedger(principal: principal)
        for c in commits { t.commitList.append(c); t.hashes.append(Merkle.leafHash(.string(c))) }
        return t
    }

    public var size: Int { commitList.count }
    public func commits() -> [String] { commitList }

    /// The root of a commit sequence (the empty log is SHA-256 of the empty string).
    public static func rootOf(_ commits: [String]) -> String {
        commits.isEmpty ? Ledger.EMPTY_TREE_ROOT : Base64URLStrict.encode(Merkle.build(commits.map { Merkle.leafHash(.string($0)) }))
    }

    @discardableResult
    public func appendCommitment(_ commit: String) throws -> (index: Int, commit: String) {
        if commit.isEmpty { throw JSError("appendCommitment: commit must be a non-empty string") }
        commitList.append(commit)
        hashes.append(Merkle.leafHash(.string(commit)))
        return (commitList.count - 1, commit)
    }

    public func head() -> JSONValue { .object(["size": .int(Int64(size)), "root": .string(PCATransparencyLedger.rootOf(commitList))]) }

    /// The root the log had when it held only its first `size` entries.
    public func rootAt(_ sizeV: JSONValue?) throws -> String {
        guard let n = StoreJ.safe(sizeV), n >= 0, n <= Int64(size) else { throw PCAStoreError.range("rootAt: size out of range") }
        return PCATransparencyLedger.rootOf(Array(commitList[..<Int(n)]))
    }

    /// RFC 6962 audit path of entry `index`.
    public func inclusionProof(_ indexV: JSONValue?) throws -> JSONValue {
        guard let i = StoreJ.safe(indexV), i >= 0, i < Int64(size) else { throw PCAStoreError.range("merkleProof: index out of range") }
        return try PCAGrants.merkleProof(commitList.map { JSONValue.string($0) }, Int(i))
    }

    /// RFC 9162 SUBPROOF(m, D[n], true): the consistency proof between the first `oldSize` and the first `newSize` entries.
    public func consistencyProof(_ oldV: JSONValue?, _ newV: JSONValue? = nil) throws -> JSONValue {
        let nAll = Int64(size)
        func whole(_ v: JSONValue) -> Int64? { if case let .int(i) = v { return i }; if case let .double(d) = v, d.rounded() == d, d.isFinite, abs(d) < 9e15 { return Int64(d) }; return nil }
        guard let o = oldV.flatMap(whole), let n = (newV ?? .int(nAll)).flatMapWhole(), o >= 0, o <= n, n <= nAll else { throw PCAStoreError.range("consistencyProof: invalid sizes") }
        var out: [[UInt8]] = []
        func sub(_ m: Int, _ hs: [[UInt8]], _ b: Bool) {
            let n = hs.count
            if m == n { if !b { out.append(Merkle.build(hs)) }; return }
            var k = 1
            while k * 2 < n { k *= 2 }
            if m <= k { sub(m, Array(hs[..<k]), b); out.append(Merkle.build(Array(hs[k...]))) } else { sub(m - k, Array(hs[k...]), false); out.append(Merkle.build(Array(hs[..<k]))) }
        }
        if o > 0 && o < n { sub(Int(o), Array(hashes[..<Int(n)]), true) }
        return .object(["oldSize": .int(o), "newSize": .int(n), "path": .array(out.map { .string(Base64URLStrict.encode($0)) })])
    }
}

private extension JSONValue {
    func flatMapWhole() -> Int64? {
        if case let .int(i) = self { return i }
        if case let .double(d) = self, d.isFinite, d.rounded() == d, abs(d) < 9e15 { return Int64(d) }
        return nil
    }
}

/// The persistence contract of a transparency log: an append-only list of commitments and a list of signed checkpoints. `append` and `appendCheckpoint` are
/// compare-and-swap on the current length (all entries of a batch or none); committing the same batch again at the same position is a replay.
public protocol LedgerStore: AnyObject {
    func size() throws -> Int
    func read(_ from: JSONValue, _ to: JSONValue) throws -> [String]
    /// `{outcome: appended | replayed | conflict, size}`.
    func append(_ expectedSize: JSONValue, _ commits: JSONValue) throws -> JSONValue
    func checkpointCount() throws -> Int
    func checkpoints(_ from: JSONValue) throws -> [JSONValue]
    /// `{outcome: appended | replayed | conflict, count, reason?}`.
    func appendCheckpoint(_ expectedCount: JSONValue, _ cp: JSONValue) throws -> JSONValue
}

/// The reference ledger store: the whole log is one document in an atomic key-value store, so every write is one atomic read-modify-write.
/// LIMIT: rewritten on every write; a production log lives in a database with a unique index on the position.
public final class KvLedgerStore: LedgerStore, @unchecked Sendable {
    public static let DOC_KEY = "pca-ledger-store/v1"
    private let kv: AtomicKV
    private let key: String

    public init(kv: AtomicKV, key: String = KvLedgerStore.DOC_KEY) { self.kv = kv; self.key = key }

    struct Doc { var commits: [String] = []; var checkpoints: [JSONValue] = [] }

    static func isCommit(_ v: JSONValue) -> Bool { if let s = v.asString, !s.isEmpty { return true }; return false }

    static func decode(_ raw: JSONValue?) throws -> Doc {
        guard let r = raw, !r.isNull else { return Doc() }
        guard r.isObject, IV.num(r.get("v")) == 1, let cs = r.get("commits")?.asArray, let cps = r.get("checkpoints")?.asArray, cs.allSatisfy(isCommit) else {
            throw PCAStoreError("store_corrupt", "ledger document has the wrong shape")
        }
        guard cps.allSatisfy({ $0.isObject && $0.get("sth")?.isObject == true }) else { throw PCAStoreError("store_corrupt", "malformed checkpoint entry") }
        return Doc(commits: cs.compactMap { $0.asString }, checkpoints: cps)
    }

    static func encode(_ d: Doc) -> JSONValue {
        .object(["v": .int(1), "commits": .array(d.commits.map { .string($0) }), "checkpoints": .array(d.checkpoints)])
    }

    private func doc() throws -> Doc { try KvLedgerStore.decode(try kv.get(key)) }

    public func size() throws -> Int { try doc().commits.count }

    public func read(_ from: JSONValue, _ to: JSONValue) throws -> [String] {
        let d = try doc()
        guard let f = StoreJ.safe(from), let t = StoreJ.safe(to), f >= 0, f <= t, t <= Int64(d.commits.count) else { throw PCAStoreError.range("read: range is not inside the log") }
        return Array(d.commits[Int(f)..<Int(t)])
    }

    /// Append `commits` to `doc` iff it has exactly `expectedSize` entries (all or none); a batch already stored there is a replay.
    static func appendToDoc(_ d: inout Doc, _ expected: JSONValue, _ commits: JSONValue) throws -> JSONValue {
        guard let e = StoreJ.safe(expected), e >= 0 else { throw PCAStoreError.range("append: expectedSize must be a non-negative safe integer") }
        guard let cs = commits.asArray, !cs.isEmpty, cs.allSatisfy(isCommit) else { throw PCAStoreError.range("append: commits must be a non-empty array of non-empty strings") }
        let size = d.commits.count
        let strs = cs.compactMap { $0.asString }
        if e < Int64(size) {
            let same = strs.enumerated().allSatisfy { i, c in Int(e) + i < size && d.commits[Int(e) + i] == c }
            return .object(["outcome": .string(same ? "replayed" : "conflict"), "size": .int(Int64(size))])
        }
        if e > Int64(size) { return .object(["outcome": .string("conflict"), "size": .int(Int64(size))]) }
        d.commits.append(contentsOf: strs)
        return .object(["outcome": .string("appended"), "size": .int(Int64(d.commits.count))])
    }

    static func checkpointToDoc(_ d: inout Doc, _ expected: JSONValue, _ cp: JSONValue) throws -> JSONValue {
        guard let e = StoreJ.safe(expected), e >= 0 else { throw PCAStoreError.range("appendCheckpoint: expectedCount must be a non-negative safe integer") }
        let count = d.checkpoints.count
        func conflict(_ why: String) -> JSONValue { .object(["outcome": .string("conflict"), "count": .int(Int64(count)), "reason": .string(why)]) }
        if e < Int64(count) {
            if Canonical.hashCanonical(d.checkpoints[Int(e)]) == Canonical.hashCanonical(cp) { return .object(["outcome": .string("replayed"), "count": .int(Int64(count))]) }
            return conflict("another checkpoint holds that position")
        }
        if e > Int64(count) { return conflict("the checkpoint position is ahead of the log") }
        guard let sth = cp.get("sth"), sth.isObject, let size = StoreJ.safe(sth.get("size")), size >= 0, !StoreJ.isNegativeZero(sth.get("size")), sth.get("root")?.asString != nil else { return conflict("malformed checkpoint") }
        if size > Int64(d.commits.count) { return conflict("the checkpoint is beyond the end of the log") }
        if count > 0, let last = d.checkpoints[count - 1].get("sth"), let ls = StoreJ.safe(last.get("size")) {
            if size < ls || (size == ls && !IV.same(sth.get("root")?.asString, last.get("root")?.asString)) { return conflict("the checkpoint does not extend the previous one") }
        }
        d.checkpoints.append(cp)
        return .object(["outcome": .string("appended"), "count": .int(Int64(d.checkpoints.count))])
    }

    public func append(_ expectedSize: JSONValue, _ commits: JSONValue) throws -> JSONValue {
        var out: JSONValue?
        var failure: Error?
        try kv.update(key) { prev in
            do {
                var d = try KvLedgerStore.decode(prev)
                let r = try KvLedgerStore.appendToDoc(&d, expectedSize, commits)
                out = r
                return r.get("outcome")?.asString == "appended" ? KvLedgerStore.encode(d) : nil
            } catch { failure = error; return nil }
        }
        if let f = failure { throw f }
        return out ?? .null
    }

    public func append(expectedSize: Int, commits: [String]) throws -> JSONValue { try append(.int(Int64(expectedSize)), .array(commits.map { .string($0) })) }

    public func checkpointCount() throws -> Int { try doc().checkpoints.count }

    public func checkpoints(_ from: JSONValue) throws -> [JSONValue] {
        let d = try doc()
        guard let f = StoreJ.safe(from), f >= 0, f <= Int64(d.checkpoints.count) else { throw PCAStoreError.range("checkpoints: from is not inside the list") }
        return Array(d.checkpoints[Int(f)...])
    }

    public func appendCheckpoint(_ expectedCount: JSONValue, _ cp: JSONValue) throws -> JSONValue {
        var out: JSONValue?
        var failure: Error?
        try kv.update(key) { prev in
            do {
                var d = try KvLedgerStore.decode(prev)
                let r = try KvLedgerStore.checkpointToDoc(&d, expectedCount, cp)
                out = r
                return r.get("outcome")?.asString == "appended" ? KvLedgerStore.encode(d) : nil
            } catch { failure = error; return nil }
        }
        if let f = failure { throw f }
        return out ?? .null
    }
}

/// A transparency log over a ledger store. Open it with `open`; the initializer is private so that no instance exists whose state was not verified against
/// the stored checkpoints.
///
/// CLAIMED: TAMPER EVIDENCE, given at least one honest independent witness. `open` rebuilds the Merkle tree from the stored commits and checks it against EVERY
/// stored checkpoint (guardian signature, signed `prev_root` chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each root): a
/// store that lost entries after a checkpoint (`rollback`), edited an entry (`tamper`) or holds a forged checkpoint FAILS CLOSED with a typed error.
/// `checkpoint` refuses to sign a head that is not consistent with the previous one. Every handle serializes its operations.
public final class StoredLedger: @unchecked Sendable {
    private let store: LedgerStore
    private let guardianKey: PCASuiteKey
    private let guardianPublic: String
    private let instanceId: String
    private let principal: String
    private let clock: (() -> Double)?
    private let pin: [String: String]?
    private let log: PCATransparencyLedger
    private var cps: [JSONValue]
    private let lock = PCALock(recursive: true)

    private init(store: LedgerStore, guardian: PCASuiteKey, guardianPublic: String, instanceId: String, principal: String, clock: (() -> Double)?, pin: [String: String]?,
                 log: PCATransparencyLedger, cps: [JSONValue]) {
        self.store = store; self.guardianKey = guardian; self.guardianPublic = guardianPublic; self.instanceId = instanceId; self.principal = principal
        self.clock = clock; self.pin = pin; self.log = log; self.cps = cps
    }

    static func unavailable(_ e: Error) -> PCAStoreError {
        if let s = e as? PCAStoreError, s.code != "RangeError" { return s }
        let t = PCAStoreError.text(e)
        return PCAStoreError("store_unavailable", t.isEmpty ? "store failed" : t)
    }

    /// Load the log and verify it against every stored checkpoint. `guardian` is the guardian key (its Ed25519 identity is what every checkpoint verifies
    /// under); a post-quantum or hybrid suite needs `pin`, the PQ pins `{ed25519 b64u: pq public key}`. Throws `store_missing`, `guardian_key_missing`,
    /// `pin_missing`, `rollback`, `tamper`, `forged_checkpoint`, `inconsistent`, `store_corrupt` or `store_unavailable`.
    public static func open(store: LedgerStore, guardian: PCASuiteKey, instanceId: String, principal: String, clock: (() -> Double)? = nil,
                            pin: [String: String]? = nil) throws -> StoredLedger {
        guard let pub = guardian.id else { throw PCAStoreError("guardian_key_missing", "a guardian secret key is required") }
        if guardian.alg != "ed25519" && (pin ?? [:]).isEmpty {
            throw PCAStoreError("pin_missing", "a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)")
        }
        do {
            let size = try store.size()
            let commits = try store.read(.int(0), .int(Int64(size)))
            let cps = try store.checkpoints(.int(0))
            let s = StoredLedger(store: store, guardian: guardian, guardianPublic: pub, instanceId: instanceId, principal: principal, clock: clock, pin: pin,
                                 log: PCATransparencyLedger.fromCommits(commits, principal: principal), cps: cps)
            try s.verifyAgainstCheckpoints()
            return s
        } catch { throw unavailable(error) }
    }

    private func verifyChain(_ list: [JSONValue]) -> (ok: Bool, at: Int, reason: String) {
        for (i, cp) in list.enumerated() {
            if !cp.isObject || !Ledger.verifyTreeHead(cp.get("sth"), guardianPublic, nil, pin) { return (false, i, "head") }
            if i == 0 { continue }
            guard let proof = cp.get("proof"), !proof.isNull, proof != .bool(false) else { return (false, i, "proof_missing") }
            if !Ledger.verifyHeadConsistency(list[i - 1].get("sth"), cp.get("sth"), proof, guardianPublic, nil, pin) { return (false, i, "inconsistent") }
        }
        return (true, 0, "")
    }

    private func verifyAgainstCheckpoints() throws {
        var attested: Int64 = 0
        for c in cps { if let n = StoreJ.safe(c.get("sth")?.get("size")) { attested = Swift.max(attested, n) } }
        if Int64(log.size) < attested { throw PCAStoreError("rollback", "the log has \(log.size) entries but a checkpoint attests \(attested)") }
        for (i, cp) in cps.enumerated() {
            let sth = cp.get("sth") ?? .null
            if !IV.same(sth.get("instance_id")?.asString, instanceId) || !IV.same(sth.get("principal")?.asString, principal) {
                throw PCAStoreError("forged_checkpoint", "checkpoint \(i) belongs to another log")
            }
            let root = try log.rootAt(sth.get("size"))
            if !IV.same(root, sth.get("root")?.asString ?? "\u{0}") { throw PCAStoreError("tamper", "the stored entries do not reproduce the root of checkpoint \(i) (size \(sth.get("size").map { Canonical.canonicalize($0) } ?? ""))") }
        }
        if cps.isEmpty { return }
        let v = verifyChain(cps)
        if !v.ok { throw PCAStoreError(v.reason == "inconsistent" ? "inconsistent" : "forged_checkpoint", "checkpoint \(v.at): \(v.reason)") }
    }

    public var size: Int { lock.lock(); defer { lock.unlock() }; return log.size }
    /// The guardian public key (b64u) every checkpoint verifies under.
    public var guardian: String { guardianPublic }
    public func latestCheckpoint() -> JSONValue? { lock.lock(); defer { lock.unlock() }; return cps.last?.get("sth") }
    public func checkpointChain() -> [JSONValue] { lock.lock(); defer { lock.unlock() }; return cps }
    public func head() -> JSONValue { lock.lock(); defer { lock.unlock() }; return log.head() }
    public func inclusionProof(_ index: JSONValue) throws -> JSONValue { lock.lock(); defer { lock.unlock() }; return try log.inclusionProof(index) }
    /// RFC 9162 proof from a size the caller already pinned to the current log.
    public func consistencyProofFrom(_ oldSize: JSONValue) throws -> JSONValue { lock.lock(); defer { lock.unlock() }; return try log.consistencyProof(oldSize, .int(Int64(log.size))) }
    public func commits() -> [String] { lock.lock(); defer { lock.unlock() }; return log.commits() }

    /// Append an opaque commitment leaf. Idempotent under retry at the position the caller read; if another writer took that position the ledger reloads and
    /// appends at the new tail. Answers `{index, commit}`.
    public func append(_ commit: JSONValue) throws -> JSONValue {
        guard let c = commit.asString, !c.isEmpty else { throw PCAStoreError("invalid_commit", "a commit must be a non-empty string") }
        lock.lock(); defer { lock.unlock() }
        for _ in 0..<16 {
            let index = log.size
            let out: JSONValue
            do { out = try store.append(.int(Int64(index)), .array([.string(c)])) } catch { throw StoredLedger.unavailable(error) }
            let outcome = out.get("outcome")?.asString
            if outcome == "appended" || outcome == "replayed" {
                try log.appendCommitment(c)
                return .object(["index": .int(Int64(index)), "commit": .string(c)])
            }
            try catchUpLocked() // another writer advanced the log: pick up its entries, then try the new tail
        }
        throw PCAStoreError("conflict", "the log kept moving; could not append")
    }

    public func append(_ commit: String) throws -> JSONValue { try append(.string(commit)) }

    /// Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints).
    public func catchUp() throws { lock.lock(); defer { lock.unlock() }; try catchUpLocked() }

    private func catchUpLocked() throws {
        do {
            let size = try store.size()
            if size < log.size { throw PCAStoreError("rollback", "the store shrank from \(log.size) to \(size) entries") }
            for c in try store.read(.int(Int64(log.size)), .int(Int64(size))) { try log.appendCommitment(c) }
            cps.append(contentsOf: try store.checkpoints(.int(Int64(cps.count))))
            try verifyAgainstCheckpoints()
        } catch { throw StoredLedger.unavailable(error) }
    }

    private func assertStoreMatchesMemory() throws {
        let stored: [String]
        do { stored = try store.read(.int(0), .int(Int64(log.size))) } catch { throw StoredLedger.unavailable(error) }
        if stored != log.commits() { throw PCAStoreError("tamper", "the stored entries no longer match this handle; refusing to sign a checkpoint over them") }
    }

    /// Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the previous checkpoint, so a
    /// log that was rewritten under this handle is refused (`inconsistent`). An unchanged head returns the existing checkpoint.
    public func checkpoint() throws -> JSONValue {
        lock.lock(); defer { lock.unlock() }
        try catchUpLocked()
        try assertStoreMatchesMemory()
        let prev = cps.last
        let h = log.head()
        if let p = prev, IV.num(p.get("sth")?.get("size")) == IV.num(h.get("size")) { return p.get("sth") ?? .null }
        let t = clock?() ?? Date().timeIntervalSince1970 * 1000
        if !t.isFinite { throw PCAStoreError("clock_invalid", "the clock returned a non-finite time") }
        var body: JObject = ["instance_id": .string(instanceId), "principal": .string(principal), "size": h.get("size") ?? .null, "root": h.get("root") ?? .null,
                             "prev_root": prev?.get("sth")?.get("root") ?? .string(""), "timestamp": StoreJ.num(t.rounded(.down))]
        var signed = try PCAIssue.signArtifact(domain: Ledger.STH_DOMAIN, body: .object(body), signer: guardianKey)
        signed["guardian"] = .string(guardianPublic)
        body = signed
        let sth = JSONValue.object(body)
        var cp: JObject = ["sth": sth]
        if let p = prev, let ps = StoreJ.safe(p.get("sth")?.get("size")) { cp["proof"] = try log.consistencyProof(.int(ps), h.get("size")) }
        let cpv = JSONValue.object(cp)
        let v = verifyChain(cps + [cpv])
        if !v.ok {
            if v.reason == "head" { throw PCAStoreError("forged_checkpoint", "the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)") }
            throw PCAStoreError("inconsistent", "the new head is not consistent with checkpoint \(v.at - 1)")
        }
        let out: JSONValue
        do { out = try store.appendCheckpoint(.int(Int64(cps.count)), cpv) } catch { throw StoredLedger.unavailable(error) }
        if out.get("outcome")?.asString == "conflict" { throw PCAStoreError("conflict", out.get("reason")?.asString ?? "conflict") }
        cps.append(cpv)
        return sth
    }
}
