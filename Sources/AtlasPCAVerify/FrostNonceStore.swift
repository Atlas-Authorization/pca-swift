import Foundation

/// One FROST signing session's secret nonce pair and its public commitments, as the durable store keeps them.
public struct PCAFrostNonceRecord: Equatable {
    public var hiding: [UInt8]
    public var binding: [UInt8]
    public var hidingCommitment: [UInt8]
    public var bindingCommitment: [UInt8]
    public var createdAt: Double
    public init(hiding: [UInt8], binding: [UInt8], hidingCommitment: [UInt8], bindingCommitment: [UInt8], createdAt: Double) {
        self.hiding = hiding; self.binding = binding; self.hidingCommitment = hidingCommitment; self.bindingCommitment = bindingCommitment; self.createdAt = createdAt
    }
}

/// The durable nonce store of a FROST signer. `create` refuses an id that is live or spent; `spend` removes the secret and keeps a marker (a second spend, or a spend of an
/// unknown id, throws); `drop` removes a live record without marking it spent. A restart must keep both the live records and the spent markers: forgetting either
/// would let a nonce be reused, which leaks the signing share. `assertNonceStoreContract` checks a store for exactly these properties.
public protocol PCAFrostNonceStore {
    func create(_ sessionId: String, _ record: PCAFrostNonceRecord) throws
    func load(_ sessionId: String) throws -> PCAFrostNonceRecord?
    func spend(_ sessionId: String) throws
    func drop(_ sessionId: String) throws
    func isSpent(_ sessionId: String) throws -> Bool
}

/// The in-memory reference store (a restart loses everything: tests and single-process use only).
public final class PCAMemoryFrostNonceStore: PCAFrostNonceStore {
    private var live: [String: PCAFrostNonceRecord] = [:]
    private var spent = Set<String>()
    private let lock = NSLock()
    public init() {}

    public func create(_ sessionId: String, _ record: PCAFrostNonceRecord) throws {
        lock.lock(); defer { lock.unlock() }
        if sessionId.isEmpty { throw JSError("nonce-store: session id must be a non-empty string") }
        if live[sessionId] != nil || spent.contains(sessionId) { throw JSError("nonce-store: session already exists") }
        live[sessionId] = record
    }
    public func load(_ sessionId: String) throws -> PCAFrostNonceRecord? { lock.lock(); defer { lock.unlock() }; return live[sessionId] }
    public func spend(_ sessionId: String) throws {
        lock.lock(); defer { lock.unlock() }
        guard live[sessionId] != nil else { throw JSError("nonce-store: cannot spend a session that is not live") }
        live[sessionId] = nil
        spent.insert(sessionId)
    }
    public func drop(_ sessionId: String) throws { lock.lock(); defer { lock.unlock() }; live[sessionId] = nil }
    public func isSpent(_ sessionId: String) throws -> Bool { lock.lock(); defer { lock.unlock() }; return spent.contains(sessionId) }
}

public enum PCAFrostNonceStoreContract {
    /// Throws `nonce-store contract: ...` for the first property `make()`'s store lacks. `reopen` models a restart over the same storage.
    public static func assertNonceStoreContract(make: () -> PCAFrostNonceStore, reopen: (PCAFrostNonceStore) -> PCAFrostNonceStore = { $0 }) throws {
        func rec(_ n: UInt8) -> PCAFrostNonceRecord {
            PCAFrostNonceRecord(hiding: [UInt8](repeating: n, count: 32), binding: [UInt8](repeating: n &+ 1, count: 32), hidingCommitment: [UInt8](repeating: n &+ 2, count: 32),
                                bindingCommitment: [UInt8](repeating: n &+ 3, count: 32), createdAt: Double(n))
        }
        func must(_ ok: Bool, _ what: String) throws { if !ok { throw JSError("nonce-store contract: \(what)") } }
        func throwsOn(_ f: () throws -> Void) -> Bool { do { try f() } catch { return true }; return false }
        var s = make()
        try must((try s.load("a")) == nil && !(try s.isSpent("a")), "an unknown id is neither live nor spent")
        try s.create("a", rec(1))
        try must(throwsOn { try s.create("a", rec(9)) }, "create must refuse an existing live id")
        try s.create("b", rec(5))
        s = reopen(s)
        let got = try s.load("a")
        try must(got != nil && got!.hiding[0] == 1 && got!.createdAt == 1, "a live record survives a restart")
        // records are values: a caller can never change a stored secret through what load returned (the reference's `load returns a copy` check cannot fail here)
        try s.spend("a")
        try must((try s.load("a")) == nil && (try s.isSpent("a")), "spend removes the secret and records the marker")
        try must(throwsOn { try s.spend("a") }, "a second spend must throw")
        try must(throwsOn { try s.create("a", rec(2)) }, "create must refuse a spent id")
        try must(throwsOn { try s.spend("zzz") }, "spend of an unknown id must throw")
        s = reopen(s)
        try must((try s.isSpent("a")) && (try s.load("a")) == nil, "a spent marker survives a restart")
        try must((try s.load("b")) != nil, "the other live record survives")
        try s.drop("b")
        try must((try s.load("b")) == nil && !(try s.isSpent("b")), "drop removes a live record without marking it spent")
        try s.drop("never-existed")
    }
}
