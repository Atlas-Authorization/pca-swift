import Foundation

/// SCITT Transparency Services: the in-memory reference log (`PCAScittMemoryService`, tests and demos only: it recomputes the tree on every
/// registration and forgets everything on restart) and the durable log (`PCAScittDurableService`) over a `ScittLogStore` you supply: the
/// log keeps the hash of every complete aligned subtree, so an append is O(log n) store reads and writes.
public struct ScittRegistration {
    public let index: Int64
    public let receipt: [UInt8]
    public let root: String
}

public struct ScittAppendResult {
    public let statement: [UInt8]
    public let registration: ScittRegistration
}

public struct ScittConsistencyProof {
    public let oldSize: Int64
    public let newSize: Int64
    /// Roots (b64u) of the log at `oldSize` and `newSize`.
    public let oldRoot: String
    public let newRoot: String
    /// CBOR `[tree-size-1, tree-size-2, [+ bstr]]` (RFC 9942 section 5.3).
    public let proof: [UInt8]
}

private func scittProofJSON(_ index: Int64, _ size: Int64, _ path: [[UInt8]]) -> JSONValue {
    let sides = PCAScitt.siblingSides(index, size)
    let steps: [JSONValue] = path.enumerated().map { .object(["side": .string(sides[$0.offset]), "hash": .string(Base64URLStrict.encode($0.element))]) }
    return .object(["index": .int(index), "size": .int(size), "path": .array(steps)])
}

private func scittConsistencyBytes(_ oldSize: Int64, _ newSize: Int64, _ path: [[UInt8]]) throws -> [UInt8] {
    try PCAScitt.encode(.array([.int(oldSize), .int(newSize), .array(path.map { .bytes($0) })]))
}

public final class PCAScittMemoryService {
    private var statements: [[UInt8]] = []
    private var leafHashes: [[UInt8]] = []
    private let signer: PCAScitt.CoseSigner
    private let issuer: String?

    public init(signer: PCAScitt.CoseSigner, issuer: String? = nil) { self.signer = signer; self.issuer = issuer }

    public var size: Int64 { Int64(statements.count) }
    public var root: String { Base64URLStrict.encode(PCARfc9162.treeHash(leafHashes)) }
    /// The statement leaves (b64u of each Signed Statement) in order.
    public func snapshot() -> [String] { statements.map { Base64URLStrict.encode($0) } }

    private func receiptFor(_ index: Int64) throws -> ScittRegistration {
        let root = PCARfc9162.treeHash(leafHashes)
        let proof = scittProofJSON(index, Int64(leafHashes.count), try PCARfc9162.inclusionPath(leafHashes, index))
        let rootText = Base64URLStrict.encode(root)
        return ScittRegistration(index: index, receipt: try PCAScitt.buildReceipt(root: rootText, proof: proof, signer: signer, issuer: issuer), root: rootText)
    }

    /// Register an already-signed statement (validated structurally first) and return a signed inclusion receipt.
    public func register(_ statement: [UInt8]) throws -> ScittRegistration {
        guard try PCAScitt.decodeCoseSign1(statement).payload != nil else { throw JSError("scitt: cannot register a statement with a detached payload") }
        let index = Int64(statements.count)
        statements.append(statement)
        leafHashes.append(PCARfc9162.leafHash(statement))
        return try receiptFor(index)
    }

    public func appendAndReceipt(_ payload: JSONValue, signer stmtSigner: PCAScitt.CoseSigner, issuer stmtIssuer: String, subject: String? = nil, contentType: String? = nil) throws -> ScittAppendResult {
        let st = try PCAScitt.signStatement(payload, signer: stmtSigner, issuer: stmtIssuer, subject: subject, contentType: contentType)
        return ScittAppendResult(statement: st, registration: try register(st))
    }

    /// A receipt for an already-registered statement, against the CURRENT root.
    public func getReceipt(_ index: Int64) throws -> ScittRegistration {
        guard index >= 0, index < Int64(statements.count) else { throw JSError("getReceipt: index out of range") }
        return try receiptFor(index)
    }

    public func consistencyProof(_ oldSize: Int64) throws -> ScittConsistencyProof {
        guard oldSize >= 1, oldSize <= Int64(statements.count) else { throw JSError("consistencyProof: size out of range") }
        let path = try PCARfc9162.consistencyPath(leafHashes, oldSize)
        return ScittConsistencyProof(oldSize: oldSize, newSize: Int64(statements.count), oldRoot: Base64URLStrict.encode(PCARfc9162.treeHash(Array(leafHashes[..<Int(oldSize)]))),
                                     newRoot: root, proof: try scittConsistencyBytes(oldSize, Int64(statements.count), path))
    }
}

// MARK: durable log

/// The hash of the complete subtree at `level` covering leaves [index * 2^level, (index + 1) * 2^level).
public struct ScittStoredNode {
    public let level: Int
    public let index: Int64
    public let hash: [UInt8]
    public init(level: Int, index: Int64, hash: [UInt8]) { self.level = level; self.index = index; self.hash = hash }
}

/// Durable, append-only storage for a transparency log. `append` is atomic: it succeeds only when the log still has exactly
/// `expectedSize` entries (a compare-and-set) and stores the entry and the new subtree hashes together, or none of them.
public protocol ScittLogStore {
    func size() throws -> Int64
    func getEntry(_ index: Int64) throws -> [UInt8]?
    func getNode(_ level: Int, _ index: Int64) throws -> [UInt8]?
    func append(expectedSize: Int64, entry: [UInt8], nodes: [ScittStoredNode]) throws -> Bool
}

/// In-memory log store: single process, forgets everything on restart. For tests only.
public final class MemoryScittLogStore: ScittLogStore {
    private var entries: [[UInt8]] = []
    private var nodes: [String: [UInt8]] = [:]
    public init() {}
    public func size() throws -> Int64 { Int64(entries.count) }
    public func getEntry(_ index: Int64) throws -> [UInt8]? { index >= 0 && index < Int64(entries.count) ? entries[Int(index)] : nil }
    public func getNode(_ level: Int, _ index: Int64) throws -> [UInt8]? { nodes["\(level):\(index)"] }
    public func append(expectedSize: Int64, entry: [UInt8], nodes ns: [ScittStoredNode]) throws -> Bool {
        if Int64(entries.count) != expectedSize { return false }
        entries.append(entry)
        for n in ns { nodes["\(n.level):\(n.index)"] = n.hash }
        return true
    }
}

public enum PCAScittLogError {
    public static let storeRequired = "store_required"
    public static let storeCorrupt = "store_corrupt"
    public static let appendContention = "append_contention"
    public static let outOfRange = "out_of_range"
    public static let badStatement = "bad_statement"
}

public final class PCAScittDurableService {
    static let maxAppendAttempts = 16
    private let store: ScittLogStore
    private let signer: PCAScitt.CoseSigner
    private let issuer: String?

    public init(store: ScittLogStore, signer: PCAScitt.CoseSigner, issuer: String? = nil) { self.store = store; self.signer = signer; self.issuer = issuer }

    private func corrupt(_ m: String) -> JSError { JSError(m, code: PCAScittLogError.storeCorrupt) }

    private func node(_ level: Int, _ index: Int64) throws -> [UInt8] {
        guard let h = try store.getNode(level, index), h.count == 32 else { throw corrupt("missing or malformed subtree hash (\(level), \(index))") }
        return h
    }

    private static func largestPow2Below(_ n: Int64) -> Int64 {
        var k: Int64 = 1
        while k * 2 < n { k *= 2 }
        return k
    }

    /// MTH over leaves [lo, lo + n): `lo` is a multiple of the split points, which every caller guarantees.
    private func range(_ lo: Int64, _ n: Int64) throws -> [UInt8] {
        if n == 1 { return try node(0, lo) }
        if n > 0 && n & (n - 1) == 0 && lo % n == 0 { return try node(n.trailingZeroBitCount, lo / n) }
        let k = Self.largestPow2Below(n)
        return PCARfc9162.nodeHash(try range(lo, k), try range(lo + k, n - k))
    }

    private func rootOf(_ size: Int64) throws -> [UInt8] {
        if size == 0 { return PCARfc9162.emptyRoot() }
        return try range(0, size)
    }

    private func inclusion(_ lo: Int64, _ n: Int64, _ idx: Int64) throws -> [[UInt8]] {
        if n == 1 { return [] }
        let k = Self.largestPow2Below(n)
        if idx < k { return try inclusion(lo, k, idx) + [try range(lo + k, n - k)] }
        return try inclusion(lo + k, n - k, idx - k) + [try range(lo, k)]
    }

    private func consistency(_ lo: Int64, _ n: Int64, _ mm: Int64, _ complete: Bool) throws -> [[UInt8]] {
        if mm == n { return complete ? [] : [try range(lo, n)] }
        let k = Self.largestPow2Below(n)
        if mm <= k { return try consistency(lo, k, mm, complete) + [try range(lo + k, n - k)] }
        return try consistency(lo + k, n - k, mm - k, false) + [try range(lo, k)]
    }

    public func size() throws -> Int64 {
        let n = try store.size()
        guard n >= 0, n <= Canonical.MAX_SAFE else { throw corrupt("the store reported an invalid size") }
        return n
    }

    /// The current tree root (b64u).
    public func root() throws -> String { Base64URLStrict.encode(try rootOf(try size())) }

    private func receiptFor(_ index: Int64, _ size: Int64) throws -> ScittRegistration {
        let root = try rootOf(size)
        let proof = scittProofJSON(index, size, try inclusion(0, size, index))
        let text = Base64URLStrict.encode(root)
        return ScittRegistration(index: index, receipt: try PCAScitt.buildReceipt(root: text, proof: proof, signer: signer, issuer: issuer), root: text)
    }

    /// Append a Signed Statement (validated structurally first) and return its receipt against the new root.
    public func register(_ statement: [UInt8]) throws -> ScittRegistration {
        do {
            guard try PCAScitt.decodeCoseSign1(statement).payload != nil else { throw JSError("detached payload") }
        } catch {
            throw JSError("cannot register: \((error as? JSError)?.message ?? "\(error)")", code: PCAScittLogError.badStatement)
        }
        for _ in 0..<Self.maxAppendAttempts {
            let n = try size()
            var nodes = [ScittStoredNode(level: 0, index: n, hash: PCARfc9162.leafHash(statement))]
            // completing a subtree at level l: the new leaf is its last leaf, so its left sibling is already stored
            var hash = nodes[0].hash
            var level = 1
            while level < 62, (n + 1) % (Int64(1) << Int64(level)) == 0 {
                let idx = (n + 1) / (Int64(1) << Int64(level)) - 1
                guard let left = try store.getNode(level - 1, 2 * idx), left.count == 32 else { throw corrupt("missing subtree hash (\(level - 1), \(2 * idx))") }
                hash = PCARfc9162.nodeHash(left, hash)
                nodes.append(ScittStoredNode(level: level, index: idx, hash: hash))
                level += 1
            }
            if try store.append(expectedSize: n, entry: statement, nodes: nodes) { return try receiptFor(n, n + 1) }
        }
        throw JSError("could not append: the log kept changing", code: PCAScittLogError.appendContention)
    }

    public func appendAndReceipt(_ payload: JSONValue, signer stmtSigner: PCAScitt.CoseSigner, issuer stmtIssuer: String, subject: String? = nil, contentType: String? = nil) throws -> ScittAppendResult {
        let st = try PCAScitt.signStatement(payload, signer: stmtSigner, issuer: stmtIssuer, subject: subject, contentType: contentType)
        return ScittAppendResult(statement: st, registration: try register(st))
    }

    /// A receipt for an entry, against the CURRENT root.
    public func getReceipt(_ index: Int64) throws -> ScittRegistration {
        let size = try self.size()
        guard index >= 0, index < size else { throw JSError("getReceipt: index out of range", code: PCAScittLogError.outOfRange) }
        return try receiptFor(index, size)
    }

    public func getEntry(_ index: Int64) throws -> [UInt8] {
        let size = try self.size()
        guard index >= 0, index < size else { throw JSError("getEntry: index out of range", code: PCAScittLogError.outOfRange) }
        guard let e = try store.getEntry(index) else { throw corrupt("entry \(index) is missing") }
        return e
    }

    /// An RFC 9162 consistency proof that the first `oldSize` entries are a prefix of the current log.
    public func consistencyProof(_ oldSize: Int64) throws -> ScittConsistencyProof {
        let size = try self.size()
        guard oldSize >= 1, oldSize <= size else { throw JSError("consistencyProof: size out of range", code: PCAScittLogError.outOfRange) }
        let path = try consistency(0, size, oldSize, true)
        return ScittConsistencyProof(oldSize: oldSize, newSize: size, oldRoot: Base64URLStrict.encode(try rootOf(oldSize)), newRoot: Base64URLStrict.encode(try rootOf(size)),
                                     proof: try scittConsistencyBytes(oldSize, size, path))
    }
}

/// Check a store against the contract the durable service relies on; returns the failures (empty = conforms): compare-and-set, atomic
/// entry-plus-nodes, immutability and a read-back of what was stored.
public func checkScittLogStore(_ makeStore: () throws -> ScittLogStore) -> [String] {
    var failures: [String] = []
    func fail(_ m: String) { failures.append(m) }
    do {
        let s = try makeStore()
        if try s.size() != 0 { fail("a new store is not empty") }
        func h(_ b: UInt8) -> [UInt8] { [UInt8](repeating: b, count: 32) }
        if try !s.append(expectedSize: 0, entry: [1], nodes: [ScittStoredNode(level: 0, index: 0, hash: h(1))]) { fail("append at the right size was refused") }
        if try s.append(expectedSize: 0, entry: [2], nodes: [ScittStoredNode(level: 0, index: 1, hash: h(2))]) { fail("append at a stale size was accepted (no compare-and-set)") }
        if try s.size() != 1 { fail("a refused append changed the size") }
        if try s.getNode(0, 1) != nil { fail("a refused append left a node behind (not atomic)") }
        if try s.getEntry(1) != nil { fail("a refused append left an entry behind") }
        if try s.getEntry(0) != [1] { fail("the stored entry does not read back") }
        var wins = 0
        for i in 1...4 {
            if try s.append(expectedSize: 1, entry: [UInt8(10 + i)], nodes: [ScittStoredNode(level: 0, index: 1, hash: h(UInt8(10 + i)))]) { wins += 1 }
        }
        if wins != 1 { fail("concurrent appends at the same size did not produce exactly one winner") }
        if try s.size() != 2 { fail("the size after a race is not 2") }
    } catch {
        fail("the store threw: \((error as? JSError)?.message ?? "\(error)")")
    }
    return failures
}
