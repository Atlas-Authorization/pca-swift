import Foundation

/// A refusal of the undo ledger: `code` is one of `not_durable`, `store_missing`, `store_corrupt`, `invalid`, `conflict_exhausted`, `signer_missing`, `config`.
public struct UndoError: Error, Equatable, CustomStringConvertible {
    public let code: String
    public let message: String
    public init(_ code: String, _ message: String) { self.code = code; self.message = message }
    public var description: String { "UndoError(\(code)): \(message)" }
}

/// What a store `list` is asked: the records in `state` (and, when given, whose window ended at or before `windowEndedBy`, for the finalize sweep, or
/// that carry the grant / bond reference), at most `limit`.
public struct UndoQuery: Equatable {
    public var state: String
    public var windowEndedBy: Int64?
    public var grantRef: String?
    public var bondRef: String?
    public var limit: Int?
    public init(state: String, windowEndedBy: Int64? = nil, grantRef: String? = nil, bondRef: String? = nil, limit: Int? = nil) {
        self.state = state; self.windowEndedBy = windowEndedBy; self.grantRef = grantRef; self.bondRef = bondRef; self.limit = limit
    }
}

/// The persistence contract of the undo ledger. Implement it over a database (a row per record with a unique id and a version column:
/// `UPDATE ... WHERE id = $1 AND ver = $2`) or use `KvUndoStore`. A record is a JSON object (`{v: 1, id, state, ver, receipts, ...}`).
public protocol UndoStore: AnyObject {
    /// True ONLY when acknowledged writes survive a restart or crash. The coordinator refuses a store that does not say so.
    var durable: Bool { get }
    func get(_ id: String) throws -> JSONValue?
    /// Atomically insert if no record with this id exists; otherwise answer the stored one unchanged.
    func create(_ rec: JSONValue) throws -> (created: Bool, record: JSONValue?)
    /// Atomically replace the record iff its stored `ver` is `expectedVer`.
    func replace(_ id: String, expectedVer: Int64, next: JSONValue) throws -> Bool
    func list(_ q: UndoQuery) throws -> [JSONValue]
}

/// An `AtomicKV` that can list its keys (the undo ledger's sweep needs it).
public protocol ListableAtomicKV: AtomicKV {
    func keys() throws -> [String]
}

extension MemoryAtomicKV: ListableAtomicKV {}

public enum PCAUndoStores {
    /// True iff `s` is an `UndoStore`.
    public static func isUndoStore(_ s: Any?) -> Bool { s is UndoStore }

    static func matches(_ r: JSONValue, _ q: UndoQuery) -> Bool {
        guard IV.same(r.get("state")?.asString, q.state) else { return false }
        if let e = q.windowEndedBy, !((r.get("window_end")?.safeInt ?? Int64.max) <= e) { return false }
        if let g = q.grantRef, !IV.same(r.get("grant_ref")?.asString, g) { return false }
        if let b = q.bondRef, !IV.same(r.get("bond_ref")?.asString, b) { return false }
        return true
    }

    static func decode(_ raw: JSONValue?) throws -> JSONValue? {
        guard let r = raw else { return nil }
        guard r.isObject, IV.num(r.get("v")) == 1, Undo.idOk(r.get("id")), r.get("state")?.asString.map({ IV.contains(Undo.STATES, $0) }) == true,
              r.get("ver")?.safeInt != nil, r.get("receipts")?.isArray == true else { throw UndoError("store_corrupt", "an undo record has the wrong shape") }
        return r
    }

    static func idKey(_ id: JSONValue?) throws -> String {
        guard Undo.idOk(id), let s = id?.asString else { throw UndoError("invalid", "an undo record id is a non-empty string without control characters") }
        return s
    }
}

/// A process-memory `UndoStore`: `durable` is false, so the coordinator refuses it unless the caller says, for a test, that it accepts losing every open
/// window on restart. Never use it in production.
public final class MemoryUndoStore: UndoStore, @unchecked Sendable {
    public let durable = false
    private var m: [String: JSONValue] = [:]
    private let lock = NSLock()
    public init() {}

    public func get(_ id: String) -> JSONValue? { lock.lock(); defer { lock.unlock() }; return m[id] }

    public func create(_ rec: JSONValue) throws -> (created: Bool, record: JSONValue?) {
        let id = try PCAUndoStores.idKey(rec.get("id"))
        lock.lock(); defer { lock.unlock() }
        if let cur = m[id] { return (false, cur) }
        m[id] = rec
        return (true, nil)
    }

    public func replace(_ id: String, expectedVer: Int64, next: JSONValue) throws -> Bool {
        guard IV.same(next.get("id")?.asString, id) else { throw UndoError("invalid", "replace: the record id cannot change") }
        lock.lock(); defer { lock.unlock() }
        guard m[id]?.get("ver")?.safeInt == expectedVer else { return false }
        m[id] = next
        return true
    }

    public func list(_ q: UndoQuery) -> [JSONValue] {
        lock.lock(); defer { lock.unlock() }
        let out = m.values.filter { PCAUndoStores.matches($0, q) }.sorted { ($0.get("id")?.asString ?? "").utf16.lexicographicallyPrecedes(($1.get("id")?.asString ?? "").utf16) }
        return q.limit.map { Array(out.prefix(Swift.max(0, $0))) } ?? out
    }
}

/// The reference `UndoStore` over any `ListableAtomicKV` (one document per record under `pca-undo/v1/<id>`, every write one atomic read-modify-write).
/// `durable` is declared by the caller because a kv cannot tell: true only over a persistent kv, false over an in-memory one. `list` scans every key (fine
/// for one host's backlog); a database store indexes (state, window_end).
public final class KvUndoStore: UndoStore, @unchecked Sendable {
    static let PREFIX = "pca-undo/v1/"
    private let kv: ListableAtomicKV
    public let durable: Bool

    public init(_ kv: ListableAtomicKV, durable: Bool) { self.kv = kv; self.durable = durable }

    public func get(_ id: String) throws -> JSONValue? { try PCAUndoStores.decode(try kv.get(try key(id))) }

    private func key(_ id: String) throws -> String { try PCAUndoStores.idKey(.string(id)).withPrefix(Self.PREFIX) }

    public func create(_ rec: JSONValue) throws -> (created: Bool, record: JSONValue?) {
        let k = Self.PREFIX + (try PCAUndoStores.idKey(rec.get("id")))
        var existing: JSONValue?
        var failure: Error?
        try kv.update(k) { prev in
            do { existing = try PCAUndoStores.decode(prev) } catch { failure = error; return nil }
            return existing != nil ? nil : rec
        }
        if let f = failure { throw f }
        return existing != nil ? (false, existing) : (true, nil)
    }

    public func replace(_ id: String, expectedVer: Int64, next: JSONValue) throws -> Bool {
        guard IV.same(next.get("id")?.asString, id) else { throw UndoError("invalid", "replace: the record id cannot change") }
        let k = try key(id)
        var done = false
        var failure: Error?
        try kv.update(k) { prev in
            do {
                let cur = try PCAUndoStores.decode(prev)
                done = cur?.get("ver")?.safeInt == expectedVer
            } catch { failure = error; return nil }
            return done ? next : nil
        }
        if let f = failure { throw f }
        return done
    }

    public func list(_ q: UndoQuery) throws -> [JSONValue] {
        var out: [JSONValue] = []
        for k in try kv.keys().filter({ $0.hasPrefix(Self.PREFIX) }).sorted(by: { $0.utf16.lexicographicallyPrecedes($1.utf16) }) {
            if let r = try PCAUndoStores.decode(try kv.get(k)), PCAUndoStores.matches(r, q) { out.append(r) }
            if let l = q.limit, out.count >= l { break }
        }
        return out
    }
}

private extension String {
    func withPrefix(_ p: String) -> String { p + self }
}

extension Undo {
    /// Append the signed receipt of an applied transition (linked to the previous one): `record.state` is the state AFTER `event`.
    public static func withReceipt(_ rec: JSONValue, event: String, note: String, at: Int64, key: PCAEdKey) throws -> JSONValue {
        guard let id = rec.get("id")?.asString, let state = rec.get("state")?.asString, let cd = rec.get("compensation_digest")?.asString else { throw UndoError("invalid", "withReceipt: malformed record") }
        let receipts = rec.get("receipts")?.asArray ?? []
        let prev = try receipts.last.map { r -> String in
            guard let d = receiptDigest(r) else { throw UndoError("invalid", "withReceipt: malformed receipt") }
            return d
        } ?? ""
        let receipt = try signReceipt(record: id, event: event, state: state, at: at, compensationDigest: cd, prev: prev, note: note, key: key)
        var o = rec.asObject ?? [:]
        o[JKey("receipts")] = .array(receipts + [receipt])
        return .object(o)
    }
}
