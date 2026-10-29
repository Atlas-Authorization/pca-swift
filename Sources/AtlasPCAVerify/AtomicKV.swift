import Foundation

/// An atomic key/value store of JSON values: the one primitive the plan registry and `KVOperationStore` need. `update` MUST be an
/// atomic read-modify-write across every process and node that shares the store (a row-locked transaction, a conditional write):
/// `f` sees the current value (nil: none) and returns the value to store, or nil to leave the key unchanged. `f` runs exactly once,
/// synchronously, and must not call the store. A call that cannot decide MUST throw.
public protocol AtomicKV: Sendable {
    func get(_ key: String) throws -> JSONValue?
    func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws
}

/// In-process `AtomicKV` for ONE process (the default of `PlanRegistry`; tests).
public final class MemoryAtomicKV: AtomicKV, @unchecked Sendable {
    private var values: [String: JSONValue] = [:]
    private let lock = NSLock()

    public init() {}

    public func get(_ key: String) -> JSONValue? {
        lock.lock()
        defer { lock.unlock() }
        return values[key]
    }

    public func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) {
        lock.lock()
        defer { lock.unlock() }
        if let next = f(values[key]) { values[key] = next }
    }
}

/// An `OperationStore` over any `AtomicKV` (every state change is one atomic update). It is not an `OperationLister`: recover a known
/// id with `PCA.recoverOperation`.
public final class KVOperationStore: OperationStore, @unchecked Sendable {
    public static let DEFAULT_PREFIX = "pca-op:"
    private let kv: AtomicKV
    private let prefix: String

    public init(kv: AtomicKV, prefix: String = KVOperationStore.DEFAULT_PREFIX) {
        self.kv = kv
        self.prefix = prefix
    }

    public func create(_ record: OperationRecord) throws -> OperationCreate {
        var existing: OperationRecord?
        try kv.update(prefix + record.id) { prev in
            if let p = prev, let cur = OperationRecord(json: p) {
                existing = cur
                return nil
            }
            return record.json
        }
        return existing.map { .existing($0) } ?? .created
    }

    public func get(_ id: String) throws -> OperationRecord? {
        guard let v = try kv.get(prefix + id) else { return nil }
        return OperationRecord(json: v)
    }

    public func transition(_ id: String, from: OperationState, to next: OperationRecord) throws -> Bool {
        var n = next
        n.id = id
        var done = false
        try kv.update(prefix + id) { prev in
            guard let p = prev, let cur = OperationRecord(json: p), cur.state == from else { return nil }
            done = true
            return n.json
        }
        return done
    }
}
