import Foundation

/// In-flight de-duplication: callers that ask for the same key while one is running share that run's result (or its error) instead of
/// starting another. Used so a rotating refresh token is spent exactly once however many requests find the token stale together.
final class SingleFlight<Key: Hashable, Value> {
    private final class Flight {
        let cond = NSCondition()
        var result: Result<Value, Error>?
        func finish(_ r: Result<Value, Error>) { cond.lock(); result = r; cond.broadcast(); cond.unlock() }
        func wait() throws -> Value {
            cond.lock(); defer { cond.unlock() }
            while result == nil { cond.wait() }
            return try result!.get()
        }
    }
    private let lock = NSLock()
    private var flights: [Key: Flight] = [:]

    /// Run `work` unless a run for `key` is already in flight, in which case wait for and return that run's outcome. The key is released
    /// BEFORE the waiters wake, so a call made after the outcome starts a fresh run.
    func run(_ key: Key, _ work: () throws -> Value) throws -> Value {
        lock.lock()
        if let fl = flights[key] {
            lock.unlock()
            return try fl.wait()
        }
        let fl = Flight()
        flights[key] = fl
        lock.unlock()
        let r = Result { try work() }
        lock.lock(); flights[key] = nil; lock.unlock()
        fl.finish(r)
        return try r.get()
    }
}
