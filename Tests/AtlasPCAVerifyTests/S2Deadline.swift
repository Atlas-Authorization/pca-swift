import XCTest
import Foundation

/// A deadline for a call a mutant could make loop or recurse forever: the call runs on a background thread and the test FAILS (an
/// assertion, so the mutant is killed by a test) when it has not finished in `seconds`. The unmutated code finishes in milliseconds.
/// A mutant that never ends leaves its thread spinning; the failed test ends the run, so nothing waits for it.
enum S2Deadline {
    private final class Box<T>: @unchecked Sendable {
        private let l = NSLock()
        private var v: T?
        func set(_ x: T) { l.lock(); v = x; l.unlock() }
        func get() -> T? { l.lock(); defer { l.unlock() }; return v }
    }

    /// The call's result, or nil (after an XCTFail) if it did not finish in time.
    @discardableResult
    static func within<T>(_ seconds: Double = 3, _ what: String, file: StaticString = #filePath, line: UInt = #line, _ body: @escaping @Sendable () -> T) -> T? {
        let box = Box<T>()
        let done = DispatchSemaphore(value: 0)
        let t = Thread { box.set(body()); done.signal() }
        t.stackSize = 8 << 20
        t.start()
        if done.wait(timeout: .now() + seconds) == .timedOut {
            XCTFail("\(what): did not finish within \(seconds) s", file: file, line: line)
            return nil
        }
        return box.get()
    }
}
