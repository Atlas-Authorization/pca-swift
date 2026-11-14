import Foundation

/// A mutex that also counts how often it was taken and whether it is held, so a test can check deterministically that a critical
/// section really takes the lock and gives it back (a dropped `lock()` or `unlock()` shows as a count, a held depth or an imbalance,
/// not as a data race). `recursive` selects an NSRecursiveLock.
package final class PCALock: @unchecked Sendable {
    private let m: NSLocking
    private let meta = NSLock()
    private var heldDepth = 0, taken = 0, unbalanced = 0

    package init(recursive: Bool = false) { m = recursive ? NSRecursiveLock() : NSLock() }

    package func lock() {
        m.lock()
        meta.lock(); heldDepth += 1; taken += 1; meta.unlock()
    }

    package func unlock() {
        meta.lock()
        if heldDepth == 0 { unbalanced += 1; meta.unlock(); return } // an unlock with no lock: counted, never passed to the mutex
        heldDepth -= 1
        meta.unlock()
        m.unlock()
    }

    /// How many times `lock()` has been called.
    package var acquisitions: Int { meta.lock(); defer { meta.unlock() }; return taken }
    /// Nesting depth now held (0 when free).
    package var depth: Int { meta.lock(); defer { meta.unlock() }; return heldDepth }
    /// Unlocks that had no matching lock.
    package var imbalance: Int { meta.lock(); defer { meta.unlock() }; return unbalanced }
}
