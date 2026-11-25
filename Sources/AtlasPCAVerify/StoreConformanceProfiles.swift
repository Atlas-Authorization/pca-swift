import Foundation

/// The shared machinery of the profile suites (bond, budget, ledger): one check list per store kind, a runner that gives every check a fresh backend, and
/// the text report. A check throws on a violation; the runner turns the first line of the message into the report's detail.
extension PCAStoreConformance {
    public struct ProfileCheckResult: Equatable {
        public var name: String
        /// `pass`, `fail` or `skip`.
        public var status: String
        public var detail: String?
    }

    public struct ProfileReport: Equatable {
        public var adapter: String
        public var status: String
        public var checks: [ProfileCheckResult]
    }

    /// One claim about a store kind. `needs` is nil, `durable` or `crash`.
    public struct ProfileCheck<H> {
        public var name: String
        public var claim: String
        public var needs: String?
        public var run: (H) throws -> Void
        public init(_ name: String, _ claim: String, needs: String? = nil, run: @escaping (H) throws -> Void) {
            self.name = name; self.claim = claim; self.needs = needs; self.run = run
        }
    }

    /// The reference's inventory entry of a check: name, claim and the capability it needs (JSON null when none).
    static func inventory<H>(_ checks: [ProfileCheck<H>]) -> JSONValue {
        .array(checks.map { .object(["name": .string($0.name), "claim": .string($0.claim), "needs": $0.needs.map { .string($0) } ?? .null]) })
    }

    static func runProfile<H>(_ checks: [ProfileCheck<H>], adapter: String, durable: Bool?, only: [String]?, create: () throws -> H, canCrash: (H) -> Bool,
                              close: (H) -> Void, prepare: (inout H) -> Void = { _ in }) throws -> ProfileReport {
        var out: [ProfileCheckResult] = []
        for c in checks {
            if let o = only, !o.contains(c.name) { continue }
            if c.needs == "durable" && durable == false { out.append(ProfileCheckResult(name: c.name, status: "skip", detail: "the adapter declares durable: false")); continue }
            var h = try create() // a backend that cannot be created is the caller's failure, not a failed check
            prepare(&h)
            defer { close(h) }
            if c.needs == "crash" && !canCrash(h) { out.append(ProfileCheckResult(name: c.name, status: "skip", detail: "the adapter has no crash()")); continue }
            do { try c.run(h); out.append(ProfileCheckResult(name: c.name, status: "pass", detail: nil)) } catch {
                out.append(ProfileCheckResult(name: c.name, status: "fail", detail: scText(error)))
            }
        }
        return ProfileReport(adapter: adapter, status: out.contains { $0.status == "fail" } ? "fail" : "pass", checks: out)
    }

    static func formatProfile(_ kind: String, _ r: ProfileReport) -> String {
        (["pca-store-conformance (\(kind)): \(r.adapter) -> \(r.status.uppercased())"]
            + r.checks.map { c in "  [\(c.status.uppercased())] \(c.name)" + (c.detail.flatMap { $0.isEmpty ? nil : ": " + (IV.split($0, "\n").first ?? "") } ?? "") }).joined(separator: "\n")
    }

    // MARK: helpers the checks share

    static func scText(_ e: Error) -> String { (e as? JSError)?.message ?? (e as? PCAProducerError)?.message ?? PCAStoreError.text(e) }

    /// JSON text to a value (the checks write their plans as literals).
    static func scJ(_ text: String) -> JSONValue { (try? StrictJSON.parseLenient(text)) ?? .null }

    static func scNeed(_ cond: Bool, _ what: @autoclosure () -> String) throws { if !cond { throw JSError(what()) } }

    /// Deep equality of two JSON values (number spellings and member order do not matter).
    static func scEq(_ got: JSONValue?, _ want: JSONValue?, _ what: String = "") throws {
        if !StoreJ.same(got, want) {
            throw JSError((what.isEmpty ? "" : what + ": ") + "expected \(want.map { JS.stringify($0) } ?? "undefined") but got \(got.map { JS.stringify($0) } ?? "undefined")")
        }
    }

    static func scIs<T: Equatable>(_ got: T, _ want: T, _ what: String = "") throws {
        if got != want { throw JSError((what.isEmpty ? "" : what + ": ") + "expected \(want) but got \(got)") }
    }

    static func scEqD(_ got: [Double], _ want: [Double], _ what: String = "") throws { try scIs(got, want, what) }

    /// The call must throw.
    static func scThrows(_ what: String, _ f: () throws -> Void) throws {
        var threw = false
        do { try f() } catch { threw = true }
        if !threw { throw JSError("\(what): expected it to throw") }
    }

    /// The call must throw a range error (`PCAStoreError.range`): the caller's bug, never a store state.
    static func scThrowsRange(_ what: String, _ f: () throws -> Void) throws {
        do { try f() } catch {
            if PCAStoreError.codeOf(error) == "RangeError" { return }
            throw JSError("\(what): expected a range error but got \(scText(error))")
        }
        throw JSError("\(what): expected it to throw")
    }

    /// `scRace` for bodies that may throw: the first failure (in order) fails the whole race.
    static func scRaceTry<T>(_ bodies: [() throws -> T]) throws -> [T] {
        try scRace(bodies.map { b -> () -> Result<T, Error> in { Result(catching: b) } }).map { try $0.get() }
    }

    /// Run the bodies at once, each on its own thread, and collect their results in order.
    static func scRace<T>(_ bodies: [() -> T]) -> [T] {
        let slots = RaceSlots<T>(Array(repeating: nil, count: bodies.count))
        let group = DispatchGroup()
        for (i, b) in bodies.enumerated() {
            group.enter()
            Thread { let r = b(); slots.lock.lock(); slots.v[i] = r; slots.lock.unlock(); group.leave() }.start()
        }
        group.wait()
        return slots.v.map { $0! }
    }

    /// Start a body on its own thread and do not wait for it (a write in flight at a crash).
    static func scFireAndForget(_ body: @escaping () -> Void) { Thread { body() }.start() }

    static func scStr(_ v: JSONValue?, _ k: String) -> String? { v?.get(k)?.asString }

    static func scTempDir(_ prefix: String) -> String { NSTemporaryDirectory() + prefix + UUID().uuidString }
}

fileprivate final class RaceSlots<T>: @unchecked Sendable { let lock = NSLock(); var v: [T?]; init(_ v: [T?]) { self.v = v } }
