import Foundation

/// Conformance cases for a `MeshWitnessStore`: the durable memory of a mesh log witness (mesh-witness.ts). A witness cosigns a head only if it extends the last
/// head THIS witness cosigned. A store that forgets across a restart, or that loses a save and still lets the cosignature out, lets a domain walk the witness back
/// and show two verifiers different histories. The cases check the store by itself (round trip, replace, copy semantics, atomicity, reopen) and through a real
/// `MeshWitness` (every cosignature is persisted first; a restarted witness refuses rollback and forks; a failed save refuses the cosignature and changes
/// nothing; damaged storage is not read as empty).
extension PCAStoreConformance {
    public struct MeshWitnessStoreAdapter {
        public var name: String
        /// A fresh, empty store.
        public var make: () throws -> any MeshWitnessStore
        /// A new store object over the same backing storage as `previous` (a restart). Nil for stores that cannot persist.
        public var reopen: ((any MeshWitnessStore) throws -> any MeshWitnessStore)?
        /// Damage the backing storage of `store` so that `load` must fail. Nil if the store cannot detect damage.
        public var damage: ((any MeshWitnessStore) throws -> Void)?
        public init(name: String, make: @escaping () throws -> any MeshWitnessStore, reopen: ((any MeshWitnessStore) throws -> any MeshWitnessStore)? = nil,
                    damage: ((any MeshWitnessStore) throws -> Void)? = nil) {
            self.name = name; self.make = make; self.reopen = reopen; self.damage = damage
        }
    }

    public struct MeshWitnessStoreCase {
        public var name: String
        public var run: () throws -> Void
    }

    private static func mwSeed(_ label: String) -> [UInt8] {
        let l = Array(label.utf8)
        return (0..<32).map { UInt8(truncatingIfNeeded: Int(l[$0 % l.count]) + $0) }
    }
    private static func mwKey(_ label: String) throws -> PCAEdKey { try PCAEdKey(seed: mwSeed(label)) }

    private static func mwCap(_ label: String) throws -> JSONValue {
        try PCAIssue.mintRoot(principal: .ed25519(try mwKey("principal")), holder: Base64URLStrict.encode(try mwKey("holder").pub),
                              caveats: [.object(["type": .string("scope"), "actions": .array([.string(label)])])])
    }

    /// Same domain key, different history: the second is a fork of the first from entry 0 on.
    private static func mwTwoLogs() throws -> (honest: MeshDomain, fork: MeshDomain) {
        let honest = MeshDomain(name: "d", secret: try mwKey("domain")), fork = MeshDomain(name: "d", secret: try mwKey("domain"))
        try honest.record(try mwCap("a"))
        try fork.record(try mwCap("x"))
        return (honest, fork)
    }

    private static func mwState(_ n: Int) -> JSONValue {
        scJ(#"{"seen":[{"head":{"domain":"d\#(n)","size":0,"root":"","rev_root":"r","rev_size":0,"timestamp":\#(n)},"rev_ids":[]}]}"#)
    }

    private static func mwCosigs(_ head: JSONValue) -> Int { head.get("cosigs")?.asArray?.count ?? -1 }

    /// The store that fails its saves on demand (a full disk).
    private final class FlakyMeshStore: MeshWitnessStore {
        let inner: any MeshWitnessStore
        var failing = false
        init(_ inner: any MeshWitnessStore) { self.inner = inner }
        func load() throws -> JSONValue? { try inner.load() }
        func save(_ state: JSONValue) throws {
            if failing { throw JSError("disk full") }
            try inner.save(state)
        }
    }

    public static func meshWitnessStoreCases(_ a: MeshWitnessStoreAdapter) -> [MeshWitnessStoreCase] {
        var cases: [MeshWitnessStoreCase] = [
            MeshWitnessStoreCase(name: "a fresh store loads nothing") {
                try scNeed(try a.make().load() == nil, "a fresh store must load nothing")
            },
            MeshWitnessStoreCase(name: "save then load returns the same state") {
                let s = try a.make()
                try s.save(mwState(1))
                try scEq(try s.load(), mwState(1))
            },
            MeshWitnessStoreCase(name: "a later save replaces the earlier one") {
                let s = try a.make()
                try s.save(mwState(1))
                try s.save(mwState(2))
                try scEq(try s.load(), mwState(2))
            },
            MeshWitnessStoreCase(name: "load returns a copy: changing it does not change the store") {
                let s = try a.make()
                try s.save(mwState(1))
                var got = try s.load()?.asObject ?? [:]
                got["seen"] = .array([]) // the loaded state is a value: changing it is all a caller can do
                try scEq(try s.load(), mwState(1))
            },
            MeshWitnessStoreCase(name: "save keeps its own copy: changing the argument afterwards does not change the store") {
                let s = try a.make()
                var st = mwState(1)
                try s.save(st)
                st = .object(["seen": .array([])])
                try scEq(try s.load(), mwState(1))
            },
            MeshWitnessStoreCase(name: "a witness persists every cosignature before returning it") {
                let s = try a.make()
                let w = try MeshWitness(secret: try mwKey("w"), store: s)
                let logs = try mwTwoLogs()
                let ch = try logs.honest.publishHead(witnesses: [w], timestamp: .int(1_000))
                try scEq(try s.load(), w.exportState())
                try scEq(.array((try s.load()?.get("seen")?.asArray ?? []).map { $0.get("head") ?? .null }), .array([ch.get("head") ?? .null]))
            },
            MeshWitnessStoreCase(name: "a failed save refuses the cosignature and leaves the witness unchanged") {
                let flaky = FlakyMeshStore(try a.make())
                let w = try MeshWitness(secret: try mwKey("w"), store: flaky)
                let logs = try mwTwoLogs()
                _ = try logs.honest.publishHead(witnesses: [w], timestamp: .int(1_000))
                let before = JS.stringify(w.exportState())
                try logs.honest.record(try mwCap("b"))
                flaky.failing = true
                var threw = ""
                do { _ = try logs.honest.publishHead(witnesses: [w], timestamp: .int(2_000)) } catch { threw = scText(error) }
                try scIs(threw, "witness: could not persist state; refusing to cosign")
                try scIs(JS.stringify(w.exportState()), before)
                try scEq(try flaky.inner.load(), scJ(before))
                flaky.failing = false
                try scIs(mwCosigs(try logs.honest.publishHead(witnesses: [w], timestamp: .int(2_000))), 1, "the same head is cosigned once the disk recovers")
            },
        ]
        if let reopen = a.reopen {
            cases.append(MeshWitnessStoreCase(name: "state survives reopening the store") {
                let s = try a.make()
                try s.save(mwState(3))
                try scEq(try reopen(s).load(), mwState(3))
            })
            cases.append(MeshWitnessStoreCase(name: "a restarted witness remembers what it cosigned: it refuses a fork and a rollback") {
                let s = try a.make()
                let w1 = try MeshWitness(secret: try mwKey("w"), store: s)
                let logs = try mwTwoLogs()
                _ = try logs.honest.publishHead(witnesses: [w1], timestamp: .int(1_000))
                try logs.honest.record(try mwCap("b"))
                _ = try logs.honest.publishHead(witnesses: [w1], timestamp: .int(2_000))
                let w2 = try MeshWitness(secret: try mwKey("w"), store: try reopen(s))
                try scEq(w2.lastSeen(logs.honest.id)?.get("size"), .int(2))
                try logs.fork.record(try mwCap("y"))
                try logs.fork.record(try mwCap("z"))
                var forkErr = ""
                do { _ = try logs.fork.publishHead(witnesses: [w2], timestamp: .int(3_000)) } catch { forkErr = scText(error) }
                try scNeed(forkErr != "", "a fork that grew past the remembered size must be refused")
                let rollback = MeshDomain(name: "d", secret: try mwKey("domain"))
                try rollback.record(try mwCap("a"))
                var rbErr = ""
                do { _ = try rollback.publishHead(witnesses: [w2], timestamp: .int(3_000)) } catch { rbErr = scText(error) }
                try scNeed(rbErr != "", "a rollback to the first head must be refused")
                try scNeed(mwCosigs(try logs.honest.publishHead(witnesses: [w2], timestamp: .int(3_000))) == 1, "the honest log is still cosigned")
            })
        }
        if let damage = a.damage {
            cases.append(MeshWitnessStoreCase(name: "damaged storage makes load throw, so a witness never starts empty over it") {
                let s = try a.make()
                // a state a witness accepts, so that only the damage can make construction fail
                let w0 = try MeshWitness(secret: try mwKey("w"))
                let d0 = MeshDomain(name: "d", secret: try mwKey("domain"))
                try d0.record(try mwCap("a"))
                _ = try d0.publishHead(witnesses: [w0], timestamp: .int(1_000))
                try s.save(w0.exportState())
                try damage(s)
                var threw = false
                do { _ = try s.load() } catch { threw = true }
                try scNeed(threw, "load must throw on damaged storage")
                var ctor = false
                do { _ = try MeshWitness(secret: try mwKey("w"), store: s) } catch { ctor = true }
                try scNeed(ctor, "constructing a witness over damaged storage must throw")
            })
        }
        return cases
    }

    /// Run every case of the adapter; one `ProfileCheckResult` per case.
    public static func runMeshWitnessStoreConformance(_ a: MeshWitnessStoreAdapter) -> ProfileReport {
        let results = meshWitnessStoreCases(a).map { c -> ProfileCheckResult in
            do { try c.run(); return ProfileCheckResult(name: c.name, status: "pass", detail: nil) } catch { return ProfileCheckResult(name: c.name, status: "fail", detail: scText(error)) }
        }
        return ProfileReport(adapter: a.name, status: results.contains { $0.status == "fail" } ? "fail" : "pass", checks: results)
    }

    /// GOOD, in process: `MemoryMeshWitnessStore` (it cannot reopen or detect damage).
    public static func memoryMeshWitnessStoreAdapter() -> MeshWitnessStoreAdapter { MeshWitnessStoreAdapter(name: "MemoryMeshWitnessStore", make: { MemoryMeshWitnessStore() }) }

    /// GOOD: `FileMeshWitnessStore` in a fresh temporary file (it reopens and detects damage).
    public static func fileMeshWitnessStoreAdapter() -> MeshWitnessStoreAdapter {
        final class Paths: @unchecked Sendable { let lock = NSLock(); var byStore: [ObjectIdentifier: String] = [:] }
        let paths = Paths()
        func open(_ path: String) -> FileMeshWitnessStore {
            let s = FileMeshWitnessStore(path: path)
            paths.lock.lock(); paths.byStore[ObjectIdentifier(s)] = path; paths.lock.unlock()
            return s
        }
        func pathOf(_ s: any MeshWitnessStore) throws -> String {
            paths.lock.lock(); defer { paths.lock.unlock() }
            guard let p = paths.byStore[ObjectIdentifier(s as AnyObject)] else { throw JSError("not a store of this adapter") }
            return p
        }
        return MeshWitnessStoreAdapter(name: "FileMeshWitnessStore", make: { open(scTempDir("pca-meshwitness-") + ".json") }, reopen: { open(try pathOf($0)) },
                                       damage: { try Data("not json".utf8).write(to: URL(fileURLWithPath: try pathOf($0))) })
    }
}
