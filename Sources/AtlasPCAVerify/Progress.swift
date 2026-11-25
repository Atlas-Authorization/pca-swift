import Foundation

/// Proof of progress toward a committed goal (the reference's `progress`): a goal (objective, potential id, embedder, metric, epsilon, exploration budget)
/// is hashed into a commitment; each step is a hash-chained body binding goal, action digest, before and after state digests, seq and prev, and the
/// verifier recomputes the integer potential and the mode (progress, or exploration charged to the budget). This file holds the potentials, the potential
/// registry, the goal commitment and the digests; goals, states and steps are the reference's objects as JSON trees. Every digest is the STRICT canonical
/// hash (the wire form): a state with a non-integer of more than 15 significant digits, a `-0` or a lone surrogate has no digest.
public enum PCAProgress {
    public static let PROGRESS_VERSION = 2
    public static let PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2"
    public static let TRAJECTORY_ANCHOR_DOMAIN = "atlas-pca/trajectory-anchor/v1"
    public static let STATE_ATTESTATION_DOMAIN = "atlas-pca/progress-state-attestation/v1\u{0}"
    static let GENESIS = "genesis"

    /// A potential: a pure function of the goal's objective and a state to a non-negative safe integer (anything else is a bad potential).
    public typealias PotentialFn = (_ objective: JSONValue?, _ state: JSONValue?) throws -> JSONValue?

    static func err(_ m: String) -> JSError { JSError(m) }
    static func isObj(_ v: JSONValue?) -> Bool { v?.isObject == true }
    static func str(_ v: JSONValue?) -> String? { v?.asString }
    static func safeInt(_ v: JSONValue?) -> Int64? { v?.safeInt }
    private static func assertInt(_ v: JSONValue?, _ what: String) throws -> Int64 {
        guard let i = v?.safeInt else { throw err("\(what): safe integer required") }
        return i
    }
    private static func u16(_ s: String) -> [UInt16] { Array(s.utf16) }

    /// The strict canonical hash of a value; a member the reference lacks (`undefined`) is refused.
    static func hashStrict(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }

    /// A detached copy of a value through the lenient canonical form (what the reference calls `snapshot`).
    static func snapshot(_ v: JSONValue?) throws -> JSONValue {
        guard let v = v else { throw err("canonicalize: unsupported type undefined") }
        let s = Canonical.canonicalize(v)
        if s.isEmpty { throw err("canonicalize: non-finite number") }
        return try StrictJSON.parseLenient(s)
    }

    // ---- potentials ----

    private static func num(_ i: Int64) -> JSONValue { .int(i) }

    /// `sum |target_i - x_i|` over equal-length integer arrays, the running sum checked for overflow at every element.
    public static func l1FeaturePotential(_ objective: JSONValue?, _ state: JSONValue?) throws -> JSONValue? {
        guard case let .array(t)? = objective?.get("target"), case let .array(x)? = state?.get("x"), t.count == x.count else { throw err("l1-feature-v1: bad shape") }
        var d = 0.0
        for i in 0..<t.count {
            let a = try assertInt(t[i], "target"), b = try assertInt(x[i], "x")
            d += abs(Double(a) - Double(b))
            _ = try assertInt(.double(d), "distance")
        }
        return num(Int64(d))
    }

    /// A key with the identity JavaScript's `Set` gives a value: strings by code unit, numbers by value, any object or array by reference (never equal).
    private enum Ident: Hashable { case s([UInt16]), n(Double), b(Bool), null, undef }
    private static func ident(_ v: JSONValue?) -> Ident? {
        switch v {
        case nil: return .undef
        case .null?: return .null
        case let .bool(b)?: return .b(b)
        case let .string(s)?: return .s(u16(s))
        case let .int(i)?: return .n(Double(i))
        case let .double(d)?: return .n(d.isNaN ? .nan : (d == 0 ? 0 : d))
        default: return nil
        }
    }

    /// The summed cost of the tasks not done; task ids unique, every done id a task.
    public static func dagRemainingPotential(_ objective: JSONValue?, _ state: JSONValue?) throws -> JSONValue? {
        guard case let .array(tasks)? = objective?.get("tasks"), case let .array(done)? = state?.get("done") else { throw err("dag-remaining-v1: bad shape") }
        var ids = Set<Ident>()
        var objectIds = 0
        for t in tasks {
            if t == .null { throw err("Cannot read properties of null (reading 'id')") }
            if let k = ident(t.get("id")) { ids.insert(k) } else { objectIds += 1 }
        }
        if ids.count + objectIds != tasks.count { throw err("dag-remaining-v1: duplicate task id") }
        var doneSet = Set<Ident>()
        var doneObjects = 0
        for d in done { if let k = ident(d) { doneSet.insert(k) } else { doneObjects += 1 } }
        if doneObjects > 0 { throw err("dag-remaining-v1: unknown task") }
        for d in doneSet where !ids.contains(d) { throw err("dag-remaining-v1: unknown task") }
        var rem = 0.0
        for t in tasks {
            let cost = try assertInt(t.get("cost"), "cost")
            if cost < 0 { throw err("negative cost") }
            if let k = ident(t.get("id")), doneSet.contains(k) {} else { rem += Double(cost) }
            _ = try assertInt(.double(rem), "remaining")
        }
        return num(Int64(rem))
    }

    /// Like `dag-remaining` with dependencies: tasks are objects with unique non-empty string ids, `deps` (absent or null is none), no self, unknown or
    /// cyclic dependency, and the done set unique and closed under dependencies.
    public static func dagWeightedPotential(_ objective: JSONValue?, _ state: JSONValue?) throws -> JSONValue? {
        guard case let .array(tasks)? = objective?.get("tasks"), case let .array(done)? = state?.get("done") else { throw err("dag-weighted-v1: bad shape") }
        var order: [[UInt16]] = []
        var byId: [[UInt16]: (cost: Int64, deps: [[UInt16]])] = [:]
        for t in tasks {
            guard t.isObject, let id = str(t.get("id")), !id.isEmpty else { throw err("dag-weighted-v1: bad task") }
            if byId[u16(id)] != nil { throw err("dag-weighted-v1: duplicate task id") }
            let cost = try assertInt(t.get("cost"), "cost")
            if cost < 0 { throw err("negative cost") }
            var deps: [[UInt16]] = []
            if let dv = JS.present(t.get("deps")) {
                guard case let .array(da) = dv, da.allSatisfy({ $0.asString != nil }) else { throw err("dag-weighted-v1: bad deps") }
                deps = da.map { u16($0.asString!) }
            }
            order.append(u16(id))
            byId[u16(id)] = (cost, deps)
        }
        var indeg: [[UInt16]: Int] = [:]
        var rev: [[UInt16]: [[UInt16]]] = [:]
        for id in order {
            let uniq = Set(byId[id]!.deps)
            indeg[id] = uniq.count
            for d in uniq {
                if d == id || byId[d] == nil { throw err("dag-weighted-v1: bad dependency") }
                rev[d, default: []].append(id)
            }
        }
        var q = order.filter { indeg[$0] == 0 }
        var seen = 0
        while let id = q.popLast() {
            seen += 1
            for nx in rev[id] ?? [] {
                let k = indeg[nx]! - 1
                indeg[nx] = k
                if k == 0 { q.append(nx) }
            }
        }
        if seen != byId.count { throw err("dag-weighted-v1: cycle") }
        var doneSet = Set<[UInt16]>()
        for d in done {
            guard let s = str(d), byId[u16(s)] != nil else { throw err("dag-weighted-v1: unknown task") }
            if !doneSet.insert(u16(s)).inserted { throw err("dag-weighted-v1: duplicate done") }
        }
        for d in doneSet { for dep in byId[d]!.deps where !doneSet.contains(dep) { throw err("dag-weighted-v1: done before dependency") } }
        var rem = 0.0
        for id in order {
            if !doneSet.contains(id) { rem += Double(byId[id]!.cost) }
            _ = try assertInt(.double(rem), "remaining")
        }
        return num(Int64(rem))
    }

    // ---- the potential registry ----

    public struct PotentialSpec {
        public var fn: PotentialFn
        public var embedder: String
        public init(fn: @escaping PotentialFn, embedder: String = "") { self.fn = fn; self.embedder = embedder }
    }

    /// The potentials a verifier knows by id. A goal names one; its embedder must equal the goal's (an absent embedder and `""` are the same).
    public final class PotentialRegistry {
        private var m: [[UInt16]: (id: String, spec: PotentialSpec)] = [:]
        private var frozen = false
        public init() {}

        @discardableResult
        public func register(_ id: JSONValue?, _ fn: @escaping PotentialFn, embedder: JSONValue? = nil) throws -> Self {
            if frozen { throw JSError("registry is frozen") }
            guard case let .string(s)? = id, !s.isEmpty, s.utf16.count <= 128 else { throw JSError("potential id: 1..128 chars") }
            var emb = ""
            if let e = embedder { guard case let .string(x) = e else { throw JSError("embedder must be a string") }; emb = x }
            if m[Array(s.utf16)] != nil { throw JSError("potential \(s) already registered") }
            m[Array(s.utf16)] = (s, PotentialSpec(fn: fn, embedder: emb))
            return self
        }
        public func get(_ id: String) -> PotentialSpec? { m[Array(id.utf16)]?.spec }
        public func has(_ id: String) -> Bool { m[Array(id.utf16)] != nil }
        /// The ids, sorted by UTF-16 code unit.
        public func ids() -> [String] { m.values.map { $0.id }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) } }
        @discardableResult public func freeze() -> Self { frozen = true; return self }
        /// A registry of the three built-in potentials.
        public static func defaults() -> PotentialRegistry {
            let r = PotentialRegistry()
            _ = try? r.register(.string("l1-feature-v1"), PCAProgress.l1FeaturePotential)
            _ = try? r.register(.string("dag-remaining-v1"), PCAProgress.dagRemainingPotential)
            _ = try? r.register(.string("dag-weighted-v1"), PCAProgress.dagWeightedPotential)
            return r
        }
    }

    /// The frozen default registry.
    public static let DEFAULT_POTENTIALS: PotentialRegistry = PotentialRegistry.defaults().freeze()

    // ---- goal commitment ----

    private static func validateGoal(_ goal: JSONValue?) throws {
        guard isObj(goal), let g = goal else { throw err("goal must be an object") }
        let eps = try assertInt(g.get("epsilon"), "epsilon")
        let budget = try assertInt(g.get("explorationBudget"), "explorationBudget")
        if eps < 1 { throw err("epsilon must be >= 1") }
        if budget < 0 { throw err("explorationBudget must be >= 0") }
        guard let p = str(g.get("potential")), !p.isEmpty else { throw err("potential id required") }
        _ = p
        guard str(g.get("metric")) != nil else { throw err("metric must be a string") }
        if let e = g.get("embedder"), e.asString == nil { throw err("embedder must be a string") }
    }

    /// The hash that commits a goal: `{t: "pca-goal", v: 2, objective, potential, embedder, metric, epsilon, explorationBudget}`.
    public static func goalDigest(_ goal: JSONValue?) throws -> String {
        try validateGoal(goal)
        let g = goal!
        guard let objective = g.get("objective") else { throw err("canonicalize: unsupported type undefined") }
        return try hashStrict(.object(["t": .string("pca-goal"), "v": .int(Int64(PROGRESS_VERSION)), "objective": objective, "potential": g.get("potential")!,
                                       "embedder": g.get("embedder") ?? .string(""), "metric": g.get("metric")!, "epsilon": g.get("epsilon")!,
                                       "explorationBudget": g.get("explorationBudget")!]))
    }

    /// `{goal, commitment}`: a canonical snapshot of the goal and its commitment.
    public static func commitGoal(_ goal: JSONValue?) throws -> JSONValue {
        let c = try goalDigest(goal)
        return .object(["goal": try snapshot(goal), "commitment": .string(c)])
    }

    /// True iff the goal hashes to the commitment (never throws).
    public static func verifyGoalCommitment(_ goal: JSONValue?, _ commitment: JSONValue?) -> Bool {
        guard let d = try? goalDigest(goal), case let .string(c)? = commitment else { return false }
        return d.utf16.elementsEqual(c.utf16)
    }

    // ---- digests ----

    /// The digest of a state: `{t: "pca-state", state}`.
    public static func stateDigest(_ state: JSONValue?) throws -> String {
        guard let s = state else { throw err("canonicalize: unsupported type undefined") }
        return try hashStrict(.object(["t": .string("pca-state"), "state": s]))
    }

    /// The digest of the last step, or `genesis` for an empty trajectory.
    public static func trajectoryHead(_ steps: JSONValue?) throws -> JSONValue {
        guard case let .array(a)? = steps else { throw err("Cannot read properties of undefined (reading 'length')") }
        guard let last = a.last else { return .string(GENESIS) }
        guard last.isObject || last.isArray else { throw err("Cannot read properties of null (reading 'digest')") }
        return last.get("digest") ?? .null
    }

    /// A step carries its own digest.
    public static func progressStepDigest(_ step: JSONValue?) throws -> JSONValue {
        guard let s = step, s != .null else { throw err("Cannot read properties of null (reading 'digest')") }
        return s.get("digest") ?? .null
    }

    /// What anchors a trajectory head in the transparency ledger without revealing it: `{t, salt, head}` hashed; both strings must be non-empty.
    public static func trajectoryAnchorCommit(_ salt: JSONValue?, _ head: JSONValue?) throws -> String {
        guard case let .string(s)? = salt, !s.isEmpty, case let .string(h)? = head, !h.isEmpty else { throw err("trajectoryAnchorCommit: salt and head must be non-empty strings") }
        return try hashStrict(.object(["t": .string(TRAJECTORY_ANCHOR_DOMAIN), "salt": .string(s), "head": .string(h)]))
    }

    public static func verifyTrajectoryAnchor(_ commit: JSONValue?, _ salt: JSONValue?, _ head: JSONValue?) -> Bool {
        guard let c = try? trajectoryAnchorCommit(salt, head), case let .string(x)? = commit else { return false }
        return c.utf16.elementsEqual(x.utf16)
    }
}
