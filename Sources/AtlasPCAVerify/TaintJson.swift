import Foundation

/// The taint module over the reference's JSON labels (`{kind, id?}`, and whatever else a caller hands in): the lattice, the registry, `classifyRef`
/// and `computeTaint` with the reference's per-ref classification, so a corpus of odd labels replays exactly. The typed `Taint` is the enforcement
/// path; both rank a label by the same five level names, own-name test only (`constructor`, `__proto__`, `toString` are not levels).
public enum PCATaint {
    public static let TAINT_LEVELS = Taint.LEVELS
    public static let BOTTOM: JSONValue = .object(["kind": .string("trusted")])
    public static let TOP: JSONValue = .object(["kind": .string("agent")])
    private static let MAX_RANK = 4

    public static func isTaintLevel(_ kind: JSONValue?) -> Bool {
        guard case let .string(k)? = kind else { return false }
        return TAINT_LEVELS.contains { IV.same($0, k) }
    }

    /// An unknown, inherited or non-string kind (or a label that is no object) is the WORST rank, never an undefined one.
    public static func labelRank(_ l: JSONValue?) -> Int {
        guard case let .string(k)? = l?.get("kind"), let i = TAINT_LEVELS.firstIndex(where: { IV.same($0, k) }) else { return MAX_RANK }
        return i
    }

    public static func taintValue(_ l: JSONValue?) -> Double { Double(labelRank(l)) / Double(MAX_RANK) }

    /// JavaScript `===` for an id (numbers by value, an absent id equals an absent id).
    private static func sameId(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        if let x = ToolSchema.fin(a), let y = ToolSchema.fin(b) { return x == y }
        if case let .string(x)? = a, case let .string(y)? = b { return Array(x.utf16) == Array(y.utf16) }
        return a == b
    }

    /// Least upper bound: the higher rank wins and keeps its label as is; at equal rank the id is kept only when both agree, else `{kind}` alone.
    /// A null or absent label throws (the own-member test of `id` cannot read it).
    public static func joinLabel(_ a: JSONValue?, _ b: JSONValue?) throws -> JSONValue {
        let ra = labelRank(a), rb = labelRank(b)
        if ra > rb { return a ?? .null }
        if rb > ra { return b ?? .null }
        guard let x = a, x != .null, let y = b, y != .null else { throw JSError("Cannot convert undefined or null to object") }
        if sameId(x.get("id"), y.get("id")) { return x }
        return .object(x.get("kind").map { ["kind": $0] } ?? [:])
    }

    /// Join over a list; the EMPTY lineage is the worst case (no verifiable trusted input is not "trusted").
    public static func joinLabels(_ labels: [JSONValue]) throws -> JSONValue {
        guard var acc = labels.first else { return TOP }
        for l in labels.dropFirst() { acc = try joinLabel(acc, l) }
        return acc
    }

    // ---- registry ----

    /// What the SERVER vouches for: the label of a content digest, or nil. A throw is an internal error of whoever asked.
    public protocol Registry {
        func lookup(_ digest: String) throws -> JSONValue?
    }

    /// Vouches for nothing.
    public struct EmptyRegistry: Registry {
        public init() {}
        public func lookup(_ digest: String) throws -> JSONValue? { nil }
    }

    /// An in-memory registry: only the server fills it. A digest is a non-empty string compared by UTF-16 code units (no normalisation) and a
    /// label is kept (as a shallow copy) only when its kind is a level.
    public final class InMemoryRegistry: Registry, @unchecked Sendable {
        private var m: [[UInt16]: JSONValue] = [:]
        private let lock = NSLock()
        public init() {}

        @discardableResult
        public func record(_ digest: JSONValue?, _ label: JSONValue?) -> Self {
            if case let .string(d)? = digest, !d.isEmpty, case .object? = label, isTaintLevel(label?.get("kind")), let l = label {
                lock.lock(); m[Array(d.utf16)] = l; lock.unlock()
            }
            return self
        }
        @discardableResult public func recordTrusted(_ d: String) -> Self { record(.string(d), BOTTOM) }
        @discardableResult public func recordFirstParty(_ d: String) -> Self { record(.string(d), .object(["kind": .string("first_party")])) }
        @discardableResult public func recordTool(_ d: String, id: String) -> Self { record(.string(d), .object(["kind": .string("tool"), "id": .string(id)])) }
        @discardableResult public func recordWeb(_ d: String) -> Self { record(.string(d), .object(["kind": .string("web")])) }

        public func lookup(_ digest: String) -> JSONValue? { lock.lock(); defer { lock.unlock() }; return m[Array(digest.utf16)] }
        public var size: Int { lock.lock(); defer { lock.unlock() }; return m.count }
    }

    // ---- classification ----

    /// Independently classify ONE declared ref (the agent's own label is never read): the registry's label when it names a level, else
    /// `first_party` for a node of the resource graph (a graph that throws is no node), else `agent` carrying the ref as its id when it has at most
    /// 128 UTF-16 units. A non-string or empty ref is `agent`. A missing registry or one whose lookup throws makes it throw.
    public static func classifyRef(_ ref: JSONValue?, registry: Registry?, node: ((String) throws -> Bool)? = nil) throws -> JSONValue {
        guard case let .string(r)? = ref, !r.isEmpty else { return TOP }
        guard let reg = registry else { throw JSError("Cannot read properties of undefined (reading 'lookup')") }
        if let vouched = try reg.lookup(r), JS.truthy(vouched), isTaintLevel(vouched.get("kind")) { return vouched }
        if let n = node, (try? n(r)) == true { return .object(["kind": .string("first_party")]) }
        return IV.u16(r) <= 128 ? .object(["kind": .string("agent"), "id": .string(r)]) : TOP
    }

    private static func invalid(_ reason: String) -> JSONValue {
        .object(["taint": .int(1), "label": TOP, "refs": .array([]), "valid": .bool(false), "reason": .string(reason)])
    }

    /// A label as the verified core returns it: `{kind}` plus the `id` when there is one.
    private static func normal(_ l: JSONValue) -> JSONValue {
        var o: JObject = ["kind": l.get("kind") ?? .null]
        if let id = l.get("id") { o["id"] = id }
        return .object(o)
    }

    /// The taint of a PCActn's provenance: `{taint, label, refs: [{ref, label}], valid, reason?}`. Never throws: a missing registry, absent or
    /// malformed provenance, a `trusted_refs` that is no array of non-empty strings, or any error is `{taint: 1, valid: false}` with a reason.
    /// The agent's own `taint_level` / `causal_hash` are not read. An empty lineage is taint 1.
    public static func computeTaint(_ provenance: JSONValue?, registry: Registry?, node: ((String) throws -> Bool)? = nil) -> JSONValue {
        guard let reg = registry else { return invalid("taint: no trusted-input registry") }
        guard case let .object(prov)? = provenance else { return invalid("taint: provenance is absent or malformed") }
        var refs: [String] = []
        if let raw = prov["trusted_refs"] {
            guard case let .array(a) = raw else { return invalid("taint: trusted_refs must be an array") }
            for e in a {
                guard case let .string(s) = e, !s.isEmpty else { return invalid("taint: trusted_refs must be non-empty strings") }
                refs.append(s)
            }
        }
        do {
            var classified: [JSONValue] = []
            for r in refs { classified.append(normal(try classifyRef(.string(r), registry: reg, node: node))) }
            let label = normal(try joinLabels(classified))
            let rows = zip(refs, classified).map { JSONValue.object(["ref": .string($0), "label": $1]) }
            return .object(["taint": .double(taintValue(label)), "label": label, "refs": .array(rows), "valid": .bool(true)])
        } catch {
            return invalid("taint: evaluation error (fail closed): \((error as? JSError)?.message ?? "unknown")")
        }
    }
}
