import Foundation

// L4 information-flow taint and the `enforceTaint` gate: a port of `taint.ts` (the TypeScript is authoritative).
//
// The agent's own label is never read: every declared provenance ref is re-classified from facts the SERVER holds (a trusted-input registry it
// populated, or its own committed resource graph); a ref the server cannot vouch for is `agent` (the worst case). Pure and deterministic;
// malformed or absent provenance and any internal error fail CLOSED to taint 1.

/// A label of the taint lattice `trusted < first_party < tool < web < agent`; `id` is explanatory metadata of `tool` / `agent` labels.
public struct TaintLabel: Equatable, Sendable {
    public var kind: String
    public var id: String?
    public init(kind: String, id: String? = nil) {
        self.kind = kind
        self.id = id
    }
    public var json: JSONValue {
        var o: JObject = ["kind": .string(kind)]
        if let i = id { o["id"] = .string(i) }
        return .object(o)
    }
}

/// The server's trusted-input registry: the label the SERVER independently vouches for a content digest (nil: none). A throw is judged as an
/// internal error (fail closed to taint 1).
public protocol TrustedInputRegistry {
    func lookup(_ digest: String) throws -> TaintLabel?
}

/// The registry that vouches for nothing.
public struct EmptyTrustedInputRegistry: TrustedInputRegistry {
    public init() {}
    public func lookup(_ digest: String) throws -> TaintLabel? { nil }
}

/// An in-memory registry. Only the server populates it; nothing an agent sends reaches it.
public final class InMemoryTrustedInputRegistry: TrustedInputRegistry, @unchecked Sendable {
    private var m: [JKey: TaintLabel] = [:]
    let lock = PCALock()
    public init() {}

    /// Server-only: record that `digest` is an input the server independently verified at `label` (an unknown kind or an empty digest is ignored).
    @discardableResult
    public func record(_ digest: String, _ label: TaintLabel) -> Self {
        if !digest.isEmpty && Taint.isLevel(label.kind) {
            lock.lock()
            m[JKey(digest)] = label
            lock.unlock()
        }
        return self
    }
    @discardableResult public func recordTrusted(_ digest: String) -> Self { record(digest, TaintLabel(kind: "trusted")) }
    @discardableResult public func recordFirstParty(_ digest: String) -> Self { record(digest, TaintLabel(kind: "first_party")) }
    @discardableResult public func recordTool(_ digest: String, id: String) -> Self { record(digest, TaintLabel(kind: "tool", id: id)) }
    @discardableResult public func recordWeb(_ digest: String) -> Self { record(digest, TaintLabel(kind: "web")) }

    public func lookup(_ digest: String) -> TaintLabel? {
        lock.lock()
        defer { lock.unlock() }
        return m[JKey(digest)]
    }
    public var size: Int {
        lock.lock()
        defer { lock.unlock() }
        return m.count
    }
}

/// `computeTaint`'s result: `taint` in [0, 1] (exactly 1 when fail-closed), the joined label, the per-ref classification and whether the
/// provenance was usable.
public struct TaintResult: Sendable {
    public var taint: Double
    public var label: TaintLabel
    public var refs: [(ref: String, label: TaintLabel)]
    public var valid: Bool
    public var reason: String?
}

public enum Taint {
    public static let LEVELS = ["trusted", "first_party", "tool", "web", "agent"]
    static let MAX_RANK = 4

    /// True only for the five real level names.
    public static func isLevel(_ kind: String?) -> Bool {
        guard let k = kind else { return false }
        return LEVELS.contains { IV.same($0, k) }
    }

    /// Rank of a label; an unknown kind is the WORST rank (fail closed).
    public static func rank(_ l: TaintLabel?) -> Int {
        guard let k = l?.kind, let i = LEVELS.firstIndex(where: { IV.same($0, k) }) else { return MAX_RANK }
        return i
    }

    /// Normalized taint of a label: trusted 0, first_party 0.25, tool 0.5, web 0.75, agent 1.
    public static func value(_ l: TaintLabel?) -> Double { Double(rank(l)) / Double(MAX_RANK) }

    /// Least upper bound: the higher-ranked label; equal ranks keep the id only when both agree, else the generic representative.
    public static func join(_ a: TaintLabel, _ b: TaintLabel) -> TaintLabel {
        let ra = rank(a), rb = rank(b)
        if ra > rb { return a }
        if rb > ra { return b }
        if IV.same(a.id, b.id) || (a.id == nil && b.id == nil) { return a }
        return TaintLabel(kind: a.kind)
    }

    /// Join over a list; the EMPTY lineage joins to the worst case ("no verifiable trusted input" is not "trusted").
    public static func joinLabels(_ labels: [TaintLabel]) -> TaintLabel {
        guard var acc = labels.first else { return TaintLabel(kind: "agent") }
        for l in labels.dropFirst() { acc = join(acc, l) }
        return acc
    }

    /// Independently classify ONE declared provenance ref (never reading the agent's own label): the registry's label, else `first_party`
    /// for a node of the resource graph, else `agent`. A non-string or empty ref is malformed (`agent`).
    static func classifyRef(_ ref: JSONValue?, _ registry: TrustedInputRegistry, _ node: ((String) throws -> Bool)?) throws -> TaintLabel {
        guard case let .string(r)? = ref, !r.isEmpty else { return TaintLabel(kind: "agent") }
        if let vouched = try registry.lookup(r), isLevel(vouched.kind) { return vouched }
        if let n = node, (try? n(r)) == true { return TaintLabel(kind: "first_party") }
        return IV.u16(r) <= 128 ? TaintLabel(kind: "agent", id: r) : TaintLabel(kind: "agent")
    }

    static func invalid(_ reason: String) -> TaintResult {
        TaintResult(taint: 1, label: TaintLabel(kind: "agent"), refs: [], valid: false, reason: reason)
    }

    /// The taint of a PCActn's provenance: an all-trusted verified lineage is 0, any unverifiable, web or agent ref is high, an empty lineage is
    /// 1. Absent or malformed provenance, a non-array or non-string `trusted_refs` and a missing registry return `{taint: 1, valid: false}`.
    public static func computeTaint(_ provenance: JSONValue?, registry: TrustedInputRegistry?, resourceGraphNode: ((String) throws -> Bool)? = nil) -> TaintResult {
        guard let reg = registry else { return invalid("taint: no trusted-input registry") }
        guard case let .object(prov)? = provenance else { return invalid("taint: provenance is absent or malformed") }
        var refs: [JSONValue] = []
        if let raw = prov["trusted_refs"] {
            guard case let .array(a) = raw else { return invalid("taint: trusted_refs must be an array") }
            if !a.allSatisfy({ if case let .string(s) = $0, !s.isEmpty { return true }; return false }) { return invalid("taint: trusted_refs must be non-empty strings") }
            refs = a
        }
        do {
            var classified: [(ref: String, label: TaintLabel)] = []
            for r in refs { classified.append((r.asString ?? "", try classifyRef(r, reg, resourceGraphNode))) }
            let label = joinLabels(classified.map { $0.label })
            return TaintResult(taint: value(label), label: label, refs: classified, valid: true, reason: nil)
        } catch {
            return invalid("taint: evaluation error (fail closed): \(error)")
        }
    }

    /// The `enforceTaint` gate: `(true, nil)` or `(false, reason)`. `maxTaint` is the largest taint the policy accepts; a negative, non-finite
    /// or missing bound is a misconfiguration and never passes.
    public static func gate(_ provenance: JSONValue?, registry: TrustedInputRegistry?, resourceGraphNode: ((String) throws -> Bool)? = nil, maxTaint: Double?) -> (ok: Bool, reason: String?) {
        let t = computeTaint(provenance, registry: registry, resourceGraphNode: resourceGraphNode)
        if !t.valid { return (false, t.reason ?? "provenance lineage is not server-verifiable (fail closed)") }
        guard let mt = maxTaint, mt.isFinite, mt >= 0 else { return (false, "taint gate misconfigured: maxTaint must be a non-negative number (fail closed)") }
        var allowed = -1
        for r in 0...MAX_RANK where Double(r) / Double(MAX_RANK) <= mt { allowed = r }
        if rank(t.label) <= allowed { return (true, nil) }
        return (false, "information-flow taint \(PD.numStr(t.taint)) exceeds policy max \(PD.numStr(mt))")
    }
}
