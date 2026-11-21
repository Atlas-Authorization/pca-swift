import Foundation

/// The capability-tagged, positive data-flow model (CaMeL, arXiv:2503.18813): every value carries the provenance it was derived
/// from and the sinks it may reach, and a policy over provenance decides every flow to a sink. The guarantee is conditional on
/// correct tagging at the boundaries (`fromTrustedQuery` / `fromToolOutput`): this is a capability model, not a detector. Pure
/// and deterministic. A `Tagged` is minted only by this type's constructors: an untagged value never flows.
public enum PCADataflow {
    /// The genuine user query, the one source control flow may derive from.
    public static let TRUSTED_QUERY = "trusted-query"
    /// Provenance tag of a named tool / retrieval output (always untrusted).
    public static func toolProvenance(_ name: String) -> String { "tool:" + name }

    static func has(_ xs: [String], _ x: String) -> Bool { IV.contains(xs, x) }

    /// The distinct members in first-seen order (a JS Set; strings compare by code point, not canonical equivalence).
    static func distinct(_ xs: [String]) -> [String] {
        var seen = Set<JKey>()
        return xs.filter { seen.insert(JKey($0)).inserted }
    }

    /// `[...xs].sort()`: UTF-16 code unit order.
    static func jsSorted(_ xs: [String]) -> [String] { xs.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) } }

    static func strs(_ xs: [String]) -> JSONValue { .array(xs.map { .string($0) }) }

    // ---- capability + tagged value ----

    /// A value's data-flow label: its lineage (ordered, distinct sources), whether every source is trusted, and an optional
    /// allow-list of sink ids (nil = unrestricted by the value; an empty list restricts it to no sink).
    public struct Capability {
        public let sources: [String]
        public let isTrusted: Bool
        public let readers: [String]?

        public init(sources: [String], isTrusted: Bool, readers: [String]? = nil) {
            self.sources = PCADataflow.distinct(sources)
            self.isTrusted = isTrusted
            self.readers = readers.map(PCADataflow.distinct)
        }

        /// {sources, isTrusted, readers?} with both sets in insertion order.
        public var json: JSONValue {
            var o: JObject = ["sources": PCADataflow.strs(sources), "isTrusted": .bool(isTrusted)]
            if let r = readers { o["readers"] = PCADataflow.strs(r) }
            return .object(o)
        }
    }

    /// A value carrying its capability. Only this type mints one (`untagged` makes the look-alike that never flows).
    public final class Tagged {
        public let value: JSONValue
        public let cap: Capability
        /// True only for a value made by `tag`, `fromTrustedQuery`, `fromToolOutput`, `fromSource` or `derive`.
        public let isTagged: Bool

        fileprivate init(_ value: JSONValue, _ cap: Capability, minted: Bool) {
            self.value = value; self.cap = cap; self.isTagged = minted
        }

        /// A value with no provenance tag made by this module: classifyFlow denies it, derive / dualContext refuse it.
        public static func untagged(_ value: JSONValue) -> Tagged { Tagged(value, Capability(sources: [], isTrusted: false), minted: false) }

        public var json: JSONValue { .object(["value": value, "cap": cap.json]) }
    }

    /// Tag a value with an explicit capability (escape hatch; prefer the boundary constructors). A trusted capability needs at
    /// least one source and no `tool:` source.
    public static func tag(_ value: JSONValue, _ cap: Capability) throws -> Tagged {
        if cap.isTrusted {
            if cap.sources.isEmpty { throw JSError("tag: a trusted capability needs at least one source") }
            if cap.sources.contains(where: { IV.startsWith($0, "tool:") }) { throw JSError("tag: tool output can never be trusted") }
        }
        return Tagged(value, Capability(sources: cap.sources, isTrusted: cap.isTrusted, readers: cap.readers), minted: true)
    }

    /// Tag the genuine user query (a boundary assertion: the caller vouches that the value is the user's own instruction).
    public static func fromTrustedQuery(_ value: JSONValue, readers: [String]? = nil) -> Tagged {
        Tagged(value, Capability(sources: [TRUSTED_QUERY], isTrusted: true, readers: readers), minted: true)
    }

    /// Tag the output of a named tool / retrieval: always untrusted.
    public static func fromToolOutput(_ name: String, _ value: JSONValue, readers: [String]? = nil) -> Tagged {
        Tagged(value, Capability(sources: [toolProvenance(name)], isTrusted: false, readers: readers), minted: true)
    }

    /// Tag a value from a named source: untrusted unless `isTrusted` (a `tool:` source can never be trusted).
    public static func fromSource(_ source: String, _ value: JSONValue, isTrusted: Bool = false, readers: [String]? = nil) throws -> Tagged {
        try tag(value, Capability(sources: [source], isTrusted: isTrusted, readers: readers))
    }

    // ---- capability algebra ----

    /// Union of the provenance sources of several capabilities, in first-seen order.
    public static func unionSources(_ caps: [Capability]) -> [String] { distinct(caps.flatMap { $0.sources }) }

    /// sources = union, isTrusted = AND over a non-empty list (an empty list is untrusted), readers = intersection of the inputs
    /// that restrict them (an unrestricted input drops out of the meet).
    public static func combineCaps(_ caps: [Capability]) -> Capability {
        var trusted = !caps.isEmpty
        var readers: [String]?
        for c in caps {
            trusted = trusted && c.isTrusted
            guard let r = c.readers else { continue }
            if let cur = readers { readers = cur.filter { has(r, $0) } } else { readers = r }
        }
        return Capability(sources: unionSources(caps), isTrusted: trusted, readers: readers)
    }

    /// A new tagged value from tagged ones; its capability is `combineCaps` over theirs, so trust can only be lost.
    public static func derive(_ inputs: [Tagged], _ combine: ([JSONValue]) throws -> JSONValue) throws -> Tagged {
        guard inputs.allSatisfy({ $0.isTagged }) else { throw JSError("derive: every input must be a tagged value made by this module") }
        let v = try combine(inputs.map { $0.value })
        return Tagged(v, combineCaps(inputs.map { $0.cap }), minted: true)
    }

    // ---- sinks + the policy interpreter ----

    /// What a sink accepts. A nil source list is absent; an empty `allowedSources` admits no source.
    public struct FlowPolicy {
        public var external = false
        public var requireTrusted = false
        public var allowedSources: [String]?
        public var deniedSources: [String]?
        public init(external: Bool = false, requireTrusted: Bool = false, allowedSources: [String]? = nil, deniedSources: [String]? = nil) {
            self.external = external; self.requireTrusted = requireTrusted; self.allowedSources = allowedSources; self.deniedSources = deniedSources
        }
    }

    /// Where a value leaves the trusted interior. A nil `accepts` is not a valid sink.
    public struct Sink {
        public let id: String
        public let accepts: FlowPolicy?
        public init(id: String, accepts: FlowPolicy?) { self.id = id; self.accepts = accepts }

        public var json: JSONValue {
            var o: JObject = ["id": .string(id)]
            if let a = accepts {
                var p: JObject = [:]
                if a.external { p["external"] = .bool(true) }
                if a.requireTrusted { p["requireTrusted"] = .bool(true) }
                if let s = a.allowedSources { p["allowedSources"] = PCADataflow.strs(s) }
                if let s = a.deniedSources { p["deniedSources"] = PCADataflow.strs(s) }
                o["accepts"] = .object(p)
            } else { o["accepts"] = .null }
            return .object(o)
        }
    }

    /// One value-to-sink decision (allow / step_up / deny) with the responsible provenance path.
    public struct FlowDecision {
        public let outcome: String
        public let reason: String?
        /// nil on allow; otherwise the offending sources (possibly empty).
        public let path: [String]?

        public var json: JSONValue {
            var o: JObject = ["outcome": .string(outcome)]
            if let r = reason { o["reason"] = .string(r) }
            if let p = path { o["path"] = PCADataflow.strs(p) }
            return .object(o)
        }
    }

    /// Decide one flow from the capability and the sink policy alone: the value's readers, denied sources, allowed sources,
    /// an external (exfiltrating) sink (deny), a sensitive sink (step_up). An untagged value or an invalid sink is a deny.
    public static func classifyFlow(_ value: Tagged?, _ sink: Sink?) -> FlowDecision {
        guard let value = value, value.isTagged else {
            return FlowDecision(outcome: "deny", reason: "value carries no provenance tag made by this module (fail closed)", path: [])
        }
        let cap = value.cap
        let srcs = jsSorted(cap.sources)
        guard let sink = sink, !sink.id.isEmpty, let p = sink.accepts else {
            return FlowDecision(outcome: "deny", reason: "the sink is not a valid sink (fail closed)", path: srcs)
        }
        if let rd = cap.readers, !has(rd, sink.id) {
            let rs = jsSorted(rd).joined(separator: ", ")
            return FlowDecision(outcome: "deny", reason: "value's readers capability [\(rs.isEmpty ? "\u{2205}" : rs)] does not include sink '\(sink.id)'", path: srcs)
        }
        if let denied = p.deniedSources {
            let bad = srcs.filter { has(denied, $0) }
            if !bad.isEmpty { return FlowDecision(outcome: "deny", reason: "provenance [\(bad.joined(separator: ", "))] is forbidden at sink '\(sink.id)'", path: bad) }
        }
        if let allowed = p.allowedSources {
            let bad = srcs.filter { !has(allowed, $0) }
            if !bad.isEmpty { return FlowDecision(outcome: "deny", reason: "provenance [\(bad.joined(separator: ", "))] is not in the allow-list of sink '\(sink.id)'", path: bad) }
        }
        let list = srcs.joined(separator: ", ")
        if p.external && !cap.isTrusted {
            return FlowDecision(outcome: "deny", reason: "untrusted value (provenance [\(list)]) may not flow to external-send sink '\(sink.id)' \u{2014} exfiltration / prompt-injection path", path: srcs)
        }
        if p.requireTrusted && !cap.isTrusted {
            return FlowDecision(outcome: "step_up", reason: "sink '\(sink.id)' requires trusted provenance; value provenance [\(list)] is untrusted \u{2014} needs human review", path: srcs)
        }
        return FlowDecision(outcome: "allow", reason: nil, path: nil)
    }

    /// `classifyFlow` as a boolean: ok only for a clean allow (a step_up is not ok without a human).
    public static func canFlow(_ value: Tagged?, _ sink: Sink?) -> (ok: Bool, reason: String?) {
        let d = classifyFlow(value, sink)
        return (d.outcome == "allow", d.reason)
    }

    // ---- action gate ----

    /// The verb + resource of a PCActn action.
    public struct PcaStyleAction {
        public let verb: String
        public let resource: String
        public init(verb: String, resource: String) { self.verb = verb; self.resource = resource }
    }

    /// One slot of an action's tagged argument list.
    public enum ArgSlot {
        case tagged(Tagged)
        /// An argument slot holding `undefined` (an optional argument that was not supplied): skipped.
        case undefined
        /// A hole in the list: an argument nobody tagged (a refusal).
        case hole
    }

    /// The worst flow decision over an action's arguments.
    public struct ActionDecision {
        public let outcome: String
        public let sink: String
        public let reason: String?
        public let arg: Int?
        public let path: [String]?

        public var json: JSONValue {
            var o: JObject = ["outcome": .string(outcome), "sink": .string(sink)]
            if let r = reason { o["reason"] = .string(r) }
            if let a = arg { o["arg"] = .int(Int64(a)) }
            if let p = path { o["path"] = PCADataflow.strs(p) }
            return .object(o)
        }
    }

    static let SEVERITY = ["allow": 0, "step_up": 1, "deny": 2]

    /// Gate an action by data flow: every argument is classified against the sink the action dispatches to and the worst
    /// outcome wins (deny, then step_up, then allow). `sinkFor` resolves the sink (a throw or an invalid sink denies).
    /// `expectedArgs`, when given, must equal the argument count.
    public static func checkAction(_ action: PcaStyleAction, _ args: [ArgSlot], sinkFor: (PcaStyleAction) throws -> Sink?, expectedArgs: Double? = nil) -> ActionDecision {
        let sink: Sink?
        do { sink = try sinkFor(action) } catch {
            return ActionDecision(outcome: "deny", sink: "(unresolved)", reason: "the sink for this action could not be resolved (fail closed)", arg: nil, path: nil)
        }
        guard let sink = sink, !sink.id.isEmpty else {
            return ActionDecision(outcome: "deny", sink: "(unresolved)", reason: "the sink for this action is not a valid sink (fail closed)", arg: nil, path: nil)
        }
        if let e = expectedArgs, Double(args.count) != e {
            return ActionDecision(outcome: "deny", sink: sink.id, reason: "expected \(JS.number(e)) tagged argument(s), got \(args.count) (fail closed)", arg: nil, path: nil)
        }
        var worst = ActionDecision(outcome: "allow", sink: sink.id, reason: nil, arg: nil, path: nil)
        for (i, slot) in args.enumerated() {
            switch slot {
            case .undefined: continue
            case .hole:
                return ActionDecision(outcome: "deny", sink: sink.id, reason: "an argument was not tagged (fail closed)", arg: i, path: nil)
            case let .tagged(t):
                let d = classifyFlow(t, sink)
                if SEVERITY[d.outcome]! > SEVERITY[worst.outcome]! {
                    worst = ActionDecision(outcome: d.outcome, sink: sink.id, reason: d.reason, arg: i, path: d.path)
                }
            }
        }
        return worst
    }

    // ---- dual-context (privileged planner / quarantined handler) ----

    /// Run the dual-LLM separation: the planner sees only the TRUSTED query value, the quarantined handler returns a tagged
    /// result. Refuses an untagged or untrusted query and a handler result that is not tagged.
    public static func dualContext(query: Tagged?, plan: (JSONValue) throws -> JSONValue, quarantine: (JSONValue) throws -> Tagged) throws -> (plan: JSONValue, result: Tagged) {
        guard let q = query, q.isTagged else { throw JSError("dualContext: the query must be a tagged value made by this module") }
        if !q.cap.isTrusted {
            throw JSError("dualContext: the privileged planner may only run on a TRUSTED query; got provenance [\(jsSorted(q.cap.sources).joined(separator: ", "))]")
        }
        let p = try plan(q.value)
        let r = try quarantine(p)
        guard r.isTagged else { throw JSError("dualContext: the quarantined handler must return a tagged value made by this module") }
        return (p, r)
    }

    // ---- presets ----

    /// An exfiltrating sink (email, HTTP POST, webhook): untrusted values hard-deny.
    public static func externalSendSink(_ id: String) -> Sink { Sink(id: id, accepts: FlowPolicy(external: true)) }
    /// A sensitive internal sink (write, privileged action): untrusted values step up for human review.
    public static func sensitiveSink(_ id: String) -> Sink { Sink(id: id, accepts: FlowPolicy(requireTrusted: true)) }

    /// A tagged value's label in the lattice the default authorize() gate uses: trusted only when the capability is trusted,
    /// tool when every source is a tool: output, otherwise agent. An untagged value is agent (fail closed).
    public static func levelOf(_ v: Tagged?) -> String {
        guard let v = v, v.isTagged else { return "agent" }
        if v.cap.isTrusted { return "trusted" }
        let s = v.cap.sources
        return !s.isEmpty && s.allSatisfy({ IV.startsWith($0, "tool:") }) ? "tool" : "agent"
    }
}
