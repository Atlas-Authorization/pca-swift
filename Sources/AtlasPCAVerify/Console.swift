import Foundation

// The agent console (a per-agent view of activity with a threat read), the local freeze set, multi-agent sessions, and the JSON forms of
// the immune read side they use. A read model: nothing here authorizes an action.

extension PCAImmune {
    /// Why a JSON immune state `{baseline: {n, mean, m2}, ewma, stepUps, denies, lastAt, seeded}` is malformed, nil when it is well formed.
    public static func validateImmuneState(_ s: JSONValue?) -> String? {
        func members(_ v: JSONValue?) -> JObject? { if case let .object(o)? = v { return o }; if case .array? = v { return [:] }; return nil }
        func inRange(_ v: JSONValue?, _ lo: Double, _ hi: Double) -> Bool { if let x = IV.num(v), x.isFinite, x >= lo, x <= hi { return true }; return false }
        guard let x = members(s) else { return "state must be an object" }
        guard let b = members(x["baseline"]) else { return "baseline missing" }
        if !inRange(b["n"], 0, MAX_COUNT) || !PD.isInteger(b["n"]) || PD.negZero(b["n"]) { return "baseline.n must be an integer in [0, 1e9]" }
        if !inRange(b["mean"], 0, 1) { return "baseline.mean must be in [0, 1]" }
        if !inRange(b["m2"], 0, MAX_COUNT) { return "baseline.m2 must be finite and >= 0" }
        if !inRange(x["ewma"], 0, 1) { return "ewma must be in [0, 1]" }
        if !inRange(x["stepUps"], 0, MAX_COUNT) { return "stepUps must be finite and >= 0" }
        if !inRange(x["denies"], 0, MAX_COUNT) { return "denies must be finite and >= 0" }
        if !inRange(x["lastAt"], 0, Double(Canonical.MAX_SAFE)) { return "lastAt must be a finite non-negative time" }
        guard case .bool? = x["seeded"] else { return "seeded must be a boolean" }
        return nil
    }

    /// A baseline from its JSON form (a member that is not a number reads as NaN).
    public static func baseline(json v: JSONValue?) -> Baseline {
        var b = Baseline()
        b.n = IV.num(v?.get("n")) ?? Double.nan
        b.mean = IV.num(v?.get("mean")) ?? Double.nan
        b.m2 = IV.num(v?.get("m2")) ?? Double.nan
        return b
    }

    /// A state from its JSON form, read member by member (not validated: `validateImmuneState` does that).
    public static func state(json v: JSONValue?) -> State {
        var s = State()
        s.baseline = baseline(json: v?.get("baseline"))
        s.ewma = IV.num(v?.get("ewma")) ?? Double.nan
        s.stepUps = IV.num(v?.get("stepUps")) ?? Double.nan
        s.denies = IV.num(v?.get("denies")) ?? Double.nan
        s.lastAt = IV.num(v?.get("lastAt")) ?? Double.nan
        s.seeded = JS.truthy(v?.get("seeded"))
        return s
    }

    public static func json(_ b: Baseline) -> JSONValue {
        var o: JObject = [:]
        o[o: "n"] = PD.num(b.n)
        o[o: "mean"] = PD.num(b.mean)
        o[o: "m2"] = PD.num(b.m2)
        return .object(o)
    }

    public static func json(_ s: State) -> JSONValue {
        var o: JObject = [:]
        o[o: "baseline"] = json(s.baseline)
        o[o: "ewma"] = PD.num(s.ewma)
        o[o: "stepUps"] = PD.num(s.stepUps)
        o[o: "denies"] = PD.num(s.denies)
        o[o: "lastAt"] = PD.num(s.lastAt)
        o[o: "seeded"] = .bool(s.seeded)
        return .object(o)
    }

    /// `{level, score, signals, components: {drift, volatility, violation}}`.
    public static func json(_ a: Assessment) -> JSONValue {
        var c: JObject = [:]
        c[o: "drift"] = PD.num(a.drift)
        c[o: "volatility"] = PD.num(a.volatility)
        c[o: "violation"] = PD.num(a.violation)
        var o: JObject = [:]
        o[o: "level"] = .string(a.level)
        o[o: "score"] = PD.num(a.score)
        o[o: "signals"] = .array(a.signals.map { .string($0) })
        o[o: "components"] = .object(c)
        return .object(o)
    }

    /// The threat assessment of a JSON state: a malformed one is `high` with the reason (fail closed).
    public static func assess(json s: JSONValue?, _ cfg: Config = .default) -> Assessment {
        if let bad = validateImmuneState(s) { return Assessment(level: "high", score: 1, signals: ["invalid immune state: \(bad)"], drift: 1, volatility: 1, violation: 1) }
        return assess(state(json: s), cfg)
    }
}

extension PCADlp {
    /// A starter policy: a `pii` class (auto at taint 0, hard deny above 2) and a `secrets` class (auto at taint 0, hard deny above 0) for the
    /// resource matchers given. A matcher that is absent or empty adds no class.
    public static func defaultDlpPolicy(piiResource: JSONValue? = nil, secretsResource: JSONValue? = nil) -> JSONValue {
        func cls(_ name: String, _ resource: JSONValue, _ hard: Int64) -> JSONValue {
            var o: JObject = [:]
            o[o: "name"] = .string(name)
            o[o: "resource"] = resource
            o[o: "maxTaintForAuto"] = .int(0)
            o[o: "hardDenyAbove"] = .int(hard)
            return .object(o)
        }
        var classes: [JSONValue] = []
        if let r = piiResource, JS.truthy(r) { classes.append(cls("pii", r, 2)) }
        if let r = secretsResource, JS.truthy(r) { classes.append(cls("secrets", r, 0)) }
        return .object(["classes": .array(classes)])
    }
}

/// The agent console: activity events `{at, agent, verb, resource, outcome, r?, taint?, digest?, goalCommit?}` (outcome `auto`, `step_up`,
/// `deny` or `executed`) projected into a per-agent view, and the local kill-switch set `{frozen: [agent, ...]}`.
public enum Console {
    public static let EMPTY_FREEZE: JSONValue = .object(["frozen": .array([])])

    /// The activity event of a proof-carrying action: the leaf holder as the agent (`unknown` without one), `at` (default: the action's
    /// `iat`), the claimed risk and taint, and the action digest. Throws when the action has no `cap_chain` list or no `action`, and when
    /// it cannot be digested.
    public static func eventFromPCActn(_ p: JSONValue, outcome: String, at: Double? = nil) throws -> JSONValue {
        guard case let .array(chain)? = p.get("cap_chain") else { throw JSError("eventFromPCActn: the action has no cap_chain") }
        guard let action = JS.present(p.get("action")) else { throw JSError("eventFromPCActn: the action has no action") }
        guard let digest = IV.strictHash(p) else { throw JSError(IV.strictCanonError(p) ?? "canonicalize: value out of profile") }
        var e: JObject = [:]
        e[o: "at"] = at.map { PD.num($0) } ?? p.get("iat")
        e[o: "agent"] = JS.present(chain.last?.get("holder")) ?? .string("unknown")
        e[o: "verb"] = action.get("verb")
        e[o: "resource"] = action.get("resource")
        e[o: "outcome"] = .string(outcome)
        e[o: "r"] = p.get("risk_claim")?.get("r")
        e[o: "taint"] = p.get("provenance")?.get("taint_level")
        e[o: "digest"] = .string(digest)
        return .object(e)
    }

    /// Projects events into `{agents: [{agent, actions, autos, stepUps, denies, executed, totalRisk, firstSeen, lastSeen, threat}], totals,
    /// window: {from, to}, dropped}`. An event without a finite `at` or a non-empty text `agent` is dropped and counted. Agents are ordered
    /// by threat score, then by the most recent activity.
    public static func buildConsole(_ all: [JSONValue]) -> JSONValue {
        var order: [JKey] = []
        var byAgent: [JKey: [(e: JSONValue, at: Double, i: Int)]] = [:]
        var ats: [Double] = []
        for (i, e) in all.enumerated() {
            guard e.isObject, let at = IV.num(e.get("at")), at.isFinite, let agent = e.get("agent")?.asString, !agent.isEmpty else { continue }
            let k = JKey(agent)
            if byAgent[k] == nil { order.append(k) }
            byAgent[k, default: []].append((e, at, i))
            ats.append(at)
        }
        var agents: [(row: JObject, score: Double, last: Double, i: Int)] = []
        var totals = [0, 0, 0, 0, 0]
        for (n, k) in order.enumerated() {
            let sorted = (byAgent[k] ?? []).sorted { ($0.at, $0.i) < ($1.at, $1.i) }
            var immune = PCAImmune.INITIAL_STATE
            var autos = 0, stepUps = 0, denies = 0, executed = 0, total = 0.0
            for (e, at, _) in sorted {
                // a risk that is not a number counts as NaN (the reference adds whatever it was given)
                let r = JS.present(e.get("r")) == nil ? 0 : (IV.num(e.get("r")) ?? Double.nan)
                total += r
                let outcome = e.get("outcome")?.asString
                if outcome == "auto" { autos += 1 } else if outcome == "step_up" { stepUps += 1 } else if outcome == "deny" { denies += 1 } else if outcome == "executed" { executed += 1 }
                immune = PCAImmune.observe(immune, r: r, at: at, stepUp: outcome == "step_up", denied: outcome == "deny")
            }
            let threat = PCAImmune.assess(immune)
            var row: JObject = [:]
            row[o: "agent"] = .string(k.s)
            row[o: "actions"] = .int(Int64(sorted.count))
            row[o: "autos"] = .int(Int64(autos))
            row[o: "stepUps"] = .int(Int64(stepUps))
            row[o: "denies"] = .int(Int64(denies))
            row[o: "executed"] = .int(Int64(executed))
            row[o: "totalRisk"] = PD.num(total)
            row[o: "firstSeen"] = PD.num(sorted[0].at)
            row[o: "lastSeen"] = PD.num(sorted[sorted.count - 1].at)
            row[o: "threat"] = PCAImmune.json(threat)
            agents.append((row, threat.score, sorted[sorted.count - 1].at, n))
            for (j, v) in [sorted.count, autos, stepUps, denies, executed].enumerated() { totals[j] += v }
        }
        agents.sort { a, b in a.score != b.score ? a.score > b.score : (a.last != b.last ? a.last > b.last : a.i < b.i) }
        var t: JObject = [:]
        for (j, name) in ["actions", "autos", "stepUps", "denies", "executed"].enumerated() { t[o: name] = .int(Int64(totals[j])) }
        var w: JObject = [:]
        w[o: "from"] = PD.num(ats.min() ?? 0)
        w[o: "to"] = PD.num(ats.max() ?? 0)
        var out: JObject = [:]
        out[o: "agents"] = .array(agents.map { .object($0.row) })
        out[o: "totals"] = .object(t)
        out[o: "window"] = .object(w)
        out[o: "dropped"] = .int(Int64(all.count - ats.count))
        return .object(out)
    }

    /// The agents of a console view whose threat level is not `calm`.
    public static func anomalies(_ view: JSONValue) -> [JSONValue] {
        (view.get("agents")?.asArray ?? []).filter { $0.get("threat")?.get("level") != .string("calm") }
    }

    private static func sameValue(_ a: JSONValue, _ b: JSONValue) -> Bool {
        if let x = IV.num(a), let y = IV.num(b) { return x == y }
        return a == b
    }

    /// The set with `agent` frozen: the same set when it already is, else a new one whose list is sorted (text order). Throws on an empty
    /// or non-text agent and on a set without a `frozen` list.
    public static func freezeAgent(_ set: JSONValue?, _ agent: JSONValue?) throws -> JSONValue {
        guard let name = agent?.asString, !name.isEmpty else { throw JSError("freezeAgent: agent must be a non-empty string") }
        var list: [JSONValue]
        switch set?.get("frozen") {
        case let .array(a)?:
            if a.contains(where: { sameValue($0, .string(name)) }) { return set! }
            list = a
        case let .string(text)?:
            // a text `frozen` is searched as text and spread into its code points, as the reference does with a string
            if text.range(of: name, options: .literal) != nil { return set! }
            list = text.unicodeScalars.map { .string(String($0)) }
        default: throw JSError("freezeAgent: the set has no frozen list")
        }
        list.append(.string(name))
        func key(_ v: JSONValue) -> String.UTF16View { JS.toString(v).utf16 }
        let sorted = list.enumerated().sorted { a, b in
            key(a.element).lexicographicallyPrecedes(key(b.element)) || (!key(b.element).lexicographicallyPrecedes(key(a.element)) && a.offset < b.offset)
        }
        return .object(["frozen": .array(sorted.map { $0.element })])
    }

    /// The set without `agent`. Throws on a set without a `frozen` list.
    public static func unfreezeAgent(_ set: JSONValue?, _ agent: JSONValue?) throws -> JSONValue {
        guard case let .array(list)? = set?.get("frozen") else { throw JSError("unfreezeAgent: the set has no frozen list") }
        return .object(["frozen": .array(list.filter { f in agent.map { !sameValue(f, $0) } ?? true })])
    }

    /// Fails closed: an empty or non-text agent, or a malformed set, is frozen.
    public static func isFrozen(_ set: JSONValue?, _ agent: JSONValue?) -> Bool {
        guard let name = agent?.asString, !name.isEmpty, case let .object(o)? = set, case let .array(list)? = o["frozen"] else { return true }
        return list.contains { sameValue($0, .string(name)) }
    }
}

/// A root agent and its delegated sub-agents under one signed goal.
public struct PCASession {
    public let root: PCAFacadeAgent
    public let members: [PCAFacadeAgent]
    /// The goal commitment of the root grant (empty when it has none).
    public let goalCommit: String
    public init(root: PCAFacadeAgent, members: [PCAFacadeAgent], goalCommit: String) {
        self.root = root; self.members = members; self.goalCommit = goalCommit
    }
}

public enum Session {
    /// A session is limited to this many delegation hops below the root.
    public static let SESSION_MAX_DEPTH = 32

    private static func goal(_ a: PCAFacadeAgent) -> String { PCA.readEnvelope(a.grant)?.get("goal_commit")?.asString ?? "" }

    public static func startSession(_ root: PCAFacadeAgent) -> PCASession { PCASession(root: root, members: [root], goalCommit: goal(root)) }

    /// Adds a sub-agent of the LAST member (one hop down, with the added caveats). Throws at the depth limit.
    public static func addMember(_ session: PCASession, holder: PCASuiteKey? = nil, addedCaveats: [JSONValue] = []) throws -> (session: PCASession, member: PCAFacadeAgent) {
        if session.members.count > SESSION_MAX_DEPTH { throw JSError("addMember: a session is limited to \(SESSION_MAX_DEPTH) delegation hops") }
        guard let parent = session.members.last else { throw JSError("addMember: the session has no member") }
        let member = try parent.subAgent(holder: holder, addedCaveats: addedCaveats)
        return (PCASession(root: session.root, members: session.members + [member], goalCommit: session.goalCommit), member)
    }

    /// The base64url Ed25519 holder key of every member, root first.
    public static func sessionAgents(_ session: PCASession) -> [String] { session.members.map { $0.holder.id ?? "" } }

    /// The console over the events of this session's members only. Throws on a null event.
    public static func sessionConsole(_ session: PCASession, _ events: [JSONValue]) throws -> JSONValue {
        if events.contains(where: { $0.isNull }) { throw JSError("sessionConsole: an event is null") }
        let ids = Set(sessionAgents(session).map { JKey($0) })
        return Console.buildConsole(events.filter { e in e.get("agent")?.asString.map { ids.contains(JKey($0)) } ?? false })
    }

    /// True when the session has a goal commitment and every member's grant carries it.
    public static func sharesGoal(_ session: PCASession) -> Bool { !session.goalCommit.isEmpty && session.members.allSatisfy { IV.same(goal($0), session.goalCommit) } }

    public static func sessionDepth(_ session: PCASession) -> Int { session.members.count - 1 }
}
