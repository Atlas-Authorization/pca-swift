import Foundation

// Bounded safety-LTL behavioural contracts: a port of `contracts.ts` (the TypeScript is authoritative).
//
// A contract is an optional embedded prohibition constitution (`invariants`) plus temporal `clauses` (always, never, precedes, requires_prior,
// responds_within, and) over one shared, hash-chained monitor state. A contract without clauses behaves exactly like the prohibition monitor.
// Everything malformed, unknown or unresolvable fails closed; nothing here traps.

/// The verdict of evaluating a contract against one action (`checkContract`).
public struct ContractResult: Sendable {
    public var ok: Bool
    public var violated: [String]
    public var reasons: [String]
    public var evaluated: [JSONValue]
    public var json: JSONValue {
        .object(["ok": .bool(ok), "violated": PD.strs(violated), "reasons": PD.strs(reasons), "evaluated": .array(evaluated)])
    }
}

/// `advanceContract`: the verdict plus the next state (the input state unless `ok`) and who decided.
public struct AdvanceContractResult: Sendable {
    public var ok: Bool
    public var violated: [String]
    public var reasons: [String]
    public var evaluated: [JSONValue]
    public var next: JSONValue
    /// `none` (admitted), `contract` (a clause or invariant is violated) or `state` (a structural, stale or unrecordable state).
    public var decidedBy: String
    /// `checkAndAdvanceContract` only.
    public var allow: Bool = false
    public var permitted: Bool = false
}

/// Per-clause transition: the verdict plus the intended latch / deadline updates (applied only if the whole contract is ok).
struct ClauseTransition {
    var ok: Bool
    var reason: JSONValue?
    var rows: [JSONValue]
    var latchSet: [JKey: JSONValue] = [:]
    /// id -> new deadline budget, or nil to clear an open obligation.
    var deadlineSet: [JKey: Double?] = [:]
}

public enum Contracts {
    public static let CONTRACT_VERSION = 1
    public static let CONTRACT_SIG_DOMAIN = "atlas-pca/contract/v1\u{0}"
    public static let MAX_CLAUSES = 256
    public static let MAX_CLAUSE_DEPTH = 16

    // ---- validation ------------------------------------------------------------------------------------------------------------

    /// Structural problems with a clause (empty = well-formed); collects ids into `seen` for global uniqueness. Total.
    public static func validateClause(_ cl: JSONValue?, _ seen: inout Set<JKey>, _ depth: Int) -> [String] {
        if depth > MAX_CLAUSE_DEPTH { return ["clause nesting too deep"] }
        guard case let .object(o)? = cl else { return ["clause not an object"] }
        guard case let .string(id)? = o["id"], !id.isEmpty else { return ["<no id>: missing clause id"] }
        func err(_ m: String) -> [String] { ["\(id): \(m)"] }
        if IV.u16(id) > Prohibitions.MAX_ID_LEN { return err("id too long") }
        if Prohibitions.forbiddenId(id) { return err("forbidden id") }
        if seen.contains(JKey(id)) { return err("duplicate id") }
        seen.insert(JKey(id))
        let kind = o["kind"]
        switch kind?.asString {
        case "always"?, "never"?:
            if let e = Prohibitions.validateWhen(o["p"], "p") { return err(e) }
            return []
        case "precedes"?, "requires_prior"?:
            if let e = Prohibitions.validateWhen(o["p"], "p") { return err(e) }
            if let e = Prohibitions.validateWhen(o["q"], "q") { return err(e) }
            return []
        case "responds_within"?:
            if let e = Prohibitions.validateWhen(o["p"], "p") { return err(e) }
            if let e = Prohibitions.validateWhen(o["q"], "q") { return err(e) }
            guard PD.isInteger(o["within"]), let w = IV.num(o["within"]), w >= 1, w <= Double(Prohibitions.MAX_DEADLINE) else {
                return err("within must be an integer in [1, MAX_DEADLINE]")
            }
            return []
        case "and"?:
            guard case let .array(subs)? = o["clauses"], !subs.isEmpty else { return err("and.clauses must be a non-empty array") }
            var out: [String] = []
            for s in subs { out.append(contentsOf: validateClause(s, &seen, depth + 1)) }
            return out
        default:
            return err("unknown clause kind \(PD.js(kind))")
        }
    }

    static func countClauses(_ cls: [JSONValue], _ depth: Int = 1) -> Int {
        // bounded recursion: an absurdly deep nest is "too many" at once (validateClause then reports the depth)
        if depth > MAX_CLAUSE_DEPTH + 1 { return MAX_CLAUSES + 1 }
        var n = 0
        for cl in cls {
            n += 1
            if cl.get("kind")?.asString == "and", case let .array(sub)? = cl.get("clauses") { n += countClauses(sub, depth + 1) }
        }
        return n
    }

    /// Structural problems with a contract (empty = well-formed). Total.
    public static func validateContract(_ c: JSONValue?) -> [String] {
        guard case let .object(o)? = c else { return ["contract not an object"] }
        var out: [String] = []
        let version = o["version"]
        if !(IV.num(version) == Double(CONTRACT_VERSION)) { out.append("unsupported version \(PD.js(version))") }
        if case let .string(p)? = o["principal"], !p.isEmpty {} else { out.append("principal missing") }
        var ids = Set<JKey>()
        // the embedded constitution (optional): the prohibition validator, reusing its id rules
        if let invariants = o["invariants"] {
            guard case let .array(invs) = invariants else { return out + ["invariants not an array"] }
            if invs.count > Prohibitions.MAX_INVARIANTS { out.append("too many invariants") }
            for inv in invs {
                out.append(contentsOf: Prohibitions.validateInvariant(inv))
                if case let .string(id)? = inv.asObject?[JKey("id")] {
                    if ids.contains(JKey(id)) { out.append("\(id): duplicate id") }
                    ids.insert(JKey(id))
                }
            }
        }
        if let clauses = o["clauses"] {
            guard case let .array(cls) = clauses else { return out + ["clauses not an array"] }
            if countClauses(cls) > MAX_CLAUSES { out.append("too many clauses") }
            // clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
            for cl in cls { out.append(contentsOf: validateClause(cl, &ids, 1)) }
        }
        return out
    }

    // ---- commitment ------------------------------------------------------------------------------------------------------------

    /// Content address of a contract body. Throws only on non-canonicalizable input.
    public static func contractId(_ c: JSONValue) throws -> String {
        guard case let .object(o) = c else { throw PDFail(what: "not an object") }
        return try PD.hash(.object(Prohibitions.body(o)))
    }

    /// The principal signs the contract. Refuses to sign a malformed one.
    public static func signContract(_ c: JSONValue, principal: PCAEdKey) throws -> JSONValue {
        let problems = validateContract(c)
        if !problems.isEmpty { throw PCAProducerError("signContract: " + problems.joined(separator: "; ")) }
        guard case let .object(o) = c else { throw PCAProducerError("signContract: not an object") }
        let id = try contractId(c)
        var out = Prohibitions.body(o)
        out["id"] = .string(id)
        out["sig"] = .string(Base64URLStrict.encode(try principal.sign(PD.domainMessage(CONTRACT_SIG_DOMAIN, id))))
        return .object(out)
    }

    /// Well-formed, id matches content, signature by `expectedPrincipal` (or the embedded one). Never throws.
    public static func verifyContract(_ sc: JSONValue?, expectedPrincipal: String? = nil) -> ProhibitionVerdict {
        Prohibitions.verifySigned(sc, expectedPrincipal, CONTRACT_SIG_DOMAIN, validateContract)
    }

    /// The embedded prohibition constitution of a contract (empty when `invariants` is omitted).
    public static func embeddedConstitution(_ c: JSONValue) -> JSONValue {
        .object(["version": .int(1), "principal": c.get("principal") ?? .null, "invariants": c.get("invariants")?.isArray == true ? (c.get("invariants") ?? .array([])) : .array([])])
    }

    /// Lift a plain prohibition constitution into the degenerate contract (no temporal clauses).
    public static func contractFromConstitution(_ c: JSONValue) -> JSONValue {
        .object(["version": .int(Int64(CONTRACT_VERSION)), "principal": c.get("principal") ?? .null, "invariants": c.get("invariants") ?? .null, "clauses": .array([])])
    }

    // ---- clause evaluation -----------------------------------------------------------------------------------------------------

    static func row(_ cl: JObject, _ ok: Bool, _ reason: JSONValue?) -> JSONValue {
        var r: JObject = ["id": cl["id"] ?? .null, "kind": cl["kind"] ?? .null, "result": .string(ok ? "pass" : "violated")]
        if let why = reason, PD.truthy(why) { r["reason"] = why }
        return .object(r)
    }

    static func base(_ cl: JObject, _ ok: Bool, _ reason: JSONValue? = nil) -> ClauseTransition {
        ClauseTransition(ok: ok, reason: (reason.map { PD.truthy($0) } ?? false) ? reason : nil, rows: [row(cl, ok, reason)])
    }

    static func desc(_ cl: JObject, _ def: String) -> JSONValue {
        if let d = cl["description"], !d.isNull { return d }
        return .string(def)
    }

    static func evalClause(_ cl: JObject, _ ctx: JSONValue, _ state: JObject, _ now: Double, _ scope: SafeRegex.Budget) -> ClauseTransition {
        let latched = state["latched"]
        let deadlines: JObject = state["deadlines"]?.asObject ?? [:]
        let id = cl["id"]?.asString ?? ""
        switch cl["kind"]?.asString {
        case "always"?:
            // positive authority: every action must AFFIRMATIVELY satisfy p; unresolvable => violation
            return Prohibitions.whenAffirmative(cl["p"], ctx, scope: scope) ? base(cl, true) : base(cl, false, desc(cl, "always-invariant violated (action does not satisfy p)"))
        case "never"?:
            // = always not p; conservative: an unresolvable trigger counts as matched (veto)
            return Prohibitions.whenMatches(cl["p"], ctx, scope: scope) ? base(cl, false, desc(cl, "never-invariant violated (forbidden action)")) : base(cl, true)
        case "precedes"?, "requires_prior"?:
            let isQ = Prohibitions.whenMatches(cl["q"], ctx, scope: scope) // guarded action, conservative
            let held = PD.has(latched, id)
            var t = base(cl, !isQ || held, !isQ || held ? nil : desc(cl, "precedence violated (prerequisite p not yet admitted before q)"))
            // latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
            if !held && Prohibitions.whenAffirmative(cl["p"], ctx, scope: scope) { t.latchSet[JKey(id)] = PD.num(now) }
            return t
        case "responds_within"?:
            let within = IV.num(cl["within"]) ?? 0
            var violated = false
            var carried: Double? = nil // budget carried from an existing obligation (not yet discharged)
            if let cur = IV.num(deadlines[JKey(id)]) {
                if Prohibitions.whenAffirmative(cl["q"], ctx, scope: scope) {
                    carried = nil // any response discharges all open obligations
                } else {
                    let r = cur - 1
                    if r <= 0 { violated = true } else { carried = r } // window exhausted with no response => violation at this action
                }
            }
            if violated {
                let why = desc(cl, "bounded-liveness deadline missed (no q within \(PD.js(cl["within"])) actions of p)")
                let rw = row(cl, false, why)
                return ClauseTransition(ok: false, reason: rw.get("reason"), rows: [rw])
            }
            // a (conservative) stimulus opens a fresh obligation of budget `within`; the binding deadline is the MOST URGENT open obligation
            var next: Double? = carried
            if Prohibitions.whenMatches(cl["p"], ctx, scope: scope) { next = next == nil ? within : PD.jsMin(next!, within) }
            return ClauseTransition(ok: true, reason: nil, rows: [row(cl, true, nil)], latchSet: [:], deadlineSet: [JKey(id): next])
        case "and"?:
            var rows: [JSONValue] = []
            var latchSet: [JKey: JSONValue] = [:]
            var deadlineSet: [JKey: Double?] = [:]
            var ok = true
            var reason: JSONValue? = nil
            for subV in cl["clauses"]?.asArray ?? [] {
                let r = evalClause(subV.asObject ?? [:], ctx, state, now, scope)
                rows.append(contentsOf: r.rows)
                for (k, v) in r.latchSet { latchSet[k] = v }
                for (k, v) in r.deadlineSet { deadlineSet[k] = v }
                if !r.ok && ok {
                    ok = false
                    reason = r.reason
                }
            }
            // the `and` itself emits no row: its children's rows carry the detail
            return ClauseTransition(ok: ok, reason: (reason.map { PD.truthy($0) } ?? false) ? reason : nil, rows: rows, latchSet: latchSet, deadlineSet: deadlineSet)
        default:
            return base(cl, false, .string("unknown clause kind (fail closed)"))
        }
    }

    // ---- the contract monitor --------------------------------------------------------------------------------------------------

    static func fail(_ id: String, _ reason: String) -> ContractResult {
        ContractResult(ok: false, violated: [id], reasons: ["\(id): \(reason)"], evaluated: [.object(["id": .string(id), "kind": .string("structural"), "result": .string("violated"), "reason": .string(reason)])])
    }

    /// Evaluate a whole contract (embedded constitution + temporal clauses) against one action and the running state, WITHOUT advancing.
    /// Total, fail-closed. The whole contract is one document for the regex budget.
    public static func checkContract(_ action: JSONValue?, _ contract: JSONValue?, _ state: JSONValue?) -> ContractResult {
        if let cp = validateContract(contract).first { return fail("<contract>", cp) }
        if !Prohibitions.actionOk(action) { return fail("<action>", "malformed action") }
        if let sp = Prohibitions.stateProblem(state) { return fail("<state>", sp) }
        guard let act = action, let con = contract, case let .object(st)? = state, let now = PD.fin(st["now"]) else { return fail("<monitor>", "monitor error (fail closed)") }
        var evaluated: [JSONValue] = []
        let scope = SafeRegex.Budget() // the whole contract (constitution and every clause) is one document for the regex budget
        // 1) the embedded constitution (unchanged semantics: the prohibition monitor verbatim)
        let constitution = embeddedConstitution(con)
        if !(constitution.get("invariants")?.asArray ?? []).isEmpty {
            evaluated.append(contentsOf: Prohibitions.checkProhibitions(act, constitution, state, scope: scope).evaluated)
        }
        // 2) the temporal clauses
        for clV in con.get("clauses")?.asArray ?? [] {
            evaluated.append(contentsOf: evalClause(clV.asObject ?? [:], act, st, now, scope).rows)
        }
        let bad = evaluated.filter { $0.get("result")?.asString == "violated" }
        return ContractResult(
            ok: bad.isEmpty,
            violated: bad.map { $0.get("id")?.asString ?? "" },
            reasons: bad.map { "\($0.get("id")?.asString ?? ""): \($0.get("reason").map { PD.js($0) } ?? "violated")" },
            evaluated: evaluated)
    }

    /// Check the whole contract against one action and, iff it holds, advance the hash-chained monitor state exactly like the prohibition
    /// monitor, then overlay the temporal clauses' precedence latches and deadline counters. `expectedSeq` / `expectedStateDigest` are the
    /// compare-and-swap guards on the chain head; `now` (epoch ms, >= state.now) defaults to the state's. Fail closed; `next` is the input
    /// state unless `ok`. Never throws.
    public static func advanceContract(_ state: JSONValue?, _ action: JSONValue?, _ contract: JSONValue?, now nowIn: Double? = nil,
                                       expectedSeq: Double? = nil, expectedStateDigest: String? = nil) -> AdvanceContractResult {
        let stateOut: JSONValue = state ?? .null
        func refuse(_ by: String, _ r: ContractResult? = nil, _ why: String? = nil) -> AdvanceContractResult {
            let b = r ?? checkContract(action, contract, state)
            return AdvanceContractResult(
                ok: false,
                violated: why != nil ? b.violated.filter { $0 != "<state>" } + ["<state>"] : b.violated,
                reasons: why != nil ? b.reasons + ["<state>: \(why!)"] : b.reasons,
                evaluated: b.evaluated, next: stateOut, decidedBy: by)
        }
        let now: Double? = nowIn ?? PD.fin(state?.get("now"))
        // compare-and-swap on the chain head FIRST: a rolled-back / stale state is refused before anything else
        if let es = expectedSeq, !(PD.isObj(state) && IV.num(state?.get("seq")) == es) { return refuse("state", nil, "stale state head (seq)") }
        if let ed = expectedStateDigest, Prohibitions.safeDigest({ try Prohibitions.stateDigest(state) }) != ed { return refuse("state", nil, "stale state head (digest)") }

        let verdict = checkContract(action, contract, state)
        if !verdict.ok {
            let structural = verdict.violated.contains { $0.hasPrefix("<") && $0.hasSuffix(">") }
            return AdvanceContractResult(ok: false, violated: verdict.violated, reasons: verdict.reasons, evaluated: verdict.evaluated, next: stateOut, decidedBy: structural ? "state" : "contract")
        }
        guard let con = contract, let act = action, case let .object(st)? = state, let n = now else { return refuse("state", nil, "advance error (fail closed)") }
        let constitution = embeddedConstitution(con)
        let adv = Prohibitions.advanceStateStrict(act, constitution, state, now: n)
        guard adv.ok, case var .object(next)? = adv.state else { return refuse("state", verdict, "advance failed: " + (adv.reason ?? "")) }

        // overlay the temporal clauses' state: recompute their transitions against the PRE-state and apply to the advanced base
        var latched: JObject = next["latched"]?.asObject ?? [:]
        var deadlines: JObject = st["deadlines"]?.asObject ?? [:]
        let scope = SafeRegex.Budget() // a second evaluation pass: its own document budget
        for clV in con.get("clauses")?.asArray ?? [] {
            let t = evalClause(clV.asObject ?? [:], act, st, n, scope)
            for (k, v) in t.latchSet where latched[k] == nil { latched[k] = v }
            for (k, v) in t.deadlineSet {
                if let d = v { deadlines[k] = PD.num(d) } else { deadlines[k] = nil }
            }
        }
        next["latched"] = .object(latched)
        if !deadlines.isEmpty { next["deadlines"] = .object(deadlines) }
        let nextV: JSONValue = .object(next)
        if let sp = Prohibitions.stateProblem(nextV) { return refuse("state", verdict, "resulting state invalid: " + sp) }
        return AdvanceContractResult(ok: true, violated: verdict.violated, reasons: verdict.reasons, evaluated: verdict.evaluated, next: nextV, decidedBy: "none")
    }

    /// `allow = permitted AND contract.ok`; on allow the state advances. The contract monitor runs unconditionally.
    public static func checkAndAdvanceContract(permitted: Bool, _ state: JSONValue?, _ action: JSONValue?, _ contract: JSONValue?, now: Double? = nil,
                                               expectedSeq: Double? = nil, expectedStateDigest: String? = nil) -> AdvanceContractResult {
        var adv = advanceContract(state, action, contract, now: now, expectedSeq: expectedSeq, expectedStateDigest: expectedStateDigest)
        adv.permitted = permitted
        if !adv.ok { adv.allow = false; return adv }
        if !permitted {
            return AdvanceContractResult(ok: false, violated: adv.violated, reasons: adv.reasons + ["<permission>: not permitted"], evaluated: adv.evaluated,
                                         next: state ?? .null, decidedBy: "contract", allow: false, permitted: permitted)
        }
        adv.allow = true
        return adv
    }
}
