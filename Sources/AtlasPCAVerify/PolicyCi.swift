import Foundation

/// The shift-left policy-safety CI gate: five lint rules (over-broad grant, privilege escalation, redundant caveat, dangerous
/// reachability, missing safety floor) plus a schema check, driven by the real static analyzer (`PCAAnalyzer`), the roll-up with
/// exit codes, the pinned action-kit lint-rule digest, the authoring gates (`diff`, `test`, `coverage`) and the command line.
///
/// SOUNDNESS: a hard `error` is only emitted from a PROVEN analyzer verdict; an undecidable feature fails safe to a `warn` / `info`
/// that says so, so the gate never fails a build on a false positive and never silently passes a provably unsafe policy. A rule that
/// throws is a finding (`internal-error`), never silence.
///
/// Policies, findings and results are plain JSON trees (`JSONValue`).
public enum PCAPolicyCi {
    typealias V = JSONValue
    typealias A = PCAAnalyzer

    static let ENVELOPE_CAVEAT_TYPE = PCA.ENVELOPE_CAVEAT
    static let SCOPE_NARROWING_CAVEATS = ["max_blast_radius", "rate", "reversibility_max", "budget_alloc", "delegation_depth"]
    static let BUDGET_GATE_CAVEATS = ["max_blast_radius", "rate", "budget_alloc"]
    public static let DEFAULT_DANGEROUS_VERBS = ["delete", "destroy", "drop", "remove", "purge", "transfer", "payout", "wire", "withdraw", "admin", "grant", "revoke", "deploy", "shutdown", "rotate"]
    public static let SEVERITY_RANK: [String: Int] = ["info": 1, "warn": 2, "error": 3]

    // ---- small helpers ----

    static func mem(_ x: V?, _ k: String) -> V? { JSLoose.get(x, k) }
    static func isRecord(_ x: V?) -> Bool { x?.isObject ?? false }
    static func isStr(_ x: V?) -> Bool { x?.asString != nil }
    static func has(_ xs: [String], _ x: String) -> Bool { IV.contains(xs, x) }
    static func s(_ v: V?) -> String { JS.toString(v) }
    /// `typeof v === 'object' ? v.k : undefined` for an options member: null is an object whose members cannot be read (a TypeError).
    static func objMember(_ v: V?, _ k: String) throws -> V? {
        if v == .null { throw JSError("cannot read properties of null (reading '\(k)')") }
        return mem(v, k)
    }

    static func finding(_ rule: String, _ severity: String, _ message: String, _ where_: String? = nil) -> V {
        A.obj([("rule", .string(rule)), ("severity", .string(severity)), ("message", .string(message)), ("where", where_.map { .string($0) })])
    }

    /// `JSON.stringify(x)` of a string list.
    static func jsonStrs(_ xs: [String]) -> String { JS.stringify(PCADataflow.strs(xs)) }

    static func verbsOf(_ v: V?) -> [String] {
        if let str = v?.asString { return [str] }
        if let a = v?.asArray { return a.compactMap { $0.asString } }
        return []
    }

    static func isDangerousVerb(_ verb: String, _ dangerous: [String]) -> Bool {
        let v = verb.lowercased()
        return dangerous.contains { kw in let k = kw.lowercased(); return k.isEmpty || v.contains(k) }
    }

    static func isWildcardResource(_ r: V?) -> Bool { r == nil || r?.asString.map { IV.same($0, "*") } ?? false }

    /// A caveat that is an object with a string `type`.
    static func caveatType(_ c: V?) -> String? { isRecord(c) ? mem(c, "type")?.asString : nil }

    static func hasCaveatOfType(_ caveats: [V], _ types: [String]) -> Bool { caveats.contains { c in caveatType(c).map { has(types, $0) } ?? false } }

    /// A one-line rendering of an analyzer witness / counterexample action (`order`: the reference's member order of its params).
    static func describeAction(_ a: V?, _ order: [String]) -> String {
        func part(_ v: V?) -> String { (v == nil || v == .null) ? "" : s(v) }
        var parts = [part(mem(a, "verb")), part(mem(a, "resource"))]
        if let p = mem(a, "params"), JS.truthy(p), !JSLoose.keys(p).isEmpty { parts.append(JS.stringify(p, order: order)) }
        if let rc = mem(a, "reversibilityClass") { parts.append("[\(s(rc))]") }
        return parts.joined(separator: " ")
    }

    // ---- normalisation ----

    struct Norm {
        var predicates: [V]
        var caveats: [V]
        var riskPolicy: V?
        var kind: String
        var json: V { A.obj([("predicates", .array(predicates)), ("caveats", .array(caveats)), ("riskPolicy", riskPolicy), ("kind", .string(kind))]) }
    }

    /// A minted grant / delegation hop: the content-addressed, signed shape of a capability.
    public static func isCapability(_ x: JSONValue?) -> Bool {
        guard isRecord(x) else { return false }
        return isStr(mem(x, "id")) && isStr(mem(x, "issuer")) && isStr(mem(x, "holder")) && isStr(mem(x, "body_digest")) && isStr(mem(x, "sig")) && mem(x, "caveats")?.isArray == true
    }

    /// A signed policy envelope (the Root Intent Grant payload).
    public static func isEnvelope(_ x: JSONValue?) -> Bool {
        guard isRecord(x) else { return false }
        return isStr(mem(x, "goal_commit")) && mem(x, "predicates")?.isArray == true && mem(x, "caveats")?.isArray == true && isRecord(mem(x, "agent_binding")) && isRecord(mem(x, "risk_policy"))
    }

    static func isCompiledPolicy(_ x: V?) -> Bool {
        guard isRecord(x) else { return false }
        return mem(x, "predicates")?.isArray == true && mem(x, "caveats")?.isArray == true && isRecord(mem(x, "riskPolicy")) && mem(x, "actions")?.isArray == true
    }

    /// Drop the envelope-carrying caveat; keep the runtime gate caveats (objects or arrays whose `type` is not `envelope`).
    static func runtimeCaveats(_ caveats: [V]) -> [V] {
        caveats.filter { c in (c.isObject || c.isArray) && !IV.same(mem(c, "type")?.asString, ENVELOPE_CAVEAT_TYPE) }
    }

    enum NormResult {
        case ok(Norm)
        case fail(String)
        var json: V {
            switch self {
            case let .ok(p): return .object(["ok": .bool(true), "policy": p.json])
            case let .fail(r): return .object(["ok": .bool(false), "reason": .string(r)])
            }
        }
    }

    /// The grant's effective authority: the predicates and baseline gates live in its envelope, delegation appends further gates.
    static func fromGrant(_ grant: V) -> NormResult {
        guard let env = PCA.readEnvelope(grant) else { return .fail("grant has no readable `envelope` caveat (malformed or unsigned payload)") }
        let appended = runtimeCaveats(A.arr(mem(grant, "caveats")))
        return .ok(Norm(predicates: A.arr(mem(env, "predicates")), caveats: A.arr(mem(env, "caveats")) + appended, riskPolicy: mem(env, "risk_policy"), kind: "grant"))
    }

    /// Normalise any single-policy input to its effective authority.
    /// The reference's `normalizePolicyInput` as its result record: `{ok: true, policy: {predicates, caveats, riskPolicy?, kind}}` or `{ok: false, reason}`.
    public static func normalizePolicyInput(_ input: JSONValue?) -> JSONValue { normalizedInput(input).json }
    static func normalizedInput(_ input: V?) -> NormResult {
        if isCapability(input), let i = input { return fromGrant(i) }
        if isEnvelope(input) {
            return .ok(Norm(predicates: A.arr(mem(input, "predicates")), caveats: A.arr(mem(input, "caveats")), riskPolicy: mem(input, "risk_policy"), kind: "envelope"))
        }
        if isCompiledPolicy(input) {
            return .ok(Norm(predicates: A.arr(mem(input, "predicates")), caveats: A.arr(mem(input, "caveats")), riskPolicy: mem(input, "riskPolicy"), kind: "compiled"))
        }
        if isRecord(input), mem(input, "predicates")?.isArray == true {
            return .ok(Norm(predicates: A.arr(mem(input, "predicates")), caveats: A.arr(mem(input, "caveats")), riskPolicy: nil, kind: "bare"))
        }
        return .fail("unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })")
    }

    enum ChainResult {
        case ok([Norm])
        case fail(String)
        var json: V {
            switch self {
            case let .ok(h): return .object(["ok": .bool(true), "hops": .array(h.map { $0.json })])
            case let .fail(r): return .object(["ok": .bool(false), "reason": .string(r)])
            }
        }
    }

    /// One effective authority per hop (root to leaf): a chain of capabilities shares the root envelope's predicates and each hop's
    /// gates are the envelope's plus that hop's appended ones; a chain of effective `{ predicates, caveats }` hops is taken as is.
    static func normalizeChain(_ chain: [JSONValue]) -> ChainResult {
        if chain.isEmpty { return .fail("empty chain") }
        if chain.allSatisfy({ isCapability($0) }) {
            guard let env = PCA.readEnvelope(chain[0]) else { return .fail("root grant has no readable `envelope` caveat") }
            return .ok(chain.map { cap in
                Norm(predicates: A.arr(mem(env, "predicates")), caveats: A.arr(mem(env, "caveats")) + runtimeCaveats(A.arr(mem(cap, "caveats"))), riskPolicy: mem(env, "risk_policy"), kind: "chain-hop")
            })
        }
        var hops: [Norm] = []
        for (i, c) in chain.enumerated() {
            switch normalizedInput(c) {
            case let .fail(r): return .fail("hop \(i): \(r)")
            case var .ok(p): p.kind = "chain-hop"; hops.append(p)
            }
        }
        return .ok(hops)
    }

    // ---- the rules ----

    static func analyzerInput(_ p: Norm) -> V { .object(["predicates": .array(p.predicates), "caveats": .array(p.caveats)]) }

    /// Every concrete verb named across the predicate set, plus whether any predicate grants `*`.
    static func declaredVerbs(_ predicates: [V]) -> (concrete: [String], hasWildcard: Bool) {
        var concrete: [String] = [], wild = false
        for p in predicates where p.isObject || p.isArray {
            for v in verbsOf(mem(p, "verb")) { if IV.same(v, "*") { wild = true } else { concrete.append(v) } }
        }
        return (PCADataflow.distinct(concrete), wild)
    }

    /// Does the policy carry a budget / step-up gate that bounds a dangerous action?
    static func gateDescription(_ p: Norm) throws -> String? {
        var gates: [String] = []
        if hasCaveatOfType(p.caveats, BUDGET_GATE_CAVEATS) {
            var types: [String] = []
            for c in p.caveats {
                guard c != .null else { throw JSError("cannot read properties of null (reading 'type')") }
                if let t = mem(c, "type")?.asString, has(BUDGET_GATE_CAVEATS, t) { types.append(t) }
            }
            gates.append(types.joined(separator: "/"))
        }
        if let rp = p.riskPolicy, let t2 = A.fin(mem(rp, "theta2")), t2 < 1 { gates.append("risk step-up (theta2 < 1)") }
        return gates.isEmpty ? nil : gates.joined(separator: ", ")
    }

    static func ruleOverBroadGrant(_ policy: Norm, _ dangerous: [String], _ opts: V?) throws -> [V] {
        var out: [V] = []
        let input = analyzerInput(policy)
        let hasScopeNarrowing = hasCaveatOfType(policy.caveats, SCOPE_NARROWING_CAVEATS)
        for (i, p) in policy.predicates.enumerated() where p.isObject || p.isArray {
            let verbs = verbsOf(mem(p, "verb"))
            let where_ = "predicates[\(i)]"
            let hasWhere = (mem(p, "where")?.asArray?.isEmpty == false)
            if verbs.contains(where: { IV.same($0, "*") }) {
                out.append(finding("over-broad-grant", "error", "predicate grants a WILDCARD verb '*' \u{2014} authority over any action", where_))
            }
            if isWildcardResource(mem(p, "resource")) {
                let dv = verbs.filter { isDangerousVerb($0, dangerous) }
                if !dv.isEmpty {
                    out.append(finding("over-broad-grant", "error", "dangerous verb(s) \(jsonStrs(dv)) granted on a WILDCARD resource ('*')", where_))
                } else if !verbs.contains(where: { IV.same($0, "*") }) {
                    out.append(finding("over-broad-grant", "warn", "predicate matches ANY resource ('*') \u{2014} consider a resource prefix", where_))
                }
            }
            for v in verbs where !IV.same(v, "*") && isDangerousVerb(v, dangerous) && !hasWhere && !hasScopeNarrowing {
                out.append(finding("over-broad-grant", "error",
                                   "dangerous verb '\(v)' is granted with NO narrowing `where` and no scope-narrowing caveat (\(SCOPE_NARROWING_CAVEATS.joined(separator: "/")))", where_))
            }
        }
        // a verb the analyzer PROVES total (admits every action of that verb)
        for v in declaredVerbs(policy.predicates).concrete {
            let aa = try A.alwaysAllows(input, .string(v), opts)
            if mem(aa, "alwaysAllows") == .bool(true) && mem(aa, "approximate") != .bool(true) {
                out.append(finding("over-broad-grant", "error", "grants EVERY action of '\(v)' \u{2014} the authority has no effective constraint (always-allow)"))
            }
        }
        return out
    }

    static func rulePrivilegeEscalation(_ hops: [Norm], _ opts: V?) throws -> [V] {
        var out: [V] = []
        for i in hops.indices.dropFirst() {
            let order = A.WitnessOrder()
            let r = try A.subsumes(analyzerInput(hops[i - 1]), analyzerInput(hops[i]), opts, order: order)
            let where_ = "hop[\(i)]"
            if mem(r, "subsumes") == .bool(true) { continue }
            if mem(r, "approximate") == .bool(true) {
                let reason = mem(r, "reason").flatMap { JS.truthy($0) ? ": \(s($0))" : nil } ?? ""
                out.append(finding("privilege-escalation", "warn", "could not prove hop \(i) attenuation (undecidable\(reason)) \u{2014} attenuation not verified", where_))
            } else {
                let ex = mem(r, "counterexample").map { " \u{2014} child admits '\(describeAction($0, order.params))' which its parent denies" } ?? ""
                out.append(finding("privilege-escalation", "error",
                                   "delegation hop \(i) ESCALATES authority: its effective authority is not a subset of its parent (attenuation violated)\(ex)", where_))
            }
        }
        return out
    }

    /// type -> (bound field, keep the min or the max): the strictest caveat of a type dominates the looser ones.
    static let ORDERED_CAVEATS: [(type: String, field: String, keepMin: Bool)] = [
        ("expires", "at", true), ("not_before", "at", false), ("max_blast_radius", "max", true), ("delegation_depth", "max", true), ("budget_alloc", "limit", true),
    ]

    static func ruleRedundantCaveat(_ policy: Norm) -> [V] {
        var out: [V] = []
        // (a) exact-duplicate caveats (compared by their JSON text)
        var seen: [JKey: Int] = [:]
        for (i, cv) in policy.caveats.enumerated() where cv.isObject || cv.isArray {
            let k = JKey(JS.stringify(cv))
            if let first = seen[k] {
                out.append(finding("redundant-caveat", "warn", "caveat \(i) ('\(s(mem(cv, "type")))') is an exact duplicate of caveat \(first) \u{2014} dead policy", "caveats[\(i)]"))
            } else { seen[k] = i }
        }
        // (b) same-type domination
        for spec in ORDERED_CAVEATS {
            var vals: [(i: Int, v: Double)] = []
            for (i, cv) in policy.caveats.enumerated() where isRecord(cv) && IV.same(mem(cv, "type")?.asString, spec.type) {
                if let v = A.fin(mem(cv, spec.field)) { vals.append((i, v)) }
            }
            if vals.count < 2 { continue }
            let binding = spec.keepMin ? vals.map { $0.v }.min()! : vals.map { $0.v }.max()!
            for e in vals where e.v != binding {
                out.append(finding("redundant-caveat", "warn",
                                   "caveat \(e.i) ('\(spec.type)' \(spec.field)=\(JS.number(e.v))) is subsumed by a stricter '\(spec.type)' (\(spec.field)=\(JS.number(binding))) \u{2014} it can never bite", "caveats[\(e.i)]"))
            }
        }
        // (c) a predicate whose numeric `where` conjunction is unsatisfiable never matches
        for (i, p) in policy.predicates.enumerated() where p.isObject || p.isArray {
            guard let w = mem(p, "where")?.asArray else { continue }
            if !A.predicateNumericSatisfiable(.array(w)) {
                out.append(finding("redundant-caveat", "warn", "predicate \(i) can never match \u{2014} its numeric `where` constraints are unsatisfiable (dead policy)", "predicates[\(i)]"))
            } else { out += nonBindingConditions(w, i) }
        }
        return out
    }

    static let NUMERIC_OPS = ["lt", "lte", "gt", "gte", "eq"]

    /// A numeric leaf condition that does not tighten its field's interval is redundant (never binds).
    static func nonBindingConditions(_ where_: [V], _ predIndex: Int) -> [V] {
        var byField: [(field: String, conds: [(c: V, i: Int)])] = []
        for (i, c) in where_.enumerated() {
            guard A.isLeaf(c), mem(c, "ref") == nil, let op = mem(c, "op")?.asString, has(NUMERIC_OPS, op), A.fin(mem(c, "value")) != nil else { continue }
            let f = mem(c, "field")!.asString!
            if let k = byField.firstIndex(where: { IV.same($0.field, f) }) { byField[k].conds.append((c, i)) } else { byField.append((f, [(c, i)])) }
        }
        var out: [V] = []
        func fold(_ cs: [(c: V, i: Int)]) -> A.Interval { cs.reduce(A.Interval.full) { A.tightenInterval($0, mem($1.c, "op"), mem($1.c, "value")) } }
        for g in byField where g.conds.count >= 2 {
            let full = fold(g.conds)
            if A.intervalEmpty(full) { continue } // the whole-predicate unsat case is reported in (c)
            for e in g.conds {
                let without = fold(g.conds.filter { $0.i != e.i })
                if without.lo == full.lo && without.loInc == full.loInc && without.hi == full.hi && without.hiInc == full.hiInc {
                    out.append(finding("redundant-caveat", "info",
                                       "condition on '\(g.field)' (\(s(mem(e.c, "op"))) \(s(mem(e.c, "value")))) does not tighten the authority \u{2014} redundant with the other bounds on this field",
                                       "predicates[\(predIndex)].where[\(e.i)]"))
                }
            }
        }
        return out
    }

    static func ruleDangerousReachability(_ policy: Norm, _ dangerous: [String], _ extraTargets: [V], _ opts: V?) throws -> [V] {
        var out: [V] = []
        let input = analyzerInput(policy)
        var targets: [V] = declaredVerbs(policy.predicates).concrete.filter { isDangerousVerb($0, dangerous) }.map { .object(["verb": .string($0)]) }
        targets += extraTargets
        let gate = try gateDescription(policy)
        for t in targets {
            let verb = mem(t, "verb")
            var proven = false, approximate = false
            var reason: V?
            var witness: String
            if let res = mem(t, "resource") {
                let r = try A.reachable(input, A.obj([("verb", verb), ("resource", res)]), opts)
                proven = mem(r, "reachable") == .bool(true) && mem(r, "approximate") != .bool(true)
                approximate = mem(r, "approximate") == .bool(true)
                reason = mem(r, "reason")
                witness = "\(s(verb)) \(s(res))"
            } else {
                let order = A.WitnessOrder()
                let r = try A.alwaysDenies(input, verb, opts, order: order)
                proven = mem(r, "alwaysDenies") == .bool(false) && mem(r, "approximate") != .bool(true)
                approximate = mem(r, "approximate") == .bool(true)
                reason = mem(r, "reason")
                witness = mem(r, "witness").map { describeAction($0, order.params) } ?? s(verb)
            }
            if approximate {
                let why = reason.flatMap { JS.truthy($0) ? ": \(s($0))" : nil } ?? ""
                out.append(finding("dangerous-reachability", "warn", "could not decide reachability of dangerous verb '\(s(verb))' (undecidable\(why))"))
            } else if proven {
                if let g = gate { out.append(finding("dangerous-reachability", "info", "dangerous action '\(witness)' is reachable but gated by \(g)")) }
                else { out.append(finding("dangerous-reachability", "error", "dangerous action '\(witness)' is REACHABLE with no budget / rate / step-up gate")) }
            }
        }
        return out
    }

    /// A grant is non-trivial when any predicate grants a dangerous / wildcard verb, a wildcard resource, or is unconstrained.
    static func isNonTrivial(_ policy: Norm, _ dangerous: [String]) -> Bool {
        policy.predicates.contains { p in
            guard p.isObject || p.isArray else { return false }
            let verbs = verbsOf(mem(p, "verb"))
            let hasWhere = mem(p, "where")?.asArray?.isEmpty == false
            return verbs.contains { IV.same($0, "*") } || verbs.contains { isDangerousVerb($0, dangerous) } || isWildcardResource(mem(p, "resource")) || !hasWhere
        }
    }

    static func ruleMissingSafetyFloor(_ policy: Norm, requireExpiry: Bool, requireScopeGate: Bool, _ dangerous: [String]) -> [V] {
        var out: [V] = []
        if policy.predicates.isEmpty { return out } // nothing is granted; default-deny needs no floor
        if requireExpiry && !hasCaveatOfType(policy.caveats, ["expires"]) {
            out.append(finding("missing-safety-floor", "warn", "grant has no `expires` caveat \u{2014} the authority never expires"))
        }
        if requireScopeGate && isNonTrivial(policy, dangerous) && !hasCaveatOfType(policy.caveats, BUDGET_GATE_CAVEATS) {
            out.append(finding("missing-safety-floor", "warn", "non-trivial grant has no blast-radius / rate / budget gate (\(BUDGET_GATE_CAVEATS.joined(separator: "/")))"))
        }
        return out
    }

    /// The policy compared with the action schema it is written for (`validatePolicyAgainstSchema`).
    static func ruleSchemaMismatch(_ policy: Norm, _ schema: V?, _ options: V?) throws -> [V] {
        let r = try A.validatePolicyAgainstSchema(.object(["predicates": .array(policy.predicates), "caveats": .array(policy.caveats)]), schema, options)
        return A.arr(mem(r, "findings")).map { f in
            A.obj([("rule", .string("schema-mismatch")), ("severity", mem(f, "severity")), ("message", .string("\(s(mem(f, "code"))): \(s(mem(f, "message")))")), ("where", mem(f, "where"))])
        }
    }

    // ---- lint ----

    /// A rule that throws is a finding, not a crash and not silence.
    static func guarded(_ rule: String, _ run: () throws -> [V]) -> [V] {
        do { return try run() } catch {
            return [finding("internal-error", "error", "rule \(rule) could not run: \((error as? JSError)?.message ?? "\(error)")")]
        }
    }

    struct Resolved {
        var overBroad: (enabled: Bool, dangerousVerbs: [String])
        var privilegeEscalation: Bool
        var redundantCaveat: Bool
        var reachability: (enabled: Bool, dangerousVerbs: [String], targets: [V])
        var floor: (enabled: Bool, requireExpiry: Bool, requireScopeGate: Bool)
    }

    static func resolveRules(_ rules: V?) throws -> Resolved {
        let r: V? = JS.present(rules)
        let ob = mem(r, "overBroadGrant"), dr = mem(r, "dangerousReachability"), sf = mem(r, "missingSafetyFloor")
        func list(_ v: V?) throws -> [String]? {
            guard let x = try objMember(v, "dangerousVerbs"), JS.truthy(x) else { return nil }
            guard case let .array(a) = x else { throw JSError("dangerous.some is not a function") }
            return try a.map { guard let t = $0.asString else { throw JSError("kw.toLowerCase is not a function") }; return t }
        }
        func isObj(_ v: V?) -> Bool { v?.isObject == true || v?.isArray == true || v == .null }
        let obVerbs = isObj(ob) ? try list(ob) : nil
        let drVerbs = isObj(dr) ? try list(dr) : nil
        var targets: [V] = []
        if isObj(dr), let t = try objMember(dr, "targets"), JS.truthy(t) { targets = A.arr(t) }
        var reqExpiry = true, reqGate = true
        if isObj(sf) {
            reqExpiry = try objMember(sf, "requireExpiry") != .bool(false)
            reqGate = try objMember(sf, "requireScopeGate") != .bool(false)
        }
        return Resolved(overBroad: (ob != .bool(false), obVerbs ?? DEFAULT_DANGEROUS_VERBS), privilegeEscalation: mem(r, "privilegeEscalation") != .bool(false),
                        redundantCaveat: mem(r, "redundantCaveat") != .bool(false), reachability: (dr != .bool(false), drVerbs ?? DEFAULT_DANGEROUS_VERBS, targets),
                        floor: (sf != .bool(false), reqExpiry, reqGate))
    }

    static func analyzerOpts(_ opts: V?) -> V {
        if let m = mem(opts, "maxCombinations") { return .object(["maxCombinations": m]) }
        return .object([:])
    }

    /// `opts.rules` where opts must not be null.
    static func optRules(_ opts: V?) throws -> V? {
        if opts == .null { throw JSError("cannot read properties of null (reading 'rules')") }
        return mem(opts, "rules")
    }

    static func single(_ cfg: Resolved, _ policy: Norm, _ ao: V) -> [V] {
        var out: [V] = []
        if cfg.overBroad.enabled { out += guarded("over-broad-grant") { try ruleOverBroadGrant(policy, cfg.overBroad.dangerousVerbs, ao) } }
        if cfg.redundantCaveat { out += guarded("redundant-caveat") { ruleRedundantCaveat(policy) } }
        if cfg.reachability.enabled { out += guarded("dangerous-reachability") { try ruleDangerousReachability(policy, cfg.reachability.dangerousVerbs, cfg.reachability.targets, ao) } }
        if cfg.floor.enabled { out += guarded("missing-safety-floor") { ruleMissingSafetyFloor(policy, requireExpiry: cfg.floor.requireExpiry, requireScopeGate: cfg.floor.requireScopeGate, cfg.overBroad.dangerousVerbs) } }
        return out
    }

    /// Lint one policy: an envelope, a minted grant, a compiled policy or a bare `{ predicates, caveats? }`. Empty = clean.
    static func lintPolicy(_ input: V?, _ opts: V? = nil) throws -> [V] {
        switch normalizedInput(input) {
        case let .fail(r): return [finding("malformed-policy", "error", r)]
        case let .ok(policy):
            let cfg = try resolveRules(try optRules(opts))
            let ao = analyzerOpts(opts)
            var out = single(cfg, policy, ao)
            if let schema = mem(opts, "schema") {
                out += guarded("schema-mismatch") { try ruleSchemaMismatch(policy, schema, mem(opts, "schemaOptions")) }
            }
            return out
        }
    }

    /// Lint a delegation chain: the escalation check across every consecutive pair, then the single-policy rules on the leaf.
    public static func lintChain(_ chain: [JSONValue], _ opts: JSONValue? = nil) throws -> [JSONValue] {
        switch normalizeChain(chain) {
        case let .fail(r): return [finding("malformed-policy", "error", r)]
        case let .ok(hops):
            let cfg = try resolveRules(try optRules(opts))
            let ao = analyzerOpts(opts)
            var out: [V] = []
            if cfg.privilegeEscalation { out += guarded("privilege-escalation") { try rulePrivilegeEscalation(hops, ao) } }
            if let leaf = hops.last { out += single(cfg, leaf, ao) }
            return out
        }
    }

    /// An array input is a delegation chain; anything else is a single policy.
    public static func lint(_ input: JSONValue?, _ opts: JSONValue? = nil) throws -> [JSONValue] {
        if case let .array(a)? = input { return try lintChain(a, opts) }
        return try lintPolicy(input, opts)
    }

    // ---- lintPolicies + summary ----

    public static func lintPolicies(_ items: JSONValue?, _ opts: JSONValue? = nil) throws -> JSONValue {
        guard case let .array(list)? = items else { throw JSError("items.map is not a function") }
        var results: [V] = []
        for (i, item) in list.enumerated() {
            if item == .null { throw JSError("cannot read properties of null (reading 'label')") }
            let label = JS.present(mem(item, "label")) ?? .string("policy[\(i)]")
            results.append(.object(["label": label, "findings": .array(try lint(mem(item, "policy"), opts))]))
        }
        return try summarize(.array(results), opts)
    }

    /// Roll labeled findings into counts + an exit-code mapping.
    static func summarize(_ results: V?, _ opts: V? = nil) throws -> V {
        if opts == .null { throw JSError("cannot read properties of null (reading 'maxSeverity')") }
        let ms = JS.present(mem(opts, "maxSeverity")) ?? .string("error")
        guard let sev = ms.asString, let threshold = SEVERITY_RANK.first(where: { IV.same($0.key, sev) })?.value else {
            throw JSError("summarize: maxSeverity must be one of info, warn, error")
        }
        func counts(_ e: Int, _ w: Int, _ i: Int) -> V { .object(["error": .int(Int64(e)), "warn": .int(Int64(w)), "info": .int(Int64(i))]) }
        guard case let .array(list)? = results, !list.isEmpty else {
            return .object(["results": .array([]), "counts": counts(0, 0, 0), "maxSeverity": .string(sev), "ok": .bool(false), "exitCode": .int(2), "reason": .string("no policies were linted")])
        }
        var c = (e: 0, w: 0, i: 0), failing = 0
        for r in list {
            if r == .null { throw JSError("cannot read properties of null (reading 'findings')") }
            guard case let .array(fs)? = mem(r, "findings") else { throw JSError("r.findings is not iterable") }
            for f in fs {
                if f == .null { throw JSError("cannot read properties of null (reading 'severity')") }
                var level = "error"
                if let fsev = mem(f, "severity")?.asString, SEVERITY_RANK.contains(where: { IV.same($0.key, fsev) }) { level = fsev }
                switch level { case "info": c.i += 1; case "warn": c.w += 1; default: c.e += 1 }
                if SEVERITY_RANK[level]! >= threshold { failing += 1 }
            }
        }
        let ok = failing == 0
        return .object(["results": .array(list), "counts": counts(c.e, c.w, c.i), "maxSeverity": .string(sev), "ok": .bool(ok), "exitCode": .int(ok ? 0 : 1)])
    }

    // ---- pinned lint rule list ----

    public static let LINT_RULES_DIGEST_DOMAIN = "atlas-pca/action-lint-rules/v1"

    /// The action-kit lint rule list, in order (order and wording are part of the pinned digest).
    public static let LINT_RULES: [(id: String, severity: String, title: String)] = [
        ("LD-001", "error", "a destroy-like verb whose effects do not delete"),
        ("LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format"),
        ("LD-003", "error", "a numeric parameter without min and max"),
        ("LD-004", "error", "a money-moving action without idempotency"),
        ("LD-005", "error", "personal data can leave without the matching effect"),
        ("LD-006", "error", "a declared reversibility or blast below the effective floor"),
        ("LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait"),
        ("LD-008", "error", "resource id '*' with scope one"),
        ("LD-009", "error", "a duplicate verb or alias collision"),
        ("LD-010", "error", "a write marked reversible with no compensating action in the pack"),
        ("LD-011", "error", "review state confirmed without a valid attestation for this digest"),
        ("LD-012", "error", "a structural param rule that the effective traits require is violated"),
        ("LD-013", "error", "a read-only action that can mutate or handles credentials"),
        ("LD-014", "error", "one binding in two defs"),
        ("LW-001", "warning", "description missing or too long, or title not imperative"),
        ("LW-002", "warning", "a string parameter without max_len"),
        ("LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag"),
        ("LW-004", "warning", "an unreviewed def in a stable pack"),
        ("LW-005", "warning", "a dismissed suggested trait without a reason"),
        ("LW-006", "warning", "an array parameter without max_items"),
        ("LW-007", "warning", "a critical parameter without provenance_min"),
        ("LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace"),
        ("LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example"),
        ("LW-010", "warning", "since is missing"),
    ]

    /// The digest the CI gate pins: the ordered (id, severity, title) list of the action-kit lint rules.
    static func lintRulesDigest() throws -> String {
        let rules: [V] = LINT_RULES.map { .object(["id": .string($0.id), "severity": .string($0.severity), "title": .string($0.title)]) }
        guard let h = IV.strictHash(.object(["d": .string(LINT_RULES_DIGEST_DOMAIN), "rules": .array(rules)])) else { throw JSError("lint rules digest: outside the strict JSON profile") }
        return h
    }

    /// Enforce the pinned digest of the lint rule list: `pinText` is the content of the pin file (one digest, surrounding whitespace
    /// ignored). An empty or malformed pin fails.
    public static func checkLintRulesPin(_ pinText: String, actual: String? = nil) throws -> JSONValue {
        let actual = try actual ?? lintRulesDigest()
        let pinned = Attest.jsTrim(pinText)
        let u = Array(pinned.unicodeScalars)
        let digestOk = u.count == 43 && u.allSatisfy { ($0.value >= 48 && $0.value <= 57) || ($0.value >= 65 && $0.value <= 90) || ($0.value >= 97 && $0.value <= 122) || $0 == "_" || $0 == "-" }
        if !digestOk { return .object(["ok": .bool(false), "message": .string("the lint rules pin is not a digest (expected 43 base64url characters)")]) }
        if IV.same(pinned, actual) { return .object(["ok": .bool(true), "message": .string("lint rules digest \(actual) matches the pin")]) }
        return .object(["ok": .bool(false), "message": .string("lint rules digest \(actual) differs from the pin \(pinned): the rule list changed; review it and update the pin")])
    }

    // ---- authoring gates ----

    static func result(_ ok: Bool, _ code: Int, _ lines: [String]) -> V { .object(["ok": .bool(ok), "exitCode": .int(Int64(code)), "lines": PCADataflow.strs(lines)]) }
    static func bad(_ line: String) -> V { result(false, 2, [line]) }

    enum AnalyzerPolicy {
        case ok(V)
        case fail(String)
        var json: V {
            switch self {
            case let .ok(p): return .object(["ok": .bool(true), "policy": p])
            case let .fail(r): return .object(["ok": .bool(false), "reason": .string(r)])
            }
        }
    }

    /// A policy document as the analyzer reads it: any shape `lint` accepts, plus optional `vetoes` and `tighten` members.
    /// The reference's `toAnalyzerPolicy` as its result record: `{ok: true, policy: {predicates, caveats, vetoes?, tighten?}}` or `{ok: false, reason}`.
    public static func toAnalyzerPolicy(_ doc: JSONValue?) -> JSONValue { analyzerPolicy(doc).json }
    static func analyzerPolicy(_ doc: V?) -> AnalyzerPolicy {
        switch normalizedInput(doc) {
        case let .fail(r): return .fail(r)
        case let .ok(n):
            var o: JObject = ["predicates": .array(n.predicates), "caveats": .array(n.caveats)]
            if isRecord(doc) {
                if let v = mem(doc, "vetoes"), v.isArray { o["vetoes"] = v }
                if let t = mem(doc, "tighten"), t.isArray { o["tighten"] = t }
            }
            return .ok(.object(o))
        }
    }

    /// `diff`: does this change widen authority or raise the most that can leave? (exit 0 ok, 1 a gate failed, 2 unusable input)
    public static func diffCommand(_ oldDoc: JSONValue?, _ newDoc: JSONValue?, _ o: JSONValue? = nil) throws -> JSONValue {
        let a = analyzerPolicy(oldDoc), b = analyzerPolicy(newDoc)
        guard case let .ok(pa) = a else { if case let .fail(r) = a { return bad("old policy: \(r)") }; return bad("old policy") }
        guard case let .ok(pb) = b else { if case let .fail(r) = b { return bad("new policy: \(r)") }; return bad("new policy") }
        if o == .null { throw JSError("cannot read properties of null (reading 'verb')") }
        var dopts: V = .object([:])
        if let verb = mem(o, "verb") {
            var e: JObject = ["verb": verb]
            if let f = mem(o, "amountField"), JS.truthy(f) { e["amountField"] = f }
            if let i = mem(o, "integer"), JS.truthy(i) { e["integer"] = .bool(true) }
            if let w = mem(o, "windowSecs") { e["windowSecs"] = w }
            dopts = .object(["exposure": .object(e)])
        }
        let d = try A.diffPolicies(pa, pb, dopts)
        var gopts: JObject = ["widen": .bool(mem(o, "allowWiden") == .bool(true))]
        if let m = mem(o, "maxExposureIncrease") { gopts["maxExposureIncrease"] = m }
        let gate = try A.diffGate(d, .object(gopts))
        let summary = A.arr(mem(d, "summary"))
        var lines: [String] = JS.truthy(mem(d, "equivalent")) ? ["no change in what is admitted"] : !summary.isEmpty ? summary.map { s($0) } : ["no witness found"]
        let gateOk = JS.truthy(mem(gate, "ok"))
        if !gateOk { lines += A.arr(mem(gate, "reasons")).map { "FAIL: \(s($0))" } }
        lines.append(gateOk ? "PASS" : "FAIL")
        return result(gateOk, gateOk ? 0 : 1, lines)
    }

    /// `test`: a policy test document against a policy, pinned by digest.
    public static func testCommand(_ policyDoc: JSONValue?, _ testsDoc: JSONValue?, _ o: JSONValue? = nil) throws -> JSONValue {
        let p = analyzerPolicy(policyDoc)
        guard case let .ok(policy) = p else { if case let .fail(r) = p { return bad("policy: \(r)") }; return bad("policy") }
        guard isRecord(testsDoc), IV.same(mem(testsDoc, "kind")?.asString, "pca-policy-tests"), mem(testsDoc, "cases")?.isArray == true else { return bad("tests: not a pca-policy-tests document") }
        if o == .null { throw JSError("cannot read properties of null (reading 'requireDigest')") }
        let requireDigest = mem(o, "requireDigest")
        let r = try A.runPolicyTests(policy, testsDoc, requireDigest.map { .object(["requireDigest": $0]) } ?? .object([:]))
        var lines: [String] = []
        for f in A.arr(mem(r, "failures")) {
            let by = JS.truthy(mem(f, "expectedDecidedBy")) ? " by \(s(mem(f, "expectedDecidedBy")))" : ""
            let got = JS.present(mem(f, "decidedBy")).map { s($0) } ?? "no clause"
            lines.append("FAIL \(s(mem(f, "name"))): expected \(s(mem(f, "expected")))\(by), got \(s(mem(f, "got"))) by \(got)")
        }
        if !JS.truthy(mem(r, "digestMatch")) {
            lines.append("\(JS.truthy(requireDigest) ? "FAIL" : "note"): the policy differs from the one the examples were confirmed against")
        }
        let ok = JS.truthy(mem(r, "ok"))
        lines.append("\(s(mem(r, "passed")))/\(s(mem(r, "total"))) examples \(ok ? "PASS" : "FAIL")")
        return result(ok, ok ? 0 : 1, lines)
    }

    /// `x.toFixed(0)` of a non-negative number: the integer nearest to it, a tie going to the larger.
    static func toFixed0(_ d: Double) -> String { d.isFinite ? JS.number(d.rounded(.toNearestOrAwayFromZero)) : JS.number(d) }

    /// The member order of an action the analyzer produces (its JSON text keeps it).
    static let ACTION_ORDER = ["verb", "resource", "params", "reversibilityClass", "subject", "env"]

    /// `coverage`: which clauses and thresholds the traffic never exercises, and which mutations of the policy it cannot tell apart.
    public static func coverageCommand(_ policyDoc: JSONValue?, _ trafficDoc: JSONValue?, _ o: JSONValue? = nil) throws -> JSONValue {
        let p = analyzerPolicy(policyDoc)
        guard case let .ok(policy) = p else { if case let .fail(r) = p { return bad("policy: \(r)") }; return bad("policy") }
        // traffic: an array of actions, or a pca-policy-tests document (its cases are the traffic)
        var actions: [V]?
        if case let .array(a)? = trafficDoc { actions = a }
        else if isRecord(trafficDoc), case let .array(cases)? = mem(trafficDoc, "cases") { actions = cases.map { isRecord($0) ? (mem($0, "action") ?? .null) : $0 } }
        // an absent `action` member reads as undefined, which is not a record: the same refusal
        guard let acts = actions, !acts.contains(where: { !isRecord($0) || mem($0, "verb")?.asString == nil || mem($0, "resource")?.asString == nil }) else {
            return bad("traffic: expected an array of {verb, resource, params?} actions or a pca-policy-tests document")
        }
        if o == .null { throw JSError("cannot read properties of null (reading 'minClauses')") }
        let r = try A.coverage(policy, .array(acts), nil)
        var g: JObject = [:]
        for (src, dst) in [("minClauses", "clauses"), ("minBoundaries", "boundaries"), ("minMutation", "mutation"), ("maxSurvivors", "maxSurvivors")] {
            if let v = mem(o, src) { g[JKey(dst)] = v }
        }
        let gate = try A.coverageGate(r, .object(g))
        func pct(_ k: String) -> String { toFixed0((A.fin(mem(mem(r, "score"), k)) ?? .nan) * 100) }
        let m = mem(r, "mutants")
        let total = (A.fin(mem(m, "total")) ?? .nan) - (A.fin(mem(m, "equivalent")) ?? .nan)
        var lines = ["clauses decisive \(pct("clauses"))%, boundaries covered \(pct("boundaries"))%, mutants killed \(pct("mutation"))% (\(s(mem(m, "killed")))/\(JS.number(total)))"]
        lines += A.arr(mem(r, "untested")).map { "untested: \(s($0))" }
        for sv in A.arr(mem(m, "survivors")) {
            let killer = mem(sv, "killer")
            lines.append("survives: \(s(mem(sv, "description")))\(JS.truthy(killer) ? " (kill with \(JS.stringify(killer ?? .null, order: ACTION_ORDER)))" : "")")
        }
        lines += A.arr(mem(gate, "reasons")).map { "FAIL: \(s($0))" }
        let ok = JS.truthy(mem(gate, "ok"))
        lines.append(ok ? "PASS" : "FAIL")
        return result(ok, ok ? 0 : 1, lines)
    }
}
