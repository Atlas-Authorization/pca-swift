import Foundation

/// mulberry32, the seeded generator behind every generated case of the invariant checks: the same seed always yields the same sequence,
/// so a failing case is reproducible from `(seed, run index)`. No randomness from the platform is used.
public final class PCAInvariantRng {
    private var a: UInt32

    public init(_ seed: Int64) { a = UInt32(truncatingIfNeeded: seed) }

    /// A double in [0, 1).
    public func next() -> Double {
        a = a &+ 0x6d2b79f5
        var t = a
        t = (t ^ (t >> 15)) &* (t | 1)
        t = t ^ (t &+ (t ^ (t >> 7)) &* (t | 61))
        return Double(t ^ (t >> 14)) / 4294967296.0
    }

    /// An integer in [lo, hi] inclusive.
    public func integer(_ lo: Int64, _ hi: Int64) -> Int64 { lo + Int64((next() * Double(hi - lo + 1)).rounded(.down)) }

    public func bool() -> Bool { next() < 0.5 }

    public func pick<T>(_ xs: [T]) -> T { xs[Int(integer(0, Int64(xs.count - 1)))] }

    public func bytes(_ n: Int) -> [UInt8] { (0..<n).map { _ in UInt8(integer(0, 255)) } }

    /// A double in [lo, hi], with the endpoints drawn on their own about one time in ten each.
    public func real(_ lo: Double, _ hi: Double) -> Double {
        let x = next()
        if x < 0.1 { return lo }
        if x < 0.2 { return hi }
        return lo + next() * (hi - lo)
    }

    /// A printable-ASCII string of `min...max` characters.
    public func string(_ min: Int, _ max: Int) -> String {
        let n = Int(integer(Int64(min), Int64(max)))
        var s = ""
        for _ in 0..<n { s.unicodeScalars.append(Unicode.Scalar(UInt8(integer(0x20, 0x7e)))) }
        return s
    }
}

/// Generators of WELL-FORMED random inputs for the PCA core, driven by a seeded `PCAInvariantRng` (the shapes of the reference's
/// property-test arbitraries). Everything is plain data fed to the real core.
extension PCAInvariants {
    static let VERBS = ["read", "write", "delete", "transfer", "list", "admin"]
    static let RESOURCES = ["/acct/a", "/acct/b", "/docs/1", "/docs/2", "/x/y", "/"]
    static let LEAF_OPS = ["eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists"]
    static let LEAF_FIELDS = ["subject.role", "subject.tier", "env.ip", "action.verb", "action.resource", "action.params.amount"]
    static let REVERSIBILITY = ["reversible", "rate_limited", "irreversible", "teleport"]

    /// `n` items from `f`, n drawn first (the reference draws the length before the elements).
    static func times(_ n: Int64, _ f: () -> JSONValue) -> [JSONValue] {
        var out: [JSONValue] = []
        var i = n
        while i > 0 { out.append(f()); i -= 1 }
        return out
    }

    static func jint(_ v: Int64) -> JSONValue { .int(v) }

    /// 32 random bytes: a reproducible Ed25519 secret seed.
    public static func arbSeed32(_ r: PCAInvariantRng) -> [UInt8] { r.bytes(32) }

    public static func arbKeyPair(_ r: PCAInvariantRng) throws -> KeyPair { try keyPairFromSeed(arbSeed32(r)) }

    public static func arbVerb(_ r: PCAInvariantRng) -> String { r.pick(VERBS) }

    public static func arbResource(_ r: PCAInvariantRng) -> String { r.bool() ? r.pick(RESOURCES) : r.string(0, 10) }

    /// A known-operator leaf comparison (a decidable, well-formed condition).
    public static func arbLeafCondition(_ r: PCAInvariantRng) -> JSONValue {
        let value: JSONValue
        switch r.integer(0, 3) {
        case 0: value = .string(r.string(0, 10))
        case 1: value = .int(r.integer(-10, 10))
        case 2: value = .bool(r.bool())
        default: value = .array(times(r.integer(0, 3)) { .string(r.string(0, 10)) })
        }
        return .object(["field": .string(r.pick(LEAF_FIELDS)), "op": .string(r.pick(LEAF_OPS)), "value": value])
    }

    public static func arbCondition(_ r: PCAInvariantRng) -> JSONValue { arbLeafCondition(r) }

    public static func arbPredicate(_ r: PCAInvariantRng) -> JSONValue {
        let verb: JSONValue
        switch r.integer(0, 2) {
        case 0: verb = .string(arbVerb(r))
        case 1: verb = .array(times(r.integer(1, 3)) { .string(arbVerb(r)) })
        default: verb = .string("*")
        }
        var p: JObject = ["verb": verb]
        switch r.integer(0, 4) {
        case 0: break // resource absent
        case 1: p["resource"] = .string("*")
        case 2: p["resource"] = .string(r.pick(["/acct/*", "/docs/*"]))
        default: p["resource"] = .string(arbResource(r))
        }
        if r.bool() { p["where"] = .array(times(r.integer(0, 2)) { arbCondition(r) }) }
        return .object(p)
    }

    public static func arbPredicateList(_ r: PCAInvariantRng) -> JSONValue { .array(times(r.integer(1, 4)) { arbPredicate(r) }) }

    public static func arbActionContext(_ r: PCAInvariantRng) -> JSONValue {
        var action: JObject = ["verb": .string(arbVerb(r)), "resource": .string(arbResource(r))]
        if r.bool() {
            var params: JObject = [:]
            for k in ["amount", "target", "reason"] {
                if params.count >= 3 || !r.bool() { continue }
                switch r.integer(0, 2) {
                case 0: params[JKey(k)] = .string(r.string(0, 10))
                case 1: params[JKey(k)] = .int(r.integer(-5, 100))
                default: params[JKey(k)] = .bool(r.bool())
                }
            }
            action["params"] = .object(params)
        }
        let role = r.pick(["admin", "user", "guest"])
        let tier = r.integer(0, 5)
        let ip = r.string(0, 10)
        let withSubject = r.bool()
        let withEnv = r.bool()
        var ctx: JObject = ["action": .object(action)]
        if withSubject { ctx["subject"] = .object(["role": .string(role), "tier": .int(tier)]) }
        if withEnv { ctx["env"] = .object(["ip": .string(ip)]) }
        return .object(ctx)
    }

    public static func arbCaveatContext(_ r: PCAInvariantRng) -> JSONValue {
        var ctx: JObject = ["now": .int(r.integer(0, 10_000_000))]
        if r.bool() { ctx["blast_radius"] = number(r.real(0, 1)) }
        if r.bool() { ctx["reversibility_class"] = .string(r.pick(REVERSIBILITY)) }
        if r.bool() { ctx["delegation_depth"] = .int(r.integer(0, 20)) }
        if r.bool() { ctx["recent_action_times"] = .array(times(r.integer(0, 6)) { .int(r.integer(0, 10_000_000)) }) }
        return .object(ctx)
    }

    /// An action context and a caveat context together: one point at which to probe a chain's effective authority.
    public static func arbEvalPoint(_ r: PCAInvariantRng) -> JSONValue {
        let action = arbActionContext(r)
        return .object(["action": action, "cavCtx": arbCaveatContext(r)])
    }

    /// A well-formed, built-in, evaluator-decidable caveat spec; `budget_frac` becomes a monotone non-increasing allocation.
    public static func arbCaveatSpec(_ r: PCAInvariantRng) -> JSONValue {
        switch r.integer(0, 6) {
        case 0: return .object(["k": .string("expires"), "at": .int(r.integer(0, 10_000_000))])
        case 1: return .object(["k": .string("not_before"), "at": .int(r.integer(0, 10_000_000))])
        case 2:
            let max = r.integer(1, 10)
            return .object(["k": .string("rate"), "max": .int(max), "per_secs": .int(r.integer(1, 3600))])
        // quantized to 3 decimals so the limit is canonical-wire-safe
        case 3: return .object(["k": .string("max_blast_radius"), "max": number(Double(r.integer(0, 1000)) / 1000)])
        case 4: return .object(["k": .string("reversibility_max"), "cls": .string(r.pick(["reversible", "rate_limited", "irreversible"]))])
        case 5: return .object(["k": .string("delegation_depth"), "max": .int(r.integer(0, 20))])
        default: return .object(["k": .string("budget_frac"), "frac": number(r.real(0, 1))])
        }
    }

    static func specs(_ r: PCAInvariantRng, _ lo: Int64, _ hi: Int64) -> [JSONValue] { times(r.integer(lo, hi)) { arbCaveatSpec(r) } }

    /// A chain model for `buildChain`.
    public static func arbChainModel(_ r: PCAInvariantRng) -> ChainModel {
        let principal = arbSeed32(r)
        let holder0 = arbSeed32(r)
        let rootSpecs = specs(r, 1, 4)
        var hops: [Hop] = []
        var n = r.integer(0, 5)
        while n > 0 { let s = arbSeed32(r); hops.append(Hop(holderSeed: s, addedSpecs: specs(r, 0, 3))); n -= 1 }
        return ChainModel(principalSeed: principal, holder0Seed: holder0, rootSpecs: rootSpecs, hops: hops, predicates: arbPredicateList(r))
    }

    public static func arbChain(_ r: PCAInvariantRng) throws -> Chain { try buildChain(arbChainModel(r)) }

    public static func arbRiskWeights(_ r: PCAInvariantRng) -> JSONValue {
        .object(["alpha": number(r.real(0, 2)), "beta": number(r.real(0, 2)), "gamma": number(r.real(0, 2)),
                 "delta": number(r.real(0, 2)), "epsilon": number(r.real(0, 2)), "zeta": number(r.real(0, 2))])
    }

    /// A well-formed risk policy (passes the core validation): kappa > 0, 0 <= theta1 <= theta2, the rest finite and >= 0.
    public static func arbRiskPolicy(_ r: PCAInvariantRng) -> JSONValue {
        let w = arbRiskWeights(r)
        let theta1 = r.real(0, 1)
        let gap = r.real(0, 1)
        let kappa = r.real(0.001, 5)
        let lambda = r.real(0, 0.01)
        let rho = r.real(0, 2)
        return .object(["weights": w, "theta1": number(theta1), "theta2": number(theta1 + gap), "kappa": number(kappa),
                        "lambda": number(lambda), "rho": number(rho), "bMax": number(r.real(0, 10))])
    }

    public static func arbRiskInputs(_ r: PCAInvariantRng) -> JSONValue {
        .object(["semanticDistance": number(r.real(0, 1)), "reversibility": number(r.real(0, 1)), "blastRadius": number(r.real(0, 1)),
                 "taint": number(r.real(0, 1)), "confidence": number(r.real(0, 1)), "age": number(r.real(0, 1))])
    }

    public static func arbTrustBudget(_ r: PCAInvariantRng) -> JSONValue {
        var b: JObject = ["B": number(r.real(0, 10)), "tau": .int(r.integer(0, 10_000_000))]
        if r.bool() { b["asOf"] = .int(r.integer(0, 10_000_000)) }
        return .object(b)
    }

    /// Non-negative deltas for a pointwise-worse risk input (the monotonicity property).
    public static func arbRiskDeltas(_ r: PCAInvariantRng) -> JSONValue {
        .object(["dSem": number(r.real(0, 1)), "dBlast": number(r.real(0, 1)), "dTaint": number(r.real(0, 1)),
                 "dAge": number(r.real(0, 1)), "dRev": number(r.real(0, 1)), "dConf": number(r.real(0, 1))])
    }
}

/// The PCA core safety invariants as seeded property checks: each `*Property` runs ONE generated case from a `PCAInvariantRng` and
/// returns true when the invariant holds (any violation is false); `run` repeats it `numRuns` times from a fixed seed and fails with the
/// failing run index. Every property feeds the REAL core (chain verification, predicate and caveat evaluation, the risk functional and
/// admission, forbid-wins).
extension PCAInvariants {
    static let EPS = 1e-9

    static func d(_ v: JSONValue?) throws -> Double {
        guard let x = IV.num(v) else { throw JSError("invariants: expected a number") }
        return x
    }

    static func chainOk(_ caps: [JSONValue], _ rootIssuer: String?) -> Bool { Capability.verifyChain(caps, expectedRootIssuer: rootIssuer) == nil }

    static func riskOf(_ inputs: JSONValue, _ weights: JSONValue) -> Double {
        let o = inputs.asObject ?? [:]
        return Risk.riskScore(Risk.KEYS.map { IV.num(o[JKey($0)]) }, weights: weights.asObject ?? [:])
    }

    static func threshold(_ r: Double, _ theta1: Double, _ theta2: Double) -> Int { Risk.requiredThreshold(r, theta1: theta1, theta2: theta2).t }

    static func admit(_ r: Double, _ budgetB: Double, _ theta1: Double, _ theta2: Double, _ kappa: Double) -> Risk.Admission {
        Risk.admit(t: threshold(r, theta1, theta2), covers: budgetB >= Risk.cost(r, kappa: kappa))
    }

    /// Envelope predicates AND every caveat satisfied, at a probe point.
    static func authAllowed(_ caveats: JSONValue?, _ predicates: JSONValue, _ pt: JSONValue) -> Bool {
        Predicates.evaluate(predicates, pt.get("action") ?? .null) && PCA.evaluateCaveats(caveats, context: pt.get("cavCtx") ?? .null).ok
    }

    static func prefixExtension(_ parent: JSONValue, _ child: JSONValue) -> Bool {
        let pc = parent.get("caveats")?.asArray ?? [], cc = child.get("caveats")?.asArray ?? []
        if cc.count < pc.count { return false }
        for j in pc.indices where Canonical.hashCanonical(cc[j]) != Canonical.hashCanonical(pc[j]) { return false }
        return true
    }

    /// For any legal chain: it verifies; each hop's caveats extend its parent's append-only; budget_alloc limits are monotone
    /// non-increasing; at every probe point the per-hop allowed verdict is monotone non-increasing root to leaf.
    public static func attenuationMonotonicityProperty(_ r: PCAInvariantRng) throws -> Bool {
        let chain = try arbChain(r)
        var points: [JSONValue] = []
        var i = r.integer(1, 5)
        while i > 0 { points.append(arbEvalPoint(r)); i -= 1 }
        let caps = chain.caps
        if !chainOk(caps, chain.rootIssuer) { return false }
        for k in 1..<max(caps.count, 1) where !prefixExtension(caps[k - 1], caps[k]) { return false }
        let leaf = caps[caps.count - 1]
        if Capability.allocationsMonotoneError(leaf.get("caveats")) != nil { return false }
        var prev = Double.nan
        for cv in leaf.get("caveats")?.asArray ?? [] {
            if cv.get("type")?.asString != "budget_alloc" { continue }
            guard let cur = IV.num(cv.get("limit")) else { continue }
            if !prev.isNaN && cur > prev { return false }
            prev = cur
        }
        for pt in points {
            var ancestorAllowed = true
            for cap in caps {
                let allowed = authAllowed(cap.get("caveats"), chain.predicates, pt)
                if allowed && !ancestorAllowed { return false } // a true after a false would be a widening
                ancestorAllowed = allowed
            }
        }
        return true
    }

    /// r is clamped to [0, 1] and monotone: a pointwise-worse input never yields a lower r.
    public static func riskMonotoneProperty(_ r: PCAInvariantRng) throws -> Bool {
        let policy = arbRiskPolicy(r), inputs = arbRiskInputs(r), deltas = arbRiskDeltas(r)
        let w = policy.get("weights") ?? .null
        let risk = riskOf(inputs, w)
        if !(risk >= 0 && risk <= 1) { return false }
        let worse = riskOf(try worsen(inputs, deltas), w)
        if !(worse >= 0 && worse <= 1) { return false }
        return worse + EPS >= risk
    }

    /// Whenever admit lets an action proceed without a human, the admitted cost kappa*r is covered by the budget.
    public static func admissionSoundnessProperty(_ r: PCAInvariantRng) throws -> Bool {
        let policy = arbRiskPolicy(r), inputs = arbRiskInputs(r), budget = arbTrustBudget(r)
        if PCA.validateRiskPolicy(policy) != nil { return false }
        let risk = riskOf(inputs, policy.get("weights") ?? .null)
        let kappa = try d(policy.get("kappa")), b = try d(budget.get("B"))
        let c = Risk.cost(risk, kappa: kappa)
        let adm = admit(risk, b, try d(policy.get("theta1")), try d(policy.get("theta2")), kappa)
        if adm.metered {
            if adm.t >= 3 { return false }
            if !(b + EPS >= c) { return false }
        }
        if adm.admit {
            if adm.t != 1 || !adm.metered { return false }
            if !(b + EPS >= c) { return false }
        }
        return true
    }

    /// Starting from a full budget, machine-only actions debit kappa*r each: B never goes negative and Sum(r) <= bMax/kappa.
    public static func cumulativeBudgetBoundProperty(_ r: PCAInvariantRng) throws -> Bool {
        let policy = arbRiskPolicy(r)
        var seq: [JSONValue] = []
        var i = r.integer(1, 40)
        while i > 0 { seq.append(arbRiskInputs(r)); i -= 1 }
        let kappa = try d(policy.get("kappa")), bMax = try d(policy.get("bMax"))
        let bound = kappa > 0 ? max(0, bMax) / kappa : 0
        let th1 = try d(policy.get("theta1")), th2 = try d(policy.get("theta2"))
        var budget = max(0, bMax)
        var sumR = 0.0
        for inputs in seq {
            let risk = riskOf(inputs, policy.get("weights") ?? .null)
            let adm = admit(risk, budget, th1, th2, kappa)
            if adm.metered && adm.t < 3 {
                let c = Risk.cost(risk, kappa: kappa)
                if !(budget + EPS >= c) { return false }
                budget = max(0, budget - c)
                sumR += risk
                if budget < -EPS { return false }
                if !(kappa * sumR <= bMax + 1e-6) { return false }
                if !(sumR <= bound + 1e-6) { return false }
            }
        }
        return true
    }

    static let KNOWN_CAVEAT_TYPES: Set<String> = ["expires", "not_before", "rate", "max_blast_radius", "reversibility_max", "delegation_depth",
                                                  "budget_alloc", "max_spend", "intent_session"]

    /// Every structurally undecidable (but well-typed) leaf evaluates to unknown, never true, so a predicate carrying it never grants.
    public static func undecidableLeafFailsClosedProperty(_ r: PCAInvariantRng) -> Bool {
        let pick = r.integer(0, 4)
        let verb = r.pick(["read", "write", "delete"])
        let f = "subject.role"
        let leaf: JSONValue
        switch pick {
        case 0: leaf = .object(["field": .string("\(f).definitely_absent"), "op": .string("eq"), "value": .string("x")]) // missing field
        case 1: leaf = .object(["field": .string(f), "op": .string("lt"), "value": .int(5)]) // string field vs number: incomparable
        case 2: leaf = .object(["field": .string(f), "op": .string("in"), "value": .string("not-an-array")]) // non-array operand
        case 3: leaf = .object(["field": .string(f), "op": .string("eq")]) // no value and no ref
        default: leaf = .object(["field": .string(f), "op": .string("member_of"), "value": .string("g"), "collection": .string("env.no_such_collection")])
        }
        let ctx: JSONValue = .object(["action": .object(["verb": .string(verb), "resource": .string("/x")]), "subject": .object(["role": .string("admin")])])
        if Predicates.conditionTri(leaf, ctx, SafeRegex.Budget()) == .t { return false }
        let preds: JSONValue = .array([.object(["verb": .string(verb), "resource": .string("/x"), "where": .array([leaf])])])
        return !Predicates.evaluate(preds, ctx)
    }

    /// A not / all_of / any_of built over undecidable or empty children fails closed (never true).
    public static func undecidableGroupsFailClosedProperty(_ r: PCAInvariantRng) -> Bool {
        let ctx: JSONValue = .object(["action": .object(["verb": .string("read"), "resource": .string("/x")]), "subject": .object(["role": .string("admin")])])
        let child: JSONValue = .object(["field": .string("subject.role"), "op": .string("lt"), "value": .int(5)])
        let groups: [JSONValue] = [.object(["not": child]), .object(["all_of": .array([])]), .object(["any_of": .array([])]),
                                   .object(["all_of": .array([child])]), .object(["any_of": .array([child])])]
        for g in groups where Predicates.conditionTri(g, ctx, SafeRegex.Budget()) == .t { return false }
        return true
    }

    /// member_of over a cyclic adjacency terminates with the correct verdict: reachable targets true, an unreachable one false.
    public static func memberOfCycleSafeProperty(_ r: PCAInvariantRng) -> Bool {
        let target = r.pick(["a", "b", "c", "z"])
        let rel: JSONValue = .object(["a": .array([.string("b")]), "b": .array([.string("a"), .string("c")])])
        let ctx: JSONValue = .object(["action": .object(["verb": .string("read"), "resource": .string("/x")]), "subject": .object(["g": .string("a")]),
                                      "env": .object(["rel": rel])])
        let tri = Predicates.conditionTri(.object(["field": .string("subject.g"), "op": .string("member_of"), "value": .string(target),
                                                   "collection": .string("env.rel")]), ctx, SafeRegex.Budget())
        return tri == (["a", "b", "c"].contains(target) ? .t : .f)
    }

    /// An unknown caveat TYPE is never satisfied, so a caveat set containing it is never ok.
    public static func unknownCaveatTypeDeniesProperty(_ r: PCAInvariantRng) -> Bool {
        var type: String
        repeat { type = r.string(1, 12) } while KNOWN_CAVEAT_TYPES.contains(type)
        let now = r.integer(0, 10_000_000)
        return !PCA.evaluateCaveats(.array([.object(["type": .string(type)])]), context: .object(["now": .int(now)])).ok
    }

    static let ALL_MUTATIONS = ["tamper-caveat", "drop-leaf-caveat", "swap-holder", "break-parent", "bad-sig", "wrong-root-issuer", "suite-mismatch",
                                "break-id", "append-forged-hop"]

    static func with(_ cap: JSONValue, _ key: String, _ v: JSONValue) -> JSONValue {
        var o = cap.asObject ?? [:]
        o[JKey(key)] = v
        return .object(o)
    }

    /// Every forged chain (nine distinct attacks on a legal one) fails verification.
    public static func forgedChainRejectedProperty(_ r: PCAInvariantRng) throws -> Bool {
        let chain = try arbChain(r)
        let mutation = r.pick(ALL_MUTATIONS)
        let pick = r.integer(0, 1_000_000)
        let aux = try arbKeyPair(r)
        let caps = chain.caps
        let root = chain.rootIssuer
        if !chainOk(caps, root) { return false }
        let n = caps.count
        let idx = Int(pick) % n
        var m = caps
        switch mutation {
        case "tamper-caveat":
            m[idx] = with(m[idx], "caveats", .array((m[idx].get("caveats")?.asArray ?? []) + [.object(["type": .string("expires"), "at": .int(999)])]))
            return !chainOk(m, root)
        case "drop-leaf-caveat":
            let cv = m[n - 1].get("caveats")?.asArray ?? []
            if cv.isEmpty { return true } // inapplicable: trivially pass
            m[n - 1] = with(m[n - 1], "caveats", .array(Array(cv.dropLast())))
            return !chainOk(m, root)
        case "swap-holder":
            m[idx] = with(m[idx], "holder", .string(aux.pub)) // changes the signed body: digest mismatch
            return !chainOk(m, root)
        case "break-parent":
            if n < 2 { return true } // no non-root hop to detach
            let j = max(1, idx)
            m[j] = with(m[j], "parent", .string(Canonical.hashCanonical(.object(["bogus": .int(32), "tag": .string("not-a-real-parent")]))))
            return !chainOk(m, root)
        case "bad-sig":
            // a well-formed but wrong signature: over different bytes, by a different key
            m[idx] = with(m[idx], "sig", .string(Base64URLStrict.encode(try aux.key.sign([1, 2, 3, 4]))))
            return !chainOk(m, root)
        case "wrong-root-issuer":
            if aux.pub == root { return true } // negligibly rare key collision: skip
            return !chainOk(caps, aux.pub)
        case "suite-mismatch":
            m[idx] = with(m[idx], "alg", .string("ml-dsa-65")) // the suite fields are bound into body_digest
            return !chainOk(m, root)
        case "break-id":
            m[idx] = with(m[idx], "id", .string(Canonical.hashCanonical(.object(["not": .string("the-body-digest"), "n": .int(Int64(idx))]))))
            return !chainOk(m, root)
        default: // append-forged-hop: issued as if from the leaf, but signed by a key that is NOT the leaf's holder
            let forged = try PCAIssue.delegate(parent: caps[n - 1], toHolder: aux.pub, added: [], signer: .ed25519(aux.key))
            m.append(forged)
            return !chainOk(m, root)
        }
    }

    /// Well-typed but never-signed "capabilities" (random fields) never verify; neither does the empty chain.
    public static func garbageChainRejectedProperty(_ r: PCAInvariantRng) -> Bool {
        var garbage: [JSONValue] = []
        var i = r.integer(0, 4)
        while i > 0 {
            var cv: [JSONValue] = []
            var j = r.integer(0, 3)
            while j > 0 { cv.append(.object(["type": .string(r.string(0, 10))])); j -= 1 }
            let id = r.string(0, 10), issuer = r.string(0, 10), holder = r.string(0, 10), digest = r.string(0, 10)
            garbage.append(.object(["id": .string(id), "issuer": .string(issuer), "holder": .string(holder), "caveats": .array(cv),
                                    "body_digest": .string(digest), "sig": .string(r.string(0, 10))]))
            i -= 1
        }
        return Capability.verifyChain(garbage, expectedRootIssuer: nil) != nil
    }

    /// verifyChain, evaluatePredicates, evaluateCaveats, riskScore, the threshold band and admit are all deterministic.
    public static func determinismProperty(_ r: PCAInvariantRng) throws -> Bool {
        let chain = try arbChain(r)
        let pt = arbEvalPoint(r), preds = arbPredicateList(r), policy = arbRiskPolicy(r), inputs = arbRiskInputs(r), budget = arbTrustBudget(r)
        let caps = chain.caps, root = chain.rootIssuer
        if Capability.verifyChain(caps, expectedRootIssuer: root) != Capability.verifyChain(caps, expectedRootIssuer: root) { return false }
        let ctx = pt.get("action") ?? .null
        if Predicates.evaluate(preds, ctx) != Predicates.evaluate(preds, ctx) { return false }
        let leaf = caps[caps.count - 1]
        let c1 = PCA.evaluateCaveats(leaf.get("caveats"), context: pt.get("cavCtx") ?? .null)
        let c2 = PCA.evaluateCaveats(leaf.get("caveats"), context: pt.get("cavCtx") ?? .null)
        if c1.ok != c2.ok || c1.failed != c2.failed { return false }
        let w = policy.get("weights") ?? .null
        let r1 = riskOf(inputs, w), r2 = riskOf(inputs, w)
        if r1.bitPattern != r2.bitPattern { return false }
        let th1 = try d(policy.get("theta1")), th2 = try d(policy.get("theta2")), kappa = try d(policy.get("kappa")), b = try d(budget.get("B"))
        if threshold(r1, th1, th2) != threshold(r1, th1, th2) { return false }
        return admit(r1, b, th1, th2, kappa) == admit(r1, b, th1, th2, kappa)
    }

    static func clauses(_ kind: String, _ ps: [JSONValue], _ tag: String) -> [JSONValue] {
        ps.enumerated().map { .object(["id": .string("\(tag)\($0.offset)"), "kind": .string(kind), "when": $0.element]) }
    }

    static func decisionRank(_ decision: String) -> Int { decision == "deny" ? 0 : decision == "escalate" ? 1 : 2 }

    /// Forbid-wins is monotone and order-independent: adding a forbid clause only moves a decision down, a matching forbid always denies
    /// whatever the permits say, and the decision does not depend on the order of the clauses.
    public static func forbidMonotoneProperty(_ r: PCAInvariantRng) -> Bool {
        let permits = arbPredicateList(r).asArray ?? [], forbids = arbPredicateList(r).asArray ?? [], extra = arbPredicateList(r).asArray ?? []
        let pt = arbEvalPoint(r)
        let rot = r.integer(0, 5)
        let ctx = pt.get("action") ?? .null
        let base = clauses("permit", permits, "p") + clauses("escalate", extra, "e")
        let withForbid = base + clauses("forbid", forbids, "f")
        let before = decisionRank(ForbidClauses.decideClauses(.array(base), ctx).decision)
        let afterDecision = ForbidClauses.decideClauses(.array(withForbid), ctx).decision
        if decisionRank(afterDecision) > before { return false } // adding a forbid must never grow the admit set
        if forbids.contains(where: { Prohibitions.whenMatches($0, ctx) }) && afterDecision != "deny" { return false } // a matching forbid beats every permit
        let k = Int(rot) % withForbid.count
        let rotated = Array(withForbid[k...]) + Array(withForbid[..<k])
        return ForbidClauses.decideClauses(.array(rotated), ctx).decision == afterDecision // order-independent
    }

    /// The twelve invariants by name, in registry order (the same names as `INVARIANT_NAMES`).
    public static let INVARIANTS: [(name: String, run: (PCAInvariantRng) throws -> Bool)] = [
        ("attenuation-monotonicity", { try attenuationMonotonicityProperty($0) }),
        ("risk-wellformed-and-monotone", { try riskMonotoneProperty($0) }),
        ("admission-soundness", { try admissionSoundnessProperty($0) }),
        ("cumulative-budget-bound", { try cumulativeBudgetBoundProperty($0) }),
        ("fail-closed:undecidable-leaf", { undecidableLeafFailsClosedProperty($0) }),
        ("fail-closed:undecidable-groups", { undecidableGroupsFailClosedProperty($0) }),
        ("fail-closed:member-of-cycle-safe", { memberOfCycleSafeProperty($0) }),
        ("fail-closed:unknown-caveat-type", { unknownCaveatTypeDeniesProperty($0) }),
        ("fail-closed:forged-chain-rejected", { try forgedChainRejectedProperty($0) }),
        ("fail-closed:garbage-chain-rejected", { garbageChainRejectedProperty($0) }),
        ("forbid-monotone", { forbidMonotoneProperty($0) }),
        ("determinism", { try determinismProperty($0) }),
    ]

    /// Run one property `numRuns` times from `seed`; throws naming the failing run (a property that throws fails too). The same
    /// (seed, numRuns) always generates the same cases.
    public static func run(_ property: (PCAInvariantRng) throws -> Bool, numRuns: Int64, seed: Int64) throws {
        let rng = PCAInvariantRng(seed)
        var i: Int64 = 0
        while i < numRuns {
            let ok: Bool
            do { ok = try property(rng) } catch { throw JSError("Property failed after \(i + 1) test(s) (seed \(seed)): threw \(error)") }
            if !ok { throw JSError("Property failed after \(i + 1) test(s) (seed \(seed))") }
            i += 1
        }
    }

    /// Machine-check every invariant: one result per invariant `{name, ok, numRuns, seed[, error]}`. `ok: false` with an `error` is a
    /// surfaced counterexample. A check that runs zero cases passes vacuously, so it is refused.
    public static func checkInvariants(numRuns numRunsOpt: Int64? = nil, seed seedOpt: Int64? = nil, bail: Bool = false) throws -> [JSONValue] {
        let numRuns = numRunsOpt ?? Int64(DEFAULT_NUM_RUNS), seed = seedOpt ?? Int64(DEFAULT_SEED)
        guard numRuns >= 1 && numRuns <= Canonical.MAX_SAFE else { throw JSError("checkInvariants: numRuns must be a positive integer") }
        guard abs(seed) <= Canonical.MAX_SAFE else { throw JSError("checkInvariants: seed must be an integer") }
        var results: [JSONValue] = []
        for inv in INVARIANTS {
            do {
                try run(inv.run, numRuns: numRuns, seed: seed)
                results.append(.object(["name": .string(inv.name), "ok": .bool(true), "numRuns": .int(numRuns), "seed": .int(seed)]))
            } catch {
                results.append(.object(["name": .string(inv.name), "ok": .bool(false), "numRuns": .int(numRuns), "seed": .int(seed), "error": .string("\(error)")]))
                if bail { break }
            }
        }
        return results
    }
}
