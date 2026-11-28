import Foundation

/// Quantitative and ternary static queries over a policy (the policy analyzer): the most that can ever be spent, the actions that
/// need a human, the reach of a delegation chain, a first-class diff of two policies and the check of an external solver's answer.
/// Everything sits on the same sound bounded enumeration as the rest of the analyzer; every witness is re-checked by the real
/// evaluator, and a number is exact only on the decided fragment (otherwise the result is marked `approximate`, erring high).
///
/// Policies, options and results are plain JSON trees; a missing member is `nil` (JavaScript `undefined`), `.null` is `null`, and a
/// reference TypeError is a thrown `JSError`.

/// The largest amount one verb can reach: `max` is a supremum no action reaches when `attained` is false.
fileprivate struct ExPeak {
    var admitted: Bool
    var max: Double
    var attained: Bool
    var witness: JSONValue?
    var json: JSONValue {
        PCAAnalyzer.obj([("admitted", .bool(admitted)), ("max", PCAAnalyzer.num(max)), ("attained", .bool(attained)), ("witness", witness)])
    }
    static let unbounded = ExPeak(admitted: true, max: .infinity, attained: false, witness: nil)
}

extension PCAAnalyzer {
    fileprivate static let exHuge = Double(Canonical.MAX_SAFE)
    fileprivate static let exWiden = ["deny->allow", "deny->escalate", "escalate->allow"]

    /// A number as JavaScript prints it (`${x}`).
    fileprivate static func exStr(_ d: Double) -> String { JS.toString(.double(d)) }
    /// `Math.max` / `Math.min` of two numbers (NaN wins).
    fileprivate static func exMax(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : Swift.max(a, b) }
    fileprivate static func exMin(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : Swift.min(a, b) }
    fileprivate static func exCeil(_ d: Double) -> Double { d.rounded(.up) }
    fileprivate static func exReason(_ overflow: Bool, _ undecidable: [String]) -> String {
        overflow ? "representative grid exceeded the bound" : "over-approximated (" + undecidable.joined(separator: "; ") + ")"
    }
    /// A `limit` argument as the count `hits.length >= limit` reaches (a limit under 1 still stops at the first hit).
    fileprivate static func exLimit(_ v: V?, _ dflt: Double) -> Int {
        let l = JS.toNumber(JS.present(v) ?? .double(dflt))
        if l.isNaN || l >= 1e12 { return 1 << 40 }
        return l <= 0 ? 0 : Int(exCeil(l))
    }
    fileprivate static func exWith(_ b: Model, vetoes extra: [V]) -> Model {
        let m = Model()
        m.predicates = b.predicates; m.caveats = b.caveats; m.vetoes = b.vetoes + extra; m.tighten = b.tighten; m.meets = b.meets
        m.caveatSat = b.caveatSat; m.caveatReason = b.caveatReason; m.revCap = b.revCap; m.undecidable = b.undecidable
        return m
    }

    // ---- thresholds ----

    fileprivate static func exCondThresholds(_ c: V?, _ path: String, _ into: inout [Double]) {
        guard isObjRec(c) else { return }
        if isGroup(c) {
            if inObj(c, "all_of"), let a = mem(c, "all_of")?.asArray { for x in a { exCondThresholds(x, path, &into) } }
            else if inObj(c, "any_of"), let a = mem(c, "any_of")?.asArray { for x in a { exCondThresholds(x, path, &into) } }
            else if inObj(c, "not") { exCondThresholds(mem(c, "not"), path, &into) }
            return
        }
        guard isLeaf(c), IV.same(mem(c, "field")?.asString, path) else { return }
        let v = mem(c, "value")
        if let d = fin(v) { into.append(d) }
        else if let a = v?.asArray { for x in a { if let d = fin(x) { into.append(d) } } }
    }

    /// Every numeric literal the policy compares `path` against (conditions of permits, vetoes and tighten rules), ascending, distinct.
    static func thresholdsOf(_ model: Model, _ path: String) throws -> [Double] {
        var out: [Double] = []
        for p in try probeSet(model) {
            guard let w = JS.present(try rd(p, "where")) else { continue }
            switch w {
            case let .array(a): for c in a { exCondThresholds(c, path, &out) }
            case .string: break
            default: throw fail("p.where is not iterable")
            }
        }
        for v in model.vetoes {
            guard let over = JS.present(try rd(v, "over")), IV.same(mem(over, "path")?.asString, path) else { continue }
            // a veto threshold that is not a number has no sound place in a sorted list of numbers: refuse
            guard let t = IV.num(mem(over, "threshold")), !t.isNaN else { throw fail("veto threshold is not a number") }
            out.append(t)
        }
        var seen = Set<Double>(), uniq: [Double] = []
        for x in out where seen.insert(x == 0 ? 0 : x).inserted { uniq.append(x) }
        return uniq.sorted()
    }

    // ---- per-action peak ----

    fileprivate static func exPinned(_ pr: Probes, _ path: String, _ value: Double, _ resource: V?) -> Probes {
        var p = pr
        if let r = resource { p.resources = [r] }
        p.fields = pr.fields.filter { !IV.same($0.path, path) } + [(path: path, values: [Cell.value(num(value))])]
        return p
    }

    fileprivate static func exPeakAt(_ model: Model, _ o: V, _ level: String) throws -> (peak: ExPeak, overflow: Bool) {
        let fname = JS.toString(JS.present(mem(o, "amountField")) ?? .string("amount"))
        let path = "action.params." + fname
        let mx = boundOf(o)
        var base = try collectProbes(ProbeInputs(predicateSets: [try probeSet(model)], varyReversibility: model.revCap != nil))
        base.verbs = [mem(o, "verb")]
        let T = try thresholdsOf(model, path)
        let lo = exMax(0, JS.toNumber(JS.present(mem(o, "min")) ?? .int(0)))
        let hiV = JS.present(mem(o, "max"))
        let hi = hiV.map { JS.toNumber($0) } ?? .infinity
        let hiFin = hiV.flatMap { fin($0) } != nil // Number.isFinite(hi): no coercion
        var raw: [Double] = []
        for i in T.indices {
            raw += [T[i] - 1, T[i]]
            if i + 1 < T.count { raw.append((T[i] + T[i + 1]) / 2) }
        }
        raw.append(T.last.map { $0 + 1 } ?? 0)
        raw += [exHuge, lo]
        if hiFin { raw.append(hi) }
        var seen = Set<Double>(), cands: [Double] = []
        for c in raw where !c.isNaN && seen.insert(c == 0 ? 0 : c).inserted && c >= lo && c <= hi && c.isFinite { cands.append(c) }
        cands.sort(by: >)
        let ok: (Rep) throws -> Bool = { rep in
            let d = try decide(model, rep)
            return level == "allow" ? d == "allow" : d != "deny"
        }
        var overflow = false
        for c in cands {
            let out = try search(exPinned(base, path, c, mem(o, "resource")), ok, mx)
            if out.overflow { overflow = true; break }
            guard let hit = out.hit else { continue }
            func act(_ v: Double) -> V {
                var a = repToAction(hit).asObject ?? [:]
                var p = a[JKey("params")]?.asObject ?? [:]
                p[JKey(fname)] = num(v)
                a[JKey("params")] = .object(p)
                return .object(a)
            }
            func holds(_ a: V) throws -> Bool {
                let d = try decideAction(model, a)
                return level == "allow" ? d == "allow" : d != "deny"
            }
            if c > (T.last ?? -.infinity) {
                // the cell above every threshold: unbounded unless the schema caps the parameter
                if hiFin { let w = act(hi); return (ExPeak(admitted: true, max: hi, attained: try holds(w), witness: w), false) }
                return (ExPeak(admitted: true, max: .infinity, attained: false, witness: act(exHuge)), false)
            }
            if T.contains(c) { return (ExPeak(admitted: true, max: c, attained: true, witness: act(c)), false) }
            let next = T.first { $0 > c } ?? c
            if mem(o, "integer") == .bool(true) {
                let m = exCeil(next) - 1
                if m >= c { let w = act(m); if try holds(w) { return (ExPeak(admitted: true, max: m, attained: true, witness: w), false) } }
            }
            return (ExPeak(admitted: true, max: next, attained: false, witness: act(c)), false)
        }
        return (ExPeak(admitted: false, max: 0, attained: false, witness: nil), overflow)
    }

    // ---- windowed exposure ----

    fileprivate static func exInvariants(_ c: V?) throws -> [V] {
        guard let iv = JS.present(mem(c, "invariants")) else { return [] }
        switch iv {
        case let .array(a): return a
        case let .string(s): return s.unicodeScalars.map { .string(String($0)) }
        default: throw fail("constitution.invariants is not iterable")
        }
    }

    /// Does the trigger provably apply to every action of the verb (a universal trigger)?
    fileprivate static func exUniversal(_ p: V?, _ verb: V?) throws -> Bool {
        let pv = try rd(p, "verb")
        var verbOk = IV.strictEq(pv, .string("*")) || IV.strictEq(pv, verb)
        if !verbOk, let l = pv?.asArray { verbOk = l.contains { IV.strictEq($0, .string("*")) } || l.contains { IV.strictEq($0, verb) } }
        if !verbOk { return false }
        if let r = try rd(p, "resource"), !IV.strictEq(r, .string("*")) { return false }
        guard let w = try rd(p, "where") else { return true }
        return IV.num(try rd(w, "length")) == 0
    }

    fileprivate static func exBlast(_ verb: V?) throws -> Double {
        guard let s = verb?.asString else { throw fail("verb.split is not a function") }
        return PCACatalog.default.get(s)?.blastRadius ?? 1
    }

    fileprivate static func exWindowBound(_ model: Model, _ c: V?, _ o: V, _ peak: ExPeak) throws -> V {
        let Wv = mem(o, "windowSecs")
        let W = Wv.map { JS.toNumber($0) }
        let path = "action.params." + JS.toString(JS.present(mem(o, "amountField")) ?? .string("amount"))
        let per = peak.admitted ? peak.max : 0
        var basis: [V] = [], notApplied: [V] = []
        var maxActions = Double.infinity
        func limitActions(_ n: V?, _ perSecs: V?, _ why: String) {
            // a sliding limit of n per perSecs: at most n per started period
            let k: Double = W.map { JS.toNumber(n) * exCeil($0 / JS.toNumber(perSecs)) } ?? .infinity
            if k < maxActions { maxActions = k; basis.append(.string(why)) }
        }
        let caveats = model.caveats + model.meets.flatMap { $0.caveats }
        for cv in caveats {
            if IV.same(try rd(cv, "type")?.asString, "rate"), IV.num(mem(cv, "max")) != nil, let ps = IV.num(mem(cv, "per_secs")), ps > 0 {
                limitActions(mem(cv, "max"), mem(cv, "per_secs"), "rate caveat \(JS.toString(mem(cv, "max")))/\(JS.toString(mem(cv, "per_secs")))s")
            }
        }
        for inv in try exInvariants(c) {
            guard IV.same(try rd(inv, "kind")?.asString, "rate") else { continue }
            if try exUniversal(try rd(inv, "when"), mem(o, "verb")) {
                limitActions(mem(inv, "max"), mem(inv, "window_secs"), "rate invariant " + JS.toString(mem(inv, "id")))
            } else { notApplied.append(mem(inv, "id") ?? .null) }
        }
        var bound: Double = per == 0 ? 0 : maxActions == .infinity ? .infinity : per * maxActions
        if per.isFinite && per > 0 { basis.insert(.string("per-action ceiling"), at: 0) }
        let bm = mem(o, "budgetModel")
        for cv in caveats {
            guard IV.same(try rd(cv, "type")?.asString, "budget_alloc"), let lim = IV.num(mem(cv, "limit")) else { continue }
            if IV.strictEq(bm, .string("dollars")) {
                if lim < bound { bound = lim; basis.append(.string("budget_alloc limit \(exStr(lim))")) } // a lifetime cap on the total
            } else if IV.strictEq(bm, .string("risk")), let kappa = IV.num(mem(o, "kappa")), kappa > 0 {
                let r = try JS.present(mem(o, "blastRadius")).map { JS.toNumber($0) } ?? exBlast(mem(o, "verb"))
                let cost = kappa * exMin(1, exMax(0, r))
                let n = cost > 0 ? (lim / cost).rounded(.down) : .infinity
                if n < maxActions {
                    maxActions = n
                    bound = n == 0 ? 0 : (per.isFinite && per > 0 ? per * n : bound)
                    basis.append(.string("budget_alloc \(exStr(lim)) / cost \(exStr(cost)) = \(exStr(n)) actions"))
                }
            } else { notApplied.append(.string("budget_alloc \(exStr(lim)) (trust-budget units; pass budgetModel and kappa)")) }
        }
        for inv in try exInvariants(c) {
            guard IV.same(try rd(inv, "kind")?.asString, "cap") else { continue }
            if try !exUniversal(try rd(inv, "when"), mem(o, "verb")) || !IV.same(mem(inv, "amount")?.asString, path) {
                notApplied.append(mem(inv, "id") ?? .null)
                continue
            }
            let ws = mem(inv, "window_secs")
            if ws != nil && W == nil { continue } // a windowed cap says nothing about a lifetime total
            let cap = JS.toNumber(mem(inv, "max")) * (ws == nil || W == nil ? 1 : exCeil(W! / JS.toNumber(ws)))
            if cap < bound { bound = cap; basis.append(.string("cap invariant " + JS.toString(mem(inv, "id")))) }
        }
        var out: [(String, V?)] = [("maxActions", num(maxActions)), ("bound", num(bound)), ("basis", .array(basis)), ("notApplied", .array(notApplied))]
        if let w = Wv { out.append(("secs", w)) }
        if peak.admitted, let w = peak.witness, maxActions.isFinite, peak.max.isFinite, peak.max > 0 {
            out.append(("sequence", obj([("action", w), ("repeat", num(maxActions))])))
        }
        return obj(out)
    }

    /// The most that can ever leave under a policy: the largest single action, the largest autonomous action, and the total over a
    /// window, composing the per-action ceiling with rate limits, the grant's `budget_alloc` and a constitution's `cap` / `rate`
    /// invariants (a cap or rate invariant counts only when it provably applies to every action of the verb).
    static func maxExposure(_ policy: V?, _ given: V?) throws -> V {
        var o = JSLoose.spread(given)
        if try rd(given, "budgetModel") == nil {
            let bm = try rd(policy, "budgetModel")
            if bm == .string("dollars") || bm == .string("risk") { o[JKey("budgetModel")] = bm! }
        }
        if try rd(given, "kappa") == nil {
            let rp = JS.present(try rd(policy, "riskPolicy"))
            if let k = rp.flatMap({ mem($0, "kappa") }), IV.num(k) != nil { o[JKey("kappa")] = k }
        }
        let ov: V = .object(o)
        let cons = mem(ov, "constitution")
        let cv = try cons.map { _ in try vetoesFromConstitution(cons) }
        let base = try toModel(policy)
        let model = cv.map { exWith(base, vetoes: arr(mem($0, "vetoes"))) } ?? base
        let admit = try exPeakAt(model, ov, "admit")
        let auto = try exPeakAt(model, ov, "allow")
        let ap = admit.overflow ? ExPeak.unbounded : admit.peak
        let up = auto.overflow ? ExPeak.unbounded : auto.peak
        let unmodeled: [V] = cv.map { c in
            arr(mem(c, "unmodeled")).filter { u in
                let k = mem(u, "kind")
                return !IV.strictEq(k, .string("cap")) && !IV.strictEq(k, .string("rate"))
            }.map { .string("\(JS.toString(mem($0, "id"))): \(JS.toString(mem($0, "reason")))") }
        } ?? []
        var out: [(String, V?)] = [
            ("verb", mem(ov, "verb")), ("amountField", JS.present(mem(ov, "amountField")) ?? .string("amount")),
            ("perAction", ap.json), ("autonomousPerAction", up.json),
            ("window", try exWindowBound(model, cons, ov, ap)), ("autonomousWindow", try exWindowBound(model, cons, ov, up)),
            ("unmodeled", .array(unmodeled)),
        ]
        if admit.overflow || auto.overflow || !model.undecidable.isEmpty {
            out.append(("approximate", .bool(true)))
            out.append(("reason", .string(admit.overflow || auto.overflow ? "representative grid exceeded the bound; exposure reported as unbounded" : exReason(false, model.undecidable))))
        }
        return obj(out)
    }

    // ---- escalation surface ----

    /// The set of actions that escalate (admitted, but not autonomous), at most `opts.limit` witnesses.
    static func escalationSurface(_ policy: V?, _ opts: V? = nil) throws -> V {
        let o: V = opts ?? .object([:])
        let model = try toModel(policy)
        var base = try collectProbes(ProbeInputs(predicateSets: [try probeSet(model)], varyReversibility: model.revCap != nil))
        if let verb = try rd(o, "verb") { base.verbs = [verb] }
        let r = try collect(base, { try decide(model, $0) == "escalate" }, boundOf(o), exLimit(mem(o, "limit"), 8))
        var witnesses: [V] = []
        for h in r.hits { let a = repToAction(h); if try decideAction(model, a) == "escalate" { witnesses.append(a) } }
        var out: [(String, V?)] = [("escalates", .bool(!witnesses.isEmpty)), ("witnesses", .array(witnesses))]
        if r.overflow || !model.undecidable.isEmpty {
            out.append(("approximate", .bool(true)))
            out.append(("reason", .string(exReason(r.overflow, model.undecidable))))
        }
        return obj(out)
    }

    // ---- delegation envelope ----

    /// The join of everything any holder of the leaf could do: the meet of the chain's policies (every hop must admit) with the
    /// remaining `delegation_depth`. A sub-delegate can only narrow this envelope.
    static func delegationEnvelope(_ chainIn: V?, _ opts: V? = nil) throws -> V {
        guard case let .array(chain)? = chainIn else { throw fail("chain.slice is not a function") }
        var policy: V = .object(["predicates": .array([])])
        if let leaf = chain.last, leaf.isObject || leaf.isArray {
            var meet = Array(chain.dropLast())
            var m: JObject = leaf.asObject ?? [:]
            if let lm = mem(leaf, "meet"), leaf.isObject, JS.truthy(lm) { meet += try JS.spread(lm) }
            m[JKey("meet")] = .array(meet)
            policy = .object(m)
        }
        let model = try toModel(policy)
        let base = try collectProbes(ProbeInputs(predicateSets: [try probeSet(model)], varyReversibility: model.revCap != nil))
        let mx = boundOf(opts)
        var verbs: [V] = []
        var anyVerb = false, overflow = false
        for verb in base.verbs {
            var pr = base
            pr.verbs = [verb]
            let r = try collect(pr, { try decide(model, $0) != "deny" }, mx, 1)
            if r.overflow { overflow = true; break }
            guard let hit = r.hits.first else { continue }
            let w = repToAction(hit)
            if let s = verb?.asString, IV.startsWith(s, "\u{0}") { anyVerb = true }
            else { verbs.append(obj([("verb", verb), ("witness", w), ("autonomous", .bool(try decide(model, hit) == "allow"))])) }
        }
        var violations: [V] = []
        if chain.count > 1 {
            for i in 0..<(chain.count - 1) {
                let a = try toModel(chain[i]), b = try toModel(chain[i + 1])
                let pr = try collectProbes(ProbeInputs(predicateSets: [try probeSet(a), try probeSet(b)], varyReversibility: a.revCap != nil || b.revCap != nil))
                let out = try search(pr, { try decide(b, $0) != "deny" && decide(a, $0) == "deny" }, mx)
                if out.hit != nil || out.overflow { violations.append(.int(Int64(i + 1))) }
            }
        }
        var depths: [Double] = []
        for p in chain where isObjRec(p) && inObj(p, "caveats") {
            guard let cs = mem(p, "caveats")?.asArray else { continue }
            for c in cs {
                if IV.same(try rd(c, "type")?.asString, "delegation_depth"), let m = IV.num(mem(c, "max")) { depths.append(m) }
            }
        }
        let used = Double(Swift.max(0, chain.count - 1))
        var depth: [(String, V?)] = [("used", num(used))]
        if var allowed = depths.first {
            for d in depths.dropFirst() { allowed = exMin(allowed, d) }
            depth.append(("allowed", num(allowed)))
            depth.append(("remaining", num(exMax(0, allowed - used))))
        }
        var out: [(String, V?)] = [("violations", .array(violations)), ("verbs", .array(verbs)), ("anyVerb", .bool(anyVerb)), ("depth", obj(depth))]
        if overflow || !model.undecidable.isEmpty {
            out.append(("approximate", .bool(true)))
            out.append(("reason", .string(exReason(overflow, model.undecidable))))
        }
        return obj(out)
    }

    // ---- semantic diff ----

    private static func exSub(_ x: Double, _ y: Double) -> Double { x == y ? 0 : x - y } // Infinity - Infinity is no change

    private static func exNumAt(_ e: V?, _ k1: String, _ k2: String) -> Double { IV.num(mem(mem(e, k1), k2)) ?? .nan }

    /// `diff(A, B)`: which actions move between allow / escalate / deny, with witnesses (at most `limit` per kind), and optionally how
    /// the max exposure of a verb moved. `equivalent` / `widens` / `narrows` count every moved action (a limit under 1 hides none).
    static func diffPolicies(_ a: V?, _ b: V?, _ optsIn: V? = nil) throws -> V {
        let o: V = optsIn ?? .object([:])
        let ma = try toModel(a), mb = try toModel(b)
        let pr = try collectProbes(ProbeInputs(predicateSets: [try probeSet(ma), try probeSet(mb)], varyReversibility: ma.revCap != nil || mb.revCap != nil))
        let limit = JS.toNumber(JS.present(try rd(o, "limit")) ?? .int(4))
        var counts: [String: Int] = [:], counted: [String] = []
        var kinds: [String] = [], shifts: [String: [V]] = [:], order: [String: [String]] = [:]
        let walk = try collect(pr, { rep in
            let x = try decide(ma, rep), y = try decide(mb, rep)
            if x == y { return false }
            let k = "\(x)->\(y)"
            let n = counts[k] ?? 0
            if n == 0 { counted.append(k) }
            counts[k] = n + 1
            if Double(n) < limit {
                if shifts[k] == nil {
                    kinds.append(k)
                    var names: [String] = []
                    for asg in rep.assignments where IV.startsWith(asg.path, "action.params.") {
                        for seg in IV.split(asg.path, ".").dropFirst(2) where !names.contains(where: { IV.same($0, seg) }) { names.append(seg) }
                    }
                    order[k] = names
                }
                shifts[k, default: []].append(repToAction(rep))
            }
            return false // walk the whole grid
        }, boundOf(o), 1)
        let widens = counted.contains { exWiden.contains($0) }
        let narrows = counted.contains { !exWiden.contains($0) }
        var summary: [V] = kinds.map { k in
            let first = shifts[k]![0]
            let params = JS.present(mem(first, "params")) ?? .object([:])
            return .string("\(k): \(shifts[k]!.count)+ action(s), e.g. \(JS.toString(mem(first, "verb"))) \(JS.toString(mem(first, "resource"))) \(JS.stringify(params, order: order[k] ?? []))")
        }
        var shiftsOut: JObject = [:]
        for k in kinds { shiftsOut[JKey(k)] = .array(shifts[k]!) }
        var d: [(String, V?)] = [("equivalent", .bool(counted.isEmpty && !walk.overflow && ma.undecidable.isEmpty && mb.undecidable.isEmpty)),
                                 ("shifts", .object(shiftsOut)), ("widens", .bool(widens)), ("narrows", .bool(narrows))]
        if let ex = mem(o, "exposure") {
            let before = try maxExposure(a, ex), after = try maxExposure(b, ex)
            let pa = exSub(exNumAt(after, "perAction", "max"), exNumAt(before, "perAction", "max"))
            let au = exSub(exNumAt(after, "autonomousWindow", "bound"), exNumAt(before, "autonomousWindow", "bound"))
            let dl = exSub(exNumAt(after, "window", "bound"), exNumAt(before, "window", "bound"))
            d.append(("exposure", obj([("before", before), ("after", after), ("perActionDelta", num(pa)), ("delta", num(dl)), ("autonomousDelta", num(au))])))
            let worst = exMax(dl, exMax(pa, au)), best = exMin(dl, pa)
            if worst > 0 { summary.append(.string("max exposure of \(JS.toString(mem(ex, "verb"))) rises by \(exStr(worst))")) }
            else if best < 0 { summary.append(.string("max exposure of \(JS.toString(mem(ex, "verb"))) falls by \(exStr(-best))")) }
        }
        d.append(("summary", .array(summary)))
        if walk.overflow || !ma.undecidable.isEmpty || !mb.undecidable.isEmpty {
            d.append(("approximate", .bool(true)))
            d.append(("reason", .string(walk.overflow ? exReason(true, []) : exReason(false, uniq(ma.undecidable + mb.undecidable)))))
        }
        return obj(d)
    }

    /// A CI gate over a diff: fails when the change widens authority beyond what the reviewer allowed.
    static func diffGate(_ d: V?, _ allowIn: V? = nil) throws -> V {
        let allow: V = allowIn ?? .object([:])
        var reasons: [V] = []
        if JS.truthy(try rd(d, "widens")), !IV.strictEq(try rd(allow, "widen"), .bool(true)) {
            guard let sm = mem(d, "summary")?.asArray else { throw fail("d.summary.filter is not a function") }
            var ws: [String] = []
            for s in sm {
                guard let str = s.asString else { throw fail("s.startsWith is not a function") }
                if exWiden.contains(where: { IV.startsWith(str, $0) }) { ws.append(str) }
            }
            reasons.append(.string("widens authority: " + ws.joined(separator: "; ")))
        }
        var rise = 0.0
        if let ex = mem(d, "exposure"), JS.truthy(ex) {
            rise = exMax(JS.toNumber(mem(ex, "delta")), exMax(JS.toNumber(mem(ex, "perActionDelta")), JS.toNumber(mem(ex, "autonomousDelta"))))
        }
        if rise > JS.toNumber(JS.present(try rd(allow, "maxExposureIncrease")) ?? .int(0)) { reasons.append(.string("max exposure rises by \(exStr(rise))")) }
        if JS.truthy(mem(d, "approximate")) { reasons.append(.string("inconclusive: " + JS.toString(JS.present(mem(d, "reason")) ?? .string("approximate")))) }
        return obj([("ok", .bool(reasons.isEmpty)), ("reasons", .array(reasons))])
    }

    // ---- optional solver backend ----

    /// What an optional external solver returned: a witness is re-checked by the real evaluator (never trusted, and refused when
    /// wrong); an "unsat" claim is returned labelled as solver-claimed, never as a proved verdict.
    static func findWithBackend(_ q: V?, name: V?, result: V?) throws -> V {
        if let w = try rd(result, "witness") {
            let ma = try toModel(try rd(q, "a"))
            let qv = mem(q, "verb")
            let ok: Bool
            if IV.strictEq(mem(q, "kind"), .string("reachable")) {
                ok = try decideAction(ma, w) != "deny" && (qv == nil || IV.strictEq(mem(w, "verb"), qv))
            } else if let qb = mem(q, "b") {
                let x = try decideAction(ma, w) != "deny"
                let y = try decideAction(try toModel(qb), w) != "deny"
                ok = x != y
            } else { ok = false }
            return ok ? obj([("witness", w)]) : obj([("rejected", .bool(true))])
        }
        if IV.strictEq(mem(result, "unsat"), .bool(true)) {
            return obj([("claimedUnsat", obj([("by", name), ("proof", .string("solver-claimed, not machine-checked"))]))])
        }
        return .object([:])
    }
}
