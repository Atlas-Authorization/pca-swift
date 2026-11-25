import Foundation

/// Active disambiguation by version-space halving over a finite class of readings. A reading is an object
/// {id, family, deterministic, goal, notes}; a distinguishing case is {act, prior, rels}.
///
/// shortcut: a question's `id` is the JSON text of [act, prior count]; a parsed act has no member order, so the keys are written in
/// the order the reference builds an action (verb, res, params, t, sess, prin, org, agent, depth; a value as k then its payload) and
/// the parameter names in code-unit order (the order the case builder inserts them).
public enum PCAGoalDisambiguate {
    public static let DEFAULT_RISK: [String: Int] = ["read": 1, "reversible": 2, "external_send": 8, "irreversible": 10]

    /// Question options: the IR ontology the readings are decided against and optional risk / mass of an action (default risk by
    /// effect class of the verb, mass 1), plus an optional question budget (default: the number of readings).
    public final class Opts {
        public var ont: JSONValue
        public var riskOf: ((JSONValue) throws -> Double)?
        public var massOf: ((JSONValue) throws -> Double)?
        public var budget: Int?

        public init(_ ont: JSONValue) {
            self.ont = ont
            self.riskOf = nil
            self.massOf = nil
            self.budget = nil
        }
    }

    /// Member order of an action's text form (see the note above).
    static let ACT_ORDER: [String] = ["verb", "res", "params", "t", "sess", "prin", "org", "agent", "depth", "k", "q", "s", "items", "u", "ccy", "n"]

    static func mx(_ v: JSONValue?, _ what: String) throws -> JSONValue {
        guard let x = v, x.isObject else { throw IrError("\(what) expected an object") }
        return x
    }

    static func h2(_ p: Double) -> Double {
        if p <= 0 || p >= 1 { return 0 }
        return -(p * PCAIntentMath.log2(p) + (1 - p) * PCAIntentMath.log2(1 - p))
    }

    public static func allowsWitness(_ g: JSONValue, _ ont: JSONValue, _ w: JSONValue) throws -> Bool {
        let prior: [JSONValue] = try GV.arr(w.get("prior"), "prior")
        let rels: [JSONValue] = try GV.arr(w.get("rels"), "rels")
        let hist: JSONValue = try PCAGoalExamples.replay(g, ont, prior, rels)
        let c: JSONValue = GV.obj([("act", w.get("act") ?? JSONValue.null), ("hist", hist), ("rels", w.get("rels") ?? JSONValue.null)])
        let d: JSONValue = try PCAGoalExamples.decideCase(g, ont, c)
        return d.get("decision") == JSONValue.string("allow")
    }

    static func allowSet(_ r: JSONValue, _ w: JSONValue, _ ont: JSONValue) throws -> Bool {
        return try allowsWitness(try mx(r.get("goal"), "goal"), ont, w)
    }

    static func goalsOf(_ readings: [JSONValue]) throws -> [JSONValue] {
        var goals: [JSONValue] = []
        for r in readings { goals.append(try mx(r.get("goal"), "goal")) }
        return goals
    }

    /// Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences.
    static func witnesses(_ readings: [JSONValue], _ ont: JSONValue) throws -> [JSONValue] {
        let goals = try goalsOf(readings)
        var out: [JSONValue] = []
        let space = try PCAGoalExamples.buildSpace(goals, [])
        let cs = try PCAGoalExamples.cells(space, nil)
        for co in try GV.arr(cs.get("cases"), "cases") {
            out.append(GV.obj([("act", GV.get(co, "act") ?? JSONValue.null), ("prior", JSONValue.array([])), ("rels", GV.get(co, "rels") ?? JSONValue.null)]))
        }
        for r in readings {
            let be = try PCAGoalExamples.boundaryExamples(try mx(r.get("goal"), "goal"), ont, goals, nil)
            for eo in try GV.arr(be.get("examples"), "examples") {
                if GV.get(eo, "kind") != JSONValue.string("cap_sequence") { continue }
                var prior: [JSONValue] = []
                for a in try GV.arr(GV.get(GV.get(eo, "hist"), "adms"), "adms") { prior.append(GV.get(a, "act") ?? JSONValue.null) }
                out.append(GV.obj([("act", GV.get(eo, "act") ?? JSONValue.null), ("prior", JSONValue.array(prior)), ("rels", GV.get(eo, "rels") ?? JSONValue.null)]))
            }
        }
        return out
    }

    /// `a.id < b.id` by UTF-16 code units.
    static func lessStr(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    /// Questions over the symmetric difference of the readings, ranked by H2(vote) x risk x mass (best first).
    public static func questions(_ readings: [JSONValue], _ opts: Opts) throws -> [JSONValue] {
        let ont = opts.ont
        let k = readings.count
        var cls: [JKey: JSONValue] = [:]
        for v in try GV.arr(ont.get("verbs"), "verbs") {
            guard let name = GV.get(v, "verb")?.asString else { throw IrError("verb must be a string") }
            cls[JKey(name)] = GV.get(v, "cls") ?? JSONValue.null
        }
        var out: [(JSONValue, String, Double)] = []
        var seen = Set<JKey>()
        for w in try witnesses(readings, ont) {
            var yes: [JSONValue] = []
            for r in readings {
                if try allowSet(r, w, ont) { yes.append(r.get("id") ?? JSONValue.null) }
            }
            if yes.isEmpty || yes.count == k { continue }
            let np: Int = try GV.arr(w.get("prior"), "prior").count
            let id: String = JS.stringify(.array([w.get("act") ?? JSONValue.null, .int(Int64(np))]), order: ACT_ORDER)
            if !seen.insert(JKey(id)).inserted { continue }
            let act: JSONValue = try mx(w.get("act"), "act")
            var risk: Double = 10.0
            if let ro = opts.riskOf {
                risk = try ro(act)
            } else if let vb = act.get("verb")?.asString, let c = cls[JKey(vb)]?.asString, let dr = DEFAULT_RISK[c] {
                risk = Double(dr)
            }
            var mass: Double = 1.0
            if let mo = opts.massOf { mass = try mo(act) }
            var notAllow: [JSONValue] = []
            for r in readings {
                let rid: JSONValue = r.get("id") ?? JSONValue.null
                if !yes.contains(rid) { notAllow.append(rid) }
            }
            var text: String = "Should this be allowed: " + (try PCAGoalFmt.fmtAct(act))
            if np > 0 { text += " (after " + String(np) + " earlier identical action(s))" }
            text += "?"
            let score: Double = h2(Double(yes.count) / Double(k)) * risk * mass
            let q: JSONValue = GV.obj([
                ("id", JSONValue.string(id)), ("act", w.get("act") ?? JSONValue.null), ("prior", w.get("prior") ?? JSONValue.null),
                ("rels", w.get("rels") ?? JSONValue.null), ("allow", JSONValue.array(yes)), ("notAllow", JSONValue.array(notAllow)),
                ("text", JSONValue.string(text)), ("score", JSONValue.double(score)),
            ])
            out.append((q, id, score))
        }
        // best score first; ties (and NaN) by id
        let sorted = out.sorted { (a: (JSONValue, String, Double), b: (JSONValue, String, Double)) -> Bool in
            let d: Double = b.2 - a.2
            if d != 0 && !d.isNaN { return d < 0 }
            return lessStr(a.1, b.1)
        }
        return sorted.map { $0.0 }
    }

    /// Fraction of witness cells on which the readings do not all agree on Allow.
    public static func disagreementMass(_ readings: [JSONValue], _ ont: JSONValue) throws -> Double {
        let w = try witnesses(readings, ont)
        if w.isEmpty { return 0.0 }
        var split = 0
        for x in w {
            var n = 0
            for r in readings {
                if try allowSet(r, x, ont) { n += 1 }
            }
            if n > 0 && n < readings.count { split += 1 }
        }
        return Double(split) / Double(w.count)
    }

    /// Active disambiguation: {status, goal, asked, residualMass, remaining}. `ask` maps a question to "allow" or "deny".
    public static func disambiguate(_ readings: [JSONValue], _ ask: (JSONValue) throws -> String, _ opts: Opts) throws -> JSONValue {
        let ont = opts.ont
        let budget: Int = opts.budget ?? readings.count
        var active: [JSONValue] = readings
        var asked: [JSONValue] = []
        while active.count > 1 && asked.count < budget {
            let qs = try questions(active, opts)
            guard let q = qs.first else { break } // the survivors agree on every witness cell
            asked.append(q)
            let allow: Bool = try ask(q) == "allow"
            var next: [JSONValue] = []
            for r in active {
                if try allowSet(r, q, ont) == allow { next.append(r) }
            }
            active = next
        }
        let mass: Double = try disagreementMass(active, ont)
        let g: JSONValue = try PCAGoalNVersion.meet(try goalsOf(active))
        var remaining: [JSONValue] = []
        for r in active { remaining.append(r.get("id") ?? JSONValue.null) }
        if mass > 0 {
            var hs: [JSONValue] = GV.strs(g.get("holes"))
            hs.append(GV.obj([
                ("hid", JSONValue.string("budget")), ("q", JSONValue.string("Question budget exhausted with disagreement left.")),
                ("domain", JSONValue.array([])), ("affects", JSONValue.array([])), ("global", JSONValue.bool(true)),
            ]))
            var keyed: [(Int, String, JSONValue)] = []
            for i in 0..<hs.count { keyed.append((i, GV.jsStr(GV.get(hs[i], "hid")), hs[i])) }
            let sortedHoles = keyed.sorted { (a: (Int, String, JSONValue), b: (Int, String, JSONValue)) -> Bool in
                if lessStr(a.1, b.1) { return true }
                if lessStr(b.1, a.1) { return false }
                return a.0 < b.0
            }
            guard var go = g.asObject else { throw IrError("goal expected an object") }
            go[JKey("holes")] = .array(sortedHoles.map { $0.2 })
            return GV.obj([
                ("status", JSONValue.string("budget_exhausted")), ("goal", JSONValue.object(go)), ("asked", JSONValue.array(asked)),
                ("residualMass", JSONValue.double(mass)), ("remaining", JSONValue.array(remaining)),
            ])
        }
        return GV.obj([
            ("status", JSONValue.string("resolved")), ("goal", g), ("asked", JSONValue.array(asked)),
            ("residualMass", JSONValue.int(0)), ("remaining", JSONValue.array(remaining)),
        ])
    }
}
