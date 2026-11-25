import Foundation

extension WalletOmega {
    /// An outcome space from its verb spaces (the augmented space of a trajectory grant).
    init(augmented verbs: [WalletVerb]) { self.verbs = verbs }
}

/// Trajectory intent as ordinary intent: the augmented outcome space adds to every verb one numeric dimension per accumulator (the
/// value the accumulator would have after the action) and one categorical dimension per monitor (its state), the lift of a candidate
/// action into it, the per-step admission rule, and the accumulators the wallet always adds. Psi, histories and schemas are JSON trees;
/// outcomes are `{verb, values}` values. The outcome space has no `approximate` list here (the wallet's space does not carry one).
public enum PCAIntentTrajectory {
    public static let ACC_DIM_PREFIX = "env.acc."
    public static let MON_DIM_PREFIX = "env.mon."

    public static func accDimPath(_ id: String) -> String { ACC_DIM_PREFIX + id + ".post" }

    public static func monDimPath(_ id: String) -> String { MON_DIM_PREFIX + id + ".state" }

    /// The v2 dimension kind of a path: param, acc, mon, canon, world, rel, prov, class or other.
    public static func dimKindOf(_ path: String) -> String {
        if IV.startsWith(path, "action.params.") { return "param" }
        if IV.startsWith(path, ACC_DIM_PREFIX) { return "acc" }
        if IV.startsWith(path, MON_DIM_PREFIX) { return "mon" }
        if IV.startsWith(path, "env.canon.") { return "canon" }
        if IV.startsWith(path, "env.world.") { return "world" }
        if IV.startsWith(path, "env.rel.") { return "rel" }
        if IV.startsWith(path, "env.prov.") { return "prov" }
        if IV.startsWith(path, "env.class.") { return "class" }
        return "other"
    }

    private static func obj(_ v: JSONValue?, _ what: String) throws -> JObject {
        guard let o = v?.asObject else { throw JSError("\(what) must be an object") }
        return o
    }

    private static func list(_ v: JSONValue?, _ what: String) throws -> [JSONValue] {
        guard let a = v?.asArray else { throw JSError("\(what) must be a list") }
        return a
    }

    private static func slice(_ s: String, _ from: Int, _ cutEnd: Int) -> String { WJ.u16slice(s, from, s.utf16.count - cutEnd) }

    private static func predicateVerbs(_ verb: JSONValue?) throws -> [String] {
        if let a = verb?.asArray {
            return try a.map { guard let s = $0.asString else { throw JSError("predicate verb must be a string") }; return s }
        }
        guard let s = verb?.asString else { throw JSError("predicate verb must be a string") }
        return [s]
    }

    /// Does the accumulator select the verb (by its verb list or through the schema's accumulation parameters)?
    private static func selects(_ a: JObject, _ verb: String, _ schema: JSONValue?) -> Bool {
        let sel: JObject = a["sel"]?.asObject ?? [:]
        if let vs = sel["verbs"]?.asArray, vs.contains(where: { IV.same($0.asString, verb) }) { return true }
        if let unit = sel["accumulates_into"], !unit.isNull {
            guard let s = schema, let v = ActionSchema.verb(s, verb), let u = unit.asString else { return false }
            return !IntentAcc.accumulationParams(v, u).isEmpty
        }
        return false
    }

    /// The augmented space from the outcome space and Psi (`{accumulators, monitors}`). `opts`: cuts? (accumulator id to cuts), scope?
    /// ("all" | "selected"), schema? (`{verbs}`). Wallet-held accumulators are not dimensions.
    public static func augmentOmega(_ omega: WalletOmega, _ psi: JSONValue, _ opts: JSONValue?) throws -> WalletOmega {
        let selected: Bool = IV.same(opts?.get("scope")?.asString, "selected")
        let cutsByAcc: JObject = opts?.get("cuts")?.asObject ?? [:]
        let schema: JSONValue? = opts?.get("schema")
        let accs: [JSONValue] = try list(psi.get("accumulators"), "accumulators")
        let mons: [JSONValue] = try list(psi.get("monitors"), "monitors")
        var verbs: [WalletVerb] = []
        for vs in omega.verbs {
            var extra: [WalletDim] = []
            for ao in accs {
                let a: JObject = try obj(ao, "accumulator")
                if IV.same(a["holder"]?.get("kind")?.asString, "wallet") { continue }
                if selected && !selects(a, vs.verb, schema) { continue }
                guard let dmv = a["domain_max"], !dmv.isNull else {
                    throw JSError("augmentOmega: accumulator '\(a["id"].map { IntentV2.jsString($0) } ?? "undefined")' needs domain_max (A_\u{03C8}) to be a dimension of \u{03A9}\u{0303}")
                }
                guard let dm = IV.num(dmv), dm.isFinite, dm == dm.rounded(.towardZero), abs(dm) <= Double(Canonical.MAX_SAFE) else {
                    throw JSError("augmentOmega: domain_max must be a safe integer")
                }
                var cuts: [Double] = []
                if let id = a["id"]?.asString, let cb = cutsByAcc[JKey(id)], !cb.isNull {
                    for c in try list(cb, "cuts") {
                        let x: Double = IV.num(c) ?? Double.nan
                        if x == x.rounded(.down) && abs(x) <= 9007199254740991.0 && x >= 0 && x <= dm {
                            let y = x + 0.0
                            if !cuts.contains(y) { cuts.append(y) }
                        }
                    }
                    cuts.sort()
                }
                guard let accId = a["id"]?.asString else { throw JSError("augmentOmega: accumulator id must be a string") }
                extra.append(WalletDim(kind: "num", path: accDimPath(accId), lo: 0, hi: Int(dm), cuts: cuts.map { Int($0) }, dist: "loguniform", values: []))
            }
            for mo in mons {
                let mon: JObject = try obj(mo, "monitor")
                if selected {
                    var keep = true
                    if let q = mon["q"], !q.isNull {
                        let pv = try predicateVerbs(q.get("verb"))
                        keep = pv.contains { IV.same($0, vs.verb) } || pv.contains { IV.same($0, "*") }
                    }
                    if !keep { continue }
                }
                guard let monId = mon["id"]?.asString else { throw JSError("augmentOmega: monitor id must be a string") }
                var dim = WalletDim(kind: "cat", path: monDimPath(monId))
                dim.values = IntentAcc.monitorStates(mo).map { (kind: "exact", value: $0) }
                extra.append(dim)
            }
            var dims: [WalletDim] = vs.dims.filter { d in
                let k = dimKindOf(d.path)
                return k != "acc" && k != "mon"
            }
            dims.append(contentsOf: extra)
            let ordered: [WalletDim] = dims.enumerated().sorted { x, y in
                if IV.utf8Less(x.element.path, y.element.path) { return true }
                if IV.utf8Less(y.element.path, x.element.path) { return false }
                return x.offset < y.offset
            }.map { $0.element }
            verbs.append(WalletVerb(verb: vs.verb, reversibility: vs.reversibility, weight: vs.weight, dims: ordered))
        }
        return WalletOmega(augmented: verbs)
    }

    /// lift(history, action, t) as an outcome of the augmented space, or nil when the verb is not in it. `cand`: verb, resource, params, t.
    /// Throws where the accumulator or monitor computation does.
    public static func liftAction(_ omegaTilde: WalletOmega, _ psi: JSONValue, _ history: [JSONValue], _ cand: JSONValue, _ schema: JSONValue?) throws -> JSONValue? {
        guard let verb = cand.get("verb")?.asString, let vs = omegaTilde.verb(verb) else { return nil }
        let decl: JObject? = schema.flatMap { ActionSchema.verb($0, verb) }
        let params: JObject = try obj(cand.get("params"), "params")
        var values: JObject = [:]
        for d in vs.dims {
            let k = dimKindOf(d.path)
            if k == "param" {
                let name = IV.dropPrefix(d.path, 14)
                if let x = params[JKey(name)], x.isNumber || x.asString != nil { values[JKey(d.path)] = x }
            } else if k == "canon" {
                let name = IV.dropPrefix(d.path, 10)
                let pd: JSONValue? = decl?["params"]?.get("action.params." + name)
                if let pd = pd, !pd.isNull, let x = params[JKey(name)] { values[JKey(d.path)] = .string(try PCAIntentSchema.canonValue(pd, x)) }
            } else if k == "acc" {
                let id = slice(d.path, ACC_DIM_PREFIX.utf16.count, ".post".utf16.count)
                for ao in try list(psi.get("accumulators"), "accumulators") where IV.same(ao.get("id")?.asString, id) {
                    guard let a = ao.asObject, let post = IntentHistory.accPost(a, history, verb, params, cand.get("t"), schema) else {
                        throw JSError("liftAction: the accumulator '\(id)' cannot be computed")
                    }
                    values[JKey(d.path)] = .double(post)
                    break
                }
            } else if k == "mon" {
                let id = slice(d.path, MON_DIM_PREFIX.utf16.count, ".state".utf16.count)
                for mo in try list(psi.get("monitors"), "monitors") where IV.same(mo.get("id")?.asString, id) {
                    guard let m = mo.asObject else { throw JSError("liftAction: a monitor must be an object") }
                    values[JKey(d.path)] = .string(IntentHistory.monitorState(m, history))
                    break
                }
            } else if IV.same(d.path, "action.resource") {
                values[JKey(d.path)] = cand.get("resource") ?? .null
            }
        }
        return .object(["verb": .string(verb), "values": .object(values)])
    }

    /// The space and per-dimension cell of a lifted outcome, or nil when it lies outside the space.
    public struct LiftedCell {
        public let vs: WalletVerb
        public let cell: [Int]
    }

    public static func liftedCell(_ omegaTilde: WalletOmega, _ o: JSONValue) -> LiftedCell? {
        guard let verb = o.get("verb")?.asString, let vs = omegaTilde.verb(verb), let cell = WalletOmegaMath.cellOf(vs, values: o.get("values")) else { return nil }
        return LiftedCell(vs: vs, cell: cell)
    }

    /// The result of one step: whether it was admitted, the new history, and the lifted outcome.
    public struct Step {
        public let admitted: Bool
        public let history: [JSONValue]
        public let lifted: JSONValue?
    }

    /// The trajectory-grant step rule: admit the action iff its lift lies in a cell `inGrant` accepts; the history gains a reserved event on admission.
    public static func stepTrajectory(_ omegaTilde: WalletOmega, _ psi: JSONValue, _ history: [JSONValue], _ cand: JSONValue, _ inGrant: (String, [Int]) -> Bool,
                                      _ schema: JSONValue?) throws -> Step {
        let lifted: JSONValue? = try liftAction(omegaTilde, psi, history, cand, schema)
        let c: LiftedCell? = lifted.flatMap { liftedCell(omegaTilde, $0) }
        var ok = false
        if let c = c, let verb = cand.get("verb")?.asString { ok = inGrant(verb, c.cell) }
        var next: [JSONValue] = history
        if ok {
            var ev: JObject = [:]
            for k in ["id", "verb", "resource", "params", "t"] { if let x = cand.get(k) { ev[JKey(k)] = x } }
            ev["status"] = .string("reserved")
            next.append(.object(ev))
        }
        return Step(admitted: ok, history: next, lifted: lifted)
    }

    /// A string reduced to `[A-Za-z0-9_]` per UTF-16 unit (as the reference's `replace(/[^A-Za-z0-9_]/g, '_')`), at most 58 characters.
    private static func sanitize(_ u: String) -> String {
        var out = ""
        for c in u.utf16 {
            let ok = (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x5F
            out += ok ? String(UnicodeScalar(UInt8(c))) : "_"
        }
        return WJ.u16slice(out, 0, 58)
    }

    private static func spendAcc(_ id: String, _ spendDomainMax: Double, _ holder: JSONValue, _ sel: JSONValue, _ extraKey: String, _ extraVal: String) -> JSONValue {
        .object(["id": .string(id), "agg": .string("sum"), JKey(extraKey): .string(extraVal), "sel": sel, "win": .object(["kind": .string("task")]), "key": .null,
                 "domain_max": WJ.plain(.double(spendDomainMax)), "holder": holder])
    }

    /// The accumulators the wallet always adds: a per-task spend sum for every accumulation unit any verb feeds, a per-verb spend sum for
    /// every untagged `money.amount` integer parameter, and the wallet-held question counter. `holder` defaults to site_local.
    public static func defaultAccumulators(_ schema: JSONValue?, _ spendDomainMax: Double, _ questionCap: Double?, _ holderIn: JSONValue?) throws -> [JSONValue] {
        let holder: JSONValue = holderIn ?? .object(["kind": .string("site_local")])
        var units: [String] = []
        var untagged: [(verb: String, path: String)] = []
        for vo in try list(schema?.get("verbs"), "verbs") {
            let v: JObject = try obj(vo, "verb entry")
            guard let verb = v["verb"]?.asString else { throw JSError("verb entry: verb must be a string") }
            let ps: JObject = try obj(v["params"], "params")
            for (pk, pv) in ps {
                let d: JObject = try obj(pv, "param")
                var into: [JSONValue] = []
                if let a = d["accumulates_into"]?.asArray { into = a }
                for u in into {
                    guard let us = u.asString else { throw JSError("accumulates_into must hold strings") }
                    if !units.contains(where: { IV.same($0, us) }) { units.append(us) }
                }
                if IV.same(d["type"]?.asString, "integer") && IV.same(d["semantic"]?.asString, "money.amount") && into.isEmpty { untagged.append((verb, pk.s)) }
            }
        }
        units.sort { IV.utf8Less($0, $1) }
        var out: [JSONValue] = []
        for u in units {
            out.append(spendAcc("spend_" + sanitize(u), spendDomainMax, holder, .object(["accumulates_into": .string(u)]), "unit", u))
        }
        let ordered = untagged.enumerated().sorted { x, y in
            let a = x.element.verb + x.element.path, b = y.element.verb + y.element.path
            if IV.utf8Less(a, b) { return true }
            if IV.utf8Less(b, a) { return false }
            return x.offset < y.offset
        }.map { $0.element }
        for u in ordered {
            let id = "spend_" + sanitize(u.verb) + "_" + sanitize(IV.dropPrefix(u.path, 14))
            out.append(spendAcc(WJ.u16slice(id, 0, 64), spendDomainMax, holder, .object(["verbs": .array([.string(u.verb)])]), "val", u.path))
        }
        out.append(.object(["id": .string("questions"), "agg": .string("count"), "sel": .object(["event": .string("intent_required")]),
                            "win": .object(["kind": .string("task")]), "key": .null, "cap": WJ.plain(.double(questionCap ?? 6.0)),
                            "holder": .object(["kind": .string("wallet")])]))
        return out
    }

    /// The fact line for an accumulator dimension of a cell (`fmt`: amount renderer, default the integer; `thisAction` may be nil).
    public static func describeAccCell(_ d: WalletDim, _ cellIndex: Int, _ label: String, _ thisAction: Double?, _ fmt: ((Double) -> String)?) throws -> String {
        guard d.isNum else { throw JSError("describeAccCell: the dimension is not numeric") }
        let f: (Double) -> String = fmt ?? { x in Canonical.numberString(x) }
        let cells = WalletOmegaMath.numCells(d)
        if cellIndex < 0 || cellIndex >= cells.count { throw JSError("describeAccCell: no such cell") }
        let c = cells[cellIndex]
        let loText: String = f(Double(c.lo))
        let hiText: String = f(Double(c.hi))
        let range: String
        if c.lo == c.hi { range = "exactly " + loText } else { range = "between " + loText + " and " + hiText }
        var suffix = ""
        if let t = thisAction { suffix = " (this action: " + f(t) + ")" }
        return label + ": " + range + suffix
    }

    /// The per-session harm range of a trajectory Monte Carlo estimate: [0, L_max * H_max].
    public static func trajectoryHarmRange(_ maxSessionLength: Double, _ harmMax: Double) throws -> Double {
        guard maxSessionLength.isFinite, maxSessionLength == maxSessionLength.rounded(.down), abs(maxSessionLength) <= 9007199254740991.0, maxSessionLength >= 0, harmMax >= 0 else {
            throw JSError("trajectoryHarmRange: bad arguments")
        }
        return maxSessionLength * harmMax
    }
}
