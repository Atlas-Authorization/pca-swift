import Foundation

/// Policy coverage (`opa test --coverage` for PCA): which clause decided each action of a body of traffic, which never matched, how
/// close the traffic came to every numeric threshold, and which single-edit mutations of the policy the traffic cannot tell from the
/// original. Policies, actions and reports are plain JSON trees (`JSONValue`); a reference TypeError is a thrown `JSError`.
extension PCAAnalyzer {
    public static func permitId(_ i: Int) -> String { "permit[\(i)]" }

    // ---- small JS helpers shared by the coverage, validate and test-runner ports ----

    /// `a === b` over JSON values (numbers by binary64 value, undefined only equals undefined).
    static func cvSeq(_ a: V?, _ b: V?) -> Bool {
        if let x = IV.num(a), let y = IV.num(b) { return x == y }
        return same(a, b)
    }

    /// `typeof v`.
    static func cvTypeof(_ v: V?) -> String {
        switch v {
        case nil: return "undefined"
        case .bool?: return "boolean"
        case .int?, .double?: return "number"
        case .string?: return "string"
        default: return "object"
        }
    }

    /// A Map / Set key of a value (SameValueZero for primitives); nil for an object or array (never equal to another).
    static func cvKey(_ v: V?) -> JKey? {
        switch v {
        case nil: return JKey("u")
        case .null?: return JKey("n")
        case let .bool(b)?: return JKey(b ? "b:true" : "b:false")
        case .int?, .double?: return JKey("d:" + JS.toString(v))
        case let .string(s)?: return JKey("s:" + s)
        default: return nil
        }
    }

    /// `[...].join(sep)` element text: null and undefined are empty.
    static func cvJoinElem(_ v: V?) -> String { (v == nil || v == .null) ? "" : JS.toString(v) }

    /// `x.toFixed(2)` of a number (the exact decimal expansion, ties to the larger value).
    static func cvToFixed2(_ v: V?) throws -> String {
        guard let x = IV.num(v) else { throw JSError("x.toFixed is not a function") }
        if x.isNaN || x.isInfinite || abs(x) >= 1e21 { return JS.toString(.double(x)) }
        var a = abs(x)
        let j = a * 8 // exact: a power-of-two scaling; a tie needs x = odd / 8
        if j == j.rounded() && j.truncatingRemainder(dividingBy: 2) == 1 && a < 1e15 { a += 1e-9 }
        let s = String(format: "%.2f", a)
        return (x < 0 ? "-" : "") + s
    }

    /// `a + b` with b a number.
    static func cvAdd(_ a: V?, _ b: Double) -> V {
        switch a {
        case nil: return .double(.nan)
        case .null?: return num(b)
        case let .bool(x)?: return num((x ? 1 : 0) + b)
        case .int?, .double?: return num(IV.num(a)! + b)
        default: return .string(JS.toString(a) + JS.toString(.double(b)))
        }
    }

    /// An options number: absent / null is the default; anything but a number is refused (the reference would coerce it).
    static func cvOpt(_ v: V?, _ def: Double, _ what: String) throws -> Double {
        guard let x = JS.present(v) else { return def }
        guard let d = IV.num(x) else { throw JSError("\(what) must be a number") }
        return d
    }

    /// The list a `for (x of v)` / `v.map` / `v.forEach` walks: only an array (anything else is not iterable / has no such method).
    static func cvList(_ v: V?, _ what: String) throws -> [V] {
        guard case let .array(a)? = v else { throw JSError("\(what) is not iterable") }
        return a
    }

    /// UTF-16 code unit order (the default `Array.prototype.sort`).
    static func cvUnitLess(_ a: String, _ b: String) -> Bool { a.utf16.lexicographicallyPrecedes(b.utf16) }

    /// `s.slice(n)` by UTF-16 code units.
    static func cvSlice(_ s: String, _ n: Int) -> String {
        let u = Array(s.utf16)
        return n >= u.count ? "" : String(decoding: u[n...], as: UTF16.self)
    }

    // ---- which clause decided ----

    struct CoverageWitness {
        var decision: String
        var kind: String
        /// nil is JavaScript `undefined` (a clause without an `id`).
        var id: V?
        var also: [V?]

        var json: V {
            obj([("decision", .string(decision)), ("winner", obj([("kind", .string(kind)), ("id", id)])), ("also", .array(also.map { $0 ?? .null }))])
        }
    }

    static func clauseWitness(_ model: Model, _ action: V?) throws -> CoverageWitness {
        let decision = try decideAction(model, action)
        let ctx = try contextOfAction(action)
        var permits: [V?] = []
        for (i, p) in model.predicates.enumerated() where Predicates.predicateMatches(p, ctx, SafeRegex.Budget()) { permits.append(.string(permitId(i))) }
        var vetoes: [V] = []
        for v in model.vetoes { if try vetoApplies(v, ctx) { vetoes.append(v) } }
        var tighten: [V] = []
        for t in model.tighten {
            if Predicates.conditionTri(try rd(t, "when") ?? .null, ctx, SafeRegex.Budget()) != .f { tighten.append(t) }
        }
        func others(_ win: V?) -> [V?] {
            (permits + vetoes.map { mem($0, "id") } + tighten.map { mem($0, "id") }).filter { !cvSeq($0, win) }
        }
        func done(_ kind: String, _ id: V?) -> CoverageWitness { CoverageWitness(decision: decision, kind: kind, id: id, also: others(id)) }
        if !model.caveatSat || decision == "deny" {
            if !model.caveatSat { return done("caveat", V.string("caveats")) }
            if permits.isEmpty { return CoverageWitness(decision: decision, kind: "none", id: .null, also: others(.null)) }
            if let v = vetoes.first(where: { mem($0, "kind") == .string("deny") }) { return done("veto", mem(v, "id")) }
            if let t = tighten.first(where: { mem($0, "signal") == .string("deny") }) { return done("tighten", mem(t, "id")) }
            return done("caveat", V.string("caveats")) // reversibility cap or an ancestor of the chain
        }
        if decision == "escalate" {
            if let v = vetoes.first(where: { mem($0, "kind") == .string("approval") }) { return done("veto", mem(v, "id")) }
            return done("tighten", tighten.first.flatMap { JS.present(mem($0, "id")) } ?? .null)
        }
        return done("permit", permits.first.flatMap { $0 } ?? .null)
    }

    /// The decision with the clause that decided it: a forbid beats an approval rule, which beats a permit.
    static func witnessOf(_ model: Model, _ action: V?) throws -> V { try clauseWitness(model, action).json }

    // ---- mutation operators ----

    private static let flipOps: [String: String] = ["lt": "lte", "lte": "lt", "gt": "gte", "gte": "gt", "eq": "ne", "ne": "eq", "in": "nin", "nin": "in"]
    /// Names `flip[c.op]` would find on Object.prototype: the reference mutates to a function there, which no JSON can carry.
    private static let protoNames: Set<String> = ["constructor", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable",
                                                  "toLocaleString", "__proto__", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"]

    static func variantsOfCond(_ c: V?, _ eps: Double) throws -> [(cond: V, what: String)] {
        guard let c = c, isObjRec(c) else { return [] }
        if isGroup(c) {
            var out: [(cond: V, what: String)] = []
            if inObj(c, "not") {
                for v in try variantsOfCond(mem(c, "not"), eps) { out.append((.object(["not": v.cond]), "not(\(v.what))")) }
                return out
            }
            let isAll = inObj(c, "all_of")
            let key = isAll ? "all_of" : "any_of"
            guard case let .array(kids)? = mem(c, key) else { throw JSError("kids.forEach is not a function") }
            for (i, k) in kids.enumerated() {
                for v in try variantsOfCond(k, eps) {
                    var next = kids
                    next[i] = v.cond
                    out.append((.object([JKey(key): .array(next)]), "\(key)[\(i)] \(v.what)"))
                }
            }
            return out
        }
        guard isLeaf(c), mem(c, "ref") == nil else { return [] }
        var out: [(cond: V, what: String)] = []
        let field = mem(c, "field")!.asString!
        let name = IV.startsWith(field, "action.params.") ? IV.dropPrefix(field, 14) : field
        let op = mem(c, "op")
        let value = mem(c, "value")
        if let d = fin(value), let o = op?.asString, ["lt", "lte", "gt", "gte", "eq"].contains(o) {
            for nv in [d + eps, d - eps] {
                var m = c.asObject!
                m["value"] = num(nv)
                out.append((.object(m), "\(name) \(o) \(JS.toString(value)) -> \(JS.toString(.double(nv)))"))
            }
        }
        if let o = op?.asString {
            if protoNames.contains(o) { throw JSError("an operator named like an Object.prototype member") }
            if let f = flipOps[o] {
                var m = c.asObject!
                m["op"] = .string(f)
                out.append((.object(m), "\(name) \(o) -> \(f)"))
            }
        }
        return out
    }

    static func mutantsOf(_ model: Model, _ eps: Double) throws -> [(id: String, description: String, policy: V)] {
        var out: [(id: String, description: String, policy: V)] = []
        func mk(_ over: [String: V]) -> V {
            var o: JObject = ["predicates": .array(model.predicates), "caveats": .array(model.caveats), "vetoes": .array(model.vetoes), "tighten": .array(model.tighten)]
            for (k, v) in over { o[JKey(k)] = v }
            return .object(o)
        }
        func without(_ xs: [V], _ i: Int) -> [V] { xs.enumerated().filter { $0.offset != i }.map { $0.element } }
        func replacing(_ xs: [V], _ i: Int, _ v: V) -> [V] { var r = xs; r[i] = v; return r }
        for (i, p) in model.predicates.enumerated() {
            out.append(("drop-\(permitId(i))", "drop \(permitId(i))", mk(["predicates": .array(without(model.predicates, i))])))
            let whereList = try cvList(JS.present(try rd(p, "where")) ?? .array([]), "p.where")
            for (j, c) in whereList.enumerated() {
                for v in try variantsOfCond(c, eps) {
                    var np = JSLoose.spread(p)
                    np["where"] = .array(replacing(whereList, j, v.cond))
                    out.append(("\(permitId(i)).where[\(j)]:\(v.what)", "\(permitId(i)): \(v.what)", mk(["predicates": .array(replacing(model.predicates, i, .object(np)))])))
                }
                var np = JSLoose.spread(p)
                np["where"] = .array(without(whereList, j))
                out.append(("\(permitId(i)).where[\(j)]:drop", "\(permitId(i)): drop condition \(j)", mk(["predicates": .array(replacing(model.predicates, i, .object(np)))])))
            }
        }
        for (i, v) in model.vetoes.enumerated() {
            let id = JS.toString(try rd(v, "id"))
            out.append(("drop-veto:\(id)", "drop prohibition \(id)", mk(["vetoes": .array(without(model.vetoes, i))])))
            if let over = mem(v, "over"), JS.truthy(over) {
                var no = JSLoose.spread(over)
                no["threshold"] = cvAdd(mem(over, "threshold"), eps)
                var nv = JSLoose.spread(v)
                nv["over"] = .object(no)
                out.append(("veto:\(id):threshold+", "raise the \(id) threshold by \(JS.toString(.double(eps)))", mk(["vetoes": .array(replacing(model.vetoes, i, .object(nv)))])))
            }
        }
        for (i, t) in model.tighten.enumerated() {
            let id = JS.toString(try rd(t, "id"))
            out.append(("drop-tighten:\(id)", "drop tighten rule \(id)", mk(["tighten": .array(without(model.tighten, i))])))
        }
        return out
    }

    // ---- coverage ----

    /// The `where` conditions a predicate carries (`(p.where ?? []).forEach`).
    static func cvWhere(_ p: V?) throws -> [V] { try cvList(JS.present(try rd(p, "where")) ?? .array([]), "p.where") }

    /// Coverage of `policy` by `traffic` (production traffic, simulated actions or the cases of a test document).
    static func coverage(_ policy: V?, _ traffic: V?, _ o: V? = nil) throws -> V {
        let model = try toModel(policy)
        let opts: V = o ?? .object([:])
        let eps = try cvOpt(try rd(opts, "epsilon"), 1, "epsilon")
        let np = model.predicates.count, nv = model.vetoes.count
        var ids: [(id: V?, kind: String)] = []
        for i in model.predicates.indices { ids.append((V.string(permitId(i)), "permit")) }
        for v in model.vetoes { ids.append((mem(v, "id"), "veto")) }
        for t in model.tighten { ids.append((mem(t, "id"), "tighten")) }
        var matched: [JKey: Int] = [:], decisive: [JKey: Int] = [:]
        func bump(_ m: inout [JKey: Int], _ k: V?) { if k != .null, let key = cvKey(k) { m[key, default: 0] += 1 } }
        let list = try cvList(traffic, "traffic")
        for a in list {
            let w = try clauseWitness(model, a)
            bump(&decisive, w.id)
            for id in [w.id] + w.also { bump(&matched, id) }
        }
        func reach(_ kind: String, _ idx: Int) throws -> V {
            let r: V
            switch kind {
            case "permit": r = try alwaysDenies(obj([("predicates", .array([model.predicates[idx]])), ("caveats", .array(model.caveats))]), nil)
            case "veto": r = try alwaysDenies(obj([("predicates", .array([try rd(model.vetoes[idx], "when") ?? .null]))]), nil)
            default: return .string("unknown")
            }
            if JS.truthy(mem(r, "approximate")) { return .string("unknown") }
            return .bool(!JS.truthy(mem(r, "alwaysDenies")))
        }
        struct Cl { var id: V?; var kind: String; var matched: Int; var decisive: Int; var reachable: V }
        var cls: [Cl] = []
        for (n, c) in ids.enumerated() {
            let key = cvKey(c.id)
            let m = key.flatMap { matched[$0] } ?? 0, d = key.flatMap { decisive[$0] } ?? 0
            cls.append(Cl(id: c.id, kind: c.kind, matched: m, decisive: d, reachable: try reach(c.kind, c.kind == "permit" ? n : c.kind == "veto" ? n - np : n - np - nv)))
        }
        // the numeric thresholds of the policy
        var paths: [String] = []
        func addPath(_ p: String) { if !paths.contains(where: { IV.same($0, p) }) { paths.append(p) } }
        func walk(_ c: V?) throws {
            guard let c = c, isObjRec(c) else { return }
            if isGroup(c) {
                if inObj(c, "all_of") { for x in try cvList(mem(c, "all_of"), "c.all_of") { try walk(x) } }
                else if inObj(c, "any_of") { for x in try cvList(mem(c, "any_of"), "c.any_of") { try walk(x) } }
                else { try walk(mem(c, "not")) }
            } else if isLeaf(c), let f = mem(c, "field")?.asString, IV.startsWith(f, "action.params."),
                      let op = mem(c, "op")?.asString, ["lt", "lte", "gt", "gte", "eq", "in", "nin"].contains(op) { addPath(f) }
        }
        for p in try probeSet(model) { for c in try cvWhere(p) { try walk(c) } }
        for v in model.vetoes {
            if let over = mem(v, "over"), JS.truthy(over) {
                guard let s = mem(over, "path")?.asString else { throw JSError("path.slice is not a function") }
                addPath(s)
            }
        }
        var boundaries: [V] = []
        for path in paths.sorted(by: cvUnitLess) {
            let name = cvSlice(path, 14)
            var vals: [Double] = []
            for a in list {
                if let x = IV.num(mem(JS.present(try rd(a, "params")) ?? .object([:]), name)) { vals.append(x) }
            }
            for t in try thresholdsOf(model, path) {
                boundaries.append(obj([("path", .string(path)), ("threshold", num(t)), ("at", .bool(vals.contains { $0 == t })),
                                       ("below", .bool(vals.contains { $0 < t && $0 >= t - eps })), ("above", .bool(vals.contains { $0 > t && $0 <= t + eps }))]))
            }
        }
        // mutants
        let allMut = try mutantsOf(model, eps)
        let mm = JS.present(try rd(opts, "maxMutants")).map { JS.toNumber($0) } ?? 200
        var end = 0
        if !mm.isNaN {
            let t = mm.rounded(.towardZero)
            let c = Swift.max(Swift.min(t, 1e9), -1e9)
            end = c < 0 ? Swift.max(allMut.count + Int(c), 0) : Swift.min(Int(c), allMut.count)
        }
        let muts = Array(allMut[..<end])
        var survivors: [V] = []
        var killed = 0, equiv = 0
        let base = try list.map { try decideAction(model, $0) }
        for m in muts {
            let mmod = try toModel(m.policy)
            var differs = false
            for (i, a) in list.enumerated() {
                if try decideAction(mmod, a) != base[i] { differs = true; break }
            }
            if differs { killed += 1; continue }
            let eq = try equivalent(policy, m.policy)
            if mem(eq, "equivalent") == .bool(true) { equiv += 1; continue }
            var s: [(String, V?)] = [("id", .string(m.id)), ("description", .string(m.description))]
            if let ce = mem(eq, "counterexample"), JS.truthy(ce) { s.append(("killer", ce)) }
            survivors.append(obj(s))
        }
        func ratio(_ n: Int, _ d: Int) -> V { d == 0 ? .int(1) : num(Double(n) / Double(d)) }
        let live = cls.filter { $0.reachable != .bool(false) }
        func idList(_ xs: [Cl]) -> V { .array(xs.map { $0.id ?? .null }) }
        return obj([
            ("traffic", .int(Int64(list.count))), ("policyDigest", .string(try policyDigestOf(model))),
            ("clauses", .array(cls.map { obj([("id", $0.id), ("kind", .string($0.kind)), ("matched", .int(Int64($0.matched))), ("decisive", .int(Int64($0.decisive))), ("reachable", $0.reachable)]) })),
            ("neverMatched", idList(cls.filter { $0.matched == 0 })), ("neverDecisive", idList(cls.filter { $0.decisive == 0 })),
            ("untested", idList(cls.filter { $0.reachable != .bool(false) && $0.matched == 0 })), ("unreachable", idList(cls.filter { $0.reachable == .bool(false) })),
            ("boundaries", .array(boundaries)),
            ("mutants", obj([("total", .int(Int64(muts.count))), ("killed", .int(Int64(killed))), ("equivalent", .int(Int64(equiv))), ("survivors", .array(survivors))])),
            ("score", obj([("clauses", ratio(live.filter { $0.decisive > 0 }.count, live.count)),
                           ("boundaries", ratio(boundaries.filter { mem($0, "at") == .bool(true) && mem($0, "below") == .bool(true) && mem($0, "above") == .bool(true) }.count, boundaries.count)),
                           ("mutation", ratio(killed, muts.count - equiv))])),
        ])
    }

    /// A CI gate over a coverage report: {ok, reasons}.
    static func coverageGate(_ r: V?, _ min: V? = nil) throws -> V {
        let mn: V = min ?? .object([:])
        var reasons: [String] = []
        for (key, label) in [("clauses", "clause coverage"), ("boundaries", "boundary coverage"), ("mutation", "mutation score")] {
            let sc = try rd(try rd(r, "score"), key)
            let lim = try rd(mn, key)
            if JSLoose.lt(sc, JS.present(lim) ?? .int(0)) { reasons.append("\(label) \(try cvToFixed2(sc)) < \(JS.toString(lim))") }
        }
        if let ms = try rd(mn, "maxSurvivors") {
            let len = try rd(try rd(try rd(r, "mutants"), "survivors"), "length")
            if JSLoose.gt(len, ms) { reasons.append("\(JS.toString(len)) surviving mutants > \(JS.toString(ms))") }
        }
        let un = try rd(try rd(r, "unreachable"), "length")
        if JSLoose.gt(un, .int(0)) {
            guard case let .array(items)? = mem(r, "unreachable") else { throw JSError("r.unreachable.join is not a function") }
            reasons.append("unreachable clauses: " + items.map { cvJoinElem($0) }.joined(separator: ", "))
        }
        return obj([("ok", .bool(reasons.isEmpty)), ("reasons", strs(reasons))])
    }
}
