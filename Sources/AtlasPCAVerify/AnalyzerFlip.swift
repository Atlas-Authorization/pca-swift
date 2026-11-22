import Foundation

/// Minimal-change counterfactual search on a deny or escalate: the smallest verified change that gets an action to the wanted decision
/// (default allow), ordered by cost: wait, change one parameter, change two together, another resource, obtain a fact, split (opt-in),
/// and only then ask a human. The search PROPOSES, the real decision VERIFIES: a candidate is returned only when the evaluator confirms
/// it, so a bug here can lose a repair but never invent one. Values of `critical` parameters are redacted by default.

/// A verified repair: the typed patch, its relative cost, the decision it reaches and the repaired action.
fileprivate struct FlCand {
    var repair: JSONValue
    var cost: Double
    var decision: String
    var action: JSONValue
    var json: JSONValue { PCAAnalyzer.obj([("repair", repair), ("cost", PCAAnalyzer.num(cost)), ("decision", .string(decision)), ("action", action)]) }
}

/// One dimension of a two-edit repair.
fileprivate struct FlDim {
    var cost: Double
    var make: (JSONValue, JSONValue) -> JSONValue
    var step: (JSONValue) -> JSONValue
    var values: [JSONValue]
}

extension PCAAnalyzer {
    /// `RANK[x]`: deny 0, escalate 1, allow 2; anything else is `undefined` (every comparison with it is false: NaN).
    fileprivate static func flRank(_ v: V?) -> Double {
        switch v?.asString {
        case "deny"?: return 0
        case "escalate"?: return 1
        case "allow"?: return 2
        default: return .nan
        }
    }

    /// The camelCase caveat context of a query as the context the caveat evaluator reads (its own spelling is snake_case; a snake_case
    /// member of the query is not part of the camelCase context and is dropped, so it can never open a caveat).
    fileprivate static func flCtx(_ c: V?) -> V {
        guard case let .object(o)? = c else { return c ?? .null }
        let pairs = [("blastRadius", "blast_radius"), ("reversibilityClass", "reversibility_class"), ("delegationDepth", "delegation_depth"), ("recentActionTimes", "recent_action_times")]
        var out = o
        for (_, snake) in pairs { out[JKey(snake)] = nil }
        for (camel, snake) in pairs { if let v = o[JKey(camel)] { out[JKey(camel)] = nil; out[JKey(snake)] = v } }
        return .object(out)
    }

    fileprivate static func flOpen(_ model: Model, _ ctx: V?) -> Bool { PCA.evaluateCaveats(.array(model.caveats), context: flCtx(ctx)).ok }

    /// A stable sort by a comparator that returns a number (negative: first); a NaN result keeps the order.
    fileprivate static func flStable<T>(_ xs: [T], _ cmp: (T, T) -> Double) -> [T] {
        xs.indices.sorted { a, b in
            let r = cmp(xs[a], xs[b])
            return r < 0 || (!(r > 0) && a < b)
        }.map { xs[$0] }
    }

    /// `shape?.params[name]` (a shape without `params` is a TypeError).
    fileprivate static func flDecl(_ shape: V?, _ name: String) throws -> V? {
        guard let s = shape else { return nil }
        return try rd(try rd(s, "params"), name)
    }

    /// `{...action, params: {...(action.params ?? {}), [name]: v}}`.
    fileprivate static func flWithParam(_ a: V, _ name: String, _ v: V) -> V {
        var o = JSLoose.spread(a)
        var p = JSLoose.spread(JS.present(mem(a, "params")) ?? .object([:]))
        p[JKey(name)] = v
        o[JKey("params")] = .object(p)
        return .object(o)
    }

    /// `{...action, [key]: v}`.
    fileprivate static func flWith(_ a: V, _ key: String, _ v: V) -> V {
        var o = JSLoose.spread(a)
        o[JKey(key)] = v
        return .object(o)
    }

    fileprivate static func flSetPath(_ o: JObject, _ path: [String], _ v: V) -> JObject {
        guard let k = path.first else { return o }
        var out = o
        let rest = Array(path.dropFirst())
        out[JKey(k)] = rest.isEmpty ? v : .object(flSetPath(JSLoose.spread(JS.present(o[JKey(k)]) ?? .object([:])), rest, v))
        return out
    }

    /// `[...new Set(xs)]` over strings and numbers (the only values it is given).
    fileprivate static func flDedupe(_ xs: [V]) -> [V] {
        var seen = Set<String>(), out: [V] = []
        for x in xs {
            let k: String
            if let s = x.asString { k = "s" + s } else if let d = IV.num(x) { k = "n" + (d == 0 ? "0" : JS.toString(.double(d))) } else { k = "o\(out.count)" }
            if seen.insert(k).inserted { out.append(x) }
        }
        return out
    }

    /// `slice(0, n)` of a list of `count`.
    fileprivate static func flSliceEnd(_ n: Double, _ count: Int) -> Int {
        if n.isNaN { return 0 }
        let t = n.rounded(.towardZero)
        if t < 0 { return Swift.max(count + Int(Swift.max(t, -1e9)), 0) }
        return t >= Double(count) ? count : Int(t)
    }

    /// Anything that bounds the total over several actions: a rate, a budget allocation.
    fileprivate static func flMeters(_ m: Model) throws -> Bool {
        for c in m.caveats + m.meets.flatMap({ $0.caveats }) {
            let t = try rd(c, "type")?.asString
            if IV.same(t, "rate") || IV.same(t, "budget_alloc") || IV.same(t, "max_blast_radius") { return true }
        }
        return false
    }

    /// The time at which a closed time or rate caveat opens (nil when no caveat names one).
    fileprivate static func flWait(_ caveats: [V], _ ctx: V) throws -> Double? {
        var at: Double?
        let now = mem(ctx, "now")
        for c in caveats {
            let t = try rd(c, "type")?.asString
            if IV.same(t, "not_before"), let cat = IV.num(mem(c, "at")), JSLoose.gt(.double(cat), now) { at = exMaxFl(at ?? 0, cat) }
            if IV.same(t, "rate"), let mx = IV.num(mem(c, "max")), let ps = IV.num(mem(c, "per_secs")) {
                let span = ps * 1000
                var times: [V] = []
                if let rv = JS.present(mem(ctx, "recentActionTimes")) {
                    guard case let .array(l) = rv else { throw fail("recentActionTimes.filter is not a function") }
                    times = l
                }
                let floor = JS.toNumber(now) - span
                let recent = flStable(times.filter { JSLoose.gt($0, .double(floor)) }.map { JS.toNumber($0) }) { $0 - $1 }
                if Double(recent.count) >= mx {
                    let i = Double(recent.count) - mx
                    let v: Double = (i == i.rounded(.towardZero) && i >= 0 && i < Double(recent.count)) ? recent[Int(i)] + span : .nan
                    at = exMaxFl(at ?? 0, v)
                }
            }
        }
        return at
    }

    private static func exMaxFl(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : Swift.max(a, b) }

    /// The smallest verified change that gets `action` to the wanted decision. `o`: {desired, schema, holderAuthenticated, probe,
    /// changeable, caveatContext, allowSplit, redact, maxCandidates}.
    static func minimalFlip(_ policy: V?, _ action: V?, _ o: V?) throws -> V {
        let model = try toModel(policy)
        let cctx = try rd(o, "caveatContext")
        let caveatsOk = cctx == nil || flOpen(model, cctx)
        var current = "deny"
        if caveatsOk { current = try decideAction(model, action) }
        let want: V = JS.present(try rd(o, "desired")) ?? .string("allow")
        let rankWant = flRank(want)
        var res: JObject = ["current": .string(current), "repairs": .array([]), "repairExists": .bool(false)]
        if !JS.truthy(try rd(o, "holderAuthenticated")) {
            res["refused"] = .string("counterfactuals are shown only to the authenticated holder")
            return .object(res)
        }
        if let probe = try rd(o, "probe"), JS.truthy(probe) {
            guard case let .array(hist)? = try rd(probe, "history") else { throw fail("probe.history.filter is not a function") }
            let probeNow = JS.toNumber(mem(probe, "now")), probeWindow = JS.toNumber(mem(probe, "windowSecs"))
            // a clock, window or history stamp that is not finite cannot say what is still inside the window: refuse (a +Infinity limit stays an unbounded cap)
            if !(probeNow.isFinite && probeWindow.isFinite && hist.allSatisfy({ IV.num($0)?.isFinite ?? false })) {
                res["refused"] = .string("probe budget exhausted")
                res["probe"] = .object(["history": .array(hist)])
                return .object(res)
            }
            let floor = probeNow - probeWindow * 1000
            let recent = hist.filter { JSLoose.gt($0, .double(floor)) }
            if !(Double(recent.count) < JS.toNumber(mem(probe, "limit"))) {
                res["refused"] = .string("probe budget exhausted")
                res["probe"] = .object(["history": .array(recent)])
                return .object(res)
            }
            res["probe"] = .object(["history": .array(recent + [mem(probe, "now") ?? .null])])
        }
        let digest = try policyDigestOf(model)
        if flRank(.string(current)) >= rankWant { return .object(res) }

        var shape: V?
        if let schema = JS.present(try rd(o, "schema")) {
            guard case let .array(sl) = schema else { throw fail("o.schema.find is not a function") }
            for s in sl { if IV.strictEq(try rd(s, "verb"), try rd(action, "verb")) { shape = s; break } }
        }
        func reaches(_ a: V) throws -> String? {
            let d = try decideAction(model, a)
            return flRank(.string(d)) >= rankWant ? d : nil
        }
        var cands: [FlCand] = []
        func push(_ repair: V, _ cost: Double, _ a: V) throws {
            if let d = try reaches(a) { cands.append(FlCand(repair: repair, cost: cost, decision: d, action: a)) }
        }
        let pr = try collectProbes(ProbeInputs(predicateSets: [try probeSet(model)], varyReversibility: model.revCap != nil))
        let paramsV: V = JS.present(try rd(action, "params")) ?? .object([:])
        let paramsObj = JSLoose.spread(paramsV)
        let act: V = action ?? .null
        let actResource = mem(action, "resource")
        var names: [String]
        if let ch = JS.present(try rd(o, "changeable")) {
            guard case let .array(l) = ch else { throw fail("changeable is not iterable") }
            names = l.map { JS.toString($0) }
        } else if let sh = shape {
            guard let sp = try rd(sh, "params"), sp != .null else { throw fail("Cannot convert undefined or null to object") }
            names = JSLoose.keys(sp)
        } else {
            names = JSLoose.keys(paramsV)
        }
        func fieldValues(_ path: String) -> [V] {
            (pr.fields.first { IV.same($0.path, path) }?.values ?? []).compactMap { if case let .value(v) = $0 { return v }; return nil }
        }
        let otherRes: [V] = pr.resources.compactMap { $0 }.filter { x in
            guard let s = x.asString else { return false }
            return !IV.startsWith(s, "\u{0}") && !IV.strictEq(x, actResource)
        }

        // 1. wait: a time caveat that is not open yet, or a rate window that will reset (decided by the caveat evaluator at that time)
        if !caveatsOk, let cc = cctx, JS.truthy(cc) {
            let at = try flWait(model.caveats, cc)
            let d = try decideAction(model, action)
            if let at = at {
                var later = JSLoose.spread(cc)
                later[JKey("now")] = num(at)
                if flOpen(model, .object(later)), flRank(.string(d)) >= rankWant {
                    cands.append(FlCand(repair: obj([("kind", .string("wait_until")), ("at", num(at)), ("reason", .string("a time or rate caveat opens then"))]), cost: 1, decision: d, action: act))
                }
            }
        }
        let finish = !caveatsOk // nothing else helps while a caveat is closed: the other repairs are only searched once it is open

        // 2. one parameter changed: the nearest verified value, per parameter
        if !finish {
            for name in names {
                let path = "action.params." + name
                let decl = try flDecl(shape, name)
                let cur = JSLoose.get(paramsV, name)
                var pool = fieldValues(path)
                if let dv = JS.present(mem(decl, "values")) { pool += try JS.spread(dv) }
                if let mn = mem(decl, "min") { pool.append(mn) }
                if let mx = mem(decl, "max") { pool.append(mx) }
                let nums = pool.compactMap { fin($0) }
                let T = try thresholdsOf(model, path)
                let curNum = IV.num(cur)
                let integer = IV.strictEq(mem(decl, "type"), .string("integer")) || (curNum.map { $0.isFinite && $0 == $0.rounded(.towardZero) } ?? false)
                let ints = integer ? T.flatMap { [$0 - 1, $0 + 1] } : []
                var seenN = Set<Double>(), numeric: [Double] = []
                for v in nums + ints where !v.isNaN && seenN.insert(v == 0 ? 0 : v).inserted { numeric.append(v) }
                let dmin = mem(decl, "min"), dmax = mem(decl, "max")
                numeric = numeric.filter { v in (dmin == nil || v >= JS.toNumber(dmin)) && (dmax == nil || v <= JS.toNumber(dmax)) }
                let c0 = curNum ?? 0
                numeric = flStable(numeric) { a, b in
                    let d = abs(a - c0) - abs(b - c0)
                    return (d != 0 && !d.isNaN) ? d : a - b
                }
                var strsL: [String] = []
                for v in pool { if let s = v.asString, !IV.startsWith(s, "\u{0}"), !strsL.contains(where: { IV.same($0, s) }) { strsL.append(s) } }
                for v in numeric.map({ num($0) }) + strsL.map({ V.string($0) }) {
                    if IV.strictEq(v, cur) { continue }
                    let a = flWithParam(act, name, v)
                    guard let d = try reaches(a) else { continue }
                    var extra = 0.5
                    if let vn = IV.num(v), let cn = curNum {
                        let q = abs(vn - cn) / (abs(cn) + 1)
                        extra = q.isNaN ? .nan : Swift.min(1, q)
                    }
                    cands.append(FlCand(repair: obj([("kind", .string("set_param")), ("param", .string(name)), ("from", cur), ("to", v)]), cost: 2 + extra, decision: d, action: a))
                    break // the pool is ordered nearest first
                }
            }
        }

        // 2b. when no single edit works, the cheapest PAIR of edits (a parameter and the resource, or two parameters)
        if !finish && cands.isEmpty {
            var dims: [FlDim] = []
            for name in names {
                var vals = fieldValues("action.params." + name)
                if let dv = JS.present(mem(try flDecl(shape, name), "values")) { vals += try JS.spread(dv) }
                let curp = JSLoose.get(paramsV, name)
                let kept = vals.filter { v in (v.asString.map { !IV.startsWith($0, "\u{0}") } ?? v.isNumber) && !IV.strictEq(v, curp) }
                dims.append(FlDim(cost: 2, make: { a, v in flWithParam(a, name, v) },
                                  step: { v in obj([("kind", .string("set_param")), ("param", .string(name)), ("from", curp), ("to", v)]) },
                                  values: Array(flDedupe(kept).prefix(6))))
            }
            dims.append(FlDim(cost: 3, make: { a, v in flWith(a, "resource", v) },
                              step: { v in obj([("kind", .string("set_resource")), ("from", actResource), ("to", v)]) },
                              values: Array(otherRes.prefix(6))))
            for i in dims.indices {
                for j in dims.indices where j > i {
                    for x in dims[i].values {
                        for y in dims[j].values {
                            let a = dims[j].make(dims[i].make(act, x), y)
                            if let d = try reaches(a) {
                                cands.append(FlCand(repair: obj([("kind", .string("combine")), ("steps", .array([dims[i].step(x), dims[j].step(y)]))]), cost: dims[i].cost + dims[j].cost, decision: d, action: a))
                            }
                        }
                    }
                }
            }
        }

        if !finish {
            // 3. another allowed resource
            for r in otherRes {
                try push(obj([("kind", .string("set_resource")), ("from", actResource), ("to", r)]), 3, flWith(act, "resource", r))
            }
            // 4. a named fact that is missing: a subject or env field the policy reads
            for f in pr.fields where IV.startsWith(f.path, "subject.") || IV.startsWith(f.path, "env.") {
                let segs = IV.split(f.path, ".")
                let root = segs[0], rest = Array(segs.dropFirst())
                for case let .value(v) in f.values {
                    let a = flWith(act, root, .object(flSetPath(JSLoose.spread(JS.present(mem(action, root)) ?? .object([:])), rest, v)))
                    let before = try reaches(act)
                    if let d = try reaches(a), before == nil {
                        cands.append(FlCand(repair: obj([("kind", .string("obtain_fact")), ("path", .string(f.path)), ("value", v)]), cost: 4, decision: d, action: a))
                        break
                    }
                }
            }
        }

        // 5. split (opt-in, and only when nothing meters the total)
        if mem(o, "allowSplit") == .bool(true), try !flMeters(model) {
            for name in names {
                guard let cur = IV.num(JSLoose.get(paramsV, name)), cur.isFinite else { continue }
                let flipped = cands.first { c in
                    IV.same(mem(c.repair, "kind")?.asString, "set_param") && IV.same(mem(c.repair, "param")?.asString, name) && IV.num(mem(c.repair, "to")) != nil
                }
                guard let part = flipped.flatMap({ IV.num(mem($0.repair, "to")) }), part > 0, part < cur else { continue }
                let n = (cur / part).rounded(.up)
                if n > 8 { continue }
                var parts: [V] = []
                for i in 0..<Int(n) { parts.append(.object([JKey(name): num(i < Int(n) - 1 ? part : cur - part * (n - 1))])) }
                var all = true
                for p in parts {
                    var merged = paramsObj
                    for (k, v) in JSLoose.spread(p) { merged[k] = v }
                    if try reaches(flWith(act, "params", .object(merged))) == nil { all = false; break }
                }
                if all { cands.append(FlCand(repair: obj([("kind", .string("split")), ("param", .string(name)), ("parts", .array(parts))]), cost: 3 + n, decision: want.asString ?? "allow", action: act)) }
            }
        }

        let sorted = flStable(cands) { $0.cost - $1.cost }
        let top = Array(sorted.prefix(flSliceEnd(JS.toNumber(JS.present(try rd(o, "maxCandidates")) ?? .int(8)), sorted.count)))
        res["repairExists"] = .bool(!top.isEmpty)
        let redact: V = JS.present(try rd(o, "redact")) ?? .string("critical")
        var redacted = false
        func hide(_ c: FlCand) throws -> FlCand {
            guard IV.same(mem(c.repair, "kind")?.asString, "set_param"), !IV.strictEq(redact, .string("none")) else { return c }
            let param = mem(c.repair, "param")?.asString ?? ""
            let sens = mem(try flDecl(shape, param), "sensitivity")
            if IV.strictEq(redact, .string("critical")) && !IV.strictEq(sens, .string("critical")) { return c }
            redacted = true
            return FlCand(repair: obj([("kind", .string("set_param")), ("param", .string(param)), ("redacted", .bool(true))]), cost: c.cost, decision: c.decision, action: .object(JSLoose.spread(act)))
        }
        if IV.strictEq(redact, .string("all")) { redacted = true } else { res["repairs"] = .array(try top.map { try hide($0).json }) }
        if let free = top.first(where: { $0.decision == "allow" && !IV.same(mem($0.repair, "kind")?.asString, "split") }), current == "escalate" {
            res["humanFree"] = try hide(free).json
        }
        if current == "escalate" || top.isEmpty {
            res["humanAsk"] = obj([("verb", mem(action, "verb")), ("resource", actResource), ("params", .object(paramsObj)),
                                   ("kind", .string(current == "escalate" ? "approval" : "access-request")), ("policyDigest", .string(digest))])
        }
        if redacted { res["redacted"] = .bool(true) }
        return .object(res)
    }
}
