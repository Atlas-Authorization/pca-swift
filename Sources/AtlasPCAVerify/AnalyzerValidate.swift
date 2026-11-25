import Foundation

/// Validating a policy against the action schema / ActionDefs it is written for (a lint that runs before the policy is signed).
/// Schemas, definitions and policies are plain JSON trees (`JSONValue`); a reference TypeError is a thrown `JSError`.
extension PCAAnalyzer {
    private static let defTypes: Set<String> = ["string", "integer", "boolean", "date", "set", "array"]

    /// `Object.entries(x)` of a value: an object's members, an array's / string's indices, nothing for any other value.
    static func vdEntries(_ x: V?) -> [(key: String, value: V?)] { JSLoose.keys(x).map { ($0, JSLoose.get(x, $0)) } }

    /// The shape of one ActionDef parameter (`verbShapesFromActionDefs` of a single parameter).
    static func vdDefShape(_ p: V?) throws -> V {
        let t = JS.toString(try rd(p, "type"))
        var o: [(String, V?)] = []
        if defTypes.contains(t) { o.append(("type", .string(t))) }
        if let r = mem(p, "role"), JS.truthy(r) { o.append(("semantic", r)) }
        if let v = mem(p, "values"), JS.truthy(v) { o.append(("values", v)) }
        o.append(("min", mem(p, "min")))
        o.append(("max", mem(p, "max")))
        if let s = mem(p, "sensitivity"), JS.truthy(s) { o.append(("sensitivity", s)) }
        o.append(("required", mem(p, "required")))
        return obj(o)
    }

    /// Verb shapes from real ActionDefs. Types the policy language cannot compare directly are left untyped (unchecked).
    static func verbShapesFromActionDefs(_ defs: V?) throws -> V {
        var out: [V] = []
        for d in try cvList(defs, "defs") {
            var params: JObject = [:]
            for (k, p) in vdEntries(JS.present(try rd(d, "params")) ?? .object([:])) { params[JKey(k)] = try vdDefShape(p) }
            out.append(obj([("verb", try rd(d, "verb")), ("params", .object(params))]))
        }
        return .array(out)
    }

    /// The verbs and parameters of a signed action schema, a list of shapes, or a list of ActionDefs.
    static func verbShapes(_ src: V?) throws -> V {
        var out: [V] = []
        if case .array? = src {} else {
            guard let s = src, isObjRec(s) else { throw JSError("Cannot use 'in' operator to search for 'verbs'") }
            guard inObj(s, "verbs") else { throw JSError("list.map is not a function") }
            for v in try cvList(mem(s, "verbs"), "src.verbs") {
                var params: JObject = [:]
                for (k, d) in vdEntries(JS.present(try rd(v, "params")) ?? .object([:])) {
                    var o: [(String, V?)] = [("type", try rd(d, "type"))]
                    if let x = mem(d, "values"), JS.truthy(x) { o.append(("values", x)) }
                    o.append(("min", mem(d, "min")))
                    o.append(("max", mem(d, "max")))
                    if let x = mem(d, "unit"), JS.truthy(x) { o.append(("unit", x)) }
                    o.append(("semantic", mem(d, "semantic")))
                    o.append(("sensitivity", mem(d, "sensitivity")))
                    o.append(("required", mem(d, "required")))
                    params[JKey(k)] = obj(o)
                }
                out.append(obj([("verb", try rd(v, "verb")), ("params", .object(params))]))
            }
            return .array(out)
        }
        for d in try cvList(src, "src") {
            guard d.isObject || d.isArray else { throw JSError("Cannot use 'in' operator to search for 'verb'") }
            var verb: V = .string("")
            if inObj(d, "verb"), let x = mem(d, "verb"), JS.truthy(x) { verb = x }
            else if inObj(d, "id"), let x = mem(d, "id"), JS.truthy(x) { verb = x }
            let origParams = JS.present(mem(d, "params")) ?? .object([:])
            var params: JObject = [:]
            for (k, p) in vdEntries(origParams) {
                guard case var .object(shape) = try vdDefShape(p) else { continue }
                // shape-style params carry `semantic` and `unit` directly; keep them
                for f in ["semantic", "unit"] { if let x = mem(JSLoose.get(origParams, k), f) { shape[JKey(f)] = x } }
                params[JKey(k)] = .object(shape)
            }
            out.append(obj([("verb", verb), ("params", .object(params))]))
        }
        return .array(out)
    }

    // ---- the lint ----

    private static func vdLeaves(_ c: V?, _ into: inout [V]) {
        guard let c = c, c.isObject || c.isArray else { return }
        if isGroup(c) {
            if inObj(c, "all_of"), let a = mem(c, "all_of")?.asArray { for x in a { vdLeaves(x, &into) } }
            else if inObj(c, "any_of"), let a = mem(c, "any_of")?.asArray { for x in a { vdLeaves(x, &into) } }
            else if inObj(c, "not") { vdLeaves(mem(c, "not"), &into) }
        } else { into.append(c) }
    }

    private static func vdTypeOk(_ t: V?, _ v: V?) -> Bool {
        guard let t = t else { return true }
        switch t.asString {
        case "integer"?: return fin(v) != nil
        case "boolean"?: if case .bool? = v { return true } else { return false }
        case "string"?, "date"?: return v?.asString != nil
        default: return true
        }
    }

    /// `d.values.includes(x)` for a string x: an array holds it, a string contains it, anything else has no `includes`.
    private static func vdIncludes(_ values: V, _ x: String) throws -> Bool {
        switch values {
        case let .array(a): return a.contains { $0.asString.map { IV.same($0, x) } ?? false }
        case let .string(s):
            let h = Array(s.utf16), n = Array(x.utf16)
            if n.isEmpty { return true }
            if h.count < n.count { return false }
            return (0...(h.count - n.count)).contains { Array(h[$0..<($0 + n.count)]) == n }
        default: throw JSError("d.values.includes is not a function")
        }
    }

    /// `n <= v` / `n >= v` of JS: false when either side is NaN after conversion.
    private static func vdGe(_ a: V?, _ b: V?) -> Bool {
        !JSLoose.lt(a, b) && !JS.toNumber(JSLoose.prim(a)).isNaN && !JS.toNumber(JSLoose.prim(b)).isNaN
    }

    private static func vdOp(_ op: V?, _ names: [String]) -> Bool { op?.asString.map { s in names.contains { IV.same($0, s) } } ?? false }

    private static func vdSemanticMoney(_ d: V?) throws -> Bool {
        guard let s = JS.present(mem(d, "semantic")) else { return false }
        guard case let .string(t) = s else { throw JSError("startsWith is not a function") }
        return IV.startsWith(t, "money.")
    }

    private static func vdGrants(_ p: V?, _ verb: V?) throws -> Bool {
        let pv = try rd(p, "verb")
        if cvSeq(pv, .string("*")) || cvSeq(pv, verb) { return true }
        if case let .array(a)? = pv { return a.contains { cvSeq($0, .string("*")) } || a.contains { cvSeq($0, verb) } }
        return false
    }

    /// Lint a policy against the schema it is written for. `ok` is false when any finding is an error.
    static func validatePolicyAgainstSchema(_ policy: V?, _ src: V?, _ o: V? = nil) throws -> V {
        let shapeList = try cvList(try verbShapes(src), "shapes")
        let opts: V = o ?? .object([:])
        var byVerb: [JKey: Int] = [:]
        for (i, s) in shapeList.enumerated() { if let k = cvKey(mem(s, "verb")) { byVerb[k] = i } }
        let shapeVerbs: [V?] = shapeList.map { mem($0, "verb") }
        var srcIsList = false
        if case .array? = src { srcIsList = true }
        let schemaUnits: V? = JS.present(try rd(opts, "schemaUnits")) ?? ((!srcIsList && inObj(src, "units")) ? mem(src, "units") : nil)
        let model = try toModel(policy)
        var findings: [V] = []
        func add(_ code: String, _ severity: String, _ where_: V?, _ message: String) {
            findings.append(obj([("code", .string(code)), ("severity", .string(severity)), ("where", where_), ("message", .string(message))]))
        }
        let units = mem(opts, "units")
        let listUngranted = JS.truthy(mem(opts, "listUngranted"))
        func shapeIndex(_ v: V?) -> Int? { cvKey(v).flatMap { byVerb[$0] } }

        func check(_ p: V?, _ where_: String, _ isVeto: Bool) throws {
            let pv = try rd(p, "verb")
            let star = V.string("*")
            let verbs: [V?]
            if cvSeq(pv, star) || (pv?.asArray?.contains { cvSeq($0, star) } ?? false) { verbs = shapeVerbs }
            else if let a = pv?.asArray { verbs = a.map { Optional($0) } }
            else { verbs = [pv] }
            for v in verbs where shapeIndex(v) == nil {
                add("undeclared-verb", isVeto ? "warn" : "error", .string(where_), "verb '\(JS.toString(v))' is not declared by the schema")
            }
            let declared = verbs.compactMap { shapeIndex($0) }
            if declared.isEmpty { return }
            for (wi, w) in try cvWhere(p).enumerated() {
                var ls: [V] = []
                vdLeaves(w, &ls)
                for c in ls {
                    guard isLeaf(c), let field = mem(c, "field")?.asString, IV.startsWith(field, "action.params.") else { continue }
                    let name = IV.split(field, ".")[2]
                    let at = "\(where_).where[\(wi)]"
                    let having = declared.filter { inObj(mem(shapeList[$0], "params"), name) }
                    if having.isEmpty {
                        add("undeclared-param", "error", .string(at), "parameter '\(name)' is declared by none of \(declared.map { cvJoinElem(mem(shapeList[$0], "verb")) }.joined(separator: ", "))")
                        continue
                    }
                    if having.count < declared.count {
                        add("undeclared-param", "warn", .string(at), "parameter '\(name)' is not declared by \(declared.filter { !having.contains($0) }.map { cvJoinElem(mem(shapeList[$0], "verb")) }.joined(separator: ", "))")
                    }
                    let d = mem(mem(shapeList[having[0]], "params"), name)
                    let op = mem(c, "op")
                    let value = mem(c, "value")
                    let vals: [V?] = (value?.isArray ?? false) && vdOp(op, ["in", "nin"]) ? value!.asArray!.map { Optional($0) } : [value]
                    let dtype = mem(d, "type")
                    let hasRef = mem(c, "ref") != nil
                    if !hasRef && vdOp(op, ["eq", "ne", "in", "nin", "lt", "lte", "gt", "gte"]) {
                        for x in vals where !vdTypeOk(dtype, x) {
                            add("type-mismatch", "error", .string(at), "'\(name)' is \(JS.toString(dtype)) but is compared (\(JS.toString(op))) with \(cvTypeof(x))")
                        }
                    }
                    if vdOp(op, ["lt", "lte", "gt", "gte"]), let dt = dtype, !cvSeq(dt, .string("integer")) {
                        if cvSeq(dt, .string("string")) || cvSeq(dt, .string("date")) {
                            add("ordering-on-string", "warn", .string(at), "'\(name)' is \(JS.toString(dt)): ordering follows UTF-8 byte order")
                        } else {
                            add("type-mismatch", "error", .string(at), "ordering operator \(JS.toString(op)) on \(JS.toString(dt)) parameter '\(name)'")
                        }
                    }
                    if let dv = mem(d, "values"), JS.truthy(dv), vdOp(op, ["eq", "in"]), (vals.first.flatMap { $0 })?.asString != nil {
                        var missing: [V] = []
                        for x in vals { if let s = x?.asString, !(try vdIncludes(dv, s)) { missing.append(.string(s)) } }
                        let valsJson = JS.stringify(.array(vals.map { $0 ?? .null }))
                        if missing.count == vals.count {
                            add("value-not-in-enum", "error", .string(at), "no value of \(JS.toString(op)) \(valsJson) is in the schema's set for '\(name)'")
                        } else if !missing.isEmpty {
                            add("value-not-in-enum", "warn", .string(at), "\(JS.stringify(.array(missing))) are not in the schema's set for '\(name)'")
                        }
                    }
                    if cvSeq(dtype, .string("integer")), let v = IV.num(value), !hasRef {
                        let dmin = mem(d, "min"), dmax = mem(d, "max")
                        let vv = V.double(v)
                        let dead = (vdOp(op, ["eq"]) && ((dmax != nil && JSLoose.gt(vv, dmax)) || (dmin != nil && JSLoose.lt(vv, dmin))))
                            || (vdOp(op, ["gt"]) && dmax != nil && vdGe(vv, dmax))
                            || (vdOp(op, ["gte"]) && dmax != nil && JSLoose.gt(vv, dmax))
                            || (vdOp(op, ["lt"]) && dmin != nil && vdGe(dmin, vv))
                            || (vdOp(op, ["lte"]) && dmin != nil && JSLoose.lt(vv, dmin))
                        let lo = JS.present(dmin).map { JS.toString($0) } ?? "-inf", hi = JS.present(dmax).map { JS.toString($0) } ?? "inf"
                        if dead {
                            add("out-of-range", "error", .string(at), "'\(name)' \(JS.toString(op)) \(JS.toString(value)) can never hold: the schema bounds it to [\(lo), \(hi)]")
                        } else if (vdOp(op, ["lte"]) && dmax != nil && vdGe(vv, dmax)) || (vdOp(op, ["gte"]) && dmin != nil && vdGe(dmin, vv)) {
                            add("redundant-bound", "info", .string(at), "'\(name)' \(JS.toString(op)) \(JS.toString(value)) never binds: the schema already bounds it to [\(lo), \(hi)]")
                        }
                    }
                    if let unit = mem(d, "unit"), JS.truthy(unit), let us = units, vdOp(op, ["lt", "lte", "gt", "gte", "eq"]), !isVeto {
                        let tag = try JS.present(try rd(us, field)) ?? (try rd(us, "action.params.\(name)"))
                        let sch: V? = JS.present(schemaUnits).flatMap { mem($0, JS.toString(unit)) }
                        if tag == nil {
                            add("unit-missing", "error", .string(at), "'\(name)' carries unit '\(JS.toString(unit))' but the policy has no unit tag for it (rule 20)")
                        } else if let sc = sch, JS.truthy(sc) {
                            let differs = try !cvSeq(try rd(tag, "kind"), mem(sc, "kind")) || !cvSeq(try rd(tag, "currency"), mem(sc, "currency")) || !cvSeq(try rd(tag, "exponent"), mem(sc, "exponent"))
                            if differs {
                                // a parsed object has no member order: the unit tag is written kind, currency, exponent
                                let order = ["kind", "currency", "exponent"]
                                add("unit-mismatch", "error", .string(at), "'\(name)': policy unit \(JS.stringify(tag!, order: order)) differs from the schema's \(JS.stringify(sc, order: order)) (rule 20)")
                            }
                        }
                    }
                }
            }
        }

        for (i, p) in model.predicates.enumerated() {
            guard p.isObject || p.isArray else { continue }
            try check(p, "predicates[\(i)]", false)
            let r = try alwaysDenies(obj([("predicates", .array([p]))]), nil)
            if JS.truthy(mem(r, "alwaysDenies")) && !JS.truthy(mem(r, "approximate")) { add("unreachable-predicate", "warn", .string("predicates[\(i)]"), "no action can ever match this predicate") }
        }
        for (i, v) in model.vetoes.enumerated() { try check(try rd(v, "when"), "vetoes[\(i)]", true) }

        // a money verb with no ceiling in any predicate that grants it
        for s in shapeList {
            let sverb = mem(s, "verb")
            var money: [String] = []
            for (name, d) in vdEntries(mem(s, "params")) { if try vdSemanticMoney(d) { money.append(name) } }
            if money.isEmpty { continue }
            var granting: [V] = []
            for p in model.predicates { if try vdGrants(p, sverb) { granting.append(p) } }
            if granting.isEmpty {
                if listUngranted { add("verb-not-granted", "info", sverb, "the schema declares '\(JS.toString(sverb))' but no predicate grants it") }
                continue
            }
            for name in money {
                let path = "action.params.\(name)"
                func bounded(_ p: V) throws -> Bool {
                    for w in try cvWhere(p) {
                        var src2: V? = w
                        if isGroup(w) { src2 = .object(["all_of": mem(w, "all_of") ?? .array([])]) }
                        var ls: [V] = []
                        vdLeaves(src2, &ls)
                        if ls.contains(where: { c in isLeaf(c) && (mem(c, "field")?.asString).map { IV.same($0, path) } == true && vdOp(mem(c, "op"), ["lt", "lte", "eq", "in"]) }) { return true }
                    }
                    return false
                }
                var all = true
                for p in granting { if !(try bounded(p)) { all = false; break } }
                if !all { add("unbounded-money", "warn", sverb, "'\(JS.toString(sverb))' can move '\(name)' with no per-action ceiling in at least one granting predicate") }
            }
        }
        if listUngranted {
            for s in shapeList {
                var isMoney = false
                for (_, d) in vdEntries(mem(s, "params")) { if try vdSemanticMoney(d) { isMoney = true; break } }
                if isMoney { continue }
                let sverb = mem(s, "verb")
                var granted = false
                for p in model.predicates { if try vdGrants(p, sverb) { granted = true; break } }
                if !granted { add("verb-not-granted", "info", sverb, "the schema declares '\(JS.toString(sverb))' but no predicate grants it") }
            }
        }
        return obj([("ok", .bool(!findings.contains { mem($0, "severity") == .string("error") })), ("findings", .array(findings))])
    }
}
