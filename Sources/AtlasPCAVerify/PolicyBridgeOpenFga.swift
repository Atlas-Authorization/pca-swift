import Foundation

/// OpenFGA / Zanzibar ReBAC model plus tuples to PCA predicates. The model is resolved against the supplied tuples at translation time
/// (direct, computed userset, union, intersection, difference, tuple-to-userset, all bounded and cycle-guarded), and one permit
/// `{verb: relation, resource: object, where: [subject.id == user]}` is emitted per (user, object, relation) that holds; a public
/// `type:*` tuple becomes a `like` permit minus the named users it excludes. Userset-valued tuples are reported, not expanded.
extension PCAPolicyBridge {
    /// `order`: the member order of the model's `relations` objects (a parsed object has none); it fixes the order of the report lines.
    public static func openfgaToPca(_ model: JSONValue?, _ tuples: JSONValue?, order: KeyOrder? = nil) -> JSONValue {
        PBOpenFga.run(model, tuples, order)
    }
}

enum PBOpenFga {
    static let MAX_DEPTH = 32

    indirect enum Plan {
        case direct
        case computed(String)
        case union([Plan])
        case intersection([Plan])
        case difference(Plan, Plan)
        case ttu(tupleset: String, computed: String)
    }

    struct Build {
        var ok: Bool
        var plan: Plan?
        var partial: Bool
        var reason: String?
    }

    struct Tuple { let user: String; let relation: String; let object: String }

    /// type -> (relation, rewrite node) in the model's order; a repeated type keeps its first position and takes the last definition.
    struct Model {
        var order: [String] = []
        var rels: [JKey: [(name: String, node: JSONValue)]] = [:]
    }

    // ---- JSON reads ------------------------------------------------------------------------------------------------------------

    /// `v.k` of an object (an array or a primitive has no such member).
    static func prop(_ v: JSONValue?, _ k: String) -> JSONValue? {
        if case let .object(o)? = v { return o[JKey(k)] }
        return nil
    }
    /// `typeof v === 'object' && v !== null`.
    static func isObj(_ v: JSONValue?) -> Bool {
        switch v {
        case .object?, .array?: return true
        default: return false
        }
    }
    static func hasOwn(_ v: JSONValue, _ k: String) -> Bool { prop(v, k) != nil }

    static func nonEmptyString(_ v: JSONValue?) -> String? {
        if case let .string(s)? = v, !s.isEmpty { return s }
        return nil
    }

    // ---- resolution plan -------------------------------------------------------------------------------------------------------

    static func describe(_ p: Plan) -> String {
        switch p {
        case .direct: return "direct"
        case let .computed(r): return "computed \(r)"
        case let .union(cs): return "union[\(cs.map(describe).joined(separator: ", "))]"
        case let .intersection(cs): return "intersection[\(cs.map(describe).joined(separator: ", "))]"
        case let .difference(b, s): return "difference(\(describe(b)) - \(describe(s)))"
        case let .ttu(t, c): return "\(c) from \(t)"
        }
    }

    static func childNodes(_ container: JSONValue?) -> [JSONValue]? {
        guard isObj(container) else { return nil }
        return prop(container, "child")?.asArray
    }

    static func relationOf(_ v: JSONValue?) -> String? {
        guard isObj(v) else { return nil }
        return nonEmptyString(prop(v, "relation"))
    }

    static func fail(_ reason: String, partial: Bool = false) -> Build { Build(ok: false, plan: nil, partial: partial, reason: reason) }

    static func buildPlan(_ node: JSONValue) -> Build {
        if hasOwn(node, "this") { return Build(ok: true, plan: .direct, partial: false, reason: nil) }

        if hasOwn(node, "computedUserset") {
            let cu = prop(node, "computedUserset")
            let rel: JSONValue? = (cu.map { isObj($0) } ?? false) ? prop(cu, "relation") : nil
            guard let r = nonEmptyString(rel) else { return fail("computedUserset without a relation") }
            return Build(ok: true, plan: .computed(r), partial: false, reason: nil)
        }

        if hasOwn(node, "union") {
            guard let children = childNodes(prop(node, "union")) else { return fail("union without children") }
            var subs: [Plan] = []
            var partial = false
            for child in children {
                if !isObj(child) { partial = true; continue }
                let sub = buildPlan(child)
                guard sub.ok, let p = sub.plan else { partial = true; continue } // OR under-approximates safely: drop the unmodeled child
                if sub.partial { partial = true }
                subs.append(p)
            }
            if subs.isEmpty { return fail("union with no modeled children", partial: partial) }
            return Build(ok: true, plan: .union(subs), partial: partial, reason: nil)
        }

        if hasOwn(node, "intersection") {
            guard let children = childNodes(prop(node, "intersection")) else { return fail("intersection without children") }
            var subs: [Plan] = []
            for child in children {
                // an AND cannot drop a child without OVER-granting: every conjunct must be modeled
                if !isObj(child) { return fail("intersection child is not a rewrite") }
                let sub = buildPlan(child)
                guard sub.ok, let p = sub.plan else { return fail("intersection child unmodeled (\(sub.reason ?? "unsupported"))") }
                subs.append(p)
            }
            if subs.isEmpty { return fail("intersection with no children") }
            return Build(ok: true, plan: .intersection(subs), partial: false, reason: nil)
        }

        if hasOwn(node, "difference") {
            let diff = prop(node, "difference")
            guard isObj(diff) else { return fail("malformed difference") }
            guard let baseNode = prop(diff, "base"), isObj(baseNode), let subNode = prop(diff, "subtract"), isObj(subNode) else {
                return fail("difference needs both base and subtract")
            }
            let base = buildPlan(baseNode)
            let subtract = buildPlan(subNode)
            guard base.ok, let bp = base.plan else { return fail("difference base unmodeled (\(base.reason ?? "?"))") }
            guard subtract.ok, let sp = subtract.plan else { return fail("difference subtract unmodeled (\(subtract.reason ?? "?"))") }
            return Build(ok: true, plan: .difference(bp, sp), partial: base.partial || subtract.partial, reason: nil)
        }

        if hasOwn(node, "tupleToUserset") {
            let ttu = prop(node, "tupleToUserset")
            guard isObj(ttu) else { return fail("malformed tupleToUserset") }
            guard let tupleset = relationOf(prop(ttu, "tupleset")) else { return fail("tupleToUserset without a tupleset relation") }
            guard let computed = relationOf(prop(ttu, "computedUserset")) else { return fail("tupleToUserset without a computedUserset relation") }
            return Build(ok: true, plan: .ttu(tupleset: tupleset, computed: computed), partial: false, reason: nil)
        }

        return fail("unknown rewrite node")
    }

    // ---- model / tuples --------------------------------------------------------------------------------------------------------

    static func parseModel(_ model: JSONValue?, _ report: PCAPolicyBridge.Report, _ order: PCAPolicyBridge.KeyOrder?) -> Model? {
        guard isObj(model) else {
            report.errors.append("model is not an object")
            return nil
        }
        guard case let .array(defs)? = prop(model, "type_definitions") else {
            report.errors.append("model.type_definitions is missing or not an array")
            return nil
        }
        var out = Model()
        for def in defs {
            guard isObj(def), let type = nonEmptyString(prop(def, "type")) else { continue }
            var relMap: [(name: String, node: JSONValue)] = []
            switch prop(def, "relations") {
            case let .object(o)?:
                for name in PCAPolicyBridge.orderedKeys(o, order) {
                    if let node = o[JKey(name)], isObj(node) { relMap.append((name, node)) }
                }
            case let .array(a)?:
                for (i, node) in a.enumerated() where isObj(node) { relMap.append((String(i), node)) }
            default: break
            }
            if out.rels[JKey(type)] == nil { out.order.append(type) }
            out.rels[JKey(type)] = relMap
        }
        return out
    }

    static func parseTuples(_ tuples: JSONValue?, _ report: PCAPolicyBridge.Report) -> [Tuple] {
        guard case let .array(list)? = tuples else {
            if tuples != nil { report.errors.append("tuples is not an array") }
            return []
        }
        var out: [Tuple] = []
        for t in list {
            guard isObj(t), case let .string(user)? = prop(t, "user"), case let .string(relation)? = prop(t, "relation"),
                  case let .string(object)? = prop(t, "object") else { continue }
            out.append(Tuple(user: user, relation: relation, object: object))
        }
        return out
    }

    // ---- translation -----------------------------------------------------------------------------------------------------------

    static func key(_ a: String, _ b: String) -> JKey { JKey(a + "\u{0}" + b) }
    static func utf16Sorted(_ xs: [String]) -> [String] { xs.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) } }

    /// `object.slice(0, object.indexOf(':'))`, the whole text when it has no colon.
    static func typeOf(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for c in s.unicodeScalars { if c == ":" { return String(out) }; out.append(c) }
        return s
    }
    static func objectOfUserset(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for c in s.unicodeScalars { if c == "#" { return String(out) }; out.append(c) }
        return s
    }
    static func escapeGlob(_ t: String) -> String {
        var out = String.UnicodeScalarView()
        for c in t.unicodeScalars {
            if c == "*" || c == "?" || c == "\\" { out.append("\\") }
            out.append(c)
        }
        return String(out)
    }

    static func run(_ modelArg: JSONValue?, _ tuplesArg: JSONValue?, _ order: PCAPolicyBridge.KeyOrder?) -> JSONValue {
        let report = PCAPolicyBridge.Report("openfga")
        var predicates: [JSONValue] = []

        let typeRelations = parseModel(modelArg, report, order)
        let tupleList = parseTuples(tuplesArg, report)
        guard let model = typeRelations else { return PCAPolicyBridge.bridgeResult(predicates, [], report) }

        // direct tuples: (object, relation) -> users; userset-valued users are noted
        var direct: [JKey: Set<JKey>] = [:]
        var usersSeen = Set<JKey>()
        var wildcardTypes = Set<JKey>()
        var objectsSeen = Set<JKey>()
        var usersetTuples = 0
        for t in tupleList {
            objectsSeen.insert(JKey(t.object))
            direct[key(t.object, t.relation), default: []].insert(JKey(t.user))
            let hasHash = t.user.unicodeScalars.contains("#")
            if hasHash {
                usersetTuples += 1
            } else if IV.endsWith(t.user, ":*") && t.user.utf16.count > 2 {
                wildcardTypes.insert(JKey(IV.text(t.user.unicodeScalars.dropLast(2))))
            } else {
                usersSeen.insert(JKey(t.user))
            }
        }
        if usersetTuples > 0 {
            report.skipped.append("\(usersetTuples) userset-valued tuple(s) (user contains '#') not expanded to concrete users")
        }

        // a resolution plan per (type, relation)
        var plans: [JKey: Plan] = [:]
        for type in model.order {
            for (relation, node) in model.rels[JKey(type)] ?? [] {
                let built = buildPlan(node)
                guard built.ok, let plan = built.plan else {
                    report.skipped.append("relation \(type)#\(relation): \(built.reason ?? "unsupported rewrite") — skipped")
                    continue
                }
                if built.partial {
                    report.skipped.append("relation \(type)#\(relation): some union children unsupported and dropped (under-approximated)")
                }
                plans[key(type, relation)] = plan
                report.translated.append("relation \(type)#\(relation) (\(describe(plan)))")
            }
        }

        func holdsRel(_ user: String, _ object: String, _ relation: String, _ depth: Int, _ visited: Set<JKey>) -> Bool {
            let k = key(object, relation)
            if depth > MAX_DEPTH || visited.contains(k) { return false }
            guard let plan = plans[key(typeOf(object), relation)] else { return false }
            var next = visited
            next.insert(k)
            return evalPlan(user, object, relation, plan, depth, next)
        }

        func evalPlan(_ user: String, _ object: String, _ relation: String, _ plan: Plan, _ depth: Int, _ visited: Set<JKey>) -> Bool {
            switch plan {
            case .direct:
                guard let set = direct[key(object, relation)] else { return false }
                return set.contains(JKey(user)) || set.contains(JKey(typeOf(user) + ":*"))
            case let .computed(r):
                return holdsRel(user, object, r, depth + 1, visited)
            case let .union(cs):
                return cs.contains { evalPlan(user, object, relation, $0, depth, visited) }
            case let .intersection(cs):
                return cs.allSatisfy { evalPlan(user, object, relation, $0, depth, visited) }
            case let .difference(base, subtract):
                return evalPlan(user, object, relation, base, depth, visited) && !evalPlan(user, object, relation, subtract, depth, visited)
            case let .ttu(tupleset, computed):
                guard let related = direct[key(object, tupleset)] else { return false }
                for p in related where holdsRel(user, objectOfUserset(p.s), computed, depth + 1, visited) { return true }
                return false
            }
        }

        // every (user, object, relation-defined-on-that-object's-type) triple that holds
        let sortedUsers = utf16Sorted(usersSeen.map { $0.s })
        let sortedObjects = utf16Sorted(objectsSeen.map { $0.s })
        let sortedWildcards = utf16Sorted(wildcardTypes.map { $0.s })
        for object in sortedObjects {
            let type = typeOf(object)
            guard let relations = model.rels[JKey(type)] else {
                report.skipped.append("object \(object): type \"\(type)\" not defined in model — ignored")
                continue
            }
            for relation in utf16Sorted(relations.map { $0.name }) {
                if plans[key(type, relation)] == nil { continue } // unsupported relation
                for user in sortedUsers where holdsRel(user, object, relation, 0, []) {
                    predicates.append(.object(["verb": .string(relation), "resource": .string(object),
                                               "where": .array([PCAPolicyBridge.leaf("subject.id", "eq", value: .string(user))])]))
                }
                // a public tuple (`type:*`) grants every subject of that type, named or not; the named ones were decided above (a
                // difference or an intersection may exclude them), so they are excluded here
                for wtype in sortedWildcards {
                    if !holdsRel(wtype + ":\u{0}anyone", object, relation, 0, []) { continue }
                    let named = sortedUsers.filter { IV.same(typeOf($0), wtype) }
                    var w: [JSONValue] = [PCAPolicyBridge.leaf("subject.id", "like", value: .string(escapeGlob(wtype) + ":*"))]
                    if !named.isEmpty {
                        w.append(PCAPolicyBridge.not(PCAPolicyBridge.leaf("subject.id", "in", value: .array(named.map { .string($0) }))))
                    }
                    predicates.append(.object(["verb": .string(relation), "resource": .string(object), "where": .array(w)]))
                }
            }
        }
        return PCAPolicyBridge.bridgeResult(predicates, [], report)
    }
}
