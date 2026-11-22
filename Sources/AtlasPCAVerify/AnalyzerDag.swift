import Foundation

/// What a committed workflow (a DAG of steps, edges and a budget) can EVER do, decided statically from its body: the most steps one
/// run executes, the dependency depth and width, the number of maximal paths (capped), the cost per cap, the steps no run can reach,
/// the sinks with their data lineage and whether any label protects them, ordering-only steps and pipelinable edges. Deterministic
/// and total; a body that is not a DAG is refused (a thrown `JSError`).
extension PCAAnalyzer {
    fileprivate static let dgPathCap = 1_000_000.0

    /// A step id: ids are strings (anything else cannot name a step here, which is stricter than the reference).
    fileprivate static func dgId(_ s: V?) throws -> String {
        guard let id = try rd(s, "id")?.asString else { throw fail("step id is not a string") }
        return id
    }

    /// `x.length > 0` (a read of `length` on null / undefined is a TypeError).
    fileprivate static func dgLenPositive(_ v: V?) throws -> Bool { (IV.num(try rd(v, "length")) ?? 0) > 0 }

    /// A string step reference (an edge end, a dependency).
    fileprivate static func dgRef(_ v: V?) throws -> String {
        guard let s = v?.asString else { throw fail("step reference is not a string") }
        return s
    }

    static func dagExposure(_ b: V?) throws -> V {
        guard case let .array(steps)? = try rd(b, "steps") else { throw fail("b.steps.map is not a function") }
        var byId: [JKey: Int] = [:]
        var ids: [String] = []
        for (i, s) in steps.enumerated() {
            let id = try dgId(s)
            ids.append(id)
            byId[JKey(id)] = i
        }
        if byId.count != steps.count { throw fail("dagExposure: duplicate step id") }
        func deps(_ i: Int) throws -> [String] {
            guard case let .array(d)? = try rd(steps[i], "deps") else { throw fail("s.deps is not iterable") }
            return try d.map { try dgRef($0) }
        }
        var level: [JKey: Int] = [:], anc: [JKey: Set<JKey>] = [:], visiting = Set<JKey>()
        func visit(_ id: String) throws {
            let k = JKey(id)
            if level[k] != nil { return }
            if visiting.contains(k) { throw fail("dagExposure: cycle") }
            visiting.insert(k)
            guard let idx = byId[k] else { throw fail("dagExposure: unknown step \(id)") }
            var a = Set<JKey>()
            var l = 0
            for d in try deps(idx) {
                try visit(d)
                a.insert(JKey(d))
                a.formUnion(anc[JKey(d)] ?? [])
                l = Swift.max(l, (level[JKey(d)] ?? 0) + 1)
            }
            visiting.remove(k)
            anc[k] = a
            level[k] = l
        }
        for id in ids { try visit(id) }
        let depth = (level.values.max() ?? 0) + 1
        var widths: [Int: Int] = [:]
        for l in level.values { widths[l, default: 0] += 1 }
        let levelWidth = widths.values.max().map { Double($0) } ?? -Double.infinity

        // maximal paths: the number of paths from a source to each step, summed over leaves
        var children: [JKey: [JKey]] = [:]
        for id in ids { children[JKey(id)] = [] }
        for (i, id) in ids.enumerated() { for d in try deps(i) { children[JKey(d), default: []].append(JKey(id)) } }
        var memo: [JKey: Double] = [:]
        var capped = false
        func toLeaves(_ k: JKey) -> Double {
            if let m = memo[k] { return m }
            let kids = children[k] ?? []
            var n = kids.isEmpty ? 1.0 : 0.0
            for c in kids { n += toLeaves(c) }
            if n > dgPathCap { n = dgPathCap; capped = true }
            memo[k] = n
            return n
        }
        var paths = 0.0
        for (i, id) in ids.enumerated() { if try deps(i).isEmpty { paths = Swift.min(dgPathCap, paths + toLeaves(JKey(id))) } }

        let budget = try rd(b, "budget")
        // Object.entries of anything but an object is refused here (stricter than the reference, which reads a string or array's indexes)
        guard case let .object(caps)? = try rd(budget, "caps") else { throw fail("Object.entries requires an object") }
        var cost: JObject = [:]
        for (name, cap) in caps {
            var total = 0.0
            for s in steps {
                guard let c = JS.present(mem(try rd(s, "cost"), name.s)) else { continue }
                guard let d = IV.num(c) else { throw fail("step cost is not a number") }
                total += d
            }
            cost[name] = .object(["cap": cap, "total": num(total), "maxSpend": num(exDgMin(JS.toNumber(cap), total))])
        }
        var never: [V] = []
        for (i, s) in steps.enumerated() {
            var over = false
            if case let .object(sc)? = try rd(s, "cost") {
                for (n, c) in sc where JSLoose.gt(c, JS.present(caps[n]) ?? .int(0)) { over = true }
            }
            if over { never.append(.object(["step": .string(ids[i]), "reason": .string("cost_over_cap")])) }
            else if JSLoose.gt(.int(Int64((anc[JKey(ids[i])] ?? []).count + 1)), mem(budget, "max_steps")) {
                never.append(.object(["step": .string(ids[i]), "reason": .string("needs_more_steps_than_budget")]))
            }
        }

        // data lineage: a step's outputs reach `t` along edges (transitively through steps that consume them)
        guard case let .array(edges)? = try rd(b, "edges") else { throw fail("b.edges is not iterable") }
        var feeds: [JKey: Set<JKey>] = [:]
        for id in ids { feeds[JKey(id)] = [] }
        var edgeTo: [String] = []
        for e in edges {
            let to = try dgRef(try rd(try rd(e, "to"), "step"))
            let from = try dgRef(try rd(try rd(e, "from"), "step"))
            guard feeds[JKey(to)] != nil else { throw fail("Cannot read properties of undefined (reading 'add')") }
            feeds[JKey(to)]!.insert(JKey(from))
            edgeTo.append(to)
        }
        func lineage(_ id: JKey, _ seen: inout Set<JKey>) throws {
            guard let f = feeds[id] else { throw fail("feeds.get(id) is not iterable") }
            for x in f where !seen.contains(x) {
                seen.insert(x)
                try lineage(x, &seen)
            }
        }
        var sinks: [V] = [], unprotected: [V] = []
        for (i, s) in steps.enumerated() {
            let sk = mem(s, "sink")
            if sk == .null { continue }
            var seen = Set<JKey>()
            try lineage(JKey(ids[i]), &seen)
            let lin = seen.map { $0.s }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            var prot = try dgLenPositive(rd(s, "deny_labels")) || dgLenPositive(rd(s, "escalate_labels"))
            if !prot {
                for (j, e) in edges.enumerated() where IV.same(edgeTo[j], ids[i]) { if try dgLenPositive(try rd(e, "deny_labels")) { prot = true; break } }
            }
            sinks.append(obj([("step", .string(ids[i])), ("sink", sk), ("lineage", strs(lin)), ("protected", .bool(prot))]))
            if !prot && !lin.isEmpty { unprotected.append(.string(ids[i])) }
        }
        var orderingOnly: [V] = []
        for (i, id) in ids.enumerated() { if try !deps(i).isEmpty && !edgeTo.contains(where: { IV.same($0, id) }) { orderingOnly.append(.string(id)) } }
        var pipelinable: [V] = []
        for (i, e) in edges.enumerated() where mem(e, "promise") != .null { pipelinable.append(.int(Int64(i))) }
        return obj([
            ("steps", .int(Int64(steps.count))), ("maxSteps", num(exDgMin(Double(steps.count), JS.toNumber(mem(budget, "max_steps"))))),
            ("depth", .int(Int64(depth))), ("levelWidth", num(levelWidth)), ("paths", num(paths)), ("pathsCapped", .bool(capped)),
            ("cost", .object(cost)), ("neverRunnable", .array(never)), ("sinks", .array(sinks)), ("unprotectedSinks", .array(unprotected)),
            ("orderingOnly", .array(orderingOnly)), ("pipelinable", .array(pipelinable)),
        ])
    }

    private static func exDgMin(_ a: Double, _ b: Double) -> Double { (a.isNaN || b.isNaN) ? .nan : Swift.min(a, b) }
}
