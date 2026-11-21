import Foundation

/// Question cards (a deterministic, structured form of a cell question: the sentence, one fact line per dimension, the verb's
/// reversibility, the three answers and the typed "partly" slots) and the parser that turns card input into the learner's answer.
/// Cards and inputs are JSON trees.
public enum PCAIntentUx {
    private static func n(_ d: Double) -> String { return PCAIntentRender.jsNum(d) }
    private static func num(_ d: Double) -> JSONValue { return WJ.plain(.double(d)) }
    private static func fail(_ what: String) -> JSError { return JSError("pca-intent: \(what)") }

    private static func fact(_ d: WalletDim, _ i: Int) throws -> JSONValue {
        var m: JObject = ["path": .string(d.path), "label": .string(PCAIntentRender.labelOf(d.path))]
        if d.isNum {
            let cells = WalletOmegaMath.numCells(d)
            if i < 0 || i >= cells.count { throw fail("cell index out of range") }
            let c = cells[i]
            let eg: Int = WalletOmegaMath.numRep(d, i)
            let text: String
            if c.lo == c.hi { text = "exactly \(c.lo)" } else { text = "any value from \(c.lo) to \(c.hi) (for example \(eg))" }
            m["text"] = .string(text)
        } else {
            if i < 0 || i >= d.values.count { throw fail("cell index out of range") }
            let v = d.values[i]
            let text: String
            if v.kind == "exact" { text = "\"\(v.value)\"" }
            else if v.kind == "prefix" { text = "anything under \"\(v.value)\" not named elsewhere" }
            else { text = "any value not named anywhere in the grant or your request" }
            m["text"] = .string(text)
        }
        return .object(m)
    }

    public static func questionCard(_ omega: WalletOmega, _ verb: String, _ cell: [Int], _ catalog: PCACatalog = PCAIntentRender.defaultCatalog) throws -> JSONValue {
        guard let vs = omega.verb(verb) else { throw JSError("questionCard: no verb \(verb)") }
        var facts: [JSONValue] = []
        var partial: [JSONValue] = []
        for k in 0..<vs.dims.count {
            let d = vs.dims[k]
            if k >= cell.count { throw fail("cell index out of range") }
            facts.append(try fact(d, cell[k]))
            var slot: JObject = ["path": .string(d.path)]
            if d.isNum {
                let cells = WalletOmegaMath.numCells(d)
                let c = cells[cell[k]]
                slot["kind"] = .string("num")
                slot["lo"] = .int(Int64(c.lo))
                slot["hi"] = .int(Int64(c.hi))
            } else {
                slot["kind"] = .string("cat")
                slot["options"] = .array(d.values.filter { $0.kind == "exact" }.map { JSONValue.string($0.value) })
            }
            partial.append(.object(slot))
        }
        let body: JObject = [
            "v": .int(1), "verb": .string(verb), "cell": .array(cell.map { JSONValue.int(Int64($0)) }),
            "sentence": .string(try PCAIntentRender.renderQuestion(vs, cell, catalog)),
            "facts": .array(facts), "reversibility": .string(vs.reversibility),
            "answers": .array([.string("yes"), .string("no"), .string("partly")]), "partial": .array(partial),
        ]
        var card = body
        card["digest"] = .string(try WJ.hash(.object(["d": .string("atlas-pca/intent-card/v1"), "c": .object(body)])))
        return .object(card)
    }

    private static func res(_ answer: JSONValue) -> JSONValue { return .object(["ok": .bool(true), "answer": answer]) }
    private static func err(_ e: String) -> JSONValue { return .object(["ok": .bool(false), "error": .string(e)]) }

    /// The distinct non-empty strings of the list in first-seen order; throws when it is not an array (the reference calls .filter).
    private static func namedValues(_ list: JSONValue?) throws -> [JSONValue] {
        guard let a = list?.asArray else { throw fail("filter is not a function") }
        var out: [JSONValue] = []
        var seen = Set<JKey>()
        for x in a {
            if let s = x.asString, !s.isEmpty, !seen.contains(JKey(s)) {
                seen.insert(JKey(s))
                out.append(x)
            }
        }
        return out
    }

    private static func has(_ o: JSONValue?, _ k: String) -> Bool { return o?.asObject?[JKey(k)] != nil }
    private static func get(_ o: JSONValue?, _ k: String) -> JSONValue? { return o?.asObject?[JKey(k)] }

    /// `^(?:action\.params\.[a-z_][a-z0-9_]*|action\.resource)$`
    private static func isFieldPath(_ s: String) -> Bool {
        if IV.same(s, "action.resource") { return true }
        guard IV.startsWith(s, "action.params.") else { return false }
        let rest = Array(IV.dropPrefix(s, 14).unicodeScalars)
        guard let f = rest.first else { return false }
        func lower(_ c: Unicode.Scalar) -> Bool { return c.value >= 0x61 && c.value <= 0x7A }
        func digit(_ c: Unicode.Scalar) -> Bool { return c.value >= 0x30 && c.value <= 0x39 }
        guard lower(f) || f == "_" else { return false }
        return rest.dropFirst().allSatisfy { lower($0) || digit($0) || $0 == "_" }
    }

    private static func inRange(_ x: JSONValue?, _ lo: Double, _ hi: Double) -> Bool {
        guard let v = IV.num(x), v.isFinite, v == v.rounded(.towardZero), !IV.isNegZero(v) else { return false }
        return v >= lo && v <= hi
    }

    private static func part(_ kv: [(String, JSONValue)]) -> JSONValue {
        var m: JObject = [:]
        for (k, v) in kv { m[JKey(k)] = v }
        return .object(m)
    }

    private static func partsNamed(_ vals: [JSONValue]) -> JSONValue {
        return .array([part([("values", .array(vals)), ("y", .int(0))]), part([("other", .bool(true)), ("y", .int(1))])])
    }

    /// Turn the UI input into the learner's answer: {ok: true, answer} or {ok: false, error}.
    public static func parseCardAnswer(_ card: JSONValue?, _ input: JSONValue?) throws -> JSONValue {
        if !IV.same(get(input, "answer")?.asString, "partly") {
            return res(.int(IV.same(get(input, "answer")?.asString, "yes") ? 1 : 0))
        }
        guard let slots = get(card, "partial")?.asArray else { throw fail("not an array") }
        if has(input, "newField") {
            let nf = PCAIntentRender.str(get(input, "newField"))
            if !isFieldPath(nf) { return err("unknown field \(nf)") }
            for s in slots where IV.same(get(s, "path")?.asString, nf) { return err("\(nf) is already on the card; answer partly for it directly") }
            let vals = try namedValues(get(input, "notFor"))
            if vals.isEmpty { return err("name at least one value") }
            var dvals: [JSONValue] = vals.map { part([("kind", .string("exact")), ("value", $0)]) }
            dvals.append(part([("kind", .string("other")), ("value", .string(WalletOmegaMath.OTHER))]))
            let newDim = part([("kind", .string("cat")), ("path", .string(nf)), ("values", .array(dvals))])
            return res(part([("kind", .string("partial")), ("path", .string(nf)), ("newDim", newDim), ("parts", partsNamed(vals))]))
        }
        return try parseSlot(slots, input)
    }

    private static func parseSlot(_ slots: [JSONValue], _ input: JSONValue?) throws -> JSONValue {
        let path = get(input, "path")
        var slot: JSONValue? = nil
        if let p = path?.asString { slot = slots.first { IV.same(get($0, "path")?.asString, p) } }
        guard let sl = slot else { return err("the card has no field " + PCAIntentRender.str(has(input, "path") ? path : nil)) }
        guard let sp = get(sl, "path")?.asString else { throw fail("slot path") }
        if IV.same(get(sl, "kind")?.asString, "num") {
            guard let lo = IV.num(get(sl, "lo")), let hi = IV.num(get(sl, "hi")) else { throw fail("slot range") }
            if has(input, "upTo") {
                let x = get(input, "upTo")
                guard inRange(x, lo, hi), let u = IV.num(x), u != hi else { return err("upTo must be an integer in [" + n(lo) + ", " + n(hi - 1) + "]") }
                let p1: JSONValue = part([("lo", num(lo)), ("hi", num(u)), ("y", .int(1))])
                let p2: JSONValue = part([("lo", num(u + 1)), ("hi", num(hi)), ("y", .int(0))])
                return res(part([("kind", .string("partial")), ("path", .string(sp)), ("cuts", .array([num(u)])), ("parts", .array([p1, p2]))]))
            }
            if has(input, "from") {
                let x = get(input, "from")
                guard inRange(x, lo, hi), let f = IV.num(x), f != lo else { return err("from must be an integer in [" + n(lo + 1) + ", " + n(hi) + "]") }
                let p1: JSONValue = part([("lo", num(lo)), ("hi", num(f - 1)), ("y", .int(0))])
                let p2: JSONValue = part([("lo", num(f)), ("hi", num(hi)), ("y", .int(1))])
                return res(part([("kind", .string("partial")), ("path", .string(sp)), ("cuts", .array([num(f)])), ("parts", .array([p1, p2]))]))
            }
            if has(input, "except") {
                let ex0 = get(input, "except")
                if let e = ex0, !e.isNull, e.asArray == nil, e.asString == nil { throw fail("not iterable") }
                var ex: [Double] = []
                var allIn = true
                if let list = ex0?.asArray {
                    var seen = Set<Double>()
                    for x in list {
                        if !inRange(x, lo, hi) { allIn = false } else if let d = IV.num(x) {
                            let v = d + 0.0
                            if !seen.contains(v) { seen.insert(v); ex.append(v) }
                        }
                    }
                    ex.sort()
                } else { allIn = false }
                if ex0?.asArray?.isEmpty == true || ex0 == nil || ex0?.isNull == true || !allIn {
                    return err("except values must be integers in [" + n(lo) + ", " + n(hi) + "]")
                }
                var parts: [JSONValue] = ex.map { part([("lo", num($0)), ("hi", num($0)), ("y", .int(0))]) }
                parts.append(part([("lo", num(lo)), ("hi", num(hi)), ("y", .int(1))]))
                return res(part([("kind", .string("partial")), ("path", .string(sp)), ("cuts", .array(ex.map { num($0) })), ("parts", .array(parts))]))
            }
            return err("a numeric partly answer needs upTo, from or except")
        }
        if !has(input, "notFor") { return err("a categorical partly answer needs notFor") }
        let vals = try namedValues(get(input, "notFor"))
        if vals.isEmpty { return err("name at least one value") }
        return res(part([("kind", .string("partial")), ("path", .string(sp)), ("values", .array(vals)), ("parts", partsNamed(vals))]))
    }
}
