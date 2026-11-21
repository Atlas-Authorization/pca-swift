import Foundation

/// Round-trip checks. (a) The card's lossless token tape decodes back to the goal. (b) An explainer sees only the compiled card
/// lines and a comparator judges the explanation against the principal's text: a detector, tighten-only (it can only escalate),
/// measured by semantic mutations that WIDEN the policy.
public enum PCAGoalRoundTrip {
    public static let MUTATION_KINDS: [String] = ["widen_cap", "widen_where", "drop_prohibit", "drop_bound", "swap_resource", "add_grant"]

    private static func nv(_ v: JSONValue?) -> JSONValue { v ?? .null }

    private static func obj(_ v: JSONValue?, _ what: String) throws -> JObject {
        guard let o = v?.asObject else { throw IrError("\(what) expected an object") }
        return o
    }

    private static func isObj(_ v: JSONValue?) -> Bool { v?.isObject ?? false }

    /// decode(encode(goal)) equals the goal: nothing the goal says is lost on the card tape.
    public static func cardRoundTrips(_ g: JSONValue) throws -> Bool {
        let back = try PCAGoalCodec.decodeGoal(try PCAGoalCodec.encodeGoal(g))
        return IV.same(GV.stable(back), GV.stable(g))
    }

    private static func numOut(_ d: Double) throws -> JSONValue {
        if d == d.rounded(.toNearestOrEven) && abs(d) <= Double(GV.MAX_SAFE) { return .int(Int64(d)) }
        throw IrError("non-integer result")
    }

    private static func scale(_ x: JSONValue, _ f: Double) throws -> JSONValue {
        var r = try obj(x, "quantity")
        let uk = GV.kind(r[JKey("u")])
        if uk != "money" && uk != "count" { return x }
        r[JKey("n")] = try numOut(JS.toNumber(nv(r[JKey("n")])) * f)
        return .object(r)
    }

    private static func mapLitsInCond(_ c: JSONValue) throws -> JSONValue {
        let k = GV.kind(c)
        var out = try obj(c, "condition")
        if k == "cmp" {
            let r = out[JKey("r")]
            let op = nv(out[JKey("op")])
            let lit = GV.kind(r) == "lit" && GV.kind(GV.get(r, "v")) == "q" && (op == .string("lte") || op == .string("lt"))
            if lit {
                let qv = try obj(GV.get(r, "v"), "v")
                let sc = try scale(try req(qv[JKey("q")], "q"), 10.0)
                out[JKey("r")] = GV.obj([("k", .string("lit")), ("v", GV.obj([("k", .string("q")), ("q", sc)]))])
            }
            return .object(out)
        }
        if k == "and" || k == "or" {
            out[JKey("a")] = try mapLitsInCond(try req(out[JKey("a")], "a"))
            out[JKey("b")] = try mapLitsInCond(try req(out[JKey("b")], "b"))
            return .object(out)
        }
        return c
    }

    private static func req(_ v: JSONValue?, _ what: String) throws -> JSONValue {
        guard let v = v, v.isObject else { throw IrError("\(what) expected an object") }
        return v
    }

    /// A semantic mutation that WIDENS the policy (or leaves it equal); nil when the goal has nothing to mutate.
    public static func mutateGoal(_ g: JSONValue, _ kind: String, _ ontology: JSONValue?) throws -> JSONValue? {
        var x = try obj(g, "goal")
        switch kind {
        case "widen_cap":
            var bounds = try GV.arr(x[JKey("bounds")], "bounds")
            if bounds.isEmpty { return nil }
            var b0 = try obj(bounds[0], "bound")
            b0[JKey("cap")] = try scale(try req(b0[JKey("cap")], "cap"), 10.0)
            bounds[0] = .object(b0)
            x[JKey("bounds")] = .array(bounds)
            return .object(x)
        case "widen_where":
            var grants = try GV.arr(x[JKey("grants")], "grants")
            for i in grants.indices {
                var y = try obj(grants[i], "grant")
                let mapped = try mapLitsInCond(try req(y[JKey("cond")], "cond"))
                if GV.stringify(mapped) != GV.stringify(y[JKey("cond")]) {
                    y[JKey("cond")] = mapped
                    grants[i] = .object(y)
                    x[JKey("grants")] = .array(grants)
                    return .object(x)
                }
            }
            return nil
        case "drop_prohibit":
            var ps = try GV.arr(x[JKey("prohibits")], "prohibits")
            if ps.isEmpty { return nil }
            ps.removeLast()
            x[JKey("prohibits")] = .array(ps)
            return .object(x)
        case "drop_bound":
            var bs = try GV.arr(x[JKey("bounds")], "bounds")
            if bs.isEmpty { return nil }
            bs.removeLast()
            x[JKey("bounds")] = .array(bs)
            return .object(x)
        case "swap_resource":
            var grants = try GV.arr(x[JKey("grants")], "grants")
            for i in grants.indices {
                var y = try obj(grants[i], "grant")
                if GV.kind(y[JKey("res")]) == "exact" {
                    let id = GV.jsStr(GV.get(y[JKey("res")], "id"))
                    y[JKey("res")] = GV.obj([("k", .string("exact")), ("id", .string(id + "9"))])
                    grants[i] = .object(y)
                    x[JKey("grants")] = .array(grants)
                    return .object(x)
                }
            }
            return nil
        case "add_grant":
            var grants = try GV.arr(x[JKey("grants")], "grants")
            var have: [JSONValue] = []
            for y in grants { have.append(nv(GV.get(y, "verb"))) }
            var chosen: JObject? = nil
            for yo in try GV.arr(GV.get(ontology, "verbs"), "verbs") {
                let y = try obj(yo, "verb")
                if nv(y[JKey("effect")]) == .string("read") || have.contains(nv(y[JKey("id")])) { continue }
                var prohibited = false
                for p in try GV.arr(x[JKey("prohibits")], "prohibits") {
                    if GV.kind(GV.get(p, "target")) == "verb" {
                        let tv = try obj(GV.get(p, "target"), "target")
                        if nv(tv[JKey("verb")]) == nv(y[JKey("id")]) { prohibited = true }
                    }
                }
                if !prohibited {
                    chosen = y
                    break
                }
            }
            guard let v = chosen else { return nil }
            grants.append(GV.obj([("gid", .string("injected")), ("verb", nv(v[JKey("id")])),
                                  ("res", GV.obj([("k", .string("any")), ("reason", .string("injected"))])), ("cond", GV.obj([("k", .string("true"))]))]))
            x[JKey("grants")] = .array(grants)
            var ack = try GV.arr(x[JKey("wildcardAck")], "wildcardAck")
            ack.append(.string("injected"))
            x[JKey("wildcardAck")] = .array(ack)
            return try PCAGoalNormalize.canonicalizeGoal(.object(x))
        default:
            return nil
        }
    }

    /// The reference explainer: the card lines themselves.
    public static func deterministicExplain(_ proseLines: [String]) -> String { proseLines.joined(separator: "\n") }

    /// Round trip (b): the explainer sees ONLY the compiled card lines. `comparator(goalText, explanation)` returns an object with
    /// `equivalent`. Any failure escalates. Result: "ok" or "escalate".
    public static func roundTrip(_ goal: JSONValue, _ goalText: String, _ explainer: ([String]) throws -> String,
                                 _ comparator: (String, String) throws -> JSONValue) -> String {
        do {
            var lines: [String] = []
            for l in try GV.arr(try PCAGoalCard.renderCard(goal).get("lines"), "lines") {
                guard let s = l.asString else { return "escalate" }
                lines.append(s)
            }
            let e = try explainer(lines)
            return JS.truthy(try comparator(goalText, e).get("equivalent")) ? "ok" : "escalate"
        } catch {
            return "escalate"
        }
    }

    private static func rateOut(_ detected: Int, _ applied: Int) -> JSONValue {
        if applied == 0 { return .int(0) }
        let d = Double(detected) / Double(applied)
        return IV.isSafeDouble(d) ? .int(Int64(d)) : .double(d)
    }

    /// Fraction of semantic widenings the pair flags, per mutation kind: [{kind, applied, detected, rate}]. `cases` = [{goal, text}].
    public static func measureDetection(_ cases: JSONValue, _ ontology: JSONValue?, _ explainer: ([String]) throws -> String,
                                        _ comparator: (String, String) throws -> JSONValue) throws -> JSONValue {
        let list = try GV.arr(cases, "cases")
        var out: [JSONValue] = []
        for kind in MUTATION_KINDS {
            var applied = 0
            var detected = 0
            for co in list {
                guard let goal = GV.get(co, "goal"), goal.isObject else { throw IrError("goal expected") }
                guard let m = try mutateGoal(goal, kind, ontology) else { continue }
                applied += 1
                guard let text = GV.get(co, "text")?.asString else { throw IrError("text expected") }
                if roundTrip(m, text, explainer, comparator) == "escalate" { detected += 1 }
            }
            out.append(GV.obj([("kind", .string(kind)), ("applied", .int(Int64(applied))), ("detected", .int(Int64(detected))), ("rate", rateOut(detected, applied))]))
        }
        return .array(out)
    }
}
