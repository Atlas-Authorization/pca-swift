import Foundation

/// The human-readable PolicyCard text: a fixed phrase table over the IR, every clause with its exact numbers.
public enum PCAGoalCard {
    public static func q(_ x: JSONValue?) -> String { GV.quote(x) }

    private static func s(_ o: JSONValue?) -> String { GV.jsStr(o) }

    private static func mm(_ o: JSONValue?) throws -> JSONValue {
        guard let v = o, v.isObject else { throw IrError("value expected an object") }
        return v
    }

    private static func join(_ xs: [JSONValue], _ f: (JSONValue) throws -> String, _ sep: String) rethrows -> String {
        var out: [String] = []
        for x in xs { out.append(try f(x)) }
        return out.joined(separator: sep)
    }

    public static func unit(_ u: JSONValue) -> String { GV.kind(u) == "money" ? s(GV.get(u, "ccy")) + " minor units" : GV.kind(u) }

    public static func quantity(_ x: JSONValue) throws -> String { s(GV.get(x, "n")) + " " + unit(try mm(GV.get(x, "u"))) }

    public static func renderQuantity(_ x: JSONValue) throws -> String { try quantity(x) }

    public static func value(_ v: JSONValue) throws -> String {
        let k = GV.kind(v)
        if k == "q" { return try quantity(try mm(GV.get(v, "q"))) }
        if k == "s" { return q(GV.get(v, "s")) }
        return "{" + (try join(try GV.arr(GV.get(v, "items"), "items"), { i in try value(try mm(i)) }, ", ")) + "}"
    }

    public static func term(_ t: JSONValue) throws -> String {
        let k = GV.kind(t)
        if k == "param" {
            let ty = try mm(GV.get(t, "ty"))
            var tyText = "text"
            if GV.kind(ty) == "q" { tyText = unit(try mm(GV.get(ty, "u"))) }
            return "param " + q(GV.get(t, "path")) + " (" + tyText + ")"
        }
        if k == "lit" { return try value(try mm(GV.get(t, "v"))) }
        return "running total of bound " + q(GV.get(t, "bid")) + " (" + unit(try mm(GV.get(t, "u"))) + ")"
    }

    private static let OPW: [String: String] = [
        "eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">=", "in": "is one of", "nin": "is none of",
    ]

    public static func cond(_ c: JSONValue) throws -> String {
        switch GV.kind(c) {
        case "true": return "always"
        case "cmp":
            let l = try term(try mm(GV.get(c, "l")))
            let w = OPW[s(GV.get(c, "op"))] ?? "undefined"
            let r = try term(try mm(GV.get(c, "r")))
            return l + " " + w + " " + r
        case "and":
            let a = try cond(try mm(GV.get(c, "a")))
            let b = try cond(try mm(GV.get(c, "b")))
            return "(" + a + ") AND (" + b + ")"
        case "or":
            let a = try cond(try mm(GV.get(c, "a")))
            let b = try cond(try mm(GV.get(c, "b")))
            return "(" + a + ") OR (" + b + ")"
        case "not": return "NOT (" + (try cond(try mm(GV.get(c, "c")))) + ")"
        default: throw IrError("unknown condition")
        }
    }

    public static func renderCond(_ c: JSONValue) throws -> String { try cond(c) }

    public static func res(_ r: JSONValue) throws -> String {
        switch GV.kind(r) {
        case "exact": return "exactly " + q(GV.get(r, "id"))
        case "oneof": return "one of [" + (try join(try GV.arr(GV.get(r, "ids"), "ids"), { x in q(x) }, ", ")) + "]"
        case "related": return s(GV.get(r, "rel")) + " of " + q(GV.get(r, "anchor"))
        case "all_of": return "ALL OF (" + (try join(try GV.arr(GV.get(r, "parts"), "parts"), { p in try res(try mm(p)) }, " AND ")) + ")"
        default: return "ANY RESOURCE (reason: " + q(GV.get(r, "reason")) + ")"
        }
    }

    public static func win(_ w: JSONValue) -> String {
        switch GV.kind(w) {
        case "task": return "per task"
        case "lifetime": return "over the lifetime"
        case "sliding": return "in any " + s(GV.get(w, "ms")) + " ms window"
        default: return "per " + s(GV.get(w, "ms")) + " ms period starting at " + s(GV.get(w, "t0"))
        }
    }

    public static func scope(_ sc: JSONValue) throws -> String {
        if GV.kind(sc) == "fleet" { return "fleet [" + (try join(try GV.arr(GV.get(sc, "agents"), "agents"), { x in q(x) }, ", ")) + "]" }
        return GV.kind(sc)
    }

    public static func grantLine(_ x: JSONValue) throws -> String {
        let r = try res(try mm(GV.get(x, "res")))
        let c = try cond(try mm(GV.get(x, "cond")))
        return "ALLOW " + q(GV.get(x, "gid")) + ": verb " + q(GV.get(x, "verb")) + " on " + r + " when " + c
    }

    public static func prohibitLine(_ x: JSONValue) throws -> String {
        let t = try mm(GV.get(x, "target"))
        let tgt = GV.kind(t) == "verb" ? "verb " + q(GV.get(t, "verb")) : "every verb of effect class " + q(GV.get(t, "cls"))
        let r = try res(try mm(GV.get(x, "res")))
        let c = try cond(try mm(GV.get(x, "cond")))
        return "NEVER " + q(GV.get(x, "pid")) + ": " + tgt + " on " + r + " when " + c
    }

    public static func boundLine(_ b: JSONValue) throws -> String {
        let sel = try mm(GV.get(b, "sel"))
        let over: String
        if GV.kind(sel) == "gids" { over = "grants [" + (try join(try GV.arr(GV.get(sel, "gids"), "gids"), { x in q(x) }, ", ")) + "]" }
        else { over = "effect class " + q(GV.get(sel, "cls")) }
        let agg = s(GV.get(b, "agg"))
        let of: String
        if agg == "count" { of = "" }
        else if agg == "distinct" { of = " of " + q(GV.get(b, "key")) }
        else { of = " of " + (try term(try mm(GV.get(b, "value")))) }
        let w = win(try mm(GV.get(b, "window")))
        let sc = try scope(try mm(GV.get(b, "scope")))
        let cap = try quantity(try mm(GV.get(b, "cap")))
        let beyond = GV.get(b, "onExceed") == .string("deny") ? "deny" : "ask the principal"
        var out: String = "LIMIT " + q(GV.get(b, "bid")) + ": " + agg + of
        out += " over " + over + ", " + w + ", scope " + sc
        out += ", at most " + cap + "; beyond that: " + beyond
        return out
    }

    public static func validityLine(_ v: JSONValue) -> String {
        "VALID from " + s(GV.get(v, "notBefore")) + " to " + s(GV.get(v, "notAfter")) + "; idle limit " +
            (JS.toNumber(GV.get(v, "maxIdle") ?? .null) > 0 ? s(GV.get(v, "maxIdle")) + " ms" : "none")
    }

    public static func delegationLine(_ d: JSONValue) throws -> String {
        "DELEGATION depth at most " + s(GV.get(d, "maxDepth")) + ", narrow only " + s(GV.get(d, "narrowOnly")) + ", delegates may use grants [" +
            (try join(try GV.arr(GV.get(d, "mayTouch"), "mayTouch"), { x in q(x) }, ", ")) + "]"
    }

    public static func escalateLine(_ c: JSONValue) throws -> String { "ASK THE PRINCIPAL when " + (try cond(c)) }

    public static func holeLine(_ h: JSONValue) throws -> String {
        let affects: String
        if JS.truthy(GV.get(h, "global")) { affects = "everything" }
        else { affects = "[" + (try join(try GV.arr(GV.get(h, "affects"), "affects"), { x in q(x) }, ", ")) + "]" }
        return "UNRESOLVED " + q(GV.get(h, "hid")) + ": " + q(GV.get(h, "q")) + " options [" +
            (try join(try GV.arr(GV.get(h, "domain"), "domain"), { x in q(x) }, ", ")) + "] affects " + affects
    }

    /// One line per clause in canonical order, plus the warnings the principal must look at twice: {lines, warnings}.
    public static func renderCard(_ g: JSONValue) throws -> JSONValue {
        var lines: [JSONValue] = []
        var warnings: [JSONValue] = []
        var head: String = "Goal v" + s(GV.get(g, "v")) + " for principal " + q(GV.get(g, "principal"))
        head += "; ontology " + q(GV.get(g, "ontDigest")) + "; request text digest " + q(GV.get(g, "nlDigest"))
        lines.append(.string(head))
        for x in try GV.arr(GV.get(g, "sources"), "sources") { lines.append(.string("Source " + q(x))) }
        let ack = try GV.arr(GV.get(g, "wildcardAck"), "wildcardAck")
        for x in try GV.arr(GV.get(g, "grants"), "grants") {
            let gr = try mm(x)
            lines.append(.string(try grantLine(gr)))
            if GV.kind(GV.get(gr, "res")) == "any" {
                warnings.append(.string("grant " + q(GV.get(gr, "gid")) + " applies to every resource" + (ack.contains(GV.get(gr, "gid") ?? .null) ? " (acknowledged)" : " (NOT acknowledged)")))
            }
        }
        for x in try GV.arr(GV.get(g, "prohibits"), "prohibits") { lines.append(.string(try prohibitLine(try mm(x)))) }
        for b in try GV.arr(GV.get(g, "bounds"), "bounds") { lines.append(.string(try boundLine(try mm(b)))) }
        lines.append(.string(validityLine(try mm(GV.get(g, "validity")))))
        lines.append(.string(try delegationLine(try mm(GV.get(g, "deleg")))))
        for c in try GV.arr(GV.get(g, "escalateOn"), "escalateOn") { lines.append(.string(try escalateLine(c))) }
        for a in ack { lines.append(.string("Wildcard acknowledged for " + q(a))) }
        let holes = try GV.arr(GV.get(g, "holes"), "holes")
        for h in holes { lines.append(.string(try holeLine(try mm(h)))) }
        if !holes.isEmpty { warnings.append(.string("this goal has unresolved questions and cannot be signed")) }
        return GV.obj([("lines", .array(lines)), ("warnings", .array(warnings))])
    }
}
