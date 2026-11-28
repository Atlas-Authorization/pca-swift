import Foundation

/// Canonical form of a Goal: id-sorted clauses (code-unit order); duplicated ids are kept (the typechecker refuses them).
public enum PCAGoalNormalize {
    /// Stable JSON (keys sorted by UTF-16 code unit, no index-key-first rule): an in-memory key for maps and sets, not a signed encoding.
    public static func stable(_ v: JSONValue?) -> String {
        guard let v = v else { return "null" }
        var out = ""
        write(&out, v)
        return out
    }

    private static func write(_ out: inout String, _ v: JSONValue) {
        switch v {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .int(let i): out += String(i)
        case .double(let d): out += d.isFinite ? JS.number(d) : "null"
        case .string(let s): out += GV.q(s)
        case .array(let a):
            out += "["
            var first = true
            for x in a {
                if !first { out += "," }
                first = false
                write(&out, x)
            }
            out += "]"
        case .object(let o):
            let ks = o.keys.map { $0.s }.sorted(by: { GV.less($0, $1) })
            out += "{"
            var first = true
            for k in ks {
                if !first { out += "," }
                first = false
                out += GV.q(k) + ":"
                write(&out, o[JKey(k)]!)
            }
            out += "}"
        }
    }

    /// Stable sort of the clauses by their id member (UTF-16 code-unit order), like Array.prototype.sort.
    private static func byId(_ xs: JSONValue?, _ field: String) throws -> JSONValue {
        let a = try GV.arr(xs, field)
        var keyed: [(Int, String, JSONValue)] = []
        for (i, x) in a.enumerated() {
            guard let id = GV.get(x, field)?.asString else { throw IrError("string expected (\(field))") }
            keyed.append((i, id, x))
        }
        keyed.sort(by: { (p: (Int, String, JSONValue), q: (Int, String, JSONValue)) -> Bool in
            let c = GV.cmp(p.1, q.1)
            return c != 0 ? c < 0 : p.0 < q.0
        })
        return JSONValue.array(keyed.map { $0.2 })
    }

    /// `[...new Set(xs)].sort()`: de-duplicated by code points, ordered by UTF-16 code unit.
    private static func sortedSet(_ xs: JSONValue?) throws -> JSONValue {
        var seen = Set<JKey>()
        var out: [String] = []
        for o in try GV.arr(xs, "") {
            guard let s = o.asString else { throw IrError("string expected") }
            if seen.insert(JKey(s)).inserted { out.append(s) }
        }
        out.sort(by: { GV.less($0, $1) })
        return JSONValue.array(out.map { JSONValue.string($0) })
    }

    public static func canonicalizeGoal(_ g: JSONValue) throws -> JSONValue {
        guard var out = g.asObject else { throw IrError("goal expected an object") }
        out[JKey("grants")] = try byId(GV.get(g, "grants"), "gid")
        out[JKey("prohibits")] = try byId(GV.get(g, "prohibits"), "pid")
        out[JKey("bounds")] = try byId(GV.get(g, "bounds"), "bid")
        out[JKey("holes")] = try byId(GV.get(g, "holes"), "hid")
        out[JKey("wildcardAck")] = try sortedSet(GV.get(g, "wildcardAck"))
        guard var d = GV.get(g, "deleg")?.asObject else { throw IrError("deleg expected an object") }
        d[JKey("mayTouch")] = try sortedSet(d[JKey("mayTouch")])
        out[JKey("deleg")] = JSONValue.object(d)
        return JSONValue.object(out)
    }
}
