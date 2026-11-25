import Foundation

/// Plain-text rendering of quantities, values and acts. An unknown currency is shown in raw minor units, never guessed.
public enum PCAGoalFmt {
    public static let CCY_EXPONENT: [String: Int] = ["USD": 2, "EUR": 2, "GBP": 2, "CAD": 2, "AUD": 2, "CHF": 2, "JPY": 0, "KRW": 0]

    private static func exponent(_ ccy: String) -> Int? {
        for (k, v) in CCY_EXPONENT where IV.same(k, ccy) { return v }
        return nil
    }

    /// `minor` is rendered as `String(minor)` (padded to the exponent in UTF-16 units, like padStart / slice).
    public static func fmtMoney(_ ccy: String, _ minor: JSONValue?) -> String {
        let m = GV.jsStr(minor)
        guard let e = exponent(ccy) else { return ccy + " " + m + " (minor units)" }
        if e == 0 { return ccy + " " + m }
        var u = Array(m.utf16)
        while u.count < e + 1 { u.insert(48, at: 0) }
        let cut = u.count - e
        return ccy + " " + String(decoding: u[0..<cut], as: UTF16.self) + "." + String(decoding: u[cut...], as: UTF16.self)
    }

    public static func fmtQuantity(_ q: JSONValue) throws -> String {
        let u = try GV.obj(GV.get(q, "u"), "unit")
        let n = GV.get(q, "n")
        let uv = JSONValue.object(u)
        switch GV.kind(uv) {
        case "money": return fmtMoney(GV.jsStr(u[JKey("ccy")]), n)
        case "count": return GV.jsStr(n)
        case "duration": return GV.jsStr(n) + "ms"
        case "instant": return "@" + GV.jsStr(n)
        case "bytes": return GV.jsStr(n) + "B"
        case "ratio": return GV.jsStr(n) + "ppm"
        default: throw IrError("unknown unit")
        }
    }

    public static func fmtValue(_ v: JSONValue) throws -> String {
        let k = GV.kind(v)
        if k == "q" {
            guard let q = GV.get(v, "q"), q.isObject else { throw IrError("quantity expected an object") }
            return try fmtQuantity(q)
        }
        if k == "s" {
            guard let s = GV.get(v, "s")?.asString else { throw IrError("string expected") }
            return GV.q(s)
        }
        var xs: [String] = []
        for i in try GV.arr(GV.get(v, "items"), "items") {
            guard i.isObject else { throw IrError("value expected an object") }
            xs.append(try fmtValue(i))
        }
        return "{" + xs.joined(separator: ", ") + "}"
    }

    public static func fmtAct(_ a: JSONValue) throws -> String {
        let params = try GV.obj(GV.get(a, "params"), "params")
        let ks = params.keys.map { $0.s }.sorted(by: { GV.less($0, $1) })
        var ps: [String] = []
        for k in ks {
            guard let pv = params[JKey(k)], pv.isObject else { throw IrError("value expected an object") }
            ps.append(k + "=" + (try fmtValue(pv)))
        }
        return GV.jsStr(GV.get(a, "verb")) + " on " + GV.jsStr(GV.get(a, "res")) + (ps.isEmpty ? "" : " (" + ps.joined(separator: ", ") + ")")
    }
}
