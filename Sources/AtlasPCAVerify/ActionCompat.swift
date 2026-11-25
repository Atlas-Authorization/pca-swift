import Foundation

/// Migration shims between the old, disagreeing action vocabularies and the one action-def vocabulary. Old names stay accepted on INPUT
/// for one release; every conversion is total and fails closed.
public enum ActionCompat {
    private static let BLAST_RADII = ["one", "bounded", "tenant", "global"]
    private static let BLAST_PPM: [String: Int64] = ["one": 50_000, "bounded": 300_000, "tenant": 700_000, "global": 1_000_000]
    public static let PPM_MAX: Int64 = 1_000_000

    /// Any old reversibility word to the canonical class (anything unknown is irreversible: fail closed).
    public static func normalizeReversibility(_ x: JSONValue?) -> String {
        if x == .string("reversible") || x == .string("read") { return "reversible" }
        if x == .string("rate_limited") || x == .string("costly") { return "rate_limited" }
        return "irreversible"
    }

    /// The operations-side word for the revocation staleness table (`rate_limited` becomes `costly`).
    public static func legacyOperationsClass(_ r: String) -> String { r == "rate_limited" ? "costly" : r }

    public static func maxRevOf(_ a: String, _ b: String) -> String { (Actions.REV_RANK[a] ?? 2) >= (Actions.REV_RANK[b] ?? 2) ? a : b }

    /// The schema `units` entry and the envelope unit tag from a def's unit (nil for a money unit whose currency is a reference).
    public static func unitTagOf(_ u: JObject) -> JSONValue? {
        if u["kind"] != .string("money") { return AK.obj(["kind": u["kind"] ?? .null]) }
        guard u["ccy"]?.asString != nil else { return nil }
        var m: JObject = ["kind": .string("money"), "currency": u["ccy"] ?? .null]
        if let e = u[JKey("exp")] { m["exponent"] = e }
        return .object(m)
    }

    private static func ppmOf(_ x: Double) -> Int64 {
        let v = (x.isNaN || x.isInfinite ? 1.0 : x) * 1_000_000
        let r = v.rounded(.down)
        let rounded: Double = v - r >= 0.5 ? r + 1 : r
        // clamp as a Double first: Int64(1e300) traps, the reference's Math.min(PPM_MAX, ...) just returns PPM_MAX
        return Int64(min(Double(PPM_MAX), max(0, rounded)))
    }

    /// The smallest radius whose default covers the float, and the integer ppm.
    public static func blastOfFloat(_ x: Double) -> JSONValue {
        let ppm = ppmOf(x)
        var radius = "global"
        for r in BLAST_RADII where BLAST_PPM[r]! >= ppm { radius = r; break }
        return AK.obj(["radius": .string(radius), "ppm": .int(ppm)])
    }

    /// A legacy float kept EXACTLY: the largest radius whose default does not exceed it, with the ppm override carrying the exact value.
    public static func blastExactOfFloat(_ x: Double) -> JSONValue {
        let ppm = ppmOf(x)
        var radius = "one"
        for r in BLAST_RADII.reversed() where BLAST_PPM[r]! <= ppm { radius = r; break }
        return AK.obj(["radius": .string(radius), "ppm": .int(ppm)])
    }

    private static func tokens(_ s: String) -> [String] { s.components(separatedBy: "_") }

    /// Convert an old catalog entry (`connector, action, verb, reversibility, blastRadius, amountField?, resource?, description`).
    /// Effects are inferred conservatively from the action name (an unknown write is `update`, never `read`); `o`: `{ccy?, exp?, maxAmount?}`.
    public static func fromCatalogSpec(_ s: JObject, _ o: JObject?) throws -> JSONValue {
        var effects: [JSONValue] = []
        let amountField = AK.pres(s, "amountField")
        guard let action = s["action"]?.asString, let desc = s["description"]?.asString, let br = IV.num(s["blastRadius"]) else { throw AK.fail("bad_spec", "action, description, blastRadius") }
        if amountField != nil { effects.append(.string("pay")) }
        if ["read", "get", "list", "view", "search", "fetch", "head"].contains(tokens(action)[0]) { effects.append(.string("read")) }
        let tk = tokens(action)
        if tk.contains(where: { ["delete", "remove", "destroy", "drop", "purge"].contains($0) }) { effects.append(.string("delete")) }
        if tk.contains(where: { ["send", "post", "publish", "notify", "email", "sms"].contains($0) }) { effects.append(.string("send")) }
        if effects.isEmpty { effects.append(.string("update")) }
        var params: JObject = [:]
        if let af = amountField {
            guard let name = af.asString else { throw AK.fail("bad_spec", "amountField") }
            let max = o.flatMap { AK.pres($0, "maxAmount") } ?? .int(100_000_000_000)
            let ccy = o.flatMap { AK.pres($0, "ccy") } ?? .string("USD")
            let exp = o.flatMap { AK.pres($0, "exp") } ?? .int(2)
            params[JKey(name)] = AK.obj(["type": .string("integer"), "role": .string("money.amount"), "min": .int(0), "max": max, "unit": AK.obj(["kind": .string("money"), "ccy": ccy, "exp": exp])])
            params["idempotency_key"] = AK.obj(["type": .string("string"), "max_len": .int(128)])
        }
        let b = blastOfFloat(br)
        let resource = AK.pres(s, "resource")
        let wildcard = resource == nil || resource == .string("*")
        let du = Array(desc.utf16)
        let title = du.count > 120 ? String(decoding: du[..<117], as: UTF16.self) + "..." : desc
        let id: JSONValue = wildcard ? .string("*") : AK.obj(["prefix": .string(""), "class": .string("any_safe"), "len": .array([.int(1), .int(128)])])
        var d: JObject = ["v": .int(1), "kind": .string("pca-action-def"), "verb": s["verb"] ?? .null, "title": .string(title), "description": .string(desc), "effects": .array(effects),
                          "resource": AK.obj(["type": s["connector"] ?? .null, "id": id, "scope": .string(wildcard ? "set" : "one")]),
                          "params": .object(params), "reversibility": .string(normalizeReversibility(s["reversibility"])),
                          "blast": AK.obj(["radius": b.get("radius") ?? .null, "ppm": b.get("ppm") ?? .null])]
        if amountField != nil { d["idempotency"] = AK.obj(["mode": .string("key_param"), "param": .string("idempotency_key")]) }
        d["review"] = AK.obj(["state": .string("authored")])
        return .object(d)
    }

    public static func fromCatalog(_ specs: [JSONValue], _ o: JObject?) throws -> [JSONValue] { try specs.map { try fromCatalogSpec(AK.o($0), o) } }
}
