import Foundation

/// The restricted resource id grammar: matching and (decidable) containment between two patterns. A pattern is `"*"`, `{exact}` or `{prefix, class, len}`.
public enum ActionIdPattern {
    private static let DIGITS = Array("0123456789".utf16)
    private static let HEXLC = DIGITS + Array("abcdef".utf16)
    private static let LOWER = Array("abcdefghijklmnopqrstuvwxyz".utf16)
    private static let UPPER = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ".utf16)
    private static let MAX_ID_LEN = 128

    /// The character set of an id class (digits, hex, alnum, slug, uuid, any_safe).
    public static func idClassChars(_ c: String) throws -> Set<UInt16> {
        let alnum = DIGITS + LOWER + UPPER
        switch c {
        case "digits": return Set(DIGITS)
        case "hex": return Set(HEXLC)
        case "alnum": return Set(alnum)
        case "slug": return Set(DIGITS + LOWER + Array("-_".utf16))
        case "uuid": return Set(HEXLC + [45])
        case "any_safe": return Set(alnum + Array("._-:/".utf16))
        default: throw AK.fail("unknown_id_class", "unknown id class \(c)")
        }
    }

    private static func inClass(_ s: [UInt16], _ c: String) throws -> Bool {
        let set = try idClassChars(c)
        return s.allSatisfy { set.contains($0) }
    }

    private static func isExact(_ p: JSONValue?) -> Bool { p?.asObject?[JKey("exact")] != nil }

    private static func isUuid(_ s: [UInt16]) -> Bool {
        guard s.count == 36 else { return false }
        for (i, u) in s.enumerated() {
            if i == 8 || i == 13 || i == 18 || i == 23 { if u != 45 { return false } } else if !HEXLC.contains(u) { return false }
        }
        return true
    }

    private static func lenPair(_ p: JSONValue?) throws -> (Double, Double) {
        let l = AK.arr(p?.get("len"))
        guard l.count >= 2, let a = IV.num(l[0]), let b = IV.num(l[1]) else { throw AK.fail("bad_pattern", "len") }
        return (a, b)
    }

    /// Does `id` (the id part of a resource, without the type) match the pattern?
    public static func idMatches(_ p: JSONValue?, _ id: String) throws -> Bool {
        let u = Array(id.utf16)
        if p?.asString == "*" { return try !u.isEmpty && u.count <= MAX_ID_LEN && (try inClass(u, "any_safe")) }
        if isExact(p) { return p?.get("exact")?.asString.map { IV.same($0, id) } ?? false }
        guard let prefix = p?.get("prefix")?.asString else { throw AK.fail("bad_pattern", "prefix") }
        let pu = Array(prefix.utf16)
        if !u.starts(with: pu) { return false }
        let rest = Array(u[pu.count...])
        let (lo, hi) = try lenPair(p)
        if Double(rest.count) < lo || Double(rest.count) > hi { return false }
        guard let cls = p?.get("class")?.asString else { throw AK.fail("bad_pattern", "class") }
        if cls == "uuid" { return isUuid(rest) }
        return try inClass(rest, cls)
    }

    private static func classSubset(_ a: String, _ b: String) throws -> Bool {
        let sa = try idClassChars(a), sb = try idClassChars(b)
        return sa.isSubset(of: sb)
    }

    /// Is every id matched by `inner` also matched by `outer`?
    public static func idPatternContains(_ outer: JSONValue?, _ inner: JSONValue?) throws -> Bool {
        if outer?.asString == "*" { return true }
        if inner?.asString == "*" { return false }
        if isExact(outer) { return isExact(inner) && AK.sameJson(inner?.get("exact"), outer?.get("exact")) }
        if isExact(inner) {
            guard let e = inner?.get("exact")?.asString else { throw AK.fail("bad_pattern", "exact") }
            return try idMatches(outer, e)
        }
        guard let ip = inner?.get("prefix")?.asString, let op = outer?.get("prefix")?.asString else { throw AK.fail("bad_pattern", "prefix") }
        let iu = Array(ip.utf16), ou = Array(op.utf16)
        if !iu.starts(with: ou) { return false }
        let r = Array(iu[ou.count...])
        guard let oc = outer?.get("class")?.asString, let ic = inner?.get("class")?.asString else { throw AK.fail("bad_pattern", "class") }
        if !(try inClass(r, oc)) { return false }
        if oc == "uuid" { return ic == "uuid" && r.isEmpty }
        if !(try classSubset(ic, oc)) { return false }
        let (ol0, ol1) = try lenPair(outer), (il0, il1) = try lenPair(inner)
        return Double(r.count) + il0 >= ol0 && Double(r.count) + il1 <= ol1
    }
}
