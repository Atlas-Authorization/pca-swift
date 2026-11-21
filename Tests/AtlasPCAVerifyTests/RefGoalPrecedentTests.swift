import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the goal precedent log (scripted flows over signed escalation answers: append, revoke, chain
/// verification, lookup, authorization with precedents, tampering), the ceilings, the answer body and the revocation signature
/// against the reference (@atlasauth/pca-goal). A reference throw requires a native refusal.
final class RefGoalPrecedentTests: XCTestCase {
    typealias P = PCAGoalPrecedent
    static let file = "ref-goal-precedent.json.gz"

    static func entryOut(_ r: JSONValue, _ withCell: Bool) -> JSONValue {
        if r.get("ok") != .bool(true) { return r }
        guard let e = r.get("entry") else { return r }
        var o: [(String, JSONValue)] = [("ok", .bool(true)), ("digest", e.get("digest") ?? .null)]
        if withCell { o.append(("cell", e.get("cell") ?? .null)) }
        o.append(("seq", e.get("seq") ?? .null))
        return GV.obj(o)
    }

    static func flow(_ a: [JSONValue]) throws -> JSONValue {
        let goal = a[0], ont = a[1], grant = a[2]
        let log = P.Log(a[3])
        let space = try PCAGoalExamples.buildSpace([goal], [])
        var out: [JSONValue] = []
        for s in a[4].asArray ?? [] {
            var now: Int64 = 0
            if let n = s.get("now"), !n.isNull { guard let i = IV.int(n) else { throw JSError("now") }; now = i }
            switch s.get("op")?.asString ?? "" {
            case "append":
                out.append(entryOut(try log.append(s.get("answer") ?? .null, s.get("answered") ?? .null, grant, space, now), true))
            case "revoke":
                out.append(entryOut(try log.revoke(s.get("rev") ?? .null), false))
            case "verifyChain":
                out.append(.bool(log.verifyChain(space)))
            case "lookup":
                guard let pd = s.get("policyDigest")?.asString else { throw JSError("policyDigest") }
                if let h = try log.lookup(pd, space, s.get("case") ?? .null, Double(now)) {
                    out.append(GV.obj([("decision", h.get("decision") ?? .null), ("digest", h.get("entry")?.get("digest") ?? .null)]))
                } else { out.append(.null) }
            case "authorize":
                guard let pd = s.get("policyDigest")?.asString else { throw JSError("policyDigest") }
                let r = try P.authorizeWithPrecedents(goal, ont, pd, log, s.get("case") ?? .null, Double(now))
                var o: [(String, JSONValue)] = [("decision", r.get("decision") ?? .null), ("via", r.get("via") ?? .null)]
                if let p = r.get("precedent"), !p.isNull { o.append(("digest", p.get("digest") ?? .null)) }
                out.append(GV.obj(o))
            case "tamper":
                guard let idx = IV.int(s.get("index")), idx >= 0, Int(idx) < log.entries.count, let key = s.get("key")?.asString else { throw JSError("tamper") }
                if s.get("del") == .bool(true) { log.entries[Int(idx)][JKey(key)] = nil } else { log.entries[Int(idx)][JKey(key)] = s.get("value") ?? .null }
                out.append(.bool(true))
            default:
                out.append(.string(log.head()))
            }
        }
        return .array(out)
    }

    func testGoalPrecedentAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "flow": return try Self.flow(a)
                case "ceilingsOf": return try P.ceilingsOf(a[0])
                case "answerBodyFor":
                    guard let o = a[1].asObject, let pr = o["principal"]?.asString, let dec = o["decision"]?.asString, let nonce = o["nonce"]?.asString else { throw JSError("answer options") }
                    return P.answerBodyFor(a[0], pr, dec, o["iat"], o["expires_at"], nonce)
                case "signRevocationSeed":
                    guard let s = a[1].asString, let seed = Base64URLStrict.decode(s) else { throw JSError("seed") }
                    return try P.signRevocation(a[0], seed)
                default: throw JSError("not mapped: \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(30)
    }
}
