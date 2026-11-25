import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCARevoke against the reference (@atlasauth/pca-revoke): scenario scripts over a registry (revoke,
/// subtree, kill-switch, unrevoke, the chain check, verifyWithRevocation, the CAEP bridge), isActiveAt and the event-type constants.
final class RefRevokeTests: XCTestCase {
    static let file = "ref-revoke.json.gz"
    /// The frozen clock the corpus generator ran under (its header's clockMs).
    static let clock = Base.clockMs(file)

    /// A store whose `get` (failGet) or `all` (failAll) throws, as the reference's throwing stores do.
    final class Failing: PCARevoke.Store {
        let base = PCARevoke.InMemoryStore()
        let failGet: Bool, failAll: Bool
        init(failGet: Bool, failAll: Bool) { self.failGet = failGet; self.failAll = failAll }
        func add(_ entry: JSONValue) throws { try base.add(entry) }
        func remove(_ kind: String, _ value: String) throws -> Bool { try base.remove(kind, value) }
        func get(_ kind: String, _ value: String) throws -> JSONValue? { if failGet { throw JSError("boom") }; return try base.get(kind, value) }
        func all() throws -> [JSONValue] { if failAll { throw JSError("boom") }; return try base.all() }
        func clear() throws { try base.clear() }
    }

    /// The reference prints a revokedAt within two minutes of the wall clock, or of the generator's frozen clock, as "<now>".
    static func norm(_ v: JSONValue, clock: Double = RefRevokeTests.clock) -> JSONValue {
        let now = PCARevoke.nowMs()
        switch v {
        case let .array(a): return .array(a.map { norm($0, clock: clock) })
        case let .object(o):
            var out: JObject = [:]
            for (k, x) in o {
                if k.s == "revokedAt", let f = PCARevoke.finite(x), (abs(f - now) < 120_000 || abs(f - clock) < 120_000) { out[k] = .string("<now>") } else { out[k] = norm(x, clock: clock) }
            }
            return .object(out)
        default: return v
        }
    }

    static func scenario(_ spec: JSONValue?) -> JSONValue {
        let st = spec?.get("store")?.asString ?? "mem"
        let reg = PCARevoke.Registry(Failing(failGet: st == "failGet", failAll: st == "failAll"))
        var out: [JSONValue] = []
        for s in spec?.get("ops")?.asArray ?? [] {
            func v(_ k: String) -> JSONValue { s.get(k) ?? .null }
            do {
                let r: JSONValue
                switch s.get("op")?.asString ?? "" {
                case "revoke": r = try reg.revoke(v("input"))
                case "revokeSubtree": r = try reg.revokeSubtree(v("target"), s.get("opts"))
                case "unrevoke": r = .bool(try reg.unrevoke(v("key")))
                case "list": r = .array(try reg.list())
                case "lookup": r = try reg.lookup(s.get("kind")?.asString ?? "", s.get("value")?.asString ?? "") ?? .null
                case "prefixes": r = .array(try reg.prefixes())
                case "clear": try reg.clear(); r = .null
                case "killAgent": r = try reg.killAgent(v("holder"), s.get("opts"))
                case "killSubtree": r = try reg.killSubtree(v("root"), s.get("opts"))
                case "check": r = PCARevoke.checkRevocation(v("p"), reg, s.get("opts"))
                case "verify": r = PCARevoke.verifyWithRevocation(v("p"), v("core"), reg, s.get("opts"))
                case "ingest": r = .array(try PCARevoke.ingestCaepEvent(v("event"), reg))
                default: XCTFail("unknown op"); r = .null
                }
                out.append(norm(r))
            } catch {
                out.append(.object(["$err": .bool(true)]))
            }
        }
        return .array(out)
    }

    func testRevoke() throws {
        try K042.requireCovers(["Revoke", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "scenario": got = .value(Self.scenario(c.arg(0)))
            case "isActiveAt": got = .value(.bool(PCARevoke.isActiveAt(c.arg(0) ?? .null, c.arg(1))))
            case "caepEventTypes": got = .value(PCARevoke.caepEventTypes())
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1800)
    }

    func testRevokeFailClosed() throws {
        let reg = PCARevoke.Registry()
        let p: JSONValue = .object(["cap_chain": .array([.object(["id": .string("c"), "issuer": .string("i"), "holder": .string("h")])])])
        XCTAssertEqual(PCARevoke.checkRevocation(p, reg, .object(["now": .double(.nan)])).get("revoked"), .bool(true))
        XCTAssertEqual(PCARevoke.checkRevocation(.null, reg).get("revoked"), .bool(true))
        try reg.killAgent(.string("h"))
        XCTAssertEqual(PCARevoke.verifyWithRevocation(p, .object(["allow": .bool(true)]), reg).get("allow"), .bool(false))
        let broken = PCARevoke.Registry(Failing(failGet: true, failAll: false))
        XCTAssertEqual(PCARevoke.checkRevocation(p, broken).get("revoked"), .bool(true))
    }
}
