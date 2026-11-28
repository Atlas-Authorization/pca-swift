import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAScim against the reference (@atlasauth/pca-scim): the /Agents handler over request sessions (the
/// generator's named option sets are rebuilt here), the passport mapping, filters, the Entra / Okta payloads and their push.
final class RefScimTests: XCTestCase {
    static let file = "ref-scim.json.gz"
    static let T0: Double = 1_700_000_000_000

    static func handler(_ name: String) throws -> PCAScim.Handler {
        let store = PCAScim.MemoryStore()
        let fixed: () -> Double = { T0 }
        switch name {
        case "open": return try PCAScim.Handler(store: store, authenticate: { _ in true }, baseUrl: "https://scim.acme.com/scim/v2", now: fixed)
        case "slash": return try PCAScim.Handler(store: store, authenticate: { _ in true }, baseUrl: "https://scim.acme.com/scim/v2///", now: fixed)
        case "nobase": return try PCAScim.Handler(store: store, authenticate: nil, allowUnauthenticated: true, now: fixed)
        case "tick":
            var tick = 0.0
            return try PCAScim.Handler(store: store, authenticate: { _ in true }, baseUrl: "https://x.example", now: { defer { tick += 1 }; return T0 + 1000 * tick })
        case "deny": return try PCAScim.Handler(store: store, authenticate: { _ in false }, now: fixed)
        case "throwauth": return try PCAScim.Handler(store: store, authenticate: { _ in throw JSError("x") }, now: fixed)
        case "truthy": return try PCAScim.Handler(store: store, authenticate: { _ in false }, now: fixed) // returns "yes": not `true`
        default: return try PCAScim.Handler(store: store, authenticate: nil, now: fixed) // none / not a function
        }
    }

    static func meta(_ v: JSONValue?) -> PCAScim.MetaInput {
        var m = PCAScim.MetaInput()
        m.baseUrl = v?.get("baseUrl")?.asString
        m.created = v?.get("created")?.asString
        m.lastModified = v?.get("lastModified")?.asString
        return m
    }

    static func fetch(_ mode: String, _ calls: @escaping (JSONValue) -> Void) -> PCAScim.Fetch {
        return { url, method, headers, body in
            var h: JObject = [:]
            for (k, v) in headers { h[JKey(k)] = .string(v) }
            calls(.object(["url": .string(url), "init": .object(["method": .string(method), "headers": .object(h), "body": .string(body)])]))
            switch mode {
            case "ok201": return (true, 201, { .object(["id": .string("obj-1")]) })
            case "err500": return (false, 500, { .object(["detail": .string("x")]) })
            case "badjson": return (true, 204, { throw JSError("no body") })
            default: return (true, 200, { .null })
            }
        }
    }

    func testScim() throws {
        try K042.requireCovers(["Scim", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            let got: BaseGot
            switch c.fn {
            case "scimSession":
                got = Ref.v {
                    let h = try Self.handler(a0?.asString ?? "")
                    for r in a1?.asArray ?? [] { _ = try h.handle(r) }
                    return .array(try (a2?.asArray ?? []).map { try h.handle($0) })
                }
            case "passportToScim":
                got = Ref.v {
                    var m = Self.meta(a2)
                    if let ms = a2, ms.isNumber { m = PCAScim.MetaInput(); m.now = { IV.num(ms) ?? 0 } }
                    return try PCAScim.passportToScim(Ref.obj(a0), Ref.obj(a1), m)
                }
            case "scimToProvisioningRequest":
                got = Ref.v { try PCAScim.scimToProvisioningRequest(a0) }
            case "parseFilter":
                got = Ref.v { let f = try PCAScim.parseFilter(a0); return .object(["attr": .string(f.attr), "value": f.value]) }
            case "scimError":
                // the reference sets `scimType` whenever it is not undefined, so an explicit JSON null is carried through as null
                var e = PCAScim.scimError(Int(IV.num(a0) ?? 0), a1?.asString ?? "", a2?.asString)
                if a2 == .null, case .object(var o) = e { o["scimType"] = .null; e = .object(o) }
                got = .value(e)
            case "scimListResponse":
                got = .value(PCAScim.scimListResponse(a0?.asArray ?? [], a1 ?? .null, a2 ?? .null))
            case "passportFingerprint":
                got = Ref.s { try PCAIssue.passportFingerprint(Ref.obj(a0)) }
            case "issuePassport":
                got = Ref.v { .object(try PCAIssue.issuePassport(Ref.obj(a0))) }
            case "registry":
                let all = PCAScim.buildRegistry((a0?.asArray ?? []).map { $0.asObject ?? [:] })
                let hit = all.first { $0["id"] == a1 }
                got = .value(.object(["all": .array(all.map { .object($0) }), "has": .bool(hit != nil), "get": hit.map { .object($0) } ?? .null]))
            case "toEntraAgentPayload":
                got = .value(PCAScim.toEntraAgentPayload(Ref.obj(a0)))
            case "toOktaScimPayload":
                got = .value(PCAScim.toOktaScimPayload(Ref.obj(a0)))
            case "pushToEntra", "pushToOkta", "pushProvision":
                got = Ref.v {
                    var calls: [JSONValue] = []
                    let push = c.fn == "pushProvision"
                    let agent = Ref.obj(push ? a0 : a1), mode = (push ? a1 : a2)?.asString ?? ""
                    let entra = push || a0?.asString == "pushToEntra"
                    let payload = entra ? PCAScim.toEntraAgentPayload(agent) : PCAScim.toOktaScimPayload(agent)
                    let r = try PCAScim.pushProvision(payload, endpoint: push ? "e" : "https://dir.example/scim/Agents", token: push ? "t" : "TOK",
                                                      fetch: Self.fetch(mode) { calls.append($0) })
                    return .object(["result": r, "calls": .array(calls)])
                }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1000)
    }

    func testScimFailClosed() throws {
        // no authenticator without the explicit opt-out; an authenticator that throws denies
        XCTAssertThrowsError(try PCAScim.Handler(store: PCAScim.MemoryStore(), authenticate: nil))
        let h = try PCAScim.Handler(store: PCAScim.MemoryStore(), authenticate: { _ in throw JSError("down") })
        XCTAssertEqual(try h.handle(.object(["method": .string("GET")])).get("status"), .int(401))
        XCTAssertEqual(try PCAScim.isoString(0), "1970-01-01T00:00:00.000Z")
        XCTAssertEqual(try PCAScim.isoString(-1), "1969-12-31T23:59:59.999Z")
        XCTAssertEqual(try PCAScim.isoString(253_402_300_800_000), "+010000-01-01T00:00:00.000Z")
        XCTAssertThrowsError(try PCAScim.isoString(8.64e15 + 1))
    }
}
