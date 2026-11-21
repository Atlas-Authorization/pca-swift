import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAOidc against the reference (@atlasauth/pca-oidc): discovery, ID-token verification across
/// algorithms and key sources, the remote JWK Set cache, the principal mapping. Function-valued options travel as JSON specs
/// (a key set, a resolver, a scripted fetch) and are rebuilt here as the generator builds them.
final class RefOidcTests: XCTestCase {
    static let file = "ref-oidc.json.gz"

    /// A scripted fetch: the replies in order (the last repeats); {throws: true} is a transport failure.
    static func fetch(_ spec: JSONValue?, record: ((String) -> Void)? = nil) -> OidcFetch {
        let replies = spec?.get("responses")?.asArray ?? []
        var i = 0
        return { url in
            record?(url)
            guard !replies.isEmpty else { throw JSError("no reply") }
            let r = replies[min(i, replies.count - 1)]
            i += 1
            if r.get("throws") == .bool(true) { throw JSError("boom") }
            var h: [String: String] = [:]
            for (k, v) in r.get("headers")?.asObject ?? [:] { h[k.s.lowercased()] = JS.toString(v) }
            return OidcFetchResponse(status: Int(IV.num(r.get("status")) ?? 0), body: r.get("body")?.asString ?? "", headers: h)
        }
    }

    static func key(_ k: JSONValue) throws -> OidcKey {
        if let b = Base.bytes(k) { return .secret(b) }
        if let o = k.asObject {
            if let j = o["jwks"] { return .set(try OidcLocalJwks(j)) }
            if let r = o["resolver"]?.asObject {
                var ro = r
                ro["fetch"] = nil
                return .resolver(try OidcJwks(ro, fetch: fetch(r["fetch"])))
            }
        }
        return .jwk(k)
    }

    static func pick(_ j: JObject) -> JSONValue {
        var o: JObject = [:]
        for k in ["kty", "crv", "x", "y", "n", "e"] { if let v = j[JKey(k)] { o[JKey(k)] = v } }
        return .object(o)
    }

    static func errKind(_ e: Error) -> JSONValue { .object(["err": .string((e as? JSError)?.code == "keys" ? "keys" : "other")]) }

    func testOidc() throws {
        try K042.requireCovers(["Oidc", "Jose", "WhatwgURL", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object([
                    "DEFAULT_ID_TOKEN_ALGS": .array(PCAOidc.DEFAULT_ID_TOKEN_ALGS.map { .string($0) }),
                    "DEFAULT_MAX_DISCOVERY_BYTES": .int(Int64(PCAOidc.DEFAULT_MAX_DISCOVERY_BYTES)),
                    "DEFAULT_JWKS_TIMEOUT_MS": .int(Int64(PCAOidc.DEFAULT_JWKS_TIMEOUT_MS)), "OIDC_SUBJECT_CAVEAT": .string(PCAOidc.OIDC_SUBJECT_CAVEAT),
                ]))
            case "verifyIdToken":
                got = Ref.v {
                    let o = a1?.asObject
                    let k = try o?["key"].map { try Self.key($0) }
                    let f = o?["fetch"].map { Self.fetch($0) }
                    return try PCAOidc.verifyIdToken(a0, a1, key: k, fetch: f)
                }
            case "discoveryUrl":
                got = Ref.s { try PCAOidc.discoveryUrl(a0) }
            case "discoverOidc":
                got = Ref.v { try PCAOidc.discoverOidc(a0, a1, fetch: a1?.asObject?["fetch"].map { Self.fetch($0) }) }
            case "discoverOidcCalls":
                var urls: [String] = []
                let f = Self.fetch(a1?.get("fetch")) { urls.append($0) }
                let outcome = (try? PCAOidc.discoverOidc(a0, a1, fetch: f)) == nil ? "error" : "ok"
                got = .value(.object(["urls": .array(urls.map { .string($0) }), "outcome": .string(outcome)]))
            case "createOidcJwks":
                got = Ref.v {
                    var clock = 0.0
                    var fetches = 0
                    let s = a0?.asObject ?? [:]
                    let f = Self.fetch(s["fetch"])
                    var ro: JObject = s["opts"]?.asObject ?? [:]
                    if let u = s["jwksUri"] { ro["jwksUri"] = u }
                    let r = try OidcJwks(ro, fetch: { fetches += 1; return try f($0) }, now: { clock })
                    var steps: [JSONValue] = []
                    for st in s["steps"]?.asArray ?? [] {
                        clock = IV.num(st.get("atMs")) ?? 0
                        do { steps.append(.object(["ok": Self.pick(try r.resolveJwk(st.get("header")?.asObject ?? [:]))])) } catch { steps.append(Self.errKind(error)) }
                    }
                    return .object(["steps": .array(steps), "fetches": .int(Int64(fetches))])
                }
            case "createOidcJwksFromIssuer":
                got = Ref.v {
                    let s = a0?.asObject ?? [:]
                    var urls: [String] = []
                    let r = try PCAOidc.createOidcJwksFromIssuer(s["issuer"], s["opts"]?.asObject ?? [:], fetch: Self.fetch(s["fetch"]) { urls.append($0) })
                    let out: JSONValue
                    do { out = .object(["ok": Self.pick(try r.resolveJwk(s["header"]?.asObject ?? [:]))]) } catch { out = Self.errKind(error) }
                    return .object(["out": out, "urls": .array(urls.map { .string($0) })])
                }
            case "oidcPrincipal":
                got = Ref.v { try PCAOidc.oidcPrincipal(a0, c.args.count > 1 ? (a1 ?? .null) : nil) }
            case "isOidcSubjectCaveat":
                got = .value(.bool(PCAOidc.isOidcSubjectCaveat(a0)))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(600)
    }
}
