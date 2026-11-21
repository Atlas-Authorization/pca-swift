import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the web request guard (PCAFetch): the construction guards and the pre-verification refusals (no, undecodable or
/// malformed proof, unknown grant, a grant resolver that throws). The verifier's own reason text and challenge string belong to the core
/// guard and differ per language, so only their shape is compared (status, decision, challenge prefix, content type, body members).
final class RefFetchTests: XCTestCase {
    static let aud = "rs_fetch"

    static func options(_ audience: String, signatureOnly: Bool, resolve: @escaping (String) throws -> JSONValue?) -> PCAFetch.Options {
        PCAFetch.Options(config: PcaGuardConfig(audience: audience, resolveGrant: resolve, signatureOnly: signatureOnly), insecureAllowUnboundOperation: signatureOnly)
    }

    func testFetchGuardAgainstTheReference() throws {
        try K042.requireCovers(["Fetch", "PcaGuard"])
        let d = Base.Diffs()
        try Base.each("ref-fetch.json.gz") { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "constructScenario":
                    let kind = a[0].asString
                    let o = Self.options(kind == "noaudience" ? "" : Self.aud, signatureOnly: kind != "nooperation") { _ in nil }
                    _ = try PCAFetch.withPCA(o) { _, _ in PCAFetch.Response(status: 200) }
                    return .object(["built": .bool(true)])
                case "requestScenario":
                    let spec = a[0]
                    let throwing = spec.get("resolve")?.asString == "throws"
                    let o = Self.options(Self.aud, signatureOnly: true) { _ in if throwing { throw JSError("store down") }; return nil }
                    var headers: [String: String] = [:]
                    for (k, v) in spec.get("headers")?.asObject ?? [:] { headers[k.s] = v.asString ?? "" }
                    let req = PCAFetch.Request(method: "POST", url: "http://localhost/refunds", headers: headers, body: Array((spec.get("body")?.asString ?? "").utf8))
                    switch try PCAFetch.createGuard(o)(req) {
                    case .allow: return Self.shape(PCAFetch.Response(status: 200, headers: ["content-type": "application/json"], body: Array(#"{"ok":true}"#.utf8)), true)
                    case let .deny(res): return Self.shape(res, false)
                    }
                default: throw JSError("not mapped")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(50)
    }

    static func shape(_ res: PCAFetch.Response, _ ran: Bool) -> JSONValue {
        var body: JSONValue?
        if case let .object(o)? = try? StrictJSON.parse(String(decoding: res.body, as: UTF8.self)) { body = .object(o) }
        let www = res.header("www-authenticate")
        return .object([
            "status": .int(Int64(res.status)), "handlerRan": .bool(ran), "decision": body?.get("decision") ?? .null,
            "challenge": res.status == 401 ? .bool(www?.hasPrefix("PCA realm=\"") ?? false) : .null,
            "contentType": res.header("content-type").map { .string($0) } ?? .null,
            "bodyKeys": body.map { b in .array((b.asObject ?? [:]).keys.map { $0.s }.sorted().map { .string($0) }) } ?? .null,
            "errorIsString": .bool(body?.get("error")?.asString != nil)])
    }
}
