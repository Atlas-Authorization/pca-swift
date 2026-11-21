import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the gateway's Cloudflare Worker adapter against the reference: the decision, the strip of inbound `x-pca-*` headers
/// before the upstream, the deny JSON and the forged-header 400, over injected `next` / `respond`. The request is {method, url, headers}.
final class RefGatewayWorkerTests: XCTestCase {
    static let file = "ref-gateway-worker.json.gz"
    typealias G = PCAGateway

    static func headerObject(_ h: [String: String]) -> JSONValue {
        var o = JObject()
        for (k, v) in h { o[JKey(k.lowercased())] = .string(v) }
        return .object(o)
    }

    static func scenario(_ spec: JSONValue) -> JSONValue? {
        guard let opts = RefGatewayTests.scenarioOptions(spec), let ev = spec.get("events")?.asArray?.first,
              let method = ev.get("method")?.asString, let url = ev.get("url")?.asString, let hv = ev.get("headers") else { return nil }
        guard let hs = RefGatewayTests.stringHeaders(hv) else { return nil }
        var rewrite: G.WorkerRewrite = .standard
        switch ev.get("rewrite")?.asString {
        case "null"?: rewrite = .none
        case "custom"?:
            rewrite = .custom { r, drop in
                var c = r
                c.headers = r.headers.filter { !drop.contains($0.key.lowercased()) }
                c.headers["x-rewritten"] = drop.joined(separator: ",")
                return c
            }
        default: break
        }
        let w: (G.WorkerRequest) throws -> JSONValue
        do {
            w = try G.cloudflareWorker(opts,
                next: { r in .object(["forwarded": .object(["method": .string(r.method), "url": .string(r.url), "headers": headerObject(r.headers)])]) },
                respond: { body, status, headers in
                    var h = JObject()
                    for (k, v) in headers { h[JKey(k)] = .string(v) }
                    return .object(["status": .int(Int64(status)), "headers": .object(h), "body": (try? StrictJSON.parse(body)) ?? .null])
                },
                rewrite: rewrite)
        } catch { return .object(["create": .string(G.errMessage(error))]) }
        do { return RefGatewayTests.mask(try w(G.WorkerRequest(method: method, url: url, headers: hs))) } catch { return .object(["threw": .string(G.errMessage(error))]) }
    }

    func testGatewayWorker() throws {
        try K042.requireCovers(["GatewayWorker"])
        let d = Base.Diffs()
        let n = try Base.each(Self.file) { c in
            guard c.fn == "workerScenario", let spec = c.arg(0), let got = Self.scenario(spec) else { d.skip("\(c.fn): untyped"); return }
            let w = RefGatewayTests.mask(c.out)
            d.add(c, Base.canon(got) == Base.canon(w) ? nil : "\(c.name): want \(Base.firstDiff(w, got, "@")) || want \(Base.canon(w).prefix(300)) got \(Base.canon(got).prefix(300))")
        }
        XCTAssertEqual(n, 22)
        d.finish(22)
    }
}
