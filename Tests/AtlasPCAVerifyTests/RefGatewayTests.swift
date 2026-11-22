import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAGateway (canonical query and request binding, path ambiguity, replay guard, provenance log, presented
/// artifacts, signature-only authorize over real signed proofs, the Envoy HTTP / gRPC shapes and the Lambda authorizers) against the
/// reference. Verdict objects are not compared (the native lists its own check names): `x-pca-verdict` / `pcaVerdict` print "<verdict>"
/// and the strict-JSON parser's own message prints "<json>", on both sides. The proofs are minted in the corpus; no key material.
final class RefGatewayTests: XCTestCase {
    static let file = "ref-gateway.json.gz"
    typealias G = PCAGateway

    static func mask(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .string(s):
            let marker = "undecodable PCA-Action header: "
            guard let r = s.range(of: marker) else { return v }
            let rest = s[r.upperBound...]
            return rest.hasPrefix("PCA-Action header") ? v : .string(String(s[..<r.upperBound]) + "<json>")
        case let .array(a): return .array(a.map(mask))
        case let .object(o):
            var out = JObject()
            for (k, x) in o {
                if (k.s == "x-pca-verdict" || k.s == "pcaVerdict"), let s = x.asString, !s.isEmpty { out[k] = .string("<verdict>") } else { out[k] = mask(x) }
            }
            if let h = out[JKey("header")]?.asObject, h[JKey("key")]?.asString == "x-pca-verdict", h[JKey("value")]?.asString != "" {
                var hh = h
                hh[JKey("value")] = .string("<verdict>")
                out[JKey("header")] = .object(hh)
            }
            return .object(out)
        default: return v
        }
    }

    static func headers(_ v: JSONValue?) -> G.HeaderMap? {
        guard let o = v?.asObject else { return v == nil ? [] : nil }
        var out: G.HeaderMap = []
        for k in o.keys.sorted(by: { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }) {
            switch o[k]! {
            case let .string(s): out.append((k.s, .one(s)))
            case let .array(a): guard a.allSatisfy({ $0.asString != nil }) else { return nil }; out.append((k.s, .many(a.compactMap { $0.asString })))
            default: return nil
            }
        }
        return out
    }

    static func request(_ v: JSONValue?) -> G.GatewayRequest? {
        guard let o = v?.asObject, let m = o[JKey("method")]?.asString, let p = o[JKey("path")]?.asString, let h = headers(o[JKey("headers")]) else { return nil }
        for k in ["query", "authority", "bodySha256", "body"] { if let x = o[JKey(k)], x.asString == nil { return nil } }
        return G.GatewayRequest(method: m, path: p, query: o[JKey("query")]?.asString, authority: o[JKey("authority")]?.asString, bodySha256: o[JKey("bodySha256")]?.asString,
                                body: o[JKey("body")]?.asString, headers: h)
    }

    static func bindOptions(_ v: JSONValue?) -> G.BindRequestOptions? {
        guard let v = v, !v.isNull else { return G.BindRequestOptions() }
        guard let o = v.asObject else { return nil }
        var b = G.BindRequestOptions()
        b.authority = JS.truthy(o[JKey("authority")])
        switch o[JKey("body")] {
        case .bool(true)?: b.body = .on
        case .bool(false)?, .null?: b.body = .off
        case nil: b.body = .auto
        default: return nil
        }
        return b
    }

    static func provObs(_ v: JSONValue?) -> G.ProvObservation { G.ProvObservation(origin: v?.get("origin"), source: v?.get("source")) }
    static func obsJSON(_ o: G.ProvObservation) -> JSONValue {
        var m = JObject()
        if let x = o.origin { m["origin"] = x }
        if let x = o.source { m["source"] = x }
        return .object(m)
    }

    static func presentedJSON(_ p: G.Presented) -> JSONValue {
        switch p { case .absent: return .object(["undef": .bool(true)]); case let .value(v): return v }
    }

    static func replayScenario(_ spec: JSONValue) -> JSONValue {
        final class Clock { var t = 0.0 }
        let clock = Clock()
        clock.t = IV.num(spec.get("clock")) ?? 0
        let g = G.memoryReplayGuard(Int(IV.num(spec.get("max")) ?? 0), now: { clock.t })
        var out: [JSONValue] = []
        for op in spec.get("ops")?.asArray ?? [] {
            if let t = IV.num(op.get("setClock")) { clock.t = t; continue }
            do { out.append(.bool(try g.claim(op.get("key")?.asString ?? "", expiresAtMs: IV.num(op.get("exp")) ?? 0, nowMs: IV.num(op.get("now"))))) }
            catch { out.append(.object(["threw": .string(G.errMessage(error))])) }
        }
        return .array(out)
    }

    static func provenanceScenario(_ spec: JSONValue) -> JSONValue {
        let l = G.MemoryProvenanceLog(maxSessions: Int(IV.num(spec.get("max")) ?? 0))
        var out: [JSONValue] = []
        for op in spec.get("ops")?.asArray ?? [] {
            let s = op.get("session")?.asString ?? ""
            if op.get("add") != nil { l.add(s, provObs(op.get("o"))); out.append(.string("added")) } else { out.append(.array(l.seen(s).map(obsJSON))) }
        }
        return .array(out)
    }

    // MARK: gateway options

    static func options(_ spec: JSONValue) -> G.GatewayOptions? {
        let clockNow = Int64(IV.num(spec.get("now")) ?? 0)
        let grants = spec.get("grants")?.asObject ?? [:]
        guard let aud = spec.get("audience")?.asString, let routesV = spec.get("routes")?.asArray else { return nil }
        var routes: [G.RouteRule] = []
        for r in routesV {
            guard let p = r.get("path")?.asString, let cap = r.get("capability"), let verb = cap.get("verb")?.asString else { return nil }
            routes.append(G.RouteRule(method: r.get("method")?.asString, path: p, capability: G.RequiredCapability(verb: verb, resource: cap.get("resource")?.asString)))
        }
        var policy: G.Policy?
        switch spec.get("policy")?.asString {
        case "sig"?: policy = .signatureOnly
        case "none"?: policy = nil
        case "full-missing"?: policy = .full(G.FullPolicy(params: .body, input: PCA.AuthorizeInput()))
        default: return nil
        }
        var o = G.GatewayOptions(audience: aud, routes: routes, resolveGrant: { ref, _ in grants[JKey(ref)] }, policy: policy)
        o.now = { clockNow }
        switch spec.get("bindRequest") {
        case .string("off")?: o.bindRequestOff = true
        case let b?: guard let bo = bindOptions(b) else { return nil }; o.bindRequest = bo
        case nil: break
        }
        if let u = spec.get("unmatched")?.asString { o.unmatchedRoute = u }
        if let p = spec.get("pathPolicy")?.asString { o.pathPolicy = p }
        if let rc = spec.get("requireChecks") { guard let l = RefConnectTests.strings(rc) else { return nil }; o.requireChecks = l }
        o.realm = spec.get("realm")?.asString
        o.insecureSkipPlanRootCheck = spec.get("skipPlan") == .bool(true)
        if let pr = spec.get("planRoots") { guard let l = RefConnectTests.strings(pr) else { return nil }; o.authorizedPlanRoots = l }
        switch spec.get("replay")?.asString {
        case "always"?: o.replayGuard = Scripted { _ in true }
        case "false"?: o.replayGuard = Scripted { _ in false }
        case "throws"?: o.replayGuard = Scripted { _ in throw JSError("store down") }
        case "memory"?: o.replayGuard = G.memoryReplayGuard(100_000, now: { Double(clockNow) })
        case "memory-full"?: o.replayGuard = G.memoryReplayGuard(1, now: { Double(clockNow) })
        default: break
        }
        switch spec.get("revocation")?.asString {
        case "ok"?: o.revocation = { _, _, _ in .enforced(ok: true, reason: nil) }
        case "revoked"?: o.revocation = { _, _, _ in .enforced(ok: false, reason: "grant revoked") }
        case "revoked-noreason"?: o.revocation = { _, _, _ in .enforced(ok: false, reason: nil) }
        case "notEnforced"?: o.revocation = { _, _, _ in .notEnforced }
        case "throws"?: o.revocation = { _, _, _ in throw JSError("rev down") }
        default: break
        }
        switch spec.get("checkProof")?.asString {
        case "true"?, "obj-true"?: o.checkProof = { _ in (true, nil) }
        case "false"?, "obj-false"?: o.checkProof = { _ in (false, nil) }
        case "obj-false-reason"?: o.checkProof = { _ in (false, "over limit") }
        case "throws"?: o.checkProof = { _ in throw JSError("policy down") }
        default: break
        }
        return o
    }

    /// A replay guard scripted by a closure.
    final class Scripted: G.ReplayGuard {
        let f: (String) throws -> Bool
        init(_ f: @escaping (String) throws -> Bool) { self.f = f }
        func claim(_ key: String, expiresAtMs: Double, nowMs: Double?) throws -> Bool { try f(key) }
    }

    static func projection(_ d: G.Decision) -> JSONValue {
        var h = JObject()
        for (k, v) in d.headers { h[JKey(k)] = .string(v) }
        var o: JObject = ["allow": .bool(d.allow), "status": .int(Int64(d.status)), "code": .string(d.code.rawValue), "reason": .string(d.reason), "headers": .object(h)]
        if let m = d.matched { o["matched"] = m.json }
        if let g = d.pcactn?.get("grant_ref") { o["grant"] = g }
        if let v = d.verdict { o["verdictAllow"] = .bool(v.allow) }
        return mask(.object(o))
    }

    static func authorizeScenario(_ spec: JSONValue) -> JSONValue? {
        guard let o = options(spec) else { return nil }
        let gw: (G.GatewayRequest) throws -> G.Decision
        do { gw = try G.createGateway(o) } catch { return .object(["create": .string(G.errMessage(error))]) }
        var out: [JSONValue] = []
        for r in spec.get("requests")?.asArray ?? [] {
            guard let req = request(r) else { return nil }
            do { out.append(projection(try gw(req))) } catch { out.append(.object(["threw": .string(G.errMessage(error))])) }
        }
        return .array(out)
    }

    // MARK: adapters

    static func stringHeaders(_ v: JSONValue?) -> [String: String]? {
        guard let o = v?.asObject, o.values.allSatisfy({ $0.asString != nil }) else { return v == nil ? [:] : nil }
        return Dictionary(uniqueKeysWithValues: o.map { ($0.key.s, $0.value.asString!) })
    }

    static func envoyEvent(_ e: JSONValue) -> G.EnvoyHttpCheckRequest? {
        guard let h = stringHeaders(e.get("headers")) else { return nil }
        for k in ["method", "path", "authority", "body"] { if let x = e.get(k), x.asString == nil { return nil } }
        return G.EnvoyHttpCheckRequest(method: e.get("method")?.asString, path: e.get("path")?.asString, authority: e.get("authority")?.asString, headers: h, body: e.get("body")?.asString)
    }

    static func grpcOptions(_ o: [G.EnvoyGrpcHeaderValueOption]) -> JSONValue {
        .array(o.map { .object(["header": .object(["key": .string($0.key), "value": .string($0.value)]), "appendAction": .int(Int64($0.appendAction))]) })
    }

    static func grpcOut(_ r: G.EnvoyGrpcCheckResponse) -> JSONValue {
        var o: JObject = ["status": .object(["code": .int(Int64(r.code)), "message": .string(r.message)])]
        if let h = r.okHeaders, let rm = r.okHeadersToRemove { o["okResponse"] = .object(["headers": grpcOptions(h), "headersToRemove": .array(rm.map { .string($0) })]) }
        if let st = r.deniedStatus, let h = r.deniedHeaders, let b = r.deniedBody {
            o["deniedResponse"] = .object(["status": .object(["code": .int(Int64(st))]), "headers": grpcOptions(h), "body": .string(b)])
        }
        return mask(.object(o))
    }

    static func lambdaEvent(_ e: JSONValue) -> G.LambdaEvent? {
        guard e.isObject, let h = headers(e.get("headers")) else { return nil }
        var ev = G.LambdaEvent()
        ev.headers = h
        for k in ["methodArn", "routeArn", "httpMethod", "path", "rawPath", "rawQueryString"] { if let x = e.get(k), x.asString == nil { return nil } }
        ev.methodArn = e.get("methodArn")?.asString
        ev.routeArn = e.get("routeArn")?.asString
        ev.httpMethod = e.get("httpMethod")?.asString
        ev.path = e.get("path")?.asString
        ev.rawPath = e.get("rawPath")?.asString
        ev.rawQueryString = e.get("rawQueryString")?.asString
        ev.contextHttpMethod = e.get("requestContext")?.get("http")?.get("method")?.asString
        ev.contextHttpPath = e.get("requestContext")?.get("http")?.get("path")?.asString
        ev.queryStringParameters = e.get("queryStringParameters")
        ev.multiValueQueryStringParameters = e.get("multiValueQueryStringParameters")
        return ev
    }

    static func scenarioOptions(_ s: JSONValue) -> G.GatewayOptions? { options(s) }

    func testGateway() throws {
        try K042.requireCovers(["Gateway"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "canonicalQuery":
                let q = c.arg(0)
                if let qv = q, !qv.isNull, qv.asString == nil { d.skip("canonicalQuery: untyped"); return }
                got = Base.run {
                    if q == .null { throw JSError("Cannot read properties of null (reading 'startsWith')") } // the reference calls `q.startsWith` on what it was given
                    return .string(try G.canonicalQuery(q?.asString))
                }
            case "requestBinding":
                guard let r = c.arg(0), let req = Self.request(.object(r.asObject?.merging([JKey("headers"): .object([:])]) { a, _ in a } ?? [:])), let bo = Self.bindOptions(c.arg(1)) else { d.skip("requestBinding: untyped"); return }
                got = Base.run { .object(try G.requestBinding(req, bo)) }
            case "bindParams":
                guard let p = c.arg(0)?.asObject else { d.skip("bindParams: untyped"); return }
                let b = c.arg(1)
                if let bv = b, !bv.isNull, !bv.isObject { d.skip("bindParams: untyped"); return }
                got = Base.run { .object(try G.bindParams(p, b?.asObject)) }
            case "ambiguousPathReason":
                guard let p = c.arg(0)?.asString else { d.skip("ambiguousPathReason: untyped"); return }
                got = .value(G.ambiguousPathReason(p).map { .string($0) } ?? .null)
            case "replayScenario": got = .value(Self.replayScenario(c.arg(0) ?? .null))
            case "provenanceLogScenario": got = .value(Self.provenanceScenario(c.arg(0) ?? .null))
            case "presentedProvenance", "presentedArtifacts":
                guard let r = c.arg(0), let kind = c.arg(1)?.asString, let req = Self.request(.object(["method": .string("POST"), "path": .string("/")].merging(r.asObject ?? [:]) { _, b in b })) else { d.skip("\(c.fn): untyped"); return }
                let src: G.ParamsSource = kind == "body" ? .body : .fn { _ in [:] }
                if c.fn == "presentedProvenance" { got = .value(Self.presentedJSON(G.presentedProvenance(req, src))) } else {
                    let a = G.presentedArtifacts(req, src)
                    var o = JObject()
                    if let x = a.discharges { o["discharges"] = .array(x) }
                    if let x = a.narrow { o["narrow"] = x }
                    got = .value(.object(o))
                }
            case "authorizeScenario":
                guard let g = Self.authorizeScenario(c.arg(0) ?? .null) else { d.skip("authorizeScenario: untyped"); return }
                got = .value(g)
            case "envoyScenario", "grpcScenario", "lambdaScenario", "lambdaSimpleScenario":
                guard let spec = c.arg(0), let opts = Self.scenarioOptions(spec), let ev = spec.get("events")?.asArray?.first else { d.skip("\(c.fn): untyped"); return }
                got = .value(Self.adapter(c.fn, opts, ev) ?? .null)
                if case .value(.null) = got { d.skip("\(c.fn): untyped event"); return }
            default: d.skip("\(c.fn): not mapped"); return
            }
            let w = Self.mask(c.out)
            if case let .value(v) = got { d.add(c, Base.canon(Self.mask(v)) == Base.canon(w) ? nil : "\(c.name): want \(Base.firstDiff(w, v, "@")) || want \(Base.canon(w).prefix(300)) got \(Base.canon(v).prefix(300))") } else { d.add(c, Base.diff(c, got)) }
        }
        d.finish(380)
    }

    static func adapter(_ fn: String, _ opts: G.GatewayOptions, _ ev: JSONValue) -> JSONValue? {
        do {
            switch fn {
            case "envoyScenario":
                guard let e = envoyEvent(ev) else { return nil }
                let r = try G.envoyExtAuthz(opts)(e)
                var h = JObject()
                for (k, v) in r.headers { h[JKey(k)] = .string(v) }
                return mask(.object(["status": .int(Int64(r.status)), "headers": .object(h), "body": .string(r.body)]))
            case "grpcScenario":
                let http = ev.get("attributes")?.get("request")?.get("http")
                var g: G.EnvoyGrpcHttp?
                if let h = http {
                    guard let hs = stringHeaders(h.get("headers")) else { return nil }
                    g = G.EnvoyGrpcHttp(method: h.get("method")?.asString, path: h.get("path")?.asString, host: h.get("host")?.asString, headers: hs, body: h.get("body")?.asString)
                }
                return grpcOut(try G.envoyGrpcExtAuthz(opts)(g))
            default:
                guard let e = lambdaEvent(ev) else { return nil }
                if fn == "lambdaScenario" {
                    let r = try G.lambdaAuthorizer(opts)(e)
                    var ctx = JObject()
                    for (k, v) in r.context { ctx[JKey(k)] = .string(v) }
                    return mask(.object(["principalId": r.principalId, "policyDocument": .object(["Version": .string("2012-10-17"), "Statement": .array([.object(["Action": .string("execute-api:Invoke"), "Effect": .string(r.effect), "Resource": .string(r.resource)])])]), "context": .object(ctx)]))
                }
                let r = try G.lambdaSimpleAuthorizer(opts)(e)
                var ctx = JObject()
                for (k, v) in r.context { ctx[JKey(k)] = .string(v) }
                return mask(.object(["isAuthorized": .bool(r.isAuthorized), "context": .object(ctx)]))
            }
        } catch {
            return mask(.object(["create": .string(G.errMessage(error))]))
        }
    }
}
