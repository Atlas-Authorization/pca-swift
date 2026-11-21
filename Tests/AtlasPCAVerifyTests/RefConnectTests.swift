import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAConnect (oauth_scope caveats, the request extractor, proxy headers, signed release receipts, token refresh,
/// the envelope-encrypted store and the TokenVault release / proxy scenarios) against the reference. The corpus carries no key material:
/// signing seeds and key-ring keys appear as "$seed:<label>" and are derived here (sha256 of "atlas-pca-conformance/<label>").
/// Member order is not kept by the JSON model, so the refresh form body is compared as a sorted list of its pairs.
final class RefConnectTests: XCTestCase {
    static let file = "ref-connect-v2.json.gz"
    typealias C = PCAConnect

    static func seed(_ v: JSONValue?) -> [UInt8]? {
        // the corpus writes a seeded key as {"$seed": label}
        if let l = v?.get("$seed")?.asString { return Canonical.sha256(Array("atlas-pca-conformance/\(l)".utf8)) }
        guard let s = v?.asString else { return nil }
        if s.hasPrefix("$seed:") { return Canonical.sha256(Array("atlas-pca-conformance/\(s.dropFirst(6))".utf8)) }
        return nil
    }

    static func pairs(_ v: JSONValue?) -> [(String, String)] {
        (v?.asObject ?? [:]).keys.sorted { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }.map { ($0.s, v?.get($0.s)?.asString ?? "") }
    }

    static func obj(_ p: [(String, String)]) -> JSONValue {
        var o = JObject()
        for (k, v) in p { o[JKey(k)] = .string(v) }
        return .object(o)
    }

    static func strings(_ v: JSONValue?) -> [String]? { v?.asArray.flatMap { $0.allSatisfy { $0.asString != nil } ? $0.compactMap { $0.asString } : nil } }

    static func errOut(_ e: Error) -> JSONValue {
        guard let v = e as? C.VaultError else { return .object(["ok": .bool(false), "name": .string("Error")]) }
        var o: JObject = ["ok": .bool(false), "name": .string(v.name), "code": .string(v.code)]
        if v.code != "not_authorized" { o["message"] = .string(v.message) }
        if let s = v.status { o["status"] = .int(Int64(s)) }
        if let m = v.missing { o["missing"] = .array(m.map { .string($0) }) }
        return .object(o)
    }

    static func extractorSpec(_ v: JSONValue?) -> C.HttpRequestSpec? {
        guard let o = v?.asObject, let m = o[JKey("method")]?.asString, let u = o[JKey("url")]?.asString else { return nil }
        var q: [String] = []
        if let qv = o[JKey("query")] { guard let s = strings(qv) else { return nil }; q = s }
        var body: String?
        if let b = o[JKey("body")] { guard let s = b.asString else { return nil }; body = s }
        var fixed = JObject()
        if let f = o[JKey("fixed")] { guard let fo = f.asObject else { return nil }; fixed = fo }
        return C.HttpRequestSpec(method: m, url: u, query: q, body: body, fixed: fixed)
    }

    static func request(_ v: JSONValue?) -> C.ProxyRequest? {
        guard let o = v?.asObject, let m = o[JKey("method")]?.asString, let u = o[JKey("url")]?.asString else { return nil }
        var headers: [(String, String)] = []
        if let h = o[JKey("headers")] {
            guard let ho = h.asObject, ho.values.allSatisfy({ $0.asString != nil }) else { return nil }
            headers = pairs(h)
        }
        var body: String?
        if let b = o[JKey("body")] { guard let s = b.asString else { return nil }; body = s }
        return C.ProxyRequest(method: m, url: u, headers: headers, body: body)
    }

    static func connection(_ v: JSONValue?) -> C.StoredConnection? {
        guard let o = v?.asObject, let agent = o[JKey("agentId")]?.asString, let prov = o[JKey("provider")]?.asString, let id = o[JKey("connectionId")]?.asString,
              let at = o[JKey("accessToken")]?.asString, let exp = IV.num(o[JKey("expiresAt")]), let scopes = strings(o[JKey("scopes")]), let a = o[JKey("authority")],
              let ap = a.get("provider")?.asString, let pr = a.get("principal")?.asString, let asc = strings(a.get("scopes")), let created = IV.num(o[JKey("createdAt")]) else { return nil }
        return C.StoredConnection(agentId: agent, provider: prov, connectionId: id, accessToken: at, refreshToken: o[JKey("refreshToken")]?.asString, expiresAt: exp, scopes: scopes,
                                  authority: C.ConnectionAuthority(provider: ap, principal: pr, scopes: asc, audience: a.get("audience")?.asString), createdAt: created,
                                  lastUsedAt: IV.num(o[JKey("lastUsedAt")]), useCount: Int(IV.num(o[JKey("useCount")]) ?? 0))
    }

    static func providerConfig(_ v: JSONValue?) -> C.ProviderConfig? {
        guard let o = v?.asObject, let ep = o[JKey("tokenEndpoint")]?.asString, let cid = o[JKey("clientId")]?.asString else { return nil }
        return C.ProviderConfig(tokenEndpoint: ep, clientId: cid, clientSecret: o[JKey("clientSecret")]?.asString, supportsScopeNarrowing: o[JKey("supportsScopeNarrowing")] == .bool(true),
                                extraParams: pairs(o[JKey("extraParams")]))
    }

    /// A scripted transport: each call is logged, then answered by the next script element (the last one repeats).
    final class Transport {
        var log: [JSONValue] = []
        var i = 0
        let script: [JSONValue]
        init(_ s: [JSONValue]) { script = s }
        func fetch(_ url: String, _ req: C.VaultHttpRequest) throws -> C.VaultHttpResponse {
            var h = JObject()
            for (k, v) in req.headers { h[JKey(k)] = .string(v) }
            log.append(.object(["url": .string(url), "method": .string(req.method), "headers": .object(h), "body": .string(req.body)]))
            guard !script.isEmpty else { throw JSError("empty script") }
            let r = script[min(i, script.count - 1)]
            i += 1
            if let t = r.get("throws")?.asString { throw JSError(t) }
            return C.VaultHttpResponse(ok: r.get("ok") == .bool(true), status: Int(IV.num(r.get("status")) ?? 0),
                                       json: { if r.get("jsonThrows") == .bool(true) { throw JSError("bad json") }; return r.get("json") ?? .null },
                                       text: { if r.get("textThrows") == .bool(true) { throw JSError("bad text") }; return r.get("text")?.asString ?? "" })
        }
    }

    static func fetchFn(_ t: Transport?) -> C.VaultFetch? {
        guard let t = t else { return nil }
        return { (url: String, req: C.VaultHttpRequest) throws -> C.VaultHttpResponse in try t.fetch(url, req) }
    }

    static func refresh(_ c: JSONValue) -> JSONValue {
        let script = c.get("script")?.asArray
        let t = script.map { Transport($0) }
        var out: JObject
        do {
            guard let conn = connection(c.get("connection")), let rt = c.get("refreshToken")?.asString, let req = strings(c.get("requested")), let now = IV.num(c.get("now")),
                  let life = IV.num(c.get("defaultTokenLifetimeMs")) else { throw C.ConnectError("case") }
            let r = try C.refreshConnection(connection: conn, config: providerConfig(c.get("config")), refreshToken: rt, requested: req, fetch: fetchFn(t), now: now, defaultTokenLifetimeMs: life)
            out = ["ok": .bool(true), "value": .object(["accessToken": .string(r.accessToken), "refreshToken": .string(r.refreshToken), "expiresAt": PCASandbox.num(r.expiresAt), "scopes": .array(r.scopes.map { .string($0) })])]
        } catch {
            out = errOut(error).asObject ?? [:]
        }
        out["calls"] = .array(t?.log ?? [])
        return .object(out)
    }

    static func decrypt(_ c: JSONValue) -> JSONValue {
        do {
            var ring: [String: [UInt8]] = [:]
            for (k, v) in c.get("ring")?.asObject ?? [:] { guard let s = seed(v) else { throw C.ConnectError("ring") }; ring[k.s] = s }
            guard let active = c.get("active")?.asString, let rec = connection(c.get("record")), let k = c.get("key"), let a = k.get("agentId")?.asString, let p = k.get("provider")?.asString,
                  let id = k.get("connectionId")?.asString else { throw C.ConnectError("case") }
            let inner = C.InMemoryConnectionStore()
            try inner.set(rec)
            let store = C.EncryptedConnectionStore(inner: inner, wrapper: try C.LocalKeyWrapper(keys: ring, activeId: active))
            return .object(["ok": .bool(true), "value": try store.get(C.ConnectionKey(agentId: a, provider: p, connectionId: id))?.json ?? .null])
        } catch { return errOut(error) }
    }

    // MARK: vault

    final class Clock { var v: Int64 = 0 }

    static func vault(_ s: JSONValue) -> JSONValue {
        let clock = Clock()
        clock.v = Int64(IV.num(s.get("nowMs")) ?? 0)
        let op = s.get("opts") ?? .object([:])
        let store = C.InMemoryConnectionStore()
        let fetchT = s.get("fetchScript")?.asArray.map { Transport($0) }
        var proxyLog: [JSONValue] = [], receipts: [JSONValue] = []
        var pi = 0
        var o = C.VaultOptions()
        o.strict = false
        o.store = store
        o.now = { clock.v }
        o.fetch = fetchFn(fetchT)
        o.insecureBearerRelease = op.get("insecureBearerRelease") == .bool(true)
        o.insecureSkipPlanRootCheck = op.get("insecureSkipPlanRootCheck") == .bool(true)
        o.authorizedPlanRoots = strings(op.get("authorizedPlanRoots"))
        o.audience = op.get("audience")?.asString
        if let v = IV.num(op.get("expiryLeewayMs")) { o.expiryLeewayMs = v }
        if let v = IV.num(op.get("defaultTokenLifetimeMs")) { o.defaultTokenLifetimeMs = v }
        if let v = op.get("requireActionBinding") { o.requireActionBinding = v == .bool(true) }
        if let u = op.get("useVerb") { o.useVerb = u.asString }
        if let v = op.get("defaultConnectionId")?.asString { o.defaultConnectionId = v }
        for (k, v) in op.get("providers")?.asObject ?? [:] { if let cfg = providerConfig(v) { o.providers[k.s] = cfg } }
        if let pins = op.get("pqPins")?.asObject { o.pqPins = Dictionary(uniqueKeysWithValues: pins.compactMap { k, v in v.asString.map { (k.s, $0) } }) }
        if let v = IV.num(op.get("maxProxyResponseBytes")) { o.maxProxyResponseBytes = Int(v) }
        if op.get("replay") == .bool(true) { o.replay = C.InMemoryReplayStore() }
        if let r = op.get("revoked")?.asString { o.isRevoked = { _ in if r == "throws" { throw JSError("src down") }; return r == "yes" } }
        if let table = s.get("actionsTable")?.asObject {
            o.actions = { verb in
                guard let t = table[JKey(verb)], let tv = t.get("verb")?.asString, let up = t.get("upstream"), let prov = up.get("provider")?.asString, let min = strings(up.get("scopes_min")) else { return nil }
                var extract: ((C.ProxyRequest) throws -> JObject)?
                if let spec = t.get("extract") { extract = Self.extractorSpec(spec).flatMap { try? C.httpExtractor($0) } }
                return C.VaultAction(verb: tv, defDigest: t.get("def_digest")?.asString ?? "", confirmed: t.get("confirmed") == .bool(true), provider: prov, scopesMin: min, extract: extract)
            }
        }
        if op.get("proxy") == .bool(true) {
            let script = s.get("proxyScript")?.asArray ?? []
            o.proxyFetch = { req in
                proxyLog.append(.object(["method": .string(req.method), "url": .string(req.url), "headers": obj(req.headers.map { ($0.key, $0.value) }.sorted { $0.0 < $1.0 }), "body": Base.opt(req.body), "redirect": .string("manual")]))
                guard !script.isEmpty else { throw JSError("empty script") }
                let r = script[min(pi, script.count - 1)]
                pi += 1
                if r.get("throws") != nil { throw JSError("net") }
                return C.ProxyResponse(status: Int(IV.num(r.get("status")) ?? 0), headers: pairs(r.get("headers")), body: r.get("body")?.asString ?? "")
            }
        }
        if let rs = op.get("receiptSeed") {
            o.receiptKey = seed(rs)
            o.receiptSink = { r in receipts.append(r); if op.get("failingSink") == .bool(true) { throw JSError("sink") } }
        }
        var results: [JSONValue] = [], watched: [JSONValue] = []
        do {
            let vault = try C.TokenVault(o)
            for c in s.get("calls")?.asArray ?? [] {
                func rec(_ f: () throws -> JSONValue) { do { results.append(.object(["ok": .bool(true), "value": try f()])) } catch { results.append(errOut(error)) } }
                switch c.get("op")?.asString {
                case "put"?:
                    rec {
                        guard let a = c.get("args"), let agent = a.get("agentId")?.asString, let prov = a.get("provider")?.asString, let at = a.get("accessToken")?.asString, let exp = IV.num(a.get("expiresAt")),
                              let sc = strings(a.get("scopes")), let au = a.get("authority"), let pr = au.get("principal")?.asString else { throw C.ConnectError("put args") }
                        return try vault.putConnection(C.PutConnectionArgs(agentId: agent, provider: prov, connectionId: a.get("connectionId")?.asString, accessToken: at, refreshToken: a.get("refreshToken")?.asString,
                                                                           expiresAt: exp, scopes: sc, principal: pr, authorityScopes: strings(au.get("scopes")), audience: au.get("audience")?.asString)).json
                    }
                case "get"?:
                    rec {
                        guard let a = c.get("args"), let prov = a.get("provider")?.asString, let p = c.get("pcActn") else { throw C.ConnectError("get args") }
                        return try vault.getConnectionToken(p, C.GetConnectionTokenArgs(provider: prov, connectionId: a.get("connectionId")?.asString, scopes: strings(a.get("scopes")))).json
                    }
                case "proxy"?:
                    rec {
                        guard let a = c.get("args"), let prov = a.get("provider")?.asString, let p = c.get("pcActn"), let req = request(c.get("request")) else { throw C.ConnectError("proxy args") }
                        let r = try vault.proxyCall(p, req, C.ProxyCallArgs(provider: prov, connectionId: a.get("connectionId")?.asString))
                        var out: JObject = ["response": .object(["status": .int(Int64(r.response.status)), "headers": obj(r.response.headers), "body": .string(r.response.body)])]
                        if let rc = r.receipt { out["receipt"] = rc }
                        return .object(out)
                    }
                case "delete"?:
                    rec {
                        guard let agent = c.get("agentId")?.asString, let prov = c.get("provider")?.asString else { throw C.ConnectError("delete args") }
                        try vault.deleteConnection(agentId: agent, provider: prov, connectionId: c.get("connectionId")?.asString)
                        return .null
                    }
                case "now"?: clock.v = Int64(IV.num(c.get("now")) ?? 0)
                default: break
                }
            }
        } catch { results.append(errOut(error)) }
        for k in s.get("watch")?.asArray ?? [] {
            if let a = k.get("agentId")?.asString, let p = k.get("provider")?.asString, let id = k.get("connectionId")?.asString {
                watched.append((try? store.get(C.ConnectionKey(agentId: a, provider: p, connectionId: id)))?.json ?? .null)
            }
        }
        return .object(["results": .array(results), "store": .array(watched), "receipts": .array(receipts), "fetchCalls": .array(fetchT?.log ?? []), "proxyCalls": .array(proxyLog)])
    }

    /// A form body (member order of the reference's object is not kept): its `a=b` pairs sorted.
    static func normForm(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .object(o):
            var m = o.mapValues(normForm)
            if let b = o[JKey("body")]?.asString, (o[JKey("headers")]?.get("content-type")?.asString ?? "").contains("x-www-form-urlencoded") {
                m[JKey("body")] = .string(b.split(separator: "&", omittingEmptySubsequences: false).map(String.init).sorted().joined(separator: "&"))
            }
            return .object(m)
        case let .array(a): return .array(a.map(normForm))
        default: return v
        }
    }

    func testConnect() throws {
        try K042.requireCovers(["Connect"])
        let d = Base.Diffs()
        try Base.each(Self.file, seeds: true) { c in
            let got: BaseGot
            switch c.fn {
            case "oauthScopeCaveat":
                guard let p = c.arg(0)?.asString, let s = Self.strings(c.arg(1)) else { d.skip("oauthScopeCaveat: untyped args"); return }
                got = .value(C.oauthScopeCaveat(p, s))
            case "isOAuthScopeCaveat": got = .value(.bool(C.isOAuthScopeCaveat(c.arg(0))))
            case "grantedOAuthScopes":
                guard let p = c.arg(1)?.asString else { d.skip("grantedOAuthScopes: untyped provider"); return }
                if let g = C.grantedOAuthScopes(c.arg(0), p) { got = .value(.array(g.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }.map { .string($0) })) } else { got = .value(.null) }
            case "httpExtractor":
                guard let spec = Self.extractorSpec(c.arg(0)), let req = Self.request(c.arg(1)) else { d.skip("httpExtractor: untyped args"); return }
                got = Base.run({ ($0 as? C.VaultError)?.code }) { .object(try C.httpExtractor(spec)(req)) }
            case "checkProxyHeaders":
                guard let allow = Self.strings(c.arg(1)) else { d.skip("checkProxyHeaders: untyped allow"); return }
                let h = c.arg(0)
                if let ho = h?.asObject, ho.values.contains(where: { $0.asString == nil }) { got = .threw("request_mismatch"); break }
                got = Base.run({ ($0 as? C.VaultError)?.code }) { Self.obj(try C.checkProxyHeaders(Self.pairs(h), allow).map { ($0.key, $0.value) }.sorted { $0.0 < $1.0 }) }
            case "DEFAULT_PROXY_HEADERS": got = .value(.array(C.DEFAULT_PROXY_HEADERS.map { .string($0) }))
            case "outboundRequestDigest":
                guard let m = c.arg(0)?.asString, let u = c.arg(1)?.asString, c.arg(2)?.asObject?.values.allSatisfy({ $0.asString != nil }) == true else { d.skip("outboundRequestDigest: untyped args"); return }
                got = Base.run { .string(try C.outboundRequestDigest(method: m, url: u, headers: Dictionary(uniqueKeysWithValues: Self.pairs(c.arg(2))), body: c.arg(3)?.asString).unwrap()) }
            case "signReleaseReceipt":
                got = Base.run { guard let sd = Self.seed(c.arg(1)) else { throw C.ConnectError("seed") }; return try C.signReleaseReceipt(c.arg(0) ?? .null, seed: sd) }
            case "verifyReleaseReceipt":
                guard let pk = c.arg(1)?.asString else { d.skip("verifyReleaseReceipt: untyped key"); return }
                got = .value(.bool(C.verifyReleaseReceipt(c.arg(0), vaultPk: pk)))
            case "receiptActionDigest": got = Base.run { .string(try C.receiptActionDigest(c.arg(0) ?? .null).unwrap()) }
            case "refreshConnection":
                let g = Self.normForm(Self.refresh(IV.normalized(c.arg(0) ?? .null))), w = Self.normForm(c.out)
                d.add(c, Base.canon(g) == Base.canon(w) ? nil : "\(c.name): want \(Base.firstDiff(w, g, "@")) || want \(Base.canon(w).prefix(300)) got \(Base.canon(g).prefix(300))")
                return
            case "decryptRecord": got = .value(Self.decrypt(c.arg(0) ?? .null))
            case "vault":
                let g = Self.normForm(Self.vault(IV.normalized(c.arg(0) ?? .null))), w = Self.normForm(c.out)
                d.add(c, Base.canon(g) == Base.canon(w) ? nil : "\(c.name): want \(Base.firstDiff(w, g, "@")) || want \(Base.canon(w).prefix(300)) got \(Base.canon(g).prefix(300))")
                return
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(700)
    }

    /// The strict-mode constructor and the encrypting store round trip (not in the corpus).
    func testStrictVaultAndRoundTrip() throws {
        var o = C.VaultOptions()
        o.store = C.InMemoryConnectionStore()
        XCTAssertThrowsError(try C.TokenVault(o))
        let ring = try C.LocalKeyWrapper(keys: ["k1": Canonical.sha256(Array("a".utf8)), "k2": Canonical.sha256(Array("b".utf8))], activeId: "k1")
        let inner = C.InMemoryConnectionStore()
        let enc = C.EncryptedConnectionStore(inner: inner, wrapper: ring)
        let conn = C.StoredConnection(agentId: "a", provider: "google", connectionId: "default", accessToken: "AT", refreshToken: "RT", expiresAt: 5, scopes: ["r"],
                                      authority: C.ConnectionAuthority(provider: "google", principal: "p", scopes: ["r"]), createdAt: 1)
        try enc.set(conn)
        XCTAssertNotEqual(try inner.get(conn.key)?.accessToken, "AT")
        XCTAssertEqual(try enc.get(conn.key), conn)
        try ring.setActive("k2")
        XCTAssertTrue(try enc.reencrypt(conn.key))
        XCTAssertEqual(try enc.get(conn.key), conn)
        var plain = conn
        plain.accessToken = "plaintext"
        try inner.set(plain)
        XCTAssertThrowsError(try enc.get(conn.key))
    }
}

private extension Optional {
    func unwrap() throws -> Wrapped {
        guard let v = self else { throw PCAConnect.ConnectError("nil") }
        return v
    }
}
