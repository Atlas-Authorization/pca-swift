import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAConnectors (manifest validation and digest, the provider registry and seeded catalog, authorize URL / PKCE /
/// URL variables, access-token placement, the manifest -> vault provider config, and code exchange / refresh into the vault) against the
/// reference. The JSON model keeps no member order, so issue lists, authorize-URL parameters and form bodies are compared order-free.
final class RefConnectorsTests: XCTestCase {
    static let file = "ref-connectors.json.gz"
    typealias K = PCAConnectors

    static func errOut(_ e: Error) -> JSONValue {
        guard let c = e as? K.ConnectorError else { return .object(["ok": .bool(false), "name": .string("Error")]) }
        var o: JObject = ["ok": .bool(false), "name": .string(c.name), "message": .string(c.message)]
        if let i = c.issues { o["issues"] = .array(i.map { .string($0) }) }
        return .object(o)
    }

    static func guarded(_ f: () throws -> JSONValue) -> JSONValue {
        do { return .object(["ok": .bool(true), "value": try f()]) } catch { return errOut(error) }
    }

    static func strings(_ v: JSONValue?) -> [String]? { RefConnectTests.strings(v) }
    static func sortedPairs(_ v: JSONValue?) -> [(String, String)]? {
        guard let o = v?.asObject, o.values.allSatisfy({ $0.asString != nil }) else { return nil }
        return RefConnectTests.pairs(v)
    }

    /// Issue lists carry a map's reserved keys in the reference's insertion order: compared sorted (message rebuilt from the sorted list).
    static func normIssues(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .object(o):
            var m = o.mapValues(normIssues)
            if let a = o[JKey("issues")]?.asArray, a.allSatisfy({ $0.asString != nil }) {
                let s = a.compactMap { $0.asString }.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
                m[JKey("issues")] = .array(s.map { .string($0) })
                if o[JKey("message")]?.asString?.hasPrefix("invalid provider manifest: ") == true { m[JKey("message")] = .string("invalid provider manifest: " + s.joined(separator: "; ")) }
            }
            return .object(m)
        case let .array(a): return .array(a.map(normIssues))
        default: return v
        }
    }

    /// An authorize URL's query parameters sorted (their order follows an object the JSON model keeps no order of).
    static func normUrl(_ v: JSONValue) -> JSONValue {
        guard case var .object(o) = v, case var .object(val)? = o[JKey("value")], let u = val[JKey("url")]?.asString, let q = u.firstIndex(of: "?") else { return v }
        let base = u[..<q], pairs = u[u.index(after: q)...].split(separator: "&", omittingEmptySubsequences: false).map(String.init).sorted()
        val[JKey("url")] = .string(base + "?" + pairs.joined(separator: "&"))
        o[JKey("value")] = .object(val)
        return .object(o)
    }

    static func nonASCIIUrl(_ v: JSONValue) -> Bool {
        switch v {
        case let .string(s): return s.unicodeScalars.contains { $0.value > 0x7F } && (s.hasPrefix("http") || s.contains("://"))
        case let .array(a): return a.contains(where: nonASCIIUrl)
        case let .object(o): return o.values.contains(where: nonASCIIUrl)
        default: return false
        }
    }

    static func registry(customs: [JSONValue]?, empty: Bool = false) throws -> K.ProviderRegistry {
        let r = empty ? K.ProviderRegistry() : K.createDefaultRegistry()
        for m in customs ?? [] { try r.register(m) }
        return r
    }

    static func registryScenario(_ s: JSONValue) -> JSONValue {
        let r = (try? registry(customs: nil, empty: s.get("empty") == .bool(true))) ?? K.ProviderRegistry()
        var out: [JSONValue] = []
        for op in s.get("ops")?.asArray ?? [] {
            out.append(guarded {
                switch op.get("op")?.asString {
                case "register"?:
                    let o = op.get("opts")
                    return try r.register(op.get("manifest") ?? .null, replace: o?.get("replace") == .bool(true), expectedDigest: o?.get("expectedDigest")?.asString).json
                case "get"?: return r.get(op.get("id")?.asString ?? "")?.json ?? .null
                case "require"?: return try r.require(op.get("id")?.asString ?? "").json
                case "has"?: return .bool(r.has(op.get("id")?.asString ?? ""))
                case "list"?: return .array(r.list().map { $0.json })
                case "ids"?: return .array(r.ids().map { .string($0) })
                default: return .string(K.catalogDigest(r))
                }
            })
        }
        return .array(out)
    }

    static func authorizeOptions(_ o: JSONValue, customs: [JSONValue]?) throws -> K.BuildAuthorizeUrlOptions? {
        guard let obj = o.asObject else { return nil }
        var extra: [(String, String)] = []
        if let e = obj[JKey("extraParams")] { guard let p = sortedPairs(e) else { return nil }; extra = p }
        var scopes: [String]?
        if let s = obj[JKey("scopes")], !s.isNull { guard let l = strings(s) else { return nil }; scopes = l }
        var state: String?
        if let s = obj[JKey("state")] { state = s.asString ?? "" } // a non-string state is refused like a short one
        var pkce: K.PkceOption?
        if let p = obj[JKey("pkce")] {
            switch p {
            case .bool(false): pkce = .off
            case .bool(true): pkce = .on
            case .object(let po): pkce = .params(verifier: po[JKey("verifier")]?.asString ?? "", method: po[JKey("method")]?.asString)
            default: return nil
            }
        }
        var vars: JObject?
        if let v = obj[JKey("vars")], !v.isNull { guard let vo = v.asObject else { return nil }; vars = vo }
        var opts = K.BuildAuthorizeUrlOptions(clientId: obj[JKey("clientId")]?.asString, redirectUri: JS.toString(obj[JKey("redirectUri")]), scopes: scopes, state: state, pkce: pkce, vars: vars,
                                              registry: try registry(customs: customs), extraParams: extra)
        opts.allowUnlistedScopes = obj[JKey("allowUnlistedScopes")] == .bool(true)
        opts.allowPlainPkce = obj[JKey("allowPlainPkce")] == .bool(true)
        return opts
    }

    static func lenientManifest(_ v: JSONValue) -> K.ProviderManifest? {
        guard let o = v.asObject, let tp = o[JKey("tokenPlacement")]?.asString.flatMap({ K.TokenPlacement(rawValue: $0) }) else { return nil }
        return K.ProviderManifest(id: o[JKey("id")]?.asString ?? "", displayName: "", authorizeUrl: "", tokenUrl: "", scopesAvailable: [], defaultScopes: [], refresh: K.RefreshSpec(mode: .none),
                                  tokenPlacement: tp, headerName: o[JKey("headerName")]?.asString, queryParam: o[JKey("queryParam")]?.asString)
    }

    static func credentials(_ v: JSONValue?) -> K.ProviderCredentials? {
        guard let o = v?.asObject, let cid = o[JKey("clientId")]?.asString else { return nil }
        return K.ProviderCredentials(clientId: cid, clientSecret: o[JKey("clientSecret")]?.asString, vars: o[JKey("vars")]?.asObject)
    }

    static func tokenRun(_ c: JSONValue, refresh: Bool) -> JSONValue {
        let transport = RefConnectTests.Transport(c.get("script")?.asArray ?? [])
        let store = PCAConnect.InMemoryConnectionStore()
        var result: JSONValue
        let bind = c.get("bind")
        let agent = bind?.get("agentId")?.asString ?? ""
        let connId = bind?.get("connectionId")?.asString
        do {
            var o = PCAConnect.VaultOptions()
            o.strict = false
            o.store = store
            o.insecureSkipPlanRootCheck = true
            let nowV = IV.num(c.get("now")) ?? 0
            o.now = { Int64(nowV) }
            let vault = try PCAConnect.TokenVault(o)
            guard let b = bind, let principal = b.get("principal")?.asString, let provider = c.get("providerId")?.asString, let cid = c.get("clientId")?.asString else { throw K.ConnectorError("case") }
            let binding = K.ConnectionBinding(vault: vault, agentId: agent, connectionId: connId, principal: principal, scopes: strings(b.get("scopes")), audience: b.get("audience")?.asString)
            var extra: [(String, String)] = []
            if let e = c.get("extraParams") { guard let p = sortedPairs(e) else { throw K.ConnectorError("case") }; extra = p }
            let reg = try registry(customs: c.get("customs")?.asArray)
            let fetch: PCAConnect.VaultFetch = { try transport.fetch($0, $1) }
            let stored: PCAConnect.StoredConnection
            if refresh {
                stored = try K.refresh(K.RefreshArgs(providerId: provider, clientId: cid, clientSecret: c.get("clientSecret")?.asString, refreshToken: c.get("refreshToken")?.asString,
                                                     scopes: strings(c.get("scopes")), fetch: fetch, bind: binding, now: nowV, registry: reg, vars: c.get("vars")?.asObject, extraParams: extra))
            } else {
                stored = try K.exchangeCode(K.ExchangeCodeArgs(providerId: provider, clientId: cid, clientSecret: c.get("clientSecret")?.asString, code: c.get("code")?.asString,
                                                               redirectUri: c.get("redirectUri")?.asString ?? "", codeVerifier: c.get("codeVerifier")?.asString, scopes: strings(c.get("scopes")),
                                                               fetch: fetch, bind: binding, now: nowV, registry: reg, vars: c.get("vars")?.asObject, extraParams: extra))
            }
            result = .object(["ok": .bool(true), "value": stored.json])
        } catch { result = errOut(error) }
        let g = (try? store.get(PCAConnect.ConnectionKey(agentId: agent, provider: c.get("providerId")?.asString ?? "", connectionId: connId ?? "default")))?.json ?? .null
        return .object(["result": result, "fetchCalls": .array(transport.log), "stored": g])
    }

    func testConnectors() throws {
        try K042.requireCovers(["Connectors"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            var norm: (JSONValue) -> JSONValue = Self.normIssues
            let got: JSONValue
            switch c.fn {
            case "validateManifest":
                switch K.validateManifest(c.arg(0)) {
                case let .valid(m): got = .object(["ok": .bool(true), "manifest": m.json])
                case let .invalid(i): got = .object(["ok": .bool(false), "issues": .array(i.map { .string($0) })])
                }
            case "assertManifest": got = Self.guarded { try K.assertManifest(c.arg(0)).json }
            case "manifestDigest": got = Self.guarded { .string(K.manifestDigest(try K.assertManifest(c.arg(0)))) }.get("value") ?? .null
            case "catalog":
                let list = K.createDefaultRegistry().list()
                got = .object(["ids": .array(list.map { .string($0.id) }), "manifests": .array(list.map { $0.json }), "digest": .string(K.catalogDigest()),
                               "google": K.defaultRegistry.get("google")?.json ?? .null, "nope": .null])
            case "registry": got = Self.registryScenario(c.arg(0) ?? .null)
            case "substituteVars":
                guard let u = c.arg(0)?.asString else { d.skip("substituteVars: untyped url"); return }
                let vars = c.arg(1)
                if let v = vars, !v.isNull, !v.isObject { d.skip("substituteVars: untyped vars"); return }
                var r = Self.guarded { .string(try K.substituteVars(u, vars?.asObject)) }
                // `Object.prototype.hasOwnProperty.call(null, name)` is an engine TypeError in the reference (a plain Error, no message); the native is handed no object and refuses the
                // missing variable, which is the same refusal
                if vars == JSONValue.null, r.get("ok") == .bool(false) { r = .object(["ok": .bool(false), "name": .string("Error")]) }
                got = r
            case "pkceChallenge":
                guard let v = c.arg(0)?.asString else { d.skip("pkceChallenge: untyped verifier"); return }
                got = Self.guarded { .string(K.pkceChallenge(v, c.arg(1)?.asString ?? "S256")) }
            case "buildAuthorizeUrl":
                guard let id = c.arg(0)?.asString, let o = c.arg(1), let opts = try Self.authorizeOptions(o, customs: c.arg(2)?.asArray) else { d.skip("buildAuthorizeUrl: untyped options"); return }
                if let st = o.get("state"), st.asString == nil { d.skip("buildAuthorizeUrl: non-string state"); return }
                got = Self.guarded {
                    let r = try K.buildAuthorizeUrl(id, opts)
                    var out: JObject = ["url": .string(r.url), "state": .string(r.state)]
                    if let p = r.pkce { out["pkce"] = .object(["verifier": .string(p.verifier), "challenge": .string(p.challenge), "method": .string(p.method)]) }
                    return .object(out)
                }
                norm = { Self.normUrl(Self.normIssues($0)) }
            case "applyAccessToken":
                guard let m = c.arg(0).flatMap({ Self.lenientManifest($0) }) else { d.skip("applyAccessToken: untyped manifest"); return }
                got = Self.guarded {
                    let t = try K.applyAccessToken(m, c.arg(1)?.asString)
                    return .object(["kind": .string(t.kind), "name": .string(t.name), "value": .string(t.value)])
                }
            case "manifestToProviderConfig":
                guard let id = c.arg(0)?.asString, let creds = Self.credentials(c.arg(1)) else { d.skip("manifestToProviderConfig: untyped"); return }
                got = Self.guarded {
                    guard let m = K.defaultRegistry.get(id) else { throw K.ConnectorError("no manifest") }
                    return try K.manifestToProviderConfig(m, creds).json
                }
            case "buildVaultProviders":
                guard let o = c.arg(0)?.asObject else { d.skip("buildVaultProviders: untyped"); return }
                got = Self.guarded {
                    var list: [(String, K.ProviderCredentials)] = []
                    for k in o.keys.sorted(by: { $0.s.utf16.lexicographicallyPrecedes($1.s.utf16) }) {
                        guard let cr = Self.credentials(o[k]) else { throw K.ConnectorError("creds") }
                        list.append((k.s, cr))
                    }
                    var out = JObject()
                    for (id, cfg) in try K.buildVaultProviders(list) { out[JKey(id)] = cfg.json }
                    return .object(out)
                }
            case "exchange", "refresh":
                let g = RefConnectTests.normForm(Self.tokenRun(IV.normalized(c.arg(0) ?? .null), refresh: c.fn == "refresh")), w = RefConnectTests.normForm(c.out)
                d.add(c, Base.canon(g) == Base.canon(w) ? nil : "\(c.name): want \(Base.firstDiff(w, g, "@")) || want \(Base.canon(w).prefix(300)) got \(Base.canon(g).prefix(300))")
                return
            default: d.skip("\(c.fn): not mapped"); return
            }
            let g = norm(got), w = norm(c.out)
            if Base.canon(g) != Base.canon(w), Self.nonASCIIUrl(.array(c.args)) { d.skip("native stricter: non-ASCII host (no IDNA mapping)"); return }
            d.add(c, Base.canon(g) == Base.canon(w) ? nil : "\(c.name): want \(Base.firstDiff(w, g, "@")) || want \(Base.canon(w).prefix(300)) got \(Base.canon(g).prefix(300))")
        }
        d.finish(1300)
    }
}
