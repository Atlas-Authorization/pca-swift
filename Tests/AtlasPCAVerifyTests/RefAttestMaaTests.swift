import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The Azure MAA key trust (guarded certs fetch over a scripted transport, JWKS evaluation over real and forged certificates, the rotation-safe trust store
/// with re-pinning, the durable store, multi-vantage corroboration) and the release-signed built-in pins against the reference corpus: every case, every fn.
/// The corpus stores long strings in a blob table; arguments and outputs are hydrated. A refusal text that is library text (OpenSSL, a Node type error) is
/// compared by presence only; every other reason is compared up to its first colon.
final class RefAttestMaaTests: XCTestCase {
    typealias M = PCAMaaKeys
    typealias A = RefAnalyzer

    private static func policy(_ p: JSONValue?) -> M.Policy {
        func strings(_ v: JSONValue?) -> [String]? { v?.asArray.map { $0.compactMap { $0.asString } } }
        var pins: [String: [String]]? = nil
        if let o = p?.get("initialPins")?.asObject { pins = [:]; for (k, v) in o { pins?[k.s] = strings(v) ?? [] } }
        var bp: M.BuiltinPins = .shipped
        if p?.get("builtinPins") == .bool(false) { bp = .disabled } else if let o = p?.get("builtinPins"), o.isObject { bp = .source(o) }
        return M.Policy(trustedIssuers: strings(p?.get("trustedIssuers")) ?? [], ttlMs: IV.num(p?.get("ttlMs")), maxStaleMs: IV.num(p?.get("maxStaleMs")),
                        maxNewKeysPerFetch: IV.num(p?.get("maxNewKeysPerFetch")), maxInitialKeys: IV.num(p?.get("maxInitialKeys")), maxKeyAgeMs: IV.num(p?.get("maxKeyAgeMs")),
                        requireOverlap: { if case let .bool(b)? = p?.get("requireOverlap") { return b } else { return nil } }(),
                        allowTrustOnFirstUse: { if case let .bool(b)? = p?.get("allowTrustOnFirstUse") { return b } else { return nil } }(), initialPins: pins,
                        chainRootSpkiSha256: strings(p?.get("chainRootSpkiSha256")), chainIntermediateSpkiSha256: strings(p?.get("chainIntermediateSpkiSha256")), builtinPins: bp,
                        chainLeafCn: strings(p?.get("chainLeafCn")), clockSkewMs: IV.num(p?.get("clockSkewMs")), fetchTimeoutMs: IV.num(p?.get("fetchTimeoutMs")),
                        maxBodyBytes: IV.num(p?.get("maxBodyBytes")))
    }

    /// The response of a scripted fetch step: `{$throws}` throws; `{status?, url?, contentLength?, body | bodyBytes}`; a bare JWKS is a 200 response with that body.
    private static func response(_ r: JSONValue) throws -> M.Response {
        if let t = r.get("$throws")?.asString { throw JSError(t) }
        let step: JSONValue = (r.get("keys") != nil && r.get("body") == nil) ? .object(["body": r]) : r
        var bytes: [UInt8] = []
        if let b = Base.bytes(step.get("bodyBytes")) { bytes = b }
        else if let body = step.get("body") {
            if let t = body.get("$text")?.asString, body.asObject?.count == 1 { bytes = Array(t.utf8) } else { bytes = Array(JS.stringify(body).utf8) }
        }
        return M.Response(status: Int(step.get("status")?.safeInt ?? 200), url: step.get("url")?.asString, contentLength: step.get("contentLength").map { JS.toString($0) }, body: bytes)
    }

    private static func sequence(_ steps: [JSONValue], _ log: Box) -> M.Fetch {
        var i = 0
        return { url in
            log.urls.append(url + " [redirect:error]")
            let s = steps[Swift.min(i, steps.count - 1)]
            i += 1
            return try response(s)
        }
    }

    final class Box { var urls: [String] = [] }

    private static func fetchCerts(_ a: JSONValue?) -> JSONValue {
        let log = Box()
        var out: JObject = [:]
        do {
            guard let r = a?.get("response") else { throw JSError("response") }
            let o = a?.get("opts")
            out["jwks"] = try M.fetchMaaCerts(a?.get("issuer")?.asString ?? "", fetch: sequence([r], log), timeoutMs: IV.num(o?.get("timeoutMs")), maxBytes: IV.num(o?.get("maxBytes")))
            out["ok"] = .bool(true)
        } catch { out["ok"] = .bool(false); out["error"] = .string((error as? JSError)?.message ?? "\(error)") }
        out["requests"] = .array(log.urls.map { .string($0) })
        return .object(out)
    }

    private static func trust(_ a: JSONValue?) throws -> JSONValue {
        let store = M.MemoryKeyStateStore()
        for (k, v) in a?.get("initial")?.asObject ?? [:] { store.set(k.s, v) }
        let log = Box()
        let t = try M.createMaaKeyTrust(policy: policy(a?.get("policy")), store: store, fetch: sequence(a?.get("fetches")?.asArray ?? [], log))
        let results = (a?.get("calls")?.asArray ?? []).map { c -> JSONValue in
            var repin: M.Repin? = nil
            if let r = c.get("repin") { repin = M.Repin(manifest: r.get("manifest"), verify: r.get("verify") ?? .object([:])) }
            return t.getTrustAnchors(c.get("issuer")?.asString ?? "", nowMs: IV.num(c.get("nowMs")) ?? .nan, repin: repin)
        }
        return .object(["results": .array(results), "store": store.snapshot(), "fetches": .array(log.urls.map { .string($0) })])
    }

    private static func kvStore(_ a: JSONValue?) -> JSONValue {
        let kv = MemoryAtomicKV()
        let s = M.DurableKeyStateStore(kv)
        let results: [JSONValue] = (a?.get("steps")?.asArray ?? []).map { st in
            if let p = st.get("set")?.asArray, p.count == 2, let i = p[0].asString { try? s.set(i, p[1]); return .null }
            if let i = st.get("get")?.asString { return ((try? s.get(i)) ?? nil) ?? .null }
            return .null
        }
        var snapshot = JObject()
        for k in kv.keys() { snapshot[JKey(k)] = kv.get(k) ?? .null }
        return .object(["results": .array(results), "kv": .object(snapshot)])
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "constants":
            return .value(.object(["BUILTIN_CHAIN_LEAF_CN": .array(M.BUILTIN_CHAIN_LEAF_CN.map { .string($0) }), "BUILTIN_MAA_PINS_ISSUER_ID": .string(M.BUILTIN_MAA_PINS_ISSUER_ID),
                                   "BUILTIN_MAA_PINS_ISSUER_KEYS": M.BUILTIN_MAA_PINS_ISSUER_KEYS]))
        case "evaluateMaaJwks": return .value(M.evaluateMaaJwks(a0, issuer: a1?.asString ?? "", policy: policy(a2), nowMs: IV.num(a3) ?? .nan))
        case "loadBuiltinMaaPins": return .value(M.loadBuiltinMaaPins(nowMs: IV.num(a0?.get("nowMs")) ?? .nan, source: a0?.get("source")))
        case "corroborate":
            return .value(M.corroborateMaaKeySets(a0, k: IV.num(a1) ?? .nan, issuer: a2?.get("issuer")?.asString ?? "", nowMs: IV.num(a2?.get("nowMs")) ?? .nan,
                                                  policy: a2?.get("policy").map { policy($0) }))
        case "fetchCerts": return .value(fetchCerts(a0))
        case "trust": return A.run { try trust(a0) }
        case "kvStore": return .value(kvStore(a0))
        case "buildTrust":
            return A.run {
                if a0?.get("noFetch") == .bool(true) { throw JSError("createMaaKeyTrust: fetch must be injected") }
                _ = try M.createMaaKeyTrust(policy: policy(a0?.get("policy")), store: M.MemoryKeyStateStore(), fetch: { _ in M.Response(status: 200, body: []) })
                return .object(["built": .bool(true)])
            }
        default: return nil
        }
    }

    private static func hydrate(_ x: JSONValue, _ blobs: JObject) -> JSONValue { AttestVectorTests.hydrate(x, blobs) }

    /// Library text (OpenSSL, a Node type error): compared by presence. Any other reason: compared up to its first colon.
    private static func isLibrary(_ s: String) -> Bool { s.hasPrefix("error:") || s.hasPrefix("The first argument") || s.hasPrefix("Invalid ") }

    private static func norm(_ ours: JSONValue, _ ref: JSONValue) -> (JSONValue, JSONValue) {
        switch (ours, ref) {
        case let (.array(a), .array(b)) where a.count == b.count:
            let p = zip(a, b).map { norm($0, $1) }
            return (.array(p.map { $0.0 }), .array(p.map { $0.1 }))
        case let (.object(a), .object(b)):
            var oa = JObject(), ob = JObject()
            for (k, v) in b {
                guard let x = a[k] else { ob[k] = v; continue }
                if k.s == "reason", let rs = v.asString, let os = x.asString {
                    if isLibrary(rs) { oa[k] = .string("<library>"); ob[k] = .string("<library>") }
                    else { oa[k] = .string(String(os.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")); ob[k] = .string(String(rs.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")) }
                } else { let p = norm(x, v); oa[k] = p.0; ob[k] = p.1 }
            }
            for (k, v) in a where b[k] == nil { oa[k] = v }
            return (.object(oa), .object(ob))
        default: return (ours, ref)
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let doc = K042.parse(String(decoding: try K042.bytes("ref-attest-maa.json.gz"), as: UTF8.self))
        let blobs = doc.get("blobs")?.asObject ?? [:]
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        for raw in doc.get("cases")?.asArray ?? [] {
            let c = BaseCase(fn: raw.get("fn")?.asString ?? "", name: raw.get("name")?.asString ?? "?", args: (raw.get("args")?.asArray ?? []).map { Self.hydrate($0, blobs) },
                             out: Self.hydrate(raw.get("out") ?? .null, blobs), suspect: false, raw: raw)
            seen[c.fn, default: 0] += 1
            // an OS without CryptoKit's ML-DSA refuses a hybrid-signed manifest (and so the shipped pins, which are hybrid-signed) as an unsupported suite
            if !MLDSA.available, (c.fn == "loadBuiltinMaaPins" && c.arg(0)?.get("source") == nil) || Base.canon(.array(c.args)).contains("hybrid-ed25519-ml-dsa") {
                if PqRequirement.mayLeaveOut("the hybrid-signed MAA pins cases") { d.skip("ML-DSA is not available on this OS") }
                continue
            }
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); continue }
            if c.threw { d.add(c, Base.diff(c, got)); continue }
            guard case let .value(v) = got else { d.add(c, Base.diff(c, got)); continue }
            let (o, r) = Self.norm(v, c.out)
            d.add(c, Base.canon(o) == Base.canon(r) ? nil : "\(c.name): \(Base.firstDiff(r, o, "@"))")
        }
        XCTAssertEqual(doc.get("cases")?.asArray?.count, 261)
        XCTAssertEqual(seen, ["evaluateMaaJwks": 92, "trust": 60, "fetchCerts": 36, "loadBuiltinMaaPins": 32, "corroborate": 26, "buildTrust": 9, "kvStore": 5, "constants": 1])
        d.finish(261 - d.skipped.values.reduce(0, +))
    }
}
