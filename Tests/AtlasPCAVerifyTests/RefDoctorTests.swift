import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of pca-doctor (PCADoctor: credential scrubbing, the clock, proxy, suite, root-caveat and enforcement checks,
/// results formatting, configuration from the environment and the command line, the whole run) against the reference
/// (@atlasauth/pca-doctor). The network, the clock and the installed library are the corpus's named stand-ins. A reference throw
/// requires a native refusal.
final class RefDoctorTests: XCTestCase {
    typealias D = PCADoctor
    typealias N = PCASchema.Node

    static func json(_ n: N) -> JSONValue {
        switch n {
        case .null: return .null
        case let .bool(b): return .bool(b)
        case let .num(d): return WJ.plain(.double(d))
        case let .str(s): return .string(s)
        case let .arr(a): return .array(a.map(json))
        case let .obj(m): return .object(Dictionary(m.map { (JKey($0.key), json($0.value)) }) { _, b in b })
        }
    }

    static func node(_ v: JSONValue?) -> N { v.map { N(json: $0) } ?? .null }

    // the corpus's fake network: each fetch pops the next entry of its url (the last repeats), advances the clock by `rtt` first
    final class Env {
        var t: Double
        var idx: [String: Int] = [:]
        let responses: JObject
        init(_ spec: JSONValue?) { t = IV.num(spec?.get("now")) ?? 0; responses = spec?.get("responses")?.asObject ?? [:] }
        func fetch(_ method: String, _ url: String, _ headers: [String: String], _ timeout: Double) throws -> D.FetchResponse {
            guard let lst = responses[JKey(url)]?.asArray, !lst.isEmpty else { throw JSError("no route \(url)") }
            let i = idx[url] ?? 0
            idx[url] = i + 1
            let rsp = lst[min(i, lst.count - 1)]
            t += IV.num(rsp.get("rtt")) ?? 0
            if let m = rsp.get("throw")?.asString { throw JSError(m) }
            return D.FetchResponse(date: rsp.get("date")?.asString, rateLimitRemaining: rsp.get("rl")?.asString)
        }
    }

    static func fakePca(_ spec: JSONValue?) -> (String?) throws -> D.LoadedPca {
        { _ in
            if let t = spec?.get("throws")?.asString { throw JSError(t) }
            let behavior = spec?.get("behavior")?.asString ?? ""
            return D.LoadedPca(version: spec?.get("version")?.asString ?? "", path: spec?.get("path")?.asString ?? "") { cav, amount in
                if behavior == "throws" { throw JSError("boom") }
                if behavior == "allow-all" { return (true, []) }
                if behavior == "deny-all" { return (false, ["denied", "7"]) }
                if behavior == "nonarray-reasons" { return (false, []) }
                if cav[JKey("type")]?.asString == "max_spend" {
                    if behavior == "ignore-max" { return (true, []) }
                    return amount <= (IV.num(cav[JKey("usd")]) ?? 0) ? (true, []) : (false, ["over max_spend"])
                }
                if behavior == "ignore-unknown" { return (true, []) }
                return (false, ["unknown caveat type"])
            }
        }
    }

    static func strings(_ v: JSONValue?) -> [String] { (v?.asArray ?? []).compactMap { $0.asString } }

    func testDoctorAgainstTheReference() throws {
        try K042.requireCovers(["Doctor", "Schema"])
        let d = Base.Diffs()
        try Base.each("ref-doctor.json.gz") { c in
            let a = c.args
            func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
            // a refusal carries the reference's Node error code (ERR_INVALID_URL) where it has one
            let got: BaseGot = Base.run({ ($0 as? JSError)?.code }) {
                switch c.fn {
                case "consts":
                    return .object(["USAGE": .string(D.USAGE), "CHECK_GROUPS": .array(D.CHECK_GROUPS.map { .string($0) }), "DEFAULT_REQUIRED": .array(D.DEFAULT_REQUIRED.map { .string($0) }),
                                    "ROOT_CAVEAT_MIN_VERSION": .string(D.ROOT_CAVEAT_MIN_VERSION), "DEFAULT_REFERENCE_URL": .string(D.DEFAULT_REFERENCE_URL),
                                    "SUITES_REMEDIATION": .string(D.SUITES_REMEDIATION), "PQ_REMEDIATION": .string(D.PQ_REMEDIATION), "CLOCK_REMEDIATION": .string(D.CLOCK_REMEDIATION),
                                    "PROXY_REMEDIATION": .string(D.PROXY_REMEDIATION), "ATOMICITY_REMEDIATION": .string(D.ATOMICITY_REMEDIATION),
                                    "DURABILITY_REMEDIATION": .string(D.DURABILITY_REMEDIATION), "CAVEAT_REMEDIATION": .string(D.CAVEAT_REMEDIATION)])
                case "scrubText": return .string(D.scrubText(arg(0) ?? .null))
                case "scrubDeep": return D.scrubDeep(arg(0) ?? .null)
                case "checkAllowedSuites": return Self.json(D.checkAllowedSuites(Self.node(arg(0))))
                case "checkPqBinding": return Self.json(try D.checkPqBinding(Self.node(arg(0))))
                case "checkProxyConfig": return Self.json(D.checkProxyConfig(Self.node(arg(0))))
                case "checkEnforcement": return Self.json(try D.checkEnforcement(Self.node(arg(0))))
                case "testNetIp":
                    guard let seed = IV.num(arg(0)) else { throw JSError("seed") }
                    return .string(D.testNetIp(D.mulberry32(UInt32(truncatingIfNeeded: Int64(seed)))))
                case "forgedHeaders":
                    guard let seed = IV.num(arg(0)) else { throw JSError("seed") }
                    var o = JObject()
                    for (k, v) in D.forgedHeaders(D.mulberry32(UInt32(truncatingIfNeeded: Int64(seed)))) { o[JKey(k)] = .string(v) }
                    return .object(o)
                case "readDate":
                    let e = Env(arg(1))
                    return Self.json(D.readDateJSON("https://api.example.com", e.fetch, { e.t }, 1000))
                case "checkClock":
                    let e = Env(arg(1))
                    return Self.json(D.checkClock(Self.node(arg(0)), fetch: e.fetch, now: { e.t }))
                case "checkProxyProbe":
                    let e = Env(arg(1))
                    return Self.json(try D.checkProxyProbe(Self.node(arg(0)), fetch: e.fetch, rand: D.mulberry32(7)))
                case "compareVersion":
                    guard let x = arg(0)?.asString, let y = arg(1)?.asString else { throw JSError("versions") }
                    return .int(Int64(D.compareVersion(x, y)))
                case "checkRootCaveats": return Self.json(D.checkRootCaveats(Self.node(arg(0)), loadPca: Self.fakePca(arg(1))))
                case "configProblems": return .array(D.configProblems(Self.node(arg(0))).map { .string($0) })
                case "verdictOf": return .string(D.verdictOf((arg(0)?.asArray ?? []).map { Self.node($0) }, strict: arg(1) == .bool(true)))
                case "formatResults":
                    return .string(D.formatResults((arg(0)?.asArray ?? []).map { Self.node($0) }, target: arg(1)?.asString, strict: arg(2) == .bool(true)))
                case "configFromEnv":
                    var env: [String: String] = [:]
                    for (k, v) in arg(0)?.asObject ?? [:] { env[k.s] = v.asString ?? "" }
                    return Self.json(try D.configFromEnv(env))
                case "mergeConfig": return Self.json(try D.mergeConfig(a.map { Self.node($0) }))
                case "parseDoctorArgs":
                    let r = try D.parseDoctorArgs(Self.strings(arg(0)))
                    var o: JObject = ["flags": Self.json(r.flags), "only": .array(r.only.map { .string($0) }), "json": .bool(r.json), "strict": .bool(r.strict), "help": .bool(r.help)]
                    if let cfg = r.config { o["config"] = .string(cfg) }
                    return .object(o)
                case "main":
                    var env: [String: String] = [:]
                    for (k, v) in arg(1)?.asObject ?? [:] { env[k.s] = v.asString ?? "" }
                    var out: [JSONValue] = [], err: [JSONValue] = []
                    let code = D.main(Self.strings(arg(0)), env: env, deps: D.Deps(fetch: { _, _, _, _ in throw JSError("no network in the replay") }),
                                      print: { out.append(.string($0)) }, printErr: { err.append(.string($0)) })
                    return .object(["code": .int(Int64(code)), "out": .array(out), "err": .array(err)])
                case "runDoctor":
                    let e = Env(arg(2))
                    let only: [String]? = arg(1)?.asArray == nil ? nil : Self.strings(arg(1))
                    let deps = D.Deps(fetch: e.fetch, now: { e.t }, loadPca: Self.fakePca(arg(3)))
                    return .array(D.runDoctor(Self.node(arg(0)), only: only, deps: deps).map { Self.json($0) })
                default: throw JSError("not mapped")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1200)
    }
}
