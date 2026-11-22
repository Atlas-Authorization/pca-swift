import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCASandbox (receipt chain, handle table, signed runtime claims, policy compile and OS profile generators,
/// egress admission, address classification, reference tool builders) against the reference. The corpus carries no key material: the
/// claim keys are derived here from the seed labels (sha256 of "atlas-pca-conformance/<label>").
final class RefSandboxTests: XCTestCase {
    static let file = "ref-sandbox.json.gz"
    typealias S = PCASandbox

    /// The reference this corpus was generated from read these spellings as public; the native check classifies the parsed address and
    /// refuses them (native stricter).
    static let stricterPrivate: Set<String> = ["0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:0", "::ffff:7f00:1", "::ffff:0:0", "::1%eth0", "::127.0.0.1", "::ffff:1.2.3.4%x",
                                               "::2", "fec0::1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:1.2.3.4", "f::"]

    final class Clock { var t = 0.0 }

    static func seed(_ label: String) -> [UInt8] { Canonical.sha256(Array("atlas-pca-conformance/\(label)".utf8)) }
    static let err = JSONValue.object(["$err": .bool(true)])

    static func operation(_ v: JSONValue?) -> PCA.Operation? {
        guard let o = v, let verb = o.get("verb")?.asString, let res = o.get("resource")?.asString else { return nil }
        return PCA.Operation(verb: verb, resource: res, params: o.get("params") ?? .null)
    }

    /// {allow, operation: {verb, resource, params_digest: hashCanonical(bind.params), id}} like the generator's mkRes.
    static func grant(_ allow: Bool, _ bind: JSONValue?) -> S.Grant {
        guard let b = bind, b.isObject, let op = operation(b), let d = IV.strictHash(op.params) else { return S.Grant(allow: allow) }
        return S.Grant(allow: allow, operation: PCA.AuthorizedOperation(verb: op.verb, resource: op.resource, paramsDigest: d, id: b.get("id")?.asString ?? "op"))
    }

    static func num(_ v: JSONValue?) -> Double? { IV.num(v) }

    // MARK: receipt log

    static func receiptLog(_ spec: JSONValue) -> JSONValue {
        let clock = Clock()
        let signer: ((String) -> String)? = spec.get("sign") == .bool(true) ? { "sig:" + $0 } : nil
        let log = S.ReceiptLog(now: { clock.t }, sign: signer)
        var outs: [JSONValue] = []
        for a in spec.get("appends")?.asArray ?? [] {
            clock.t = num(a.get("t")) ?? 0
            guard let rc = a.get("rc")?.asString, let body = a.get("body")?.asObject, let r = try? log.append(rc, body) else { outs.append(err); continue }
            outs.append(r)
        }
        return .array(outs)
    }

    // MARK: egress

    static func template(_ v: JSONValue?) throws -> S.EgressTemplate {
        guard let o = v?.asObject else { throw S.SandboxError("template is not an object") }
        func str(_ k: String) throws -> String? {
            guard let x = o[JKey(k)], !x.isNull else { return nil }
            guard let s = x.asString else { throw S.SandboxError("\(k) is not a string") }
            return s
        }
        var port: Int?
        if let p = o[JKey("port")], !p.isNull {
            guard let d = IV.safe(p) else { throw S.SandboxError("port is not an integer") }
            port = Int(d)
        }
        guard let method = try str("method"), let scheme = try str("scheme"), let host = try str("host"), let path = try str("path") else { throw S.SandboxError("missing member") }
        return S.EgressTemplate(method: method, scheme: scheme, host: host, port: port, path: path, pathPrefix: JS.truthy(o[JKey("path_prefix")]),
                                query: try str("query"), bodySha256: try str("body_sha256"), tunnel: o[JKey("tunnel")] == .bool(true))
    }

    static func egress(_ spec: JSONValue) -> JSONValue {
        let clock = Clock()
        let p = S.EgressPolicy(now: { clock.t })
        var outs: [JSONValue] = []
        for st in spec.get("steps")?.asArray ?? [] {
            switch st.get("op")?.asString {
            case "now"?:
                clock.t = num(st.get("t")) ?? 0
                outs.append(.null)
            case "admit"?:
                do {
                    guard let op = operation(st.get("operation")) else { throw S.SandboxError("operation") }
                    let t = try template(st.get("template"))
                    try p.admit(grant(st.get("allow") == .bool(true), st.get("bind")), op, toRequest: { _ in t },
                                uses: num(st.get("opts")?.get("uses")), expiresAt: num(st.get("opts")?.get("expiresAt")))
                    outs.append(.string("ok"))
                } catch { outs.append(err) }
            default:
                guard let r = st.get("req"), let method = r.get("method")?.asString else { outs.append(err); continue }
                let body = r.get("body").flatMap { Base.bytes($0) } ?? []
                let d = p.claim(S.EgressRequest(method: method, url: r.get("url")?.asString ?? "", body: body))
                if d.allow, let a = d.admission {
                    outs.append(.object(["allow": .bool(true), "op_id": .string(d.opId),
                                         "admission": .object(["verb": .string(a.verb), "resource": .string(a.resource), "params_digest": .string(a.paramsDigest)])]))
                } else {
                    outs.append(.object(["allow": .bool(false), "reason": .string(d.reason)]))
                }
            }
        }
        return .array(outs)
    }

    // MARK: handles

    static let executors: [String: S.Executor] = [
        "fs.read": { _ in [1, 2, 3] },
        // canonical JSON of the operation (the reference writes JSON.stringify; compared as parsed JSON, member order is not kept)
        "fs.echo": { op in Canonical.utf8(try Canonical.canonicalizeStrict(.object(["verb": .string(op.verb), "resource": .string(op.resource), "params": op.params]))) },
        "fs.throw": { _ in throw S.SandboxError("boom") },
        "fs.notbytes": { _ in nil },
    ]

    static func handles(_ spec: JSONValue) -> JSONValue {
        let clock = Clock()
        let log = S.ReceiptLog(now: { clock.t })
        let table = S.HandleTable(runtimeClass: spec.get("cls")?.asString ?? "", log: log, executors: executors, now: { clock.t })
        var outs: [JSONValue] = []
        for st in spec.get("steps")?.asArray ?? [] {
            let index = num(st.get("index")) ?? .nan
            do {
                switch st.get("op")?.asString {
                case "now"?: clock.t = num(st.get("t")) ?? 0; outs.append(.null)
                case "mint"?:
                    guard let op = operation(st.get("operation")) else { throw S.SandboxError("operation") }
                    var bind = st.get("bind")
                    if bind == nil, var o = st.get("operation")?.asObject { o[JKey("id")] = .string(st.get("id")?.asString ?? "op-h"); bind = .object(o) }
                    let o = st.get("opts")
                    let n = try table.mint(grant(st.get("allow").map { $0 == .bool(true) } ?? true, bind), op, uses: num(o?.get("uses")), expiresAt: num(o?.get("expiresAt")), requires: o?.get("requires")?.asString)
                    outs.append(.int(Int64(n)))
                case "attenuate"?:
                    let nw = st.get("narrower")
                    outs.append(.int(Int64(try table.attenuate(index, uses: num(nw?.get("uses")), expiresAt: num(nw?.get("expiresAt"))))))
                case "revoke"?: table.revoke(index); outs.append(.null)
                case "use"?:
                    switch try table.use(index) {
                    case let .ok(b): outs.append(.object(["ok": .bool(true), "result": Base.bytesValue(b)]))
                    case let .failed(f): outs.append(.object(["ok": .bool(false), "reason": .string(f.rawValue)]))
                    }
                case "verbOf"?: outs.append(Base.opt(table.verbOf(index)))
                case "size"?: outs.append(.int(Int64(table.size)))
                default: break
                }
            } catch { outs.append(err) }
        }
        return .object(["outs": .array(outs), "log": .array(log.entries)])
    }

    /// An echoed operation is compared as parsed JSON (the reference's JSON.stringify keeps member order, this model does not).
    static func normEcho(_ v: JSONValue) -> JSONValue {
        switch v {
        case let .object(o):
            if o.count == 1, let b = Base.bytes(v), b.first == UInt8(ascii: "{"), let p = K042.parseOrNil(String(decoding: b, as: UTF8.self)), let c = IV.strictCanon(p) { return .string("echo:" + c) }
            return .object(o.mapValues(normEcho))
        case let .array(a): return .array(a.map(normEcho))
        default: return v
        }
    }

    // MARK: spec builders

    static func toolSpec(_ v: JSONValue?) -> S.ToolSpec? {
        guard let o = v?.asObject else { return nil }
        func int(_ x: JSONValue?) -> Int? { IV.safe(x).map { Int($0) } }
        var calls: [S.ToolCall] = []
        for c in o[JKey("calls")]?.asArray ?? [] {
            guard let h = int(c.get("handle")), let p = int(c.get("ptr")), let cap = int(c.get("cap")) else { return nil }
            calls.append(S.ToolCall(handle: h, ptr: p, cap: cap))
        }
        var extras: [(module: String, name: String)] = []
        for e in o[JKey("extraImports")]?.asArray ?? [] {
            guard let m = e.get("module")?.asString, let n = e.get("name")?.asString else { return nil }
            extras.append((m, n))
        }
        var memory: (min: Int, max: Int?) = (1, 1)
        if let m = o[JKey("memory")] {
            guard let mn = int(m.get("min")) else { return nil }
            memory = (mn, m.get("max").flatMap { $0.isNull ? nil : int($0) })
            if let mx = m.get("max"), !mx.isNull, int(mx) == nil { return nil }
        }
        return S.ToolSpec(calls: calls, returns: o[JKey("returns")]?.asString, extraImports: extras, memory: memory, spin: JS.truthy(o[JKey("spin")]))
    }

    /// Trust and claims the strict runtime-claim profile refuses (negative times, empty or over-long digests): the corpus predates them.
    static func strictTrigger(_ c: BaseCase) -> Bool {
        func bad(_ v: JSONValue?) -> Bool {
            guard let v = v else { return false }
            if let d = IV.num(v) { return d < 0 || IV.isNegZero(d) }
            if let s = v.asString { return s.isEmpty || s.utf16.count > 128 }
            if let a = v.asArray { return a.contains { bad($0) } }
            return false
        }
        let claim = c.arg(0), trust = c.arg(1)
        return ["iat", "exp", "passport_digest", "evidence_digest", "attestor"].contains { bad(claim?.get($0)) }
            || ["now", "passportDigest", "verifiedEvidenceDigests", "pinnedAttestors"].contains { bad(trust?.get($0)) }
    }

    func testSandbox() throws {
        try K042.requireCovers(["Sandbox"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "moduleConsts":
                var ue = JObject()
                for (k, v) in S.USE_ERR { ue[JKey(k)] = .int(Int64(v)) }
                got = .value(.object(["IMPORT_MODULE": .string(S.IMPORT_MODULE), "ALLOWED_IMPORTS": .array(S.ALLOWED_IMPORTS.map { .string($0) }), "USE_ERR": .object(ue),
                                      "GENESIS": .string(S.GENESIS), "RUNTIME_CLASSES": .array(S.RUNTIME_CLASSES.map { .string($0) }), "DOMAIN": .string(S.RUNTIME_CLAIM_DOMAIN)]))
            case "satisfiesRuntimeClass":
                got = .value(.bool(S.satisfiesRuntimeClass(c.arg(0)?.asString ?? "\u{0}non-string", c.arg(1)?.asString ?? "\u{0}non-string")))
            case "receiptLog": got = .value(Self.receiptLog(c.arg(0) ?? .null))
            case "verifyReceiptChain":
                let tag = c.arg(1)?.asString == "tag"
                got = Base.run { try S.verifyReceiptChain(c.arg(0) ?? .null, verifySig: tag ? { $1 == "sig:" + $0 } : nil) }
            case "policyFromNeeds":
                got = Base.run { try S.policyFromNeeds(c.arg(0) ?? .null, proxyPort: c.arg(1)).json }
            case "compilePolicy":
                let spec = c.arg(0) ?? .null
                got = Base.run {
                    var items: [(grant: S.Grant, operation: PCA.Operation)] = []
                    for it in spec.get("items")?.asArray ?? [] {
                        guard let op = Self.operation(it.get("operation")) else { throw S.SandboxError("operation") }
                        items.append((Self.grant(it.get("allow") == .bool(true), it.get("bind")), op))
                    }
                    let needs = spec.get("needs")
                    return try S.compilePolicy(items, needsOf: { needs?.get("\($0.verb) \($0.resource)") }, proxyPort: spec.get("proxyPort")).json
                }
            case "seccompProfile", "landlockRuleset", "macosProfile", "confineArgs":
                guard let p = c.arg(0).flatMap({ S.Policy(json: $0) }) else { d.skip("\(c.fn): policy not in the typed form"); return }
                switch c.fn {
                case "seccompProfile": got = .value(S.seccompProfile(p))
                case "landlockRuleset": got = .value(S.landlockRuleset(p))
                case "macosProfile": got = .value(.string(S.macosProfile(p)))
                default: got = .value(.array(S.confineArgs(p).map { .string($0) }))
                }
            case "isPrivateAddress":
                guard let ip = c.arg(0)?.asString else { d.skip("isPrivateAddress: non-string (a Swift String is typed)"); return }
                let priv = S.isPrivateAddress(ip)
                if Self.stricterPrivate.contains(ip), c.out == .bool(false) {
                    XCTAssertTrue(priv, "native stricter: \(ip) must be private")
                    d.skip("isPrivateAddress: native stricter than the reference (parsed address)")
                    return
                }
                got = .value(.bool(priv))
            case "egress": got = .value(Self.egress(c.arg(0) ?? .null))
            case "handles":
                let g = Self.normEcho(Self.handles(c.arg(0) ?? .null)), w = Self.normEcho(c.out)
                d.add(c, Base.canon(g) == Base.canon(w) ? nil : "\(c.name): want \(Base.firstDiff(w, g, "@")) || want \(Base.canon(w).prefix(300)) got \(Base.canon(g).prefix(300))")
                return
            case "signRuntimeClaim":
                got = Base.run {
                    let key: [UInt8]
                    if let l = c.arg(0)?.asString { key = Self.seed(l) } else if let n = c.arg(0)?.get("short")?.safeInt { key = [UInt8](repeating: 0, count: Int(n)) } else { throw S.SandboxError("key") }
                    let pub = Ed25519Deterministic.publicKey(seed: Self.seed(c.arg(1)?.asString ?? "x"))
                    guard let claim = c.arg(2)?.asObject else { throw S.SandboxError("claim") }
                    return try S.signRuntimeClaim(seed: key, publicKey: pub, claim)
                }
            case "verifiedRuntimeClass":
                let r = S.verifiedRuntimeClass(c.arg(0), trust: c.arg(1))
                if r == "none", c.out != .string("none"), Self.strictTrigger(c) { d.skip("verifiedRuntimeClass: strict form (negative time / empty or long digest) stricter than the corpus"); return }
                got = .value(.string(r))
            case "passportDigest", "evidenceDigest":
                got = Base.run { .string(try S.passportDigest(c.arg(0) ?? .null)) }
            case "buildTool":
                guard let spec = Self.toolSpec(c.arg(0)) else { d.skip("buildTool: spec not in the typed form"); return }
                got = .value(Base.bytesValue(S.buildTool(spec)))
            case "buildProbeTool":
                got = .value(Base.bytesValue(c.args.isEmpty ? S.buildProbeTool() : S.buildProbeTool(cap: IV.safe(c.arg(0)).map { Int($0) } ?? 64)))
            case "referenceComponentWat":
                let o = c.arg(0)
                got = .value(.string(S.referenceComponentWat(handle: IV.safe(o?.get("handle")).map { Int($0) }, spin: JS.truthy(o?.get("spin")), extraImport: o?.get("extraImport")?.asString)))
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1400)
    }

    /// The strict runtime-claim form and the parsed-address rule, pinned directly (not through the corpus).
    func testAddressRule() {
        for ip in ["0:0:0:0:0:0:0:1", "0::1", "::ffff:7f00:1", "::FFFF:7F00:0001", "::127.0.0.1", "::7f00:1", "64:ff9b::7f00:1", "64:ff9b::10.0.0.1", "::1%eth0",
                   "fe80::1%25eth0", "2606:4700::1111%eth0", "FE80::1", "fc::1", "fec0::1", "1fff::1", "4000::1", "1::2::3", "::00001", "::01.2.3.4", "[::1]", " ::1", "", "localhost"] {
            XCTAssertTrue(S.isPrivateAddress(ip), ip)
        }
        for ip in ["2606:4700:0:0:0:0:0:1111", "2001:DB8::1", "::ffff:808:808", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "2000::", "3fff::1", "8.8.8.8"] {
            XCTAssertFalse(S.isPrivateAddress(ip), ip)
        }
    }

    func testRuntimeClaimStrictForm() throws {
        let seed = Self.seed("strict-attestor")
        let pub = Ed25519Deterministic.publicKey(seed: seed)
        func run(_ over: [String: JSONValue], _ tover: [String: JSONValue]) throws -> String {
            var c: JObject = ["class": .string("os_confined"), "passport_digest": .string("pd"), "evidence_digest": .string("ev"), "iat": .int(0), "exp": .int(100)]
            for (k, v) in over { c[JKey(k)] = v }
            let claim = try S.signRuntimeClaim(seed: seed, publicKey: pub, c)
            var t: JObject = ["pinnedAttestors": .array([claim.get("attestor")!]), "passportDigest": claim.get("passport_digest")!,
                              "verifiedEvidenceDigests": .array([claim.get("evidence_digest")!]), "now": .int(50)]
            for (k, v) in tover { t[JKey(k)] = v }
            return S.verifiedRuntimeClass(claim, trust: .object(t))
        }
        XCTAssertEqual(try run([:], [:]), "os_confined")
        let long = JSONValue.string(String(repeating: "d", count: 129))
        for (o, t) in [(["iat": JSONValue.int(-5)], [:]), (["iat": .int(-10), "exp": .int(-1)], ["now": .int(-5)]), (["iat": .int(-10)], ["now": .int(-1)]),
                       (["evidence_digest": .string("")], [:]), (["passport_digest": .string("")], [:]), (["evidence_digest": long], [:]), (["passport_digest": long], [:]),
                       ([:], ["now": .int(9007199254740992)])] as [([String: JSONValue], [String: JSONValue])] {
            XCTAssertEqual(try run(o, t), "none", "\(o) \(t)")
        }
        XCTAssertEqual(try run(["evidence_digest": .string(String(repeating: "d", count: 128)), "passport_digest": .string(String(repeating: "p", count: 128))], [:]), "os_confined")
    }

    func testIsAuthorizedFor() {
        let op = PCA.Operation(verb: "fs.read", resource: "file:a", params: .object(["p": .int(1)]))
        let d = IV.strictHash(op.params)!
        let bound = PCA.AuthorizedOperation(verb: "fs.read", resource: "file:a", paramsDigest: d, id: "i")
        XCTAssertTrue(PCA.isAuthorizedFor(allow: true, bound: bound, operation: op))
        XCTAssertFalse(PCA.isAuthorizedFor(allow: false, bound: bound, operation: op))
        XCTAssertFalse(PCA.isAuthorizedFor(allow: true, bound: nil, operation: op))
        XCTAssertFalse(PCA.isAuthorizedFor(allow: true, bound: bound, operation: PCA.Operation(verb: "fs.read", resource: "file:a", params: .object(["p": .int(2)]))))
        XCTAssertFalse(PCA.isAuthorizedFor(allow: true, bound: bound, operation: PCA.Operation(verb: "fs.write", resource: "file:a", params: op.params)))
        XCTAssertFalse(PCA.isAuthorizedFor(allow: true, bound: bound, operation: PCA.Operation(verb: "fs.read", resource: "file:a", params: .array([]))))
    }
}
