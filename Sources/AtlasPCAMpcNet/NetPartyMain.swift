import Foundation
import AtlasPCAVerify
import AtlasPCAMpc

/// One MPC node (a party or the dealer) as its OWN OS process, talking to the others only over the mutual-TLS mesh. Usage: `pca-mpc-party <config.json>`
/// or `pca-mpc-party keygen <dir> <cn>`. Roles: party, dealer, ot-sender, ot-receiver (config `ot` {kind: "ec" | "lwe", count; "lwe" needs a build with ATLAS_PCA_LWEOT=1}). Prints exactly one JSON line (the result or the attributable abort) on stdout; exit code 3 on an abort. Test hooks
/// need both `unsafeTestHooks` in the config and the environment variable `PCA_MPC_UNSAFE_TEST_HOOKS=1`, else the node refuses to start.
public enum NetPartyMain {
    private struct ConfigError: Error, CustomStringConvertible { let description: String }

    private static func obj(_ v: JSONValue?, _ what: String) throws -> JSONValue {
        guard let v = v, v.jObj != nil else { throw ConfigError(description: "config: \(what) must be an object") }
        return v
    }

    private static func num(_ v: JSONValue?, _ what: String) throws -> Int {
        guard let i = NetUtil.int(v) else { throw ConfigError(description: "config: \(what) must be an integer") }
        return i
    }

    private static func str(_ v: JSONValue?, _ what: String) throws -> String {
        guard let s = v?.jStr else { throw ConfigError(description: "config: \(what) must be a string") }
        return s
    }

    private static func has(_ cfg: JSONValue, _ k: String) -> Bool { cfg.jGet(k) != nil && cfg.jGet(k) != .null }

    private static func emit(_ o: JObject) { print(JS.stringify(.object(o))) }

    private static func resultJson(_ r: PartyResult) -> JSONValue {
        .object(["id": .int(Int64(r.id)), "n": .int(Int64(r.n)), "Q": .int(Int64(r.Q)),
                 "composed": .object(["allow": .int(Int64(r.composed.allow)), "t": .int(Int64(r.composed.t)), "rQuant": .int(Int64(r.composed.rQuant))]),
                 "transcriptDigest": .string(r.transcriptDigest), "multiplications": .int(Int64(r.multiplications)), "opens": .int(Int64(r.opens)),
                 "offlineMode": .string(r.offlineMode), "macKeys": .int(Int64(r.macKeys)), "sacrificedTriples": .int(Int64(r.sacrificedTriples)),
                 "sacrificePartners": .int(Int64(r.sacrificePartners)), "identifiableAbort": .bool(r.identifiableAbort)])
    }

    private static func links(_ mesh: Mesh) -> JSONValue {
        .array(mesh.stats().map { .object(["peer": .int(Int64($0.peer)), "appBytesOut": .int($0.appBytesOut), "appBytesIn": .int($0.appBytesIn),
                                            "framesOut": .int($0.framesOut), "framesIn": .int($0.framesIn)]) })
    }

    private static func abortJson(_ role: String, _ id: Int, _ e: NetAbort) -> JObject {
        func opt(_ x: Int?) -> JSONValue { x.map { JSONValue.int(Int64($0)) } ?? JSONValue.null }
        func optS(_ x: String?) -> JSONValue { x.map { JSONValue.string($0) } ?? JSONValue.null }
        return ["ok": .bool(false), "role": .string(role), "id": .int(Int64(id)),
                "error": .object(["kind": .string(e.kind), "blamed": opt(e.blamed), "reporter": .int(Int64(e.reporter)), "claimedKind": optS(e.claimedKind),
                                  "claimedBlame": opt(e.claimedBlame), "reason": optS(e.reason), "evidence": e.evidence ?? .null, "deadlineMs": opt(e.deadlineMs), "message": .string(e.message)])]
    }

    private static func read(_ path: String) throws -> String {
        guard let d = FileManager.default.contents(atPath: path) else { throw ConfigError(description: "cannot read \(path)") }
        return String(decoding: d, as: UTF8.self)
    }

    /// Runs the node and returns the process exit code (0 ok, 3 abort or refusal).
    public static func run(_ argv: [String], env: [String: String] = ProcessInfo.processInfo.environment) -> Int32 {
        do {
            if argv.count >= 2 && argv[0] == "keygen" {
                let id = try NetCerts.generateIdentity(argv[1], argv.count > 2 ? argv[2] : "mpc-node")
                emit(["keyPath": .string(id.keyPath), "certPath": .string(id.certPath)])
                return 0
            }
            guard argv.count == 1 else { throw ConfigError(description: "usage: pca-mpc-party <config.json> | keygen <dir> <cn>") }
            return try runNode(try obj(try StrictJSON.parseLenient(try read(argv[0])), "config"), env)
        } catch {
            emit(["ok": .bool(false), "error": .object(["kind": .string("local"), "message": .string("\(error)")])])
            return 3
        }
    }

    private static func runNode(_ cfg: JSONValue, _ env: [String: String]) throws -> Int32 {
        let role = try str(cfg.jGet("role"), "role")
        let id = try num(cfg.jGet("id"), "id")
        let hooks = has(cfg, "behavior") || has(cfg, "frameFault") || has(cfg, "dealerFault")
        if hooks && !(cfg.jGet("unsafeTestHooks") == .bool(true) && env["PCA_MPC_UNSAFE_TEST_HOOKS"] == "1") {
            emit(abortJson(role, id, NetAbort(kind: "local", blamed: nil, reporter: id, detail: "refusing to start: test hooks are not enabled in this environment")))
            return 3
        }
        if has(cfg, "frameFault") {
            emit(abortJson(role, id, NetAbort(kind: "local", blamed: nil, reporter: id, detail: "refusing to start: frame faults are not supported by this node")))
            return 3
        }
        if !["party", "dealer", "ot-sender", "ot-receiver"].contains(role) {
            emit(abortJson(role, id, NetAbort(kind: "local", blamed: nil, reporter: id, detail: "refusing to start: unknown role '\(role)' (this node runs a party, the dealer or an ot-* role)")))
            return 3
        }
        let n = try num(cfg.jGet("n"), "n")
        var nodes: [NodeAddr] = []
        guard let nodeList = cfg.jGet("nodes")?.jArr else { throw ConfigError(description: "config: nodes must be an array") }
        for x in nodeList {
            nodes.append(NodeAddr(id: try num(x.jGet("id"), "node id"), host: try str(x.jGet("host"), "host"), port: try num(x.jGet("port"), "port"),
                                  certPem: try read(try str(x.jGet("certPath"), "certPath"))))
        }
        var mc = MeshConfig(selfId: id, nodes: nodes, keyPem: try read(try str(cfg.jGet("keyPath"), "keyPath")), certPem: try read(try str(cfg.jGet("certPath"), "certPath")),
                            sessionId: try str(cfg.jGet("sessionId"), "sessionId"))
        if role == "dealer" { mc.linkTo = nodes.filter { $0.id < n }.map { $0.id } }
        if has(cfg, "listenHost") { mc.listenHost = try str(cfg.jGet("listenHost"), "listenHost") }
        if has(cfg, "recvTimeoutMs") { mc.recvTimeoutMs = Int64(try num(cfg.jGet("recvTimeoutMs"), "recvTimeoutMs")) }
        if has(cfg, "connectTimeoutMs") { mc.connectTimeoutMs = Int64(try num(cfg.jGet("connectTimeoutMs"), "connectTimeoutMs")) }
        let mesh = try Mesh(mc)
        let Q: Int? = has(cfg, "Q") ? try num(cfg.jGet("Q"), "Q") : nil
        let t0 = DispatchTime.now().uptimeNanoseconds
        defer {
            Thread.sleep(forTimeInterval: 0.3) // give sockets a moment to flush abort frames
            mesh.kill()
        }
        do {
            try mesh.connect()
            var res: JObject = ["ok": .bool(true), "role": .string(role), "id": .int(Int64(id)),
                                "connectMs": .int(Int64((DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000))]
            if role == "dealer" {
                var d = DealerConfig(n: n, mesh: mesh)
                d.Q = Q
                d.insecureTrustedDealer = cfg.jGet("insecureTrustedDealer") == .bool(true)
                if has(cfg, "dealerSeed") {
                    guard let s = PCAMpc.Field.low64(try str(cfg.jGet("dealerSeed"), "dealerSeed")) else { throw ConfigError(description: "config: dealerSeed must be a decimal integer") }
                    d.seed = s
                }
                if has(cfg, "dealerFault") {
                    let df = try obj(cfg.jGet("dealerFault"), "dealerFault")
                    func big(_ v: JSONValue?, _ what: String) throws -> UInt64? {
                        guard let v = v, v != .null else { return nil }
                        guard let x = PCAMpc.Field.parse(try str(v, what)) else { throw ConfigError(description: "config: \(what) must be a decimal integer") }
                        return x
                    }
                    let keep = try big(df.jGet("keepCDelta"), "keepCDelta")
                    var partners: [UInt64?]? = nil
                    if let arr = df.jGet("partnerCDelta")?.jArr { partners = try arr.map { try big($0, "partnerCDelta") } }
                    d.fault = PCAMpc.Spdz.DealerFault(keepCDelta: keep, partnerCDelta: partners)
                    if has(df, "macFaultAtInput") { d.macFaultAtInput = try num(df.jGet("macFaultAtInput"), "macFaultAtInput") }
                }
                try NetProtocol.runDealer(d)
            } else if role == "ot-sender" || role == "ot-receiver" {
                let ot = cfg.jGet("ot")
                let kind = try has(cfg, "ot") ? str(ot?.jGet("kind"), "ot.kind") : "ec"
                let count = try has(cfg, "ot") ? num(ot?.jGet("count"), "ot.count") : 128
                let r = role == "ot-sender" ? try NetOtNet.runOtSender(mesh, peer: 1, kind: kind, count: count) : try NetOtNet.runOtReceiver(mesh, peer: 0, kind: kind, count: count)
                res["result"] = .object(["kind": .string(r.kind), "role": .string(r.role), "count": .int(Int64(r.count)), "ms": .int(r.ms), "wasmCurveActive": .bool(false),
                                         "matched": .bool(r.matched), "padDigest": .string(r.padDigest)])
            } else {
                let inp = try obj(cfg.jGet("input"), "input")
                var c = PartyConfig(id: id, n: n, input: DecisionVector(allow: try num(inp.jGet("allow"), "allow"), t: try num(inp.jGet("t"), "t"), rQuant: try num(inp.jGet("rQuant"), "rQuant")),
                                    mesh: mesh, sessionId: mc.sessionId)
                c.Q = Q
                if has(cfg, "offline") { c.offline = try str(cfg.jGet("offline"), "offline") }
                c.insecureTrustedDealer = cfg.jGet("insecureTrustedDealer") == .bool(true)
                if has(cfg, "behavior") {
                    let b = try obj(cfg.jGet("behavior"), "behavior")
                    c.behavior = Behavior(kind: try str(b.jGet("kind"), "behavior.kind"), round: has(b, "round") ? try str(b.jGet("round"), "behavior.round") : "")
                    c.unsafeTestHooks = true
                }
                res["result"] = resultJson(try NetProtocol.runParty(c))
            }
            res["links"] = links(mesh)
            res["events"] = .array(mesh.events().map { .string($0) })
            emit(res)
            return 0
        } catch is CrashParty {
            // the reference exits the process abruptly (exit code 7) with no output: peers see the links drop
            mesh.kill()
            return 7
        } catch is SilentParty {
            var m = abortJson(role, id, NetAbort(kind: "local", blamed: nil, reporter: id, detail: "silent"))
            m["links"] = links(mesh)
            m["events"] = .array(mesh.events().map { .string($0) })
            emit(m)
            return 3
        } catch {
            let f = mesh.failed()
            let ne = (error as? NetAbort) ?? f ?? NetAbort(kind: "local", blamed: nil, reporter: id, detail: "\(error)")
            var m = abortJson(role, id, ne)
            m["links"] = links(mesh)
            m["events"] = .array(mesh.events().map { .string($0) })
            emit(m)
            return 3
        }
    }
}
