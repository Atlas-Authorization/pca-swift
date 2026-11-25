import Foundation
import Dispatch
import NIOCore
import NIOPosix
import AtlasPCAVerify
import AtlasPCAMpc

/// What a node ended with: a result (parties only), or the error that stopped it.
public struct NodeOutput {
    public let id: Int
    public let role: String
    public let result: PartyResult?
    public let error: Error?
    public var abort: NetAbort? { error as? NetAbort }
}

public struct Launched {
    public let outputs: [NodeOutput]
    public let wallMs: Int64
}

/// TEST ONLY: route node `dialer`'s connection to node `target` through a byte-level fault proxy.
public struct WireFaultSpec {
    public var dialer: Int
    public var target: Int
    public var fault: WireFault
    public init(dialer: Int, target: Int, fault: WireFault) { self.dialer = dialer; self.target = target; self.fault = fault }
}

public struct LaunchOptions {
    public var n: Int
    public var Q: Int?
    public var vectors: [DecisionVector]
    public var recvTimeoutMs: Int64 = 30_000
    public var connectTimeoutMs: Int64 = 120_000
    /// Hard wall-clock cap for the whole run.
    public var killAfterMs: Int64 = 120_000
    /// TEST ONLY: protocol misbehaviour per node id (parties only).
    public var behaviors: [Int: Behavior] = [:]
    /// "no-dealer" (default) or "trusted-dealer" (spawns a dealer node; needs insecureTrustedDealer).
    public var offline = "no-dealer"
    public var insecureTrustedDealer = false
    public var dealerSeed: UInt64?
    public var dealerFault: PCAMpc.Spdz.DealerFault?
    public var macFaultAtInput: Int?
    public var wireFault: WireFaultSpec?
    /// TEST ONLY: application-layer frame tampering per node id (the node then runs with its test hooks on).
    public var tamper: [Int: (TamperEvent) -> [[UInt8]]] = [:]
    /// TEST ONLY: derive every node's key from this seed (no key is ever stored); nil means fresh keys from the CSPRNG.
    public var identitySeed: [UInt8]?
    /// Time source of every node's mesh (default: the wall clock).
    public var clock: MeshClock?
    public init(n: Int, vectors: [DecisionVector]) { self.n = n; self.vectors = vectors }
}

/// Launches n parties (and, for the trusted-dealer mode, a dealer node) in this process on loopback, each with its own fresh per-run identity, its own
/// mutual-TLS mesh and its own thread, and collects what every node ended with. The nodes talk only over TLS sockets, exactly as separate hosts would;
/// a stuck run is cut off after `killAfterMs`.
public enum NetLaunch {
    private final class Slot {
        let done = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var output: NodeOutput?
        func put(_ o: NodeOutput) { lock.lock(); if output == nil { output = o }; lock.unlock(); done.signal() }
        func get() -> NodeOutput? { lock.lock(); defer { lock.unlock() }; return output }
    }

    private final class Counters {
        let lock = NSLock()
        var active: Int
        var idle = 0
        init(_ a: Int) { active = a }
        func finish() { lock.lock(); active -= 1; lock.unlock() }
        func goIdle() { lock.lock(); idle += 1; lock.unlock() }
        var othersRunning: Bool { lock.lock(); defer { lock.unlock() }; return active > idle }
    }

    private static func role(_ dealerMode: Bool, _ id: Int, _ n: Int) -> String { dealerMode && id == n ? "dealer" : "party" }

    public static func launch(_ o: LaunchOptions) throws -> Launched {
        let n = o.n
        guard o.vectors.count == n else { throw NetError("launchLocal: one decision vector per party") }
        let dealerMode = o.offline == "trusted-dealer"
        guard !dealerMode || o.insecureTrustedDealer else { throw NetError("launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer") }
        let nodeCount = dealerMode ? n + 1 : n
        let sessionId = NetUtil.hex(NetUtil.random(8))
        // bind first: every node binds port 0 itself and keeps it; only then is any node told a peer's real port (no port is probed and released)
        var nodes: [NodeAddr] = []
        var idents: [NetCerts.Identity] = []
        for i in 0..<nodeCount {
            let ident = try NetCerts.generate(cn: "mpc-node-\(i)", seed: o.identitySeed.map { $0 + [UInt8(i)] })
            idents.append(ident)
            nodes.append(NodeAddr(id: i, host: "127.0.0.1", port: 0, certPem: ident.certPem))
        }
        var meshes: [Mesh] = []
        var proxy: FaultProxy?
        do {
            for i in 0..<nodeCount {
                var c = MeshConfig(selfId: i, nodes: nodes, keyPem: idents[i].keyPem, certPem: idents[i].certPem, sessionId: sessionId)
                c.listenHost = "127.0.0.1"
                c.recvTimeoutMs = o.recvTimeoutMs
                c.connectTimeoutMs = o.connectTimeoutMs
                c.clock = o.clock
                if let tam = o.tamper[i] {
                    c.tamper = tam
                    c.unsafeTestHooks = true
                }
                if dealerMode && i == n { c.linkTo = Array(0..<n) }
                meshes.append(try Mesh(c))
            }
            let ports = try meshes.map { try $0.listen() }
            for i in 0..<nodeCount { for j in 0..<nodeCount where j != i { try meshes[i].setPeerPort(j, ports[j]) } }
            if let w = o.wireFault {
                // the proxy binds port 0 too and stands in for the target in the dialer's view
                proxy = FaultProxy(listenPort: 0, targetHost: "127.0.0.1", targetPort: ports[w.target], fault: w.fault)
                try proxy!.listen()
                try meshes[w.dialer].setPeerPort(w.target, proxy!.port)
            }
        } catch {
            for m in meshes { m.kill() }
            proxy?.close()
            throw error
        }
        let t0 = DispatchTime.now().uptimeNanoseconds
        let counters = Counters(nodeCount)
        let slots = (0..<nodeCount).map { _ in Slot() }
        for i in 0..<nodeCount {
            let mesh = meshes[i]
            Thread.detachNewThread {
                let out = runNode(o, i, n, dealerMode, mesh, sessionId, counters)
                counters.finish()
                slots[i].put(out)
            }
        }
        var outs: [NodeOutput] = []
        let deadline = DispatchTime.now() + .milliseconds(Int(o.killAfterMs))
        for i in 0..<nodeCount {
            if slots[i].done.wait(timeout: deadline) == .timedOut {
                // a hang is a failure: cut the straggler off and record it
                for m in meshes { m.kill() }
                slots[i].put(NodeOutput(id: i, role: role(dealerMode, i, n), result: nil, error: NetAbort(kind: "local", blamed: nil, reporter: i, detail: "killed after \(o.killAfterMs)ms")))
            }
            outs.append(slots[i].get()!)
        }
        for m in meshes { m.kill() }
        proxy?.close()
        return Launched(outputs: outs, wallMs: Int64((DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000))
    }

    private static func runNode(_ o: LaunchOptions, _ id: Int, _ n: Int, _ dealerMode: Bool, _ mesh: Mesh, _ sessionId: String, _ counters: Counters) -> NodeOutput {
        let role = NetLaunch.role(dealerMode, id, n)
        do {
            try mesh.connect()
            if role == "dealer" {
                var d = DealerConfig(n: n, mesh: mesh)
                d.insecureTrustedDealer = o.insecureTrustedDealer
                d.Q = o.Q
                d.seed = o.dealerSeed
                d.fault = o.dealerFault
                d.macFaultAtInput = o.macFaultAtInput
                try NetProtocol.runDealer(d)
                return NodeOutput(id: id, role: role, result: nil, error: nil)
            }
            var c = PartyConfig(id: id, n: n, input: o.vectors[id], mesh: mesh, sessionId: sessionId)
            c.Q = o.Q
            c.offline = dealerMode ? "trusted-dealer" : "no-dealer"
            c.insecureTrustedDealer = o.insecureTrustedDealer
            if let b = o.behaviors[id] {
                c.behavior = b
                c.unsafeTestHooks = true
            }
            return NodeOutput(id: id, role: role, result: try NetProtocol.runParty(c), error: nil)
        } catch is CrashParty {
            mesh.kill()
            return NodeOutput(id: id, role: role, result: nil, error: CrashParty())
        } catch is SilentParty {
            // stays connected and stops participating; peers must time out. Idle until every other node has finished.
            counters.goIdle()
            while counters.othersRunning { Thread.sleep(forTimeInterval: 0.05) }
            return NodeOutput(id: id, role: role, result: nil, error: SilentParty())
        } catch {
            var e: Error = error
            if !(error is NetAbort), let f = mesh.failed() { e = f }
            return NodeOutput(id: id, role: role, result: nil, error: e)
        }
    }
}
