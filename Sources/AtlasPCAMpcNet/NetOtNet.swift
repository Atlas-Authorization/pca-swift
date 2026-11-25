import Foundation
import AtlasPCAVerify
import AtlasPCAMpc

private typealias NetOt = PCAMpc.NetOt

/// Pairwise base oblivious transfer OVER THE NETWORK (research prototype): the malicious-secure Chou-Orlandi-style base OT on Ed25519 (Schnorr proof of
/// knowledge, subgroup validation of every received point), for the `ot-sender` / `ot-receiver` roles of the party program. A FUNCTIONAL-CORRECTNESS
/// demonstration: afterwards the receiver reveals its choice bits and a hash of each received pad (a demo-only step, NOT part of the OT) so the sender can
/// check the pads over a real network. The post-quantum endemic-LWE kind ("lwe") runs only when the build links the separate AtlasPCALweOt product (see NetOtNetLwe.swift); without it a "lwe" request aborts locally (it never falls back to "ec").
public enum NetOtNet {
    public struct Result {
        public let kind: String
        public let role: String
        public let count: Int
        public let ms: Int64
        public let matched: Bool
        public let padDigest: String
    }

    private static func now() -> Int64 { Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000) }

    static func sha(_ parts: [[UInt8]]) -> String { NetUtil.hex(NetUtil.sha256(parts)) }

    static func fail(_ mesh: Mesh, _ kind: String, _ peer: Int?, _ detail: String) -> NetAbort {
        let ne = NetAbort(kind: kind, blamed: peer, reporter: mesh.selfId, detail: detail)
        mesh.fail(ne, nil)
        return ne
    }

    /// Wraps peer-supplied data parsing so any failure aborts naming the peer.
    static func parsing<T>(_ mesh: Mesh, _ peer: Int, _ rd: String, _ f: () throws -> T) throws -> T {
        do { return try f() } catch let e as NetAbort { throw e } catch {
            throw fail(mesh, "malformed", peer, "round '\(rd)': \(error)")
        }
    }

    /// Binding of a base OT on this mesh: session (hashed to a fixed length), who sends, who receives, which round.
    static func binding(_ mesh: Mesh, _ sender: Int, _ receiver: Int, _ round: String) -> PCAMpc.NetOt.Binding {
        NetOt.Binding(sessionId: NetOt.sessionBytes(mesh.sessionId), sender: sender, receiver: receiver, round: round)
    }

    private static func senderPads(_ mesh: Mesh, _ peer: Int, _ kind: String, _ count: Int) throws -> [[[UInt8]]] {
        switch kind {
        case "ec":
            let sender = try NetOt.BaseSender(binding(mesh, mesh.selfId, peer, "ot-ec"))
            try mesh.send(peer, "ot-S", sender.message())
            let rRaw = try mesh.recv(peer, "ot-R")
            do { return try sender.derive(rRaw, count: count) } catch let e as NetAbort { throw e } catch {
                throw fail(mesh, "malformed", peer, "round 'ot-R': \(error)")
            }
        case "lwe": return try lweSenderPads(mesh, peer, count)
        default: throw fail(mesh, "local", nil, "unknown ot kind '\(kind)' (expected 'ec' or 'lwe')")
        }
    }

    private static func receiverPads(_ mesh: Mesh, _ peer: Int, _ kind: String, _ choices: [Int]) throws -> [[UInt8]] {
        switch kind {
        case "ec":
            let sRaw = try mesh.recv(peer, "ot-S")
            let recv: NetOt.BaseReceiver
            do { recv = try NetOt.BaseReceiver(sMessage: sRaw, choices: choices, binding(mesh, peer, mesh.selfId, "ot-ec")) } catch let e as NetAbort { throw e } catch {
                throw fail(mesh, NetOt.isCheckFailure(error) ? "commitment" : "malformed", peer, "\(error)")
            }
            try mesh.send(peer, "ot-R", recv.message)
            return recv.recvPads
        case "lwe": return try lweReceiverPads(mesh, peer, choices)
        default: throw fail(mesh, "local", nil, "unknown ot kind '\(kind)' (expected 'ec' or 'lwe')")
        }
    }

    public static func runOtSender(_ mesh: Mesh, peer: Int, kind: String, count: Int) throws -> Result {
        let t0 = now()
        let pads = try senderPads(mesh, peer, kind, count)
        // demo-only verification: the receiver reveals choices + pad hashes
        let v = try mesh.recv(peer, "ot-verify")
        let ok: Bool = try parsing(mesh, peer, "ot-verify") {
            guard let cs = v.jGet("choices")?.jArr, let hs = v.jGet("padHashes")?.jArr, cs.count == count, hs.count == count else { throw NetError("bad verify message") }
            for i in 0..<count {
                guard let c = NetUtil.int(cs[i]), c == 0 || c == 1, sha([pads[i][c]]) == hs[i].jStr else { return false }
            }
            return true
        }
        try mesh.send(peer, "ot-done", .object(["matched": .bool(ok)]))
        mesh.finish()
        return Result(kind: kind, role: "sender", count: count, ms: now() - t0, matched: ok, padDigest: sha(pads.flatMap { $0 }))
    }

    public static func runOtReceiver(_ mesh: Mesh, peer: Int, kind: String, count: Int) throws -> Result {
        let t0 = now()
        guard kind == "ec" || kind == "lwe" else { throw fail(mesh, "local", nil, "unknown ot kind '\(kind)' (expected 'ec' or 'lwe')") }
        let choices = NetUtil.random(count).map { Int($0 & 1) }
        let recvPads = try receiverPads(mesh, peer, kind, choices)
        try mesh.send(peer, "ot-verify", .object(["choices": .array(choices.map { .int(Int64($0)) }), "padHashes": .array(recvPads.map { .string(sha([$0])) })]))
        let d = try mesh.recv(peer, "ot-done")
        let matched = d.jGet("matched") == .bool(true)
        mesh.finish()
        return Result(kind: kind, role: "receiver", count: count, ms: now() - t0, matched: matched, padDigest: sha(recvPads))
    }
}
