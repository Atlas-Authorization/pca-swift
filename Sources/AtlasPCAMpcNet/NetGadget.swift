import Foundation
import AtlasPCAVerify
import AtlasPCAMpc

/// Agreement on the joint choice-bit gadget seeds: a signed commit-reveal with an echo round, so ONE corrupt party cannot make honest parties derive
/// different gadgets and then blame each other. Every commitment and opening is signed with the sender's pinned TLS identity key; after the reveal each
/// party echoes the signed values it got from every third party (round gd-e). An echoed signature that does not verify blames the echoer; a verifying
/// statement that differs from the one received directly blames the signer with both statements as transferable evidence. With n = 2 the echo is skipped.
public enum NetGadget {
    private static func isSigned(_ x: JSONValue?, _ valueLen: Int) -> Bool {
        guard let v = x?.jGet("v")?.jStr, NetUtil.isHex(v, valueLen), let s = x?.jGet("s")?.jStr else { return false }
        let u = s.utf8
        return u.count >= 16 && u.count <= 200 && u.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
    }

    private static func signed(_ mesh: Mesh, _ round: String, _ value: String) -> JSONValue {
        let sig = (try? mesh.sign(PCAMpc.NetCodec.gadgetStatement(mesh.sessionId, round, mesh.selfId, value))) ?? []
        return .object(["v": .string(value), "s": .string(NetUtil.hex(sig))])
    }

    private static func check(_ mesh: Mesh, _ signer: Int, _ round: String, _ m: JSONValue) -> Bool {
        guard let v = m.jGet("v")?.jStr, let s = m.jGet("s")?.jStr, let sig = NetUtil.unhex(s) else { return false }
        return mesh.verify(signer, PCAMpc.NetCodec.gadgetStatement(mesh.sessionId, round, signer, v), sig)
    }

    public static func agreeGadgetSeeds(_ mesh: Mesh, _ n: Int, _ io: Exchanger, mySeed: [UInt8]? = nil) throws -> [[UInt8]] {
        let seed = mySeed ?? NetUtil.random(32)
        let id = mesh.selfId
        let sid = mesh.sessionId
        let myCommit = PCAMpc.NetCodec.gadgetCommit(sid, id, seed)
        let commits: [Int: JSONValue] = try io.exchange("gd-c", { _ in signed(mesh, "gd-c", myCommit) }, { p, raw in
            guard isSigned(raw, 64) else { throw io.bad(p, "bad gadget commitment") }
            guard check(mesh, p, "gd-c", raw) else { throw io.bad(p, "gadget commitment signature does not verify") }
            return raw
        })
        let mySeedHex = NetUtil.hex(seed)
        let opens: [Int: JSONValue] = try io.exchange("gd-o", { _ in signed(mesh, "gd-o", mySeedHex) }, { p, raw in
            guard isSigned(raw, 64) else { throw io.bad(p, "bad gadget seed") }
            guard check(mesh, p, "gd-o", raw) else { throw io.bad(p, "gadget seed signature does not verify") }
            guard let sd = NetUtil.unhex(raw.jGet("v")!.jStr!), PCAMpc.NetCodec.gadgetCommit(sid, p, sd) == commits[p]!.jGet("v")!.jStr! else {
                throw NetAbort(kind: "commitment", blamed: p, reporter: id, detail: "party \(p) opened a gadget seed that does not match its commitment")
            }
            return raw
        })
        if n >= 3 {
            let others = (0..<n).filter { $0 != id }
            _ = try io.exchange("gd-e", { peer in
                .array(others.filter { $0 != peer }.map { (j: Int) -> JSONValue in
                    JSONValue.object(["j": .int(Int64(j)), "c": commits[j]!, "o": opens[j]!])
                })
            }, { p, raw in
                let expect = others.filter { $0 != p }
                guard let arr = raw.jArr, arr.count == expect.count else { throw io.bad(p, "bad gadget echo") }
                for (k, j) in expect.enumerated() {
                    let e = arr[k]
                    guard e.jObj != nil, NetUtil.int(e.jGet("j")) == j, isSigned(e.jGet("c"), 64), isSigned(e.jGet("o"), 64) else { throw io.bad(p, "bad gadget echo entry") }
                    let ec = e.jGet("c")!, eo = e.jGet("o")!
                    // a statement that does not verify under j's pinned key was forged by the echoer p
                    guard check(mesh, j, "gd-c", ec), check(mesh, j, "gd-o", eo) else { throw io.bad(p, "gadget echo carries a statement that party \(j) did not sign") }
                    let mineC = commits[j]!, mineO = opens[j]!
                    let cDiff = ec.jGet("v") != mineC.jGet("v")
                    if cDiff || eo.jGet("v") != mineO.jGet("v") {
                        // both statements verify under j's key and differ: j signed two values for one round
                        let ev: JSONValue = .object(["signer": .int(Int64(j)), "round": .string(cDiff ? "gd-c" : "gd-o"), "statements": .array(cDiff ? [mineC, ec] : [mineO, eo])])
                        throw NetAbort(kind: "equivocation", blamed: j, reporter: id,
                                       detail: "party \(j) signed different gadget \(cDiff ? "commitments" : "seeds") for different parties (shown by party \(p)'s echo)", evidence: ev)
                    }
                }
                return true
            })
        }
        return (0..<n).map { p in p == id ? seed : NetUtil.unhex(opens[p]!.jGet("v")!.jStr!)! }
    }
}

/// Commit-first disclosure exchange for a failed triple (dealer-free mode). Nobody opens before every commitment is in hand (round forensic-c completes
/// first), so no party's disclosure can depend on another's; an opening that does not match its commitment is blamed, a late or absent party times out
/// at the shared deadline.
public enum NetForensic {
    /// Every OTHER party's verified disclosure.
    public static func exchangeDisclosures(_ sessionId: String, _ id: Int, _ n: Int, _ tripleIndex: Int, _ mine: [PCAMpc.NetForensics.SlotDisclosure], _ slots: Int, _ rows: Int,
                                           _ deadlineMs: Int64, _ io: Exchanger) throws -> [Int: [PCAMpc.NetForensics.SlotDisclosure]] {
        let wire = PCAMpc.NetForensics.wireDisclosure(mine)
        let nonce = NetUtil.hex(NetUtil.random(32))
        let myCommit = PCAMpc.NetForensics.disclosureCommit(sessionId, id, tripleIndex, deadlineMs, nonce, wire)
        let commits: [Int: String] = try io.exchange("forensic-c", { _ in .object(["c": .string(myCommit), "d": .int(deadlineMs)]) }, { p, raw in
            guard NetUtil.isHex(raw.jGet("c")?.jStr, 64) else { throw io.bad(p, "bad forensic commitment") }
            guard IV.num(raw.jGet("d")) == Double(deadlineMs) else { throw io.bad(p, "forensic deadline differs from the agreed \(deadlineMs)") }
            return raw.jGet("c")!.jStr!
        }, timeoutMs: deadlineMs)
        return try io.exchange("forensic-o", { _ in .object(["w": wire, "nonce": .string(nonce)]) }, { p, raw in
            guard NetUtil.isHex(raw.jGet("nonce")?.jStr, 64) else { throw io.bad(p, "bad forensic opening") }
            let w = raw.jGet("w") ?? .null
            let c = PCAMpc.NetForensics.disclosureCommit(sessionId, p, tripleIndex, deadlineMs, raw.jGet("nonce")!.jStr!, w)
            guard c == commits[p]! else {
                throw NetAbort(kind: "commitment", blamed: p, reporter: id, detail: "party \(p) opened a forensic disclosure that does not match its commitment")
            }
            return try PCAMpc.NetForensics.parseDisclosure(w, slots, rows, (0..<n).filter { $0 != p })
        }, timeoutMs: deadlineMs)
    }
}
