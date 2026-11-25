import Foundation
import AtlasPCAVerify
import AtlasPCAMpc
#if canImport(AtlasPCALweOt)
import AtlasPCALweOt
#endif

/// The post-quantum endemic-LWE kind of the base OT over the mesh (wire-compatible with the reference: `ot-recv` {rn, points, rhos} in base64, then `ot-ct`).
/// Compiled against AtlasPCALweOt only when the package is built with ATLAS_PCA_LWEOT=1 (liblweot present); otherwise a "lwe" request aborts locally.
extension NetOtNet {
#if canImport(AtlasPCALweOt)
    private static func b64(_ b: [UInt8]) -> JSONValue { .string(Data(b).base64EncodedString()) }

    /// Strict base64 (re-encoding must reproduce the input: no padding or trailing-bit aliases), optionally of an exact length.
    private static func unb64(_ v: JSONValue?, _ len: Int? = nil) throws -> [UInt8] {
        guard let s = v?.jStr, s.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || $0 == 43 || $0 == 47 || $0 == 61 }),
              let d = Data(base64Encoded: s), d.base64EncodedString() == s else { throw NetError("bad base64") }
        if let len = len, d.count != len { throw NetError("bad length") }
        return Array(d)
    }

    private static func pairs(_ v: JSONValue?, _ count: Int) throws -> [[[UInt8]]] {
        guard let a = v?.jArr, a.count == count else { throw NetError("bad array") }
        return try a.map { p in
            guard let q = p.jArr, q.count == 2 else { throw NetError("bad pair") }
            return [try unb64(q[0]), try unb64(q[1])]
        }
    }

    static func lweSenderPads(_ mesh: Mesh, _ peer: Int, _ count: Int) throws -> [[[UInt8]]] {
        let m = try mesh.recv(peer, "ot-recv")
        let msg: EndemicReceiverMessage = try parsing(mesh, peer, "ot-recv") {
            guard m.jObj != nil, let rhos = m.jGet("rhos")?.jArr, rhos.count == count else { throw NetError("bad receiver message") }
            return EndemicReceiverMessage(rn: try unb64(m.jGet("rn"), 32), points: try pairs(m.jGet("points"), count), rhos: try rhos.map { try unb64($0, 32) })
        }
        let sm: EndemicSenderMessage
        do { sm = try EndemicOt.sendRandom(msg) } catch { throw fail(mesh, "malformed", peer, "lwe sender: \(error)") }
        try mesh.send(peer, "ot-ct", .array(sm.ciphertexts.map { .array([b64($0[0]), b64($0[1])]) }))
        return sm.senderPads
    }

    static func lweReceiverPads(_ mesh: Mesh, _ peer: Int, _ choices: [Int]) throws -> [[UInt8]] {
        let r: (message: EndemicReceiverMessage, state: EndemicReceiverState)
        do { r = try EndemicOt.receive(choices) } catch { throw fail(mesh, "local", nil, "lwe receiver: \(error)") }
        let message = r.message, state = r.state
        try mesh.send(peer, "ot-recv", .object(["rn": b64(message.rn), "points": .array(message.points.map { .array([b64($0[0]), b64($0[1])]) }),
                                                 "rhos": .array(message.rhos.map { b64($0) })]))
        let ctRaw = try mesh.recv(peer, "ot-ct")
        return try parsing(mesh, peer, "ot-ct") {
            try EndemicOt.recoverRandom(state, EndemicSenderMessage(ciphertexts: try pairs(ctRaw, choices.count), senderPads: []))
        }
    }
#else
    static func lweSenderPads(_ mesh: Mesh, _ peer: Int, _ count: Int) throws -> [[[UInt8]]] { throw unavailable(mesh) }
    static func lweReceiverPads(_ mesh: Mesh, _ peer: Int, _ choices: [Int]) throws -> [[UInt8]] { throw unavailable(mesh) }

    private static func unavailable(_ mesh: Mesh) -> NetAbort {
        fail(mesh, "local", nil, "ot kind 'lwe' needs a build with ATLAS_PCA_LWEOT=1 (liblweot present); refusing instead of running 'ec'")
    }
#endif
}
