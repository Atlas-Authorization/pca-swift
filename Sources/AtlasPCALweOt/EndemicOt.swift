import CryptoKit
import Foundation

/// A source of random bytes for OT needs.
public protocol LweOtRandom: AnyObject {
    func bytes(_ n: Int) -> [UInt8]
}

/// The CSPRNG-backed default.
public final class SecureLweOtRandom: LweOtRandom {
    public init() {}
    public func bytes(_ n: Int) -> [UInt8] {
        var b = [UInt8](repeating: 0, count: n)
        var g = SystemRandomNumberGenerator()
        for i in 0..<n { b[i] = UInt8.random(in: 0...255, using: &g) }
        return b
    }
}

/// A deterministic SplitMix64 stream, each 64-bit draw consumed least-significant byte first (reproducible tests only).
public final class SplitMix64Stream: LweOtRandom {
    private var s: UInt64
    public init(seed: UInt64) { s = seed }
    private func next() -> UInt64 {
        s = s &+ 0x9e3779b97f4a7c15
        var z = s
        z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
        z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
        return z ^ (z >> 31)
    }
    public func bytes(_ n: Int) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(n)
        while out.count < n {
            var v = next()
            var i = 0
            while i < 8 && out.count < n { out.append(UInt8(truncatingIfNeeded: v)); v >>= 8; i += 1 }
        }
        return out
    }
}

public struct EndemicReceiverMessage {
    public var rn: [UInt8]
    /// Per transfer, the ordered ring-vector pair `[P_0, P_1]`.
    public var points: [[[UInt8]]]
    public var rhos: [[UInt8]]
    public init(rn: [UInt8], points: [[[UInt8]]], rhos: [[UInt8]]) { self.rn = rn; self.points = points; self.rhos = rhos }
}

public struct EndemicReceiverState {
    public let choices: [Int], secretKeys: [[UInt8]], rhos: [[UInt8]], rn: [UInt8], sid: [UInt8]
}

public struct EndemicSenderMessage {
    public var ciphertexts: [[[UInt8]]]
    public let senderPads: [[[UInt8]]]
    public init(ciphertexts: [[[UInt8]]], senderPads: [[[UInt8]]]) { self.ciphertexts = ciphertexts; self.senderPads = senderPads }
}

public struct EndemicTranscript { public let rn: [UInt8], points: [[[UInt8]]], rhos: [[UInt8]], ciphertexts: [[[UInt8]]], encrypted: [[[UInt8]]], commitments: [[[UInt8]]] }

/// The post-quantum, maliciously-secure endemic base OT (Masny-Rindal over Module-LWE, Kyber-768 K-PKE), the TypeScript package's recommended base OT.
/// The receiver places a real key's offset-by-oracle point at its choice slot and a uniform ring vector at the other, so the sender's effective key for
/// the other slot is uniform and its ciphertext is unrecoverable; the chosen-message form pads and commits each message and aborts on any inconsistency.
/// All lattice work is `LweLattice` (the audited pqc_kyber through liblweot); this enum hashes, xors and marshals bytes. The receiver's real key pair is the
/// FIPS 203 K-PKE.KeyGen(d), the derivation the reference uses, so every receiver message matches it byte for byte.
public enum EndemicOt {
    public static let secretBytes = LweLattice.symBytes
    private static let tagSid = Array("atlas-pca-mpc/endemic-lwe-ot-sid".utf8), tagHpk = Array("atlas-pca-mpc/endemic-lwe-ot-hpk".utf8)
    private static let tagN = Array("atlas-pca-mpc/endemic-lwe-ot-N".utf8), tagPad = Array("atlas-pca-mpc/endemic-lwe-ot-pad".utf8)
    private static let tagCommit = Array("atlas-pca-mpc/endemic-lwe-ot-commit".utf8)

    private static func sha(_ chunks: [UInt8]...) -> [UInt8] {
        var h = SHA256()
        for c in chunks { h.update(data: c) }
        return Array(h.finalize())
    }

    private static func u32(_ x: Int) -> [UInt8] { [UInt8(truncatingIfNeeded: x >> 24), UInt8(truncatingIfNeeded: x >> 16), UInt8(truncatingIfNeeded: x >> 8), UInt8(truncatingIfNeeded: x)] }

    private static func xor(_ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
        guard a.count == b.count else { throw LweOtError.invalid("endemic-ot: XOR length mismatch") }
        return zip(a, b).map { $0 ^ $1 }
    }

    private static func ctEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0
        for i in 0..<a.count { d |= a[i] ^ b[i] }
        return d == 0
    }

    /// `sid = H(TAG || rn)`: binds every oracle query to this receiver nonce.
    public static func sessionId(_ rn: [UInt8]) -> [UInt8] { sha(tagSid, rn) }

    private static func hpk(_ sid: [UInt8], _ i: Int, _ other: [UInt8]) throws -> [UInt8] { try LweLattice.hashToRing(tagHpk + sid + u32(i) + other) }

    /// The pad for a slot: SHA-256 in counter mode over `TAG || sid || i || slot || ctr || payload`.
    public static func pad(_ sid: [UInt8], _ index: Int, _ slot: Int, _ payload: [UInt8], _ len: Int) -> [UInt8] {
        var out: [UInt8] = []
        var ctr = 0
        while out.count < len { out += sha(tagPad, sid, u32(index), [UInt8(slot & 1)], u32(ctr), payload); ctr += 1 }
        return Array(out.prefix(len))
    }

    private static func commit(_ sid: [UInt8], _ i: Int, _ slot: Int, _ msg: [UInt8], _ pad: [UInt8]) -> [UInt8] { sha(tagCommit, sid, u32(i), [UInt8(slot & 1)], msg, pad) }

    /// Receiver round: a real key pair per choice, a uniform vector for the other slot, and `C = t_real - Hpk(sid, i, N)` at the choice slot.
    public static func receive(_ choices: [Int], _ rng: LweOtRandom = SecureLweOtRandom()) throws -> (message: EndemicReceiverMessage, state: EndemicReceiverState) {
        let rn = rng.bytes(LweLattice.symBytes), sid = sessionId(rn)
        var points: [[[UInt8]]] = [], rhos: [[UInt8]] = [], sks: [[UInt8]] = [], kept: [Int] = []
        for (i, ch) in choices.enumerated() {
            let c = ch & 1
            let kp = try LweLattice.keygenFips203(rng.bytes(LweLattice.symBytes))
            let nSlot = try LweLattice.hashToRing(tagN + sid + u32(i) + rng.bytes(LweLattice.symBytes))
            let cPoint = try LweLattice.ringSub(Array(kp.publicKey[0..<LweLattice.tvecBytes]), try hpk(sid, i, nSlot))
            points.append(c == 0 ? [cPoint, nSlot] : [nSlot, cPoint])
            rhos.append(Array(kp.publicKey[LweLattice.tvecBytes...]))
            sks.append(kp.secretKey)
            kept.append(c)
        }
        return (EndemicReceiverMessage(rn: rn, points: points, rhos: rhos), EndemicReceiverState(choices: kept, secretKeys: sks, rhos: rhos, rn: rn, sid: sid))
    }

    private static func validate(_ m: EndemicReceiverMessage) throws {
        guard m.rn.count == LweLattice.symBytes else { throw LweOtError.abort("endemic LWE OT: malformed session nonce") }
        guard m.points.count == m.rhos.count else { throw LweOtError.abort("endemic LWE OT: points/rhos length mismatch") }
        for i in 0..<m.points.count {
            guard m.points[i].count == 2, m.points[i][0].count == LweLattice.tvecBytes, m.points[i][1].count == LweLattice.tvecBytes else {
                throw LweOtError.abort("endemic LWE OT: malformed point pair at index \(i)")
            }
            guard m.rhos[i].count == LweLattice.pkBytes - LweLattice.tvecBytes else { throw LweOtError.abort("endemic LWE OT: malformed rho at index \(i)") }
        }
    }

    /// `pk_b = (P_b + Hpk(sid, i, P_{1-b}) || rho)`
    private static func effectiveKey(_ sid: [UInt8], _ i: Int, _ own: [UInt8], _ other: [UInt8], _ rho: [UInt8]) throws -> [UInt8] {
        try LweLattice.ringAdd(own, try hpk(sid, i, other)) + rho
    }

    /// Sender round (random-OT form): encrypt a fresh payload under each slot's effective key and output both pads. `tamper` is test-only.
    public static func sendRandom(_ message: EndemicReceiverMessage, _ rng: LweOtRandom = SecureLweOtRandom(), tamper: ((inout [[[UInt8]]]) -> Void)? = nil) throws -> EndemicSenderMessage {
        try validate(message)
        let sid = sessionId(message.rn)
        var cts: [[[UInt8]]] = [], pads: [[[UInt8]]] = []
        for i in 0..<message.points.count {
            let p0 = message.points[i][0], p1 = message.points[i][1], rho = message.rhos[i]
            let pk0 = try effectiveKey(sid, i, p0, p1, rho), pk1 = try effectiveKey(sid, i, p1, p0, rho)
            let r0 = rng.bytes(LweLattice.symBytes), r1 = rng.bytes(LweLattice.symBytes)
            let ct0 = try LweLattice.enc(pk0, r0, rng.bytes(LweLattice.symBytes))
            let ct1 = try LweLattice.enc(pk1, r1, rng.bytes(LweLattice.symBytes))
            cts.append([ct0, ct1])
            pads.append([pad(sid, i, 0, r0, secretBytes), pad(sid, i, 1, r1, secretBytes)])
        }
        tamper?(&cts)
        return EndemicSenderMessage(ciphertexts: cts, senderPads: pads)
    }

    /// Receiver recovery (random-OT form): decrypt only the chosen ciphertext.
    public static func recoverRandom(_ state: EndemicReceiverState, _ sm: EndemicSenderMessage) throws -> [[UInt8]] {
        guard sm.ciphertexts.count == state.choices.count else { throw LweOtError.abort("endemic LWE OT: ciphertext count does not match the transfer count") }
        for (i, ct) in sm.ciphertexts.enumerated() {
            guard ct.count == 2, ct[0].count == LweLattice.ctBytes, ct[1].count == LweLattice.ctBytes else { throw LweOtError.abort("endemic LWE OT: malformed ciphertext pair at index \(i)") }
        }
        return try state.choices.enumerated().map { i, c in pad(state.sid, i, c & 1, try LweLattice.dec(state.secretKeys[i], sm.ciphertexts[i][c & 1]), secretBytes) }
    }

    /// In-process chosen-message endemic base OT: `messages[i] = [m0, m1]` of equal length, `choices[i]` in {0,1}. The sender pads and commits each message;
    /// the receiver recovers `m_{choices[i]}` and checks the commitment, aborting on any inconsistency. `senderRng` is the sender's entropy (the receiver's
    /// when nil); `tamperEncrypted` (test-only) corrupts the padded messages on the wire.
    public static func baseOT(_ messages: [[[UInt8]]], _ choices: [Int], _ rng: LweOtRandom = SecureLweOtRandom(), senderRng: LweOtRandom? = nil,
                              tamperEncrypted: ((inout [[[UInt8]]]) -> Void)? = nil) throws -> (received: [[UInt8]], transcript: EndemicTranscript) {
        guard messages.count == choices.count else { throw LweOtError.invalid("endemicBaseOT: messages/choices length mismatch") }
        let srng = senderRng ?? rng
        let (msg, st) = try receive(choices, rng)
        let sid = st.sid
        var cts: [[[UInt8]]] = [], enc: [[[UInt8]]] = [], com: [[[UInt8]]] = []
        for i in 0..<messages.count {
            let m0 = messages[i][0], m1 = messages[i][1]
            guard m0.count == m1.count else { throw LweOtError.invalid("endemicBaseOT (index \(i)): the two messages must be equal length") }
            let p0 = msg.points[i][0], p1 = msg.points[i][1], rho = msg.rhos[i]
            let r0 = srng.bytes(LweLattice.symBytes), r1 = srng.bytes(LweLattice.symBytes)
            let ct0 = try LweLattice.enc(try effectiveKey(sid, i, p0, p1, rho), r0, srng.bytes(LweLattice.symBytes))
            let ct1 = try LweLattice.enc(try effectiveKey(sid, i, p1, p0, rho), r1, srng.bytes(LweLattice.symBytes))
            cts.append([ct0, ct1])
            let pad0 = pad(sid, i, 0, r0, m0.count), pad1 = pad(sid, i, 1, r1, m1.count)
            enc.append([try xor(m0, pad0), try xor(m1, pad1)])
            com.append([commit(sid, i, 0, m0, pad0), commit(sid, i, 1, m1, pad1)])
        }
        tamperEncrypted?(&enc)
        var received: [[UInt8]] = []
        for (i, c) in st.choices.enumerated() {
            let payload = try LweLattice.dec(st.secretKeys[i], cts[i][c])
            let e = enc[i][c]
            let pd = pad(sid, i, c, payload, e.count)
            let m = try xor(e, pd)
            guard ctEqual(commit(sid, i, c, m, pd), com[i][c]) else { throw LweOtError.abort("endemic base OT (index \(i)): sender ciphertext inconsistent with its commitment; aborting") }
            received.append(m)
        }
        return (received, EndemicTranscript(rn: msg.rn, points: msg.points, rhos: msg.rhos, ciphertexts: cts, encrypted: enc, commitments: com))
    }
}
