import Foundation
import CryptoKit

/// Oblivious transfer, the root of the no-dealer offline phase. (1) A maliciously secure Chou-Orlandi base OT over the Ed25519 subgroup: the sender
/// proves knowledge of its discrete log with a Schnorr NIZK, every received point is validated, and the core runs as a random OT so there is no
/// selective-failure surface. (2) IKNP OT extension with the KOS consistency check (a deviating receiver is caught and the protocol aborts). Both roles
/// run in one process; the functions take both parties' inputs and return the receiver's outputs plus an inspectable transcript.
extension PCAMpc {
    /// The KOS correlation check failed: a cheating OT-extension receiver is detected.
    struct MalOtAbort: Error, CustomStringConvertible { let description: String; init(_ m: String) { description = m } }
    /// A base OT aborted: a cheating sender (bad proof / inconsistent ciphertext) is detected.
    struct BaseOtAbort: Error, CustomStringConvertible { let description: String; init(_ m: String) { description = m } }

    /// A non-negative or negative integer of any width (magnitude on 64-bit limbs): the OT columns and the tamper hooks that corrupt them.
    struct BigN: Equatable {
        var neg: Bool
        var mag: [UInt64]
        init(neg: Bool = false, mag: [UInt64]) { self.neg = neg; self.mag = mag }
        init(bytesLE b: [UInt8]) { neg = false; mag = Dec.limbs(b) }
        var isZero: Bool { mag.allSatisfy { $0 == 0 } }
        var bitLength: Int {
            for i in stride(from: mag.count - 1, through: 0, by: -1) where mag[i] != 0 { return i * 64 + (64 - mag[i].leadingZeroBitCount) }
            return 0
        }
        /// The low `len` bytes of the magnitude, little endian.
        func bytes(_ len: Int) -> [UInt8] { Dec.bytesLE(mag, len) }
        mutating func flipBit(_ i: Int) {
            while mag.count <= i / 64 { mag.append(0) }
            mag[i / 64] ^= UInt64(1) << UInt64(i % 64)
        }
        var decimal: String { (neg && !isZero ? "-" : "") + Dec.string(mag) }
        static func == (a: BigN, b: BigN) -> Bool { a.decimal == b.decimal }
    }

    public enum Ot {
        /// IKNP security parameter (number of base OTs / width of the selector s).
        static let KAPPA = 128
        /// KOS statistical parameter: extra random check rows beyond the kappa that mask the revealed combination.
        static let SSEC = 128
        static let SEED_BYTES = KAPPA / 8

        static let TAG_BINDING = Array("atlas-pca-mpc/base-ot-binding".utf8)
        static let TAG_TRANSCRIPT = Array("atlas-pca-mpc/base-ot-transcript".utf8)
        static let TAG_KDF = Array("atlas-pca-mpc/ot-kdf".utf8)
        static let TAG_KOS = Array("atlas-pca-mpc/ot-kos".utf8)
        static let TAG_COMMIT = Array("atlas-pca-mpc/ot-msg-commit".utf8)

        static func u32(_ x: Int) -> [UInt8] { MpcHash.u32(Int64(x)) }

        /// Session binding of one base OT: who runs it, in which session and round (indices are uint32).
        struct BaseOtBinding {
            var sessionId: [UInt8]
            var senderIndex: Int64
            var receiverIndex: Int64
            var round: String
        }

        /// Canonical, length-prefixed encoding of a binding (the Schnorr context and part of every KDF input).
        static func bindingBytes(_ b: BaseOtBinding) throws -> [UInt8] {
            guard b.sessionId.count >= 8 && b.sessionId.count <= 64 else { throw MpcError("base-OT binding: sessionId must be 8..64 bytes") }
            guard b.senderIndex >= 0 && b.senderIndex <= 0xffff_ffff else { throw MpcError("base-OT binding: senderIndex must be a uint32") }
            guard b.receiverIndex >= 0 && b.receiverIndex <= 0xffff_ffff else { throw MpcError("base-OT binding: receiverIndex must be a uint32") }
            guard b.senderIndex != b.receiverIndex else { throw MpcError("base-OT binding: sender and receiver must be different parties") }
            let round = Array(b.round.utf8)
            guard !round.isEmpty && round.count <= 64 else { throw MpcError("base-OT binding: round label must be 1..64 bytes") }
            return TAG_BINDING + MpcHash.u32(Int64(b.sessionId.count)) + b.sessionId + MpcHash.u32(b.senderIndex) + MpcHash.u32(b.receiverIndex)
                + MpcHash.u32(Int64(round.count)) + round
        }

        /// A fresh binding for an in-process OT: a random 16-byte session id from `rng`.
        static func randomBinding(_ rng: OtRandom, _ round: String, _ sender: Int64 = 0, _ receiver: Int64 = 1) -> BaseOtBinding {
            BaseOtBinding(sessionId: rng.bytes(16), senderIndex: sender, receiverIndex: receiver, round: round)
        }

        /// Hash of the whole base-OT transcript: binding, S and every receiver point, in order.
        static func baseOtTranscriptHash(_ binding: BaseOtBinding, _ S: Ec.Point, _ R: [Ec.Point]) throws -> [UInt8] {
            var parts: [[UInt8]] = [TAG_TRANSCRIPT, try bindingBytes(binding), Ec.encodePoint(S), u32(R.count)]
            for r in R { parts.append(Ec.encodePoint(r)) }
            return MpcHash.sha256(parts)
        }

        /// H("ot-kdf" || H(transcript) || index || R_i || P), SEED_BYTES bytes.
        static func baseOtKdf(_ transcriptHash: [UInt8], _ index: Int, _ Ri: Ec.Point, _ p: Ec.Point) -> [UInt8] {
            Array(MpcHash.sha256([TAG_KDF, transcriptHash, u32(index), Ec.encodePoint(Ri), Ec.encodePoint(p)])[0..<SEED_BYTES])
        }

        /// The KOS row-weights as little-endian u32 words (4 per row): SHAKE256 over the binding, round and every column of u.
        static func kosChiWords(_ binding: [UInt8], _ round: Int, _ u: [BigN], _ mExt: Int) throws -> [UInt32] {
            guard mExt >= 0 else { throw MpcError("kosChiWords: negative row count") }
            let colBytes = (mExt + 7) / 8
            var chunks: [[UInt8]] = [TAG_KOS, u32(binding.count), binding, u32(round), u32(mExt), u32(u.count)]
            for col in u { chunks.append(col.bytes(colBytes)) }
            return try Otx.leWords(Shake256.hash(chunks, outLen: mExt * 16), 0, mExt * 4)
        }

        static func kosChallenges(_ binding: [UInt8], _ round: Int, _ u: [BigN], _ mExt: Int) throws -> [Gf128] {
            let w = try kosChiWords(binding, round, u, mExt)
            return try (0..<mExt).map { try Otx.gfToBig(w, 4 * $0) }
        }

        // MARK: base OT

        /// TEST-ONLY injection points modelling a malicious sender or receiver in the base OT (nil = honest).
        final class BaseOtTamper {
            var tamperS: ((Ec.Point) -> Ec.Point)?
            var tamperProof: ((Ec.SchnorrProof) -> Ec.SchnorrProof)?
            var tamperR: ((inout [Ec.Point]) -> Void)?
            var tamperCiphertext: ((inout [[[UInt8]]]) -> Void)?
        }

        /// The base-OT transcript. ct and com hold [i][0/1] byte strings.
        struct BaseOtTranscript { var S: Ec.Point; var proof: Ec.SchnorrProof; var R: [Ec.Point]; var ct: [[[UInt8]]]; var com: [[[UInt8]]] }
        struct BaseOtResult { var received: [[UInt8]]; var transcript: BaseOtTranscript }
        /// A pluggable chosen-message base OT: messages[i] = [m0, m1]; returns the receiver's recovered messages.
        typealias BaseOtFn = (_ messages: [[[UInt8]]], _ choices: [Int], _ rng: OtRandom) throws -> [[UInt8]]
        /// Output of the malicious-secure random base OT: validated points and the two RO pads per index.
        struct MalRandomOtResult { var S: Ec.Point; var proof: Ec.SchnorrProof; var R: [Ec.Point]; var senderPads: [[[UInt8]]]; var recvPads: [[UInt8]] }

        static func otCommit(_ i: Int, _ b: Int, _ msg: [UInt8], _ pad: [UInt8]) -> [UInt8] {
            MpcHash.sha256([TAG_COMMIT, u32(i), [UInt8(b & 1)], msg, pad])
        }

        struct SenderSetup { var y: Scalar; var T: Ec.Point; var S: Ec.Point; var proof: Ec.SchnorrProof }

        static func malBaseOtSenderSetup(_ rng: OtRandom, _ binding: BaseOtBinding) throws -> SenderSetup {
            let ctx = try bindingBytes(binding)
            let y = try rng.scalar()
            let S = try Ec.mulBase(y)
            let T = try Ec.mul(y, S)
            let proof = try Ec.schnorrProve(y, S, { try rng.scalar() }, ctx)
            return SenderSetup(y: y, T: T, S: S, proof: proof)
        }

        static func malBaseOtReceiverRespond(_ S: Ec.Point, _ proof: Ec.SchnorrProof, _ choices: [Int], _ rng: OtRandom, _ binding: BaseOtBinding) throws -> (R: [Ec.Point], recvPads: [[UInt8]]) {
            let ctx = try bindingBytes(binding)
            try Ec.assertInSubgroup(S, "base-OT S (received by receiver)")
            guard Ec.schnorrVerify(S, proof, ctx) else { throw BaseOtAbort("base OT: sender Schnorr proof-of-knowledge of S=y·B failed; aborting") }
            var R: [Ec.Point] = []
            var xs: [Scalar] = []
            for i in 0..<choices.count {
                let x = try rng.scalar()
                let ci = choices[i] & 1
                if ci == 1 { R.append(try Ec.add(try Ec.mulBase(x), S)) } else { R.append(try Ec.mulBase(x)) }
                xs.append(x)
            }
            let th = try baseOtTranscriptHash(binding, S, R)
            var pads: [[UInt8]] = []
            for i in 0..<choices.count { pads.append(baseOtKdf(th, i, R[i], try Ec.mul(xs[i], S))) }
            return (R, pads)
        }

        static func malBaseOtSenderDerive(_ y: Scalar, _ T: Ec.Point, _ R: [Ec.Point], _ S: Ec.Point, _ binding: BaseOtBinding) throws -> [[[UInt8]]] {
            for i in 0..<R.count { try Ec.assertInSubgroup(R[i], "base-OT R_\(i) (received by sender)") }
            let th = try baseOtTranscriptHash(binding, S, R)
            var pads: [[[UInt8]]] = []
            for i in 0..<R.count {
                let yR = try Ec.mul(y, R[i])
                pads.append([baseOtKdf(th, i, R[i], yR), baseOtKdf(th, i, R[i], try Ec.sub(yR, T))])
            }
            return pads
        }

        static func malBaseRandomOT(_ choices: [Int], _ rng: OtRandom, _ tamper: BaseOtTamper? = nil, _ binding: BaseOtBinding? = nil) throws -> MalRandomOtResult {
            let bnd = binding ?? randomBinding(rng, "base-ot")
            let setup = try malBaseOtSenderSetup(rng, bnd)
            let S = tamper?.tamperS.map { $0(setup.S) } ?? setup.S
            let proof = tamper?.tamperProof.map { $0(setup.proof) } ?? setup.proof
            var rr = try malBaseOtReceiverRespond(S, proof, choices, rng, bnd)
            tamper?.tamperR?(&rr.R)
            let senderPads = try malBaseOtSenderDerive(setup.y, setup.T, rr.R, S, bnd)
            return MalRandomOtResult(S: S, proof: proof, R: rr.R, senderPads: senderPads, recvPads: rr.recvPads)
        }

        /// One-time-pads the messages under the sender pads and commits to each (message, pad). Returns (ct, com).
        /// A message (at most the pad width) XORed with the front of its pad: the result has the message's length, as the reference's pad XOR does.
        private static func xorPad(_ m: [UInt8], _ pad: [UInt8]) -> [UInt8] {
            m.enumerated().map { $0.element ^ ($0.offset < pad.count ? pad[$0.offset] : 0) }
        }

        public static func baseOtSenderEncrypt(_ messages: [[[UInt8]]], _ senderPads: [[[UInt8]]]) throws -> (ct: [[[UInt8]]], com: [[[UInt8]]]) {
            guard messages.count == senderPads.count else { throw MpcError("baseOT: messages/pads length mismatch") }
            for i in 0..<messages.count {
                let m0 = messages[i][0], m1 = messages[i][1]
                guard m0.count <= SEED_BYTES && m1.count <= SEED_BYTES && m0.count == m1.count else {
                    throw MpcError("baseOT: message pair \(i) must be equal length and at most \(SEED_BYTES) bytes (pad width)")
                }
            }
            var ct: [[[UInt8]]] = [], com: [[[UInt8]]] = []
            for i in 0..<messages.count {
                let p0 = senderPads[i][0], p1 = senderPads[i][1]
                ct.append([xorPad(messages[i][0], p0), xorPad(messages[i][1], p1)])
                com.append([otCommit(i, 0, messages[i][0], p0), otCommit(i, 1, messages[i][1], p1)])
            }
            return (ct, com)
        }

        public static func baseOtReceiverDecrypt(_ choices: [Int], _ recvPads: [[UInt8]], _ ct: [[[UInt8]]], _ com: [[[UInt8]]]) throws -> [[UInt8]] {
            guard ct.count == choices.count && com.count == choices.count && recvPads.count == choices.count else {
                throw BaseOtAbort("base OT: ciphertext/commitment count does not match the number of choices; aborting")
            }
            var received: [[UInt8]] = []
            for i in 0..<choices.count {
                let ci = choices[i] & 1
                let c0 = ct[i][0], c1 = ct[i][1]
                guard c0.count == c1.count && c0.count <= SEED_BYTES else { throw BaseOtAbort("base OT (index \(i)): malformed ciphertext shape; aborting") }
                let m = xorPad(ct[i][ci], recvPads[i])
                guard MpcHash.ctEqual(otCommit(i, ci, m, recvPads[i]), com[i][ci]) else {
                    throw BaseOtAbort("base OT (index \(i)): sender ciphertext inconsistent with its commitment; aborting")
                }
                received.append(m)
            }
            return received
        }

        /// Chosen-message 1-of-2 OT for `choices.count` transfers, built over the random base OT.
        static func baseOT(_ messages: [[[UInt8]]], _ choices: [Int], _ rng: OtRandom, _ tamper: BaseOtTamper? = nil, _ binding: BaseOtBinding? = nil) throws -> BaseOtResult {
            let bnd = binding ?? randomBinding(rng, "base-ot")
            guard messages.count == choices.count else { throw MpcError("baseOT: messages/choices length mismatch") }
            let ro = try malBaseRandomOT(choices, rng, tamper, bnd)
            var enc = try baseOtSenderEncrypt(messages, ro.senderPads)
            tamper?.tamperCiphertext?(&enc.ct)
            let received = try baseOtReceiverDecrypt(choices, ro.recvPads, enc.ct, enc.com)
            return BaseOtResult(received: received, transcript: BaseOtTranscript(S: ro.S, proof: ro.proof, R: ro.R, ct: enc.ct, com: enc.com))
        }

        // MARK: OT extension (IKNP + KOS)

        /// The receiver's extension-round message: the u columns and the KOS values (x, t).
        struct ExtRoundMsg { var u: [BigN]; var x: Gf128; var tComb: Gf128 }
        /// The receiver's per-round state between `begin` and `finish`.
        struct ExtPending { var m: Int; var choiceBits: [Int]; var t: [UInt32]; var W: Int; var rowOffset: Int64 }

        static func checkExtInputs(_ choiceBits: [Int]) throws {
            for (j, b) in choiceBits.enumerated() where b != 0 && b != 1 { throw MpcError("OtChannel.extend: choice bit \(j) must be 0 or 1") }
        }

        /// The extension receiver (base-OT sender): makes the seed pairs, then per round the u matrix and KOS values.
        final class OtExtReceiver {
            private let rng: OtRandom
            private let kosBinding: [UInt8]
            private var seed0: [[UInt8]] = [], seed1: [[UInt8]] = []
            private var blk0 = [UInt64](repeating: 0, count: Ot.KAPPA), blk1 = [UInt64](repeating: 0, count: Ot.KAPPA)
            private var round = 0
            private var rowsDone: Int64 = 0
            private let tweakDomain: [UInt32]
            var ready = false
            /// TEST-ONLY: mutate the u columns on the wire (a malicious receiver).
            var tamperU: ((inout [BigN], Int) -> Void)?

            init(_ rng: OtRandom, _ kosBinding: [UInt8]) throws {
                self.rng = rng
                self.kosBinding = kosBinding
                tweakDomain = try Otx.otTweakDomain(kosBinding)
            }

            /// The kappa seed pairs, to be transferred by the base OT with the sender's selector as choices.
            func makeSeeds() -> [[[UInt8]]] {
                var messages: [[[UInt8]]] = []
                for _ in 0..<Ot.KAPPA {
                    let k0 = rng.bytes(Ot.SEED_BYTES), k1 = rng.bytes(Ot.SEED_BYTES)
                    seed0.append(k0)
                    seed1.append(k1)
                    messages.append([k0, k1])
                }
                ready = true
                return messages
            }

            func begin(_ choiceBits: [Int]) throws -> (msg: Ot.ExtRoundMsg, pending: Ot.ExtPending) {
                guard ready else { throw MpcError("OtExtReceiver: base OT not done") }
                try Ot.checkExtInputs(choiceBits)
                let m = choiceBits.count
                let roundIdx = round
                round += 1
                let rowOffset = rowsDone
                rowsDone += Int64(m)
                let pad = Ot.KAPPA + Ot.SSEC
                let mExt = m + pad
                let W = (mExt + 31) >> 5
                let colBytes = (mExt + 7) / 8
                var bvec = [UInt32](repeating: 0, count: W)
                for j in 0..<m where choiceBits[j] & 1 != 0 { bvec[j >> 5] |= UInt32(1) << UInt32(j & 31) }
                let padBytes = rng.bytes(pad)
                for p in 0..<pad where padBytes[p] & 1 != 0 {
                    let j = m + p
                    bvec[j >> 5] |= UInt32(1) << UInt32(j & 31)
                }
                let blocks = UInt64((W + 3) / 4)
                var t = [UInt32](repeating: 0, count: Otx.COLS * W)
                var u: [BigN] = []
                for i in 0..<Ot.KAPPA {
                    var ti = try Otx.prgColumn(seed0[i], blk0[i], W)
                    var gi = try Otx.prgColumn(seed1[i], blk1[i], W)
                    blk0[i] += blocks
                    blk1[i] += blocks
                    try Otx.maskTail(&ti, mExt)
                    try Otx.maskTail(&gi, mExt)
                    for w in 0..<W { t[i * W + w] = ti[w] }
                    let uw = (0..<W).map { gi[$0] ^ ti[$0] ^ bvec[$0] }
                    u.append(BigN(bytesLE: Array(try Otx.leBytes(uw, W)[0..<colBytes])))
                }
                tamperU?(&u, roundIdx)
                let pending = Ot.ExtPending(m: m, choiceBits: choiceBits, t: t, W: W, rowOffset: rowOffset)
                for c in u where c.neg || c.bitLength > mExt {
                    return (Ot.ExtRoundMsg(u: u, x: Gf128(hi: 0, lo: 0), tComb: Gf128(hi: 0, lo: 0)), pending)
                }
                let chi = try Ot.kosChiWords(kosBinding, roundIdx, u, mExt)
                var x = [UInt32](repeating: 0, count: 4)
                try Otx.accumColumn(bvec, 0, W, chi, &x)
                let tComb = try Otx.kosCombine(t, W, chi)
                return (Ot.ExtRoundMsg(u: u, x: try Otx.gfToBig(x), tComb: try Otx.gfToBig(tComb)), pending)
            }

            /// The receiver's outputs: m_{c_j} for every row j, from the sender's ciphertexts.
            func finish(_ pending: Ot.ExtPending, _ y0: [UInt64], _ y1: [UInt64]) throws -> [UInt64] {
                let m = pending.m
                guard y0.count == m && y1.count == m else { throw MalOtAbort("OT extension: ciphertext count does not match the number of rows; aborting") }
                let rows = try Otx.transposeCols(pending.t, pending.W, m)
                let h = try Otx.tmmoCrh(rows, m, offset: pending.rowOffset, domain: tweakDomain)
                var received: [UInt64] = []
                for j in 0..<m { received.append((pending.choiceBits[j] == 1 ? y1[j] : y0[j]) ^ (try Otx.word64(h, j))) }
                return received
            }
        }

        /// The extension sender (base-OT receiver): holds the secret selector s and answers each round after the KOS check.
        final class OtExtSender {
            private let rng: OtRandom
            private let kosBinding: [UInt8]
            private(set) var s: [Int] = []
            private(set) var sBits = Gf128(hi: 0, lo: 0)
            private var seeds: [[UInt8]] = []
            private var blk: [UInt64] = []
            private var round = 0
            private var rowsDone: Int64 = 0
            private let tweakDomain: [UInt32]
            var ready = false

            init(_ rng: OtRandom, _ kosBinding: [UInt8]) throws {
                self.rng = rng
                self.kosBinding = kosBinding
                tweakDomain = try Otx.otTweakDomain(kosBinding)
            }

            func makeSelector() -> [Int] {
                s = (0..<Ot.KAPPA).map { _ in Int(rng.bytes(1)[0] & 1) }
                return s
            }

            func setSeeds(_ seeds: [[UInt8]]) throws {
                guard seeds.count == Ot.KAPPA && s.count == Ot.KAPPA else { throw MpcError("OtExtSender: wrong base-OT output size") }
                self.seeds = seeds
                blk = [UInt64](repeating: 0, count: Ot.KAPPA)
                var hi: UInt64 = 0, lo: UInt64 = 0
                for i in 0..<Ot.KAPPA where s[i] == 1 { if i < 64 { lo |= UInt64(1) << UInt64(i) } else { hi |= UInt64(1) << UInt64(i - 64) } }
                sBits = Gf128(hi: hi, lo: lo)
                ready = true
            }

            func respond(_ msg: Ot.ExtRoundMsg, _ msg0: [UInt64], _ msg1: [UInt64]) throws -> (y0: [UInt64], y1: [UInt64]) {
                guard ready else { throw MpcError("OtExtSender: base OT not done") }
                let m = msg0.count
                guard msg1.count == m else { throw MpcError("OtChannel.extend: length mismatch") }
                let roundIdx = round
                round += 1
                let rowOffset = rowsDone
                rowsDone += Int64(m)
                let mExt = m + Ot.KAPPA + Ot.SSEC
                let u = msg.u
                guard u.count == Ot.KAPPA else {
                    throw MalOtAbort("KOS check (round \(roundIdx)): wrong number of u columns; a cheating OT-extension receiver was detected; aborting")
                }
                for i in 0..<Ot.KAPPA where u[i].neg || u[i].bitLength > mExt {
                    throw MalOtAbort("KOS check (round \(roundIdx)): malformed u column \(i); a cheating OT-extension receiver was detected; aborting")
                }
                let W = (mExt + 31) >> 5
                let colBytes = (mExt + 7) / 8
                let blocks = UInt64((W + 3) / 4)
                var q = [UInt32](repeating: 0, count: Otx.COLS * W)
                for i in 0..<Ot.KAPPA {
                    var ks = try Otx.prgColumn(seeds[i], blk[i], W)
                    blk[i] += blocks
                    try Otx.maskTail(&ks, mExt)
                    if s[i] == 1 {
                        let ub = u[i].bytes(colBytes) + [UInt8](repeating: 0, count: 4 * W - colBytes)
                        let uw = try Otx.leWords(ub, 0, W)
                        for w in 0..<W { ks[w] ^= uw[w] }
                    }
                    for w in 0..<W { q[i * W + w] = ks[w] }
                }
                let chi = try Ot.kosChiWords(kosBinding, roundIdx, u, mExt)
                let qComb = try Otx.gfToBig(try Otx.kosCombine(q, W, chi))
                let expected = Gf128.add(msg.tComb, Gf128.mul(msg.x, sBits))
                guard qComb == expected else {
                    throw MalOtAbort("KOS correlation check FAILED (round \(roundIdx)): a cheating OT-extension receiver was detected; aborting")
                }
                var rows = try Otx.transposeCols(q, W, m)
                let h0 = try Otx.tmmoCrh(rows, m, offset: rowOffset, domain: tweakDomain)
                let sw = Otx.gfFromBig(sBits)
                for j in 0..<m { for k in 0..<4 { rows[4 * j + k] ^= sw[k] } }
                let h1 = try Otx.tmmoCrh(rows, m, offset: rowOffset, domain: tweakDomain)
                var y0: [UInt64] = [], y1: [UInt64] = []
                for j in 0..<m {
                    y0.append(msg0[j] ^ (try Otx.word64(h0, j)))
                    y1.append(msg1[j] ^ (try Otx.word64(h1, j)))
                }
                return (y0, y1)
            }
        }

        /// An in-process OT-extension channel: one base-OT setup (kappa transfers) is amortised over every later `extend`. The base OT is the EC base OT
        /// unless `baseOtFn` supplies another (for example a post-quantum one).
        final class OtChannel {
            private let rng: OtRandom
            private let baseOtFn: Ot.BaseOtFn?
            private let bindingOpt: Ot.BaseOtBinding?
            private var recv: OtExtReceiver?
            private var send: OtExtSender?
            private var ready = false
            /// The EC base-OT transcript of the kappa setup transfers (nil when a custom base OT is used).
            var baseTranscript: Ot.BaseOtTranscript?
            /// TEST-ONLY: mutate the extension receiver's u matrix.
            var tamperU: ((inout [BigN], Int) -> Void)?

            /// `binding`: only sessionId, senderIndex and receiverIndex are used; its round is ignored.
            init(_ rng: OtRandom? = nil, baseOtFn: Ot.BaseOtFn? = nil, binding: Ot.BaseOtBinding? = nil) {
                self.rng = rng ?? OtRandom.secure()
                self.baseOtFn = baseOtFn
                bindingOpt = binding
            }

            private func setup() throws {
                let base = bindingOpt ?? Ot.randomBinding(rng, "x")
                let kos = try Ot.bindingBytes(Ot.BaseOtBinding(sessionId: base.sessionId, senderIndex: base.senderIndex, receiverIndex: base.receiverIndex, round: "iknp-kos"))
                let r = try OtExtReceiver(rng, kos)
                let sd = try OtExtSender(rng, kos)
                let messages = r.makeSeeds()
                let sel = sd.makeSelector()
                if let fn = baseOtFn {
                    try sd.setSeeds(try fn(messages, sel, rng))
                } else {
                    let res = try Ot.baseOT(messages, sel, rng, nil, Ot.BaseOtBinding(sessionId: base.sessionId, senderIndex: base.senderIndex, receiverIndex: base.receiverIndex, round: "iknp-kappa-setup"))
                    try sd.setSeeds(res.received)
                    baseTranscript = res.transcript
                }
                recv = r
                send = sd
                ready = true
            }

            func selector() throws -> Gf128 {
                if !ready { try setup() }
                return send!.sBits
            }

            func extend(_ choiceBits: [Int], _ msg0: [UInt64], _ msg1: [UInt64]) throws -> (received: [UInt64], uMatrix: [BigN]) {
                if !ready { try setup() }
                let m = choiceBits.count
                guard msg0.count == m && msg1.count == m else { throw MpcError("OtChannel.extend: length mismatch") }
                if m == 0 { return ([], []) }
                try Ot.checkExtInputs(choiceBits)
                recv!.tamperU = tamperU
                let b = try recv!.begin(choiceBits)
                let r = try send!.respond(b.msg, msg0, msg1)
                return (try recv!.finish(b.pending, r.y0, r.y1), b.msg.u)
            }
        }
    }
}
