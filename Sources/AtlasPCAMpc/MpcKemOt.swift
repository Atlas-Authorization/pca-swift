import Foundation
import CryptoKit

/// Post-quantum and hybrid base OTs. ML-KEM-768 (FIPS 203) is OpenSSL libcrypto's, version 3.5 or later (Libcrypto.mlkem*): key generation from a seed
/// (d || z, 64 bytes) and encapsulation from the 32-byte message the reference draws from the OT stream (the "ikme" parameter), so keys, ciphertexts and
/// shared secrets are reproducible from a seeded stream. On an older libcrypto every KEM OT refuses (fail closed).
extension PCAMpc {
    public struct KemBaseOtAbort: Error, CustomStringConvertible { public let description: String; init(_ m: String) { description = m } }
    public struct HybridOtAbort: Error, CustomStringConvertible { public let description: String; init(_ m: String) { description = m } }

    enum MlKem768 {
        static let MSG_BYTES = 32
        static let KEYGEN_SEED_BYTES = 64

        /// True when the runtime OpenSSL provides ML-KEM-768 (3.5 or later).
        static var available: Bool { Libcrypto.mlkemAvailable }

        /// A key pair: the 1184-byte encapsulation key and the 64-byte seed the decapsulation key is rebuilt from.
        struct KeyPair { var publicKey: [UInt8]; var seed: [UInt8] }

        static func keygen(_ seed64: [UInt8]) throws -> KeyPair {
            guard seed64.count == KEYGEN_SEED_BYTES else { throw MpcError("ml-kem keygen: seed must be exactly 64 bytes") }
            guard available else { throw MpcError("ML-KEM-768 is not available (needs OpenSSL 3.5); KEM oblivious transfer refuses (fail closed)") }
            return KeyPair(publicKey: try Libcrypto.mlkemPublicKey(seed64), seed: seed64)
        }

        static func encapsulate(_ publicKey: [UInt8], _ msg32: [UInt8]) throws -> (cipherText: [UInt8], sharedSecret: [UInt8]) {
            guard msg32.count == MSG_BYTES else { throw MpcError("ml-kem encapsulate: message must be exactly 32 bytes") }
            guard available else { throw MpcError("ML-KEM-768 is not available (needs OpenSSL 3.5); KEM oblivious transfer refuses (fail closed)") }
            return try Libcrypto.mlkemEncapsulate(publicKey, msg32)
        }

        static func decapsulate(_ cipherText: [UInt8], _ seed: [UInt8]) throws -> [UInt8] {
            guard available else { throw MpcError("ML-KEM-768 is not available (needs OpenSSL 3.5); KEM oblivious transfer refuses (fail closed)") }
            return try Libcrypto.mlkemDecapsulate(cipherText, seed)
        }
    }

    /// Post-quantum base OT from ML-KEM-768: the receiver publishes a public-key pair with a known secret key for only its chosen slot, the sender
    /// encapsulates to both and pads each message with the shared secret. Variants: the semi-honest transfer, the commit-then-open malicious-secure
    /// transfer with a session id, and the random-OT form that outputs fixed-width secrets for the hybrid base OT.
    public enum KemOt {
        static let TAG_KEMOT = Array("atlas-pca-mpc/kem-ot-pad".utf8)
        static let TAG_KEMOT_COMMIT = Array("atlas-pca-mpc/kem-ot-commit".utf8)
        static let TAG_KEMOT_SID = Array("atlas-pca-mpc/kem-ot-sid".utf8)
        static let TAG_KEMOT_MALPAD = Array("atlas-pca-mpc/kem-ot-mal-pad".utf8)
        static let TAG_KEMOT_MALSECRET = Array("atlas-pca-mpc/kem-ot-mal-secret".utf8)
        static let NONCE_BYTES = 32
        public static let KEM_OT_SECRET_BYTES = 32

        static func u32(_ x: Int) -> [UInt8] { MpcHash.u32(Int64(x)) }

        private static func expand(_ tag: [UInt8], _ prefix: [[UInt8]], _ index: Int, _ slot: Int, _ ss: [UInt8], _ len: Int) -> [UInt8] {
            var out: [UInt8] = []
            out.reserveCapacity(len)
            var ctr = 0
            while out.count < len {
                let block = MpcHash.sha256([tag] + prefix + [u32(index), [UInt8(slot & 1)], u32(ctr), ss])
                for b in block where out.count < len { out.append(b) }
                ctr += 1
            }
            return out
        }

        /// Pad of `len` bytes (at most 1 MiB) from the shared secret: SHA-256 in counter mode.
        public static func kemOtPad(_ index: Int, _ slot: Int, _ ss: [UInt8], _ len: Int) throws -> [UInt8] {
            guard len >= 0 && len <= 1 << 20 else { throw MpcError("kemOtPad: length must be an integer in [0, 1 MiB]") }
            return expand(TAG_KEMOT, [], index, slot, ss, len)
        }

        /// The receiver's key pairs: slot `c` holds the key it can open, the other slot a key whose secret it discards.
        static func receiverKeys(_ choices: [Int], _ rng: OtRandom) throws -> (publicKeys: [[[UInt8]]], seeds: [[UInt8]], retained: [Int]) {
            var pks: [[[UInt8]]] = [], seeds: [[UInt8]] = [], retained: [Int] = []
            for ch in choices {
                let c = ch & 1
                let chosen = try MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
                let other = try MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
                pks.append(c == 0 ? [chosen.publicKey, other.publicKey] : [other.publicKey, chosen.publicKey])
                seeds.append(chosen.seed)
                retained.append(c)
            }
            return (pks, seeds, retained)
        }

        static func encapsulatePair(_ pk: [[UInt8]], _ rng: OtRandom) throws -> (e0: (cipherText: [UInt8], sharedSecret: [UInt8]), e1: (cipherText: [UInt8], sharedSecret: [UInt8])) {
            let e0 = try MlKem768.encapsulate(pk[0], rng.bytes(MlKem768.MSG_BYTES))
            let e1 = try MlKem768.encapsulate(pk[1], rng.bytes(MlKem768.MSG_BYTES))
            return (e0, e1)
        }

        struct KemBaseOtTranscript { var publicKeys: [[[UInt8]]]; var ciphertexts: [[[UInt8]]]; var encrypted: [[[UInt8]]] }
        struct KemBaseOtResult { var received: [[UInt8]]; var transcript: KemBaseOtTranscript }

        static func kemBaseOT(_ messages: [[[UInt8]]], _ choices: [Int], _ rng: OtRandom) throws -> KemBaseOtResult {
            guard messages.count == choices.count else { throw MpcError("kemBaseOT: messages/choices length mismatch") }
            let rk = try receiverKeys(choices, rng)
            var cts: [[[UInt8]]] = [], encrypted: [[[UInt8]]] = []
            for i in 0..<messages.count {
                let m0 = messages[i][0], m1 = messages[i][1]
                guard m0.count == m1.count else { throw MpcError("kemBaseOtSend (index \(i)): the two messages must be equal length") }
                let p = try encapsulatePair(rk.publicKeys[i], rng)
                cts.append([p.e0.cipherText, p.e1.cipherText])
                encrypted.append([try MpcHash.xor(m0, try kemOtPad(i, 0, p.e0.sharedSecret, m0.count)), try MpcHash.xor(m1, try kemOtPad(i, 1, p.e1.sharedSecret, m1.count))])
            }
            var received: [[UInt8]] = []
            for i in 0..<choices.count {
                let c = rk.retained[i]
                let ss = try MlKem768.decapsulate(cts[i][c], rk.seeds[i])
                let e = encrypted[i][c]
                received.append(try MpcHash.xor(e, try kemOtPad(i, c, ss, e.count)))
            }
            return KemBaseOtResult(received: received, transcript: KemBaseOtTranscript(publicKeys: rk.publicKeys, ciphertexts: cts, encrypted: encrypted))
        }

        /// The semi-honest KEM OT as a pluggable base OT for an OtChannel.
        static var withKemBaseOt: Ot.BaseOtFn { { m, c, r in try kemBaseOT(m, c, r).received } }

        // MARK: malicious-secure (commit-then-open, session id)

        static func kemMalCommit(_ rn: [UInt8], _ index: Int, _ pk0: [UInt8], _ pk1: [UInt8]) -> [UInt8] { MpcHash.sha256([TAG_KEMOT_COMMIT, rn, u32(index), pk0, pk1]) }
        static func kemMalSid(_ rn: [UInt8], _ sn: [UInt8]) -> [UInt8] { MpcHash.sha256([TAG_KEMOT_SID, rn, sn]) }
        static func kemOtMalPad(_ sid: [UInt8], _ com: [UInt8], _ index: Int, _ slot: Int, _ ss: [UInt8], _ len: Int) -> [UInt8] { expand(TAG_KEMOT_MALPAD, [sid, com], index, slot, ss, len) }
        static func kemOtMalSecret(_ sid: [UInt8], _ com: [UInt8], _ index: Int, _ slot: Int, _ ss: [UInt8]) -> [UInt8] {
            Array(MpcHash.sha256([TAG_KEMOT_MALSECRET, sid, com, u32(index), [UInt8(slot & 1)], ss])[0..<KEM_OT_SECRET_BYTES])
        }

        /// TEST-ONLY injection points for a malicious sender or receiver (nil = honest).
        final class KemMalTamper {
            var tamperOpenedKeys: ((inout [[[UInt8]]]) -> Void)?
            var tamperReceiverSid: (([UInt8]) -> [UInt8])?
        }

        struct KemMalReceiverState { var choices: [Int]; var seeds: [[UInt8]]; var publicKeys: [[[UInt8]]]; var rn: [UInt8] }
        struct KemMalTranscript { var rn: [UInt8]; var commitments: [[UInt8]]; var sn: [UInt8]; var publicKeys: [[[UInt8]]]; var ciphertexts: [[[UInt8]]]; var encrypted: [[[UInt8]]] }
        struct KemBaseOtMalResult { var received: [[UInt8]]; var transcript: KemMalTranscript }

        static func malCommit(_ choices: [Int], _ rng: OtRandom) throws -> (rn: [UInt8], commitments: [[UInt8]], state: KemMalReceiverState) {
            let rn = rng.bytes(NONCE_BYTES)
            var pks: [[[UInt8]]] = [], seeds: [[UInt8]] = [], retained: [Int] = [], commitments: [[UInt8]] = []
            for (i, ch) in choices.enumerated() {
                let c = ch & 1
                let chosen = try MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
                let other = try MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
                let pair = c == 0 ? [chosen.publicKey, other.publicKey] : [other.publicKey, chosen.publicKey]
                pks.append(pair)
                seeds.append(chosen.seed)
                retained.append(c)
                commitments.append(kemMalCommit(rn, i, pair[0], pair[1]))
            }
            return (rn, commitments, KemMalReceiverState(choices: retained, seeds: seeds, publicKeys: pks, rn: rn))
        }

        static func checkOpening(_ rn: [UInt8], _ commitments: [[UInt8]], _ pks: [[[UInt8]]], _ i: Int) throws -> [UInt8] {
            let com = kemMalCommit(rn, i, pks[i][0], pks[i][1])
            guard MpcHash.ctEqual(com, commitments[i]) else { throw KemBaseOtAbort("kem base OT (index \(i)): opened public keys do not match the receiver's commitment; aborting") }
            return com
        }

        static func kemBaseOtMal(_ messages: [[[UInt8]]], _ choices: [Int], _ rng: OtRandom, _ tamper: KemMalTamper? = nil) throws -> KemBaseOtMalResult {
            guard messages.count == choices.count else { throw MpcError("kemBaseOtMal: messages/choices length mismatch") }
            let cs = try malCommit(choices, rng)
            let sn = rng.bytes(NONCE_BYTES)
            var opening = cs.state.publicKeys
            tamper?.tamperOpenedKeys?(&opening)
            guard messages.count == opening.count && cs.commitments.count == opening.count else { throw MpcError("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch") }
            let sid = kemMalSid(cs.rn, sn)
            var cts: [[[UInt8]]] = [], encrypted: [[[UInt8]]] = []
            for i in 0..<messages.count {
                let m0 = messages[i][0], m1 = messages[i][1]
                guard m0.count == m1.count else { throw MpcError("kemBaseOtMalSend (index \(i)): the two messages must be equal length") }
                let com = try checkOpening(cs.rn, cs.commitments, opening, i)
                let p = try encapsulatePair(opening[i], rng)
                cts.append([p.e0.cipherText, p.e1.cipherText])
                encrypted.append([try MpcHash.xor(m0, kemOtMalPad(sid, com, i, 0, p.e0.sharedSecret, m0.count)), try MpcHash.xor(m1, kemOtMalPad(sid, com, i, 1, p.e1.sharedSecret, m1.count))])
            }
            // receiver
            var rsid = kemMalSid(cs.state.rn, sn)
            if let t = tamper?.tamperReceiverSid { rsid = t(rsid) }
            var received: [[UInt8]] = []
            for i in 0..<choices.count {
                let c = cs.state.choices[i]
                let com = kemMalCommit(cs.state.rn, i, cs.state.publicKeys[i][0], cs.state.publicKeys[i][1])
                let ss = try MlKem768.decapsulate(cts[i][c], cs.state.seeds[i])
                let e = encrypted[i][c]
                received.append(try MpcHash.xor(e, kemOtMalPad(rsid, com, i, c, ss, e.count)))
            }
            return KemBaseOtMalResult(received: received, transcript: KemMalTranscript(rn: cs.rn, commitments: cs.commitments, sn: sn, publicKeys: opening, ciphertexts: cts, encrypted: encrypted))
        }

        /// The malicious-secure KEM OT as a pluggable base OT for an OtChannel.
        static var withKemBaseOtMal: Ot.BaseOtFn { { m, c, r in try kemBaseOtMal(m, c, r, nil).received } }

        // MARK: random-OT form (fixed-width secrets, for the hybrid base OT)

        struct KemMalRandomTranscript { var rn: [UInt8]; var commitments: [[UInt8]]; var sn: [UInt8]; var publicKeys: [[[UInt8]]]; var ciphertexts: [[[UInt8]]] }
        struct KemBaseOtMalRandomResult { var senderSecrets: [[[UInt8]]]; var recvSecrets: [[UInt8]]; var sid: [UInt8]; var transcript: KemMalRandomTranscript }

        static func kemBaseOtMalRandom(_ choices: [Int], _ rng: OtRandom, _ tamper: KemMalTamper? = nil) throws -> KemBaseOtMalRandomResult {
            let cs = try malCommit(choices, rng)
            let sn = rng.bytes(NONCE_BYTES)
            var opening = cs.state.publicKeys
            tamper?.tamperOpenedKeys?(&opening)
            guard cs.commitments.count == opening.count else { throw MpcError("kemBaseOtMalRandomSend: commitments/publicKeys length mismatch") }
            let sid = kemMalSid(cs.rn, sn)
            var cts: [[[UInt8]]] = [], secrets: [[[UInt8]]] = []
            for i in 0..<opening.count {
                let com = try checkOpening(cs.rn, cs.commitments, opening, i)
                let p = try encapsulatePair(opening[i], rng)
                cts.append([p.e0.cipherText, p.e1.cipherText])
                secrets.append([kemOtMalSecret(sid, com, i, 0, p.e0.sharedSecret), kemOtMalSecret(sid, com, i, 1, p.e1.sharedSecret)])
            }
            var rsid = kemMalSid(cs.state.rn, sn)
            if let t = tamper?.tamperReceiverSid { rsid = t(rsid) }
            var recv: [[UInt8]] = []
            for i in 0..<choices.count {
                let c = cs.state.choices[i]
                let com = kemMalCommit(cs.state.rn, i, cs.state.publicKeys[i][0], cs.state.publicKeys[i][1])
                recv.append(kemOtMalSecret(rsid, com, i, c, try MlKem768.decapsulate(cts[i][c], cs.state.seeds[i])))
            }
            return KemBaseOtMalRandomResult(senderSecrets: secrets, recvSecrets: recv, sid: kemMalSid(cs.rn, sn),
                                            transcript: KemMalRandomTranscript(rn: cs.rn, commitments: cs.commitments, sn: sn, publicKeys: opening, ciphertexts: cts))
        }
    }

    /// Hybrid base OT: the elliptic-curve random OT and the ML-KEM random OT run side by side and BOTH secrets are folded into every transfer key, so the
    /// transfer is secure if either the classical or the post-quantum assumption holds. The keys encrypt the messages and a per-message commitment
    /// catches an inconsistent sender.
    public enum HybridOt {
        static let TAG_HYBRID_SID = Array("atlas-pca-mpc/hybrid-ot-sid".utf8)
        static let TAG_HYBRID_KEY = Array("atlas-pca-mpc/hybrid-ot-transfer-key".utf8)
        static let TAG_HYBRID_COMMIT = Array("atlas-pca-mpc/hybrid-ot-msg-commit".utf8)

        static func hybridSessionId(_ kemSid: [UInt8], _ ecS: Ec.Point) -> [UInt8] { MpcHash.sha256([TAG_HYBRID_SID, kemSid, Ec.encodePoint(ecS)]) }

        public static func hybridTransferKey(_ sid: [UInt8], _ index: Int, _ slot: Int, _ ssEc: [UInt8], _ ssKem: [UInt8], _ len: Int) throws -> [UInt8] {
            guard len >= 0 && len <= 1 << 20 else { throw MpcError("hybridTransferKey: length must be an integer in [0, 1 MiB]") }
            var out: [UInt8] = []
            var ctr = 0
            while out.count < len {
                let block = MpcHash.sha256([TAG_HYBRID_KEY, sid, MpcHash.u32(Int64(index)), [UInt8(slot & 1)], MpcHash.u32(Int64(ctr)), ssEc, ssKem])
                for b in block where out.count < len { out.append(b) }
                ctr += 1
            }
            return out
        }

        private static func hybridCommit(_ sid: [UInt8], _ index: Int, _ slot: Int, _ msg: [UInt8], _ key: [UInt8]) -> [UInt8] {
            MpcHash.sha256([TAG_HYBRID_COMMIT, sid, MpcHash.u32(Int64(index)), [UInt8(slot & 1)], msg, key])
        }

        struct HybridSenderMessage { var encrypted: [[[UInt8]]]; var commitments: [[[UInt8]]] }

        static func hybridSenderEncrypt(_ sid: [UInt8], _ messages: [[[UInt8]]], _ ecSecrets: [[[UInt8]]], _ kemSecrets: [[[UInt8]]]) throws -> HybridSenderMessage {
            guard messages.count == ecSecrets.count && messages.count == kemSecrets.count else { throw MpcError("hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch") }
            var enc: [[[UInt8]]] = [], com: [[[UInt8]]] = []
            for i in 0..<messages.count {
                let m0 = messages[i][0], m1 = messages[i][1]
                guard m0.count == m1.count else { throw MpcError("hybridSenderEncrypt (index \(i)): the two messages must be equal length") }
                let k0 = try hybridTransferKey(sid, i, 0, ecSecrets[i][0], kemSecrets[i][0], m0.count)
                let k1 = try hybridTransferKey(sid, i, 1, ecSecrets[i][1], kemSecrets[i][1], m1.count)
                enc.append([try MpcHash.xor(m0, k0), try MpcHash.xor(m1, k1)])
                com.append([hybridCommit(sid, i, 0, m0, k0), hybridCommit(sid, i, 1, m1, k1)])
            }
            return HybridSenderMessage(encrypted: enc, commitments: com)
        }

        static func hybridReceiverRecover(_ sid: [UInt8], _ choices: [Int], _ sender: HybridSenderMessage, _ ecRecv: [[UInt8]], _ kemRecv: [[UInt8]]) throws -> [[UInt8]] {
            let n = choices.count
            guard sender.encrypted.count == n && sender.commitments.count == n && ecRecv.count == n && kemRecv.count == n else { throw MpcError("hybridReceiverRecover: length mismatch") }
            var received: [[UInt8]] = []
            for i in 0..<n {
                let c = choices[i] & 1
                let e = sender.encrypted[i][c]
                let key = try hybridTransferKey(sid, i, c, ecRecv[i], kemRecv[i], e.count)
                let m = try MpcHash.xor(e, key)
                guard MpcHash.ctEqual(hybridCommit(sid, i, c, m, key), sender.commitments[i][c]) else {
                    throw HybridOtAbort("hybrid base OT (index \(i)): sender ciphertext inconsistent with its commitment; aborting")
                }
                received.append(m)
            }
            return received
        }

        /// TEST-ONLY injection points (nil = honest).
        final class HybridBaseOtTamper {
            var ec: Ot.BaseOtTamper?
            var kem: KemOt.KemMalTamper?
            var tamperEncrypted: ((inout [[[UInt8]]]) -> Void)?
        }

        struct HybridBaseOtTranscript { var sid: [UInt8]; var ecS: Ec.Point; var kemSid: [UInt8]; var encrypted: [[[UInt8]]]; var commitments: [[[UInt8]]] }
        struct HybridBaseOtResult { var received: [[UInt8]]; var transcript: HybridBaseOtTranscript }

        static func hybridBaseOT(_ messages: [[[UInt8]]], _ choices: [Int], _ rng: OtRandom, _ tamper: HybridBaseOtTamper? = nil) throws -> HybridBaseOtResult {
            guard messages.count == choices.count else { throw MpcError("hybridBaseOT: messages/choices length mismatch") }
            let ec = try Ot.malBaseRandomOT(choices, rng, tamper?.ec, nil)
            let kem = try KemOt.kemBaseOtMalRandom(choices, rng, tamper?.kem)
            let sid = hybridSessionId(kem.sid, ec.S)
            var sender = try hybridSenderEncrypt(sid, messages, ec.senderPads, kem.senderSecrets)
            tamper?.tamperEncrypted?(&sender.encrypted)
            let received = try hybridReceiverRecover(sid, choices, sender, ec.recvPads, kem.recvSecrets)
            return HybridBaseOtResult(received: received, transcript: HybridBaseOtTranscript(sid: sid, ecS: ec.S, kemSid: kem.sid, encrypted: sender.encrypted, commitments: sender.commitments))
        }

        /// The hybrid base OT as a pluggable base OT for an OtChannel.
        static var withHybridBaseOt: Ot.BaseOtFn { { m, c, r in try hybridBaseOT(m, c, r, nil).received } }
    }
}
