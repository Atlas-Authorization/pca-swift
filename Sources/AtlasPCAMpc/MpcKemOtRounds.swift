import Foundation

/// The per-party ROUND functions of the ML-KEM base OT (each party's step on its own, so a network driver can run the two roles apart); the
/// combined in-process simulators of MpcKemOt.swift compose the same steps in the same draw order from the OT stream. The malicious-secure
/// flow is: commit (receiver) -> sender nonce -> open (receiver) -> send (sender, aborts when an opened key does not match its commitment) ->
/// recover (receiver).
extension PCAMpc {
    /// Receiver round 1 of the semi-honest flow: both public keys of every transfer (the chosen one at wire index = the choice bit).
    public struct KemOtReceiverMessage: Equatable {
        public var publicKeys: [[[UInt8]]]
        public init(publicKeys: [[[UInt8]]]) { self.publicKeys = publicKeys }
    }

    /// The receiver's retained state: only the chosen secret per transfer (the ML-KEM secret is its 64-byte keygen seed `d || z`).
    public struct KemOtReceiverState {
        public var choices: [Int]
        public var secretKeys: [[UInt8]]
        public init(choices: [Int], secretKeys: [[UInt8]]) { self.choices = choices; self.secretKeys = secretKeys }
    }

    /// Sender wire message: the two ciphertexts and the two padded messages of every transfer.
    public struct KemOtSenderMessage: Equatable {
        public var ciphertexts: [[[UInt8]]]
        public var encrypted: [[[UInt8]]]
        public init(ciphertexts: [[[UInt8]]], encrypted: [[[UInt8]]]) { self.ciphertexts = ciphertexts; self.encrypted = encrypted }
    }

    /// Receiver round 1 of the committed flow: the nonce `rn` and the commitments to the ordered public keys.
    public struct KemMalCommitMessage: Equatable {
        public var rn: [UInt8]
        public var commitments: [[UInt8]]
        public init(rn: [UInt8], commitments: [[UInt8]]) { self.rn = rn; self.commitments = commitments }
    }

    /// Sender round 2: the nonce `sn` that completes the session id.
    public struct KemMalSenderNonce: Equatable {
        public var sn: [UInt8]
        public init(sn: [UInt8]) { self.sn = sn }
    }

    /// Receiver round 3: the committed public keys, opened.
    public struct KemMalOpenMessage: Equatable {
        public var publicKeys: [[[UInt8]]]
        public init(publicKeys: [[[UInt8]]]) { self.publicKeys = publicKeys }
    }

    /// The receiver's retained state across the committed flow.
    public struct KemMalReceiverState {
        public var choices: [Int]
        public var secretKeys: [[UInt8]]
        public var publicKeys: [[[UInt8]]]
        public var rn: [UInt8]
        public init(choices: [Int], secretKeys: [[UInt8]], publicKeys: [[[UInt8]]], rn: [UInt8]) {
            self.choices = choices; self.secretKeys = secretKeys; self.publicKeys = publicKeys; self.rn = rn
        }
    }

    public struct KemMalSenderMessage: Equatable {
        public var ciphertexts: [[[UInt8]]]
        public var encrypted: [[[UInt8]]]
        public init(ciphertexts: [[[UInt8]]], encrypted: [[[UInt8]]]) { self.ciphertexts = ciphertexts; self.encrypted = encrypted }
    }

    /// Sender round 4 of the random-OT form: ciphertexts (the wire part) and both per-slot secrets (sender-local, never sent).
    public struct KemMalRandomSenderMessage: Equatable {
        public var ciphertexts: [[[UInt8]]]
        public var senderSecrets: [[[UInt8]]]
        public init(ciphertexts: [[[UInt8]]], senderSecrets: [[[UInt8]]]) { self.ciphertexts = ciphertexts; self.senderSecrets = senderSecrets }
    }

    // MARK: semi-honest rounds

    /// Receiver round 1: two ML-KEM key pairs per choice bit, the chosen one at wire index `c`; only the chosen secret is retained.
    public static func kemBaseOtReceive(_ choices: [Int], _ rng: OtRandom = .secure()) throws -> (message: KemOtReceiverMessage, state: KemOtReceiverState) {
        let k = try KemOt.receiverKeys(choices, rng)
        return (KemOtReceiverMessage(publicKeys: k.publicKeys), KemOtReceiverState(choices: k.retained, secretKeys: k.seeds))
    }

    /// Sender round: encapsulate under each received key and pad each message under H(slot || shared secret). The two messages of a transfer
    /// must have equal length.
    public static func kemBaseOtSend(_ messages: [[[UInt8]]], _ receiverMessage: KemOtReceiverMessage, _ rng: OtRandom = .secure()) throws -> KemOtSenderMessage {
        let pks = receiverMessage.publicKeys
        guard messages.count == pks.count else { throw MpcError("kemBaseOtSend: messages/publicKeys length mismatch") }
        var cts: [[[UInt8]]] = [], encrypted: [[[UInt8]]] = []
        for i in 0..<messages.count {
            let m0 = messages[i][0], m1 = messages[i][1]
            guard m0.count == m1.count else { throw MpcError("kemBaseOtSend (index \(i)): the two messages must be equal length") }
            let p = try KemOt.encapsulatePair(pks[i], rng)
            cts.append([p.e0.cipherText, p.e1.cipherText])
            encrypted.append([try MpcHash.xor(m0, try KemOt.kemOtPad(i, 0, p.e0.sharedSecret, m0.count)), try MpcHash.xor(m1, try KemOt.kemOtPad(i, 1, p.e1.sharedSecret, m1.count))])
        }
        return KemOtSenderMessage(ciphertexts: cts, encrypted: encrypted)
    }

    /// Receiver recovery: decapsulate only the chosen ciphertext and unmask the chosen message.
    public static func kemBaseOtOpen(_ state: KemOtReceiverState, _ senderMessage: KemOtSenderMessage) throws -> [[UInt8]] {
        guard senderMessage.ciphertexts.count == state.choices.count && senderMessage.encrypted.count == state.choices.count else {
            throw MpcError("kemBaseOtOpen: transcript/state length mismatch")
        }
        var received: [[UInt8]] = []
        for i in 0..<state.choices.count {
            let c = state.choices[i] & 1
            let ss = try MlKem768.decapsulate(senderMessage.ciphertexts[i][c], state.secretKeys[i])
            let e = senderMessage.encrypted[i][c]
            received.append(try MpcHash.xor(e, try KemOt.kemOtPad(i, c, ss, e.count)))
        }
        return received
    }

    // MARK: committed (malicious-secure) rounds

    /// Receiver round 1: generate the key pairs (keeping the chosen secret), draw `rn`, and commit to the ordered public keys.
    public static func kemBaseOtMalCommit(_ choices: [Int], _ rng: OtRandom = .secure()) throws -> (message: KemMalCommitMessage, state: KemMalReceiverState) {
        let rn = rng.bytes(KemOt.NONCE_BYTES)
        var pks: [[[UInt8]]] = [], seeds: [[UInt8]] = [], retained: [Int] = [], commitments: [[UInt8]] = []
        for (i, ch) in choices.enumerated() {
            let c = ch & 1
            let chosen = try MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
            let other = try MlKem768.keygen(rng.bytes(MlKem768.KEYGEN_SEED_BYTES))
            let pair = c == 0 ? [chosen.publicKey, other.publicKey] : [other.publicKey, chosen.publicKey]
            pks.append(pair)
            seeds.append(chosen.seed)
            retained.append(c)
            commitments.append(KemOt.kemMalCommit(rn, i, pair[0], pair[1]))
        }
        return (KemMalCommitMessage(rn: rn, commitments: commitments), KemMalReceiverState(choices: retained, secretKeys: seeds, publicKeys: pks, rn: rn))
    }

    /// Sender round 2: the nonce that completes the session id.
    public static func kemBaseOtMalSenderNonce(_ rng: OtRandom = .secure()) -> KemMalSenderNonce { KemMalSenderNonce(sn: rng.bytes(KemOt.NONCE_BYTES)) }

    /// Receiver round 3: open the committed public keys.
    public static func kemBaseOtMalOpen(_ state: KemMalReceiverState) -> KemMalOpenMessage { KemMalOpenMessage(publicKeys: state.publicKeys) }

    /// Sender round 4: verify the opened keys against the commitments (abort on a mismatch), encapsulate under each, and pad each message
    /// with a (session id, commitment)-bound pad.
    public static func kemBaseOtMalSend(_ messages: [[[UInt8]]], _ commit: KemMalCommitMessage, _ senderNonce: KemMalSenderNonce, _ opening: KemMalOpenMessage,
                                        _ rng: OtRandom = .secure()) throws -> KemMalSenderMessage {
        let pks = opening.publicKeys
        guard messages.count == pks.count && commit.commitments.count == pks.count else { throw MpcError("kemBaseOtMalSend: messages/commitments/publicKeys length mismatch") }
        let sid = KemOt.kemMalSid(commit.rn, senderNonce.sn)
        var cts: [[[UInt8]]] = [], encrypted: [[[UInt8]]] = []
        for i in 0..<messages.count {
            let m0 = messages[i][0], m1 = messages[i][1]
            guard m0.count == m1.count else { throw MpcError("kemBaseOtMalSend (index \(i)): the two messages must be equal length") }
            let com = try KemOt.checkOpening(commit.rn, commit.commitments, pks, i)
            let p = try KemOt.encapsulatePair(pks[i], rng)
            cts.append([p.e0.cipherText, p.e1.cipherText])
            encrypted.append([try MpcHash.xor(m0, KemOt.kemOtMalPad(sid, com, i, 0, p.e0.sharedSecret, m0.count)),
                              try MpcHash.xor(m1, KemOt.kemOtMalPad(sid, com, i, 1, p.e1.sharedSecret, m1.count))])
        }
        return KemMalSenderMessage(ciphertexts: cts, encrypted: encrypted)
    }

    /// Receiver round 5: decapsulate only the chosen ciphertext and unmask with the (session id, commitment)-bound pad. `tamperReceiverSid`
    /// is a TEST-ONLY hook on the session id the receiver derives.
    public static func kemBaseOtMalRecover(_ state: KemMalReceiverState, _ senderNonce: KemMalSenderNonce, _ senderMessage: KemMalSenderMessage,
                                           tamperReceiverSid: (([UInt8]) -> [UInt8])? = nil) throws -> [[UInt8]] {
        guard senderMessage.ciphertexts.count == state.choices.count && senderMessage.encrypted.count == state.choices.count else {
            throw MpcError("kemBaseOtMalRecover: transcript/state length mismatch")
        }
        var sid = KemOt.kemMalSid(state.rn, senderNonce.sn)
        if let t = tamperReceiverSid { sid = t(sid) }
        var received: [[UInt8]] = []
        for i in 0..<state.choices.count {
            let c = state.choices[i] & 1
            let com = KemOt.kemMalCommit(state.rn, i, state.publicKeys[i][0], state.publicKeys[i][1])
            let ss = try MlKem768.decapsulate(senderMessage.ciphertexts[i][c], state.secretKeys[i])
            let e = senderMessage.encrypted[i][c]
            received.append(try MpcHash.xor(e, KemOt.kemOtMalPad(sid, com, i, c, ss, e.count)))
        }
        return received
    }

    /// The session id `H(rn || sn)` both parties of the committed flow derive.
    public static func kemMalSessionId(_ rn: [UInt8], _ sn: [UInt8]) -> [UInt8] { KemOt.kemMalSid(rn, sn) }

    /// Sender round 4 (random-OT form): verify the opened keys (abort on a mismatch), encapsulate, and derive both session-bound secrets per transfer.
    public static func kemBaseOtMalRandomSend(_ commit: KemMalCommitMessage, _ senderNonce: KemMalSenderNonce, _ opening: KemMalOpenMessage,
                                              _ rng: OtRandom = .secure()) throws -> KemMalRandomSenderMessage {
        let pks = opening.publicKeys
        guard commit.commitments.count == pks.count else { throw MpcError("kemBaseOtMalRandomSend: commitments/publicKeys length mismatch") }
        let sid = KemOt.kemMalSid(commit.rn, senderNonce.sn)
        var cts: [[[UInt8]]] = [], secrets: [[[UInt8]]] = []
        for i in 0..<pks.count {
            let com = try KemOt.checkOpening(commit.rn, commit.commitments, pks, i)
            let p = try KemOt.encapsulatePair(pks[i], rng)
            cts.append([p.e0.cipherText, p.e1.cipherText])
            secrets.append([KemOt.kemOtMalSecret(sid, com, i, 0, p.e0.sharedSecret), KemOt.kemOtMalSecret(sid, com, i, 1, p.e1.sharedSecret)])
        }
        return KemMalRandomSenderMessage(ciphertexts: cts, senderSecrets: secrets)
    }

    /// Receiver round 5 (random-OT form): the chosen session-bound secret per transfer.
    public static func kemBaseOtMalRandomRecover(_ state: KemMalReceiverState, _ senderNonce: KemMalSenderNonce, _ senderMessage: KemMalRandomSenderMessage,
                                                 tamperReceiverSid: (([UInt8]) -> [UInt8])? = nil) throws -> [[UInt8]] {
        guard senderMessage.ciphertexts.count == state.choices.count else { throw MpcError("kemBaseOtMalRandomRecover: transcript/state length mismatch") }
        var sid = KemOt.kemMalSid(state.rn, senderNonce.sn)
        if let t = tamperReceiverSid { sid = t(sid) }
        var recv: [[UInt8]] = []
        for i in 0..<state.choices.count {
            let c = state.choices[i] & 1
            let com = KemOt.kemMalCommit(state.rn, i, state.publicKeys[i][0], state.publicKeys[i][1])
            recv.append(KemOt.kemOtMalSecret(sid, com, i, c, try MlKem768.decapsulate(senderMessage.ciphertexts[i][c], state.secretKeys[i])))
        }
        return recv
    }
}
