import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCAMpc

/// Differential replay of the oblivious-transfer stack of the MPC package against the reference (@atlasauth/pca-mpc): the Ed25519 group and Schnorr proof, the
/// word-array kernels, the base OT, IKNP / KOS extension, the ML-KEM and hybrid base OTs, the MASCOT no-dealer offline phase and the no-dealer malicious
/// runner. Every draw comes from a seeded stream. Big integers travel as decimal strings; bytes as {"$bytes": b64url}.
///
/// Platform notes. AES-128, SHAKE256 and ML-KEM-768 are OpenSSL libcrypto's on every platform; ML-KEM (seeded key generation, encapsulation from the
/// reference's 32-byte message) needs OpenSSL 3.5, and below that the KEM and hybrid cases are skipped. Their ciphertexts are compared byte for byte.
final class RefMpcOtTests: XCTestCase {
    typealias M = PCAMpc
    typealias T = RefMpcTests
    typealias Bad = RefMpcTests.Bad
    static let file = "ref-mpc-ot.json.gz"

    // MARK: argument / result codecs

    static func by(_ v: JSONValue?) throws -> [UInt8] {
        if let s = v?.asString { guard let b = Base64URLStrict.decode(s) else { throw Bad() }; return b }
        guard let b = Base.bytes(v) else { throw Bad() }
        return b
    }
    static func BY(_ b: [UInt8]) -> JSONValue { Base.bytesValue(b) }
    static func BL(_ a: [[UInt8]]) -> JSONValue { .array(a.map(BY)) }
    static func PAIRS(_ a: [[[UInt8]]]) -> JSONValue { .array(a.map { .array([BY($0[0]), BY($0[1])]) }) }
    static func pairs(_ v: JSONValue?) throws -> [[[UInt8]]] {
        guard let a = v?.asArray else { throw Bad() }
        return try a.map { e in
            guard let p = e.asArray, p.count == 2 else { throw Bad() }
            return [try by(p[0]), try by(p[1])]
        }
    }
    static func ints(_ v: JSONValue?) throws -> [Int] { try T.IA(v) }

    static func words(_ v: JSONValue?) throws -> [UInt32] {
        guard let a = v?.asArray else { throw Bad() }
        return try a.map { x in
            guard let d = IV.num(x), d >= 0, d <= 4294967295, d == d.rounded() else { throw Bad() }
            return UInt32(d)
        }
    }
    static func WJ(_ w: [UInt32]) -> JSONValue { .array(w.map { .int(Int64($0)) }) }
    static func str(_ s: String) -> JSONValue { .string(s) }

    static func P(_ v: JSONValue?) throws -> M.Ec.Point {
        guard let a = v?.asArray, a.count == 4 else { throw Bad() }
        let f = try a.map { x -> M.Fe in
            guard let s = x.asString, let f = M.Fe(decimal: s) else { throw Bad() }
            return f
        }
        return M.Ec.Point(f[0], f[1], f[2], f[3])
    }
    static func aff(_ p: M.Ec.Point) -> JSONValue { let a = M.Ec.toAffine(p); return .object(["x": str(a.x.decimal), "y": str(a.y.decimal)]) }
    static func SC(_ v: JSONValue?) throws -> M.Scalar {
        guard let s = v?.asString, let x = M.Sodium.scalar(decimal: s) else { throw Bad() }
        return x
    }
    static func u64(_ v: JSONValue?) throws -> UInt64 {
        guard let s = v?.asString, let p = M.Dec.parse(s, maxLimbs: 2), !p.neg, p.mag[1] == 0 else { throw Bad() }
        return p.mag[0]
    }
    static func u64s(_ v: JSONValue?) throws -> [UInt64] { guard let a = v?.asArray else { throw Bad() }; return try a.map { try u64($0) } }
    static func DS(_ x: UInt64) -> JSONValue { str(String(x)) }
    static func DL(_ xs: [UInt64]) -> JSONValue { .array(xs.map(DS)) }
    static func orng(_ v: JSONValue?) throws -> M.OtRandom {
        guard let s = v?.asString, let x = M.Field.low64(s) else { throw Bad() }
        return M.OtRandom.splitMix(seed: x)
    }
    static func seed(_ v: JSONValue?) throws -> UInt64 {
        guard let s = v?.asString, let x = M.Field.low64(s) else { throw Bad() }
        return x
    }
    static func idx(_ v: JSONValue?) throws -> Int64 {
        guard let d = IV.num(v), d.isFinite, d == d.rounded(), abs(d) < 9e15 else { throw Bad() }
        return Int64(d)
    }
    static func flip(_ b: [UInt8], _ mask: UInt8) -> [UInt8] { b.map { $0 ^ mask } }

    static let ORDER2 = M.Ec.Point(.zero, M.Fe.zero - M.Fe.one, .one, .zero)

    static func tamper(_ name: String) -> M.Ot.BaseOtTamper? {
        let t = M.Ot.BaseOtTamper()
        switch name {
        case "none": return nil
        case "S_identity": t.tamperS = { _ in M.Ec.identity }
        case "S_order2": t.tamperS = { _ in ORDER2 }
        case "S_other": t.tamperS = { s in (try? M.Ec.add(s, M.Ec.base)) ?? s }
        case "proof_z": t.tamperProof = { p in M.Ec.SchnorrProof(U: p.U, z: M.Sodium.add(p.z, M.Sodium.one)) }
        case "proof_U": t.tamperProof = { p in M.Ec.SchnorrProof(U: (try? M.Ec.add(p.U, M.Ec.base)) ?? p.U, z: p.z) }
        case "R0_identity": t.tamperR = { R in if !R.isEmpty { R[0] = M.Ec.identity } }
        case "R1_order2": t.tamperR = { R in if R.count > 1 { R[1] = ORDER2 } }
        case "R_swap": t.tamperR = { R in if R.count > 1 { R.swapAt(0, 1) } }
        case "ct_flip": t.tamperCiphertext = { ct in if !ct.isEmpty { ct[0][0] = flip(ct[0][0], 1) } }
        case "ct_flip1": t.tamperCiphertext = { ct in if !ct.isEmpty { ct[ct.count - 1][1] = flip(ct[ct.count - 1][1], 0x80) } }
        default: return nil
        }
        return t
    }

    static func kemTamper(_ name: String?) -> M.KemOt.KemMalTamper? {
        let t = M.KemOt.KemMalTamper()
        if name == "badKey" { t.tamperOpenedKeys = { pk in if !pk.isEmpty { pk[0].swapAt(0, 1) } } }
        else if name == "badSid" { t.tamperReceiverSid = { flip($0, 1) } }
        else { return nil }
        return t
    }

    static func binding(_ sess: JSONValue?, _ a: JSONValue?, _ b: JSONValue?, _ round: JSONValue?) throws -> M.Ot.BaseOtBinding {
        guard let r = round?.asString else { throw Bad() }
        return M.Ot.BaseOtBinding(sessionId: try by(sess), senderIndex: try idx(a), receiverIndex: try idx(b), round: r)
    }

    static func tripleJSON(_ t: M.Spdz.AuthTriple) -> JSONValue { T.tripleJSON(t) }

    static func fill(_ n: Int, _ v: UInt8) -> [UInt8] { [UInt8](repeating: v, count: n) }

    /// Skips (nil) a case the platform cannot run (no ML-KEM); everything else is a value or a refusal.
    func go(_ f: () throws -> JSONValue) -> BaseGot? {
        do { return .value(try f()) } catch {
            let m = "\(error)"
            if m.contains("is not available") { return nil }
            // a refusal without a stable code carries its text, so a divergence in the log names the refusal
            return .threw(Ref.code(error) ?? String(m.prefix(200)))
        }
    }

    /// The combined simulators of the KEM base OT.
    static func kemMain(_ c: BaseCase) throws -> JSONValue {
        let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
                    let fn = a0?.asString ?? "", tn = c.arg(4)?.asString
                    let g = try Self.orng(a3)
                    let choices = try Self.ints(a2)
                    switch fn {
                    case "kemBaseOT":
                        let r = try M.KemOt.kemBaseOT(try Self.pairs(a1), choices, g)
                        let t = r.transcript
                        return .object(["received": Self.BL(r.received), "transcript": .object(["publicKeys": Self.PAIRS(t.publicKeys), "ciphertexts": Self.PAIRS(t.ciphertexts), "encrypted": Self.PAIRS(t.encrypted)])])
                    case "kemBaseOtMal":
                        let r = try M.KemOt.kemBaseOtMal(try Self.pairs(a1), choices, g, Self.kemTamper(tn))
                        let t = r.transcript
                        return .object(["received": Self.BL(r.received), "transcript": .object(["rn": Self.BY(t.rn), "commitments": Self.BL(t.commitments), "sn": Self.BY(t.sn),
                                                                                                  "publicKeys": Self.PAIRS(t.publicKeys), "ciphertexts": Self.PAIRS(t.ciphertexts), "encrypted": Self.PAIRS(t.encrypted)])])
                    default:
                        let r = try M.KemOt.kemBaseOtMalRandom(choices, g, Self.kemTamper(tn))
                        let t = r.transcript
                        // native pairing check: what the receiver recovers is the sender's secret for the chosen slot
                        for i in 0..<choices.count where r.recvSecrets[i] != r.senderSecrets[i][choices[i] & 1] && tn != "badSid" { throw M.MpcError("kem random OT: receiver secret does not match the sender's chosen slot") }
                        return .object(["senderSecrets": Self.PAIRS(r.senderSecrets), "recvSecrets": Self.BL(r.recvSecrets), "sid": Self.BY(r.sid),
                                        "transcript": .object(["rn": Self.BY(t.rn), "commitments": Self.BL(t.commitments), "sn": Self.BY(t.sn), "publicKeys": Self.PAIRS(t.publicKeys), "ciphertexts": Self.PAIRS(t.ciphertexts)])])
                    }
    }

    /// The same flows composed from the per-party round functions.
    static func kemRounds(_ c: BaseCase) throws -> JSONValue {
        let fn = c.arg(0)?.asString ?? "", tn = c.arg(4)?.asString
        let msgs = try pairs(c.arg(1)), choices = try ints(c.arg(2))
        let g = try orng(c.arg(3))
        let t = kemTamper(tn)
        if fn == "kemBaseOT" {
            let rm = try M.kemBaseOtReceive(choices, g)
            let sm = try M.kemBaseOtSend(msgs, rm.message, g)
            let received = try M.kemBaseOtOpen(rm.state, sm)
            return .object(["received": BL(received), "transcript": .object(["publicKeys": PAIRS(rm.message.publicKeys), "ciphertexts": PAIRS(sm.ciphertexts), "encrypted": PAIRS(sm.encrypted)])])
        }
        let cm = try M.kemBaseOtMalCommit(choices, g)
        let nonce = M.kemBaseOtMalSenderNonce(g)
        var opening = M.kemBaseOtMalOpen(cm.state)
        t?.tamperOpenedKeys?(&opening.publicKeys)
        func transcript(_ cts: [[[UInt8]]], _ enc: [[[UInt8]]]?) -> JSONValue {
            var o: JObject = ["rn": BY(cm.message.rn), "commitments": BL(cm.message.commitments), "sn": BY(nonce.sn), "publicKeys": PAIRS(opening.publicKeys), "ciphertexts": PAIRS(cts)]
            if let e = enc { o["encrypted"] = PAIRS(e) }
            return .object(o)
        }
        if fn == "kemBaseOtMal" {
            let sm = try M.kemBaseOtMalSend(msgs, cm.message, nonce, opening, g)
            let received = try M.kemBaseOtMalRecover(cm.state, nonce, sm, tamperReceiverSid: t?.tamperReceiverSid)
            return .object(["received": BL(received), "transcript": transcript(sm.ciphertexts, sm.encrypted)])
        }
        let sm = try M.kemBaseOtMalRandomSend(cm.message, nonce, opening, g)
        let recv = try M.kemBaseOtMalRandomRecover(cm.state, nonce, sm, tamperReceiverSid: t?.tamperReceiverSid)
        return .object(["senderSecrets": PAIRS(sm.senderSecrets), "recvSecrets": BL(recv), "sid": BY(M.kemMalSessionId(cm.message.rn, nonce.sn)), "transcript": transcript(sm.ciphertexts, nil)])
    }

    // MARK: replay

    func testOtStack() throws {
        try K042.requireCovers(["Mpc"])
        let d = Base.Diffs()
        let body: (BaseCase) throws -> Void = { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
            let isKem = c.fn == "kemOt" || c.fn == "hybridOt"
            if isKem && !M.MlKem768.available { d.skip("ML-KEM-768 is not available on this OS (needs OpenSSL 3.5)"); return }
            let got: BaseGot? = self.go {
                switch c.fn {
                // ---- group
                case "ecOp":
                    switch a0?.asString {
                    case "mulBase":
                        let p = try M.Ec.mulBase(try Self.SC(a1))
                        return .object(["p": Self.aff(p), "enc": Self.BY(M.Ec.encodePoint(p)), "comp": Self.BY(M.Ec.compressPoint(p))])
                    case "mul": return Self.aff(try M.Ec.mul(try Self.SC(a1), try Self.P(a2)))
                    case "add": return Self.aff(try M.Ec.add(try Self.P(a1), try Self.P(a2)))
                    case "sub": return Self.aff(try M.Ec.sub(try Self.P(a1), try Self.P(a2)))
                    case "neg": return Self.aff(try M.Ec.neg(try Self.P(a1)))
                    case "dbl": return Self.aff(try M.Ec.dbl(try Self.P(a1)))
                    case "decompress":
                        let enc = try Self.by(a1)
                        // the flat, byte-level surface answers exactly as the reference's wasm group core: strict decoding, never reducing
                        XCTAssertEqual(M.isOnCurve(enc), !c.threw, c.name)
                        if c.threw { XCTAssertFalse(M.isInSubgroup(enc)); XCTAssertThrowsError(try M.decodePoint(enc)); XCTAssertThrowsError(try M.assertInSubgroup(enc)) }
                        let p = try M.Ec.decompressPoint(enc)
                        XCTAssertEqual(M.isInSubgroup(enc), M.Ec.isInSubgroup(p), c.name)
                        XCTAssertTrue(M.equal(enc, enc), c.name)
                        XCTAssertEqual(try M.decodePoint(enc), enc)
                        XCTAssertEqual(try M.encodePoint(enc), enc)
                        if M.Ec.isInSubgroup(p) { XCTAssertNoThrow(try M.assertInSubgroup(enc)) } else { XCTAssertThrowsError(try M.assertInSubgroup(enc)) }
                        return .object(["p": Self.aff(p), "onCurve": .bool(M.Ec.isOnCurve(p)), "identity": .bool(M.Ec.isIdentity(p)),
                                        "prime": .bool(M.Ec.hasPrimeOrder(p)), "inSub": .bool(M.Ec.isInSubgroup(p))])
                    default: throw Bad()
                    }
                case "ecValidate":
                    let p = try Self.P(a0)
                    return .object(["onCurve": .bool(M.Ec.isOnCurve(p)), "identity": .bool(M.Ec.isIdentity(p)), "prime": .bool(M.Ec.hasPrimeOrder(p)), "inSubgroup": .bool(M.Ec.isInSubgroup(p))])
                case "ecAssert":
                    try M.Ec.assertInSubgroup(try Self.P(a0), "p")
                    return .bool(true)
                case "schnorr":
                    let y = try Self.SC(a0), nonce = try Self.SC(a1)
                    let ctx = try Self.by(a2)
                    let S = try M.Ec.mulBase(y)
                    let proof = try M.Ec.schnorrProve(y, S, { nonce }, ctx)
                    let other = Array("other-ctx".utf8)
                    let forged = M.Ec.SchnorrProof(U: proof.U, z: M.Sodium.add(proof.z, M.Sodium.one))
                    let oor = M.Ec.SchnorrProof(U: proof.U, z: M.Sodium.L)
                    return .object(["S": Self.aff(S), "U": Self.aff(proof.U), "z": Self.str(M.Sodium.decimal(proof.z)), "ok": .bool(M.Ec.schnorrVerify(S, proof, ctx)),
                                    "badCtx": .bool(M.Ec.schnorrVerify(S, proof, other)), "forged": .bool(M.Ec.schnorrVerify(S, forged, ctx)), "oor": .bool(M.Ec.schnorrVerify(S, oor, ctx)),
                                    "wrongS": .bool(M.Ec.schnorrVerify(try M.Ec.mulBase(M.Sodium.add(y, M.Sodium.one)), proof, ctx)),
                                    "identityS": .bool(M.Ec.schnorrVerify(M.Ec.identity, proof, ctx))])
                // ---- kernels
                case "prg": return Self.WJ(try M.Otx.prgColumn(try Self.by(a0), UInt64(try T.I(a1)), try T.I(a2)))
                case "maskTail": var w = try Self.words(a0); try M.Otx.maskTail(&w, try T.I(a1)); return Self.WJ(w)
                case "transpose32": var w = try Self.words(a0); try M.Otx.transpose32(&w, 0); return Self.WJ(w)
                case "transposeCols": return Self.WJ(try M.Otx.transposeCols(try Self.words(a0), try T.I(a1), try T.I(a2)))
                case "gfMulX": var w = try Self.words(a0); try M.Otx.gfMulX(&w); return Self.WJ(w)
                case "gfXorInto": var w = try Self.words(a0); try M.Otx.gfXorInto(&w, try Self.words(a1), 0); return Self.WJ(w)
                case "gfBig":
                    let big = try M.Otx.gfToBig(try Self.words(a0))
                    return .object(["big": Self.str(big.decimal), "back": Self.WJ(M.Otx.gfFromBig(big))])
                case "accumColumn":
                    let col = try Self.words(a0)
                    var acc = [UInt32](repeating: 0, count: 4)
                    try M.Otx.accumColumn(col, 0, col.count, try Self.words(a1), &acc)
                    return Self.WJ(acc)
                case "kosCombine": return Self.WJ(try M.Otx.kosCombine(try Self.words(a0), try T.I(a1), try Self.words(a2)))
                case "tmmo": return Self.WJ(try M.Otx.tmmoCrh(try Self.words(a0), try T.I(a1), offset: try Self.idx(a2), domain: try Self.words(a3)))
                case "tweakDomain": return Self.WJ(try M.Otx.otTweakDomain(try Self.by(a0)))
                case "bigBytes":
                    guard let s = a0?.asString, let p = M.Dec.parse(s, maxLimbs: 8), !p.neg else { throw Bad() }
                    return Self.BY(M.Otx.bigToBytes(p.mag, try T.I(a1)))
                case "bytesBig": return Self.str(M.Dec.string(M.Otx.bytesToBig(try Self.by(a0))))
                case "word64": return Self.DS(try M.Otx.word64(try Self.words(a0), try T.I(a1)))
                // ---- base OT
                case "bindingBytes": return Self.BY(try M.Ot.bindingBytes(try Self.binding(a0, a1, a2, a3)))
                case "baseOtKdf":
                    let b0 = M.Ot.randomBinding(M.OtRandom.splitMix(seed: 4242), "base-ot")
                    let R = [try M.Ec.mulBase(Self.scalar(5)), try M.Ec.mulBase(Self.scalar(6))]
                    let th = try M.Ot.baseOtTranscriptHash(b0, try M.Ec.mulBase(Self.scalar(3)), R)
                    return .object(["th": Self.BY(th), "k": Self.BY(M.Ot.baseOtKdf(th, try T.I(a0), R[0], try M.Ec.mulBase(Self.scalar(9))))])
                case "randomOt":
                    let r = try M.Ot.malBaseRandomOT(try Self.ints(a0), try Self.orng(a1), Self.tamper(a2?.asString ?? "none"), nil)
                    return .object(["S": Self.aff(r.S), "U": Self.aff(r.proof.U), "z": Self.str(M.Sodium.decimal(r.proof.z)), "R": .array(r.R.map(Self.aff)),
                                    "senderPads": Self.PAIRS(r.senderPads), "recvPads": Self.BL(r.recvPads)])
                case "baseOt":
                    let r = try M.Ot.baseOT(try Self.pairs(a0), try Self.ints(a1), try Self.orng(a2), Self.tamper(a3?.asString ?? "none"), nil)
                    let t = r.transcript
                    return .object(["received": Self.BL(r.received), "S": Self.aff(t.S), "U": Self.aff(t.proof.U), "z": Self.str(M.Sodium.decimal(t.proof.z)),
                                    "R": .array(t.R.map(Self.aff)), "ct": Self.PAIRS(t.ct), "com": Self.PAIRS(t.com)])
                // ---- extension
                case "channel":
                    let ch = M.Ot.OtChannel(try Self.orng(a3))
                    switch c.arg(5)?.asString {
                    case "flip00": ch.tamperU = { u, _ in u[0].flipBit(0) }
                    case "flipLast": ch.tamperU = { u, _ in u[127].flipBit(5) }
                    case "oversize": ch.tamperU = { u, _ in u[3].flipBit(5000) }
                    case "negative": ch.tamperU = { u, _ in u[3] = M.BigN(neg: true, mag: [1]) }
                    case "round2flip": ch.tamperU = { u, round in if round == 1 { u[10].flipBit(1) } }
                    default: break
                    }
                    var outs: [JSONValue] = []
                    for _ in 0..<(try T.I(c.arg(4))) {
                        let e = try ch.extend(try Self.ints(a0), try Self.u64s(a1), try Self.u64s(a2))
                        outs.append(.object(["received": Self.DL(e.received), "uMatrix": .array(e.uMatrix.map { Self.str($0.decimal) })]))
                    }
                    let base: JSONValue = ch.baseTranscript.map { .object(["S": Self.aff($0.S), "R": .int(Int64($0.R.count))]) } ?? .null
                    return .object(["selector": Self.str(try ch.selector().decimal), "outs": .array(outs), "base": base])
                case "kosChi":
                    let u = try T.A(a2).map { v -> M.BigN in
                        guard let s = v.asString, let p = M.Dec.parse(s, maxLimbs: 8), !p.neg else { throw Bad() }
                        return M.BigN(mag: p.mag)
                    }
                    let b = try Self.by(a0), round = try T.I(a1), mExt = try T.I(c.arg(3))
                    let chi = try M.Ot.kosChallenges(b, round, u, mExt)
                    return .object(["w": Self.WJ(try M.Ot.kosChiWords(b, round, u, mExt)), "chi": .array(chi.map { Self.str($0.decimal) })])
                // ---- KEM / hybrid
                case "kemOt":
                    // the combined simulators and the per-party round functions must agree on the result and on refusal
                    let main = Result<JSONValue, Error> { try Self.kemMain(c) }
                    let alt = Result<JSONValue, Error> { try Self.kemRounds(c) }
                    switch (main, alt) {
                    case let (.success(m), .success(r)): XCTAssertEqual(m, r, "round functions differ from the simulator")
                    case (.failure, .failure): break
                    default: XCTFail("round functions and the simulator disagree on refusal: \(main) vs \(alt)")
                    }
                    return try main.get()
                case "kemPad":
                    var ss = [UInt8](repeating: 0, count: 32)
                    for k in 0..<32 { ss[k] = UInt8(k) }
                    if c.args.count == 1 { return Self.BY(try M.KemOt.kemOtPad(0, 0, [UInt8](repeating: 0, count: 32), try T.I(a0))) }
                    return Self.BY(try M.KemOt.kemOtPad(try T.I(a0), try T.I(a1), ss, try T.I(a2)))
                case "hybridOt":
                    let tn = a3?.asString
                    let t = M.HybridOt.HybridBaseOtTamper()
                    switch tn {
                    case "ec": t.ec = Self.tamper("ct_flip")
                    case "ecS": t.ec = Self.tamper("S_identity")
                    case "enc": t.tamperEncrypted = { e in if !e.isEmpty { e[0][0] = Self.flip(e[0][0], 1) } }
                    case "kem": t.kem = Self.kemTamper("badKey")
                    default: break
                    }
                    let r = try M.HybridOt.hybridBaseOT(try Self.pairs(a0), try Self.ints(a1), try Self.orng(a2), t)
                    let tr = r.transcript
                    return .object(["received": Self.BL(r.received), "sid": Self.BY(tr.sid), "ecS": Self.aff(tr.ecS), "kemSid": Self.BY(tr.kemSid),
                                    "encrypted": Self.PAIRS(tr.encrypted), "commitments": Self.PAIRS(tr.commitments)])
                case "hybridKey":
                    return Self.BY(try M.HybridOt.hybridTransferKey(Self.fill(32, 1), 3, 1, Self.fill(16, 2), Self.fill(32, 3), try T.I(a0)))
                // ---- MASCOT
                case "offline": return try Self.offline(c)
                case "offlineBlame":
                    var opts = M.Mascot.NoDealerOptions()
                    opts.deviation = M.Mascot.OfflineDeviation(productMul: try T.I(c.arg(2)), delta: try T.B(c.arg(3)))
                    do {
                        _ = try M.Mascot.makeNoDealerOffline(try T.I(a0), seed: try Self.seed(a1), opts).genAuthTriple()
                        return .object(["aborted": .bool(false)])
                    } catch let e as M.Mascot.OfflineCheatingAbort {
                        return .object(["aborted": .bool(true), "name": Self.str("OfflineCheatingAbort"), "blamed": .array(e.blamed.map { .int(Int64($0)) })])
                    }
                case "noDealerRun":
                    guard let o = a1, o.asObject != nil else { throw Bad() }
                    var cfg = M.MaliciousConfig()
                    if let q = o.get("Q"), q != .null { cfg.Q = try T.I(q) }
                    if let sd = o.get("seed"), sd != .null { cfg.seed = try Self.seed(sd) }
                    if let dv = o.get("deviations"), dv != .null { cfg.deviations = try T.devs(dv) }
                    let r = try M.composeSecureMalicious(try T.vectors(a0), cfg)
                    return .object(["composed": T.decisionJSON(r.composed), "parties": .int(Int64(r.parties)), "Q": .int(Int64(r.Q)), "opens": .int(Int64(r.opens)),
                                    "multiplications": .int(Int64(r.multiplications)), "offlineMode": .string(r.offlineMode), "triplesVerified": .bool(r.triplesVerified), "macChecked": .bool(r.macChecked)])
                default: throw Bad()
                }
            }
            guard let g = got else { d.skip("platform provides no ML-KEM for this case"); return }
            d.add(c, Base.diff(c, g))
        }
        try Base.each(Self.file, nil, body)
        // the cases that carry private keys live in ref-mpc-ot-gen.json.gz (CI-generated)
        if let g = K042.secretCorpusPath(Self.file) { try Base.each(g, nil, body) }
        d.finish(250)
    }

    static func scalar(_ n: Int) -> M.Scalar { M.Sodium.scalar(decimal: String(n))! }

    /// The MASCOT offline phase cases: ["offline", n, seed, what, opts].
    static func offline(_ c: BaseCase) throws -> JSONValue {
        let n = try T.I(c.arg(0))
        let seed = try Self.seed(c.arg(1))
        guard let what = c.arg(2)?.asString else { throw Bad() }
        let o = c.arg(3)
        var opts: M.Mascot.NoDealerOptions? = nil
        if let o = o, o != .null {
            guard o.asObject != nil else { throw Bad() }
            var x = M.Mascot.NoDealerOptions()
            if let v = o.get("sacrifice"), v != .null { guard case let .bool(b) = v else { throw Bad() }; x.sacrifice = b }
            if let v = o.get("partners"), v != .null { x.sacrificePartners = try T.I(v) }
            if let v = o.get("keys"), v != .null { x.macKeys = try T.I(v) }
            if let v = o.get("statSec"), v != .null { x.statSec = try T.I(v) }
            x.unsafeStatSec = o.get("unsafe") == .bool(true)
            if let dv = o.get("dev"), dv != .null {
                guard let a = dv.asArray, a.count >= 2 else { throw Bad() }
                x.deviation = M.Mascot.OfflineDeviation(productMul: try T.I(a[0]), delta: try T.B(a[1]))
            }
            opts = x
        }
        let off = try M.Mascot.makeNoDealerOffline(n, seed: seed, opts ?? M.Mascot.NoDealerOptions())
        var base: JObject = ["n": .int(Int64(off.n)), "statSec": .int(Int64(off.statSec)), "ctx": T.ctxJSON(off.macContext())]
        switch what {
        case "ctx": return .object(base)
        case "triple": base["t"] = T.tripleJSON(try off.genAuthTriple()); return .object(base)
        case "input": base["v"] = T.svJSON(try off.authInput(try T.B(o?.get("value")), try T.I(o?.get("owner")))); return .object(base)
        case "multiply":
            let x = try T.BAs(o?.get("x")), y = try T.BAs(o?.get("y"))
            let z = try off.otShareMultiply(x, y)
            base["z"] = T.SL(z)
            base["sum"] = T.S(z.reduce(0, M.Field.add))
            base["expect"] = T.S(M.Field.mul(x.reduce(0, M.Field.add), y.reduce(0, M.Field.add)))
            return .object(base)
        case "consistency":
            guard let values = o?.get("values")?.asArray else { throw Bad() }
            var ins: [M.Spdz.AuthSV] = []
            for (i, v) in values.enumerated() { ins.append(try off.authInput(try T.B(v), i % n)) }
            if o?.get("tamper") == .bool(true) { ins[0].value[0] = M.Field.add(ins[0].value[0], 1) }
            try off.checkInputConsistency(ins)
            base["ok"] = .bool(true)
            return .object(base)
        default: throw Bad()
        }
    }

    // MARK: anchors

    /// The mpc workflow installs OpenSSL 3.5: there the KEM cases must have run, never been skipped.
    func testMlKemAvailableWhereRequired() throws {
        guard ProcessInfo.processInfo.environment["PCA_MPC_REQUIRE_KEM"] == "1" else { throw XCTSkip("ML-KEM is optional here (needs OpenSSL 3.5)") }
        XCTAssertTrue(M.MlKem768.available)
    }

    /// NIST SHAKE256 known answer (the empty message) and the squeeze-prefix property.
    func testShake256() throws {
        let hex = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        let out = try M.Shake256.hash([], outLen: 32)
        XCTAssertEqual(out.map { String(format: "%02x", $0) }.joined(), hex)
        XCTAssertEqual(Array(try M.Shake256.hash([[], []], outLen: 300)[0..<32]), out)
        XCTAssertEqual(try M.Shake256.hash([[1, 2], [3]], outLen: 200), try M.Shake256.hash([[1, 2, 3]], outLen: 200))
    }

    /// The Ed25519 base point's RFC 8032 encoding and the group order.
    func testGroupAnchors() throws {
        XCTAssertEqual(M.Ec.compressPoint(M.Ec.base), [0x58] + [UInt8](repeating: 0x66, count: 31))
        XCTAssertTrue(M.Ec.isInSubgroup(M.Ec.base))
        XCTAssertTrue(M.Ec.isIdentity(try M.Ec.mulBase(M.Sodium.zero)))
        XCTAssertEqual(M.Sodium.decimal(M.Sodium.L), "7237005577332262213973186563042994240857116359379907606001950938285454250989")
    }
}
