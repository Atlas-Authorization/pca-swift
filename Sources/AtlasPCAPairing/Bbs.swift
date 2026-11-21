import Foundation
import CBlst

/// BBS signatures over BLS12-381 (draft-irtf-cfrg-bbs-signatures, ciphersuite BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_): signatures
/// and generators in G1 (48 bytes), public keys in G2 (96 bytes), scalars 32 bytes big-endian. Group arithmetic, hash-to-curve
/// and scalar arithmetic are blst's.
public enum Bbs {
    /// Bounds the messages in one credential (a verifier derives the count from attacker-supplied proof length).
    public static let maxMessages = 1024

    static let apiID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_"
    static let h2sDST = Array((apiID + "H2S_").utf8)
    static let mapDST = Array((apiID + "MAP_MSG_TO_SCALAR_AS_HASH_").utf8)
    static let seedDST = Array((apiID + "SIG_GENERATOR_SEED_").utf8)
    static let genDST = Array((apiID + "SIG_GENERATOR_DST_").utf8)
    static let genSeed = Array((apiID + "MESSAGE_GENERATOR_SEED").utf8)
    static let keygenDST = Array((apiID + "KEYGEN_DST_").utf8)
    static let scalarLen = 32, pointLen = 48, expandLen = 48
    /// The published fixed G1 generator P1 of the ciphersuite (draft section 7.2.2).
    static let p1Hex = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9"

    static let bp2 = G2.generator
    static let p1: G1 = {
        var b: [UInt8] = []
        var it = p1Hex.makeIterator()
        while let h = it.next(), let l = it.next() { b.append(UInt8(String([h, l]), radix: 16)!) }
        guard let p = G1(compressed: b) else { fatalError("BBS P1 generator does not decode") }
        return p
    }()

    public struct Result: Equatable {
        public let ok: Bool
        public let reason: String?
        static let pass = Result(ok: true, reason: nil)
        static func fail(_ r: String) -> Result { Result(ok: false, reason: r) }
    }

    // ---- scalars and hashing

    static func i2osp(_ n: Int, _ len: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: len)
        var v = UInt64(n)
        for i in stride(from: len - 1, through: 0, by: -1) { out[i] = UInt8(v & 0xff); v >>= 8 }
        return out
    }

    /// hash_to_scalar(msg, dst): OS2IP(expand_message_xmd(msg, dst, 48)) mod r.
    public static func hashToScalar(_ msg: [UInt8], dst: [UInt8]) throws -> Fr { Fr(reducing: try Bls12.expandMessageXmd(msg, dst, expandLen)) }

    public static func mapMessageToScalarAsHash(_ m: [UInt8]) throws -> Fr { try hashToScalar(m, dst: mapDST) }

    static func scalars(_ msgs: [[UInt8]]) throws -> [Fr] { try msgs.map { try mapMessageToScalarAsHash($0) } }

    // ---- points

    static func isInfEncoding(_ b: [UInt8]) -> Bool { b[0] & 0x40 != 0 }

    static func decodeG1(_ b: [UInt8]) -> G1? { b.count == pointLen ? G1(compressed: b) : nil }
    static func decodeG2(_ b: [UInt8]) -> G2? { b.count == 96 ? G2(compressed: b) : nil }

    // ---- generators

    static func createGens(_ count: Int) throws -> [G1] {
        if count < 0 { throw PairingError("bbs: generator count must be a non-negative integer") }
        if count > maxMessages + 1 { throw PairingError("bbs: at most \(maxMessages) messages are supported") }
        var gens: [G1] = []
        var v = try Bls12.expandMessageXmd(genSeed, seedDST, expandLen)
        for i in 0..<count {
            v = try Bls12.expandMessageXmd(v + i2osp(i + 1, 8), seedDST, expandLen)
            gens.append(G1.hash(v, dst: genDST))
        }
        return gens
    }

    /// create_generators(count): the deterministic compressed generators (Q_1, H_1, ...).
    public static func createGenerators(_ count: Int) throws -> [[UInt8]] { try createGens(count).map { $0.compressed } }

    // ---- serialization

    struct Ser {
        var buf: [UInt8] = []
        mutating func g1(_ p: G1) { buf += p.compressed }
        mutating func scalar(_ v: Fr) { buf += v.bytes }
        mutating func int(_ n: Int) { buf += Bbs.i2osp(n, 8) }
    }

    // ---- key generation

    /// Derives a secret scalar from at least 32 octets of key material and optional info (draft 3.4.1).
    public static func keyGen(keyMaterial: [UInt8], keyInfo: [UInt8] = []) throws -> Fr {
        if keyMaterial.count < 32 { throw PairingError("bbs: key material must be at least 32 octets") }
        if keyInfo.count > 65535 { throw PairingError("bbs: key info must be at most 65535 octets") }
        let sk = try hashToScalar(keyMaterial + i2osp(keyInfo.count, 2) + keyInfo, dst: keygenDST)
        if sk.isZero { throw PairingError("bbs: derived SK is zero (retry with different key material)") }
        return sk
    }

    /// The compressed G2 public key SK * BP2.
    public static func skToPk(_ sk: Fr) throws -> [UInt8] {
        if sk.isZero { throw PairingError("bbs: secret key is zero") }
        return (sk * bp2).compressed
    }

    /// A fresh key pair from the system CSPRNG.
    public static func generateKeyPair() throws -> (sk: Fr, pk: [UInt8]) {
        var rng = SystemRandomNumberGenerator()
        let ikm = (0..<32).map { _ in UInt8.random(in: 0...255, using: &rng) }
        if !ikm.contains(where: { $0 != 0 }) { throw PairingError("bbs: entropy source returned all zeros (RNG failure); refusing to generate a key") }
        let sk = try keyGen(keyMaterial: ikm)
        return (sk, try skToPk(sk))
    }

    // ---- signature

    static func octetsToSignature(_ sig: [UInt8]) throws -> (G1, Fr) {
        guard sig.count == pointLen + scalarLen else { throw PairingError("bbs: signature must be 80 octets") }
        guard let a = decodeG1(Array(sig[0..<pointLen])) else { throw PairingError("bbs: non-canonical or invalid G1 encoding") }
        if a.isIdentity { throw PairingError("bbs: signature point A is the identity") }
        guard let e = Fr(canonical: Array(sig[pointLen...])), !e.isZero else { throw PairingError("bbs: signature scalar e out of range") }
        return (a, e)
    }

    static func calculateDomain(_ pk: [UInt8], _ q1: G1, _ h: [G1], _ header: [UInt8]) throws -> Fr {
        var s = Ser()
        s.int(h.count)
        s.g1(q1)
        for x in h { s.g1(x) }
        let input = pk + s.buf + Array(apiID.utf8) + i2osp(header.count, 8) + header
        return try hashToScalar(input, dst: h2sDST)
    }

    static func computeB(_ q1: G1, _ h: [G1], _ domain: Fr, _ msgs: [Fr]) -> G1 {
        let dq: G1 = domain * q1
        var b = p1 + dq
        for (i, m) in msgs.enumerated() { let t: G1 = m * h[i]; b = b + t }
        return b
    }

    /// The 80-octet BBS signature over the ordered message vector.
    public static func sign(sk: Fr, pk: [UInt8], header: [UInt8], messages: [[UInt8]]) throws -> [UInt8] {
        if sk.isZero { throw PairingError("bbs: secret key is zero") }
        let msgs = try scalars(messages)
        let gens = try createGens(msgs.count + 1)
        let q1 = gens[0], h = Array(gens.dropFirst())
        let domain = try calculateDomain(pk, q1, h, header)
        var es = Ser()
        es.scalar(sk)
        for m in msgs { es.scalar(m) }
        es.scalar(domain)
        let e = try hashToScalar(es.buf, dst: h2sDST)
        let b = computeB(q1, h, domain, msgs)
        let inv = try (sk + e).inverse()
        let a: G1 = inv * b
        return a.compressed + e.bytes
    }

    /// Verifies a signature over exactly these messages; fails closed on any malformed input.
    public static func verifyDetailed(pk: [UInt8], signature: [UInt8], header: [UInt8], messages: [[UInt8]]) -> Result {
        guard let (a, e) = try? octetsToSignature(signature) else { return .fail("malformed-signature") }
        guard let w = decodeG2(pk), !isInfEncoding(pk) else { return .fail("malformed-public-key") }
        if messages.count > maxMessages { return .fail("disclosed-length-mismatch") }
        guard let msgs = try? scalars(messages), let gens = try? createGens(msgs.count + 1),
              let domain = try? calculateDomain(pk, gens[0], Array(gens.dropFirst()), header) else { return .fail("disclosed-length-mismatch") }
        let b = computeB(gens[0], Array(gens.dropFirst()), domain, msgs)
        // e(A, W + BP2*e) == e(B, BP2)
        let eb: G2 = e * bp2
        return Bls12.pairingEq(a, w + eb, b, bp2) ? .pass : .fail("pairing-mismatch")
    }

    public static func verify(pk: [UInt8], signature: [UInt8], header: [UInt8], messages: [[UInt8]]) -> Bool {
        verifyDetailed(pk: pk, signature: signature, header: header, messages: messages).ok
    }

    // ---- proofs

    static func calculateChallenge(_ abar: G1, _ bbar: G1, _ d: G1, _ t1: G1, _ t2: G1, _ idx: [Int], _ msgs: [Fr], _ domain: Fr, _ ph: [UInt8]) throws -> Fr {
        var s = Ser()
        s.int(idx.count)
        for k in idx.indices { s.int(idx[k]); s.scalar(msgs[k]) }
        for p in [abar, bbar, d, t1, t2] { s.g1(p) }
        s.scalar(domain)
        return try hashToScalar(s.buf + i2osp(ph.count, 8) + ph, dst: h2sDST)
    }

    struct Proof {
        var abar = G1(), bbar = G1(), d = G1()
        var eHat = Fr(), r1Hat = Fr(), r3Hat = Fr()
        var mHat: [Fr] = []
        var c = Fr()
    }

    static func octetsToProof(_ proof: [UInt8]) throws -> Proof {
        let fixed = 3 * pointLen + 4 * scalarLen
        guard proof.count >= fixed, (proof.count - fixed) % scalarLen == 0 else { throw PairingError("bbs: malformed proof length") }
        var p = Proof()
        var pts: [G1] = []
        for i in 0..<3 {
            let b = Array(proof[i * pointLen..<(i + 1) * pointLen])
            guard let g = decodeG1(b) else { throw PairingError("bbs: non-canonical or invalid G1 encoding") }
            if g.isIdentity { throw PairingError("bbs: proof contains the identity point") }
            pts.append(g)
        }
        p.abar = pts[0]; p.bbar = pts[1]; p.d = pts[2]
        var o = 3 * pointLen
        func read() throws -> Fr {
            guard let v = Fr(canonical: Array(proof[o..<o + scalarLen])) else { throw PairingError("bbs: proof scalar out of range") }
            o += scalarLen
            return v
        }
        p.eHat = try read(); p.r1Hat = try read(); p.r3Hat = try read()
        for _ in 0..<((proof.count - fixed) / scalarLen) { p.mHat.append(try read()) }
        p.c = try read()
        return p
    }

    static func proofToOctets(_ p: Proof) -> [UInt8] {
        var out = p.abar.compressed + p.bbar.compressed + p.d.compressed
        for v in [p.eHat, p.r1Hat, p.r3Hat] + p.mHat + [p.c] { out += v.bytes }
        return out
    }

    static func validateIndexes(_ idx: [Int], _ l: Int) throws {
        var seen = Set<Int>()
        for i in idx {
            if i < 0 || i >= l { throw PairingError("bbs: disclosed index \(i) out of range [0, \(l))") }
            if !seen.insert(i).inserted { throw PairingError("bbs: duplicate disclosed index \(i)") }
        }
    }

    /// A zero-knowledge proof of knowledge of the signature, disclosing the messages at `disclosedIndexes`. `ph` binds the proof
    /// to a context. `fixedRandomScalars` (5 + undisclosed scalars) pins the randomness for test vectors ONLY: reusing it across
    /// proofs breaks zero-knowledge and unlinkability; pass nil in production.
    public static func proofGen(pk: [UInt8], signature: [UInt8], header: [UInt8], ph: [UInt8], messages: [[UInt8]], disclosedIndexes: [Int],
                                fixedRandomScalars: [Fr]? = nil) throws -> [UInt8] {
        let (a, e) = try octetsToSignature(signature)
        let msgs = try scalars(messages)
        let l = msgs.count
        try validateIndexes(disclosedIndexes, l)
        let disclosed = disclosedIndexes.sorted()
        let dset = Set(disclosed)
        let undisclosed = (0..<l).filter { !dset.contains($0) }
        let u = undisclosed.count
        let gens = try createGens(l + 1)
        let q1 = gens[0], h = Array(gens.dropFirst())
        let domain = try calculateDomain(pk, q1, h, header)
        let b = computeB(q1, h, domain, msgs)

        var rs: [Fr]
        if let f = fixedRandomScalars { rs = f } else {
            var rng = SystemRandomNumberGenerator()
            rs = (0..<(5 + u)).map { _ in Fr(reducing: (0..<expandLen).map { _ in UInt8.random(in: 0...255, using: &rng) }) }
        }
        guard rs.count == 5 + u else { throw PairingError("bbs: expected \(5 + u) random scalars, got \(rs.count)") }
        if rs[0].isZero || rs[1].isZero { throw PairingError("bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)") }
        let r1 = rs[0], r2 = rs[1], eTilde = rs[2], r1Tilde = rs[3], r3Tilde = rs[4]
        let mTilde = Array(rs[5...])

        let d: G1 = r2 * b
        let r12: Fr = r1 * r2
        let abar: G1 = r12 * a
        let bbarA: G1 = r1 * d, bbarB: G1 = e * abar
        let bbar = bbarA - bbarB
        let t1a: G1 = eTilde * abar, t1b: G1 = r1Tilde * d
        let t1 = t1a + t1b
        var t2: G1 = r3Tilde * d
        for (k, j) in undisclosed.enumerated() { let t: G1 = mTilde[k] * h[j]; t2 = t2 + t }
        let c = try calculateChallenge(abar, bbar, d, t1, t2, disclosed, disclosed.map { msgs[$0] }, domain, ph)
        let r3 = try r2.inverse()
        var p = Proof()
        p.abar = abar; p.bbar = bbar; p.d = d; p.c = c
        let ec: Fr = e * c, r1c: Fr = r1 * c, r3c: Fr = r3 * c
        p.eHat = eTilde + ec
        p.r1Hat = r1Tilde - r1c
        p.r3Hat = r3Tilde - r3c
        for (k, j) in undisclosed.enumerated() { let mc: Fr = msgs[j] * c; p.mHat.append(mTilde[k] + mc) }
        return proofToOctets(p)
    }

    /// Verifies a proof; `disclosedMessages[k]` corresponds to `disclosedIndexes[k]`.
    public static func proofVerifyDetailed(pk: [UInt8], proof: [UInt8], header: [UInt8], ph: [UInt8], disclosedMessages: [[UInt8]], disclosedIndexes: [Int]) -> Result {
        guard let p = try? octetsToProof(proof) else { return .fail("malformed-proof") }
        guard let w = decodeG2(pk), !isInfEncoding(pk) else { return .fail("malformed-public-key") }
        if disclosedMessages.count != disclosedIndexes.count { return .fail("disclosed-length-mismatch") }
        let u = p.mHat.count
        let l = disclosedIndexes.count + u
        if l > maxMessages { return .fail("malformed-proof") }
        if (try? validateIndexes(disclosedIndexes, l)) == nil { return .fail("invalid-disclosed-indexes") }
        guard let scal = try? scalars(disclosedMessages) else { return .fail("malformed-proof") }
        let disclosed = zip(disclosedIndexes, scal).sorted { $0.0 < $1.0 }
        let idxs = disclosed.map { $0.0 }, msgs = disclosed.map { $0.1 }
        let dset = Set(idxs)
        let undisclosed = (0..<l).filter { !dset.contains($0) }
        guard let gens = try? createGens(l + 1) else { return .fail("malformed-proof") }
        let q1 = gens[0], h = Array(gens.dropFirst())
        guard let domain = try? calculateDomain(pk, q1, h, header) else { return .fail("malformed-proof") }

        let t1a: G1 = p.c * p.bbar, t1b: G1 = p.eHat * p.abar, t1c: G1 = p.r1Hat * p.d
        let t1 = t1a + t1b + t1c
        let dq: G1 = domain * q1
        var bv = p1 + dq
        for (i, m) in zip(idxs, msgs) { let t: G1 = m * h[i]; bv = bv + t }
        let t2a: G1 = p.c * bv, t2b: G1 = p.r3Hat * p.d
        var t2 = t2a + t2b
        for (k, j) in undisclosed.enumerated() { let t: G1 = p.mHat[k] * h[j]; t2 = t2 + t }
        guard let cv = try? calculateChallenge(p.abar, p.bbar, p.d, t1, t2, idxs, msgs, domain, ph), cv == p.c else { return .fail("challenge-mismatch") }
        // e(Abar, W) == e(Bbar, BP2)
        return Bls12.pairingEq(p.abar, w, p.bbar, bp2) ? .pass : .fail("pairing-mismatch")
    }

    public static func proofVerify(pk: [UInt8], proof: [UInt8], header: [UInt8], ph: [UInt8], disclosedMessages: [[UInt8]], disclosedIndexes: [Int]) -> Bool {
        proofVerifyDetailed(pk: pk, proof: proof, header: header, ph: ph, disclosedMessages: disclosedMessages, disclosedIndexes: disclosedIndexes).ok
    }
}
