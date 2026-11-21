import XCTest
import Foundation
import CryptoKit
@testable import AtlasPCAVerify

/// ristretto255 known answers (RFC 9496 appendix A: the generator multiples, the bad encodings and the hash-to-group map), the
/// Pedersen generator H, an independent accumulator transcript, and prover roundtrips (the provers draw fresh randomness, so their
/// proofs are checked by the verifier).
final class RefRatchetKatTests: XCTestCase {
    typealias RG = RatchetGroup
    typealias A = PCARatchetAccumulator

    static let baseMultiples: [String] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
        "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
        "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
        "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
        "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
        "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
        "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
        "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
        "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
        "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
        "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
        "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
        "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
        "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
        "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
    ]

    static let badEncodings: [String] = [
        "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516c04b0b4d2",
        "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
        "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
        "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
        "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
        "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
        "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
        "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
        "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
        "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
        "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
        "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
        "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
        "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
        "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
        "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
        "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
        "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
        "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
        "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
        "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
        "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0200000000000000000000000000000000000000000000000000000000000000",
    ]

    static let fromHash: [(input: String, encoding: String)] = [
        ("5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c14d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6", "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46"),
        ("f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b270102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38", "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b"),
        ("8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c", "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826"),
        ("ac22415129b61427bf464e17baee8db65940c233b98afce8d17c57beeb7876c2150d15af1cb1fb824bbd14955f2b57d08d388aab431a391cfc33d5bafb5dbbaf", "f8f0c87cf237953c5890aec3998169005dae3eca1fbb04548c635953c817f92a"),
        ("165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec7675debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413", "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179"),
        ("a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c", "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628"),
        ("2cdc11eaeb95daf01189417cdddbf95952993aa9cb9c640eb5058d09702c74622c9965a697a3b345ec24ee56335b556e677b30e6f90ac77d781064f866a3c982", "80bd07262511cdde4863f8a7434cef696750681cb9510eea557088f76d9e5065"),
        ("1c43e2d5538fcb64d030fdfb29d37a55a95f615c0716388aa783da414b74f3080ce7c3487c362f11d74a2a0ecc52da0284baebc2378f59037b3553ce2820e9db", "d84a5dcfe85d78d1d7ed31bfb0bc79b4dc7eb71d8238daf48796196ca9d1ea35"),
        ("8bb2829219b5f81fdc4966b1e6d19d2d46176c9aae1b83d6fab0f7f63be9d606b12ac9c39ebfb425c6af2cdff78607064eb3caa1873d55194f23db8c6074e924", "109913cd085e526ddc30c3dcf462bb3626e3b8ef8e0b8f985c8798f081d6834e"),
        ("cec00b7ffdbe4e15897c8f9d97961d883f759b179cf3ac27b3337fb22ae15e88000b963ffabd51234cda8001a5abf651691ead5ef873151ad479a28924f01fca", "62b490af128bd2a2d585179f05d6f9c39f85f6d868b843041539bc481c7c2c23"),
        ("a37173ff2d467468f9468d0020a81ce23cf9f493fdb81968cb812b0cc8efe9d0485fab715f7a756a282717964880c0c3f745341439e872ab31e01b954dfc391f", "2e8a3bd1dc493573fc7fef7d37683a69806599a119f3571739ceceb98a053d78"),
        ("8daaea459253c99e1b7db48cb153e5d889f3ece5a6328500c686f1e8c5304f7129766ca10845a927c4f0ece8cfef8c003534b7fa6b4b3a3ad8443fe127748224", "68482ea59108d3362ccf6d2b339e7a219f650853058d9b7fef2e695a9f550e58"),
        ("739cbc87636db825ca515c33d6008526730fefbb636af5cacc44d7909ced607deba60dd64ef1bd49059b14abd09fbdff66352c71348c6325f84c8c219a5d326e", "726434605ac7df648debeef0fa05ae9378819a645b26b5ff3e1b012407cb461f"),
        ("7c3eb85c1e6cf8f6187f19ca694fc1de866821c026b3b086a7a381bf765f1a75ac4808ab6f19f68fb0cb08eb42218a8a16eb6a12caf4fc0012cbb07d7df042ec", "d4fc8d08c043012fec108e8e1ca9ee2eddb05f9037440e9774dd58bf24bea63d"),
        ("4e1069640bac2d80492d2b2c7149e3478be5ee670f68fe16f28bb57003937e4c3957f2272e0c433e745d906b5c633e1c5df2f2138c643b7eab50be32802a4716", "4a3940ac12ae3d0460cb46607a29a2f456bdbab875e06cf60ebd6ede10c36042"),
        ("f59386a6c7a58181493361db46834fe770e024cd97d9ab360c853c646cb81e32806abd086b5bc70effef2d8ea13e9dd2d21fa99b1c6343a9383fed1984421a4e", "044b85c0a9a013376f120eb6f71fba66bcd9cbf65367742c919e36100c22a222"),
        ("2b226c4e7016428c8bb1c24a9621dd9e9460b7765232917fa378deb4d570e404cdb1dc70ed76454fc320ef1c503a176d48cb2ed9f5e68f7ac81c4a5962c2566f", "8462eeaaf6b58d8fce2f27d059face1c5802ffd9705d09fb90dfef1853e8a177"),
        ("b52489b675359b55a547a74216f46cdafe5068d1046ba2e0e83568d9f4e49c945a24d0dbf1e34e6e41d50a79a1e9d4988db7b60dfeef0f0517e3e0ff631bfadd", "fe9cfbba4b7390fa313ce528a84d2ed3f0132854fd5f57f3df7a403c95487d27"),
        ("0ec5ffe8209ce90d1e502818f9362c4a9291e1cd096d35dabcf3ec06caae461fe71cfabc58de264a111ca5148b73b8e3cd7ba2c8a06267b8f5b22e54ebf6a48f", "6c60c705f2d54b6927ce92e204c12e43218819a85c22b8e362185d138dd6b81d"),
        ("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a64d86820abd393c6a5feef95b64945bc0c570adebae17a99882216945fbd37a"),
    ]

    static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    static func unhex(_ s: String) -> [UInt8] {
        let c = Array(s.utf8)
        func v(_ x: UInt8) -> UInt8 { x <= 57 ? x - 48 : x - 87 }
        return stride(from: 0, to: c.count, by: 2).map { v(c[$0]) << 4 | v(c[$0 + 1]) }
    }

    func testGeneratorMultiplesMatchRfc9496() throws {
        try K042.requireCovers(["RatchetGroup"])
        XCTAssertEqual(Self.baseMultiples.count, 16)
        for (i, enc) in Self.baseMultiples.enumerated() {
            XCTAssertEqual(Self.hex(try RG.mul(RG.G, small: UInt64(i))), enc, "multiple \(i)")
        }
        var acc = RG.zero
        for enc in Self.baseMultiples {
            XCTAssertEqual(Self.hex(acc), enc)
            XCTAssertEqual(try RG.decode(Self.unhex(enc)), acc)
            acc = try RG.add(acc, RG.G)
        }
    }

    func testBadEncodingsAreRejected() throws {
        try K042.requireCovers(["RatchetGroup"])
        XCTAssertEqual(Self.badEncodings.count, 30)
        for enc in Self.badEncodings { XCTAssertFalse(RG.isValid(Self.unhex(enc)), enc) }
        XCTAssertFalse(RG.isValid([UInt8](repeating: 0, count: 31)))
        XCTAssertFalse(RG.isValid([UInt8](repeating: 0, count: 33)))
        for enc in Self.baseMultiples { XCTAssertTrue(RG.isValid(Self.unhex(enc)), enc) }
    }

    func testHashToGroupMatchesRfc9496() throws {
        try K042.requireCovers(["RatchetGroup"])
        for v in Self.fromHash { XCTAssertEqual(Self.hex(try RG.hashToCurve(Self.unhex(v.input))), v.encoding) }
        XCTAssertThrowsError(try RG.hashToCurve([UInt8](repeating: 0, count: 63)))
    }

    func testGeneratorHAndPedersenCommitmentsMatchTheIndependentEncoding() throws {
        try K042.requireCovers(["RatchetGroup", "RatchetAccumulator"])
        let k = try K042.json("ref-ratchet-kat.json.gz").get("ristretto")
        XCTAssertEqual(Self.hex(RG.H), k?.get("H")?.asString)
        for (i, enc) in (k?.get("baseMultiples")?.asArray ?? []).enumerated() {
            XCTAssertEqual(Self.hex(try RG.mul(RG.G, small: UInt64(i))), enc.asString)
        }
        for p in k?.get("pedersen")?.asArray ?? [] {
            let blinding = PCABigInt(neg: false, mag: BigUInt(bytesLE: Self.unhex(p.get("b")?.asString ?? "")))
            let c = try A.commitRisk(try XCTUnwrap(PCABigInt(p.get("v")?.asString ?? "")), blinding: blinding)
            XCTAssertEqual(Self.hex(try XCTUnwrap(Base64URLStrict.decode(c.commitment, length: 32))), p.get("C")?.asString)
        }
    }

    func testBudgetVerdictsMatchTheIndependentVerifier() throws {
        try K042.requireCovers(["RatchetGroup", "RatchetAccumulator"])
        let k = try K042.json("ref-ratchet-kat.json.gz").get("ristretto")
        let budgets = k?.get("budget")?.asArray ?? []
        XCTAssertFalse(budgets.isEmpty)
        for b in budgets {
            let got = A.verifyBudget(b.get("sum"), bMax: try XCTUnwrap(PCABigInt(b.get("bMax")?.asString ?? "")), proof: b.get("proof"))
            XCTAssertEqual(got, b.get("oracle")?.asString == "1", b.get("name")?.asString ?? "")
        }
    }

    func testRecordedTranscriptVerifiesAndIsBoundToItsStatement() throws {
        try K042.requireCovers(["RatchetGroup", "RatchetAccumulator"])
        let k = try XCTUnwrap(try K042.json("ref-ratchet-kat.json.gz").get("r2"))
        let cs = try XCTUnwrap(k.get("commitments")?.asArray), rps = try XCTUnwrap(k.get("rangeProofs")?.asArray)
        let bMax = try PCABigInt.units(k.get("bMax")), total = k.get("sum"), bp = k.get("budgetProof")
        XCTAssertTrue(A.verifyRiskRange(cs[0], proof: rps[0]) && A.verifyRiskRange(cs[1], proof: rps[1]))
        XCTAssertTrue(A.verifyBudget(total, bMax: bMax, proof: bp))
        XCTAssertTrue(A.verifyBoundedBudget(.array(cs), rangeProofs: .array(rps), bMax: bMax, budgetProof: bp))
        XCTAssertFalse(A.verifyRiskRange(cs[1], proof: rps[0]))
        XCTAssertFalse(A.verifyBudget(total, bMax: PCABigInt(neg: false, mag: bMax.mag + BigUInt(1)), proof: bp))
        XCTAssertFalse(A.verifyBoundedBudget(.array(cs), rangeProofs: .array(rps + [rps[0]]), bMax: bMax, budgetProof: bp))
    }

    // MARK: provers (random coins): roundtrips

    func testBudgetProverRoundtrip() throws {
        try K042.requireCovers(["RatchetGroup", "RatchetAccumulator"])
        let risks = [PCABigInt(30), PCABigInt(12)], blindings = [PCABigInt(11), PCABigInt(22)]
        let total = try A.addCommitments(try zip(risks, blindings).map { try A.commitRisk($0, blinding: $1).commitment })
        XCTAssertTrue(A.verifyBudget(.string(total), bMax: PCABigInt(42), proof: try A.proveBudget(risks: risks, blindings: blindings, bMax: PCABigInt(42))))
        XCTAssertFalse(A.verifyBudget(.string(total), bMax: PCABigInt(41), proof: try A.proveBudget(risks: risks, blindings: blindings, bMax: PCABigInt(41))))
        // a ceiling above the range is clamped
        let big = try A.proveBudget(risks: risks, blindings: blindings, bMax: PCABigInt(Int64(1) << 40))
        XCTAssertTrue(A.verifyBudget(.string(total), bMax: PCABigInt(Int64(1) << 40), proof: big))
    }

    func testRiskRangeProverRoundtrip() throws {
        try K042.requireCovers(["RatchetGroup", "RatchetAccumulator"])
        for risk: Int64 in [0, 1, 7, 4_294_967_295] {
            let c = try A.commitRisk(PCABigInt(risk), blinding: PCABigInt(5))
            let proof = try A.proveRiskRange(PCABigInt(risk), blinding: PCABigInt(5))
            XCTAssertTrue(A.verifyRiskRange(.string(c.commitment), proof: proof), "\(risk)")
            XCTAssertTrue(A.openCommitment(.string(c.commitment), risk: PCABigInt(risk), blinding: PCABigInt(5)))
            XCTAssertFalse(A.openCommitment(.string(c.commitment), risk: PCABigInt(risk + 1), blinding: PCABigInt(5)))
        }
        // a value past the range has no valid proof
        let over = try A.commitRisk(PCABigInt(Int64(1) << 32), blinding: PCABigInt(5))
        XCTAssertFalse(A.verifyRiskRange(.string(over.commitment), proof: try A.proveRiskRange(PCABigInt(Int64(1) << 32), blinding: PCABigInt(5))))
    }

    func testAttestedBudgetRoundtrip() throws {
        try K042.requireCovers(["Ratchet"])
        let seed = RefKeys.seed("ratchet-kat-authority")
        let pub = Base64URLStrict.encode(Array(try Curve25519.Signing.PrivateKey(rawRepresentation: Data(seed)).publicKey.rawRepresentation))
        let iss = try PCARatchet.issueRiskCommitment(risk: PCABigInt(9), actionDigest: "only", authoritySecretKey: seed)
        let items: JSONValue = .array([.object(["commitment": .string(iss.commitment), "rangeProof": iss.rangeProof, "attestation": iss.attestation])])
        let proof = try A.proveBudget(risks: [PCABigInt(9)], blindings: [iss.blinding], bMax: PCABigInt(9))
        XCTAssertTrue(PCARatchet.verifyAttestedBudget(items: items, expectedActionDigests: .array([.string("only")]), authorityPublicKey: .string(pub),
                                                      bMax: PCABigInt(9), budgetProof: proof))
        XCTAssertFalse(PCARatchet.verifyAttestedBudget(items: items, expectedActionDigests: .array([.string("other")]), authorityPublicKey: .string(pub),
                                                       bMax: PCABigInt(9), budgetProof: proof))
        XCTAssertFalse(PCARatchet.verifyAttestedBudget(items: items, expectedActionDigests: .array([.string("only")]), authorityPublicKey: .string(pub),
                                                       bMax: PCABigInt(8), budgetProof: proof))
        XCTAssertThrowsError(try PCARatchet.issueRiskCommitment(risk: PCABigInt(9), actionDigest: "x", authoritySecretKey: [UInt8](repeating: 0, count: 3)))
    }

    func testRatchetRoundtripAndPuncturing() throws {
        try K042.requireCovers(["Ratchet"])
        let (root, st) = try PCARatchet.deriveRatchetRoot(seed: [UInt8](repeating: 7, count: 32), depth: .int(3))
        XCTAssertEqual(PCARatchet.availableLeaves(st), Array(0..<8))
        let msg: [UInt8] = Array("hello".utf8)
        let (sig, next) = try PCARatchet.signAtLeaf(st, leafIndex: .int(5), message: msg)
        XCTAssertTrue(PCARatchet.verifyLeafSignature(rootCommitment: .string(root), leafIndex: .int(5), message: msg, signature: sig))
        XCTAssertFalse(PCARatchet.verifyLeafSignature(rootCommitment: .string(root), leafIndex: .int(4), message: msg, signature: sig))
        XCTAssertEqual(PCARatchet.availableLeaves(next), [0, 1, 2, 3, 4, 6, 7])
        XCTAssertThrowsError(try PCARatchet.signAtLeaf(next, leafIndex: .int(5), message: msg)) {
            XCTAssertEqual(($0 as? PCARatchetError)?.code, "leaf_punctured")
        }
        let store = PCAMemorySpentLeafStore()
        XCTAssertEqual(PCARatchet.verifyLeafSignatureOnce(rootCommitment: .string(root), leafIndex: .int(5), message: msg, signature: sig, store: store).get("ok"), .bool(true))
        XCTAssertEqual(PCARatchet.verifyLeafSignatureOnce(rootCommitment: .string(root), leafIndex: .int(5), message: msg, signature: sig, store: store).get("reason"), .string("replay"))
    }
}
