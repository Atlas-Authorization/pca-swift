import XCTest
@testable import AtlasPCAVerify
@testable import AtlasPCAPairing

/// Replays the reference corpus (BBS signatures over BLS12-381 and the capability-credential layer). Secret keys are never
/// stored in it: `{"$bbssk": n}` is the key Bbs.keyGen(fill(n) x 32) derives, as an argument and as a keyGen result.
final class BbsTests: XCTestCase {
    static func fillBytes(_ v: JSONValue?) -> [UInt8]? {
        guard let a = v?.get("$fill")?.asArray, a.count == 2, case let .int(b)? = a.first, case let .int(n)? = a.last, b >= 0, b < 256, n >= 0 else { return nil }
        return [UInt8](repeating: UInt8(b), count: Int(n))
    }

    static func bytes(_ v: JSONValue?) -> [UInt8]? { Ref.bytes(v) ?? fillBytes(v) }

    static func list(_ v: JSONValue?) -> [[UInt8]]? {
        guard let a = v?.asArray else { return nil }
        var out: [[UInt8]] = []
        for x in a { guard let b = Ref.bytes(x) else { return nil }; out.append(b) }
        return out
    }

    static func ints(_ v: JSONValue?) -> [Int]? {
        guard let a = v?.asArray else { return nil }
        var out: [Int] = []
        for x in a { guard case let .int(i) = x else { return nil }; out.append(Int(i)) }
        return out
    }

    /// A secret scalar argument: a derived test key or a lowercase-hex scalar.
    static func scalar(_ v: JSONValue?) -> Fr? {
        if case let .int(i)? = v?.get("$bbssk") { return try? Bbs.keyGen(keyMaterial: [UInt8](repeating: UInt8(i), count: 32)) }
        guard let h = v?.asString, let b = Ref.unhex(h) else { return nil }
        return Fr(reducing: b)
    }

    static func result(_ r: Bbs.Result) -> JSONValue {
        r.ok ? .object(["ok": .bool(true)]) : .object(["ok": .bool(false), "reason": .string(r.reason ?? "")])
    }

    static func run(_ c: RefCase) -> JSONValue? {
        let a = c.args
        func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
        func bv(_ b: [UInt8]?) -> JSONValue? { b.map { Ref.bytesValue($0) } }
        switch c.fn {
        case "hashToScalar":
            guard let m = bytes(arg(0)), let dst = arg(1)?.asString else { return nil }
            return (try? Bbs.hashToScalar(m, dst: Array(dst.utf8))).map { .string(Ref.hex($0.bytes)) }
        case "mapMessageToScalarAsHash":
            return bytes(arg(0)).flatMap { try? Bbs.mapMessageToScalarAsHash($0) }.map { .string(Ref.hex($0.bytes)) }
        case "createGenerators":
            guard case let .int(n)? = arg(0), let g = try? Bbs.createGenerators(Int(n)) else { return nil }
            return .array(g.map { Ref.bytesValue($0) })
        case "keyGen":
            guard let km = bytes(arg(0)), let info = bytes(arg(1)), let sk = try? Bbs.keyGen(keyMaterial: km, keyInfo: info) else { return nil }
            // a key equal to a labelled one is written as its label in the corpus
            if case let .int(n)? = c.out.get("$bbssk"), let lk = try? Bbs.keyGen(keyMaterial: [UInt8](repeating: UInt8(n), count: 32)), lk.bytes == sk.bytes { return c.out }
            return .string(Ref.hex(sk.bytes))
        case "skToPk": return scalar(arg(0)).flatMap { try? Bbs.skToPk($0) }.flatMap(bv)
        case "sign":
            guard let sk = scalar(arg(0)), let pk = bytes(arg(1)), let h = bytes(arg(2)), let ms = list(arg(3)) else { return nil }
            return bv(try? Bbs.sign(sk: sk, pk: pk, header: h, messages: ms))
        case "verifyDetailed":
            guard let pk = bytes(arg(0)), let sig = bytes(arg(1)), let h = bytes(arg(2)), let ms = list(arg(3)) else { return nil }
            return result(Bbs.verifyDetailed(pk: pk, signature: sig, header: h, messages: ms))
        case "proofGen":
            guard let pk = bytes(arg(0)), let sig = bytes(arg(1)), let h = bytes(arg(2)), let ph = bytes(arg(3)), let ms = list(arg(4)),
                  let idx = ints(arg(5)), let rsHex = arg(6)?.asArray else { return nil }
            var rs: [Fr] = []
            for x in rsHex { guard let s = x.asString, let b = Ref.unhex(s) else { return nil }; rs.append(Fr(reducing: b)) }
            return bv(try? Bbs.proofGen(pk: pk, signature: sig, header: h, ph: ph, messages: ms, disclosedIndexes: idx, fixedRandomScalars: rs))
        case "proofVerifyDetailed":
            guard let pk = bytes(arg(0)), let pr = bytes(arg(1)), let h = bytes(arg(2)), let ph = bytes(arg(3)), let ms = list(arg(4)), let idxList = arg(5)?.asArray else { return nil }
            // a JS array element that is not an integer (an undefined index serialises as null) still counts toward the length; it is never a valid index
            let idx = idxList.map { x -> Int in if case let .int(i) = x { return Int(i) }; return Int.min }
            return result(Bbs.proofVerifyDetailed(pk: pk, proof: pr, header: h, ph: ph, disclosedMessages: ms, disclosedIndexes: idx))
        case "capabilityAttributes": return arg(0).flatMap { try? BbsCredential.capabilityAttributes($0) }
        case "issueCapabilityCredential":
            guard let cap = arg(0), let sk = scalar(arg(1)), let pk = bytes(arg(2)), let h = bytes(arg(3)) else { return nil }
            return try? BbsCredential.issueCapabilityCredential(cap, sk: sk, pk: pk, header: h)
        case "verifyCredential": return arg(0).map { .bool(BbsCredential.verifyCredential($0)) }
        case "verifyPresentation":
            guard let pres = arg(0), let o = arg(1), o.asObject != nil else { return nil }
            var opts = BbsCredential.PresentOptions()
            if let pk = o.get("pk") { guard let b = Ref.bytes(pk) else { return nil }; opts.publicKey = b }
            if let ph = o.get("presentationHeader") { guard let b = Ref.bytes(ph) else { return nil }; opts.presentationHeader = b }
            if let d = o.get("disclosed") { guard let l = d.asArray else { return nil }; opts.disclosed = l }
            return .bool(BbsCredential.verifyPresentation(pres, opts))
        default: return nil
        }
    }

    func testReplayCorpus() throws {
        let known: Set<String> = ["hashToScalar", "mapMessageToScalarAsHash", "createGenerators", "keyGen", "skToPk", "sign", "verifyDetailed", "proofGen",
                                  "proofVerifyDetailed", "capabilityAttributes", "issueCapabilityCredential", "verifyCredential", "verifyPresentation"]
        let d = Ref.Diffs()
        let n = try Ref.each("ref-bbs.json.gz") { c in
            if !known.contains(c.fn) { d.skip("unknown fn \(c.fn)"); return }
            d.add(Ref.diff(c, BbsTests.run(c)))
        }
        // the one case carrying a lone surrogate cannot be held by a Swift String
        XCTAssertLessThanOrEqual(Ref.lastUnparsed, 1)
        XCTAssertEqual(n + Ref.lastUnparsed, 278)
        d.finish(277)
    }

    func testProofRoundTripAndTamper() throws {
        let sk = try Bbs.keyGen(keyMaterial: [UInt8](repeating: 9, count: 32))
        let pk = try Bbs.skToPk(sk)
        let msgs: [[UInt8]] = [Array("a".utf8), Array("b".utf8), Array("c".utf8)]
        let sig = try Bbs.sign(sk: sk, pk: pk, header: [1], messages: msgs)
        XCTAssertTrue(Bbs.verify(pk: pk, signature: sig, header: [1], messages: msgs))
        XCTAssertFalse(Bbs.verify(pk: pk, signature: sig, header: [2], messages: msgs))
        let proof = try Bbs.proofGen(pk: pk, signature: sig, header: [1], ph: [7], messages: msgs, disclosedIndexes: [1])
        XCTAssertTrue(Bbs.proofVerify(pk: pk, proof: proof, header: [1], ph: [7], disclosedMessages: [msgs[1]], disclosedIndexes: [1]))
        XCTAssertFalse(Bbs.proofVerify(pk: pk, proof: proof, header: [1], ph: [8], disclosedMessages: [msgs[1]], disclosedIndexes: [1]))
        XCTAssertFalse(Bbs.proofVerify(pk: pk, proof: proof, header: [1], ph: [7], disclosedMessages: [msgs[0]], disclosedIndexes: [1]))
    }
}

final class BbsSurfaceTests: XCTestCase {
    func testKeyBytesRoundTripAndRefusals() throws {
        XCTAssertEqual(Bbs.CIPHERSUITE_ID, "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_")
        let sk = try Bbs.keyGen(keyMaterial: [UInt8](repeating: 9, count: 32))
        XCTAssertEqual(try Bbs.skFromBytes(Bbs.skToBytes(sk)).bytes, sk.bytes)
        XCTAssertThrowsError(try Bbs.skFromBytes([UInt8](repeating: 1, count: 31)))
        XCTAssertThrowsError(try Bbs.skFromBytes([UInt8](repeating: 0, count: 32)))
        XCTAssertThrowsError(try Bbs.skFromBytes([UInt8](repeating: 0xff, count: 32)))
    }

    func testPresentCredentialIsVerifiableAndBoundToItsHeader() throws {
        let sk = try Bbs.keyGen(keyMaterial: [UInt8](repeating: 3, count: 32))
        let pk = try Bbs.skToPk(sk)
        let cap: JSONValue = .object(["issuer": .string("iss"), "holder": .string("hld"), "caveats": .array([.object(["type": .string("expires"), "at": .int(5)])])])
        let cred = try BbsCredential.issueCapabilityCredential(cap, sk: sk, pk: pk, header: [1, 2])
        XCTAssertTrue(BbsCredential.verifyCredential(cred))
        let pres = try BbsCredential.presentCredential(cred, disclose: ["iss"], presentationHeader: [9])
        XCTAssertTrue(BbsCredential.verifyPresentation(pres))
        XCTAssertTrue(BbsCredential.verifyPresentation(pres, BbsCredential.PresentOptions(publicKey: pk, presentationHeader: [9])))
        XCTAssertFalse(BbsCredential.verifyPresentation(pres, BbsCredential.PresentOptions(presentationHeader: [8])))
        XCTAssertEqual(pres.get("disclosed")?.asArray?.count, 1)
        XCTAssertEqual(pres.get("messageCount"), .int(3))
        XCTAssertThrowsError(try BbsCredential.presentCredential(cred, disclose: ["iss", "nope"]))
        XCTAssertThrowsError(try BbsCredential.presentCredential(.null, disclose: []))
    }
}
