import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The producer-vector driver's own helpers: the key-order scanner (every scan loop ends on short and truncated text, which is never
/// JSON), the JavaScript array-index rule (indices are canonical decimals below 2^32 - 1), the test clock, and the argument handling
/// of sign_contract_reset, sign_threshold_share, sign_pq_binding and suite_sign against the reference's acceptance and refusal texts.
/// The class sorts before ProducerVectorsTests, so a scan that never ends fails a deadline here first.
final class ProducerVectorsK05Kill2Tests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    /// objectKeyOrders under a deadline (a scan that stops advancing never returns).
    private func orders(_ s: String, line: UInt = #line) -> [String: [String]] {
        S2Deadline.within(5, "objectKeyOrders(\(s))", line: line) { PCAProducerVectors.objectKeyOrders(s) } ?? ["<did not finish>": []]
    }

    private func vector(_ name: String, _ file: String = "producer-vectors.json") throws -> (args: JObject, keys: JSONValue) {
        let f = try ProducerVectorsTests.VectorFile(file)
        let c = try XCTUnwrap(f.cases.first { $0.get("name")?.asString == name }, name)
        let args = try XCTUnwrap(c.get("args")?.asObject, name)
        return (args, f.doc.get("keys") ?? .null)
    }

    func testA1EveryScanLoopAdvances() {
        XCTAssertEqual(orders(" {}"), ["": []], "leading whitespace")
        XCTAssertEqual(orders("{\"a\":1}"), ["": ["a"]], "a key string and a number")
        XCTAssertEqual(orders("{\"a\\\"b\":true}"), ["": ["a\"b"]], "an escaped quote inside a key")
    }

    func testA2WhitespaceAndArraysInsideObjects() {
        XCTAssertEqual(orders("{ }"), ["": []], "whitespace before the closing brace")
        XCTAssertEqual(orders("{\"a\" :1}"), ["": ["a"]], "whitespace before the colon")
        XCTAssertEqual(orders("{\"a\":[ ]}"), ["": ["a"]], "whitespace inside an empty array")
        XCTAssertEqual(orders("{\"a\":[1,2]}"), ["": ["a"]], "the element after a comma is read")
    }

    func testA3TruncatedTextIsNotJSON() {
        for s in ["{", "\"ab", "{\"a\"", "{\"a\":1", "[", "[1"] { XCTAssertEqual(orders(s), [:], s) }
        XCTAssertEqual(orders("1"), [:], "a bare number is well formed and holds no object")
    }

    /// ECMAScript own-key order: array indices are canonical decimal strings for 0 ... 2^32 - 2, first and ascending.
    func testJsKeyOrderArrayIndexRule() {
        XCTAssertEqual(PCAProducerVectors.jsKeyOrder(["a", "9", "0"]), ["0", "9", "a"])
        XCTAssertEqual(PCAProducerVectors.jsKeyOrder(["a", "+1", "-1", "1.0"]), ["a", "+1", "-1", "1.0"], "a sign or a point is no index")
        XCTAssertEqual(PCAProducerVectors.jsKeyOrder(["a", "1000000000"]), ["1000000000", "a"], "ten digits")
        XCTAssertEqual(PCAProducerVectors.jsKeyOrder(["a", "4294967295", "4294967294"]), ["4294967294", "a", "4294967295"], "2^32 - 2 is the last index")
    }

    /// Each reading takes the lock once and the next tick; a reading past the end stays in bounds.
    func testTickReadsUnderTheLock() {
        let t = PCAProducerVectors.Tick([5, 7])
        XCTAssertEqual([t.next(), t.next()], [5, 7])
        _ = t.next()
        XCTAssertEqual(t.lock.acquisitions, 3)
        XCTAssertEqual(t.lock.imbalance, 0)
    }

    /// The reference signs any seq: 0 and 2^31 - 1 sign exactly what the enforcer's own signer signs.
    func testContractResetSignsSeqZeroAndInt32Max() throws {
        let (a0, keys) = try vector("contract-reset")
        let seed = try XCTUnwrap(Base64URLStrict.decode(keys.get("principal")?.get("seed")?.asString ?? "", length: 32))
        let id = try XCTUnwrap(a0["contract_id"]?.asString)
        for seq: Int64 in [0, Int64(Int32.max)] {
            var a = a0
            a["seq"] = .int(seq)
            let got = try PCAProducerVectors.produce(op: "sign_contract_reset", args: .object(a), keys: keys)
            let want = try ContractEnforcer.signContractReset(principal: try Ed25519Deterministic.key(seed: seed), contractId: id, seq: Int(seq))
            XCTAssertEqual(got, .object(["sig": .string(want)]), "seq \(seq)")
        }
    }

    /// The reference's shareMessage refuses every t but 1, 2 and 3 (a missing t too), with its own text.
    func testThresholdShareRefusesOtherT() throws {
        let (a0, keys) = try vector("threshold-share-agent")
        for t: JSONValue? in [.int(0), .int(4), .int(-1), .int(1 << 40), .double(1.5), nil] {
            var a = a0
            a["t"] = t
            XCTAssertThrowsError(try PCAProducerVectors.produce(op: "sign_threshold_share", args: .object(a), keys: keys), "t \(String(describing: t))") {
                XCTAssertEqual("\($0)", "shareMessage: t must be 1, 2 or 3")
            }
        }
    }

    /// The reference refuses a missing or non-integer epoch.
    func testPqBindingWithoutAnIntegerEpochIsRefused() throws {
        let (a0, keys) = try vector("pq-binding")
        for e: JSONValue? in [nil, .double(1.5)] {
            var a = a0
            a["epoch"] = e
            XCTAssertThrowsError(try PCAProducerVectors.produce(op: "sign_pq_binding", args: .object(a), keys: keys), "epoch \(String(describing: e))") {
                XCTAssertEqual("\($0)", "signPqBinding: epoch must be a positive safe integer")
            }
        }
    }

    /// A hybrid suite signature carries its ML-DSA half as pq_sig, and both halves verify.
    func testHybridSuiteSignCarriesPqSig() throws {
        guard PCAPQKey.signingAvailable else { throw XCTSkip("no ML-DSA signing on this platform") }
        let f = try ProducerVectorsTests.VectorFile("producer-pq-vectors.json")
        let i = try XCTUnwrap(f.cases.firstIndex { $0.get("name")?.asString == "suite-sign-hybrid-ed25519-ml-dsa-65" })
        let got = try f.produce(i)
        let msg = Canonical.utf8(try XCTUnwrap(f.cases[i].get("args")?.get("message_utf8")?.asString))
        let holder = try XCTUnwrap(f.doc.get("ed_keys")?.get("agent")?.get("public")?.asString)
        let pqPk = try XCTUnwrap(f.doc.get("pq_keys")?.get("agent/ml-dsa-65")?.get("public")?.asString)
        let pqSig = try XCTUnwrap(got.get("pq_sig")?.asString, "a hybrid signature carries pq_sig")
        XCTAssertTrue(PQ.verifyLeaf(alg: "hybrid-ed25519-ml-dsa-65", holder: holder, pqPublicKey: pqPk, message: msg, sig: got.get("sig")?.asString, pqSig: pqSig))
    }
}

/// RFC 8032 deterministic signing: section 7.1 TEST 2, TEST 3 and TEST SHA(abc) (their encoded points with an odd x set bit 7 of the
/// last byte), scalar reduction at exactly L, the 32-byte little-endian scalar encoding, and the two scalar loops ending.
/// The class sorts before Ed25519DeterministicTests, so a loop that never ends fails a deadline here first.
final class Ed25519DeterministicK05Kill2Tests: XCTestCase {
    typealias D = Ed25519Deterministic
    override func setUp() { super.setUp(); continueAfterFailure = false }

    private func hex(_ s: String) -> [UInt8] {
        var out = [UInt8](); var i = s.startIndex
        while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
        return out
    }

    func testA1ScalarLoopsEnd() {
        let three: [UInt8]? = S2Deadline.within(10, "mul") { D.encode(D.mul(BigUInt(3), D.B)) }
        XCTAssertEqual(three, D.encode(Ed25519Torsion.add(Ed25519Torsion.add(D.B, D.B), D.B)), "3B")
        let r: BigUInt? = S2Deadline.within(10, "modL") { D.modL(BigUInt(1000)) }
        XCTAssertEqual(r, BigUInt(1000))
    }

    func testA2ModLReducesTheModulusItself() {
        XCTAssertEqual(D.modL(D.L), BigUInt(0))
        XCTAssertEqual(D.modL(D.L - BigUInt(1)), D.L - BigUInt(1))
        XCTAssertEqual(D.modL(D.L + D.L + BigUInt(5)), BigUInt(5))
    }

    func testA3Bytes32IsLittleEndian() {
        XCTAssertEqual(D.bytes32(BigUInt(0x0102)), [0x02, 0x01] + [UInt8](repeating: 0, count: 30))
        XCTAssertEqual(D.bytes32(BigUInt(1) << 255), [UInt8](repeating: 0, count: 31) + [0x80], "bit 255 is bit 7 of byte 31")
        XCTAssertEqual(D.bytes32(BigUInt(1) << 256).count, 32, "the encoding stays 32 bytes")
    }

    func testRfc8032Vectors() {
        let vectors: [(seed: String, msg: String, pk: String, sig: String)] = [
            ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
             "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
             "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
            ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
             "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
             "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
            ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
             "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
             "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
             "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
        ]
        for v in vectors {
            XCTAssertEqual(D.publicKey(seed: hex(v.seed)), hex(v.pk), v.pk)
            XCTAssertEqual(D.sign(seed: hex(v.seed), hex(v.msg)), hex(v.sig), v.sig)
        }
    }
}
