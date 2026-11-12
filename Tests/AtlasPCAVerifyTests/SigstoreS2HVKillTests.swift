import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

/// Heavy-fixture kill tests for Sigstore.swift (heavy-brief items 1, 2, 3 and 7): the precertificate size boundary, a forged and
/// correctly signed bundle whose SCT extension cannot be read, extra base64 inputs, and non-crashing distinguishers.
final class S2HVSigstoreKillTests: XCTestCase {
    private static func e(_ tag: UInt8, _ c: [UInt8]) -> [UInt8] { Sigstore.enc(tag, c) }
    private func failMessage(_ body: () throws -> Void) -> String? {
        do { try body(); return nil } catch let e as Sigstore.Fail { return e.m } catch { return "other: \(error)" }
    }

    // ---------------------------------------------------------------- item 1: line 314

    private static let sctOid: [UInt8] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]
    private static let padOid: [UInt8] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x09]

    private static func ext(_ oid: [UInt8], _ value: [UInt8]) -> [UInt8] { e(0x30, e(0x06, oid) + e(0x04, value)) }

    private static func leaf(padding pad: Int) throws -> Sigstore.Parsed {
        let sct = ext(sctOid, e(0x04, [0, 0]))
        let kept = ext(padOid, [UInt8](repeating: 0, count: pad))
        var exts: [UInt8] = sct
        exts += kept
        let tbs = e(0x30, e(0xa3, e(0x30, exts)))
        return try Sigstore.parseCert(e(0x30, tbs))
    }

    /// The length of the precertificate TBS verifySct rebuilds when the only other extension holds `pad` bytes.
    private static func tbsCount(_ pad: Int) -> Int {
        func h(_ n: Int) -> Int { Cert.lengthHeader(0x30, n).count }
        let inner = (2 + padOid.count) + (h(pad) + pad)
        let c = h(inner) + inner
        let b = h(c) + c
        let a = h(b) + b
        return h(a) + a
    }

    private static func padding(forTbs target: Int) -> Int {
        var pad = target - 64
        while tbsCount(pad) < target { pad += 1 }
        return pad
    }

    private func issuer() -> AttCert {
        var c = AttCert()
        c.rawSPKI = [1, 2, 3]
        return c
    }

    private func roots() -> SigstoreRoots {
        let k = try! Cert.keyOfSPKI(Array(P256.Signing.PrivateKey().publicKey.derRepresentation))
        let log = SigstoreRoots.Log(keyId: [UInt8](repeating: 1, count: 32), key: k, start: 0, end: Int64.max, v2Name: nil)
        return SigstoreRoots(tlogs: [], ctlogs: [log], cas: [], tsas: [])
    }

    private func sct(forTbs target: Int) throws -> String? {
        let pad = Self.padding(forTbs: target)
        XCTAssertEqual(Self.tbsCount(pad), target)
        return try Sigstore.verifySct(try Self.leaf(padding: pad), issuer(), roots())
    }

    func testPrecertificateSizeBoundaryAtTwoToTheTwentyFour() throws {
        let limit = 1 << 24
        XCTAssertEqual(try sct(forTbs: limit), "precertificate too large", "line 314: 2^24 bytes is too large")
        XCTAssertEqual(try sct(forTbs: limit - 1), "no SCT from a pinned CT log", "line 314: 2^24 - 1 bytes is read")
    }

    func testPrecertificateSizeBoundaryAtTwoToTheTwentyThree() throws {
        XCTAssertEqual(try sct(forTbs: 1 << 23), "no SCT from a pinned CT log", "line 314 24->23: 2^23 bytes is read")
    }

    // ---------------------------------------------------------------- item 2: line 573

    private static let ecdsaSha256: [UInt8] = e(0x30, e(0x06, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]))

    private static func name(_ cn: String) -> [UInt8] {
        e(0x30, e(0x31, e(0x30, e(0x06, [0x55, 0x04, 0x03]) + e(0x0c, Array(cn.utf8)))))
    }

    /// A v3 X.509 certificate (P-256, ecdsa-with-SHA256, valid 2025-2035) signed by `signer`.
    private static func cert(serial: UInt8, subject: String, issuer: String, key: P256.Signing.PublicKey, exts: [[UInt8]], signer: P256.Signing.PrivateKey) -> [UInt8] {
        let validity = e(0x30, e(0x17, Array("250101000000Z".utf8)) + e(0x17, Array("350101000000Z".utf8)))
        var t: [UInt8] = e(0xa0, e(0x02, [2]))
        t += e(0x02, [serial])
        t += ecdsaSha256
        t += name(issuer)
        t += validity
        t += name(subject)
        t += Array(key.derRepresentation)
        var all: [UInt8] = []
        for x in exts { all += x }
        t += e(0xa3, e(0x30, all))
        let tbs = e(0x30, t)
        let sig = [UInt8](try! signer.signature(for: Data(tbs)).derRepresentation)
        var out: [UInt8] = tbs
        out += ecdsaSha256
        out += e(0x03, [0x00] + sig)
        return e(0x30, out)
    }

    func testAnUnreadableSctExtensionIsReportedAtTheSctStage() throws {
        let caKey = P256.Signing.PrivateKey(), leafKey = P256.Signing.PrivateKey(), logKey = P256.Signing.PrivateKey()
        let basicConstraintsCa = Self.ext([0x55, 0x1d, 0x13], Self.e(0x30, Self.e(0x01, [0xff])))
        let rootDer = Self.cert(serial: 1, subject: "ca", issuer: "ca", key: caKey.publicKey, exts: [basicConstraintsCa], signer: caKey)
        let eku = Self.ext([0x55, 0x1d, 0x25], Self.e(0x30, Self.e(0x06, [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03])))
        let emptySct = Self.ext(Self.sctOid, [])   // an OCTET STRING with no content: tlv(e.value, 0) throws
        let leafDer = Self.cert(serial: 2, subject: "leaf", issuer: "ca", key: leafKey.publicKey, exts: [eku, emptySct], signer: caKey)

        let logId = [UInt8](repeating: 0x42, count: 32)
        let body = Data("rekor-entry".utf8)
        let bodyB64 = body.base64EncodedString()
        let integrated: Int64 = 1_767_225_600
        let setMessage = "{\"body\":\"\(bodyB64)\",\"integratedTime\":\(integrated),\"logID\":\"\(ACrypto.hex(logId))\",\"logIndex\":0}"
        let setSig = Data(try logKey.signature(for: Data(setMessage.utf8)).derRepresentation)
        let root64 = Data(PCA.rfc9162LeafHash([UInt8](body))).base64EncodedString()
        let head = "origin\n1\n\(root64)"
        let cpSig = [UInt8](try logKey.signature(for: Data((head + "\n").utf8)).derRepresentation)
        let cpLine = "\u{2014} log " + Data(Array(logId.prefix(4)) + cpSig).base64EncodedString()
        let envelope = head + "\n\n" + cpLine + "\n"

        let entry: JSONValue = .object([
            "logIndex": .string("0"), "logId": .object(["keyId": .string(Data(logId).base64EncodedString())]),
            "kindVersion": .object(["kind": .string("dsse"), "version": .string("0.0.1")]), "integratedTime": .string(String(integrated)),
            "inclusionPromise": .object(["signedEntryTimestamp": .string(setSig.base64EncodedString())]),
            "inclusionProof": .object(["logIndex": .string("0"), "rootHash": .string(root64), "treeSize": .string("1"), "hashes": .array([]),
                                       "checkpoint": .object(["envelope": .string(envelope)])]),
            "canonicalizedBody": .string(bodyB64),
        ])
        let bundle: JSONValue = .object([
            "mediaType": .string("application/vnd.dev.sigstore.bundle.v0.3+json"),
            "verificationMaterial": .object(["certificate": .object(["rawBytes": .string(Data(leafDer).base64EncodedString())]), "tlogEntries": .array([entry])]),
            "dsseEnvelope": .object(["payload": .string(Data("{}".utf8).base64EncodedString()), "payloadType": .string("application/vnd.in-toto+json"),
                                     "signatures": .array([.object(["sig": .string(Data([1, 2, 3, 4, 5, 6, 7, 8]).base64EncodedString())])])]),
        ])

        let logKeyParsed = try Cert.keyOfSPKI(Array(logKey.publicKey.derRepresentation))
        let log = SigstoreRoots.Log(keyId: logId, key: logKeyParsed, start: 0, end: Int64.max, v2Name: nil)
        let ctLog = SigstoreRoots.Log(keyId: [UInt8](repeating: 7, count: 32), key: logKeyParsed, start: 0, end: Int64.max, v2Name: nil)
        let ca = SigstoreRoots.CA(chain: [try Cert.parseDER(rootDer)], start: 0, end: Int64.max)
        let withCt = SigstoreRoots(tlogs: [log], ctlogs: [ctLog], cas: [ca], tsas: [])

        let r = PCA.verifySigstoreBundleCore(bundle, roots: withCt)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.code, "sct", "line 573: the stage is \"sct\" when verifySct throws; \(r.detail)")
        XCTAssertTrue(r.detail.hasPrefix("fail closed: "), r.detail)

        // control: with no CT log pinned the same bundle passes the certificate path and goes on to the entry body
        let noCt = SigstoreRoots(tlogs: [log], ctlogs: [], cas: [ca], tsas: [])
        let c = PCA.verifySigstoreBundleCore(bundle, roots: noCt)
        XCTAssertNotEqual(c.code, "cert_chain", c.detail)
        XCTAssertNotEqual(c.code, "sct", c.detail)
    }

    // ---------------------------------------------------------------- item 3: b64s (lines 55, 57)

    func testB64sInputsFoundationMightAccept() {
        // every one of these must be refused by the alphabet / length / padding guard whatever Data(base64Encoded:) would do
        let bad = ["QQ", "QUI", "QUJDQQ", "QQ==\n", "QUJD\n", " QUJD", "QUJD ", "QUJD\r\n", "QU JD", "QU\nJD", "QUJ-", "QUJ_", "QQ=a", "Q===", "====",
                   "QUJDQQ==QUJD", "QQ===", "QUI==", "AAAAA===", "AA=A"]
        for s in bad { XCTAssertEqual(failMessage { _ = try Sigstore.b64s(s) }, "not base64", s.debugDescription) }
        XCTAssertEqual(try Sigstore.b64s("QUJD"), [0x41, 0x42, 0x43])
        XCTAssertEqual(try Sigstore.b64s("QUI="), [0x41, 0x42])
        XCTAssertEqual(try Sigstore.b64s("QQ=="), [0x41])
    }

    // ---------------------------------------------------------------- item 7: non-crashing distinguishers

    func testTlvLengthOctetsBeyondTheLimit() {
        // limit 3 inside a longer buffer: the mutant `body - n > limit` reads the octets past the limit and fails later with another message
        let b: [UInt8] = [0x30, 0x82, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00]
        XCTAssertEqual(failMessage { _ = try Sigstore.tlv(b, 0, 3) }, "DER length", "line 155")
    }

    func testRfc3161ContentInfoWithOneNonOidElement() {
        let e = Self.e
        // line 389 (count >= 1): oidText of a non-OID first element throws "not an OID" instead of "not CMS SignedData"
        let one = e(0x30, e(0x05, []))
        XCTAssertEqual(failMessage { _ = try Sigstore.verifyRfc3161(one, [], []) }, "not CMS SignedData")
        // line 393 (count >= 1): the same for the encapContentInfo
        let signedData: [UInt8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]
        let sd = e(0x30, e(0x02, [3]) + e(0x31, []) + e(0x30, e(0x05, [])))
        let token = e(0x30, e(0x06, signedData) + e(0xa0, sd))
        XCTAssertEqual(failMessage { _ = try Sigstore.verifyRfc3161(token, [], []) }, "content is not TSTInfo")
    }
}
