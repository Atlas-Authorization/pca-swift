import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// Really-signed RIM documents and the rules read from them, the NVDEC0 and merge rules, the RIM ids, the CRL walk and the firmware version rules
/// (packages/pca/src/attest-nvidia-rim.ts).
final class AttestNvidiaRimK05Tests: XCTestCase {
    typealias F = StrictChainForge

    static let pins = [F.pin(F.rootKey)]
    static let META = "<Meta product=\"GH100\" colloquialVersion=\"535.86.10\"/>"
    static let MALFORMED = "RIM: malformed Measurement resource"
    static let TRANSFORMS = "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"

    static func doc(_ body: String, digest: String, sig: String, transforms: [String] = [RIM.ALG_ENVELOPED, RIM.ALG_C14N11]) -> String {
        let certs = F.chain().b64.map { "<X509Certificate>" + $0 + "</X509Certificate>" }.joined()
        let ts = transforms.map { "<Transform Algorithm=\"" + $0 + "\"/>" }.joined()
        let parts: [String] = [
            "<SoftwareIdentity xmlns=\"http://standards.iso.org/iso/19770/-2/2015/schema.xsd\">",
            body,
            "<Signature xmlns=\"\(RIM.NS_DSIG)\"><SignedInfo>",
            "<CanonicalizationMethod Algorithm=\"\(RIM.ALG_C14N11)\"/>",
            "<SignatureMethod Algorithm=\"\(RIM.ALG_ECDSA384)\"/>",
            "<Reference URI=\"\"><Transforms>", ts, "</Transforms><DigestMethod Algorithm=\"\(RIM.ALG_SHA384)\"/>",
            "<DigestValue>", digest, "</DigestValue></Reference></SignedInfo>",
            "<SignatureValue>", sig, "</SignatureValue><KeyInfo><X509Data>", certs, "</X509Data></KeyInfo></Signature>",
            "</SoftwareIdentity>",
        ]
        return parts.joined()
    }

    /// The document with its real digest and its real signature under the chain's leaf key.
    static func signed(_ body: String) -> String {
        let draft = try! XML.parse(doc(body, digest: "AA==", sig: "AA==")).root!
        let draftSig = draft.elementChildrenNS(RIM.NS_DSIG, "Signature")[0]
        let digest = Attest.base64StdEncode(ACrypto.sha384(Array(XML.canonicalize(draft, [:], draftSig).utf8)))
        let second = try! XML.parse(doc(body, digest: digest, sig: "AA==")).root!
        let canon = withExtendedLifetime(second) { () -> String in
            let si = second.elementChildrenNS(RIM.NS_DSIG, "Signature")[0].elementChildrenNS(RIM.NS_DSIG, "SignedInfo")[0]
            return XML.canonicalize(si, si.parent?.scope() ?? [:], nil)
        }
        let sig = try! F.leafKey.signature(for: Data(canon.utf8))
        return doc(body, digest: digest, sig: Attest.base64StdEncode(Array(sig.rawRepresentation)))
    }

    static func res(index: String = "1", alts: String = "1", size: String = "1", hashes: String = "Hash0=\"ab\"") -> String {
        "<Resource type=\"Measurement\" index=\"\(index)\" active=\"true\" alternatives=\"\(alts)\" size=\"\(size)\" \(hashes)/>"
    }

    static func payload(_ inner: String) -> String { META + "<Payload>" + inner + "</Payload>" }

    func verify(_ inner: String) -> (VerifiedRim?, String) { RIM.verify(Self.signed(Self.payload(inner)), Self.pins, F.NOW) }

    func why(_ inner: String) -> String { verify(inner).1 }

    func hashes(_ attrs: String, alts: String) -> [String]? { verify(Self.res(alts: alts, hashes: attrs)).0?.golden[1]?.hashes }

    // ---- the document ----

    func testASignedDocumentIsRead() throws {
        let (rimOpt, reason) = verify(Self.res())
        XCTAssertEqual(reason, "")
        let rim = try XCTUnwrap(rimOpt)
        XCTAssertEqual(rim.product, "GH100")
        XCTAssertEqual(rim.version, "535.86.10")
        XCTAssertEqual(rim.golden[1]?.index, 1)
        XCTAssertEqual(rim.golden[1]?.active, true)
        XCTAssertEqual(rim.golden[1]?.alternatives, 1)
        XCTAssertEqual(rim.golden[1]?.size, 1)
        XCTAssertEqual(rim.golden[1]?.hashes, ["ab"])
    }

    /// attest-nvidia-rim.ts:144 counts `xml.length`, UTF-16 code units; the bound is met before anything is parsed, so the next check answers.
    func testDocumentSizeBound() {
        let tooBig = "RIM: empty or oversized document", next = "RIM: no pinned RIM root configured"
        XCTAssertEqual(RIM.verify("", [], F.NOW).1, tooBig)
        XCTAssertEqual(RIM.verify(String(repeating: "x", count: 4_000_000), [], F.NOW).1, next)
        XCTAssertEqual(RIM.verify(String(repeating: "x", count: 4_000_001), [], F.NOW).1, tooBig)
        XCTAssertEqual(RIM.verify(String(repeating: "\u{1F600}", count: 2_000_000), [], F.NOW).1, next)
        XCTAssertEqual(RIM.verify(String(repeating: "\u{1F600}", count: 2_000_000) + "x", [], F.NOW).1, tooBig)
    }

    /// attest-nvidia-rim.ts:132-135
    func testPemOfDerB64() {
        let begin = "-----BEGIN CERTIFICATE-----\n", end = "\n-----END CERTIFICATE-----"
        let a64 = String(repeating: "A", count: 64)
        XCTAssertEqual(RIM.pemOfDerB64(""), begin + end)
        XCTAssertEqual(RIM.pemOfDerB64("AB CD\n"), begin + "ABCD" + end)
        XCTAssertEqual(RIM.pemOfDerB64(a64), begin + a64 + end)
        XCTAssertEqual(RIM.pemOfDerB64(a64 + "B"), begin + a64 + "\nB" + end)
    }

    /// attest-nvidia-rim.ts:183
    func testTransformsAreExact() {
        let e = RIM.ALG_ENVELOPED, c = RIM.ALG_C14N11
        func reason(_ t: [String]) -> String { RIM.verify(Self.doc(Self.META, digest: "AA==", sig: "AA==", transforms: t), Self.pins, F.NOW).1 }
        XCTAssertEqual(reason([e, c]), "RIM: SignatureValue is not a 96-byte P-384 signature")
        XCTAssertEqual(reason([e, c, c]), Self.TRANSFORMS)
        XCTAssertEqual(reason([c, c]), Self.TRANSFORMS)
        XCTAssertEqual(reason([e, e]), Self.TRANSFORMS)
        XCTAssertEqual(reason([c, e]), Self.TRANSFORMS)
    }

    /// attest-nvidia-rim.ts:187
    func testDigestAndSignatureValuesAreBothRequired() {
        let want = "RIM: missing DigestValue / SignatureValue"
        XCTAssertEqual(RIM.verify(Self.doc(Self.META, digest: "", sig: "AA=="), Self.pins, F.NOW).1, want)
        XCTAssertEqual(RIM.verify(Self.doc(Self.META, digest: "AA==", sig: ""), Self.pins, F.NOW).1, want)
        XCTAssertEqual(RIM.verify(Self.doc(Self.META, digest: "", sig: ""), Self.pins, F.NOW).1, want)
    }

    /// attest-nvidia-rim.ts:212-213: `.find`, the first of each.
    func testTheFirstMetaAndPayloadAreRead() throws {
        let other = "<Meta product=\"OTHER\" colloquialVersion=\"1\"/>"
        let p1 = "<Payload>" + Self.res(index: "1") + "</Payload>", p2 = "<Payload>" + Self.res(index: "2") + "</Payload>"
        let rim = try XCTUnwrap(RIM.verify(Self.signed("<Other/>" + Self.META + other + p1 + p2), Self.pins, F.NOW).0)
        XCTAssertEqual(rim.product, "GH100")
        XCTAssertEqual(Array(rim.golden.keys), [1])
        XCTAssertEqual(RIM.verify(Self.signed("<Other/>" + p1), Self.pins, F.NOW).1, "RIM: missing Meta / Payload")
        XCTAssertEqual(RIM.verify(Self.signed(Self.META + "<Other/>"), Self.pins, F.NOW).1, "RIM: missing Meta / Payload")
    }

    /// attest-nvidia-rim.ts:217
    func testOnlyMeasurementResourcesAreRead() throws {
        let rim = try XCTUnwrap(verify("<Resource type=\"Other\"/><Foo type=\"Measurement\"/>" + Self.res()).0)
        XCTAssertEqual(Array(rim.golden.keys), [1])
        XCTAssertEqual(why("<Resource type=\"Other\"/>"), "RIM: no measurements")
    }

    // ---- Hash attributes ----

    /// attest-nvidia-rim.ts:222: `^Hash\d+$`
    func testOnlyHashNAttributesCount() {
        XCTAssertEqual(hashes("Hash=\"zz\" Hash0=\"ab\"", alts: "1"), ["ab"])
        XCTAssertEqual(hashes("HashX=\"zz\" Hash0=\"ab\"", alts: "1"), ["ab"])
        XCTAssertEqual(hashes("Hash1x=\"zz\" Hash0=\"ab\"", alts: "1"), ["ab"])
        XCTAssertEqual(hashes("Xash1=\"zz\" Hash0=\"ab\"", alts: "1"), ["ab"])
    }

    /// attest-nvidia-rim.ts:223: numeric order, a tie keeps document order; `.toLowerCase()`.
    func testHashOrder() {
        XCTAssertEqual(hashes("Hash10=\"bb\" Hash2=\"aa\"", alts: "2"), ["aa", "bb"])
        XCTAssertEqual(hashes("Hash01=\"cc\" Hash1=\"dd\"", alts: "2"), ["cc", "dd"])
        XCTAssertEqual(hashes("Hash1=\"dd\" Hash01=\"cc\"", alts: "2"), ["dd", "cc"])
        XCTAssertEqual(hashes("Hash99999999999999999999=\"bb\" Hash2=\"aa\"", alts: "2"), ["aa", "bb"], "too big for an Int, not for Number()")
        XCTAssertEqual(hashes("Hash0=\"AB\"", alts: "1"), ["ab"])
    }

    // ---- Measurement numbers ----

    /// attest-nvidia-rim.ts:225
    func testMeasurementNumbers() throws {
        for bad in ["abc", "1.5", "-1", "Infinity"] { XCTAssertEqual(why(Self.res(index: bad)), Self.MALFORMED, bad) }
        for bad in ["abc", "0", "-1", "1.5", "Infinity"] { XCTAssertEqual(why(Self.res(alts: bad)), Self.MALFORMED, bad) }
        for bad in ["abc", "0", "-1", "1.5", "Infinity"] { XCTAssertEqual(why(Self.res(size: bad)), Self.MALFORMED, bad) }
        XCTAssertNotNil(verify(Self.res(index: "0")).0?.golden[0])
    }

    /// An index beyond the safe integers has no Int form (Int(1e300) traps). Stricter than attest-nvidia-rim.ts:225, which keeps it as a Map key.
    func testAHugeIndexIsRefusedNotATrap() throws {
        XCTAssertNotNil(verify(Self.res(index: "9007199254740991")).0?.golden[9_007_199_254_740_991])
        XCTAssertEqual(why(Self.res(index: "9007199254740992")), Self.MALFORMED)
        XCTAssertEqual(why(Self.res(index: "1e300")), Self.MALFORMED)
    }

    /// attest-nvidia-rim.ts:226, whole numbers beyond any Int included.
    func testHashListConsistency() {
        func inconsistent(_ index: Int) -> String { "RIM: Measurement \(index) hash list is inconsistent with alternatives/size" }
        XCTAssertEqual(why(Self.res(alts: "2")), inconsistent(1))
        XCTAssertEqual(why(Self.res(alts: "1e300")), inconsistent(1))
        XCTAssertEqual(why(Self.res(size: "1e300")), inconsistent(1))
        XCTAssertEqual(why(Self.res(size: "2")), inconsistent(1))
        XCTAssertEqual(why(Self.res(hashes: "Hash0=\"zz\"")), inconsistent(1), "not hex, the right length")
        XCTAssertEqual(why(Self.res(hashes: "Hash0=\"abc\"")), inconsistent(1), "hex, the wrong length")
        XCTAssertEqual(why(Self.res(alts: "2", hashes: "Hash0=\"ab\" Hash1=\"zz\"")), inconsistent(1))
        XCTAssertEqual(why(Self.res() + Self.res()), "RIM: duplicate Measurement index 1")
    }

    func testIsLowerHex() {
        for good in ["0", "9", "a", "f", "09af"] { XCTAssertTrue(RIM.isLowerHex(good), good) }
        for bad in ["", "g", "zz", "A", "/", ":", "`"] { XCTAssertFalse(RIM.isLowerHex(bad), bad) }
    }

    // ---- the RIM ids ----

    /// `^[A-Z][A-Z0-9]{2,11}$` (attest-nvidia-rim.ts:282)
    func testIsChipName() {
        for good in ["AAA", "ZZZ", "GH100", "A00", "A99", "AZZ", "ABCDEFGHIJKL"] { XCTAssertTrue(RIM.isChipName(good), good) }
        for bad in ["", "AB", "ABCDEFGHIJKLM", "1AA", "aAA", "@AA", "[AA", "Aaa", "A@A", "A[A", "A/A", "A:A"] { XCTAssertFalse(RIM.isChipName(bad), bad) }
    }

    func report(chip: String? = nil) -> SpdmReport {
        var r = SpdmReport()
        r.opaque[Nvidia.OPAQUE_DRIVER_VERSION] = Array("535.86.10".utf8)
        r.opaque[Nvidia.OPAQUE_VBIOS_VERSION] = [0x00, 0x9f, 0x00, 0x96, 0x04, 0x00, 0x00, 0x00]
        r.opaque[17] = Array("p1".utf8)
        r.opaque[18] = Array("s1".utf8)
        r.opaque[15] = Array("c1".utf8)
        if let c = chip { r.opaque[Nvidia.OPAQUE_CHIP_INFO] = Array(c.utf8) }
        return r
    }

    /// attest-nvidia-rim.ts:270-292
    func testIdsForReport() throws {
        let hopper = try XCTUnwrap(RIM.idsForReport(report()))
        XCTAssertEqual(hopper.chip, "GH100")
        XCTAssertEqual(hopper.driver, "NV_GPU_DRIVER_GH100_535.86.10")
        XCTAssertEqual(hopper.driverVersion, "535.86.10")
        XCTAssertEqual(hopper.vbiosVersion, "96.00.9f.00.04")
        XCTAssertEqual(hopper.vbios, "NV_GPU_VBIOS_P1_S1_C1_96009F0004")
        let blackwell = try XCTUnwrap(RIM.idsForReport(report(chip: "GB100")))
        XCTAssertEqual(blackwell.chip, "GB100")
        XCTAssertEqual(blackwell.driver, "NV_GPU_CC_DRIVER_GB100_535.86.10")
        XCTAssertEqual(try XCTUnwrap(RIM.idsForReport(report(chip: "GH100"))).driver, "NV_GPU_DRIVER_GH100_535.86.10")
        XCTAssertNil(RIM.idsForReport(report(chip: "gb100")))
    }

    func testEveryOpaqueFieldIsRequired() {
        for field in [Nvidia.OPAQUE_DRIVER_VERSION, Nvidia.OPAQUE_VBIOS_VERSION, 17, 18, 15] {
            var r = report()
            r.opaque[field] = nil
            XCTAssertNil(RIM.idsForReport(r), "\(field)")
        }
    }

    // ---- the comparison ----

    func rim(_ goldens: [RimGolden]) -> VerifiedRim {
        var m: [Int: RimGolden] = [:]
        for g in goldens { m[g.index] = g }
        return VerifiedRim(product: "", version: "", golden: m)
    }

    func gold(_ index: Int, _ hash: String = "ab") -> RimGolden { RimGolden(index: index, active: true, alternatives: 1, size: 1, hashes: [hash]) }

    func spdm(_ blocks: [Int], digest: [UInt8] = [0xab], nvdec: [UInt8]? = nil, field: Int = 11) -> SpdmReport {
        var r = SpdmReport()
        r.measurements = blocks.map { SpdmMeasurement(index: $0, digest: digest) }
        if let n = nvdec { r.opaque[field] = n }
        return r
    }

    /// attest-nvidia-rim.ts:309
    func testAsManyMeasurementsAsTheReportCarriesIsEnough() {
        XCTAssertEqual(RIM.compareReportToRims(spdm([2]), rim([gold(1)]), rim([])), "")
        XCTAssertEqual(RIM.compareReportToRims(spdm([2]), rim([gold(1)]), rim([gold(2)])), "RIMs list more active measurements than the report carries")
    }

    /// attest-nvidia-rim.ts:310-315: golden index 34 is SPDM block 35, skipped when opaque field 11 starts with 0x55.
    func testNvdecDisabledSkipsBlock35Only() {
        let differ = "runtime measurements differ from the golden RIM values at 1 index(es)"
        func cmp(_ index: Int, nvdec: [UInt8]?, field: Int = 11) -> String {
            RIM.compareReportToRims(spdm([index + 1], digest: [0xcd], nvdec: nvdec, field: field), rim([gold(index)]), rim([]))
        }
        XCTAssertEqual(cmp(34, nvdec: [0x55]), "")
        XCTAssertEqual(cmp(34, nvdec: [0x55, 0x00]), "")
        XCTAssertEqual(cmp(34, nvdec: nil), differ)
        XCTAssertEqual(cmp(34, nvdec: [0x54]), differ)
        XCTAssertEqual(cmp(34, nvdec: [0x00, 0x55]), differ)
        XCTAssertEqual(cmp(34, nvdec: []), differ)
        XCTAssertEqual(cmp(34, nvdec: [0x55], field: 10), differ)
        XCTAssertEqual(cmp(34, nvdec: [0x55], field: 12), differ)
        XCTAssertEqual(cmp(33, nvdec: [0x55]), differ)
        XCTAssertEqual(cmp(35, nvdec: [0x55]), differ)
        XCTAssertEqual(cmp(36, nvdec: [0x55]), differ)
    }

    // ---- CRLs ----

    static func crl(signer: F.Key, revoked: [UInt8] = []) -> [UInt8] {
        let alg = F.seq(F.oid(AttestNvidiaOcspK05Tests.OID_ECDSA_SHA256))
        let this = DERB.tlv(0x17, Array("270101000000Z".utf8)), next = DERB.tlv(0x17, Array("280101000000Z".utf8))
        var list: [UInt8] = []
        if !revoked.isEmpty { list = F.seq(revoked.flatMap { F.seq(DERB.tlv(0x02, [$0]) + this) }) }
        let head: [UInt8] = DERB.tlv(0x02, [0x01]) + alg + F.name("crl")
        let tbs = F.seq(head + this + next + list)
        let bits: [UInt8] = [0x00] + AttestNvidiaOcspK05Tests.sign(tbs, signer, .sha256)
        return F.seq(tbs + alg + DERB.tlv(0x03, bits))
    }

    func chain() throws -> [AttCert] { try F.chain().ders.map { try Cert.parseDER($0) } } // serials 3, 2, 1

    /// attest-nvidia-rim.ts:338-365
    func testACrlRevokesOnlyWhatItsIssuerIssued() throws {
        let c = try chain()
        func walk(_ crls: [[UInt8]], _ need: [String] = []) -> String { RIM.checkChainRevocation(c, crls, F.NOW, need) }
        XCTAssertEqual(walk([Self.crl(signer: F.rootKey)]), "")
        XCTAssertEqual(walk([Self.crl(signer: F.rootKey, revoked: [2])]), "chain certificate '\(Nvidia.subjectLine(c[1]))' is revoked", "by the root")
        XCTAssertEqual(walk([Self.crl(signer: F.midKey, revoked: [3])]), "chain certificate '\(Nvidia.subjectLine(c[0]))' is revoked", "by the intermediate")
        XCTAssertEqual(walk([Self.crl(signer: F.rootKey, revoked: [3])]), "", "the root did not issue the leaf")
        XCTAssertEqual(walk([Self.crl(signer: F.midKey, revoked: [2])]), "", "the intermediate did not issue itself")
        XCTAssertEqual(walk([Self.crl(signer: F.leafKey, revoked: [3])]), "", "the leaf's own CRL verifies and has nothing to revoke")
        XCTAssertEqual(walk([Self.crl(signer: F.rootKey, revoked: [1])]), "", "the root is not revoked by itself")
        XCTAssertEqual(walk([Self.crl(signer: F.strangerKey)]), "CRL #0 rejected: CRL signature does not verify under the issuer")
        XCTAssertEqual(walk([Self.crl(signer: F.rootKey), Self.crl(signer: F.strangerKey)]), "CRL #1 rejected: CRL signature does not verify under the issuer")
        XCTAssertEqual(walk([Self.crl(signer: F.leafKey)], ["Strict Leaf"]), "", "a CRL under the first chain certificate counts as covered")
        XCTAssertEqual(walk([Self.crl(signer: F.rootKey)], ["Strict Mid"]), "no verified CRL issued by a certificate matching 'Strict Mid'")
    }

    // ---- firmware versions ----

    /// attest-nvidia-rim.ts:410
    func testVersionPatterns() {
        for good in ["1", "1.2", "535.86.10", "0", "007"] { XCTAssertTrue(RIM.isDecVersion(good), good) }
        for bad in ["", ".", "1.", ".1", "1..2", "abc", "1.a", "/", ":"] { XCTAssertFalse(RIM.isDecVersion(bad), bad) }
        for good in ["a", "96.00.9f", "ABCD", "0.ffff"] { XCTAssertTrue(RIM.isHexVersion(good), good) }
        for bad in ["", ".", "1.", ".1", "1..2", "zz", "1.z", "12345", "1.12345"] { XCTAssertFalse(RIM.isHexVersion(bad), bad) }
    }

    /// attest-nvidia-rim.ts:412: parseInt, including digits beyond 2^64.
    func testParseVersion() {
        XCTAssertEqual(RIM.parseVersion("535.86.10", 10), [535, 86, 10])
        XCTAssertEqual(RIM.parseVersion("96.0a", 16), [150, 10])
        XCTAssertEqual(RIM.parseVersion("99999999999999999999", 10), [1e20])
        XCTAssertNil(RIM.parseVersion("1..2", 10))
        XCTAssertNil(RIM.parseVersion("1..2", 16))
        XCTAssertNil(RIM.parseVersion("zz", 16))
    }

    /// attest-nvidia-rim.ts:414-420: exactly -1, 0, 1; a missing component is 0; NaN from Infinity - Infinity is not 0.
    func testCmpVersion() {
        XCTAssertEqual(RIM.cmpVersion([1], [1]), 0)
        XCTAssertEqual(RIM.cmpVersion([1], [1, 0]), 0)
        XCTAssertEqual(RIM.cmpVersion([1, 0], [1]), 0)
        XCTAssertEqual(RIM.cmpVersion([1], [2]), -1)
        XCTAssertEqual(RIM.cmpVersion([2], [1]), 1)
        XCTAssertEqual(RIM.cmpVersion([1], [1, 1]), -1)
        XCTAssertEqual(RIM.cmpVersion([1, 1], [1]), 1)
        XCTAssertEqual(RIM.cmpVersion([0.5], [0]), 1)
        XCTAssertEqual(RIM.cmpVersion([0], [0.5]), -1)
        XCTAssertEqual(RIM.cmpVersion([1, 5], [2, 0]), -1)
        XCTAssertEqual(RIM.cmpVersion([.infinity], [.infinity]), 1)
    }

    /// attest-nvidia-rim.ts:440: the floor itself is allowed.
    func testVbiosFloor() throws {
        var ids = NvidiaRimIDs()
        ids.driverVersion = "535.86.10"
        ids.vbiosVersion = "96.00.9f.00.04"
        let at = try RIM.FirmwarePolicy(["minVbiosVersion": .string("96.00.9f.00.04")])
        XCTAssertEqual(at.check(ids), "")
        let above = try RIM.FirmwarePolicy(["minVbiosVersion": .string("96.00.a0.00.04")])
        XCTAssertEqual(above.check(ids), "VBIOS 96.00.9f.00.04 is below the minimum 96.00.a0.00.04")
    }

    // ---- the chip family ----

    /// `(^|[^A-Za-z0-9])CHIP([^A-Za-z0-9]|$)` (attest-nvidia-rim.ts:457). The refusals come first: a mutant that drops a boundary fails on them.
    func testChipInSubject() {
        for c in ["0", "5", "9", "A", "M", "Z", "a", "m", "z"] {
            XCTAssertFalse(NvidiaHook.chipInSubject(c + "GH100", "GH100"), "before: " + c)
            XCTAssertFalse(NvidiaHook.chipInSubject("GH100" + c, "GH100"), "after: " + c)
            XCTAssertFalse(NvidiaHook.chipInSubject("CN=" + c + "GH100,", "GH100"), "before, inside: " + c)
            XCTAssertFalse(NvidiaHook.chipInSubject(",GH100" + c + ",", "GH100"), "after, inside: " + c)
        }
        for s in ["", "GH10", "ABCDEFG", "xGH100y", "GH10 0"] { XCTAssertFalse(NvidiaHook.chipInSubject(s, "GH100"), s) }
        for s in ["GH100", "GH100 Device", "CN=GH100", "CN=GH100,O=x", "/GH100:", "\u{e9}GH100\u{e9}", "aGH100 GH100"] { XCTAssertTrue(NvidiaHook.chipInSubject(s, "GH100"), s) }
    }
}
