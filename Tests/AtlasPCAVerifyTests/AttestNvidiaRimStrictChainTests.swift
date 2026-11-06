import XCTest
@testable import AtlasPCAVerify

/// The RIM signer chain runs the device chain check (packages/pca/src/attest-nvidia-rim.ts:194 -> attest-nvidia-spdm.ts:224), so it gets the strict
/// profile too; and an empty firmware policy is a policy (attest-nvidia-rim.ts:424 `!fw`): an unparseable reported version is still refused.
final class AttestNvidiaRimStrictChainTests: XCTestCase {
    typealias F = StrictChainForge

    /// Structurally complete up to the signer chain. The SignatureValue is one byte, so a chain that passes stops at the very next check.
    func rim(_ c: F.Chain) -> String {
        let certs = c.b64.map { "<X509Certificate>" + $0 + "</X509Certificate>" }.joined()
        let parts: [String] = [
            "<SoftwareIdentity xmlns=\"http://standards.iso.org/iso/19770/-2/2015/schema.xsd\">",
            "<Signature xmlns=\"\(RIM.NS_DSIG)\"><SignedInfo>",
            "<CanonicalizationMethod Algorithm=\"\(RIM.ALG_C14N11)\"/>",
            "<SignatureMethod Algorithm=\"\(RIM.ALG_ECDSA384)\"/>",
            "<Reference URI=\"\"><Transforms>",
            "<Transform Algorithm=\"\(RIM.ALG_ENVELOPED)\"/>",
            "<Transform Algorithm=\"\(RIM.ALG_C14N11)\"/>",
            "</Transforms><DigestMethod Algorithm=\"\(RIM.ALG_SHA384)\"/><DigestValue>AA==</DigestValue></Reference>",
            "</SignedInfo><SignatureValue>AA==</SignatureValue><KeyInfo><X509Data>\(certs)</X509Data></KeyInfo></Signature>",
            "</SoftwareIdentity>",
        ]
        return parts.joined()
    }

    lazy var pins = [F.pin(F.rootKey)]
    static let PAST_THE_CHAIN = "RIM: SignatureValue is not a 96-byte P-384 signature"

    func testAGoodSignerChainGetsPastTheChainCheck() {
        XCTAssertEqual(RIM.verify(rim(F.chain()), pins, F.NOW).1, Self.PAST_THE_CHAIN)
        XCTAssertEqual(RIM.verify(rim(F.chain(F.Shape(leaf: F.LEAF + [F.CRITICAL_EKU]))), pins, F.NOW).1, Self.PAST_THE_CHAIN)
    }

    func testSignerChainProfileViolationsAreRefused() {
        let cases: [(F.Shape, String)] = [
            (F.Shape(leaf: [F.bc(true), F.KU_SIGN]), "device chain profile: " + F.LEAF_CA_TRUE),
            (F.Shape(root: [F.bc(true, pathLen: 0), F.KU_CERT_SIGN]), "device chain profile: issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)"),
            (F.Shape(leaf: F.LEAF + [F.CRITICAL_UNKNOWN]), "device chain profile: certificate at depth 0 has an unrecognised critical extension 1.2.3.4"),
            (F.Shape(mid: F.CA + [F.CRITICAL_UNKNOWN]), "device chain profile: certificate at depth 1 has an unrecognised critical extension 1.2.3.4"),
            (F.Shape(mid: [F.bc(false), F.KU_CERT_SIGN]), "device chain cert #1 issues a certificate but is not a CA"),
            (F.Shape(mid: [F.bc(true), F.KU_SIGN]), "device chain cert #1 issues a certificate but is not a CA"),
        ]
        for (shape, want) in cases {
            let (out, why) = RIM.verify(rim(F.chain(shape)), pins, F.NOW)
            XCTAssertNil(out, want)
            XCTAssertEqual(why, "RIM signer chain: " + want)
        }
    }

    func testRealVectorRimChainsStillPass() throws {
        try F.assertAcceptedRowsStillPass("nvidia-gpu-spdm", idPrefix: "nv-real-positive")
    }

    // ---- through the hook, and the firmware policy ----

    func report(driver: String = "535.86.10", vbios: [UInt8] = [0x00, 0x04, 0x9f, 0x00, 0x96]) -> SpdmReport {
        var r = SpdmReport()
        r.opaque[Nvidia.OPAQUE_DRIVER_VERSION] = Array(driver.utf8)
        r.opaque[Nvidia.OPAQUE_VBIOS_VERSION] = vbios
        r.opaque[17] = Array("P1".utf8)
        r.opaque[18] = Array("S1".utf8)
        r.opaque[15] = Array("C1".utf8)
        return r
    }

    /// A device chain the hook's chip-family check accepts (no chip opaque field: GH100).
    func deviceChain() throws -> [AttCert] {
        [try Cert.parseDER(F.cert(subject: "GH100 Device", issuer: "Strict Mid", subjectKey: F.leafKey, signer: F.midKey, serial: 3, exts: F.LEAF))]
    }

    func hook(_ extra: JObject = [:]) throws -> NvidiaHook {
        var col: JObject = ["rimRootSpkiSha256": .array([.string(pins[0])])]
        for (k, v) in extra { col[k] = v }
        return try NvidiaHook(col)
    }

    func testTheHookRefusesWithTheSiteReason() throws {
        let bad = rim(F.chain(F.Shape(leaf: [F.bc(true), F.KU_SIGN])))
        let col: JObject = ["driverRimXml": .string(bad), "vbiosRimXml": .string(bad)]
        XCTAssertEqual(try hook().run(col, report(), try deviceChain(), F.NOW), "driver RIM: RIM signer chain: device chain profile: " + F.LEAF_CA_TRUE)
    }

    func testAnEmptyFirmwarePolicyIsAPolicy() throws {
        let empty = try hook(["firmware": .object([:])])
        XCTAssertNotNil(empty.firmware)
        let chain = try deviceChain()
        XCTAssertEqual(empty.run(nil, report(driver: "abc"), chain, F.NOW), "firmware policy: driver version 'abc' in the GPU report is not parseable")
        XCTAssertEqual(empty.run(nil, report(vbios: []), chain, F.NOW), "firmware policy: VBIOS version '' in the GPU report is not parseable")
        XCTAssertEqual(empty.run(nil, report(), chain, F.NOW), "no RIM collateral supplied for this report")
    }

    func testNoFirmwarePolicySkipsTheVersionCheck() throws {
        let none = try hook()
        XCTAssertNil(none.firmware)
        XCTAssertEqual(none.run(nil, report(driver: "abc"), try deviceChain(), F.NOW), "no RIM collateral supplied for this report")
    }

    /// attest-nvidia-rim.ts:424-433: a truthy non-object is a policy, a falsy floor is absent, anything else that is not a version throws.
    func testMalformedFirmwareConfigIsRefused() throws {
        XCTAssertNotNil(try hook(["firmware": .int(1)]).firmware)
        XCTAssertNotNil(try hook(["firmware": .array([])]).firmware)
        XCTAssertNil(try hook(["firmware": .int(0)]).firmware)
        XCTAssertNil(try hook(["firmware": .null]).firmware)
        for k in ["minDriverVersion", "minVbiosVersion"] {
            XCTAssertThrowsError(try RIM.FirmwarePolicy([JKey(k): .int(5)]), k)
            XCTAssertThrowsError(try RIM.FirmwarePolicy([JKey(k): .string("zz.zz")]), k)
            XCTAssertNoThrow(try RIM.FirmwarePolicy([JKey(k): .int(0)]), k)
            XCTAssertNoThrow(try RIM.FirmwarePolicy([JKey(k): .string("")]), k)
        }
        XCTAssertEqual(try RIM.FirmwarePolicy(["minDriverVersion": .string("535.1")]).minDText, "535.1")
        XCTAssertEqual(try RIM.FirmwarePolicy(["minVbiosVersion": .string("96.0a")]).minVText, "96.0a")
        for k in ["denyDriverVersions", "denyVbiosVersions"] {
            XCTAssertThrowsError(try RIM.FirmwarePolicy([JKey(k): .array([.int(5)])]), k)
            XCTAssertThrowsError(try RIM.FirmwarePolicy([JKey(k): .string("1")]), k)
            XCTAssertThrowsError(try RIM.FirmwarePolicy([JKey(k): .int(0)]), k)
            XCTAssertNoThrow(try RIM.FirmwarePolicy([JKey(k): .null]), k)
        }
        XCTAssertEqual(try RIM.FirmwarePolicy(["denyDriverVersions": .array([.string("535.1")])]).denyD, [[535, 1]])
        XCTAssertEqual(try RIM.FirmwarePolicy(["denyVbiosVersions": .array([.string("10")])]).denyV, [[16]])
    }
}
