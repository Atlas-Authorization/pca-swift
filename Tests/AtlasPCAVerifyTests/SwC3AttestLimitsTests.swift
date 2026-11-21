import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Literal-valued boundaries for the size and depth caps of the attestation parsers (the caps are asserted by number, not by constant).
final class SwC3AttestCommonLimitTests: XCTestCase {
    func testLenientJsonByteCapIsSixteenMiB() {
        let cap = 16 * 1024 * 1024
        var atCap = [UInt8](repeating: 0x20, count: cap)
        atCap[0] = 0x31
        XCTAssertNotNil(Attest.jsonLenient(atCap), "exactly 16 MiB is parsed")
        var over = atCap
        over.append(0x20)
        XCTAssertNil(Attest.jsonLenient(over), "one byte over 16 MiB is refused")
    }
}

final class SwC3AttestDERLimitTests: XCTestCase {
    private func oid(_ content: [UInt8]) -> String {
        let b: [UInt8] = [0x06] + content
        do { return try DER.oidToDotted(b, DerTlv(tag: 0x06, start: 1, end: b.count)) } catch { return "ERR:\((error as? AttestError)?.message ?? "?")" }
    }

    func testOidContentCapIs256Bytes() {
        XCTAssertFalse(oid([UInt8](repeating: 0x01, count: 256)).hasPrefix("ERR"))
        XCTAssertEqual(oid([UInt8](repeating: 0x01, count: 257)), "ERR:extension OID is too long")
    }

    func testOidArcCapIs64Groups() {
        XCTAssertFalse(oid([0x2a] + [UInt8](repeating: 0x81, count: 63) + [0x01]).hasPrefix("ERR"), "64 groups decode")
        XCTAssertEqual(oid([0x2a] + [UInt8](repeating: 0x81, count: 64) + [0x01]), "ERR:extension OID has an oversized arc", "65 groups are refused")
    }
}

final class SwC3AttestXMLLimitTests: XCTestCase {
    private func parse(_ levels: Int) -> String {
        let src = String(repeating: "<a>", count: levels) + String(repeating: "</a>", count: levels)
        do { _ = try XML.parse(src); return "ok" } catch { return (error as? AttestError)?.message ?? "other" }
    }

    func testNestingCapIs64() {
        XCTAssertEqual(parse(64), "ok")
        XCTAssertEqual(parse(65), "XML nesting is too deep")
    }
}

final class SwC3AttestNvidiaOcspLimitTests: XCTestCase {
    private func nested(_ levels: Int) -> [UInt8] {
        var c: [UInt8] = [0x05, 0x00]
        for _ in 0..<levels {
            let l = c.count
            let len: [UInt8] = l < 128 ? [UInt8(l)] : l < 256 ? [0x81, UInt8(l)] : [0x82, UInt8(l >> 8), UInt8(l & 0xff)]
            c = [0x30] + len + c
        }
        return c
    }

    private func wellFormed(_ levels: Int) -> Bool {
        let der = nested(levels)
        guard let n = try? OCSP.readNode(der, 0, der.count) else { return false }
        return OCSP.timesWellFormed(der, n)
    }

    func testDepthCapIs64() {
        XCTAssertTrue(wellFormed(64))
        XCTAssertFalse(wellFormed(65))
    }
}

/// A DER ECDSA-Sig-Value shape check: every guard, by input.
final class SwC3AttestCryptoDerSigTests: XCTestCase {
    private func sig(_ l1: Int, _ l2: Int, outer: [UInt8]) -> [UInt8] {
        outer + [0x02, UInt8(l1)] + [UInt8](repeating: 0x01, count: l1) + [0x02, UInt8(l2)] + [UInt8](repeating: 0x01, count: l2)
    }

    func testOuterLengthMustMatchTheBody() {
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], maxInt: 33))
        XCTAssertTrue(ACrypto.derSigMinimal([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], maxInt: 33))
    }

    func testIntegerTagMustBeTwo() {
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02], maxInt: 33))
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x02], maxInt: 33))
    }

    func testIntegerLengthMustFitTheBody() {
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x06, 0x02, 0x09, 0x01, 0x01, 0x02, 0x01], maxInt: 33))
    }

    /// The first byte after the tag decides the form: 0x80 is neither a short length nor the 0x81 long form.
    func testLengthFormIsChosenByTheLengthByte() {
        let body = sig(62, 62, outer: [])
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x80] + body, maxInt: 100), "0x80 is not a valid length octet")
        XCTAssertTrue(ACrypto.derSigMinimal([0x30, 0x81, 0x80] + body, maxInt: 100), "a 128-byte body in the 0x81 form")
        // short-form length 0x81 (129) is not what 0x81 means: it is the long-form marker, and the next byte (0x02) is not a length
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x81] + sig(62, 63, outer: []), maxInt: 100))
    }

    func testIntegerLengthBelow128() {
        let one = [UInt8](repeating: 0x01, count: 128)
        let d: [UInt8] = [0x30, 0x81, 133, 0x02, 0x80] + one + [0x02, 0x01, 0x01]
        XCTAssertFalse(ACrypto.derSigMinimal(d, maxInt: 200), "an integer length of 0x80 is not short form")
    }

    // The following inputs make a weakened guard index past the end of the array; the exact behaviour here is plain false / true.
    func testIntegerRunningOffTheEndIsRefused() {
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x09, 0x02, 0x06, 1, 1, 1, 1, 1, 1, 0x02], maxInt: 33), "second integer starts on the last byte")
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x08, 0x02, 0x06, 1, 1, 1, 1, 1, 1], maxInt: 33), "second integer is missing")
    }

    func testZeroLengthIntegerIsRefused() {
        XCTAssertFalse(ACrypto.derSigMinimal([0x30, 0x06, 0x02, 0x00, 0x02, 0x01, 0x01, 0x00], maxInt: 33))
    }

    func testZeroIsAMinimalInteger() {
        XCTAssertTrue(ACrypto.derSigMinimal([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01], maxInt: 33))
    }
}

/// A 1-bit exponent (e = 1) makes a "signature" the padded message itself: the key rule, not the verification, must refuse it.
final class SwC3SigstoreRsaKeyTests: XCTestCase {
    private func weakKey() -> (CertKey, [UInt8], [UInt8], [UInt8]) {
        var n = [UInt8](repeating: 0xff, count: 128)
        n[127] = 0xfb
        let msg: [UInt8] = Array("weak exponent".utf8)
        let t = AHash.sha256.digestInfoPrefix + AHash.sha256.digest(msg)
        var em = [UInt8](repeating: 0xff, count: 128)
        em[0] = 0x00; em[1] = 0x01; em[128 - t.count - 1] = 0x00
        for i in 0..<t.count { em[128 - t.count + i] = t[i] }
        var k = CertKey()
        k.typ = "rsa"; k.rsaN = n; k.rsaE = [0x01]
        return (k, n, msg, em)
    }

    func testTheForgedSignatureIsAValidPkcs1Block() {
        let (k, n, msg, em) = weakKey()
        XCTAssertFalse(ACrypto.rsaKeyOK(n: n, e: k.rsaE))
        XCTAssertTrue(ACrypto.rsaVerifyPKCS1(n: n, e: k.rsaE, hash: .sha256, message: msg, sig: em), "the primitive alone accepts it")
    }

    func testSigstoreVerifyDerRefusesAWeakExponent() {
        let (k, _, msg, em) = weakKey()
        XCTAssertFalse(Sigstore.verifyDer(k, .sha256, msg, em))
    }

    func testCollateralCrlSignatureRefusesAWeakExponent() {
        let (k, _, msg, em) = weakKey()
        XCTAssertFalse(IntelCollateral.crlSigOK(msg, em, k))
    }
}

final class SwC3AttestJWSJwkRsaTests: XCTestCase {
    private func b64u(_ b: [UInt8]) -> String {
        Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func accepts(_ e: [UInt8]) -> Bool {
        (try? JWS.jwkRSAKey(b64u([UInt8](repeating: 0x81, count: 64)), b64u(e))) != nil
    }

    func testExponentRules() {
        XCTAssertTrue(accepts([0x03]))
        XCTAssertTrue(accepts([0x01, 0x00, 0x01]))
        XCTAssertTrue(accepts([0x7f, 0xff, 0xff, 0xff]), "2^31 - 1 is the largest")
        XCTAssertFalse(accepts([0x80, 0x00, 0x00, 0x01]), "2^31 + 1 is over")
        XCTAssertFalse(accepts([0xff, 0xff, 0xff, 0xff]))
        XCTAssertFalse(accepts([0x04]), "even")
        XCTAssertFalse(accepts([0x01]), "below 3")
        XCTAssertFalse(accepts([0x01, 0x00, 0x00, 0x00, 0x01]), "more than four bytes")
    }
}

/// Class name starts with A0 so it runs before the deep-nesting tests that would otherwise take the process down first.
final class A0SwC3AttestJWSDepthTests: XCTestCase {
    private func nest(_ n: Int) -> String { String(repeating: "[", count: n) + String(repeating: "]", count: n) }

    func testNestingCapIs1024() {
        XCTAssertEqual(V8JSON.error(nest(1024)), "", "1024 levels are inside the cap")
        XCTAssertEqual(V8JSON.error(nest(1025)), "Maximum call stack size exceeded")
    }

    func testDepthIsReleasedAfterEachSibling() {
        let siblings = String(repeating: "[],", count: 1100)
        XCTAssertEqual(V8JSON.error("[" + siblings + "[]]"), "", "many siblings are not nesting")
        XCTAssertEqual(V8JSON.error("[" + String(repeating: "[],", count: 10) + nest(1024) + "]"), "Maximum call stack size exceeded", "the outer level still counts")
    }
}

final class SwC3SafeRegexBudgetTests: XCTestCase {
    func testRefusalsAreCountedOneByOne() {
        let b = SafeRegex.Budget()
        XCTAssertEqual(b.refusals, 0)
        XCTAssertFalse(b.charge(srcUnits: 1, progLen: 5_000_001, subjectUnits: 0))
        XCTAssertEqual(b.refusals, 1)
        XCTAssertFalse(b.charge(srcUnits: 1, progLen: 1, subjectUnits: 0))
        XCTAssertEqual(b.refusals, 2)
    }
}

final class SwC3SigstoreTimestampCapTests: XCTestCase {
    private func detail(stamps: Int) throws -> String {
        let d = try ConformanceTests.load("sigstore-vectors.json")
        guard let c = (d.get("cases")?.asArray ?? []).first(where: { $0.get("expect")?.get("ok") == .bool(true) }),
              var bundle = c.get("bundle")?.asObject, var vm = bundle["verificationMaterial"]?.asObject else { XCTFail("no ok case"); return "" }
        let roots = try PCA.parseSigstoreTrustedRoot(d.get("roots")?.get(c.get("roots")?.asString ?? "") ?? .null)
        let ts: [JSONValue] = (0..<stamps).map { _ in .object(["signedTimestamp": .string("AAAA")]) }
        vm["timestampVerificationData"] = .object(["rfc3161Timestamps": .array(ts)])
        bundle["verificationMaterial"] = .object(vm)
        let r = PCA.verifySigstoreBundleCore(.object(bundle), roots: roots)
        XCTAssertFalse(r.ok)
        return r.detail
    }

    func testAtMostEightTimestamps() throws {
        XCTAssertFalse(try detail(stamps: 8).contains("too many RFC 3161"), "eight are verified one by one")
        XCTAssertTrue(try detail(stamps: 9).contains("too many RFC 3161 timestamps (9, at most 8)"))
    }
}

final class SwC3AttestNvidiaRimCoverageTests: XCTestCase {
    private typealias F = StrictChainForge

    func testCdpOidScanOnTheEdges() {
        XCTAssertFalse(RIM.hasCrlDistributionPoint(AttCert(raw: [])), "shorter than the OID")
        XCTAssertFalse(RIM.hasCrlDistributionPoint(AttCert(raw: [0x06, 0x03, 0x55, 0x1d])))
        XCTAssertTrue(RIM.hasCrlDistributionPoint(AttCert(raw: RIM.CDP_OID_DER)), "exactly the OID")
        XCTAssertTrue(RIM.hasCrlDistributionPoint(AttCert(raw: [0x01] + RIM.CDP_OID_DER)))
    }

    /// A chain of only the root has no non-root certificate, so no coverage is demanded under 'all' or 'cdp'.
    func testARootOnlyChainDemandsNoCoverage() throws {
        var root = try Cert.parseDER(try F.chain().ders[2])
        root.raw += RIM.CDP_OID_DER
        let crl = AttestNvidiaRimK05Tests.crl(signer: F.rootKey)
        XCTAssertEqual(RIM.checkChainRevocation([root], [crl], F.NOW, [], .all), "")
        XCTAssertEqual(RIM.checkChainRevocation([root], [crl], F.NOW, [], .cdp), "")
    }

    func testRequireCrlForIndexBound() throws {
        func hook(_ v: JSONValue) throws -> NvidiaHook {
            try NvidiaHook(["rimRootSpkiSha256": .array([.string("ab")]), "requireCrlFor": v])
        }
        XCTAssertEqual(try hook(.array([.int(999_999)])).crlRequirement(), .indices([999_999]))
        XCTAssertThrowsError(try hook(.array([.int(1_000_000)])))
        XCTAssertThrowsError(try hook(.array([.int(1_000_001)])))
    }
}

/// Class name starts with A0 so it runs before suites whose setup builds keys with `try!`.
final class A0SwC3KeysSeedLengthTests: XCTestCase {
    func testEdSeedMustBeExactly32Bytes() throws {
        XCTAssertNoThrow(try PCAEdKey(seed: [UInt8](repeating: 7, count: 32)))
        for n in [0, 1, 31, 33, 64] {
            XCTAssertThrowsError(try PCAEdKey(seed: [UInt8](repeating: 7, count: n)), "\(n) bytes")
        }
        let k = try PCAEdKey(seed: [UInt8](repeating: 7, count: 32))
        XCTAssertEqual(k.pub.count, 32)
        XCTAssertEqual(k.seed, [UInt8](repeating: 7, count: 32))
    }
}
