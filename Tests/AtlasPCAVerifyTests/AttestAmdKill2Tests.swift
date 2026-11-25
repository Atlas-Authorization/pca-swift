import XCTest
import Foundation
@testable import AtlasPCAVerify

/// AMD SEV-SNP pieces pinned against the reference (hardware-sevsnp.ts / attest-amd-snp.ts): exact-width report fields, the
/// signature's reserved high bytes, the SPL decoder and the VCEK <-> reported_tcb byte map, the chain clock skew, the VCEK key
/// type, and the JavaScript BigInt() conversion of the u64 policy floors. Uses the real-silicon row of the shared corpus.
final class AttestAmdKill2Tests: XCTestCase {
    private struct Real { let report: [UInt8]; let vcek: [UInt8]; let askArk: String; let now: Int64 }

    private func real() throws -> Real {
        let doc = try AttestVectorTests.loadVectors()
        let blobs = doc.get("blobs")?.asObject ?? [:]
        let r = (doc.get("attestation_vectors")?.asArray ?? []).first { $0.get("id")?.asString == "snp-real-positive" }
        let row = AttestVectorTests.hydrate(try XCTUnwrap(r), blobs)
        XCTAssertEqual(row.get("config")?.get("family")?.asString, "genoa")
        let ev = row.get("evidence")?.asObject
        return Real(report: try XCTUnwrap(Attest.evBytes(ev, "report")), vcek: try XCTUnwrap(Attest.evBytes(ev, "vcekDer")),
                    askArk: try XCTUnwrap(Attest.evString(ev, "askArkPem")), now: Int64(try XCTUnwrap(Attest.asFinite(row.get("now")))))
    }

    private let pin = AmdVerifier.ARK_SPKI_SHA384["genoa"]!

    func testParseReportReadsEachFieldAtItsExactWidth() throws {
        var b = [UInt8](repeating: 0, count: 0x4a0)
        for i in b.indices { b[i] = UInt8(truncatingIfNeeded: i &* 31 &+ 7) | 1 } // every byte non-zero
        func le(_ o: Int, _ n: Int) -> UInt64 { (0..<n).reversed().reduce(UInt64(0)) { $0 << 8 | UInt64(b[o + $1]) } }
        let r = try AmdVerifier.parseReport(b)
        XCTAssertEqual(UInt64(r.guestSvn), le(0x004, 4))
        XCTAssertEqual(r.policy, le(0x008, 8))
        XCTAssertEqual(UInt64(r.vmpl), le(0x030, 4))
        XCTAssertEqual(UInt64(r.sigAlgo), le(0x034, 4))
        XCTAssertEqual(r.reportedTcb, le(0x180, 8))
        XCTAssertEqual(r.committedTcb, le(0x1e0, 8))
        XCTAssertEqual(r.launchTcb, le(0x1f0, 8))
        XCTAssertEqual(r.reportData, Array(b[0x050..<0x090]))
        XCTAssertEqual(r.measurement, Array(b[0x090..<0x0c0]))
        XCTAssertEqual(r.hostData, Array(b[0x0c0..<0x0e0]))
        XCTAssertEqual(r.chipID, Array(b[0x1a0..<0x1e0]))
        XCTAssertEqual(r.signed, Array(b[0..<0x2a0]))
        XCTAssertEqual(r.sigR, Array(b[0x2a0..<0x2e8]))
        XCTAssertEqual(r.sigS, Array(b[0x2e8..<0x330]))
    }

    func testSignatureRefusesNonZeroReservedHighBytes() throws {
        let x = try real()
        let c = AmdVerifier.verifyChain(x.vcek, x.askArk, pin, x.now, nil)
        XCTAssertEqual(c.reason, "")
        let point = try XCTUnwrap(c.point)
        let rep = try AmdVerifier.parseReport(x.report)
        XCTAssertTrue(AmdVerifier.verifySignature(rep, point: point))
        var r1 = rep
        r1.sigR[48] = 1 // r alone: the low 48 bytes still verify
        XCTAssertFalse(AmdVerifier.verifySignature(r1, point: point))
        var s1 = rep
        s1.sigS[71] = 1
        XCTAssertFalse(AmdVerifier.verifySignature(s1, point: point))
    }

    func testSplBindingByteMap() throws {
        let x = try real()
        let tbs = try XCTUnwrap(AmdVerifier.verifyChain(x.vcek, x.askArk, pin, x.now, nil).tbs)
        let rep = try AmdVerifier.parseReport(x.report)
        XCTAssertEqual(AmdVerifier.checkVcekReportBinding(tbs, rep), "")
        for byte in 2...5 { // reserved bytes of REPORTED_TCB: not bound (bootloader = 0, tee = 1, snp = 6, microcode = 7)
            var r = rep
            r.reportedTcb ^= UInt64(0xff) << UInt64(8 * byte)
            XCTAssertEqual(AmdVerifier.checkVcekReportBinding(tbs, r), "", "byte \(byte)")
        }
        for (byte, name) in [(0, "bootloader"), (1, "tee"), (6, "snp"), (7, "microcode")] {
            var r = rep
            r.reportedTcb ^= UInt64(0x01) << UInt64(8 * byte)
            XCTAssertTrue(IV.startsWith(AmdVerifier.checkVcekReportBinding(tbs, r), "VCEK \(name) SPL "), name)
        }
    }

    func testChainClockSkew() throws {
        let x = try real()
        XCTAssertEqual(AmdVerifier.verifyChain(x.vcek, x.askArk, pin, x.now, .int(0)).reason, "")
        XCTAssertEqual(AmdVerifier.verifyChain(x.vcek, x.askArk, pin, x.now, .double(0.5)).reason, "")
        XCTAssertEqual(AmdVerifier.verifyChain(x.vcek, x.askArk, pin, x.now, .int(-1)).reason, "clockSkewMs must be a non-negative number")
        let pems = Cert.pemBlocks(x.askArk)
        let ders = [x.vcek, try Cert.fromPEM(pems[0]).raw, try Cert.fromPEM(pems[1]).raw]
        let end = try XCTUnwrap(ders.compactMap { DER.derValidity($0).to }.min())
        // the skew widens the END of the window too (now - skew > notAfter is expired)
        XCTAssertEqual(AmdVerifier.verifyChain(x.vcek, x.askArk, pin, end + 1000, .int(5000)).reason, "")
        XCTAssertTrue(AmdVerifier.verifyChain(x.vcek, x.askArk, pin, end + 1000, nil).reason.hasSuffix("certificate has expired"))
        XCTAssertTrue(AmdVerifier.verifyChain(x.vcek, x.askArk, pin, end + 1000, .int(999)).reason.hasSuffix("certificate has expired"))
    }

    func testVcekKeyMustBeP384() throws {
        func why(_ k: CertKey) -> String {
            do { _ = try AmdVerifier.vcekPoint(k); return "ok" } catch { return (error as? AttestError)?.message ?? "?" }
        }
        XCTAssertEqual(why(CertKey(typ: "ec", curve: "prime256v1", ecName: "P-256", point: [4])), "VCEK is not EC secp384r1 (got ec/prime256v1)")
        XCTAssertEqual(why(CertKey(typ: "rsa")), "VCEK is not EC secp384r1 (got rsa/undefined)")
        XCTAssertEqual(why(CertKey(typ: "ed25519")), "VCEK is not EC secp384r1 (got ed25519/undefined)")
        XCTAssertEqual(try AmdVerifier.vcekPoint(CertKey(typ: "ec", curve: "secp384r1", ecName: "P-384", point: [4, 9])), [4, 9])
    }

    func testDecodeSpl() {
        func spl(_ v: [UInt8]) -> String {
            do { return String(try AmdVerifier.decodeSpl(v)) } catch { return (error as? AttestError)?.message ?? "?" }
        }
        XCTAssertEqual(spl([2, 1, 5]), "5")
        XCTAssertEqual(spl([2, 1, 0]), "0")
        XCTAssertEqual(spl([2, 1, 0x7f]), "127")
        XCTAssertEqual(spl([2, 2, 0, 0x80]), "128")
        XCTAssertEqual(spl([2, 2, 0, 0xff]), "255")
        XCTAssertEqual(spl([]), "is not a DER INTEGER")
        XCTAssertEqual(spl([2]), "is not a DER INTEGER")
        XCTAssertEqual(spl([2, 0]), "is not a DER INTEGER")
        XCTAssertEqual(spl([3, 1, 5]), "is not a DER INTEGER")
        XCTAssertEqual(spl([2, 0, 5]), "has a wrong-length INTEGER")
        XCTAssertEqual(spl([2, 1, 5, 0]), "has a wrong-length INTEGER")
        XCTAssertEqual(spl([2, 2, 0]), "has a wrong-length INTEGER")
        XCTAssertEqual(spl([2, 3, 0, 0x80, 1]), "has a wrong-length INTEGER")
        XCTAssertEqual(spl([2, 3, 1, 2, 3]), "has a wrong-length INTEGER")
        XCTAssertEqual(spl([2, 1, 0x80]), "is negative")
        XCTAssertEqual(spl([2, 2, 0x80, 0x80]), "is negative")
        XCTAssertEqual(spl([2, 2, 1, 0x80]), "is out of range (> 255)")
        XCTAssertEqual(spl([2, 2, 0, 0x7f]), "is a non-minimal INTEGER")
        XCTAssertEqual(spl([2, 2, 0, 0]), "is a non-minimal INTEGER")
    }

    /// BigInt(v) as JavaScript evaluates it; `above(x)` is the reference's `x < floor` on the report's u64.
    func testBigIntFloorsFollowJavaScript() throws {
        func lim(_ v: JSONValue) throws -> BigLimit { try AmdVerifier.parseJSBigInt(v) }
        XCTAssertTrue(try lim(.bool(true)).above(0))   // BigInt(true) === 1n
        XCTAssertFalse(try lim(.bool(true)).above(1))
        XCTAssertFalse(try lim(.bool(false)).above(0))
        // a negative or zero floor: no u64 report is below it
        for v: JSONValue in [.int(-1), .int(0), .double(-1), .double(0), .double(-0.0), .string("-5"), .string("-0"), .string("0"), .string(" "),
                             .string("-99999999999999999999999")] {
            XCTAssertFalse(try lim(v).above(0), "\(v)")
        }
        XCTAssertTrue(try lim(.int(1)).above(0))
        XCTAssertFalse(try lim(.int(1)).above(1))
        XCTAssertTrue(try lim(.double(1)).above(0))
        XCTAssertEqual(try lim(.double(5)).value, 5)
        XCTAssertEqual(try lim(.double(18_446_744_073_709_549_568.0)).value, 18_446_744_073_709_549_568) // the largest double below 2^64
        XCTAssertFalse(try lim(.double(18_446_744_073_709_549_568.0)).huge)
        XCTAssertTrue(try lim(.double(18_446_744_073_709_551_616.0)).huge)                                // 2^64 itself
        XCTAssertTrue(try lim(.double(18_446_744_073_709_551_616.0)).above(UInt64.max))
        XCTAssertTrue(try lim(.double(1e300)).above(UInt64.max))
        XCTAssertEqual(try lim(.string("+5")).value, 5)
        XCTAssertTrue(try lim(.string("+5")).above(4))
        XCTAssertTrue(try lim(.string("5")).above(4))
        XCTAssertEqual(try lim(.string("1")).value, 1)
        XCTAssertEqual(try lim(.string("0")).value, 0)
        XCTAssertEqual(try lim(.string("00")).value, 0)
        XCTAssertEqual(try lim(.string("07")).value, 7)
        XCTAssertEqual(try lim(.string("0x1")).value, 1)
        XCTAssertEqual(try lim(.string("0X1f")).value, 31)
        XCTAssertEqual(try lim(.string("0o17")).value, 15)
        XCTAssertEqual(try lim(.string("0O7")).value, 7)
        XCTAssertEqual(try lim(.string("0b101")).value, 5)
        XCTAssertEqual(try lim(.string("0B1")).value, 1)
        for bad in ["0x", "0o", "0b", "0o8", "0b2", "1a", "1x5", "-0x5", "+0x5", "0x-5", "+", "-", "--5", "5-", "0xg", "1 2"] {
            XCTAssertThrowsError(try lim(.string(bad)), bad)
        }
        XCTAssertThrowsError(try lim(.null))
        XCTAssertThrowsError(try lim(.double(.infinity)))
        XCTAssertThrowsError(try lim(.double(0.5)))
    }
}
