import XCTest
@testable import AtlasPCAVerify

/// The Intel SGX extension byte scan (attest-intel-tdx.ts:333-339, 363-403) and the validity failure class of the chain check (attest-intel-tdx.ts:473-475).
final class AttestIntelK05PckTests: XCTestCase {
    private let dummy = IntelForge.component(18, [1]) // an INTEGER at an arc that sets nothing

    func testIndexOfMatchesTheReference() {
        XCTAssertEqual(DcapVerifier.indexOf([1, 2], [1, 2]), 0)
        XCTAssertEqual(DcapVerifier.indexOf([9, 1, 2], [1, 2]), 1)
        XCTAssertEqual(DcapVerifier.indexOf([1, 3, 1, 2], [1, 2]), 2)
        XCTAssertEqual(DcapVerifier.indexOf([1], [2]), -1)
        XCTAssertEqual(DcapVerifier.indexOf([1], [1, 2]), -1)
        XCTAssertEqual(DcapVerifier.indexOf([1, 2], []), 0)
        XCTAssertEqual(DcapVerifier.indexOf([], []), 0)
    }

    func testFmspcOidAtOffsetZeroWithTheTcbLast() throws {
        let t = try DcapVerifier.extractPckFmspcAndTcb(IntelForge.fmspcField() + IntelForge.tcbField([IntelForge.component(17, [1, 2])]))
        XCTAssertEqual(t.fmspc, IntelForge.FMSPC)
        XCTAssertEqual(t.pcesvn, 258) // big-endian
    }

    func testTcbOidAtOffsetZero() throws {
        let t = try DcapVerifier.extractPckFmspcAndTcb(IntelForge.tcbField([IntelForge.component(17, [5])]) + IntelForge.fmspcField())
        XCTAssertEqual(t.pcesvn, 5)
    }

    func testComponentArcs() throws {
        let t = try DcapVerifier.extractPckFmspcAndTcb(IntelForge.fmspcField() + IntelForge.tcbField([
            IntelForge.component(0, [5]), IntelForge.component(1, [7]), IntelForge.component(16, [9]), IntelForge.component(17, [0]),
        ]))
        var want = [UInt8](repeating: 0, count: 16)
        want[0] = 7
        want[15] = 9
        XCTAssertEqual(t.sgx, want) // arc 0 sets nothing, unset components stay 0, exactly 16 of them
        XCTAssertEqual(t.pcesvn, 0)
    }

    func testMissingPcesvn() {
        XCTAssertEqual(IntelForge.refusal { try DcapVerifier.extractPckFmspcAndTcb(IntelForge.fmspcField() + IntelForge.tcbField([self.dummy])) },
                       "extractPckFmspcAndTcb: PCESVN not found in TCB extension")
    }

    func testTheComponentWalkReadsSixtyFiveAndStops() throws {
        let pce = IntelForge.component(17, [7])
        let at65 = IntelForge.fmspcField() + IntelForge.tcbField(Array(repeating: dummy, count: 64) + [pce])
        XCTAssertEqual(try DcapVerifier.extractPckFmspcAndTcb(at65).pcesvn, 7)
        let at66 = IntelForge.fmspcField() + IntelForge.tcbField(Array(repeating: dummy, count: 65) + [pce])
        XCTAssertEqual(IntelForge.refusal { try DcapVerifier.extractPckFmspcAndTcb(at66) }, "extractPckFmspcAndTcb: PCESVN not found in TCB extension")
    }

    func testAFailedChainIsNotOk() {
        let r = DcapVerifier.verifyPckChain("", "00", 0)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "no PEM certificates in the PCK chain")
    }

    func testValidityWindowHasNoSkewAndIsClassified() {
        let pem = StrictChainForge.chain().pem
        for now in [IntelForge.T2025 - 1, IntelForge.T2035 + 1] {
            let r = DcapVerifier.verifyPckChain(pem, "00", now)
            XCTAssertEqual(r.reason, "PCK chain certificate outside its validity period")
            XCTAssertTrue(r.validity)
        }
        for now in [IntelForge.T2025, IntelForge.T2035] {
            let r = DcapVerifier.verifyPckChain(pem, "00", now)
            XCTAssertEqual(r.reason, "Intel SGX Root CA does not match the pinned trust anchor")
            XCTAssertFalse(r.validity)
        }
    }
}
