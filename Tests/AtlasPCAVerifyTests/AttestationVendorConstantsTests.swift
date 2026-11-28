import XCTest
@testable import AtlasPCAVerify

final class AttestationVendorConstantsTests: XCTestCase {
    func testTheExportedConstantsAreTheOnesTheVerifiersUse() {
        XCTAssertEqual(AttestationVendors.AMD_ARK_SPKI_SHA384, AmdVerifier.ARK_SPKI_SHA384)
        XCTAssertEqual(AttestationVendors.INTEL_SGX_ROOT_CA_SPKI_SHA256, DcapVerifier.INTEL_ROOT_SPKI_SHA256)
        XCTAssertEqual(AttestationVendors.DEFAULT_ACCEPTED_STATUSES, IntelCollateral.DEFAULT_ACCEPTED)
        XCTAssertEqual(AttestationVendors.GCP_CS_DEFAULT_ISSUER, "https://confidentialcomputing.googleapis.com")
    }

    func testTeeTypeOfHwModel() {
        XCTAssertEqual(AttestationVendors.teeTypeOfHwModel("GCP_AMD_SEV_SNP"), "sev-snp")
        XCTAssertEqual(AttestationVendors.teeTypeOfHwModel("GCP_INTEL_TDX"), "tdx")
        XCTAssertEqual(AttestationVendors.teeTypeOfHwModel("gcp_amd_sev_future"), "sev-snp")
        XCTAssertNil(AttestationVendors.teeTypeOfHwModel("ARM_CCA"))
    }

    func testPemToDer() throws {
        XCTAssertEqual(try AttestationVendors.pemToDer("junk\n-----BEGIN CERTIFICATE-----\nAAEC\n -----END CERTIFICATE-----\n"), [0, 1, 2])
        XCTAssertThrowsError(try AttestationVendors.pemToDer("-----BEGIN PUBLIC KEY-----\nAAEC\n-----END PUBLIC KEY-----"))
    }
}
