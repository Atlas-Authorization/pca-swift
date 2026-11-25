import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Hash-suite agility and the named limits of the pca_grant / pca_need protocols.
final class HashSuiteTests: XCTestCase {
    func testDispatchAndGuards() throws {
        XCTAssertEqual(PCA.DEFAULT_HASH_SUITE, "sha256")
        XCTAssertEqual(try PCA.hashWithSuite(Array("abc".utf8)), Canonical.sha256(Array("abc".utf8)))
        XCTAssertEqual(try PCADurableState.hex(PCA.hashWithSuite(Array("abc".utf8), suite: "sha384")),
                       "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
        XCTAssertThrowsError(try PCA.hashWithSuite([], suite: "sha512"))
        XCTAssertTrue(PCA.isHashSuite(.string("sha384")))
        XCTAssertFalse(PCA.isHashSuite(.string("sha512")))
        XCTAssertFalse(PCA.isHashSuite(nil))
        XCTAssertEqual(PCA.HASH_LEN["sha384"], 48)
    }

    func testBase64UrlLengths() {
        XCTAssertEqual([1, 2, 3, 32, 48, 64].map { PCA.b64uLen($0) }, [2, 3, 4, 43, 64, 86])
        XCTAssertTrue(PCA.isCanonicalB64u(.string(Base64URLStrict.encode([UInt8](repeating: 9, count: 32))), length: 32))
        XCTAssertFalse(PCA.isCanonicalB64u(.string("AB=="), length: nil))
        XCTAssertFalse(PCA.isCanonicalB64u(.string(Base64URLStrict.encode([1, 2, 3])), length: 32))
        XCTAssertFalse(PCA.isCanonicalB64u(.int(1)))
    }

    func testProtocolConstants() {
        XCTAssertEqual(PCA.PCA_GRANT_MAX_DETAILS, 16)
        XCTAssertEqual(PCA.PCA_GRANT_MAX_CHAIN_LEN, 16)
        XCTAssertEqual(PCA.PCA_NEED_DOMAIN, "atlas-pca/need/v1")
        XCTAssertEqual(PCA.pcaChainDigest(["a", "b"]), PcaGrant.chainDigest(["a", "b"]))
        XCTAssertEqual(PCA.PCACTN_DEFAULT_TTL_MS, 1_200_000)
        XCTAssertEqual(PCAReplayGuard.REPLAY_MIN_RETENTION_MS, 3_720_000)
    }
}
