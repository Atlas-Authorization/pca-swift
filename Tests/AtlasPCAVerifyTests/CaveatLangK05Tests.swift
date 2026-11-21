import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Character classes, clock range and hop attribution of the caveat language, against packages/pca/src/caveat-lang.ts.
final class CaveatLangK05Tests: XCTestCase {
    func testARefusalSpendsNothing() {
        let v = PCA.reserveMaxUses(store: MemoryStateStore(), bound: [], now: Int64.max)
        XCTAssertFalse(v.ok)
        XCTAssertEqual(v.spent, 0)
    }

    func testClockRange() {
        XCTAssertTrue(PCA.k1ClockOk(Canonical.MAX_SAFE))
        XCTAssertFalse(PCA.k1ClockOk(Canonical.MAX_SAFE + 1))
        XCTAssertTrue(PCA.k1ClockOk(-Canonical.MAX_SAFE))
        XCTAssertFalse(PCA.k1ClockOk(-Canonical.MAX_SAFE - 1))
    }

    func testIdCharacters() {
        for s in ["a", "z", "0", "9", "az", "a9", "a_b", "a.b", "a-b"] { XCTAssertTrue(PCA.k1IdOk(s), s) }
        for s in ["", "A", "_a", ".a", "-a", "{", "/", ":", "aZ"] { XCTAssertFalse(PCA.k1IdOk(s), s) }
    }

    func testSpiffeCharacters() {
        func ok(_ s: String) -> Bool { PCA.spiffeIdError(s) == nil }
        XCTAssertTrue(ok("spiffe://a9"))
        XCTAssertTrue(ok("spiffe://a/Z"))
        XCTAssertTrue(ok("spiffe://a/9"))
        XCTAssertFalse(ok("spiffe://a:"))
        XCTAssertFalse(ok("spiffe://a/["))
    }

    func testAHopWithoutCaveatsIntroducesNone() {
        let sealed: JSONValue = .object(["type": .string("sealed")])
        let bare: JSONValue = .object(["id": .string("r")])
        let leaf: JSONValue = .object(["id": .string("l"), "caveats": .array([sealed])])
        XCTAssertEqual(PCA.boundCaveats(grant: bare, chain: .array([bare, leaf]))?.map { $0.hop }, [1])
    }

    func testIsK1Caveat() {
        XCTAssertFalse(PCA.isK1Caveat(nil))
        XCTAssertFalse(PCA.isK1Caveat(.int(1)))
        XCTAssertFalse(PCA.isK1Caveat(.object([:])))
        XCTAssertFalse(PCA.isK1Caveat(.object(["type": .string("max_spend")])))
        XCTAssertTrue(PCA.isK1Caveat(.object(["type": .string("sealed")])))
    }

    func testAnUnknownClaimOpNeverHolds() {
        let r: JSONValue = .object(["claim": .string("c"), "op": .string("nope"), "value": .int(1)])
        XCTAssertFalse(PCA.claimHolds(r, ["c": .int(1)]))
    }

    func testNarrowPqPinNeedsTheLeafsCommitment() {
        let n: JObject = ["pq_pk": .string("pk")]
        let committed: JSONValue = .object(["holder_pq": .string(Capability.holderPqCommitment("pk"))])
        XCTAssertEqual(PCA.narrowPqPin(n, committed), "pk")
        XCTAssertNil(PCA.narrowPqPin(n, .object(["holder_pq": .string("other")])))
        XCTAssertNil(PCA.narrowPqPin(n, .object([:])))
        XCTAssertNil(PCA.narrowPqPin([:], committed))
    }

    func testSpiffeBound() {
        let id: JSONValue = .object(["type": .string("spiffe_bound"), "spiffe_id": .string("spiffe://a/b")])
        let prefix: JSONValue = .object(["type": .string("spiffe_bound"), "spiffe_prefix": .string("spiffe://a/b")])
        XCTAssertTrue(PCA.spiffeSatisfied(id, "spiffe://a/b"))
        XCTAssertFalse(PCA.spiffeSatisfied(id, "spiffe://a/b/c"))
        XCTAssertTrue(PCA.spiffeSatisfied(prefix, "spiffe://a/b"))
        XCTAssertTrue(PCA.spiffeSatisfied(prefix, "spiffe://a/b/c"))
        XCTAssertFalse(PCA.spiffeSatisfied(prefix, "spiffe://a/bc"))
        XCTAssertFalse(PCA.spiffeSatisfied(prefix, nil))
        XCTAssertFalse(PCA.spiffeSatisfied(prefix, "not-spiffe"))
        XCTAssertFalse(PCA.spiffeSatisfied(.object(["type": .string("spiffe_bound")]), "spiffe://a/b"))
    }
}
