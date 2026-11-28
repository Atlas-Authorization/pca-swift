import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the K3Sig.swift (default string cap, nil equality) and Assurance.swift (label of a revocation hook) survivors of group 5.
final class S2G5K3SigAssuranceKillTests: XCTestCase {
    func testDefaultStringCapIs512() {
        XCTAssertNotNil(K3Sig.str(.string(String(repeating: "a", count: 512))), "line 13: 512 units are allowed by default")
        XCTAssertNil(K3Sig.str(.string(String(repeating: "a", count: 513))), "line 13: 513 are not")
        XCTAssertNil(K3Sig.str(.string("")))
        XCTAssertNil(K3Sig.str(.int(1)))
        XCTAssertNotNil(K3Sig.str(.string("ab"), 2))
        XCTAssertNil(K3Sig.str(.string("abc"), 2))
    }

    func testNilIsNeverEqual() {
        XCTAssertFalse(K3Sig.eq(nil, "x"), "line 20")
        XCTAssertFalse(K3Sig.eq(nil, ""))
        XCTAssertTrue(K3Sig.eq("x", "x"))
        XCTAssertFalse(K3Sig.eq("x", "y"))
    }

    /// A labelled revocation hook (neither attestation, zk nor a threshold hook) copies level, vendor and awaiting_audit (line 299).
    func testARevocationHooksLabelIsReported() {
        let hook = PCA.withAssuranceLabel("h", AssuranceLabel(level: "lvl", vendor: "v", awaitingAudit: true))
        var hooks = AssuranceHooks()
        hooks.revocation = hook
        let r = PCA.buildAssuranceReport(AssuranceSources(checks: [NamedStatus(name: "revocation", status: "pass")], hooks: hooks))
        XCTAssertEqual(r["revocation"]?.level, "lvl")
        XCTAssertEqual(r["revocation"]?.vendor, "v")
        XCTAssertEqual(r["revocation"]?.awaitingAudit, true)
        var plain = AssuranceHooks()
        plain.revocation = PCA.withAssuranceLabel("h", AssuranceLabel(level: "lvl"))
        let r2 = PCA.buildAssuranceReport(AssuranceSources(checks: [NamedStatus(name: "revocation", status: "pass")], hooks: plain))
        XCTAssertEqual(r2["revocation"]?.awaitingAudit, false)
    }
}

/// ArgProvenance.swift: the recorder is safe for concurrent use (lines 546, 565, 581).
final class S2G5ProvenanceRecorderKillTests: XCTestCase {
    func testConcurrentSegmentsAreAllRecordedInOrder() throws {
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 7, count: 32), now: { 1_000 })
        DispatchQueue.concurrentPerform(iterations: 8) { i in
            for j in 0..<10 { _ = try? r.retrieval("src\(i)-\(j)", "content \(i) \(j)") }
        }
        let chain = r.receipts()
        XCTAssertEqual(chain.count, 80)
        XCTAssertEqual(chain.map { $0.get("seq")?.safeInt ?? -1 }, (0..<80).map { Int64($0) }, "no two appends saw the same chain head")
    }
}
