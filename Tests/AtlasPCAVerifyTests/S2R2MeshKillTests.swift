import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Mesh path bounds and attenuation (packages/pca/src/mesh.ts: validConsistency / validInclusion path <= 128, narrows).
final class S2R2MeshKillTests: XCTestCase {
    typealias J = JSONValue

    private func path(_ n: Int) -> JSONValue { J.array(Array(repeating: J.string("x"), count: n)) }

    func testPathBoundIs128() {
        XCTAssertEqual(Mesh.MAX_PATH, 128)
        func cons(_ n: Int) -> JSONValue { J.object(["oldSize": J.int(0), "newSize": J.int(0), "path": path(n)]) }
        func incl(_ n: Int) -> JSONValue { J.object(["index": J.int(0), "size": J.int(1), "path": path(n)]) }
        XCTAssertNotNil(Mesh.validConsistency(cons(128)), "line 42: 128 entries are accepted")
        XCTAssertNil(Mesh.validConsistency(cons(129)), "line 42: 129 entries are refused")
        XCTAssertNotNil(Mesh.validInclusion(incl(128)), "line 48: 128 entries are accepted")
        XCTAssertNil(Mesh.validInclusion(incl(129)), "line 48: 129 entries are refused")
    }

    private func auth() -> Mesh.Authority { Mesh.Authority() }

    func testNarrowsActionsAudienceAmountExpiryHops() {
        // nothing constrained in the parent: anything narrows
        XCTAssertTrue(Mesh.narrows(auth(), auth()))

        var pa = auth(); pa.hasAct = true; pa.actions = ["a", "b"]
        var ok = auth(); ok.hasAct = true; ok.actions = ["a"]
        var wide = auth(); wide.hasAct = true; wide.actions = ["a", "c"]
        XCTAssertTrue(Mesh.narrows(ok, pa))
        XCTAssertFalse(Mesh.narrows(auth(), pa), "line 144: a child with no scope widens a scoped parent")
        XCTAssertFalse(Mesh.narrows(wide, pa), "line 144: a child scope outside the parent widens it")

        var pd = auth(); pd.hasAud = true; pd.audience = ["d1", "d2"]
        var okd = auth(); okd.hasAud = true; okd.audience = ["d1"]
        var wided = auth(); wided.hasAud = true; wided.audience = ["d1", "d3"]
        XCTAssertTrue(Mesh.narrows(okd, pd))
        XCTAssertFalse(Mesh.narrows(auth(), pd), "line 145: no audience widens")
        XCTAssertFalse(Mesh.narrows(wided, pd), "line 145: audience outside the parent widens")

        var pm = auth(); pm.hasAmount = true; pm.maxAmount = 10
        var eq = auth(); eq.hasAmount = true; eq.maxAmount = 10
        var big = auth(); big.hasAmount = true; big.maxAmount = 11
        XCTAssertTrue(Mesh.narrows(eq, pm))
        XCTAssertFalse(Mesh.narrows(auth(), pm), "line 146: no ceiling widens")
        XCTAssertFalse(Mesh.narrows(big, pm), "line 146: a higher ceiling widens")

        var pe = auth(); pe.hasExp = true; pe.expiresAt = 100
        var eqe = auth(); eqe.hasExp = true; eqe.expiresAt = 100
        var late = auth(); late.hasExp = true; late.expiresAt = 101
        XCTAssertTrue(Mesh.narrows(eqe, pe))
        XCTAssertFalse(Mesh.narrows(auth(), pe), "line 147: no expiry widens")
        XCTAssertFalse(Mesh.narrows(late, pe), "line 147: a later expiry widens")

        var ph = auth(); ph.hasHops = true; ph.maxHops = 3
        var eqh = auth(); eqh.hasHops = true; eqh.maxHops = 3
        var more = auth(); more.hasHops = true; more.maxHops = 4
        XCTAssertTrue(Mesh.narrows(eqh, ph))
        XCTAssertFalse(Mesh.narrows(auth(), ph), "no max_hops widens")
        XCTAssertFalse(Mesh.narrows(more, ph), "more hops widens")
    }
}
