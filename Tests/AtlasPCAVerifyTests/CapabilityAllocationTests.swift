import XCTest
@testable import AtlasPCAVerify

/// Carried budget allocations are monotone down the chain, in the chain check (capability.ts:174-193, :714).
final class CapabilityAllocationTests: XCTestCase {
    private func ba(_ limit: JSONValue?) -> JSONValue {
        var o: JObject = ["type": .string("budget_alloc")]
        if let l = limit { o["limit"] = l }
        return .object(o)
    }
    private func err(_ a: [JSONValue]) -> String? { Capability.allocationsMonotoneError(a) }

    func testAllocationsMonotone() {
        let widen = "budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)"
        XCTAssertNil(err([]))
        XCTAssertNil(err([.object(["type": .string("other")]), .int(3)]))
        XCTAssertNil(err([ba(.int(10))]))
        XCTAssertNil(err([ba(.int(10)), ba(.int(10))]))
        XCTAssertNil(err([ba(.int(100)), ba(.int(10)), ba(.int(0))]))
        XCTAssertEqual(err([ba(.int(10)), ba(.int(100))]), widen)
        // the index counts every caveat; the last allocation is the bound, not the first
        XCTAssertEqual(err([ba(.int(100)), ba(.int(10)), .object(["type": .string("x")]), ba(.int(50))]),
                       "budget_alloc caveat 3: allocation 50 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)")
        XCTAssertEqual(err([ba(.double(0.5)), ba(.double(1.5))]),
                       "budget_alloc caveat 1: allocation 1.5 widens the parent's carried allocation 0.5 (monotone: a child can only allocate <= its parent)")
        let bads: [JSONValue?] = [nil, .some(.string("1")), .some(.int(-1)), .some(.double(-0.5)), .some(.null)]
        for bad in bads {
            XCTAssertEqual(err([ba(bad)]), "budget_alloc caveat 0: limit must be a finite number >= 0")
        }
    }

    func testTheChainCheckRefusesAWideningAllocation() {
        let wide = V2F.cap(issuer: V2F.principal, holder: V2F.agent, caveats: [ba(.int(10)), ba(.int(100))])
        XCTAssertEqual(Capability.verifyChain([wide], expectedRootIssuer: wide.get("issuer")?.asString),
                       "budget_alloc caveat 1: allocation 100 widens the parent's carried allocation 10 (monotone: a child can only allocate <= its parent)")
        let fine = V2F.cap(issuer: V2F.principal, holder: V2F.agent, caveats: [ba(.int(100)), ba(.int(10))])
        XCTAssertNil(Capability.verifyChain([fine], expectedRootIssuer: fine.get("issuer")?.asString))
    }
}
