import XCTest
@testable import AtlasPCAVerify

/// `policyCaveats` (packages/pca/src/policy-vm.ts:182): only what the leaf holds beyond the grant is appended, `leaf.caveats.slice(grant.caveats.length)`.
final class CaveatsK05Tests: XCTestCase {
    private func cav(_ t: String) -> JSONValue { .object(["type": .string(t)]) }

    func testOnlyTheCaveatsBeyondTheGrantAreAppended() {
        let grant: JSONValue = .object(["caveats": .array([cav("a"), cav("b")])])
        let two = JSONValue.array([cav("a"), cav("b")])
        func leaf(_ c: [JSONValue]) -> JSONValue { .array([.object(["caveats": .array(c)])]) }
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: leaf([cav("a")])), two)
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: leaf([cav("a"), cav("b")])), two)
        XCTAssertEqual(PCA.policyCaveats(grant: grant, chain: leaf([cav("a"), cav("b"), cav("c")])), JSONValue.array([cav("a"), cav("b"), cav("c")]))
    }
}
