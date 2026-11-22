import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the Policy VM decision (`decide`) against the reference. Every grant and chain in the corpus is signed by the
/// reference from label-derived keys (the corpus carries no key material).
final class RefPolicyVmTests: XCTestCase {
    static let file = "ref-decide-java.json.gz"

    func testDecide() throws {
        try K042.requireCovers(["PolicyVm", "Risk", "Authorize", "CaveatLang", "Capability", "Predicates", "Caveats"])
        let d = Base.Diffs()
        try Base.each(Self.file, ["decide"]) { c in
            // the reference computes a non-numeric budget with NaN and still releases; the native refuses it (fail closed)
            if let b = c.arg(0)?.get("budget"), let bo = b.asObject, ToolSchema.fin(bo["B"]) == nil || ToolSchema.fin(bo["tau"]) == nil {
                d.skip("native stricter: a budget whose B or tau is not a finite number"); return
            }
            let got = Base.run({ ($0 as? JSError)?.code }) { try PCAPolicyVm.decide(c.arg(0) ?? .null) }
            d.add(c, Base.diff(c, got))
        }
        d.finish(200)
    }

    /// How a verifier assembles the `decide` input from a PCActn and its own context, and the decision over that input: every case of the reference corpus.
    func testDeriveDecideInputAndDeriveThenDecide() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-decide-derive.json.gz") { c in
            let p = c.arg(0) ?? .null, ctx = c.arg(1) ?? .null
            let code: (Error) -> String? = { ($0 as? JSError)?.code }
            switch c.fn {
            case "deriveDecideInput": d.add(c, Base.diff(c, Base.run(code) { try PCAPolicyVm.deriveDecideInput(p, ctx) }))
            case "deriveThenDecide":
                d.add(c, Base.diff(c, Base.run(code) {
                    let input = try PCAPolicyVm.deriveDecideInput(p, ctx)
                    return .object(["input": input, "decision": try PCAPolicyVm.decide(input)])
                }))
            default: XCTFail("unhandled fn \(c.fn)")
            }
        }
        XCTAssertEqual(n, 224)
        d.finish(224)
    }

    func testDeriveRefusesAnArtifactWithoutAPlan() {
        let ctx: JSONValue = .object(["grant": grantOnly()])
        XCTAssertThrowsError(try PCAPolicyVm.deriveDecideInput(.object(["action": .object([:])]), ctx))
        XCTAssertThrowsError(try PCAPolicyVm.deriveDecideInput(.object(["plan": .null]), ctx))
        XCTAssertNoThrow(try PCAPolicyVm.deriveDecideInput(.object(["plan": .int(5)]), ctx))
        // an array in place of the grant passes the presence check (it is an object to the reference)
        XCTAssertNoThrow(try PCAPolicyVm.deriveDecideInput(.object(["plan": .object([:])]), .object(["grant": .array([])])))
    }

    private func grantOnly() -> JSONValue {
        .object(["id": .string("g")])
    }

    func testDeriveRequiresStoredGrant() {
        XCTAssertThrowsError(try PCAPolicyVm.deriveDecideInput(.object([:]), .object([:]))) { XCTAssertEqual(($0 as? JSError)?.code, "grant_required") }
        XCTAssertThrowsError(try PCAPolicyVm.deriveDecideInput(.object([:]), .object(["grant": .null]))) { XCTAssertEqual(($0 as? JSError)?.code, "grant_required") }
    }

    func testDeriveBuildsTheInput() throws {
        let p: JSONValue = .object(["action": .object(["verb": .string("read"), "resource": .string("doc:1")]),
                                    "plan": .object(["node_id": .string("n")]), "cap_chain": .array([.object(["x": .int(1)])])])
        let g = grantOnly()
        let o = try PCAPolicyVm.deriveDecideInput(p, .object(["grant": g, "risk": .object([:]), "budget": .object(["B": .int(1), "tau": .int(0)]), "now": .int(5)]))
        XCTAssertEqual(o.get("trustedRoot"), g)
        XCTAssertEqual(o.get("nodeId"), .string("n"))
        XCTAssertEqual(o.get("chain"), .array([.object(["x": .int(1)])]))
        XCTAssertEqual(o.get("action")?.get("action")?.get("params"), .object([:]))
        XCTAssertEqual(o.get("action")?.get("action")?.get("verb"), .string("read"))
    }

    func testUnverifiedGrantIsDenied() throws {
        let r = try PCAPolicyVm.decide(.object(["grant": .object(["caveats": .array([])]), "now": .int(1), "budget": .object(["B": .int(1), "tau": .int(0)])]))
        XCTAssertEqual(r.get("releaseGuardianShare"), .bool(false))
        XCTAssertEqual(r.get("needStepUp"), .bool(true))
    }
}
