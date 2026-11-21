import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCARag (ACL extraction, policy compilation, the principal of a PCActn and the fail-closed retrieval filter with its
/// decision digest) against the reference. The member order of an OpenFGA model's `relations` objects (it fixes the order of the translation
/// report lines) is scanned from the corpus text and handed to the translator as its KeyOrder, as the policy-bridge replay does.
final class RefRagTests: XCTestCase {
    static let file = "ref-rag.json.gz"

    func testRag() throws {
        try K042.requireCovers(["Rag", "PolicyBridge", "Predicates", "JSLoose"])
        let orders = RefComplianceTests.scanOrders([UInt8](try K042.bytes(Self.file)))
        let order: PCAPolicyBridge.KeyOrder = { o in orders[RefComplianceTests.sig(o.keys.map { $0.s })] ?? [] }
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let got: BaseGot
            switch c.fn {
            case "aclsFromMetadata": got = .value(.array(PCARag.aclsFromMetadata(c.arg(0), c.arg(1))))
            case "compilePolicy": got = Ref.v { try PCARag.compilePolicy(c.arg(0), order: order) }
            case "principalFromPCActn": got = Ref.v { try PCARag.principalFromPCActn(c.arg(0), c.arg(1)) }
            case "filterDocuments":
                let cands = c.arg(1)?.asArray
                got = Ref.v {
                    let r = try PCARag.filterDocuments(principal: c.arg(0), candidates: cands, policy: c.arg(2), order: order)
                    return .object(["documents": .array(r.documents), "decision": r.decision])
                }
            default: d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(300)
    }

    func testAnUndecidableDocumentIsDropped() throws {
        let pred: JSONValue = .object(["verb": .string("can_view"), "where": .array([.object(["field": .string("subject.group"), "op": .string("eq"), "value": .string("g1")])])])
        let doc: JSONValue = .object(["id": .string("d"), "acl": .object(["relation": .string("can_view"), "object": .string("document:d")])])
        let ok = try PCARag.filterDocuments(principal: .object(["id": .string("u"), "attributes": .object(["group": .string("g1")])]), candidates: [doc], policy: .array([pred]))
        XCTAssertEqual(ok.decision.get("allowedIds"), .array([.string("d")]))
        let no = try PCARag.filterDocuments(principal: .object(["id": .string("u"), "attributes": .object(["group": .string("g2")])]), candidates: [doc], policy: .array([pred]))
        XCTAssertEqual(no.decision.get("droppedIds"), .array([.string("d")]))
        // no policy, no ACL and no principal all drop everything
        XCTAssertTrue(try PCARag.filterDocuments(principal: .string("u"), candidates: [doc], policy: nil).documents.isEmpty)
        XCTAssertTrue(try PCARag.filterDocuments(principal: .string("u"), candidates: [.object(["id": .string("x")])], policy: .array([pred])).documents.isEmpty)
        XCTAssertTrue(try PCARag.filterDocuments(principal: nil, candidates: [doc], policy: .array([pred])).documents.isEmpty)
    }
}
