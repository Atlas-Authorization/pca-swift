import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The reference-named factories, folds and helpers of core pca: foldV2Reasons, validateWireV2, the plan registry and executor factories, the assurance refresh, the
/// regex budget (document and request scope), the threshold constants and the adapter header and input helpers.
final class SurfaceFactoriesTests: XCTestCase {
    func testFoldV2ReasonsListsEveryFailedCheckWithAReasonOnce() {
        let out = PCA.foldV2Reasons(["core: bad", "intent: x"], [.init(name: "intent", ok: false, reason: "x"), .init(name: "session", ok: false, reason: "y"),
                                                                   .init(name: "fresh", ok: false), .init(name: "ok", ok: true, reason: "z"), .init(name: "session", ok: false, reason: "y")])
        XCTAssertEqual(out, ["core: bad", "intent: x", "session: y"])
    }

    func testValidateWireV2RefusesWhatIsNotAnObject() {
        XCTAssertEqual(PCA.validateWireV2(.string("x")), "PCActn is not an object")
        XCTAssertEqual(PCA.validateWireV2(nil), "PCActn is not an object")
        XCTAssertEqual(PCA.validateWireV2(.object(["nope": .int(1)])), "unknown field 'nope'")
    }

    func testPlanRegistryFactoryAndTheThresholdConstants() {
        _ = PCA.createPlanRegistry()
        XCTAssertEqual(PCA.VALID_THRESHOLDS, [1, 2, 3])
        XCTAssertEqual(PCA.AGENT_LEAF_SHARE_BINDING_VERSION, "2.1")
        XCTAssertEqual(PCAPqThreshold.MAX_PQ_SIGNER_ENTRIES, 256)
    }

    func testRefreshAssuranceDowngradesWhatNoLongerPasses() {
        var r = AssuranceReport()
        r.set("replay", CheckAssurance(outcome: "pass", level: "hardware"))
        r.set("bond", CheckAssurance(outcome: "unsupported", reason: "no"))
        let out = PCA.refreshAssurance(r, [(name: "replay", status: "fail"), (name: "bond", status: "pass"), (name: "audience", status: "pass")])
        XCTAssertEqual(out["replay"], CheckAssurance(outcome: "fail"))
        XCTAssertEqual(out["bond"]?.outcome, "unsupported")
        XCTAssertEqual(out["audience"], CheckAssurance(outcome: "pass"))
        XCTAssertEqual(out.names, ["replay", "bond", "audience"])
        let label = AssuranceLabel(level: "hardware", vendor: "v")
        XCTAssertEqual(PCA.assuranceLabelOf(PCA.withAssuranceLabel("hook", label)), label)
        XCTAssertNil(PCA.assuranceLabelOf("plain"))
    }

    func testARequestBudgetBoundsEveryDocumentOpenedInsideIt() {
        let req = PCARegexBudget.request(source: "client-1")
        var granted = 0
        req.run {
            XCTAssertEqual(PCARegexBudget.currentRegexSource(), "client-1")
            for _ in 0..<5 {
                let doc = PCARegexBudget() // chained to the open request scope
                for _ in 0..<64 where doc.charge("a+", subjectLen: 1) { granted += 1 }
                XCTAssertFalse(doc.charge("a+", subjectLen: 1)) // the document budget is spent
            }
        }
        XCTAssertEqual(granted, PCARegexBudget.MAX_REGEX_EVALUATIONS_PER_DOCUMENT * PCARegexBudget.REGEX_REQUEST_SCALE)
        XCTAssertGreaterThan(req.refusals, 0)
        XCTAssertNil(PCARegexBudget.currentRegexSource())
        // outside any scope a charge goes to a fresh single-use budget; an unsafe pattern is refused
        XCTAssertTrue(PCARegexBudget.chargeRegex("a+", subjectLen: 1))
        XCTAssertFalse(PCARegexBudget.chargeRegex("(a+)+", subjectLen: 1))
    }

    func testWithRegexBudgetJoinsAnOpenDocument() {
        let doc = PCARegexBudget()
        PCARegexBudget.withRegexBudget(doc) {
            XCTAssertTrue(PCARegexBudget.chargeRegex("a+", subjectLen: 1))
            PCARegexBudget.withRegexBudget { XCTAssertTrue(PCARegexBudget.chargeRegex("b+", subjectLen: 1)) }
        }
        XCTAssertEqual(doc.evaluations, 2)
        XCTAssertEqual(PCARegexBudget.regexRefusals(), 0)
    }

    func testProvenanceHeadersAndTheStrictHeaderDecoder() throws {
        XCTAssertTrue(PCAAdapters.provenanceHeaders(nil).isEmpty)
        let small = PCAAdapters.provenanceHeaders(.object(["a": .int(1)]))
        XCTAssertNotNil(small[PCA.PROV_HEADER])
        let big = PCAAdapters.provenanceHeaders(.object(["x": .string(String(repeating: "q", count: PCAIssue.PROVENANCE_HEADER_MAX))]))
        XCTAssertTrue(big.isEmpty) // a bundle too large for a header goes in the body
        let h = Base64URLStrict.encode(Canonical.utf8("{\"a\":1}"))
        XCTAssertEqual(try PCAAdapters.decodePcaHeader(h), "{\"a\":1}")
        for bad in ["", "AA==", "a b", "+/+/"] {
            XCTAssertThrowsError(try PCAAdapters.decodePcaHeader(bad)) { XCTAssertEqual(($0 as? PcaHeaderError)?.code, "invalid_pca_header") }
        }
    }

    func testMessageSegmentsFollowTheConversationsRoles() {
        XCTAssertTrue(PCAAdapters.messageSegments(.object(["role": .string("assistant"), "content": .string("hi")])).isEmpty)
        let user = PCAAdapters.messageSegments(.object(["role": .string("user"), "content": .array([
            .object(["type": .string("text"), "text": .string("a")]), .object(["type": .string("text"), "text": .string("b")]),
            .object(["type": .string("tool_result"), "toolName": .string("t"), "content": .string("out")])])]))
        XCTAssertEqual(user, [PCAMessageSegment(origin: "principal", source: "user", content: .string("a\nb")), PCAMessageSegment(origin: "tool", source: "t", content: .string("out"))])
        let tool = PCAAdapters.messageSegments(.object(["role": .string("tool"), "name": .string("search"), "content": .string("r")]))
        XCTAssertEqual(tool, [PCAMessageSegment(origin: "tool", source: "search", content: .string("r"))])
    }
}
