import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAMcp against the reference (@atlasauth/pca-mcp): the WWW-Authenticate parser and step-up planner, the RFC 9207
/// `iss` table, the client conformance matrix, the tool-result proof meta, the `PCA-Action` header, and the v1 action-schema draft from an MCP
/// tool list with the developer's decisions and the closed-world tool-call check. (withPCA and pcaFetch need a live agent and transport.)
final class RefMcpTests: XCTestCase {
    static let file = "ref-mcp.json.gz"

    func testMcp() throws {
        try K042.requireCovers(["Mcp", "A2a", "ActionSchema", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            if Base.negZero(.array(c.args)) { d.skip("negative zero argument"); return }
            let got: BaseGot
            switch c.fn {
            case "constants":
                got = .value(.object(["MCP_CLIENT_REVISIONS": .array(PCAMcp.MCP_CLIENT_REVISIONS.map { .string($0) }), "MCP_AUTH_CLIENT_ROWS": .array(PCAMcp.mcpAuthClientRows())]))
            case "parseChallenges": got = .value(.array(PCAMcp.parseChallenges(a0)))
            case "pcaNeedProblem": got = .value(Base.opt(PCAMcp.pcaNeedProblem(a0)))
            case "planStepUp": got = Ref.v { try PCAMcp.planStepUp(a0, a1, a2) }
            case "checkAuthorizationResponseIss": got = Ref.v { try PCAMcp.checkAuthorizationResponseIss(a0) }
            case "guardToolResult": got = Ref.v { try PCAMcp.guardToolResult(a0, a1) }
            case "pcaHeaders":
                guard let s = a0?.asString else { d.skip("pcaHeaders: non-string"); return }
                got = .value(.object(Dictionary(uniqueKeysWithValues: PCAMcp.pcaHeaders(s).map { (JKey($0.key), JSONValue.string($0.value)) })))
            case "draftActionSchemaFromMcp": got = Ref.v { try PCAMcp.draftActionSchemaFromMcp(a0, a1) }
            case "applySchemaDecisions": got = Ref.v { try PCAMcp.applySchemaDecisions(a0, a1) }
            case "verbOfTool": got = Ref.v { try PCAMcp.verbOfTool(a0, a1) ?? .null }
            case "conformToolCall": got = Ref.v { try PCAMcp.conformToolCall(a0, a1, a2) }
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(2400)
    }

    func testStepUpNeverLoops() throws {
        let h: JSONValue = .string("Bearer error=\"insufficient_scope\", scope=\"a b\"")
        let first = try PCAMcp.planStepUp(.int(403), h, .object(["requested": .array([]), "attempts": .int(0)]))
        XCTAssertEqual(first.get("action"), .string("scope"))
        // the same challenge again adds nothing: give up instead of asking forever
        let again = try PCAMcp.planStepUp(.int(403), h, .object(["requested": first.get("scopes") ?? .null, "attempts": first.get("attempts") ?? .null]))
        XCTAssertEqual(again.get("reason"), .string("no_new_scope"))
        let limit = try PCAMcp.planStepUp(.int(403), h, .object(["requested": .array([]), "attempts": .int(3)]))
        XCTAssertEqual(limit.get("reason"), .string("retry_limit"))
    }

    func testIssTableRefusesWithoutRecordedIssuer() throws {
        XCTAssertEqual(try PCAMcp.checkAuthorizationResponseIss(.object(["iss": .string("https://as")])).get("reason"), .string("no_recorded_issuer"))
        XCTAssertEqual(try PCAMcp.checkAuthorizationResponseIss(.object(["recordedIssuer": .string("https://as"), "iss": .string("https://as/")])).get("reason"), .string("iss_mismatch"))
    }
}
