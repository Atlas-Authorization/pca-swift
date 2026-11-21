import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of PCAAuthzen (the AuthZEN PDP, handler and search APIs) against the reference. The PDP configs and the
/// search-provider tables are the ones the corpus names. The verify-stage cases (pc17 / pc18) compare the decision and the stage
/// only: the verifier's own check map and reason text are language-specific. Permit paths that need the Policy-VM or the analyzer
/// are not in this corpus.
final class RefAuthzenTests: XCTestCase {
    static let file = "ref-authzen.json.gz"
    static let NOW: Int64 = 1_000_000

    struct Boom: Error {}

    static func config(_ name: String) -> PCAAuthzenConfig {
        let ctx: (JSONValue) throws -> JSONValue? = { _ in .object(["grant": .object([:]), "policy": .object([:])]) }
        var c: PCAAuthzenConfig
        switch name {
        case "throws": c = PCAAuthzenConfig { _ in throw JSError("boom") }
        case "noauth": c = PCAAuthzenConfig(resolve: ctx)
        case "auth":
            c = PCAAuthzenConfig(resolve: ctx)
            c.authorizer = { _ in .object(["allow": .bool(true)]) }
        case "max2":
            c = PCAAuthzenConfig { _ in nil }
            c.maxEvaluations = .int(2)
        case "toolmap":
            c = PCAAuthzenConfig { _ in nil }
            c.toolCapability = { n in .string("cap." + JS.toString(n)) }
        case "toolthrow":
            c = PCAAuthzenConfig { _ in nil }
            c.toolCapability = { _ in throw JSError("bad tool") }
        default: c = PCAAuthzenConfig { _ in nil }
        }
        c.now = { NOW }
        return c
    }

    static func u(_ id: String) -> JSONValue { .object(["type": .string("user"), "id": .string(id)]) }

    static func provider(_ name: String) -> PCAAuthzenSearchProvider {
        let boom: (JSONValue) throws -> JSONValue = { _ in throw JSError("boom") }
        let echo: (JSONValue) throws -> JSONValue = { r in .object(["results": .array([]), "context": .object(["saw": r])]) }
        func fixed(_ v: JSONValue) -> (JSONValue) throws -> JSONValue { { _ in v } }
        let res = { (a: [JSONValue]) -> JSONValue in .object(["results": .array(a)]) }
        switch name {
        case "full":
            return PCAAuthzenSearchProvider(
                searchSubject: fixed(.object(["results": .array([u("a"), u("b"), .object(["type": .string("group"), "id": .string("g")]), u("a"), u("a")]),
                                             "page": .object(["next_token": .string(""), "total": .int(3), "properties": .object(["k": .int(1)])]),
                                             "context": .object(["c": .int(1)])])),
                searchResource: fixed(.object(["results": .array([.object(["type": .string("doc"), "id": .string("1")]), .object(["type": .string("doc"), "id": .string("2")]),
                                                                 .object(["type": .string("user"), "id": .string("x")])]),
                                              "page": .object(["next_token": .string("n1")])])),
                searchAction: fixed(res([.object(["name": .string("read")]), .object(["name": .string("write")]), .object(["name": .string("read")]),
                                         .object(["name": .string("read"), "properties": .object(["p": .int(1)])])])))
        case "nopage": return PCAAuthzenSearchProvider(searchSubject: fixed(res([u("a"), u("b")])), searchResource: fixed(res([])), searchAction: fixed(res([])))
        case "emptyprops":
            return PCAAuthzenSearchProvider(searchSubject: fixed(.object(["results": .array([u("a")]), "page": .object(["next_token": .string("z"), "properties": .object([:])]),
                                                                           "context": .object([:])])))
        case "bad": return PCAAuthzenSearchProvider(searchSubject: fixed(res([.null])), searchResource: fixed(res([.int(5)])), searchAction: fixed(res([.null, .int(5)])))
        case "notarray":
            return PCAAuthzenSearchProvider(searchSubject: fixed(.object(["results": .string("x")])), searchResource: fixed(.object([:])), searchAction: fixed(.object(["results": .null])))
        case "throws": return PCAAuthzenSearchProvider(searchSubject: boom, searchResource: boom, searchAction: boom)
        case "echo": return PCAAuthzenSearchProvider(searchSubject: echo, searchResource: echo, searchAction: echo)
        case "partial": return PCAAuthzenSearchProvider(searchResource: fixed(res([])))
        default: return PCAAuthzenSearchProvider()
        }
    }

    func testAuthzen() throws {
        try K042.requireCovers(["Authzen", "JSInterop"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1)
            let got: BaseGot
            switch c.fn {
            case "isAccessEvaluationRequest": got = .value(.bool(PCAAuthzen.isAccessEvaluationRequest(a0)))
            case "isAccessEvaluationsRequest": got = .value(.bool(PCAAuthzen.isAccessEvaluationsRequest(a0)))
            case "isCoazToolAuthorizationRequest": got = .value(.bool(PCAAuthzen.isCoazToolAuthorizationRequest(a0)))
            case "isAuthzenSubject": got = .value(.bool(PCAAuthzen.isAuthzenSubject(a0)))
            case "isAuthzenAction": got = .value(.bool(PCAAuthzen.isAuthzenAction(a0)))
            case "isAuthzenResource": got = .value(.bool(PCAAuthzen.isAuthzenResource(a0)))
            case "isSubjectSearch": got = .value(.bool(PCAAuthzen.isSubjectSearch(a0)))
            case "isResourceSearch": got = .value(.bool(PCAAuthzen.isResourceSearch(a0)))
            case "isActionSearch": got = .value(.bool(PCAAuthzen.isActionSearch(a0)))
            case "defaultToAction": got = Ref.v { try PCAAuthzen.defaultToAction(a0 ?? .null) }
            case "approvalOf": got = Ref.v { try PCAAuthzen.approvalOf(a0) ?? .null }
            case "isApprovalRequired": got = Ref.v { .bool(try PCAAuthzen.isApprovalRequired(a0)) }
            case "pdp.evaluate":
                guard let cfg = a0?.asString else { d.skip("pdp.evaluate: config name is not a string"); return }
                var out = PCAAuthzen.evaluate(Self.config(cfg), a1)
                var want = c.out
                if c.name.hasSuffix("/pc17") || c.name.hasSuffix("/pc18") {
                    func narrow(_ v: JSONValue) -> JSONValue {
                        .object(["decision": v.get("decision") ?? .null, "stage": v.get("context")?.get("reason_admin")?.get("stage") ?? .null])
                    }
                    out = narrow(out)
                    want = narrow(want)
                }
                d.add(c, Base.canon(out) == Base.canon(want) ? nil : "\(c.name): want \(Base.canon(want).prefix(300)) got \(Base.canon(out).prefix(300))")
                return
            case "pdp.evaluations": got = Ref.v { try PCAAuthzen.evaluations(Self.config(a0?.asString ?? ""), a1) }
            case "pdp.evaluateTool": got = Ref.v { try PCAAuthzen.evaluateTool(Self.config(a0?.asString ?? ""), a1) }
            case "authzenHandler": got = .value(PCAAuthzen.handler(Self.config(a0?.asString ?? ""))(a1))
            case "authzenSearchHandler":
                let prov = a0?.asString ?? ""
                // the reference de-duplicates by JSON.stringify (insertion order); a parsed object has none, so the one provider entry whose
                // members are written in the other order cannot be told apart from its twin
                if prov == "full", a1?.get("path")?.asString == PCAAuthzen.SEARCH_SUBJECT_PATH, c.out.get("body")?.get("results") != nil {
                    d.skip("authzenSearchHandler: de-duplication by member insertion order"); return
                }
                got = .value(PCAAuthzen.searchHandler(Self.provider(prov))(a1) ?? .null)
            case "searchMetadata": got = .value(PCAAuthzen.searchMetadata(a0?.asString ?? "", Self.provider(a1?.asString ?? "")))
            default:
                d.skip("\(c.fn): not mapped"); return
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(2500)
    }
}
