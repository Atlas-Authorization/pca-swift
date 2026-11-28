import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The layer decisions, the value-dependent verb reversibility, the objective-risk commitment reader, the natural-language catalog digest and the
/// action definition constants.
final class RefCoreLeftoversTests: XCTestCase {
    private func j(_ text: String) -> JSONValue { (try? StrictJSON.parseLenient(text)) ?? .null }

    func testReversibilityOfMatchesTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-action-schema.json.gz", ["reversibilityOf"]) { c in
            d.add(c, Base.diff(c, .value(.string(PCA.reversibilityOf(c.arg(0) ?? .null, c.arg(1))))))
        }
        XCTAssertEqual(n, 20)
        d.finish(20)
    }

    func testTheNlCatalogDigestMatchesTheReference() throws {
        let d = Base.Diffs()
        let n = try Base.each("ref-nl-approval.json.gz", ["catalogDigest"]) { c in
            d.add(c, Base.diff(c, Base.run { .string(PCA.nlCatalogDigest(try RefIntentCompilersTests.catalog(c.arg(0)))) }))
        }
        XCTAssertEqual(n, 3)
        d.finish(3)
    }

    func testLayerDecisions() {
        typealias L = PCAIntentLayers
        let ctx = j(#"{"action":{"verb":"read","resource":"x","params":{}}}"#)
        let any = #"{"predicates":[{"verb":"*"}]}"#, none = #"{"predicates":[]}"#
        XCTAssertEqual(L.decideLayers(j(#"{"org":\#(any),"task":[\#(any)]}"#), ctx), .admit(by: 0))
        XCTAssertEqual(L.decideLayers(j(#"{"task":[\#(none),\#(any)]}"#), ctx), .admit(by: 1))
        XCTAssertEqual(L.decideLayers(j(#"{"org":\#(any),"site":\#(none),"task":[\#(any)]}"#), ctx), .ceiling(layer: "site"))
        XCTAssertEqual(L.decideLayers(j(#"{"task":[\#(none)]}"#), ctx), .intentRequired)
        XCTAssertEqual(L.decideLayers(j(#"{"task":[\#(any)],"denied":[\#(any)]}"#), ctx), .intentDenied)
        // malformed members never become a question or an admission
        XCTAssertEqual(L.decideLayers(j(#"{"task":"x"}"#), ctx), .intentDenied)
        XCTAssertEqual(L.decideLayers(j(#"{}"#), ctx), .intentDenied)
        XCTAssertEqual(L.decideLayers(j(#"{"task":[\#(any)],"denied":null}"#), ctx), .intentDenied)
        XCTAssertEqual(L.decideLayers(j(#"{"task":[\#(any)],"extra":1}"#), ctx), .intentDenied)
        XCTAssertEqual(L.decideLayers(j(#"{"task":[{"predicates":[{"verb":"*"}],"x":1}]}"#), ctx), .intentDenied)
        XCTAssertEqual(L.decideLayers(j(#"{"org":null,"task":[\#(any)]}"#), ctx), .ceiling(layer: "org"))
        XCTAssertEqual(L.decideLayers(nil, ctx), .ceiling(layer: "org"))
        XCTAssertEqual(L.decideLayers(j(#"[]"#), ctx), .ceiling(layer: "org"))
        XCTAssertEqual(JS.stringify(L.LayerDecision.admit(by: 2).json), #"{"decision":"admit","by":2}"#)
        XCTAssertEqual(JS.stringify(L.LayerDecision.ceiling(layer: "std").json), #"{"decision":"ceiling","layer":"std"}"#)

        XCTAssertTrue(L.decideLayerCeilings(j("{}"), ctx).pass)
        XCTAssertTrue(L.decideLayerCeilings(j(#"{"org":\#(any),"std":\#(any)}"#), ctx).pass)
        let unknown = L.decideLayerCeilings(j(#"{"org":\#(any),"team":\#(any)}"#), ctx)
        XCTAssertEqual(unknown.layer, "org")
        XCTAssertEqual(unknown.reason, "layers: unknown member (the layers object is {org?, site?, std?})")
        XCTAssertEqual(L.decideLayerCeilings(j(#"{"std":{"predicates":"x"}}"#), ctx).reason, "layers: the std ceiling is malformed (null or not {predicates: [...]})")
        XCTAssertEqual(L.decideLayerCeilings(j(#"{"site":\#(none)}"#), ctx).reason, "layers: the action is outside the site ceiling (a ceiling is never a question)")
        XCTAssertEqual(L.decideLayerCeilings(.null, ctx).reason, "layers: the layers member is malformed (not an object)")
        XCTAssertTrue(L.isLayerPolicy(j(any)))
        XCTAssertFalse(L.isLayerPolicy(j(#"{"predicates":[],"x":1}"#)))
        XCTAssertEqual(L.LayerPolicy(json: j(any))?.predicates.count, 1)
        XCTAssertNil(L.LayerPolicy(json: .null))
    }

    func testReadObjectiveCommitment() {
        let policy = #""risk_policy":{"weights":{"alpha":0.4,"beta":0.3,"gamma":0.2,"delta":0.1,"epsilon":0,"zeta":0},"theta1":0.3,"theta2":0.7,"kappa":100,"lambda":0.1,"rho":0,"bMax":1}"#
        func grant(_ objective: String?) -> JSONValue {
            j(#"{"caveats":[{"type":"envelope","goal_commit":"g","predicates":[],"caveats":[],"agent_binding":{},\#(policy)\#(objective.map { #","objective_risk":"# + $0 } ?? "")}]}"#)
        }
        let good = #"{"v":1,"embedder":{"scheme":"native","model_id":"m","config":{}},"goal":{"commit":"c"},"registry_digest":"r","graph_digest":"g","authorized_kinds":["refund"]}"#
        // the fixture is only meaningful when the envelope itself reads
        XCTAssertNotNil(PCA.readEnvelope(grant(nil)))
        XCTAssertNil(PCA.readObjectiveCommitment(grant(nil)).commitment)
        XCTAssertNil(PCA.readObjectiveCommitment(grant(nil)).malformed)
        XCTAssertNil(PCA.readObjectiveCommitment(.object([:])).malformed)
        let r = PCA.readObjectiveCommitment(grant(good))
        XCTAssertNil(r.malformed)
        XCTAssertEqual(r.commitment?.get("registry_digest")?.asString, "r")
        func bad(_ from: String, _ to: String) -> String? { PCA.readObjectiveCommitment(grant(good.replacingOccurrences(of: from, with: to))).malformed }
        XCTAssertEqual(bad(#""v":1"#, #""v":2"#), "objective_risk: unsupported shape/version")
        XCTAssertEqual(bad(#""scheme":"native""#, #""scheme":"byo""#), "objective_risk.embedder must be { scheme: \"native\", model_id, config }")
        XCTAssertEqual(bad(#""commit":"c""#, #""commit":"""#), "objective_risk.goal must be a goal commitment")
        XCTAssertEqual(bad(#""graph_digest":"g""#, #""graph_digest":1"#), "objective_risk needs registry_digest and graph_digest")
        XCTAssertEqual(bad(#""graph_digest":"g""#, #""graph_digest":"g","calibration_digest":"""#), "objective_risk.calibration_digest must be a string")
        XCTAssertEqual(bad(#"["refund"]"#, #"["refund",1]"#), "objective_risk.authorized_kinds must be string[]")
        XCTAssertEqual(bad(#""graph_digest":"g""#, #""graph_digest":"g","denominations":{}"#), "objective_risk.denominations must be an array")
        XCTAssertEqual(bad(#""graph_digest":"g""#, #""graph_digest":"g","on_mismatch":"allow""#), "objective_risk.on_mismatch must be \"deny\" or \"heuristic\"")
        XCTAssertEqual(PCA.readObjectiveCommitment(grant("null")).malformed, "objective_risk: unsupported shape/version")
    }

    func testActionDefinitionConstantsAndHelpers() {
        XCTAssertEqual([Actions.ACTION_DEF_VERSION, Actions.MAX_VERB_BYTES, Actions.MAX_TITLE_BYTES, Actions.MAX_DESCRIPTION_BYTES, Actions.MAX_DEF_PARAMS, Actions.MAX_DEF_ALIASES,
                        Actions.MAX_DEF_TRAITS, Actions.MAX_DEF_CONTEXT, Actions.MAX_DEF_SIDE_EFFECTS, Actions.MAX_PARAM_PATH_DEPTH, Actions.MAX_TRAIT_IMPLIES_DEPTH,
                        Actions.MAX_REGISTRY_TRAITS, Actions.ESC_MAX], [1, 128, 120, 1024, 64, 16, 32, 16, 16, 3, 8, 512, 3])
        XCTAssertEqual(Actions.PARAM_TYPES_V1, ["string", "integer", "boolean", "date", "datetime", "duration", "set", "array", "object_ref"])
        XCTAssertEqual(Actions.SENSITIVITY_LEVELS, ["free", "material", "critical"])
        XCTAssertEqual(Actions.CORE_NAMESPACE, "pca.")
        XCTAssertEqual(Actions.CORE_TRAIT_DEFS.map { $0.id }, Actions.CORE_TRAIT_IDS)
        XCTAssertTrue(Actions.CORE_TRAIT_DEFS.allSatisfy { $0.id.hasPrefix(Actions.CORE_NAMESPACE) && $0.floor.esc <= Actions.ESC_MAX })
        XCTAssertEqual(Actions.meetDecision("allow", "escalate"), "escalate")
        XCTAssertEqual(Actions.meetDecision("deny", "allow"), "deny")
        XCTAssertEqual(Actions.meetDecision("allow", "allow"), "allow")
        XCTAssertEqual(Actions.meetDecision("escalate", "deny"), "deny")
        XCTAssertEqual(Actions.declaredReversibility(j(#"{"effects":["read"]}"#)), .string("reversible"))
        XCTAssertEqual(Actions.declaredReversibility(j(#"{"effects":["read","update"]}"#)), .string("irreversible"))
        XCTAssertEqual(Actions.declaredReversibility(j(#"{"effects":[]}"#)), .string("irreversible"))
        XCTAssertEqual(Actions.declaredReversibility(j(#"{"effects":["pay"],"reversibility":"rate_limited"}"#)), .string("rate_limited"))
        XCTAssertEqual(Actions.declaredReversibility(j(#"{"effects":["read"],"reversibility":{"by":"mode","map":{"a":"reversible"}}}"#)).get("by")?.asString, "mode")
    }
}
