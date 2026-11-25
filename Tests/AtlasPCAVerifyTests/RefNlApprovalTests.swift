import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The approval half of natural-language policy authoring (catalog digest, draft binding and digests, policy and draft from a model completion, approval under
/// the v2 and the legacy v1 forms, loading an approved draft with its rejection codes, minting an agent from an approved draft) against the reference corpus:
/// every case, every fn. The model is a fixed completion text (`THROWS` makes it throw). An agent is minted with a random goal salt, so only the deterministic
/// envelope members are compared, never the goal commitment.
final class RefNlApprovalTests: XCTestCase {
    typealias N = PCANLApproval
    typealias A = RefAnalyzer

    private static func complete(_ raw: String?) -> (String) throws -> String {
        { _ in
            if raw == "THROWS" { throw JSError("llm down") }
            return raw ?? ""
        }
    }

    private static func reviewer(_ secret: JSONValue?) throws -> PCAEdKey {
        guard let s = Base.bytes(secret) else { throw JSError("reviewer secret") }
        return try Ed25519Deterministic.key(seed: s)
    }

    private static func num(_ v: JSONValue?) -> Double? { IV.num(v) }

    /// `opts.now ?? default`: absent or null takes the default; any other non-number is not finite in the reference (`Number.isFinite("5")` is false), so NaN.
    private static func numOpt(_ v: JSONValue?) -> Double? {
        guard let v = v, v != .null else { return nil }
        return IV.num(v) ?? .nan
    }

    private static func agent(_ a: JSONValue?) throws -> JSONValue {
        guard let a = a, let draft = a.get("draft"), let approval = a.get("approval"), let goal = a.get("goal")?.asString, let seed = a.get("principalSeed")?.asString else { throw JSError("bad arguments") }
        let o = a.get("opts")
        let holder = try a.get("holderSeed")?.asString.map { PCASuiteKey.ed25519(try A.key($0)) }
        let r = try N.agentFromApprovedNL(draft: draft, approval: approval, reviewers: (o?.get("reviewers")?.asArray ?? []).compactMap { $0.asString },
                                          catalog: try RefIntentCompilersTests.catalog(o?.get("extras")), now: num(o?.get("now")), principal: PCASuiteKey.ed25519(try A.key(seed)), goal: goal,
                                          aud: a.get("aud")?.asString, holder: holder)
        let env = PCA.readEnvelope(r.agent.grant)
        var e = JObject()
        for k in ["predicates", "caveats", "risk_policy", "agent_binding"] { e[JKey(k)] = env?.get(k) ?? .null }
        return .object(["reviewer": .string(r.reviewer), "legacy_unbound_instruction": .bool(r.legacyUnboundInstruction), "envelope": .object(e)])
    }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1), a2 = A.arg(c, 2), a3 = A.arg(c, 3)
        switch c.fn {
        case "constants":
            return .value(.object(["NL_APPROVAL_DOMAIN": .string(N.NL_APPROVAL_DOMAIN), "NL_APPROVAL_DOMAIN_V2": .string(N.NL_APPROVAL_DOMAIN_V2), "MAX_NL_OUTPUT_BYTES": .int(Int64(N.MAX_NL_OUTPUT_BYTES)),
                                   "MAX_NL_APPROVAL_TTL_MS": .int(Int64(N.MAX_NL_APPROVAL_TTL_MS))]))
        case "catalogDigest": return A.run { .string(N.catalogDigest(try RefIntentCompilersTests.catalog(a0))) }
        case "draftBinding": return A.run { N.draftBinding(a0?.asString ?? "", try RefIntentCompilersTests.catalog(a1), model: a2?.asString) }
        case "draftDigestV2": return A.run { .string(try N.draftDigestV2(a0 ?? .null, a1 ?? .null, a2?.asString ?? "", a3 ?? .null)) }
        case "draftDigest": return A.run { .string(try N.draftDigest(a0 ?? .null, a1 ?? .null, a2?.asString ?? "")) }
        case "policyFromNL":
            return A.run { try N.policyFromNL(a0?.asString ?? "", complete: complete(a1?.asString), catalog: try RefIntentCompilersTests.catalog(a2)) }
        case "draftPolicyFromNL":
            return A.run { try N.draftPolicyFromNL(a0?.asString ?? "", complete: complete(a1?.asString), catalog: try RefIntentCompilersTests.catalog(a2), model: a3?.asString) }
        case "approveDraft":
            return A.run { try N.approveDraft(a0 ?? .null, reviewer: try reviewer(a1), now: numOpt(a2?.get("now")), ttlMs: numOpt(a2?.get("ttlMs"))) }
        case "approveDraftLegacy":
            return A.run { try N.approveDraftLegacyV1(a0 ?? .null, reviewer: try reviewer(a1), now: numOpt(a2?.get("now")), ttlMs: numOpt(a2?.get("ttlMs"))) }
        case "loadApproved":
            return A.run {
                N.loadApprovedPolicy(a0 ?? .null, a1 ?? .null, reviewers: (a2?.get("reviewers")?.asArray ?? []).compactMap { $0.asString }, catalog: try RefIntentCompilersTests.catalog(a2?.get("extras")),
                                     now: numOpt(a2?.get("now")))
            }
        case "agentFromApproved": return A.run { try agent(a0) }
        default: return nil
        }
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-nl-approval.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            guard let got = Self.call(c) else { XCTFail("unhandled fn \(c.fn)"); return }
            d.add(c, Base.diff(c, got))
        }
        XCTAssertEqual(n, 206)
        XCTAssertEqual(seen, ["loadApproved": 58, "draftPolicyFromNL": 42, "policyFromNL": 40, "approveDraft": 24, "draftDigestV2": 10, "agentFromApproved": 10, "draftDigest": 7, "draftBinding": 6,
                              "approveDraftLegacy": 5, "catalogDigest": 3, "constants": 1])
        d.finish(206)
    }
}
