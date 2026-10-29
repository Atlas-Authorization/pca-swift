import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Assurance labels (T8, B7): replays assurance-vectors.json (signature_level, report, requirement, multi_root), then the `authorize`
/// wiring. A missing vector file FAILS (it is loaded, never skipped).
final class AssuranceTests: XCTestCase {
    struct UnlabelledHook {}

    static func doc() throws -> JSONValue { try ConformanceTests.load("assurance-vectors.json") }

    static func rows(_ d: JSONValue, _ table: String, _ n: Int) -> [JSONValue] {
        let a = d.get(table)?.asArray ?? []
        XCTAssertEqual(a.count, n, "\(table): row count")
        return a
    }

    /// A hook as the vectors write it: nil (absent), "unlabelled" (a hook with no label) or a label object.
    static func hook(_ v: JSONValue?) -> Any? {
        switch v {
        case nil, .null?: return nil
        case .string?: return UnlabelledHook()
        case let .object(o)?:
            return PCA.withAssuranceLabel(UnlabelledHook(), AssuranceLabel(level: o["level"]?.asString ?? "", vendor: o["vendor"]?.asString,
                                                                          awaitingAudit: o["awaiting_audit"] == .bool(true), ceremony: o["ceremony"]?.asString))
        default: return nil
        }
    }

    /// The member order of one row's `report` object in the vector file (a parsed object has none, and the first unmet dimension of a
    /// requirement is the first in report order).
    static func reportOrder(_ lines: [Substring], row: String) -> [String] {
        guard let start = lines.firstIndex(where: { $0 == "  \"requirement\": [" }),
              let at = lines[start...].firstIndex(where: { $0 == "      \"name\": \"\(row)\"," }),
              let rep = lines[at...].firstIndex(where: { $0 == "      \"report\": {" }) else { return [] }
        var out: [String] = []
        for l in lines[(rep + 1)...] {
            if l == "      }," || l == "      }" { break }
            guard l.hasPrefix("        \""), !l.hasPrefix("         ") else { continue }
            let rest = l.dropFirst(9)
            if let close = rest.firstIndex(of: "\"") { out.append(String(rest[..<close])) }
        }
        return out
    }

    func testSignatureLevelVectors() throws {
        for v in Self.rows(try Self.doc(), "signature_level", 14) {
            XCTAssertEqual(PCA.signatureLevel(v.get("alg")), v.get("level")?.asString, Canonical.canonicalize(v))
        }
    }

    func testReportVectors() throws {
        for v in Self.rows(try Self.doc(), "report", 37) {
            var src = AssuranceSources()
            let checks = v.get("checks")?.asObject ?? [:]
            for k in checks.keys.map({ $0.s }).sorted() { src.checks.append(NamedStatus(name: k, status: checks[JKey(k)]?.asString ?? "")) }
            src.pcactn = v.get("pcactn")
            let h = v.get("hooks")
            src.hooks = AssuranceHooks(attestation: Self.hook(h?.get("attestation")), zk: Self.hook(h?.get("zk")), threshold: Self.hook(h?.get("threshold")),
                                       revocation: Self.hook(h?.get("revocation")))
            src.attestationHook = Self.hook(v.get("attestation_hook"))
            src.thresholdT = IV.num(v.get("threshold_t"))
            src.allowUnboundPq = v.get("allow_unbound_pq") == .bool(true)
            for (k, x) in v.get("degraded")?.asObject ?? [:] { src.degraded[k.s] = x.asString ?? "" }
            XCTAssertEqual(Canonical.canonicalize(PCA.buildAssuranceReport(src).json), Canonical.canonicalize(v.get("report") ?? .null), v.get("name")?.asString ?? "?")
        }
    }

    func testRequirementVectors() throws {
        let text = try ConformanceTests.readText(ConformanceTests.conformanceDir.appendingPathComponent("assurance-vectors.json"))
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        for v in Self.rows(try Self.doc(), "requirement", 47) {
            let name = v.get("name")?.asString ?? "?"
            let order = Self.reportOrder(lines, row: name)
            XCTAssertEqual(order.count, v.get("report")?.asObject?.count, "\(name): report member order")
            let report = AssuranceReport(json: v.get("report"), order: order)
            XCTAssertEqual(PCA.unmetAssurance(report, AssuranceRequirement(json: v.get("require"))), v.get("unmet")?.asString, name)
        }
    }

    func testMultiRootVectors() throws {
        for v in Self.rows(try Self.doc(), "multi_root", 10) {
            let roots = (v.get("roots")?.asArray ?? []).map { r in
                AttestationRoot(verifier: PCA.withAssuranceLabel(UnlabelledHook(), AssuranceLabel(level: r.get("level")?.asString ?? "")), required: r.get("required") == .bool(true))
            }
            XCTAssertEqual(PCA.multiRootLevel(roots, threshold: Int(v.get("threshold")?.safeInt ?? 0)), v.get("level")?.asString, v.get("name")?.asString ?? "?")
        }
    }

    // A label comes from the verifier's configuration: an unlabelled hook, a hook of another level and presented evidence can never meet a requirement.
    func testLabelsNeverFromEvidence() {
        let hw = PCA.withAssuranceLabel(UnlabelledHook(), AssuranceLabel(level: "hardware", vendor: "v"))
        var rep = PCA.buildAssuranceReport(AssuranceSources(checks: [NamedStatus(name: "attestation", status: "pass")], hooks: AssuranceHooks(attestation: hw)))
        XCTAssertNil(PCA.unmetAssurance(rep, AssuranceRequirement(attestation: "hardware")), "labelled hardware must meet hardware")
        XCTAssertNotNil(PCA.unmetAssurance(rep, AssuranceRequirement(attestation: "multi_root")), "hardware must not meet multi_root")
        rep = PCA.buildAssuranceReport(AssuranceSources(checks: [NamedStatus(name: "attestation", status: "pass")], hooks: AssuranceHooks(attestation: UnlabelledHook())))
        XCTAssertEqual(PCA.unmetAssurance(rep, AssuranceRequirement(attestation: "software")), "assurance: software attestation required but the evidence is unknown")
        XCTAssertEqual(PCA.unmetAssurance(AssuranceReport(), AssuranceRequirement(attestation: "software")),
                       "assurance: software attestation required but there is no attestation evidence")
        XCTAssertNotNil(PCA.unmetAssurance(AssuranceReport(), AssuranceRequirement(attestation: "bogus")), "an unknown required level can never be met")
    }

    // ---- the authorize wiring ----

    func authorize(_ store: MemoryStateStore, _ edit: (inout PCA.AuthorizeInput) -> Void) throws -> PCA.AuthorizeResult {
        let c = try XCTUnwrap(AuthorizeTests.CASES.first)
        let s = try XCTUnwrap(c.get("steps")?.asArray?.first)
        let g = try XCTUnwrap(c.get("grant"))
        var input = PCA.AuthorizeInput(operation: AuthorizeTests.op(s.get("operation")), audience: AuthorizeTests.AUD, resolveGrant: { _ in g },
                                       stateStore: store, isRevoked: { _, _ in false }, now: AuthorizeTests.NOW, plan: PCA.SINGLE_STEP)
        edit(&input)
        return PCA.authorize(pcactn: s.get("pcactn"), input.withProv())
    }

    func testAuthorizeAssuranceGate() throws {
        let store = MemoryStateStore()
        let denied = try authorize(store) { $0.requireAssurance = AssuranceRequirement(signature: "pq") }
        XCTAssertFalse(denied.allow)
        XCTAssertEqual(denied.checks["assurance"], .fail)
        XCTAssertEqual(denied.reason, "assurance: post-quantum signatures required but leaf_signature is ed25519")
        XCTAssertEqual(denied.assurance["leaf_signature"]?.level, "ed25519")
        XCTAssertEqual(denied.assurance["leaf_signature"]?.suites, ["ed25519"])
        // the denial must not have consumed the replay counter: the same proof still passes without the requirement
        let ok = try authorize(store) { _ in }
        XCTAssertTrue(ok.allow, "a refused assurance must leave the replay state untouched: \(ok.reasons)")
        XCTAssertEqual(ok.assurance["cap_chain"]?.outcome, "pass", "the capability chain is reported as cap_chain")
        XCTAssertEqual(ok.assurance["cap_chain"]?.level, "ed25519")
        // a requirement the evidence meets does not change the decision
        let empty = try authorize(MemoryStateStore()) { $0.requireAssurance = AssuranceRequirement() }
        XCTAssertTrue(empty.allow, "an empty requirement must allow")
        // no attestation check ran: a hardware requirement is unmet, never silently met
        let hw = try authorize(MemoryStateStore()) { $0.requireAssurance = AssuranceRequirement(attestation: "hardware") }
        XCTAssertFalse(hw.allow)
        XCTAssertEqual(hw.reason, "assurance: hardware attestation required but there is no attestation evidence")
    }
}
