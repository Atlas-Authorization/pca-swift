import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Server-side PQ pins end to end through `PCA.authorize` (packages/pca/conformance/authorize-pq-pin-fixtures.json), with a real ML-DSA-65 root
/// grant, including the classical-downgrade refusal (a classical grant from a PINNED issuer fails `pq_pin`).
final class A0F3PqPinAuthorizeTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testFixtures() throws {
        let doc = try ConformanceTests.load("authorize-pq-pin-fixtures.json")
        XCTAssertEqual(doc.get("format")?.asString, "pca-authorize-pq-pin-fixtures/1")
        let now = try XCTUnwrap(doc.get("now")?.safeInt)
        let aud = try XCTUnwrap(doc.get("audience")?.asString)
        let op = try XCTUnwrap(doc.get("operation"))
        let cases = try XCTUnwrap(doc.get("cases")?.asArray)
        XCTAssertEqual(cases.count, 9)
        var failures: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let grant = try XCTUnwrap(c.get("grant"), name)
            let id = grant.get("id")?.asString ?? ""
            var pins: [String: String]?
            if let po = c.get("pq_pins")?.asObject {
                var m: [String: String] = [:]
                for (k, v) in po { m[k.s] = v.asString ?? "" }
                pins = m
            }
            // a native that cannot verify ML-DSA-65 on this platform must answer unsupported_suite for a PQ grant
            let isPq = (grant.get("alg")?.asString ?? "ed25519") != "ed25519"
            var input = PCA.AuthorizeInput(
                operation: PCA.Operation(verb: op.get("verb")?.asString ?? "", resource: op.get("resource")?.asString ?? "", params: op.get("params") ?? .null),
                audience: aud, resolveGrant: { ref in ref == id ? grant : nil }, stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: now,
                plan: PCA.SINGLE_STEP, riskSource: PCA.insecureCalmRisk)
            input.pqPins = pins
            let r = PCA.authorize(pcactn: c.get("pcactn"), input)
            if isPq && !MLDSA.available {
                if r.allow || !r.reasons.joined(separator: " ").contains("unsupported_suite") { failures.append("\(name): a PQ grant on a platform without ML-DSA must answer unsupported_suite, got \(r.reasons)") }
                continue
            }
            let want = try XCTUnwrap(c.get("expect"), name)
            if r.allow != (want.get("allow") == .bool(true)) { failures.append("\(name): allow \(r.allow), reasons \(r.reasons)") }
            if let s = want.get("status")?.safeInt, Int64(r.status) != s { failures.append("\(name): status \(r.status), want \(s)") }
            for n in want.get("failed_includes")?.asArray?.compactMap({ $0.asString }) ?? [] where r.checks[n] != .fail { failures.append("\(name): \(n) should have failed") }
            if let want = want.get("checks")?.get("pq_pin")?.asString {
                let got: String = r.checks["pq_pin"].map { $0.rawValue } ?? "absent"
                if got != want { failures.append("\(name): pq_pin \(got), want \(want)") }
            }
            if let reason = want.get("reason")?.asString, r.reason != reason { failures.append("\(name): reason '\(r.reason)', want '\(reason)'") }
        }
        XCTAssertTrue(failures.isEmpty, failures.joined(separator: "\n"))
    }

    func testAClassicalGrantFromAPinnedIssuerIsRefusedButAnUnpinnedOrEmptyOneStands() {
        let g: JObject = ["issuer": .string("iss")]
        XCTAssertEqual(PCA.pqPinCheck(grant: g, pins: ["iss": "PK"]).pass, false)
        XCTAssertEqual(PCA.pqPinCheck(grant: g, pins: ["iss": "PK"]).reason, "the grant issuer is pinned to a post-quantum key; a classical grant is refused")
        XCTAssertEqual(PCA.pqPinCheck(grant: g, pins: ["iss": ""]).pass, false, "any value counts, even an empty one")
        XCTAssertTrue(PCA.pqPinCheck(grant: g, pins: ["other": "PK"]).pass)
        XCTAssertTrue(PCA.pqPinCheck(grant: g, pins: [:]).pass)
        XCTAssertEqual(PCA.pqPinCheck(grant: ["issuer": .string("iss"), "alg": .string("ed25519")], pins: ["iss": "PK"]).pass, false)
    }

    /// The core layer: a classical root whose issuer the caller pinned is refused after the chain check (verifyChain itself is untouched).
    func testCoreVerifyRefusesAClassicalRootFromAPinnedIssuer() throws {
        let core = try ConformanceTests.load("vectors.json")
        let v = try XCTUnwrap(core.get("vectors")?.asArray?.first { $0.get("name")?.asString == "valid-in-plan-action" })
        let grant = try XCTUnwrap(v.get("grant"))
        let issuer = try XCTUnwrap(grant.get("issuer")?.asString)
        let now = try XCTUnwrap(v.get("context")?.get("now")?.safeInt)
        let aud = try XCTUnwrap(v.get("context")?.get("aud")?.asString)
        func verify(_ pins: [String: String]?) -> PCA.Verdict {
            PCA.verify(pcactn: v.get("pcactn") ?? .null, grant: grant, now: now, audience: aud, insecureSkipPlanRootCheck: true, pqPins: pins)
        }
        let pinned = verify([issuer: "PK"])
        XCTAssertFalse(pinned.allow)
        XCTAssertEqual(pinned.checks["pq_pin"], false)
        XCTAssertTrue(pinned.reasons.contains("pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused"), "\(pinned.reasons)")
        for pins in [nil, [:], ["unrelated": "PK"]] as [[String: String]?] {
            let r = verify(pins)
            XCTAssertTrue(r.allow, "\(r.reasons)")
            XCTAssertNil(r.checks["pq_pin"], "no pq_pin check appears unless the pins name the root issuer")
        }
    }
}
