import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Behaviour the reference tightened after the shared corpora were generated: each case is a refusal (or a fail-closed value) the native side must
/// give without waiting for a corpus refresh.
final class ReferenceFollowUpTests: XCTestCase {
    // a clock or budget stamp that is not a finite number depletes the budget

    func testLeakDepletesOnANonFiniteStamp() {
        let nan = Risk.Budget(json: .object(["B": .double(1), "tau": .double(0), "asOf": .double(.nan)]))
        XCTAssertNotNil(nan)
        XCTAssertEqual(nan.map { Risk.leak($0, now: 1000, lambda: 0).b }, 0)
        let inf = Risk.Budget(json: .object(["B": .double(1), "tau": .double(0), "asOf": .double(.infinity)]))
        XCTAssertEqual(inf.map { Risk.leak($0, now: 1000, lambda: 0).b }, 0)
        let text = Risk.Budget(json: .object(["B": .double(1), "tau": .double(0), "asOf": .string("x")]))
        XCTAssertEqual(text.map { Risk.leak($0, now: 1000, lambda: 0).b }, 0)
        // an absent or null asOf still falls back to tau, so an ordinary budget is untouched
        let plain = Risk.Budget(json: .object(["B": .double(1), "tau": .double(0), "asOf": .null]))
        XCTAssertEqual(plain.map { Risk.leak($0, now: 1000, lambda: 0).b }, 1)
        // the stamps are returned as they came
        let out = Risk.leak(Risk.Budget(b: 1, tau: 5, asOf: .nan), now: 1000, lambda: 0)
        XCTAssertEqual(out.tau, 5)
        XCTAssertTrue(out.asOf?.isNaN ?? false)
    }

    func testAChargeOnABudgetWithANonFiniteStampIsNotAutoApproved() throws {
        let (m, grant) = try RefPaymentsTests.mandate()
        let charge: JSONValue = .object(["merchant": .string("openai"), "amount": .int(50), "category": .string("5734"), "now": .int(1_800_000_001_000)])
        XCTAssertEqual(try PCAPayments.authorizeChargeCore(m, charge, grant).get("outcome"), .string("auto"))
        var bad = m.asObject ?? [:]
        bad["budget"] = .object(["B": m.get("budget")?.get("B") ?? .int(0), "tau": .int(1_800_000_000_000), "asOf": .double(.nan)])
        XCTAssertNotEqual(try PCAPayments.authorizeChargeCore(.object(bad), charge, grant).get("outcome"), .string("auto"))
        bad["budget"] = .object(["B": m.get("budget")?.get("B") ?? .int(0), "asOf": .double(.nan)])
        XCTAssertNotEqual(try PCAPayments.authorizeChargeCore(.object(bad), charge, grant).get("outcome"), .string("auto"))
    }

    // buildPaymentMandate: -0 is refused

    func testBuildPaymentMandateRefusesNegativeZero() throws {
        let principal = try RefKeys.suite(.object(["$seed": .string("pay-principal")]))
        let agent = try RefKeys.edKey(.object(["$seed": .string("pay-agent")]))
        for k in ["autoApproveThreshold", "replenishPerCosign"] {
            var p: JObject = ["principalPublic": .string(principal.id ?? ""), "agentPublic": .string(agent.id), "merchants": .array([.string("openai")]),
                              "currency": .string("USD"), "perTransactionCap": .int(500), "autoApproveThreshold": .int(200), "cumulativeCap": .int(1000),
                              "goal": .string("buy compute"), "now": .int(1_800_000_000_000)]
            p[JKey(k)] = .double(-0.0)
            XCTAssertThrowsError(try PCAPayments.buildPaymentMandate(.object(p), principal: principal), k) { e in
                XCTAssertTrue((e as? JSError)?.message.contains("negative zero") ?? false, "\(e)")
            }
        }
    }

    // omegaFromJSON: a categorical dimension with no values

    func testOmegaFromJSONRefusesACategoricalWithNoValues() throws {
        func omega(_ dim: JSONValue) -> JSONValue {
            .object(["approximate": .array([]), "verbs": .array([.object(["verb": .string("x.a"), "reversibility": .string("reversible"), "w": .int(1), "dims": .array([dim])])])])
        }
        let absent: JSONValue = .object(["kind": .string("cat"), "path": .string("action.params.to")])
        let empty: JSONValue = .object(["kind": .string("cat"), "path": .string("action.params.to"), "values": .array([])])
        for d in [absent, empty] {
            XCTAssertThrowsError(try PCAIntentMap.omegaFromJSON(omega(d))) { e in
                XCTAssertEqual((e as? JSError)?.message, "omegaFromJSON: categorical dimension 'action.params.to' has no values")
            }
        }
        let one: JSONValue = .object(["kind": .string("cat"), "path": .string("action.params.to"), "values": .array([.object(["kind": .string("exact"), "value": .string("a")])])])
        XCTAssertNoThrow(try PCAIntentMap.omegaFromJSON(omega(one)))
    }

    // requireAttestedFact: the path is an array

    func testRequireAttestedFactRefusesANonArrayPath() throws {
        let key = try Ed25519Deterministic.key(seed: [UInt8](repeating: 7, count: 32))
        let k = PCANotary.NotaryKey(key)
        XCTAssertThrowsError(try PCANotary.requireAttestedFact(notary: k, path: .string("id"), equals: .int(1))) { e in
            XCTAssertEqual((e as? JSError)?.message, "requireAttestedFact: path must be an array of segments")
        }
        XCTAssertNoThrow(try PCANotary.requireAttestedFact(notary: k, path: .array([.string("id")]), equals: .int(1)))
    }

    // the NVIDIA OCSP request: a hash without a CertID OID is refused before anything is parsed

    func testOcspRequestRefusesAnUnsupportedCertIdHash() {
        for h in ["md5", "sha224", ""] {
            XCTAssertThrowsError(try PCAAttestNvidia.ocspRequest(certPem: "", issuerPem: "", hash: h), h) { e in
                XCTAssertEqual((e as? JSError)?.message, "unsupported CertID hash \(h)")
            }
        }
    }
}
