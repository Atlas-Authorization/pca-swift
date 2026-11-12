import XCTest
import Foundation
@testable import AtlasPCAVerify

/// F3 pqPins over packages/pca/conformance/pq-pin-vectors.json: the grant issuer -> PQ key pin rule of the full verifier.
final class A0F3PqPinVectorsTests: XCTestCase {
    override func setUp() { super.setUp(); continueAfterFailure = false }

    func testPqPinVectors() throws {
        let doc = try ConformanceTests.load("pq-pin-vectors.json")
        let core = try ConformanceTests.load("vectors.json")
        let cases = try XCTUnwrap(doc.get("pq_pin")?.asArray)
        XCTAssertEqual(cases.count, 9)
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let vname = c.get("vector")?.asString ?? ""
            let v = try XCTUnwrap(core.get("vectors")?.asArray?.first { $0.get("name")?.asString == vname }, "vector \(vname)")
            let grant = try XCTUnwrap(v.get("grant")?.asObject)
            let issuer = grant[JKey("issuer")]?.asString ?? ""
            let pk = grant[JKey("pq_pk")]?.asString ?? ""
            func expand(_ s: String) -> String {
                if s == "$grant.issuer" { return issuer }
                if s == "$grant.pq_pk" { return pk }
                if s == "$grant.pq_pk[0:20]" { return String(pk.prefix(20)) }
                return s
            }
            let expect = try XCTUnwrap(c.get("expect"), name)
            guard let rawPins = c.get("pq_pins")?.asObject else {
                XCTAssertEqual(expect.get("check")?.asString, "absent", name)
                continue // pq_pins omitted: the check is not reported, so there is nothing to compute
            }
            var pins: [String: String] = [:]
            for (k, val) in rawPins { pins[expand(k.s)] = expand(val.asString ?? "") }
            let fixedPins = pins
            let r = S2Deadline.within(10, "pqPinCheck \(name)") { PCA.pqPinCheck(grant: grant, pins: fixedPins) } ?? (pass: false, reason: "timeout")
            switch expect.get("check")?.asString {
            case "pass": XCTAssertTrue(r.pass, "\(name): \(r.reason)")
            case "fail":
                XCTAssertFalse(r.pass, name)
                XCTAssertEqual("pq_pin: " + r.reason, expect.get("reason")?.asString, name)
            default: XCTFail("\(name): unexpected check status")
            }
        }
    }

    func testAnOwnEntryIsRequired() {
        // a pin keyed by something that merely shares a prefix, or the empty issuer, is not the issuer's pin
        let g: JObject = ["issuer": .string("iss"), "alg": .string("ml-dsa-65"), "pq_pk": .string("PK")]
        XCTAssertFalse(PCA.pqPinCheck(grant: g, pins: ["is": "PK"]).pass)
        XCTAssertTrue(PCA.pqPinCheck(grant: g, pins: ["iss": "PK"]).pass)
        XCTAssertFalse(PCA.pqPinCheck(grant: ["alg": .string("hybrid"), "pq_pk": .string("PK")], pins: ["": "PK2"]).pass)
        XCTAssertTrue(PCA.pqPinCheck(grant: ["issuer": .string("i")], pins: [:]).pass, "an absent alg is ed25519")
    }
}
