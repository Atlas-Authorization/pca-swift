import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The forbid-wins certificate table and linked policy templates over the SHARED vectors
/// (packages/pca/conformance/forbid-certificate-vectors.json, policy-link-vectors.json): exact outcomes.
final class PolicyAuthoringTests: XCTestCase {
    func testForbidCertificateTable() throws {
        let doc = try ConformanceTests.load("forbid-certificate-vectors.json")
        let table = doc.get("table")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(table.count, 19)
        for v in table {
            let n = v.get("name")?.asString ?? "?"
            let prec = (v.get("options")?.get("precedence")?.asArray ?? []).compactMap { $0.asString }
            let want = v.get("expect")?.get("consistent") == .bool(true)
            XCTAssertEqual(PCA.forbidCertificateConsistent(v.get("certificate") ?? .null, precedence: prec), want, n)
        }
        for bad in [JSONValue.null, .int(5), .array([]), .object([:])] {
            XCTAssertFalse(PCA.forbidCertificateConsistent(bad))
        }
    }

    func testPolicyLinkVectors() throws {
        let doc = try ConformanceTests.load("policy-link-vectors.json")
        let def = doc.get("template")?.get("def") ?? .null
        XCTAssertEqual(PCA.templateDigest(def), doc.get("template")?.get("digest")?.asString)
        for v in doc.get("def_errors")?.asArray ?? [] {
            XCTAssertEqual(PCA.templateDefError(v.get("def") ?? .null), v.get("expect")?.asString, v.get("name")?.asString ?? "?")
        }
        let inst = doc.get("instantiate")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(inst.count, 14)
        for v in inst {
            let n = v.get("name")?.asString ?? "?"
            let r = PCA.instantiateTemplate(def, v.get("slots") ?? .null)
            let x = v.get("expect")
            if x?.get("ok") == .bool(true) {
                XCTAssertEqual(r.policy, x?.get("policy"), n)
            } else {
                XCTAssertNil(r.policy, n)
                XCTAssertEqual(r.reason, x?.get("reason")?.asString, n)
            }
        }
        for v in doc.get("verify")?.asArray ?? [] {
            let n = v.get("name")?.asString ?? "?"
            let trusted = (v.get("trusted")?.asArray ?? []).compactMap { $0.asString }
            let signed = v.get("signed") ?? .null
            let r = v.get("kind")?.asString == "template" ? PCA.verifyTemplate(signed, trusted: trusted) : PCA.verifyTighten(signed, trusted: trusted)
            let x = v.get("expect")
            XCTAssertEqual(r == nil, x?.get("ok") == .bool(true), n)
            if r != nil { XCTAssertEqual(r, x?.get("reason")?.asString, n) }
        }
        for v in doc.get("ref_errors")?.asArray ?? [] {
            XCTAssertEqual(PCA.templateRefError(v.get("ref") ?? .null), v.get("expect")?.asString, v.get("name")?.asString ?? "?")
        }
        for v in doc.get("resolve")?.asArray ?? [] {
            let n = v.get("name")?.asString ?? "?"
            let r = PCA.resolveLink(v.get("ref") ?? .null, registry: v.get("registry") ?? .null)
            let x = v.get("expect")
            if x?.get("ok") == .bool(true) {
                XCTAssertNil(r.reason, n)
                XCTAssertEqual(r.policy, x?.get("policy"), n)
                XCTAssertEqual(Int64(r.overlays), x?.get("overlays")?.safeInt, n)
            } else {
                XCTAssertEqual(r.reason, x?.get("reason")?.asString, n)
            }
        }
    }
}
