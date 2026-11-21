import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED offline Sigstore vectors (packages/pca/conformance/sigstore-vectors.json, track K9): `ok` and the
/// refusal `code` must match, and on ok the whole `core`.
final class SigstoreVectorTests: XCTestCase {
    func testSigstoreVectors() throws {
        let d = try ConformanceTests.load("sigstore-vectors.json")
        let cases = d.get("cases")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 30)
        var facts = 0
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let roots = try PCA.parseSigstoreTrustedRoot(d.get("roots")?.get(c.get("roots")?.asString ?? "") ?? .null)
            let r = PCA.verifySigstoreBundleCore(c.get("bundle") ?? .null, roots: roots)
            let exp = c.get("expect")
            XCTAssertEqual(.bool(r.ok), exp?.get("ok"), "\(name): \(r.code) \(r.detail)")
            if r.ok, exp?.get("ok") == .bool(true) {
                XCTAssertEqual(r.core, exp?.get("core"), name)
                let f = PCA.verifySigstoreBundle(c.get("bundle") ?? .null, roots: roots)
                if f.ok {
                    XCTAssertNil(PCA.provenanceFactsError(f.facts), name)
                    facts += 1
                }
            } else if !r.ok, exp?.get("code") != .string(r.code) {
                XCTFail("\(name): refused with \(r.code) (\(r.detail)), the reference says \(String(describing: exp?.get("code")))")
            }
        }
        print("\(cases.count) sigstore cases replayed, \(facts) produced gate-valid SLSA facts")
    }

    func testSigstoreHostileInput() throws {
        let d = try ConformanceTests.load("sigstore-vectors.json")
        let roots = try PCA.parseSigstoreTrustedRoot(d.get("roots")?.get("public-good-844a1c6d") ?? .null)
        for b: JSONValue in [.null, .array([]), .object([:]), .object(["verificationMaterial": .object([:])])] {
            XCTAssertFalse(PCA.verifySigstoreBundleCore(b, roots: roots).ok)
        }
        // every member of a verifying bundle replaced by junk: refused or verified, never a trap
        guard let ok = (d.get("cases")?.asArray ?? []).first(where: { $0.get("expect")?.get("ok") == .bool(true) })?.get("bundle") else { return XCTFail("no ok case") }
        func mutations(_ v: JSONValue) -> [JSONValue] {
            let junk: [JSONValue] = [.string("AAAA"), .string(""), .int(7), .array([])]
            switch v {
            case let .object(o):
                return o.keys.flatMap { k in junk.map { j in var m = o; m[k] = j; return .object(m) } + mutations(o[k]!).map { var m = o; m[k] = $0; return .object(m) } }
            case let .array(a):
                return a.indices.flatMap { i in junk.map { j in var m = a; m[i] = j; return .array(m) } + mutations(a[i]).map { var m = a; m[i] = $0; return .array(m) } }
            default:
                return []
            }
        }
        for m in mutations(ok) { _ = PCA.verifySigstoreBundleCore(m, roots: roots) }
    }
}
