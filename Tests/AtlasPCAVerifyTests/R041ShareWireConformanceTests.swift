import XCTest
import Foundation
@testable import AtlasPCAVerify

/// PCA 0.4.1: threshold share signatures are validated PER SUITE at the wire stage (reference: validateShareSignatureWire in
/// packages/pca/src/pq.ts, vectors `r041-share-*`). A pure ML-DSA-65 share (3309-byte `sig`) is now carried; wrong lengths, a
/// missing hybrid `pq_sig`, a stray `pq_sig`, an unknown / non-string / null `alg` are wire failures. Vectors that require a
/// suite Swift does not implement (ml-dsa-87, slh-dsa-sha2-128f) are skipped.
final class R041ShareWireConformanceTests: XCTestCase {
    func testShareWireVectors() throws {
        let doc = try ConformanceTests.loadCorpus()
        var ran = 0
        var failures: [String] = []
        for v in doc.get("vectors")?.asArray ?? [] {
            guard let name = v.get("name")?.asString, name.hasPrefix("r041-share-") else { continue }
            if let req = v.get("requires")?.asString, !ConformanceTests.SUPPORTED_SUITES.contains(req) { continue }
            ran += 1
            guard let now = v.get("context")?.get("now")?.safeInt, let aud = v.get("context")?.get("aud")?.asString,
                  case let .bool(wantAllow)? = v.get("expect")?.get("allow"),
                  let wantChecks = v.get("expect")?.get("checks")?.asObject else { failures.append("\(name): malformed"); continue }
            let got = PCA.verify(pcactn: v.get("pcactn") ?? .null, grant: v.get("grant") ?? .null, now: now, audience: aud)
            if got.allow != wantAllow { failures.append("\(name): allow = \(got.allow) (\(got.reason))") }
            for (k, w) in wantChecks {
                if case let .bool(b) = w, got.checks[k.s] != b { failures.append("\(name): check \(k.s) (\(got.reason))") }
            }
        }
        XCTAssertEqual(ran, 18)
        XCTAssertTrue(failures.isEmpty, "\(failures.count) failure(s) over \(ran) r041-share vectors:\n" + failures.joined(separator: "\n"))
        if failures.isEmpty { print("PCA conformance r041-share: \(ran)/\(ran) vectors pass") }
    }
}
