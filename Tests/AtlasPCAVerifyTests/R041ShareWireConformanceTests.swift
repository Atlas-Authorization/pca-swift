import XCTest
import Foundation
@testable import AtlasPCAVerify

/// PCA 0.4.1: threshold share signatures are validated PER SUITE at the wire stage (reference: validateShareSignatureWire in
/// packages/pca/src/pq.ts, vectors `r041-share-*`). A pure ML-DSA-65 share (3309-byte `sig`) is now carried; wrong lengths, a
/// missing hybrid `pq_sig`, a stray `pq_sig`, an unknown / non-string / null `alg` are wire failures.
///
/// Suite capability (conformance README, `requires`): a VALID entry (`expect.allow` true) whose `requires` suite (or, for an
/// untagged entry, a registered share `alg`) this host cannot verify — slh-dsa always, ml-dsa-87 when CryptoKit lacks it,
/// every ML-DSA suite before macOS / iOS 26 — must be REFUSED with `unsupported_suite` (fail closed) and is counted, never
/// compared. Expected-invalid entries are suite-agnostic wire negatives and ALWAYS run and compare.
final class R041ShareWireConformanceTests: XCTestCase {
    func testShareWireVectors() throws {
        let doc = try ConformanceTests.loadCorpus()
        var total = 0, ran = 0, refusedBySuite = 0
        var refusedSuites: [String] = []
        var failures: [String] = []
        for v in doc.get("vectors")?.asArray ?? [] {
            guard let name = v.get("name")?.asString, name.hasPrefix("r041-share-") else { continue }
            total += 1
            guard let now = v.get("context")?.get("now")?.safeInt, let aud = v.get("context")?.get("aud")?.asString,
                  case let .bool(wantAllow)? = v.get("expect")?.get("allow"),
                  let wantChecks = v.get("expect")?.get("checks")?.asObject else { failures.append("\(name): malformed"); continue }
            let got = PCA.verify(pcactn: v.get("pcactn") ?? .null, grant: v.get("grant") ?? .null, now: now, audience: aud)
            if wantAllow {
                let shareAlgs = (v.get("pcactn")?.get("threshold")?.get("shares")?.asArray ?? []).compactMap { $0.get("alg")?.asString }
                let lacking: String?
                if let req = v.get("requires")?.asString, !req.isEmpty, !ConformanceTests.SUPPORTED_SUITES.contains(req) {
                    lacking = req
                } else {
                    lacking = shareAlgs.first(where: ConformanceTests.lacksRegisteredSuite)
                }
                if let a = lacking {
                    if got.allow || !got.reason.contains(PCASuites.unsupportedSuiteReason) {
                        failures.append("\(name): suite \(a) not on this host: want an unsupported_suite refusal (allow=\(got.allow), \(got.reason))")
                    }
                    refusedBySuite += 1
                    refusedSuites.append(a)
                    continue
                }
            }
            ran += 1
            if got.allow != wantAllow { failures.append("\(name): allow = \(got.allow) (\(got.reason))") }
            for (k, w) in wantChecks {
                if case let .bool(b) = w, got.checks[k.s] != b { failures.append("\(name): check \(k.s) (\(got.reason))") }
            }
        }
        // every r041-share entry is either compared or refused-and-counted: 6 positives + 14 wire negatives
        XCTAssertEqual(total, 20)
        XCTAssertEqual(ran + refusedBySuite, total)
        XCTAssertGreaterThanOrEqual(ran, 14, "the 14 expected-invalid wire negatives always run")
        // a refusal is only ever for a suite this host lacks (with ML-DSA-65 present its positives must be compared)
        for a in refusedSuites { XCTAssertFalse(ConformanceTests.SUPPORTED_SUITES.contains(a), "refused a supported suite \(a)") }
        if ConformanceTests.SUPPORTED_SUITES.contains("ml-dsa-65") {
            XCTAssertFalse(refusedSuites.contains { $0.hasSuffix("ml-dsa-65") }, "ML-DSA-65 is supported but its positives were refused")
        }
        XCTAssertTrue(failures.isEmpty, "\(failures.count) failure(s) over \(total) r041-share vectors:\n" + failures.joined(separator: "\n"))
        if failures.isEmpty {
            print("PCA conformance r041-share: \(ran) compared, \(refusedBySuite) refused unsupported_suite (\(refusedSuites.joined(separator: ", ")))")
        }
    }
}
