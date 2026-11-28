import XCTest
import Foundation
@testable import AtlasPCAVerify

/// `PCATesting.runAdapterAcceptance`: the shared adapter matrix, run end to end through `PCA.authorize` (the pipeline every adapter wraps).
/// No corpus: the matrix mints its own proofs over fresh keys, and its expected outcomes are the reference's `ADAPTER_ACCEPTANCE_EXPECTED`.
final class RefTestingAcceptanceTests: XCTestCase {
    final class Counter { var n = 0 }

    /// The simplest adapter: map the request, hand the headers to `PCA.authorize`, answer 200 or 403; the "handler" runs on an allow.
    static func harness(_ handlerRuns: Counter) -> PCATesting.AcceptanceHarness {
        { options in
            { req in
                guard let op = try options.operation(req) else { return PCATesting.AcceptanceObservation(status: 403, handlerRan: false) }
                var input = options.input
                input.operation = op
                input.provenanceHeader = req.headers["PCA-Provenance"]
                let text = req.headers[PCAAgent.HEADER].flatMap { Base64URLStrict.decode($0) }.map { String(decoding: $0, as: UTF8.self) }
                let r = PCA.authorize(json: text, input)
                if r.allow { handlerRuns.n += 1 }
                return PCATesting.AcceptanceObservation(status: r.allow ? 200 : 403, handlerRan: r.allow, operation: r.operation)
            }
        }
    }

    func testTheMatrixThroughAuthorize() throws {
        let runs = Counter()
        let got = try PCATesting.runAdapterAcceptance(Self.harness(runs))
        XCTAssertEqual(got.map { $0.name }, PCATesting.ADAPTER_ACCEPTANCE_EXPECTED.map { $0.name })
        for (g, e) in zip(got, PCATesting.ADAPTER_ACCEPTANCE_EXPECTED) { XCTAssertEqual(g.outcome, e.outcome, g.name) }
        XCTAssertEqual(runs.n, 1, "only valid_first runs the handler")
    }

    func testAnAdapterRefusedAtConstructionIsARefusal() throws {
        struct Refused: Error {}
        let got = try PCATesting.runAdapterAcceptance { _ in throw Refused() }
        XCTAssertEqual(got.count, PCATesting.ADAPTER_ACCEPTANCE_EXPECTED.count)
        // fail closed: nothing ran, nothing is bound; only the allow rows differ from the reference's answer
        for g in got { XCTAssertFalse(g.outcome.handlerRan, g.name); XCTAssertFalse(g.outcome.bound, g.name); XCTAssertEqual(g.outcome.status, 403, g.name) }
    }

    func testAnAdapterThatAllowsEverythingFailsTheMatrix() throws {
        let got = try PCATesting.runAdapterAcceptance { _ in { _ in PCATesting.AcceptanceObservation(status: 200, handlerRan: true) } }
        let bad = zip(got, PCATesting.ADAPTER_ACCEPTANCE_EXPECTED).filter { $0.outcome != $1.outcome }.map { $0.0.name }
        XCTAssertEqual(bad.count, PCATesting.ADAPTER_ACCEPTANCE_EXPECTED.count, "every refusal row is caught; an allow with no bound operation never reads as bound")
    }
}
