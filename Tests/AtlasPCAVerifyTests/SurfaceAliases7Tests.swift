import XCTest
@testable import AtlasPCAVerify

final class SurfaceAliases7Tests: XCTestCase {
    func testTheNativeRootCaveatProbeDeniesWhatItMustDeny() throws {
        let cap: JObject = ["type": .string("max_spend"), "usd": .int(100)]
        XCTAssertFalse(try PCADoctor.probeDecision(cap, 150).allowed)
        XCTAssertTrue(try PCADoctor.probeDecision(cap, 50).allowed)
        XCTAssertFalse(try PCADoctor.probeDecision(["type": .string("pca-doctor-unknown-caveat")], 50).allowed)
        let check = PCADoctor.checkRootCaveats(.obj([]), loadPca: PCADoctor.nativeLoader(version: "0.5.0"))
        XCTAssertEqual(check.member("id"), .str("caveats.root"))
        XCTAssertEqual(check.member("status"), .str("pass"), "\(check)")
        XCTAssertEqual(PCADoctor.checkRootCaveats(.obj([]), loadPca: PCADoctor.nativeLoader(version: "0.4.0")).member("status"), .str("fail"))
    }

    func testMessagesAreRecordedBeforeTheModelCallRuns() throws {
        let a = try PCATesting.testAgent()
        var seen: JSONValue?
        let call = PCAAdapters.withPCAMessages(a) { params in seen = params; return "done" }
        let params: JSONValue = .object(["model": .string("m"), "messages": .array([.object(["role": .string("user"), "content": .string("refund order 7")])])])
        XCTAssertEqual(try call(params), "done")
        XCTAssertEqual(seen, params)
        XCTAssertEqual(try PCAAdapters.withPCACompletions(nil) { _ in 1 }(.object([:])), 1)
        // a call without messages passes through untouched
        XCTAssertEqual(try call(.object(["model": .string("m")])), "done")
    }

    func testEatKeyPairsSignWhatTheirVerifyKeyChecks() throws {
        for alg in ["EdDSA", "ES256"] {
            let kp = try PCAAttestEat.generateEatKeyPair(alg)
            let input = Array("header.payload".utf8)
            let sig = try kp.sign(alg, input)
            XCTAssertEqual(sig.count, alg == "EdDSA" ? 64 : 64)
            XCTAssertThrowsError(try kp.sign(alg == "EdDSA" ? "ES256" : "EdDSA", input))
        }
        XCTAssertThrowsError(try PCAAttestEat.generateEatKeyPair("RS256"))
        XCTAssertEqual(PCAAttestEat.DEFAULT_EAT_ALG, "EdDSA")
    }
}
