import XCTest
import Foundation
@testable import AtlasPCAVerify

/// In-flight de-duplication of token refreshes (`SingleFlight`): concurrent callers for one key share one run and its outcome.
final class RefConnectFlightTests: XCTestCase {
    private final class Counter {
        let lock = NSLock()
        var n = 0
        func bump() -> Int { lock.lock(); defer { lock.unlock() }; n += 1; return n }
        var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    }

    /// `n` callers on `n` real threads (a concurrent-perform pool runs only as many as there are cores, so on a small runner the callers would not overlap),
    /// each counted in `entered` just before it calls in. A run waits for every caller to have entered, so the callers overlap whatever the scheduler does.
    private func callers(_ n: Int, entered: Counter, _ body: @escaping () -> Void) {
        let group = DispatchGroup()
        for _ in 0..<n {
            group.enter()
            let t = Thread { _ = entered.bump(); body(); group.leave() }
            t.start()
        }
        group.wait()
    }

    private func awaitCallers(_ n: Int, _ entered: Counter) {
        while entered.value < n { Thread.sleep(forTimeInterval: 0.005) }
        // the last caller has entered; give it time to reach the shared run
        Thread.sleep(forTimeInterval: 0.3)
    }

    func testConcurrentCallersShareOneRun() throws {
        let sf = SingleFlight<String, Int>()
        let runs = Counter()
        let results = Counter()
        let entered = Counter()
        callers(6, entered: entered) {
            let v = try? sf.run("a") { _ = runs.bump(); self.awaitCallers(6, entered); return 42 }
            if v == 42 { _ = results.bump() }
        }
        XCTAssertEqual(runs.n, 1)
        XCTAssertEqual(results.n, 6)
        // after the run ends a new call starts a fresh one; another key never shares
        XCTAssertEqual(try sf.run("a") { _ = runs.bump(); return 7 }, 7)
        XCTAssertEqual(runs.n, 2)
    }

    func testErrorIsSharedAndKeyReleased() throws {
        let sf = SingleFlight<String, Int>()
        let runs = Counter()
        let failures = Counter()
        let entered = Counter()
        callers(4, entered: entered) {
            do { _ = try sf.run("k") { _ = runs.bump(); self.awaitCallers(4, entered); throw JSError("refresh failed") } } catch { _ = failures.bump() }
        }
        XCTAssertEqual(runs.n, 1)
        XCTAssertEqual(failures.n, 4)
        XCTAssertEqual(try sf.run("k") { 1 }, 1)
    }
}

/// `PCASandbox.trustFromAttestation`: only a verifier that says ok AND bound admits the evidence digest into the trust.
final class RefSandboxAttestationTests: XCTestCase {
    struct Stub: HardwareAttestationVerifier {
        let ok: Bool, bound: Bool
        func verify(evidence: JSONValue?, expected: AttestationBinding?, nowMs: Int64) -> HardwareResult { HardwareResult(ok: ok, bound: bound, reason: ok ? "" : "no") }
    }

    func testTrustFromAttestation() throws {
        let doc: JSONValue = .object(["model_id": .string("m"), "nonce": .string("n")])
        let exp = AttestationBinding(holderPub: "h", grantRef: "g", epoch: 1, nonce: "n")
        let digest = try PCASandbox.evidenceDigest(doc)
        for (ok, bound, admitted) in [(true, true, true), (true, false, false), (false, true, false), (false, false, false)] {
            let t = try PCASandbox.trustFromAttestation(document: doc, evidence: nil, verifier: Stub(ok: ok, bound: bound), expected: exp, nowMs: 5, pinnedAttestors: ["a"], passportDigest: "p")
            XCTAssertEqual(t.get("verifiedEvidenceDigests"), .array(admitted ? [.string(digest)] : []))
            XCTAssertEqual(t.get("now"), .int(5))
        }
        // a claim over unadmitted evidence is `none`; over admitted evidence with a pinned attestor it is its class
        let seed = [UInt8](repeating: 3, count: 32)
        let pub = Ed25519Deterministic.publicKey(seed: seed)
        let claim = try PCASandbox.signRuntimeClaim(seed: seed, publicKey: pub, ["class": .string("os_confined"), "passport_digest": .string("p"), "evidence_digest": .string(digest), "iat": .int(1), "exp": .int(100)])
        let attestor = Base64URLStrict.encode(pub)
        let good = try PCASandbox.trustFromAttestation(document: doc, evidence: nil, verifier: Stub(ok: true, bound: true), expected: exp, nowMs: 5, pinnedAttestors: [attestor], passportDigest: "p")
        let bad = try PCASandbox.trustFromAttestation(document: doc, evidence: nil, verifier: Stub(ok: true, bound: false), expected: exp, nowMs: 5, pinnedAttestors: [attestor], passportDigest: "p")
        XCTAssertEqual(PCASandbox.verifiedRuntimeClass(claim, trust: good), "os_confined")
        XCTAssertEqual(PCASandbox.verifiedRuntimeClass(claim, trust: bad), "none")
    }
}
