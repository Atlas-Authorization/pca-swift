import XCTest
import Foundation
import AtlasPCAVerify
import AtlasPCAMpc
@testable import AtlasPCAMpcNet

/// The networked SPDZ-style protocol over loopback mutual TLS, in both offline modes (trusted dealer and no dealer), checked against the in-process
/// engine and the cleartext composition, with the refusals of lying dealers and lying parties.
final class NetProtocolTests: XCTestCase {
    typealias S = NetTestSupport
    static let Q = 4
    static let inputs = [DecisionVector(allow: 1, t: 1, rQuant: 1), DecisionVector(allow: 1, t: 2, rQuant: 3), DecisionVector(allow: 1, t: 1, rQuant: 2)]

    private func opts(_ behaviors: [Int: Behavior] = [:]) -> LaunchOptions {
        var o = LaunchOptions(n: 3, vectors: NetProtocolTests.inputs)
        o.Q = NetProtocolTests.Q
        o.recvTimeoutMs = 60_000
        o.killAfterMs = 240_000
        o.behaviors = behaviors
        o.identitySeed = Array("atlas-pca-mpc-net-protocol".utf8)
        return o
    }

    private func dealerOpts(_ behaviors: [Int: Behavior] = [:]) -> LaunchOptions {
        var o = opts(behaviors)
        o.offline = "trusted-dealer"
        o.insecureTrustedDealer = true
        o.dealerSeed = 7
        o.recvTimeoutMs = 30_000
        return o
    }

    private func engine() throws -> DecisionVector {
        var rc = PCAMpc.MaliciousConfig()
        rc.Q = NetProtocolTests.Q
        rc.seed = 1
        rc.insecureTrustedDealer = true
        return try PCAMpc.composeSecureMalicious(NetProtocolTests.inputs, rc).composed
    }

    private func assertAgreement(_ l: Launched, mode: String, parties: Int) throws {
        let clear = try PCAMpc.composeClear(NetProtocolTests.inputs, NetProtocolTests.Q)
        XCTAssertEqual(clear, try engine())
        var digest: String?
        var seen = 0
        for o in l.outputs where o.role == "party" {
            XCTAssertNil(o.error, String(describing: o.error))
            XCTAssertEqual(o.result?.composed, clear)
            XCTAssertEqual(o.result?.offlineMode, mode)
            XCTAssertEqual(o.result?.identifiableAbort, true)
            if digest == nil { digest = o.result?.transcriptDigest }
            XCTAssertEqual(o.result?.transcriptDigest, digest)
            seen += 1
        }
        XCTAssertEqual(seen, parties)
    }

    /// Every node's outcome on one line each, so a failed assertion says what each party ended with (and whether the launcher cut it off).
    private func outcomes(_ l: Launched) -> String {
        "wall \(l.wallMs)ms; " + l.outputs.map { (o: NodeOutput) -> String in
            let end: String
            if let a = o.abort {
                end = "abort kind=\(a.kind) blamed=\(a.blamed.map { String($0) } ?? "none") reporter=\(a.reporter) claimed=\(a.claimedKind ?? "-")/\(a.claimedBlame.map { String($0) } ?? "-")"
                    + "\(a.message.contains("killed after") ? " KILLED-BY-LAUNCHER" : "") detail=\(a.message)"
            } else if let e = o.error {
                end = "error \(type(of: e)): \(e)"
            } else {
                end = "no error"
            }
            return "node \(o.id) (\(o.role)): result=\(o.result == nil ? "none" : "present") \(end)"
        }.joined(separator: " | ")
    }

    /// Nobody produced output, and some honest node named `blamed` with `kind`.
    private func assertNamed(_ l: Launched, _ kind: String, _ blamed: Int, file: StaticString = #filePath, line: UInt = #line) {
        var named = false
        for o in l.outputs where o.role == "party" {
            XCTAssertNil(o.result, "no party may produce output: \(outcomes(l))", file: file, line: line)
            if let a = o.abort, a.kind == kind, a.blamed == blamed { named = true }
        }
        XCTAssertTrue(named, "an honest party names party \(blamed) with kind \(kind): \(outcomes(l))", file: file, line: line)
    }

    func testDealerModeAgreesWithTheInProcessEngine() throws {
        let l = try NetLaunch.launch(dealerOpts())
        XCTAssertEqual(l.outputs.count, 4)
        try assertAgreement(l, mode: "trusted-dealer", parties: 3)
    }

    func testNoDealerAgreesWithTheInProcessEngine() throws {
        let l = try NetLaunch.launch(opts())
        XCTAssertEqual(l.outputs.count, 3)
        try assertAgreement(l, mode: "no-dealer", parties: 3)
    }

    func testAWrongProductFromTheDealerIsDetectedAndBlamed() throws {
        var o = dealerOpts()
        o.dealerFault = PCAMpc.Spdz.DealerFault(keepCDelta: 1, partnerCDelta: nil)
        assertNamed(try NetLaunch.launch(o), "dealer", 3)
    }

    func testALyingOpenedShareIsNamedByItsPairwiseTag() throws {
        assertNamed(try NetLaunch.launch(dealerOpts([1: Behavior(kind: "open-lie", round: "mul0")])), "mac-check", 1)
    }

    func testANonCanonicalFieldElementIsRefused() throws {
        assertNamed(try NetLaunch.launch(dealerOpts([2: Behavior(kind: "noncanonical", round: "mul0")])), "malformed", 2)
    }

    func testAWrongOtOperandInATripleProductIsCaughtByTheSacrificeAndAttributed() throws {
        assertNamed(try NetLaunch.launch(opts([1: Behavior(kind: "offline-lie", round: "")])), "mac-check", 1)
    }

    func testAnInconsistentOtExtensionMatrixIsCaughtByTheKosCheck() throws {
        assertNamed(try NetLaunch.launch(opts([2: Behavior(kind: "ot-u-lie", round: "")])), "ot-check", 2)
    }

    func testABadBaseOtProofIsRefused() throws {
        assertNamed(try NetLaunch.launch(opts([1: Behavior(kind: "ot-proof-lie", round: "")])), "ot-check", 1)
    }

    func testASilentPartyIsBlamedByTimeout() throws {
        var o = opts([2: Behavior(kind: "silent", round: "in-share")])
        o.recvTimeoutMs = 15_000
        o.killAfterMs = 120_000
        let l = try NetLaunch.launch(o)
        var named = false
        for out in l.outputs {
            XCTAssertNil(out.result)
            if let a = out.abort, a.kind == "timeout", a.blamed == 2 { named = true }
        }
        XCTAssertTrue(named)
    }

    func testTestHooksAndDealerOptInAreEnforcedBeforeAnyTraffic() throws {
        // a node that never connects: the checks run before the first message
        let id = try S.identity("solo")
        let mesh = try AtlasPCAMpcNet.Mesh(S.cfg(0, [NodeAddr(id: 0, host: "127.0.0.1", port: 1, certPem: id.certPem)], id, connectMs: 100, recvMs: 100))
        var c = PartyConfig(id: 0, n: 3, input: NetProtocolTests.inputs[0], mesh: mesh, sessionId: "s")
        c.Q = NetProtocolTests.Q
        c.offline = "trusted-dealer"
        XCTAssertEqual(S.abort(S.thrown { try NetProtocol.runParty(c) })?.kind, "local")
        c.insecureTrustedDealer = true
        c.behavior = Behavior(kind: "open-lie", round: "out")
        XCTAssertEqual(S.abort(S.thrown { try NetProtocol.runParty(c) })?.kind, "local")
        XCTAssertThrowsError(try NetProtocol.runDealer(DealerConfig(n: 3, mesh: mesh)))
        var bad = opts()
        bad.offline = "trusted-dealer"
        bad.insecureTrustedDealer = false
        XCTAssertThrowsError(try NetLaunch.launch(bad))
    }

    func testANodeRefusesToStartWithTestHooksOutsideATestEnvironment() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("node-cfg-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let f = dir.appendingPathComponent("c.json")
        try Data("{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"behavior\":{\"kind\":\"crash\",\"round\":\"out\"}}".utf8).write(to: f)
        XCTAssertEqual(NetPartyMain.run([f.path], env: [:]), 3)
        try Data("{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"frameFault\":{}}".utf8).write(to: f)
        XCTAssertEqual(NetPartyMain.run([f.path], env: ["PCA_MPC_UNSAFE_TEST_HOOKS": "1"]), 3)
    }
}
