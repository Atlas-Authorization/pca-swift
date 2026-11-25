import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The server-side helpers of the undo ledger: the veto relay, the notifier over the approval channels, the configuration check and the effect report.
final class UndoServerTests: XCTestCase {
    typealias U = PCAUndoServer

    func testMissingComponents() {
        XCTAssertEqual(U.missingUndoComponents(store: nil, hasEngine: false, signerSecret: [1], audience: "", hasResolveGrant: false, hasCompensate: false, hasOperations: false,
                                               hasNotifier: false, hasAlert: false),
                       ["store", "engine", "signerSecret", "audience", "resolveGrant", "compensate", "operations", "notifier", "alert"])
        XCTAssertEqual(U.missingUndoComponents(store: MemoryUndoStore(), hasEngine: true, signerSecret: [UInt8](repeating: 1, count: 32), audience: "a", hasResolveGrant: true, hasCompensate: true,
                                               hasOperations: true, hasNotifier: true, hasAlert: true), [])
        XCTAssertEqual(U.UNDO_RELAY_GRACE_MS, 60_000)
    }

    func testSignerPublicIsTheKeyId() throws {
        let seed = [UInt8](repeating: 7, count: 32)
        XCTAssertEqual(try U.undoSignerPublic(secret: seed), try PCAEdKey(seed: seed).id)
    }

    final class Sink: U.EffectSink {
        var calls: [String] = []
        func recordEffect(_ id: String, result: JSONValue?) -> JSONValue { calls.append("effect:\(id)"); return .string("rec") }
        func abort(_ id: String, reason: String) -> JSONValue { calls.append("abort:\(id):\(reason)"); return .string("rec") }
        func get(_ id: String) -> JSONValue? { calls.append("get:\(id)"); return id == "gone" ? nil : .string("rec") }
    }

    func testReportEffect() throws {
        let s = Sink()
        _ = try U.reportUndoEffect(s, id: "a", status: "committed")
        _ = try U.reportUndoEffect(s, id: "b", status: "failed")
        _ = try U.reportUndoEffect(s, id: "c", status: "uncertain")
        XCTAssertEqual(s.calls, ["effect:a", "abort:b:effect_failed", "get:c"])
        XCTAssertThrowsError(try U.reportUndoEffect(s, id: "gone", status: "pending")) { XCTAssertEqual(($0 as? UndoError)?.code, "invalid") }
    }

    func testRelayReadsPendingVetoesAndFailsClosed() throws {
        var seen: [(String, [String: String])] = []
        let ok = U.hostedUndoVetoRelay(baseUrl: "https://x.example//", secretKey: "sk", limit: 1000) { url, h in
            seen.append((url, h))
            return (200, JSONValue.parse(#"{"data":[{"record_id":"r1","veto":{"token":"t","at":5}}]}"#))
        }
        XCTAssertEqual(try ok(), [U.RelayedVeto(id: "r1", token: "t", at: 5)])
        XCTAssertEqual(seen[0].0, "https://x.example/v1/pca/undo/vetoes?limit=200")
        XCTAssertEqual(seen[0].1["authorization"], "Bearer sk")
        XCTAssertThrowsError(try U.hostedUndoVetoRelay(baseUrl: "https://x", secretKey: "k") { _, _ in (500, nil) }())
        XCTAssertThrowsError(try U.hostedUndoVetoRelay(baseUrl: "https://x", secretKey: "k") { _, _ in (200, JSONValue.parse(#"{"data":[{"record_id":1}]}"#)) }())
        XCTAssertThrowsError(try U.hostedUndoVetoRelay(baseUrl: "https://x", secretKey: "k") { _, _ in (200, JSONValue.parse("{}")) }())
    }

    func testNotifierBuildsAStepUpShapedNoticeAndReportsDelivery() throws {
        var bodies: [String] = []
        let ch = PCAApprovalChannels.slackApprovalChannel(webhookUrl: "https://hooks.example/s") { _, _, body in bodies.append(body); return 200 }
        let n = U.undoNotifierFromDispatcher(PCAApprovalChannels.createApprovalDispatcher([ch]), undoUrl: { t, id in "https://u.example/\(id)?t=\(t)" })
        let rec: JSONValue = JSONValue.parse(#"{"id":"r1","action":{"verb":"pay","resource":"acct/1"},"compensation":{"verb":"refund"},"window_end":1700000000000,"opened_at":1}"#)!
        let r = n(.object(["kind": .string("opened"), "record": rec, "token": .string("tok")]))
        XCTAssertEqual(r.get("delivered"), .bool(true))
        XCTAssertTrue(bodies[0].contains("https://u.example/r1?t=tok"))
        XCTAssertTrue(bodies[0].contains("Already done: pay on acct/1. You can undo it until 2023-11-14T22:13:20.000Z."))
        let none = U.undoNotifierFromDispatcher(PCAApprovalChannels.createApprovalDispatcher([]), undoUrl: { _, _ in "" })
        XCTAssertEqual(none(.object(["kind": .string("finalized"), "record": rec])).get("reason"), .string("no enabled channel"))
    }
}
