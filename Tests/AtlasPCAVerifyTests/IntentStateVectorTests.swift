import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The shared intent-state corpus (packages/pca/conformance/intent-state-vectors.json): accumulators, monitors, history windows,
/// pre-states and post-values, sequencer receipts and key sets. The accumulator / receipt / key-set functions run in
/// K042ActionSchemaAccOracleTests (the same cases, from the oracle file); the session-history functions run here, exactly.
final class IntentStateVectorTests: XCTestCase {
    static func cases() throws -> [JSONValue] {
        let d = try ConformanceTests.load("intent-state-vectors.json")
        XCTAssertEqual(d.get("format")?.asString, "pca-intent-state-vectors")
        return d.get("cases")?.asArray ?? []
    }

    /// Functions whose runner lives in K042ActionSchemaAccOracleTests.
    static let OTHER_SUITE: Set<String> = [
        "accumulatorDeclError", "monitorDeclError", "monitorStates", "trackedKeySetError", "preStateError", "preValue", "combineAcc",
        "accSelects", "accValueOf", "receiptArithmeticOk", "pcactnReservationDigest", "receiptShapeError", "keySetShapeError", "verifyKeySet",
        "verifyReceiptSignature", "verifyReceiptAgainstHolder",
    ]

    func run(_ fn: String, _ f: ([JSONValue]) -> JSONValue) throws {
        var bad: [String] = []
        var n = 0
        for c in try Self.cases() where c.get("fn")?.asString == fn {
            n += 1
            let got = f(K042.arr(c.get("args")))
            if K042.canon(got) != K042.canon(c.get("out")) {
                bad.append("\(K042.str(c.get("name")))\n    want \(K042.canon(c.get("out")))\n    got  \(K042.canon(got))")
            }
        }
        XCTAssertGreaterThan(n, 0, "no cases for \(fn)")
        K042.report(bad, n)
    }

    static let THROWS: JSONValue = .object(["throws": .bool(true)])

    func testInWindow() throws {
        try run("inWindow") { a in .bool(IntentHistory.inWindow(a[0], a[1], a[2])) }
    }

    func testAccKeyOf() throws {
        try run("accKeyOf") { a in IntentHistory.accKeyOf(K042.obj(a[0]), K042.obj(a[1])).map { .string($0) } ?? .null }
    }

    func testAccPreState() throws {
        try run("accPreState") { a in
            let cand = K042.obj(a[2])
            return IntentHistory.accPreState(K042.obj(a[0]), K042.arr(a[1]), K042.obj(cand[JKey("params")]), cand[JKey("t")], a[3].isNull ? nil : a[3]) ?? Self.THROWS
        }
    }

    func testAccPost() throws {
        try run("accPost") { a in
            let cand = K042.obj(a[2])
            guard let p = IntentHistory.accPost(K042.obj(a[0]), K042.arr(a[1]), K042.str(cand[JKey("verb")]), K042.obj(cand[JKey("params")]), cand[JKey("t")],
                                                a[3].isNull ? nil : a[3]) else { return Self.THROWS }
            return .double(p)
        }
    }

    func testMonitorStep() throws {
        try run("monitorStep") { a in .string(IntentHistory.monitorStep(K042.obj(a[0]), K042.str(a[1]), K042.obj(a[2]))) }
    }

    func testMonitorState() throws {
        try run("monitorState") { a in .string(IntentHistory.monitorState(K042.obj(a[0]), K042.arr(a[1]))) }
    }

    /// Every function of the corpus file has a runner (a new function without one fails), and the file keeps its size.
    func testCorpusIsFullyRun() throws {
        let known = Self.OTHER_SUITE.union(["inWindow", "accKeyOf", "accPreState", "accPost", "monitorStep", "monitorState"])
        let cs = try Self.cases()
        XCTAssertGreaterThanOrEqual(cs.count, 3000)
        let unknown = Set(cs.compactMap { $0.get("fn")?.asString }).subtracting(known)
        XCTAssertTrue(unknown.isEmpty, "functions without a runner: \(unknown.sorted())")
    }

    // ---- exact outcomes beyond the corpus ----

    func testWindowBoundariesAndMonitorSteps() {
        let sliding: JSONValue = .object(["kind": .string("sliding"), "ms": .int(100)])
        XCTAssertTrue(IntentHistory.inWindow(sliding, .int(101), .int(200)))   // (t-ms, t]: 101 is inside
        XCTAssertFalse(IntentHistory.inWindow(sliding, .int(100), .int(200)))  // t-ms is outside
        XCTAssertTrue(IntentHistory.inWindow(sliding, .int(201), .int(200)))   // later than t: not left any window
        XCTAssertFalse(IntentHistory.inWindow(sliding, .double(1.5), .int(200)))
        XCTAssertFalse(IntentHistory.inWindow(.object(["kind": .string("nope")]), .int(1), .int(2)))
        let m: JObject = ["kind": .string("responds_within"), "within": .int(2), "p": .object(["verb": .string("a"), "resource": .string("*")]), "q": .object(["verb": .string("b"), "resource": .string("*")])]
        func ev(_ verb: String) -> JObject { ["verb": .string(verb), "resource": .string("r"), "params": .object([:]), "status": .string("committed")] }
        XCTAssertEqual(IntentHistory.monitorStep(m, "idle", ev("a")), "pending:2")
        XCTAssertEqual(IntentHistory.monitorStep(m, "pending:2", ev("x")), "pending:1")
        XCTAssertEqual(IntentHistory.monitorStep(m, "pending:1", ev("x")), "missed")
        XCTAssertEqual(IntentHistory.monitorStep(m, "pending:2", ev("b")), "idle")
        XCTAssertEqual(IntentHistory.monitorStep(m, "missed", ev("b")), "missed")
        var reserved = ev("a")
        reserved["status"] = .string("released")
        XCTAssertEqual(IntentHistory.monitorStep(m, "idle", reserved), "idle") // a status that does not count changes nothing
    }
}
