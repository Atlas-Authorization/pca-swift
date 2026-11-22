import XCTest
import Foundation
@testable import AtlasPCAVerify

/// The lease and break-glass registries and the provenance recorder take their lock once per call and release it (see S2LK.check).
final class S2LKRegistryLockTests: XCTestCase {
    typealias J = JSONValue

    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    // Lease.swift: Registry.accept (153), revoke (198), get (208), history (214), checkLease (234)
    func testLeaseRegistry() throws {
        let doc = try ConformanceTests.load("lease-vectors.json")
        let records = doc.get("records")?.asArray ?? []
        let authority = doc.get("authority")?.asString ?? ""
        let valid = try XCTUnwrap(records.first { Lease.verifyLease($0) }, "a verifiable lease record")
        // the registry's atomicity is the store's: each store call takes the kv lock once (the first real call also pins the shard count)
        let kv = MemoryAtomicKV()
        let reg = try Lease.Registry(policy: Lease.Policy(authorities: [authority]), kv: kv)
        S2LK.check(kv.lock, "accept (malformed): no store call", expect: 0) { _ = reg.accept(J.null) }
        S2LK.check(kv.lock, "accept (a real record): meta pin + shard update", expect: 2) { _ = reg.accept(valid) }
        S2LK.check(kv.lock, "revoke (malformed): no store call", expect: 0) { _ = reg.revoke(J.null) }
        S2LK.check(kv.lock, "get") { _ = reg.get("nope") }
        S2LK.check(kv.lock, "history") { _ = reg.history("nope") }
        S2LK.check(kv.lock, "checkLease") { _ = Lease.checkLease(valid, registry: reg, now: J.int(1)) }
    }

    // BreakGlass.swift: Registry.accept (98), use (117), review (140), frozen (164)
    func testBreakGlassRegistry() {
        let kv = MemoryAtomicKV()
        let reg = try! BreakGlass.Registry(policy: BreakGlass.Policy(authorities: ["a"], reviewers: ["r"]), kv: kv)
        // malformed input is refused before any store call
        S2LK.check(kv.lock, "accept", expect: 0) { _ = reg.accept(J.null, now: J.int(1)) }
        S2LK.check(kv.lock, "use", expect: 0) { _ = reg.use(id: J.null, holder: J.null, actionDigest: J.null, now: J.null, notified: J.null) }
        S2LK.check(kv.lock, "review", expect: 0) { _ = reg.review(J.null, holder: J.null, now: J.null) }
        S2LK.check(kv.lock, "frozen", expect: 0) { _ = reg.frozen(holder: J.null, now: J.null) }
    }

    // ArgProvenance.swift: ProvenanceRecorder segment (546), forAction (565), receipts (581)
    func testProvenanceRecorder() throws {
        let r = try ProvenanceRecorder(mediator: "m", kid: "k", secretKey: [UInt8](repeating: 1, count: 32))
        try S2LK.check(r.lock, "principal") { _ = try r.principal("hello") }
        try S2LK.check(r.lock, "tool") { _ = try r.tool("t", "out") }
        try S2LK.check(r.lock, "retrieval") { _ = try r.retrieval("s", "doc") }
        try S2LK.check(r.lock, "web") { _ = try r.web("https://x", "page") }
        try S2LK.check(r.lock, "forAction") { _ = try r.forAction(PCA.Operation(verb: "v", resource: "r", params: J.object([:]))) }
        XCTAssertEqual(S2LK.check(r.lock, "receipts") { r.receipts() }.count, 5)
    }
}
