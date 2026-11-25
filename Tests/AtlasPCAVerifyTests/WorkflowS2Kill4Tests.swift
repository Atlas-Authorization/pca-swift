import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto
#endif
@testable import AtlasPCAVerify

/// K5 workflow admission (packages/pca/src/workflow.ts): the name patterns, the shape limits (WORKFLOW_LIMITS), the DAG walk, and the
/// boundaries of the clock, the receipt chain and the per-edge relations.
final class S2G4WorkflowKillTests: XCTestCase {
    typealias J = JSONValue

    func rep(_ c: Character, _ n: Int) -> String { String(repeating: String(c), count: n) }
    func b32(_ n: UInt8) -> String { Base64URLStrict.encode([UInt8](repeating: n, count: 32)) }

    // ---- name patterns ----

    func testByteClasses() {
        let alnum: [UInt8] = [0x30, 0x39, 0x41, 0x5A, 0x61, 0x7A]
        let notAlnum: [UInt8] = [0x2F, 0x3A, 0x40, 0x5B, 0x60, 0x7B, 0x00, 0xFF]
        for c in alnum { XCTAssertTrue(K5.alnum(c), "alnum \(c)") }
        for c in notAlnum { XCTAssertFalse(K5.alnum(c), "not alnum \(c)") }
        let lower: [UInt8] = [0x30, 0x39, 0x61, 0x7A]
        let notLower: [UInt8] = [0x2F, 0x3A, 0x40, 0x41, 0x5A, 0x5B, 0x60, 0x7B, 0x00, 0xFF]
        for c in lower { XCTAssertTrue(K5.lowerDigit(c), "lowerDigit \(c)") }
        for c in notLower { XCTAssertFalse(K5.lowerDigit(c), "not lowerDigit \(c)") }
    }

    func testIdPattern() {
        for ok in ["a", "Z", "0", "9", "_", ".", ":", "-", "a-b_c.d:e", rep("a", 64)] { XCTAssertTrue(K5.isId(ok), ok) }
        for bad in ["", "/", " ", "@", "[", "`", "{", "!", "\u{e9}", rep("a", 65), "__proto__"] { XCTAssertFalse(K5.isId(bad), bad) }
        XCTAssertTrue(K5.isId("__proto__x"))
    }

    func testLabelPattern() {
        for ok in ["a", "z", "0", "9", "_", ".", ":", "-", "a-b_c.d:e", rep("a", 64)] { XCTAssertTrue(K5.isLabel(ok), ok) }
        for bad in ["", "A", "Z", "/", " ", "@", "[", "`", "{", "!", rep("a", 65), "__proto__"] { XCTAssertFalse(K5.isLabel(bad), bad) }
    }

    func testNamePattern() {
        for ok in ["a", "Z", "0", "9", "_", ".", "-", "a-b_c.d", rep("a", 64)] { XCTAssertTrue(K5.isName(ok), ok) }
        for bad in ["", ":", "/", " ", "@", "[", "`", "{", "!", rep("a", 65), "__proto__"] { XCTAssertFalse(K5.isName(bad), bad) }
    }

    func testUnitPattern() {
        for ok in ["a", "Z", "0", "9", "_", ".", ":", "-", "a-b_c.d:e", rep("a", 16)] { XCTAssertTrue(K5.isUnit(ok), ok) }
        for bad in ["", "/", " ", "@", "[", "`", "{", "!", rep("a", 17)] { XCTAssertFalse(K5.isUnit(bad), bad) }
    }

    // ---- integers and scalar maps ----

    func testUnsignedAndScalarBounds() {
        let m = Canonical.MAX_SAFE
        XCTAssertEqual(K5.uint(J.int(m)), m)
        XCTAssertEqual(K5.uint(J.int(0)), 0)
        XCTAssertNil(K5.uint(J.int(m + 1)))
        XCTAssertNil(K5.uint(J.int(-1)))
        XCTAssertTrue(K5.isScalar(J.int(m)))
        XCTAssertTrue(K5.isScalar(J.int(-m)))
        XCTAssertFalse(K5.isScalar(J.int(m + 1)))
        XCTAssertFalse(K5.isScalar(J.int(-m - 1)))
        XCTAssertTrue(K5.isScalar(J.string("")))
        XCTAssertTrue(K5.isScalar(J.bool(false)))
        XCTAssertFalse(K5.isScalar(J.null))
    }

    func obj(_ n: Int, _ v: JSONValue) -> JSONValue {
        var o: JObject = [:]
        for i in 0..<n { o[JKey("k" + (i < 10 ? "0" : "") + String(i))] = v }
        return JSONValue.object(o)
    }

    func testMapSizeLimits() {
        XCTAssertEqual(Workflow.FIELDS, 32)
        XCTAssertNotNil(K5.scalarMap(obj(32, J.int(1))))
        XCTAssertNil(K5.scalarMap(obj(33, J.int(1))))
        XCTAssertNotNil(K5.uintMap(obj(3, J.int(1)), 3))
        XCTAssertNil(K5.uintMap(obj(4, J.int(1)), 3))
        XCTAssertNotNil(K5.uintMap(obj(Workflow.COST, J.int(1)), Workflow.COST))
        XCTAssertNil(K5.uintMap(obj(Workflow.COST + 1, J.int(1)), Workflow.COST))
    }

    func testLimitConstants() {
        XCTAssertEqual(Workflow.STEPS, 64)
        XCTAssertEqual(Workflow.EDGES, 256)
        XCTAssertEqual(Workflow.DEPS, 16)
        XCTAssertEqual(Workflow.LABELS, 16)
        XCTAssertEqual(Workflow.FIELDS, 32)
        XCTAssertEqual(Workflow.COST, 8)
    }

    // ---- builders ----

    func step(_ id: String, deps: [String] = [], over: JObject = [:]) -> JSONValue {
        var s: JObject = [
            "id": J.string(id), "verb": J.string("v"), "resource": J.string("r"), "params_digest": J.null, "deps": J.array(deps.map { J.string($0) }),
            "sink": J.null, "deny_labels": J.array([]), "escalate_labels": J.array([]), "fresh_ms": J.null, "cost": J.object([:]),
        ]
        for (k, v) in over { s[k] = v }
        return JSONValue.object(s)
    }

    func edge(_ from: String, _ to: String, op: String = "eq", over: JObject = [:]) -> JSONValue {
        var e: JObject = [
            "from": J.object(["step": J.string(from), "field": J.string("out")]), "to": J.object(["step": J.string(to), "param": J.string("p")]),
            "op": J.string(op), "unit": J.null, "deny_labels": J.array([]), "promise": J.null,
        ]
        for (k, v) in over { e[k] = v }
        return JSONValue.object(e)
    }

    func body(_ principal: String, _ steps: [JSONValue], _ edges: [JSONValue] = [], issued: Int64 = 100, expires: Int64 = 1000, planRoot: JSONValue = J.null,
              caps: JObject = [:]) -> JSONValue {
        JSONValue.object([
            "v": J.int(1), "id": J.string("wf1"), "principal": J.string(principal), "goal_digest": J.null, "plan_root": planRoot, "issued_at": J.int(issued),
            "expires_at": J.int(expires), "steps": J.array(steps), "edges": J.array(edges),
            "budget": J.object(["max_steps": J.int(10), "caps": J.object(caps)]),
        ])
    }

    func ids(_ n: Int) -> [String] { (0..<n).map { "s" + ($0 < 10 ? "0" : "") + String($0) } }

    // ---- shape limits ----

    func testStepAndEdgeCounts() {
        let p = b32(1)
        XCTAssertNotNil(WfBody.parse(body(p, ids(64).map { step($0) })), "64 steps")
        XCTAssertNil(WfBody.parse(body(p, ids(65).map { step($0) })), "65 steps")
        XCTAssertNil(WfBody.parse(body(p, [])), "no steps")
        let two = [step("a"), step("b")]
        XCTAssertNotNil(WfBody.parse(body(p, two, Array(repeating: edge("a", "b"), count: 256))), "256 edges")
        XCTAssertNil(WfBody.parse(body(p, two, Array(repeating: edge("a", "b"), count: 257))), "257 edges")
    }

    func testStepListLimits() {
        XCTAssertNotNil(WfStep.parse(step("a", deps: ids(16))), "16 deps")
        XCTAssertNil(WfStep.parse(step("a", deps: ids(17))), "17 deps")
        let labels: (Int) -> JSONValue = { n in J.array((0..<n).map { J.string("l" + ($0 < 10 ? "0" : "") + String($0)) }) }
        XCTAssertNotNil(WfStep.parse(step("a", over: ["deny_labels": labels(16)])), "16 deny labels")
        XCTAssertNil(WfStep.parse(step("a", over: ["deny_labels": labels(17)])), "17 deny labels")
        XCTAssertNotNil(WfStep.parse(step("a", over: ["escalate_labels": labels(16)])), "16 escalate labels")
        XCTAssertNil(WfStep.parse(step("a", over: ["escalate_labels": labels(17)])), "17 escalate labels")
        XCTAssertNotNil(WfStep.parse(step("a", over: ["cost": obj(8, J.int(1))])), "8 cost entries")
        XCTAssertNil(WfStep.parse(step("a", over: ["cost": obj(9, J.int(1))])), "9 cost entries")
        let caps8 = obj(8, J.int(5)).asObject ?? [:]
        let caps9 = obj(9, J.int(5)).asObject ?? [:]
        XCTAssertNotNil(WfBody.parse(body(b32(1), [step("a")], caps: caps8)), "8 caps")
        XCTAssertNil(WfBody.parse(body(b32(1), [step("a")], caps: caps9)), "9 caps")
    }

    func testEdgeLabelLimit() {
        let labels: (Int) -> JSONValue = { n in J.array((0..<n).map { J.string("l" + ($0 < 10 ? "0" : "") + String($0)) }) }
        XCTAssertNotNil(WfEdge.parse(edge("a", "b", over: ["deny_labels": labels(16)])))
        XCTAssertNil(WfEdge.parse(edge("a", "b", over: ["deny_labels": labels(17)])))
    }

    func testVerbAndResourceLengths() {
        XCTAssertNotNil(WfStep.parse(step("a", over: ["verb": J.string(rep("v", 128))])))
        XCTAssertNil(WfStep.parse(step("a", over: ["verb": J.string(rep("v", 129))])))
        XCTAssertNotNil(WfStep.parse(step("a", over: ["resource": J.string(rep("r", 512))])))
        XCTAssertNil(WfStep.parse(step("a", over: ["resource": J.string(rep("r", 513))])))
        func req(_ verb: String, _ resource: String) -> JSONValue {
            JSONValue.object(["step": J.string("a"), "verb": J.string(verb), "resource": J.string(resource), "params": J.object([:]), "units": J.object([:]),
                              "goal_digest": J.null, "plan_root": J.null])
        }
        XCTAssertNotNil(Workflow.Request.parse(req(rep("v", 128), "r")))
        XCTAssertNil(Workflow.Request.parse(req(rep("v", 129), "r")))
        XCTAssertNotNil(Workflow.Request.parse(req("v", rep("r", 512))))
        XCTAssertNil(Workflow.Request.parse(req("v", rep("r", 513))))
    }

    func testReceiptOutputCount() {
        func rec(_ n: Int) -> JSONValue {
            var outs: JObject = [:]
            for i in 0..<n {
                outs[JKey("o" + (i < 10 ? "0" : "") + String(i))] = J.object(["digest": J.string(b32(4)), "num": J.null, "unit": J.null, "labels": J.array([])])
            }
            return JSONValue.object(["v": J.int(1), "wf": J.string(b32(2)), "step": J.string("a"), "seq": J.int(0), "prev": J.null, "outcome": J.string("ok"),
                                     "params_digest": J.string(b32(3)), "outputs": J.object(outs), "issued_at": J.int(1), "signer": J.string(b32(5)), "sig": J.string("x")])
        }
        XCTAssertNotNil(WfReceipt.parse(rec(32)))
        XCTAssertNil(WfReceipt.parse(rec(33)))
    }

    // ---- the DAG ----

    func parsed(_ steps: [JSONValue], _ edges: [JSONValue] = []) throws -> WfBody { try XCTUnwrap(WfBody.parse(body(b32(1), steps, edges))) }

    func testAncestorsOfAChain() throws {
        let w = try parsed([step("a"), step("b", deps: ["a"]), step("c", deps: ["b"])])
        let anc = try XCTUnwrap(w.ancestors())
        XCTAssertEqual(anc["a"], Set<String>())
        XCTAssertEqual(anc["b"], Set<String>(["a"]))
        XCTAssertEqual(anc["c"], Set<String>(["a", "b"]), "transitive dependencies")
        XCTAssertTrue(w.dagOk())
    }

    func testAnUnknownDependencyHasNoAncestors() throws {
        XCTAssertNil(try parsed([step("a", deps: ["zzz"])]).ancestors())
        XCTAssertFalse(try parsed([step("a", deps: ["zzz"])]).dagOk())
    }

    func testACycleHasNoAncestors() throws {
        let w = try parsed([step("a", deps: ["b"]), step("b", deps: ["a"])])
        XCTAssertNil(w.ancestors())
        XCTAssertFalse(w.dagOk())
        XCTAssertNil(try parsed([step("a", deps: ["a"])]).ancestors())
    }

    /// 64 steps, each depending on the two before it: linear with memoisation, 2^40+ visits without.
    func testAncestorsAreMemoised() throws {
        let names = ids(64)
        var steps: [JSONValue] = []
        for i in 0..<64 {
            var deps: [String] = []
            if i >= 2 { deps.append(names[i - 2]) }
            if i >= 1 { deps.append(names[i - 1]) }
            steps.append(step(names[i], deps: deps))
        }
        let w = try parsed(steps)
        let anc = try XCTUnwrap(w.ancestors())
        XCTAssertEqual(anc[names[63]]?.count, 63)
        XCTAssertEqual(anc[names[1]], Set<String>([names[0]]))
    }

    func testEdgesMustRunFromADependency() throws {
        XCTAssertTrue(try parsed([step("a"), step("b", deps: ["a"])], [edge("a", "b")]).dagOk())
        XCTAssertFalse(try parsed([step("a"), step("b", deps: ["a"])], [edge("b", "a")]).dagOk(), "against the dependency")
        XCTAssertFalse(try parsed([step("a"), step("b")], [edge("a", "b")]).dagOk(), "not a dependency")
        XCTAssertFalse(try parsed([step("a"), step("b", deps: ["a"])], [edge("zzz", "b")]).dagOk(), "unknown source")
        XCTAssertFalse(try parsed([step("a"), step("b", deps: ["a"])], [edge("a", "zzz")]).dagOk(), "unknown target")
        XCTAssertFalse(try parsed([step("a"), step("a")]).dagOk(), "duplicate id")
    }

    // ---- signing ----

    func key(_ seed: UInt8) throws -> Curve25519.Signing.PrivateKey { try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: seed, count: 32)) }
    func pub(_ k: Curve25519.Signing.PrivateKey) -> String { Base64URLStrict.encode(Array(k.publicKey.rawRepresentation)) }
    func sign(_ domain: String, _ b: JSONValue, _ k: Curve25519.Signing.PrivateKey) throws -> String {
        let m = try XCTUnwrap(IV.message(domain, b))
        return Base64URLStrict.encode(Array(try k.signature(for: Data(m))))
    }

    func doc(_ b: JSONValue, _ k: Curve25519.Signing.PrivateKey) throws -> JSONValue {
        JSONValue.object(["body": b, "sig": J.string(try sign(Workflow.WORKFLOW_DOMAIN, b, k))])
    }

    func receipt(_ wf: String, _ step: String, seq: Int64, prev: String?, outputs: JObject, at: Int64, _ k: Curve25519.Signing.PrivateKey) throws -> JSONValue {
        var r: JObject = ["v": J.int(1), "wf": J.string(wf), "step": J.string(step), "seq": J.int(seq), "prev": prev.map { J.string($0) } ?? J.null,
                          "outcome": J.string("ok"), "params_digest": J.string(b32(3)), "outputs": J.object(outputs), "issued_at": J.int(at), "signer": J.string(pub(k))]
        r["sig"] = J.string(try sign(Workflow.WF_RECEIPT_DOMAIN, JSONValue.object(r), k))
        return JSONValue.object(r)
    }

    func request(_ step: String, params: JObject = [:]) -> JSONValue {
        JSONValue.object(["step": J.string(step), "verb": J.string("v"), "resource": J.string("r"), "params": J.object(params), "units": J.object([:]),
                          "goal_digest": J.null, "plan_root": J.null])
    }

    // ---- the clock ----

    func testTheWorkflowIsLiveFromItsIssueInstant() throws {
        let p = try key(1), r = try key(2)
        let d = try doc(body(pub(p), [step("a")], issued: 100, expires: 1000), p)
        let at = { (now: Int64) in Workflow.admitStep(workflow: d, principal: self.pub(p), rsSigner: self.pub(r), receipts: J.array([]), now: now, request: self.request("a")) }
        XCTAssertEqual(at(99).code, "not_yet")
        XCTAssertEqual(at(100).decision, "allow", "now == issued_at is inside the window")
        XCTAssertEqual(at(999).decision, "allow")
        XCTAssertEqual(at(1000).code, "expired", "now == expires_at is outside")
    }

    func testPlanRootAuthorizedWindow() throws {
        let p = try key(1)
        let root = b32(9)
        let d = try doc(body(pub(p), [step("a")], issued: 100, expires: 1000, planRoot: J.string(root)), p)
        XCTAssertFalse(Workflow.planRootAuthorized(workflow: d, principal: pub(p), now: 99, root: root))
        XCTAssertTrue(Workflow.planRootAuthorized(workflow: d, principal: pub(p), now: 100, root: root), "now == issued_at")
        XCTAssertTrue(Workflow.planRootAuthorized(workflow: d, principal: pub(p), now: 999, root: root))
        XCTAssertFalse(Workflow.planRootAuthorized(workflow: d, principal: pub(p), now: 1000, root: root), "now == expires_at")
        XCTAssertFalse(Workflow.planRootAuthorized(workflow: d, principal: pub(p), now: 500, root: b32(8)))
    }

    /// The clock bounds are checked before the signature: an unsigned (but well-formed) workflow reaches `bad_signature`
    /// for now in [0, 2^53-1] and `bad_workflow` outside it.
    func testTheClockRange() throws {
        let p = b32(1)
        let d = JSONValue.object(["body": body(p, [step("a")]), "sig": J.string("x")])
        func code(_ now: Int64) -> String? { Workflow.admitStep(workflow: d, principal: p, rsSigner: b32(2), receipts: J.array([]), now: now, request: request("a")).code }
        XCTAssertEqual(code(0), "bad_signature", "now == 0")
        XCTAssertEqual(code(1), "bad_signature")
        XCTAssertEqual(code(Canonical.MAX_SAFE), "bad_signature", "now == 2^53-1")
        XCTAssertEqual(code(-1), "bad_workflow")
        XCTAssertEqual(code(Canonical.MAX_SAFE + 1), "bad_workflow")
    }

    // ---- receipts ----

    func twoStep(_ op: String, _ p: Curve25519.Signing.PrivateKey) throws -> (doc: JSONValue, wf: String) {
        let b = body(pub(p), [step("a"), step("b", deps: ["a"])], [edge("a", "b", op: op)])
        return (try doc(b, p), try XCTUnwrap(Workflow.workflowDigest(b)))
    }

    func testAReceiptIssuedAtTheCurrentInstantIsAccepted() throws {
        let p = try key(1), r = try key(2)
        let (d, wf) = try twoStep("le", p)
        let out: JObject = ["out": J.object(["digest": J.string(b32(4)), "num": J.int(5), "unit": J.null, "labels": J.array([])])]
        func run(_ issuedAt: Int64) throws -> WfResult {
            let rc = try receipt(wf, "a", seq: 0, prev: nil, outputs: out, at: issuedAt, r)
            return Workflow.admitStep(workflow: d, principal: pub(p), rsSigner: pub(r), receipts: J.array([rc]), now: 500, request: request("b", params: ["p": J.int(5)]))
        }
        XCTAssertEqual(try run(500).decision, "allow", "issued_at == now")
        XCTAssertEqual(try run(499).decision, "allow")
        let late = try run(501)
        XCTAssertEqual(late.code, "bad_receipt")
        XCTAssertEqual(late.at, 0)
    }

    func testAReceiptMayPrecedeItsDependencyOnlyThroughAPromise() throws {
        let p = try key(1), r = try key(2)
        let b = body(pub(p), [step("a"), step("b", deps: ["a"])], [])
        let wf = try XCTUnwrap(Workflow.workflowDigest(b))
        let rc = try receipt(wf, "b", seq: 0, prev: nil, outputs: [:], at: 400, r)
        let res = Workflow.admitStep(workflow: try doc(b, p), principal: pub(p), rsSigner: pub(r), receipts: J.array([rc]), now: 500, request: request("b"))
        XCTAssertEqual(res.code, "bad_receipt", "no declared edge from the unmet dependency")
        XCTAssertEqual(res.at, 0)
    }

    // ---- the per-edge relation ----

    func relation(_ op: String, value: Int64, bound: Int64) throws -> WfResult {
        let p = try key(1), r = try key(2)
        let (d, wf) = try twoStep(op, p)
        let out: JObject = ["out": J.object(["digest": J.string(b32(4)), "num": J.int(bound), "unit": J.null, "labels": J.array([])])]
        let rc = try receipt(wf, "a", seq: 0, prev: nil, outputs: out, at: 400, r)
        return Workflow.admitStep(workflow: d, principal: pub(p), rsSigner: pub(r), receipts: J.array([rc]), now: 500, request: request("b", params: ["p": J.int(value)]))
    }

    func testEdgeRelationsAtEquality() throws {
        XCTAssertEqual(try relation("le", value: 5, bound: 5).decision, "allow", "le")
        XCTAssertEqual(try relation("ge", value: 5, bound: 5).decision, "allow", "ge")
        XCTAssertEqual(try relation("lt", value: 5, bound: 5).code, "edge_relation", "lt")
        XCTAssertEqual(try relation("gt", value: 5, bound: 5).code, "edge_relation", "gt")
    }

    func testEdgeRelationsOffByOne() throws {
        XCTAssertEqual(try relation("le", value: 6, bound: 5).code, "edge_relation")
        XCTAssertEqual(try relation("le", value: 4, bound: 5).decision, "allow")
        XCTAssertEqual(try relation("ge", value: 4, bound: 5).code, "edge_relation")
        XCTAssertEqual(try relation("ge", value: 6, bound: 5).decision, "allow")
        XCTAssertEqual(try relation("lt", value: 4, bound: 5).decision, "allow")
        XCTAssertEqual(try relation("lt", value: 6, bound: 5).code, "edge_relation")
        XCTAssertEqual(try relation("gt", value: 6, bound: 5).decision, "allow")
        XCTAssertEqual(try relation("gt", value: 4, bound: 5).code, "edge_relation")
    }
}
