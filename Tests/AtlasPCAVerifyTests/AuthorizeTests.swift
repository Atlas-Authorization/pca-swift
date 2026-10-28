import XCTest
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto // Linux: swift-crypto (tools/pca-audit/swift-mutate/linux-prep.sh)
#endif
@testable import AtlasPCAVerify

// README-SAMPLE-BEGIN
let replayStore = MemoryStateStore() // one process; several processes need a shared store (see below)

/// POST /payments: `pcactnText` is the PCActn the agent presented, `body` the request body.
func sendPayment(pcactnText: String?, body: String, grants: [String: JSONValue],
                 revokedGrantIds: Set<String>) -> (status: Int, message: String) {
    guard let params = JSONValue.parse(body) else { return (400, "the body is not JSON") }
    // What this handler will execute, from its own route and body (never from the PCActn).
    let operation = PCA.Operation(verb: "payments.send", resource: "payments/acme", params: params)
    let result = PCA.authorize(json: pcactnText, PCA.AuthorizeInput(
        operation: operation,
        audience: "payments-rs",
        resolveGrant: { ref in grants[ref] }, // grant_ref -> grant, from your own store
        stateStore: replayStore,
        isRevoked: { _, grant in
            guard case let .object(g) = grant, case let .string(id)? = g["id"] else { return nil } // nil denies
            return revokedGrantIds.contains(id)
        },
        plan: PCA.SINGLE_STEP))
    guard result.allow else {
        return (result.status, result.reason ?? "denied") // e.g. 403 "policy: caveat(s) not satisfied: max_spend"
    }
    // ... send the payment with exactly `params` ...
    return (200, "paid")
}
// README-SAMPLE-END

/// `PCA.authorize`: the full pipeline (0.5). The signed fixtures come from the TypeScript reference, which also recorded
/// its own `authorize()` outcome for every step (`ts`): each step asserts the exact Swift outcome (allow, status, sorted
/// failing checks) and that it equals the TypeScript decision.
final class AuthorizeTests: XCTestCase {
    typealias Result = PCA.AuthorizeResult

    static let FIX: JSONValue = (try? K042.json("authorize-fixtures.json")) ?? .null
    static var CASES: [JSONValue] { FIX.get("cases")?.asArray ?? [] }
    static var NOW: Int64 { FIX.get("now")?.safeInt ?? 0 }
    static var AUD: String { FIX.get("audience")?.asString ?? "" }

    func c(_ name: String) -> JSONValue {
        Self.CASES.first { $0.get("name")?.asString == name } ?? .null
    }
    func step(_ c: JSONValue, _ i: Int = 0) -> JSONValue { c.get("steps")?.asArray?[i] ?? .null }
    func pcactn(_ c: JSONValue, _ i: Int = 0) -> JSONValue { step(c, i).get("pcactn") ?? .null }
    func grant(_ c: JSONValue) -> JSONValue { c.get("grant") ?? .null }
    static func op(_ v: JSONValue?) -> PCA.Operation? {
        guard let v = v, let verb = v.get("verb")?.asString, let res = v.get("resource")?.asString, let params = v.get("params") else { return nil }
        return PCA.Operation(verb: verb, resource: res, params: params)
    }
    func operation(_ c: JSONValue, _ i: Int = 0) -> PCA.Operation { Self.op(step(c, i).get("operation"))! }
    func withParams(_ o: PCA.Operation, _ params: JSONValue) -> PCA.Operation { PCA.Operation(verb: o.verb, resource: o.resource, params: params) }
    static let P400: JSONValue = .object(["amount": .int(400), "currency": .string("usd")])
    static let P50: JSONValue = .object(["amount": .int(50), "currency": .string("usd")])

    func settle(_ r: Result) -> String { "allow=\(r.allow) status=\(r.status) failed=\(r.failedChecks)" }
    func want(_ allow: Bool, _ status: Int, _ failed: [String]) -> String { "allow=\(allow) status=\(status) failed=\(failed)" }

    /// The base input of a case step: the case's grant for any ref, a fresh memory store, never revoked, single-step.
    func input(_ c: JSONValue, _ i: Int = 0) -> PCA.AuthorizeInput {
        let g = grant(c)
        return PCA.AuthorizeInput(operation: operation(c, i), audience: Self.AUD, resolveGrant: { _ in g }, stateStore: MemoryStateStore(),
                                  isRevoked: { _, _ in false }, now: Self.NOW, plan: PCA.SINGLE_STEP)
    }
    func az(_ c: JSONValue, _ i: Int = 0, _ edit: (inout PCA.AuthorizeInput) -> Void = { _ in }) -> Result {
        var inp = input(c, i)
        edit(&inp)
        return PCA.authorize(pcactn: pcactn(c, i), inp)
    }

    // ---- the shared fixtures: exact outcome, and parity with the TypeScript authorize() ----

    func runCase(_ c: JSONValue, _ store: PCAStateStore) -> [(got: String, want: String, ts: String, reasonOK: Bool)] {
        let g = grant(c)
        let gid = g.get("id")?.asString ?? ""
        var revoked = false
        var out: [(String, String, String, Bool)] = []
        for s in c.get("steps")?.asArray ?? [] {
            revoked = s.get("revoked") == .bool(true)
            let r = PCA.authorize(pcactn: s.get("pcactn"), PCA.AuthorizeInput(
                operation: Self.op(s.get("operation")), audience: Self.AUD, resolveGrant: { ref in ref == gid ? g : nil },
                stateStore: store, isRevoked: { _, _ in revoked }, now: Self.NOW, plan: PCA.SINGLE_STEP))
            let e = s.get("expect")
            let ef = (e?.get("failed")?.asArray ?? []).compactMap { $0.asString }
            let ts = s.get("ts")
            out.append((settle(r), want(e?.get("allow") == .bool(true), Int(e?.get("status")?.safeInt ?? 0), ef),
                        "allow=\(ts?.get("allow") == .bool(true)) status=\(ts?.get("status")?.safeInt ?? 0)",
                        e?.get("reason")?.asString.map { (r.reason ?? "").contains($0) } ?? true))
            _ = (r.allow, r.status)
        }
        return out
    }

    func testFixtureShape() {
        XCTAssertEqual(Self.FIX.get("format")?.asString, "pca-authorize-fixtures/1")
        XCTAssertEqual(Self.CASES.count, 31)
        XCTAssertEqual(Self.CASES.reduce(0) { $0 + ($1.get("steps")?.asArray?.count ?? 0) }, 35)
        XCTAssertTrue(Self.CASES.allSatisfy { c in (c.get("steps")?.asArray ?? []).allSatisfy { $0.get("ts") != nil } })
        XCTAssertEqual(Self.FIX.get("plan")?.asString, PCA.SINGLE_STEP)
    }

    func fixtureParity(_ makeStore: () -> PCAStateStore) {
        var bad: [String] = []
        var steps = 0
        for c in Self.CASES {
            let name = c.get("name")?.asString ?? "?"
            for (i, x) in runCase(c, makeStore()).enumerated() {
                steps += 1
                if x.got != x.want { bad.append("\(name)[\(i)]: got \(x.got) want \(x.want)") }
                if !x.reasonOK { bad.append("\(name)[\(i)]: the refusal reason does not contain the expected text") }
                let tsGot = x.got.components(separatedBy: " failed=")[0]
                if tsGot != x.ts { bad.append("\(name)[\(i)]: \(tsGot) differs from the TypeScript \(x.ts)") }
            }
        }
        XCTAssertEqual(steps, 35)
        XCTAssertTrue(bad.isEmpty, "\(bad.count) divergent:\n" + bad.joined(separator: "\n"))
        if bad.isEmpty { print("authorize fixtures: \(Self.CASES.count) cases / \(steps) steps match expect and ts") }
    }

    func testFixturesMemoryStore() { fixtureParity { MemoryStateStore() } }
    func testFixturesSerialQueueStore() { fixtureParity { SerialQueueStore() } }

    // ---- the acceptance, spelled out ----

    func test400Under100RefusedWithReason() {
        let r = az(c("envelope-max-spend-400-refused"))
        XCTAssertEqual(settle(r), want(false, 403, ["policy"]))
        XCTAssertEqual(r.reason, "policy: caveat(s) not satisfied: max_spend")
        XCTAssertEqual(az(c("root-max-spend-400-refused")).reason, "policy: root caveat(s) not satisfied: max_spend")
        XCTAssertEqual(az(c("delegated-max-spend-400-refused")).reason, "delegated_caveats: delegation caveat(s) not satisfied: max_spend")
        XCTAssertEqual(az(c("envelope-predicate-400-refused")).reason, "policy: amount <= 100 not satisfied for payments.send on payments/acme")
        XCTAssertEqual(az(c("root-unknown-caveat")).reason?.hasPrefix("policy: root caveat(s) not satisfied: "), true)
        XCTAssertEqual(az(c("no-envelope")).reason, "policy: grant carries no valid envelope")
    }

    func testSigned50Executed400ReportsTheBindingFirst() {
        let r = az(c("envelope-max-spend-signed-50-executes-400"))
        XCTAssertEqual(r.reason, "operation: the proof's params_digest does not match the params of this payments.send operation")
        XCTAssertTrue(r.reasons.contains("params_digest: supplied params do not hash to action.params_digest"))
        XCTAssertTrue(r.reasons.contains("plan_root_authorized: known plan does not match plan.root"))
    }

    func testOperationXForYReason() {
        XCTAssertEqual(az(c("operation-other-verb")).reason,
                       "operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme")
    }

    func testAllowBindsTheOperation() {
        let k = c("envelope-max-spend-within")
        let r = az(k)
        XCTAssertTrue(r.allow)
        XCTAssertEqual(r.status, 200)
        XCTAssertNil(r.reason)
        XCTAssertEqual(r.operation?.verb, "payments.send")
        XCTAssertEqual(r.operation?.resource, "payments/acme")
        XCTAssertEqual(r.operation?.paramsDigest, pcactn(k).get("action")?.get("params_digest")?.asString)
        XCTAssertEqual(r.operation?.id, IV.strictHash(pcactn(k)))
        for n in ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format", "replay", "revocation",
                  "operation", "grant_ref", "params_digest", "plan_root_authorized", "policy", "delegated_caveats"] {
            XCTAssertEqual(r.checks[n], .pass, n)
        }
        XCTAssertEqual(Array(r.checkNames.prefix(9)), ["wire", "version", "audience", "validity", "chain", "grant_ref_bound", "plan_inclusion", "leaf_signature", "counter_format"])
        XCTAssertNil(r.checks["counter"])
        XCTAssertTrue(PCA.isAuthorized(r, for: operation(k)))
        XCTAssertFalse(PCA.isAuthorized(r, for: withParams(operation(k), Self.P400)))
        XCTAssertFalse(PCA.isAuthorized(r, for: PCA.Operation(verb: "payments.refund", resource: "payments/acme", params: Self.P50)))
        XCTAssertFalse(PCA.isAuthorized(r, for: PCA.Operation(verb: "payments.send", resource: "payments/other", params: Self.P50)))
        XCTAssertFalse(PCA.isAuthorized(r, for: nil))
        let denied = az(c("envelope-max-spend-400-refused"))
        XCTAssertFalse(PCA.isAuthorized(denied, for: operation(c("envelope-max-spend-400-refused"))))
        XCTAssertNil(denied.operation)
    }

    func testWrongAudienceIs401() {
        let r = az(c("wrong-audience"))
        XCTAssertEqual(settle(r), want(false, 401, ["audience"]))
        XCTAssertEqual(r.reason, "audience: aud does not match this resource server / instance")
    }

    func testGrantRefMustNameTheResolvedGrant() {
        let other = grant(c("envelope-predicate-within"))
        let r = az(c("envelope-max-spend-within")) { $0.resolveGrant = { _ in other } }
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.status, 401)
        XCTAssertEqual(r.checks["grant_ref"], .fail)
        XCTAssertTrue(r.reasons.contains("grant_ref: does not reference the supplied grant"))
    }

    // ---- fail closed: configuration, operation, callbacks, store ----

    func testMissingComponentRefusedBeforeVerification() {
        let k = c("envelope-max-spend-within")
        let edits: [(String, (inout PCA.AuthorizeInput) -> Void)] = [
            ("audience", { $0.audience = "" }),
            ("audience", { $0.audience = nil }),
            ("resolveGrant", { $0.resolveGrant = nil }),
            ("stateStore", { $0.stateStore = nil }),
            ("isRevoked", { $0.isRevoked = nil }),
        ]
        for (missing, edit) in edits {
            var seen: [String] = []
            let g = grant(k)
            let r = az(k) { inp in
                inp.resolveGrant = { ref in seen.append(ref); return g }
                edit(&inp)
            }
            XCTAssertEqual(settle(r), want(false, 403, ["authorize_config"]), missing)
            XCTAssertEqual(r.missing, [missing])
            XCTAssertEqual(seen, [], "the resolver must never be called (\(missing))")
            XCTAssertEqual(r.reason, "authorize_config: missing required component(s): \(missing) (fail closed)")
        }
    }

    func testAllMissingListed() {
        let r = PCA.authorize(pcactn: .object([:]), PCA.AuthorizeInput())
        XCTAssertEqual(r.missing, ["audience", "resolveGrant", "stateStore", "isRevoked"])
        XCTAssertEqual(PCA.missingAuthorizeComponents(PCA.AuthorizeInput()), ["audience", "resolveGrant", "stateStore", "isRevoked"])
        XCTAssertEqual(PCA.missingAuthorizeComponents(input(c("envelope-max-spend-within"))), [])
    }

    func testUnknownPlanModeRefused() {
        let r = az(c("envelope-max-spend-within")) { $0.plan = "multi" }
        XCTAssertEqual(r.missing, ["plan (only 'single-step' or nil)"])
        XCTAssertEqual(settle(r), want(false, 403, ["authorize_config"]))
    }

    func testOperationRequired() {
        let ops: [PCA.Operation?] = [
            nil,
            PCA.Operation(verb: "payments.send", resource: "payments/acme", params: .array([.int(1)])),
            PCA.Operation(verb: "payments.send", resource: "payments/acme", params: .null),
            PCA.Operation(verb: "payments.send", resource: "payments/acme", params: .string("{}")),
            PCA.Operation(verb: "", resource: "payments/acme", params: .object([:])),
            PCA.Operation(verb: "payments.send", resource: "", params: .object([:])),
        ]
        for o in ops {
            let r = az(c("envelope-max-spend-within")) { $0.operation = o }
            XCTAssertEqual(settle(r), want(false, 403, ["operation"]))
            XCTAssertEqual(r.reason, "operation: authorize needs the operation to execute (verb, resource, params) (fail closed)")
        }
        // params outside the strict JSON profile cannot be bound: an internal refusal, never an allow
        let r = az(c("envelope-max-spend-within")) { $0.operation = PCA.Operation(verb: "payments.send", resource: "payments/acme",
                                                                                     params: .object(["amount": .double(0.1 + 0.2)])) }
        XCTAssertEqual(settle(r), want(false, 403, ["authorize"]))
    }

    func testNoPlanSourceDenies() {
        let r = az(c("envelope-max-spend-within")) { $0.plan = nil }
        XCTAssertEqual(settle(r), want(false, 403, ["plan_root_authorized"]))
        XCTAssertEqual(r.failedChecks, ["plan_root_authorized"])
        XCTAssertEqual(r.reason, "plan_root_authorized: default-deny: no authorized plan is configured for this verifier (supply the plan and its authorization, or set insecureSkipPlanRootCheck)")
    }

    func testContextPlanMustBeAuthorized() {
        let k = c("envelope-max-spend-within")
        let digest = pcactn(k).get("action")?.get("params_digest") ?? .null
        let node: JSONValue = .object(["id": .string("n1"), "verb": .string("payments.send"), "resource": .string("payments/acme"),
                                       "params_digest": digest, "reversibility_class": .string("irreversible")])
        XCTAssertTrue(az(k) { $0.plan = nil; $0.context = { _ in PCA.AuthorizeContext(plan: [node], planAuthorized: true) } }.allow)
        let no = az(k) { $0.plan = nil; $0.context = { _ in PCA.AuthorizeContext(plan: [node]) } }
        XCTAssertEqual(no.failedChecks, ["plan_root_authorized"])
        XCTAssertEqual(no.reason, "plan_root_authorized: the plan root has not been authorized by the principal")
        let other = az(k) { $0.plan = nil; $0.context = { _ in PCA.AuthorizeContext(plan: [V2F.with(node, ["verb": .string("x")])], planAuthorized: true) } }
        XCTAssertEqual(other.reason, "plan_root_authorized: known plan does not match plan.root")
        // a context plan wins over single-step
        let ctxWins = az(k) { $0.context = { _ in PCA.AuthorizeContext(plan: [node]) } }
        XCTAssertEqual(ctxWins.failedChecks, ["plan_root_authorized"])
        // a malformed node never authorizes
        let bad = az(k) { $0.plan = nil; $0.context = { _ in PCA.AuthorizeContext(plan: [V2F.without(node, ["verb"])], planAuthorized: true) } }
        XCTAssertEqual(bad.reason, "plan_root_authorized: known plan does not match plan.root")
    }

    struct Boom: Error {}

    func testRevocationMustBeExactlyFalse() {
        let checks: [(JSONValue, JSONValue) throws -> Bool?] = [{ _, _ in nil }, { _, _ in true }, { _, _ in throw Boom() }]
        for (i, chk) in checks.enumerated() {
            let r = az(c("envelope-max-spend-within")) { $0.isRevoked = chk }
            XCTAssertEqual(settle(r), want(false, 403, ["revocation"]))
            XCTAssertEqual(r.reason, i == 1 ? "revocation: the grant is revoked" : "revocation: the revocation check failed (fail closed)")
        }
    }

    final class ThrowingStore: PCAStateStore {
        func claim(key: String, counter: Int64) throws -> ClaimResult { throw Boom() }
    }
    final class RefusingStore: PCAStateStore {
        func claim(key: String, counter: Int64) -> ClaimResult { ClaimResult(ok: false) }
    }
    final class RecordingStore: PCAStateStore {
        var seen: [(String, Int64)] = []
        func claim(key: String, counter: Int64) -> ClaimResult { seen.append((key, counter)); return ClaimResult(ok: true) }
    }
    /// A second store implementation: every claim runs on one serial queue (the shape of an actor-backed store).
    final class SerialQueueStore: PCAStateStore {
        private let q = DispatchQueue(label: "pca.replay")
        private var last: [String: Int64] = [:]
        func claim(key: String, counter: Int64) -> ClaimResult {
            q.sync {
                if let l = last[key], counter <= l { return ClaimResult(ok: false, lastCounter: l) }
                last[key] = counter
                return ClaimResult(ok: true)
            }
        }
    }

    func testStoreFailureDenies() {
        let r = az(c("envelope-max-spend-within")) { $0.stateStore = ThrowingStore() }
        XCTAssertEqual(settle(r), want(false, 403, ["replay"]))
        XCTAssertEqual(r.reason, "replay: the replay store failed (fail closed)")
        let r2 = az(c("envelope-max-spend-within")) { $0.stateStore = RefusingStore() }
        XCTAssertEqual(settle(r2), want(false, 403, ["replay"]))
        XCTAssertEqual(r2.reason, "replay: 1 was already claimed (replay)")
    }

    func testStoreKeyAndCounter() {
        let k = c("envelope-max-spend-within")
        let st = RecordingStore()
        XCTAssertTrue(az(k) { $0.stateStore = st }.allow)
        let holder = pcactn(k).get("cap_chain")?.asArray?.last?.get("holder")?.asString ?? ""
        let gid = grant(k).get("id")?.asString ?? ""
        XCTAssertEqual(st.seen.map { $0.0 }, ["\(gid):\(holder)"])
        XCTAssertEqual(st.seen.map { $0.1 }, [1])
        XCTAssertEqual(PCA.stateKey(grantId: gid, leafHolder: holder), "\(gid):\(holder)")
    }

    func testDeniedRequestNeverReachesTheStore() {
        for name in ["envelope-max-spend-400-refused", "revoked", "operation-other-verb", "wrong-audience", "attestation-bound"] {
            let st = RecordingStore()
            let r = az(c(name)) { $0.stateStore = st; $0.isRevoked = { _, _ in name == "revoked" } }
            XCTAssertFalse(r.allow, name)
            XCTAssertTrue(st.seen.isEmpty, name)
        }
    }

    func testReplayReason() {
        let k = c("envelope-max-spend-within")
        let st = MemoryStateStore()
        XCTAssertTrue(az(k) { $0.stateStore = st }.allow)
        let r = az(k) { $0.stateStore = st }
        XCTAssertEqual(settle(r), want(false, 403, ["replay"]))
        XCTAssertEqual(r.reason, "replay: 1 is not greater than last seen 1 (replay)")
    }

    func testCheckNamesAndRequireAlias() {
        let k = c("envelope-max-spend-within")
        let r = az(k)
        XCTAssertTrue(r.allow)
        XCTAssertEqual(r.checks["counter_format"], .pass)
        XCTAssertEqual(r.checks["replay"], .pass)
        XCTAssertNil(r.checks["counter"])
        XCTAssertEqual(PCA.DEFAULT_REQUIRED_CHECKS, ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity",
                                                      "grant_ref_bound", "operation", "params_digest", "policy"])
        // `counter` in a require list is the documented alias of `replay`
        XCTAssertTrue(az(k) { $0.require = ["counter"] }.allow)
        XCTAssertFalse(az(k) { $0.require = ["no_such_check"] }.allow)
        // a non-replay refusal leaves `replay` at pass: no spurious "required check is absent" reason
        let denied = az(c("envelope-max-spend-400-refused"))
        XCTAssertEqual(denied.checks["replay"], .pass)
        XCTAssertEqual(denied.reasons, ["policy: caveat(s) not satisfied: max_spend"])
    }

    func testCallbacksFailClosed() {
        let k = c("envelope-max-spend-within")
        XCTAssertEqual(az(k) { $0.resolveGrant = { _ in throw Boom() } }.failedChecks, ["resolve_grant"])
        XCTAssertEqual(az(k) { $0.context = { _ in throw Boom() } }.failedChecks, ["context"])
        XCTAssertEqual(az(k) { $0.intentV2 = .provider({ _ in throw Boom() }) }.failedChecks, ["intent_v2"])
        let unknown = az(k) { $0.resolveGrant = { _ in nil } }
        XCTAssertEqual(settle(unknown), want(false, 401, ["grant_ref"]))
        let notObject = az(k) { $0.resolveGrant = { _ in .array([]) } }
        XCTAssertEqual(settle(notObject), want(false, 401, ["grant_ref"]))
        // a context returning nil is an empty context
        XCTAssertTrue(az(k) { $0.context = { _ in nil } }.allow)
        // a provider returning nil is no v2 context
        XCTAssertTrue(az(k) { $0.intentV2 = .provider({ _ in nil }) }.allow)
    }

    func testMalformedAndAbsentProofs() {
        let k = c("envelope-max-spend-within")
        let inp = input(k)
        XCTAssertEqual(settle(PCA.authorize(pcactn: nil, inp)), want(false, 401, ["wire"]))
        XCTAssertEqual(PCA.authorize(pcactn: nil, inp).reason, "wire: no PCActn presented")
        XCTAssertEqual(settle(PCA.authorize(json: nil, inp)), want(false, 401, ["wire"]))
        XCTAssertEqual(settle(PCA.authorize(json: "{not json", inp)), want(false, 401, ["pcactn"]))
        XCTAssertEqual(PCA.authorize(json: "{not json", inp).reason, "undecodable PCActn: not a strict-JSON object")
        XCTAssertEqual(settle(PCA.authorize(pcactn: .int(12), inp)), want(false, 401, ["pcactn"]))
        XCTAssertEqual(settle(PCA.authorize(json: "[]", inp)), want(false, 401, ["pcactn"]))
        XCTAssertEqual(settle(PCA.authorize(json: String(repeating: " ", count: PCA.MAX_ARTIFACT_BYTES + 1), inp)), want(false, 401, ["pcactn"]))
        let noRef = V2F.with(pcactn(k), ["grant_ref": .int(1)])
        XCTAssertEqual(settle(PCA.authorize(pcactn: noRef, input(k))), want(false, 401, ["malformed"]))
        // a wire failure of the core verifier is terminal
        let wire = V2F.without(pcactn(k), ["action"])
        XCTAssertEqual(settle(PCA.authorize(pcactn: wire, input(k))), want(false, 401, ["malformed", "wire"]))
        // the JSON text of a valid proof is accepted
        let text = try? Canonical.canonicalizeStrict(pcactn(k))
        XCTAssertTrue(PCA.authorize(json: text, input(k)).allow)
    }

    func testZkComplianceFailsClosed() {
        let k = c("envelope-max-spend-within")
        let p = V2F.with(pcactn(k), ["zk_compliance": .object(["x": .int(1)])])
        let r = PCA.authorize(pcactn: p, input(k))
        XCTAssertFalse(r.allow)
        XCTAssertEqual(r.checks["zk_compliance"], .fail)
    }

    func testRequireAddsChecks() {
        let r = az(c("envelope-max-spend-within")) { $0.require = ["freshness"] }
        XCTAssertEqual(settle(r), want(false, 403, ["freshness"]))
        XCTAssertEqual(r.reason, "freshness: required check is absent (default-deny: not enforced by this resource server)")
        XCTAssertTrue(az(c("envelope-max-spend-within")) { $0.require = ["policy", "operation"] }.allow)
    }

    func testDelegatedCaveatsReported() {
        XCTAssertEqual(az(c("delegated-max-spend-within")).checks["delegated_caveats"], .pass)
        XCTAssertEqual(az(c("delegated-tool-schema-bound-tool")).checks["delegated_caveats"], .pass)
        let r = az(c("delegated-tool-schema-other-binding"))
        XCTAssertEqual(r.reason, "delegated_caveats: delegation caveat(s) not satisfied: tool_schema")
        XCTAssertEqual(az(c("delegated-unknown-caveat")).failedChecks, ["delegated_caveats"])
    }

    func testAttestationBoundGrantRefused() {
        let r = az(c("attestation-bound"))
        XCTAssertEqual(settle(r), want(false, 403, ["attestation"]))
        XCTAssertEqual(r.reason?.hasPrefix("attestation: the grant binds the agent (agent_binding)"), true)
    }

    // ---- natively signed proofs: reversibility, caveat context, the envelope rules ----

    func testReversibilityAuthoritativeClass() {
        let k = c("envelope-max-spend-within") // the agent declared "irreversible"
        XCTAssertEqual(az(k) { $0.context = { _ in PCA.AuthorizeContext(reversibilityClass: "reversible") } }.checks["reversibility"], .pass)
        XCTAssertEqual(az(k) { $0.context = { _ in PCA.AuthorizeContext(reversibilityClass: "nuclear") } }.checks["reversibility"], .pass)
        XCTAssertNil(az(k).checks["reversibility"])
        // a proof declaring "reversible" where the server says "irreversible" is refused
        let s = AZ.signed(declared: "reversible")
        XCTAssertTrue(AZ.run(s).allow)
        let r = AZ.run(s) { $0.context = { _ in PCA.AuthorizeContext(reversibilityClass: "irreversible") } }
        XCTAssertEqual(settle(r), want(false, 403, ["reversibility"]))
        XCTAssertEqual(r.reason, "reversibility: declared class 'reversible' is less restrictive than the authoritative 'irreversible'")
        XCTAssertEqual(AZ.run(s) { $0.context = { _ in PCA.AuthorizeContext(reversibilityClass: "costly") } }.failedChecks, ["reversibility"])
        XCTAssertTrue(AZ.run(s) { $0.context = { _ in PCA.AuthorizeContext(reversibilityClass: "reversible") } }.allow)
    }

    func testEffectiveClassReachesTheCaveats() {
        // reversibility_max "rate_limited": a "reversible" proof passes; with an authoritative "nuclear" class the effective
        // class is the most restrictive one and the caveat refuses (after the reversibility check itself refused)
        let cv: JSONValue = .object(["type": .string("reversibility_max"), "class": .string("rate_limited")])
        let s = AZ.signed(declared: "reversible", envelopeCaveats: [cv])
        XCTAssertTrue(AZ.run(s).allow)
        XCTAssertEqual(AZ.run(s) { $0.context = { _ in PCA.AuthorizeContext(reversibilityClass: "rate_limited") } }.failedChecks, ["reversibility"])
        let declaredIrr = AZ.signed(declared: "irreversible", envelopeCaveats: [cv])
        XCTAssertEqual(AZ.run(declaredIrr).reason, "policy: caveat(s) not satisfied: reversibility_max")
        // the wire requires a declared class, so there is no "absent" case to fall back on
    }

    func testCaveatContextFromTheServer() {
        let rate: JSONValue = .object(["type": .string("rate"), "max": .int(2), "per_secs": .int(60)])
        let blast: JSONValue = .object(["type": .string("max_blast_radius"), "max": .int(10)])
        let depth: JSONValue = .object(["type": .string("delegation_depth"), "max": .int(0)])
        let exp: JSONValue = .object(["type": .string("expires"), "at": .int(AZ.NOW + 1)])
        let s = AZ.signed(rootCaveats: [rate, blast, depth, exp])
        let now = Double(AZ.NOW)
        XCTAssertTrue(AZ.run(s) { $0.context = { _ in PCA.AuthorizeContext(blastRadius: 3, recentActionTimes: [now - 1_000]) } }.allow)
        let r = AZ.run(s) { $0.context = { _ in PCA.AuthorizeContext(blastRadius: 11, recentActionTimes: [now - 1_000, now - 2_000]) } }
        XCTAssertEqual(r.reason, "policy: root caveat(s) not satisfied: rate, max_blast_radius")
        XCTAssertEqual(AZ.run(s).reason, "policy: root caveat(s) not satisfied: rate, max_blast_radius")
        XCTAssertEqual(AZ.run(s) { $0.now = AZ.NOW + 1; $0.context = { _ in PCA.AuthorizeContext(blastRadius: 3, recentActionTimes: []) } }.reason,
                       "policy: root caveat(s) not satisfied: expires")
    }

    func testEnvelopeRules() {
        // the envelope's predicates read the operation's params and the server's subject
        let pred: JSONValue = .object(["verb": .string("payments.send"), "resource": .string("payments/*"),
                                       "where": .array([.object(["field": .string("subject.tier"), "op": .string("eq"), "value": .string("gold")])])])
        let s = AZ.signed(predicates: [pred])
        XCTAssertTrue(AZ.run(s) { $0.context = { _ in PCA.AuthorizeContext(subject: .object(["tier": .string("gold")])) } }.allow)
        XCTAssertEqual(AZ.run(s).reason, "policy: subject.tier == \"gold\" not satisfied for payments.send on payments/acme")
        XCTAssertEqual(AZ.run(AZ.signed(predicates: [])).reason, "policy: envelope grants no predicates")
        // a malformed envelope is no envelope
        XCTAssertEqual(AZ.run(AZ.signed(riskPolicy: .object([:]))).reason, "policy: grant carries no valid envelope")
        // envelope predicates + envelope caveats + root caveats, all reported
        let r = AZ.run(AZ.signed(predicates: [.object(["verb": .string("x")])], envelopeCaveats: [.object(["type": .string("geo")])],
                                 rootCaveats: [.object(["type": .string("note")])]))
        XCTAssertEqual(r.reasons, ["policy: no predicate permits payments.send on payments/acme", "policy: caveat(s) not satisfied: geo",
                                   "policy: root caveat(s) not satisfied: note"])
        // agent pins: each one refuses
        for b: JSONValue in [.object(["model_allowlist": .array([.string("m")])]), .object(["min_measurement": .null]),
                             .object(["require_hardware": .bool(true)]), .object(["require_measured_weights": .bool(true)]),
                             .object(["weights_allowlist": .array([.string("w")])]), .object(["system_prompt_allowlist": .array([.string("p")])]),
                             .object(["tool_manifest_allowlist": .array([.string("t")])])] {
            XCTAssertEqual(AZ.run(AZ.signed(binding: b)).failedChecks, ["attestation"], "\(b)")
        }
        for b: JSONValue in [.object(["model_allowlist": .array([])]), .object(["min_measurement": .string("")]), .object(["operator": .string("")]),
                             .object(["require_hardware": .bool(false)]), .array([])] {
            XCTAssertTrue(AZ.run(AZ.signed(binding: b)).allow, "\(b)")
        }
    }

    func testToolBindingReachesTheToolSchema() {
        let schema: JSONValue = .object(["props": .object(["amount": .object(["type": .string("number"), "max": .int(100)]),
                                                          "currency": .object(["type": .string("string")])])])
        let cv = AZ.toolCaveat(schema, tool: "payments.send", sig: V2F.digest("sig-1"))
        XCTAssertTrue(AZ.run(AZ.signed(envelopeCaveats: [cv])).allow)
        XCTAssertTrue(AZ.run(AZ.signed(envelopeCaveats: [cv], extra: ["tool_binding": .string(V2F.digest("sig-1"))])).allow)
        XCTAssertEqual(AZ.run(AZ.signed(envelopeCaveats: [cv], extra: ["tool_binding": .string(V2F.digest("sig-2"))])).reason,
                       "policy: caveat(s) not satisfied: tool_schema")
        XCTAssertEqual(AZ.run(AZ.signed(params: Self.P400, envelopeCaveats: [cv])).reason, "policy: caveat(s) not satisfied: tool_schema")
    }

    // ---- the replay store ----

    func testStoreMonotone() {
        for st in [MemoryStateStore() as PCAStateStore, SerialQueueStore()] {
            XCTAssertEqual(try st.claim(key: "k", counter: 5), ClaimResult(ok: true))
            XCTAssertEqual(try st.claim(key: "k", counter: 5), ClaimResult(ok: false, lastCounter: 5))
            XCTAssertEqual(try st.claim(key: "k", counter: 4), ClaimResult(ok: false, lastCounter: 5))
            XCTAssertEqual(try st.claim(key: "k", counter: 6), ClaimResult(ok: true))
            XCTAssertEqual(try st.claim(key: "other", counter: 0), ClaimResult(ok: true))
            XCTAssertEqual(try st.claim(key: "other", counter: 0), ClaimResult(ok: false, lastCounter: 0))
        }
    }

    func testConcurrentClaimsExactlyOneWins() {
        for _ in 0..<20 {
            let st = MemoryStateStore()
            let lock = NSLock()
            var wins = 0
            DispatchQueue.concurrentPerform(iterations: 16) { _ in
                if st.claim(key: "k", counter: 7).ok { lock.lock(); wins += 1; lock.unlock() }
            }
            XCTAssertEqual(wins, 1)
        }
    }

    func testConcurrentAuthorizeOfOneProofOneAllow() {
        let k = c("envelope-max-spend-within")
        let st = MemoryStateStore()
        let base = input(k)
        let p = pcactn(k)
        let lock = NSLock()
        var allows: [Bool] = []
        DispatchQueue.concurrentPerform(iterations: 8) { _ in
            var inp = base
            inp.stateStore = st
            let r = PCA.authorize(pcactn: p, inp)
            lock.lock(); allows.append(r.allow); lock.unlock()
        }
        XCTAssertEqual(allows.sorted { !$0 && $1 }, [Bool](repeating: false, count: 7) + [true])
    }

    // ---- caveat semantics: conformance parity and the agent-native types ----

    func testCaveatEvalVectorsThroughTheAgentEvaluator() throws {
        let doc = try ConformanceTests.loadCorpus()
        let vs = doc.get("primitives")?.get("caveat_eval")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(vs.count, 41)
        var bad: [String] = []
        for v in vs {
            let ctx = v.get("context") ?? .null
            let r = PCA.evaluateAgentCaveats(PCA.policyCaveats(grant: v.get("grant") ?? .null, chain: v.get("chain")), context: ctx,
                                             actionContext: .object(["action": ctx.get("action") ?? .null]))
            let wantOk = v.get("expect")?.get("allow") == .bool(true)
            let wantFailed = (v.get("expect")?.get("failed")?.asArray ?? []).compactMap { $0.asString }
            if r.ok != wantOk || r.failed != wantFailed { bad.append("\(v.get("name")?.asString ?? "?"): got \(r) want \(wantOk) \(wantFailed)") }
        }
        XCTAssertTrue(bad.isEmpty, bad.joined(separator: "\n"))
    }

    func testAgentCaveatsPredicatesAndUnknown() {
        let action: JSONValue = .object(["verb": .string("pay"), "resource": .string("inv:1"), "params": .object(["amount": .int(5)])])
        let ctx: JSONValue = .object(["now": .int(1), "action": action])
        let actx: JSONValue = .object(["action": action])
        let allow: JSONValue = .object(["type": .string("predicates"), "allow": .array([.object(["verb": .string("pay"), "resource": .string("inv:*")])])])
        let deny: JSONValue = .object(["type": .string("predicates"), "allow": .array([.object(["verb": .string("pay"), "resource": .string("inv:2")])])])
        func ev(_ cs: JSONValue?, _ a: JSONValue?) -> String { let r = PCA.evaluateAgentCaveats(cs, context: ctx, actionContext: a); return "\(r.ok) \(r.failed)" }
        XCTAssertEqual(ev(.array([allow]), actx), "true []")
        XCTAssertEqual(ev(.array([deny]), actx), "false [\"predicates\"]")
        XCTAssertEqual(ev(.array([.object(["type": .string("predicates"), "allow": .string("x")])]), actx), "false [\"predicates\"]")
        XCTAssertEqual(ev(.array([.object(["type": .string("predicates"), "allow": .array([])])]), actx), "false [\"predicates\"]")
        XCTAssertEqual(ev(.array([allow]), nil), "false [\"predicates\"]")
        XCTAssertEqual(ev(.array([.object(["type": .string("geo")]), .int(5)]), actx), "false [\"geo\", \"<malformed>\"]")
        XCTAssertEqual(ev(.string("x"), actx), "false [\"<malformed caveats>\"]")
        XCTAssertEqual(ev(nil, actx), "false [\"<malformed caveats>\"]")
        XCTAssertEqual(ev(.array([]), actx), "true []")
        // the stock types still run (max_spend reads the context's action params)
        XCTAssertEqual(ev(.array([.object(["type": .string("max_spend"), "usd": .int(4)])]), actx), "false [\"max_spend\"]")
        XCTAssertEqual(ev(.array([.object(["type": .string("max_spend"), "usd": .int(5)])]), actx), "true []")
        // a tool_schema caveat without a tool call is unsatisfied
        XCTAssertEqual(ev(.array([AZ.toolCaveat(.object(["props": .object([:])]))]), actx), "false [\"tool_schema\"]")
        // a Kelvin sign is not a K: types compare by code point
        XCTAssertEqual(ev(.array([.object(["type": .string("predicates\u{212A}"), "allow": .array([])])]), actx), "false [\"predicates\u{212A}\"]")
    }

    func testToolSchemaRules() {
        let cv = AZ.toolCaveat(.object([
            "props": .object([
                "n": .object(["type": .string("integer"), "min": .int(0), "max": .int(10)]),
                "flag": .object(["type": .string("boolean"), "const": .bool(true)]),
                "s": .object(["type": .string("string"), "prefix": .string("ab"), "maxLength": .int(3)]),
                "e": .object(["type": .string("number"), "enum": .array([.int(1), .double(2.5)])]),
                "o": .object(["type": .string("object"), "props": .object(["x": .object(["type": .string("string")])]), "required": .array([.string("x")])]),
                "a": .object(["type": .string("array"), "items": .object(["type": .string("integer")]), "maxItems": .int(2)]),
            ]),
            "required": .array([.string("n")]),
        ]))
        func ev(_ args: JObject, tool: String = "pay", sig: String? = nil) -> String {
            let r = PCA.evaluateToolSchema(cv, call: PCA.ToolCall(tool: tool, args: .object(args), toolSignatureDigest: sig))
            return "\(r.ok) \(r.reason ?? "nil")"
        }
        XCTAssertEqual(ev(["n": .int(3)]), "true nil")
        XCTAssertEqual(ev(["n": .double(3.0)]), "true nil") // JS: 3.0 is an integer
        XCTAssertEqual(ev(["n": .double(3.5)]), "false args.n: wrong type (expected integer)")
        XCTAssertEqual(ev(["n": .bool(true)]), "false args.n: wrong type (expected integer)") // a bool is never a number
        XCTAssertEqual(ev(["n": .int(11)]), "false args.n: above max")
        XCTAssertEqual(ev(["n": .int(-1)]), "false args.n: below min")
        XCTAssertEqual(ev([:]), "false args: missing required argument 'n'")
        XCTAssertEqual(ev(["n": .int(1), "zz": .int(1)]), "false args: unexpected argument \"zz\"")
        XCTAssertEqual(ev(["n": .int(1), "flag": .int(1)]), "false args.flag: wrong type (expected boolean)")
        XCTAssertEqual(ev(["n": .int(1), "flag": .bool(false)]), "false args.flag: violates const")
        XCTAssertEqual(ev(["n": .int(1), "flag": .bool(true)]), "true nil")
        XCTAssertEqual(ev(["n": .int(1), "s": .string("abc")]), "true nil")
        XCTAssertEqual(ev(["n": .int(1), "s": .string("a\u{1F600}")]), "false args.s: violates prefix")
        XCTAssertEqual(ev(["n": .int(1), "s": .string("ab\u{1F600}")]), "false args.s: exceeds maxLength") // UTF-16 length 4
        XCTAssertEqual(ev(["n": .int(1), "s": .int(1)]), "false args.s: wrong type (expected string)")
        XCTAssertEqual(ev(["n": .int(1), "e": .double(2.5)]), "true nil")
        XCTAssertEqual(ev(["n": .int(1), "e": .double(1.0)]), "true nil")
        XCTAssertEqual(ev(["n": .int(1), "e": .int(3)]), "false args.e: violates enum")
        XCTAssertEqual(ev(["n": .int(1), "o": .object([:])]), "false args.o: missing required argument 'x'")
        XCTAssertEqual(ev(["n": .int(1), "o": .array([])]), "false args.o: expected object")
        XCTAssertEqual(ev(["n": .int(1), "a": .array([.int(1), .int(2), .int(3)])]), "false args.a: exceeds maxItems")
        XCTAssertEqual(ev(["n": .int(1), "a": .array([.int(1), .string("2")])]), "false args.a[1]: wrong type (expected integer)")
        XCTAssertEqual(ev(["n": .int(1), "a": .string("x")]), "false args.a: expected array")
        XCTAssertEqual(ev(["n": .int(1)], tool: "refund"), "false tool \"refund\" not authorized")
        XCTAssertEqual(ev(["n": .int(1)], sig: "other"), "false signed tool_binding differs from the authorized tool signature")
        XCTAssertEqual(ev(["n": .int(1)], sig: "sigdigest"), "true nil")
        // a long unexpected key is cut to 48 characters
        let long = String(repeating: "k", count: 60)
        XCTAssertEqual(ev(["n": .int(1), JKey(long): .int(1)]), "false args: unexpected argument \"\(String(repeating: "k", count: 48))\u{2026}\"")
    }

    func testToolSchemaBoundsAndDefaults() {
        func ev(_ props: JObject, _ args: JObject) -> String {
            let r = PCA.evaluateToolSchema(AZ.toolCaveat(.object(["props": .object(props)])), call: PCA.ToolCall(tool: "pay", args: .object(args)))
            return "\(r.ok) \(r.reason ?? "nil")"
        }
        let str: JSONValue = .object(["type": .string("string"), "minLength": .int(2)])
        XCTAssertEqual(ev(["s": str], ["s": .string("a")]), "false args.s: below minLength")
        XCTAssertEqual(ev(["s": str], ["s": .string("ab")]), "true nil")
        let arr: JSONValue = .object(["type": .string("array"), "items": .object(["type": .string("boolean")]), "minItems": .int(1)])
        XCTAssertEqual(ev(["a": arr], ["a": .array([])]), "false args.a: below minItems")
        XCTAssertEqual(ev(["a": .object(["type": .string("array"), "items": .object(["type": .string("boolean")])])], ["a": .array(Array(repeating: .bool(true), count: 257))]),
                       "false args.a: exceeds maxItems")
        XCTAssertEqual(ev(["s": .object(["type": .string("string")])], ["s": .string(String(repeating: "x", count: 65_537))]), "false args.s: exceeds maxLength")
        XCTAssertEqual(ev(["s": .object(["type": .string("string"), "maxLength": .int(1_048_576)])], ["s": .string(String(repeating: "x", count: 65_537))]), "true nil")
        // enum / const: === semantics
        XCTAssertEqual(ev(["b": .object(["type": .string("boolean"), "enum": .array([.bool(true)])])], ["b": .bool(false)]), "false args.b: violates enum")
        XCTAssertEqual(ev(["s": .object(["type": .string("string"), "const": .string("e\u{301}")])], ["s": .string("\u{e9}")]), "false args.s: violates const")
        // nesting: depth 9 values are refused, 8 is fine (object specs count their own level)
        var deep: JSONValue = .object(["type": .string("string")])
        for _ in 0..<6 { deep = .object(["type": .string("object"), "props": .object(["x": deep])]) }
        var v: JSONValue = .string("ok")
        for _ in 0..<6 { v = .object(["x": v]) }
        XCTAssertEqual(ev(["x": deep], ["x": v]), "true nil")
    }

    func testToolSchemaCaveatIntegrity() {
        let schema: JSONValue = .object(["props": .object(["n": .object(["type": .string("number")])])])
        let good = AZ.toolCaveat(schema)
        let call = PCA.ToolCall(tool: "pay", args: .object(["n": .int(1)]))
        func ev(_ cv: JSONValue, _ c: PCA.ToolCall? = nil) -> String { let r = PCA.evaluateToolSchema(cv, call: c ?? call); return "\(r.ok) \(r.reason ?? "nil")" }
        XCTAssertEqual(ev(good), "true nil")
        XCTAssertEqual(ev(V2F.with(good, ["schema_digest": .string("x")])), "false schema digest mismatch")
        XCTAssertEqual(ev(V2F.with(good, ["binding_digest": .string("x")])), "false binding digest mismatch")
        XCTAssertEqual(ev(V2F.with(good, ["tool": .string("")])), "false malformed tool_schema caveat")
        XCTAssertEqual(ev(V2F.with(good, ["type": .string("tool")])), "false malformed tool_schema caveat")
        XCTAssertEqual(ev(.string("x")), "false malformed tool_schema caveat")
        XCTAssertEqual(ev(AZ.toolCaveat(.object(["props": .object(["n": .object(["type": .string("number"), "pattern": .string("x")])])]))),
                       "false malformed tool_schema caveat: n: unknown spec key")
        XCTAssertEqual(ev(good, PCA.ToolCall(tool: "pay", args: .array([.int(1)]))), "false malformed call")
        XCTAssertEqual(PCA.evaluateToolSchema(good, call: nil).reason, "malformed call")
        // the signature digest is bound: absent is "undefined"
        let unsigned = AZ.toolCaveat(schema, sig: nil)
        XCTAssertEqual(ev(unsigned), "true nil")
        XCTAssertEqual(ev(unsigned, PCA.ToolCall(tool: "pay", args: .object(["n": .int(1)]), toolSignatureDigest: "x")),
                       "false signed tool_binding differs from the authorized tool signature")
    }

    func testToolSchemaValidation() {
        func err(_ schema: JSONValue) -> String? { ToolSchema.validateArgSchema(schema) }
        let num: JSONValue = .object(["type": .string("number")])
        XCTAssertEqual(err(.array([])), "schema must be an object")
        XCTAssertEqual(err(.object(["props": .object([:]), "x": .int(1)])), "unknown schema key")
        XCTAssertEqual(err(.object([:])), "props must be an object")
        XCTAssertNil(err(.object(["props": .object([:])])))
        XCTAssertEqual(err(.object(["props": .object(["a-b": num])])), "invalid property name 'a-b'")
        XCTAssertEqual(err(.object(["props": .object([JKey(String(repeating: "a", count: 65)): num])])),
                       "invalid property name '\(String(repeating: "a", count: 32))'")
        XCTAssertEqual(err(.object(["props": .object(["\u{212A}": num])])), "invalid property name '\u{212A}'")
        XCTAssertEqual(err(.object(["props": .object(["a": num]), "required": .array([.string("b")])])), "required names an undeclared property")
        XCTAssertEqual(err(.object(["props": .object(["a": num]), "required": .null])), "required must be a short array")
        XCTAssertEqual(err(.object(["props": .object(["a": .object(["type": .string("date")])])])), "a: unknown type")
        XCTAssertEqual(err(.object(["props": .object(["a": .object(["type": .string("array")])])])), "a: unknown type")
        let many = JObject(uniqueKeysWithValues: (0..<65).map { (JKey("p\($0)"), num) })
        XCTAssertEqual(err(.object(["props": .object(many)])), "too many props")
        func spec(_ o: JObject) -> String? { err(.object(["props": .object(["a": .object(o)])])) }
        XCTAssertEqual(spec(["type": .string("string"), "minLength": .int(3), "maxLength": .int(2)]), "a: minLength > maxLength")
        XCTAssertEqual(spec(["type": .string("string"), "maxLength": .int(1_048_577)]), "a: bad maxLength")
        XCTAssertEqual(spec(["type": .string("string"), "minLength": .double(1.5)]), "a: bad minLength")
        XCTAssertEqual(spec(["type": .string("string"), "prefix": .string(String(repeating: "p", count: 513))]), "a: bad prefix")
        XCTAssertEqual(spec(["type": .string("string"), "const": .string(String(repeating: "c", count: 1025))]), "a: bad const")
        XCTAssertEqual(spec(["type": .string("integer"), "const": .double(1.5)]), "a: bad const")
        XCTAssertEqual(spec(["type": .string("integer"), "enum": .array([])]), "a: bad enum")
        XCTAssertEqual(spec(["type": .string("number"), "enum": .array([.bool(true)])]), "a: bad enum")
        XCTAssertEqual(spec(["type": .string("boolean"), "enum": .array([.int(1)])]), "a: bad enum")
        XCTAssertEqual(spec(["type": .string("number"), "enum": .array(Array(repeating: .int(1), count: 257))]), "a: bad enum")
        XCTAssertEqual(spec(["type": .string("number"), "min": .int(2), "max": .int(1)]), "a: min > max")
        XCTAssertEqual(spec(["type": .string("number"), "min": .string("1")]), "a: bad min")
        XCTAssertEqual(spec(["type": .string("number"), "max": .null]), "a: bad max")
        XCTAssertEqual(spec(["type": .string("array"), "items": num, "minItems": .int(3), "maxItems": .int(2)]), "a: minItems > maxItems")
        XCTAssertEqual(spec(["type": .string("array"), "items": num, "maxItems": .int(4097)]), "a: bad maxItems")
        XCTAssertEqual(spec(["type": .string("array"), "items": num, "minItems": .int(-1)]), "a: bad minItems")
        XCTAssertNil(spec(["type": .string("array"), "items": num, "minItems": .int(0), "maxItems": .int(4096)]))
        // depth: 7 nested object specs under the root are fine, 8 are too deep
        func nested(_ n: Int) -> JSONValue {
            var s: JSONValue = num
            for _ in 0..<n { s = .object(["type": .string("object"), "props": .object(["x": s])]) }
            return .object(["props": .object(["x": s])])
        }
        XCTAssertNil(err(nested(6)))
        XCTAssertNotNil(err(nested(7)))
        // node budget: 256 nodes
        let wide = JObject(uniqueKeysWithValues: (0..<64).map { (JKey("p\($0)"), JSONValue.object(["type": .string("object"), "props": .object(
            JObject(uniqueKeysWithValues: (0..<4).map { (JKey("q\($0)"), num) }))])) })
        XCTAssertEqual(err(.object(["props": .object(wide)]))?.hasSuffix("schema too large"), true)
    }

    // ---- the acceptance at the handler: a denial never reaches the handler ----

    /// A tiny resource server: `post` authorizes, then runs the handler only on an allow.
    final class PaymentsServer {
        var executed: [PCA.Operation] = []
        var revoked = false
        let store = MemoryStateStore()
        let grants: [String: JSONValue]
        init(_ grants: [JSONValue]) {
            var g: [String: JSONValue] = [:]
            for x in grants { if let id = x.get("id")?.asString { g[id] = x } }
            self.grants = g
        }
        func post(_ pcactn: JSONValue, _ op: PCA.Operation) -> Result {
            let r = PCA.authorize(pcactn: pcactn, PCA.AuthorizeInput(
                operation: op, audience: AuthorizeTests.AUD, resolveGrant: { [grants] ref in grants[ref] }, stateStore: store,
                isRevoked: { [unowned self] _, _ in self.revoked }, now: AuthorizeTests.NOW, plan: PCA.SINGLE_STEP))
            if r.allow && PCA.isAuthorized(r, for: op) { executed.append(op) } // the handler
            return r
        }
    }

    func testHandlerAcceptance() {
        let within = c("envelope-max-spend-within"), over = c("envelope-max-spend-400-refused")
        let srv = PaymentsServer([grant(within), grant(over)])
        let send400 = PCA.Operation(verb: "payments.send", resource: "payments/acme", params: Self.P400)
        let send50 = PCA.Operation(verb: "payments.send", resource: "payments/acme", params: Self.P50)
        // $400 under a $100 limit
        var r = srv.post(pcactn(over), send400)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.reason, "policy: caveat(s) not satisfied: max_spend")
        // a $50 proof with a $400 body
        r = srv.post(pcactn(within), send400)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.reason?.hasPrefix("operation: "), true)
        // a proof for X used for Y
        r = srv.post(pcactn(within), PCA.Operation(verb: "payments.refund", resource: "payments/acme", params: Self.P50))
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.reason, "operation: the proof is for payments.send on payments/acme, but this operation is payments.refund on payments/acme")
        // revoked
        srv.revoked = true
        r = srv.post(pcactn(within), send50)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.reason, "revocation: the grant is revoked")
        srv.revoked = false
        XCTAssertTrue(srv.executed.isEmpty, "a denial reached the handler")
        // allowed once, then a replay
        XCTAssertEqual(srv.post(pcactn(within), send50).status, 200)
        r = srv.post(pcactn(within), send50)
        XCTAssertEqual(r.status, 403)
        XCTAssertEqual(r.reason, "replay: 1 is not greater than last seen 1 (replay)")
        XCTAssertEqual(srv.executed, [send50])
        // an unknown grant
        let none = PaymentsServer([])
        XCTAssertEqual(none.post(pcactn(within), send50).status, 401)
        XCTAssertTrue(none.executed.isEmpty)
    }

    // ---- the README sample compiles (it is the code at the top of this file) and runs as documented ----

    func testReadmeSampleIsThisCode() throws {
        let here = URL(fileURLWithPath: #filePath)
        let src = String(decoding: try Data(contentsOf: here), as: UTF8.self)
        guard let a = src.range(of: "// README-SAMPLE-BEGIN\n"), let b = src.range(of: "// README-SAMPLE-END") else { return XCTFail("markers") }
        let code = String(src[a.upperBound..<b.lowerBound])
        let readme = String(decoding: try Data(contentsOf: here.deletingLastPathComponent().appendingPathComponent("../../README.md").standardized), as: UTF8.self)
        guard let m = readme.range(of: "<!-- pca-readme-sample: authorize -->\n```swift\nimport AtlasPCAVerify\n\n"),
              let e = readme.range(of: "```", range: m.upperBound..<readme.endIndex) else { return XCTFail("README sample block not found") }
        XCTAssertEqual(String(readme[m.upperBound..<e.lowerBound]), code)
    }

    func testReadmeSampleRuns() {
        // signed now on the wall clock (the sample uses it), under a $100 max_spend envelope
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let maxSpend: JSONValue = .object(["type": .string("max_spend"), "usd": .int(100)])
        let g = AZ.grant(envelope: AZ.envelope(caveats: [maxSpend]))
        let gid = g.get("id")?.asString ?? ""
        func proof(_ params: JSONValue, counter: Int64) -> String {
            let p = AZ.proof(g, params: params, declared: "irreversible", counter: counter, now: now, aud: "payments-rs")
            return (try? Canonical.canonicalizeStrict(p)) ?? ""
        }
        let grants = [gid: g]
        let p50 = proof(Self.P50, counter: 1)
        XCTAssertEqual(sendPayment(pcactnText: p50, body: #"{"amount": 50, "currency": "usd"}"#, grants: grants, revokedGrantIds: []).status, 200)
        let replay = sendPayment(pcactnText: p50, body: #"{"amount": 50, "currency": "usd"}"#, grants: grants, revokedGrantIds: [])
        XCTAssertEqual(replay.status, 403)
        XCTAssertEqual(replay.message, "replay: 1 is not greater than last seen 1 (replay)")
        let p50b = proof(Self.P50, counter: 2)
        XCTAssertEqual(sendPayment(pcactnText: p50b, body: #"{"amount": 400, "currency": "usd"}"#, grants: grants, revokedGrantIds: []).status, 403)
        XCTAssertEqual(sendPayment(pcactnText: p50b, body: #"{"amount": 50, "currency": "usd"}"#, grants: grants, revokedGrantIds: [gid]).message,
                       "revocation: the grant is revoked")
        let over = sendPayment(pcactnText: proof(Self.P400, counter: 3), body: #"{"amount": 400, "currency": "usd"}"#, grants: grants, revokedGrantIds: [])
        XCTAssertEqual(over.status, 403)
        XCTAssertEqual(over.message, "policy: caveat(s) not satisfied: max_spend")
        XCTAssertEqual(sendPayment(pcactnText: nil, body: "{}", grants: grants, revokedGrantIds: []).status, 401)
        XCTAssertEqual(sendPayment(pcactnText: p50b, body: "{", grants: grants, revokedGrantIds: []).status, 400)
        XCTAssertEqual(sendPayment(pcactnText: p50b, body: #"{"amount": 50, "currency": "usd"}"#, grants: grants, revokedGrantIds: []).status, 200)
    }
}

/// Natively signed grants and PCActns for the cases the shared fixtures do not cover (the shapes of the TypeScript
/// fixture generator: one-hop chain, an `envelope` caveat, a single-step plan).
enum AZ {
    static let principal = V2F.principal, agent = V2F.agent // the keys V2F.signP signs with
    static var NOW: Int64 { AuthorizeTests.NOW }
    static var AUD: String { AuthorizeTests.AUD }
    static let RISK: JSONValue = .object([
        "bMax": .int(1000), "kappa": .int(1), "lambda": .int(0), "rho": .int(0), "theta1": .double(0.5), "theta2": .double(0.8),
        "weights": .object(["alpha": .int(0), "beta": .int(0), "delta": .int(0), "epsilon": .int(0), "gamma": .int(0), "zeta": .int(0)]),
    ])
    static let ANY: JSONValue = .object(["verb": .string("payments.send"), "resource": .string("payments/*")])

    static func envelope(predicates: [JSONValue] = [ANY], caveats: [JSONValue] = [], binding: JSONValue = .object([:]), riskPolicy: JSONValue = RISK) -> JSONValue {
        .object(["type": .string("envelope"), "goal_commit": .string(V2F.digest("az/goal")), "predicates": .array(predicates), "caveats": .array(caveats),
                 "agent_binding": binding, "risk_policy": riskPolicy])
    }
    static func grant(envelope: JSONValue, rootCaveats: [JSONValue] = []) -> JSONValue {
        V2F.cap(issuer: principal, holder: agent, caveats: [envelope] + rootCaveats)
    }
    static func proof(_ grant: JSONValue, verb: String = "payments.send", resource: String = "payments/acme", params: JSONValue,
                      declared: String?, counter: Int64 = 1, now: Int64, aud: String, extra: JObject = [:]) -> JSONValue {
        var action: JObject = ["verb": .string(verb), "resource": .string(resource), "params_digest": .string(V2F.hash(params))]
        if let d = declared { action["reversibility_class"] = .string(d) }
        let cond = Merkle.conditionsDigestDefault()
        let root = Merkle.merkleRoot([Merkle.planLeaf(.string("n1"), action, cond)!])!
        var b: JObject = [
            "ver": .int(2), "action": .object(action), "grant_ref": grant.get("id")!, "cap_chain": .array([grant]),
            "plan": .object(["root": .string(root), "node_id": .string("n1"), "conditions_digest": .string(cond),
                             "inclusion_proof": .object(["index": .int(0), "size": .int(1), "path": .array([])])]),
            "attestation": .object(["quote_digest": .string(""), "epoch": .int(0), "model_id": .string("unattested"), "measurement": .string(""),
                                    "operator": .string("unattested")]),
            "provenance": .object(["causal_hash": .string(""), "taint_level": .int(0), "trusted_refs": .array([])]),
            "freshness": .object(["beacon_ref": .string(""), "epoch": .int(0), "accumulator_witness": .string("")]),
            "counter": .int(counter), "risk_claim": .object(["r": .int(0), "inputs": .object([:])]),
            "aud": .string(aud), "iat": .int(now), "exp": .int(now + 1_200_000),
        ]
        for (k, v) in extra { b[k] = v }
        return V2F.signP(b)
    }

    struct Signed { let grant: JSONValue; let pcactn: JSONValue; let params: JSONValue }

    static func signed(declared: String? = "irreversible", params: JSONValue = AuthorizeTests.P50, predicates: [JSONValue] = [ANY],
                       envelopeCaveats: [JSONValue] = [], rootCaveats: [JSONValue] = [], binding: JSONValue = .object([:]),
                       riskPolicy: JSONValue = RISK, extra: JObject = [:]) -> Signed {
        let g = grant(envelope: envelope(predicates: predicates, caveats: envelopeCaveats, binding: binding, riskPolicy: riskPolicy), rootCaveats: rootCaveats)
        return Signed(grant: g, pcactn: proof(g, params: params, declared: declared, now: NOW, aud: AUD, extra: extra), params: params)
    }

    static func run(_ s: Signed, _ edit: (inout PCA.AuthorizeInput) -> Void = { _ in }) -> PCA.AuthorizeResult {
        let g = s.grant
        var inp = PCA.AuthorizeInput(operation: PCA.Operation(verb: "payments.send", resource: "payments/acme", params: s.params), audience: AUD,
                                     resolveGrant: { _ in g }, stateStore: MemoryStateStore(), isRevoked: { _, _ in false }, now: NOW,
                                     plan: PCA.SINGLE_STEP)
        edit(&inp)
        return PCA.authorize(pcactn: s.pcactn, inp)
    }

    static func toolCaveat(_ schema: JSONValue, tool: String = "pay", sig: String? = "sigdigest") -> JSONValue {
        var o: JObject = ["type": .string("tool_schema"), "tool": .string(tool), "schema": schema, "schema_digest": .string(V2F.hash(schema)),
                          "binding_digest": .string(V2F.hash(.object(["tool": .string(tool), "signature_digest": .string(sig ?? "undefined"), "schema": schema])))]
        if let s = sig { o["signature_digest"] = .string(s) }
        return o.isEmpty ? .null : .object(o)
    }
}
