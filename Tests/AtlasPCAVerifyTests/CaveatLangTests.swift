import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Caveat language v2 (track K1) over the SHARED vectors (packages/pca/conformance/caveat-lang-vectors.json): all six
/// primitives, exact outcomes (every `reason_contains`, every `allow` / sorted `failed`), plus unit tests of what the
/// vectors cannot show.
final class CaveatLangTests: XCTestCase {
    static func table(_ name: String) throws -> [JSONValue] {
        let d = try ConformanceTests.load("caveat-lang-vectors.json")
        let t = d.get("primitives")?.get(name)?.asArray ?? []
        XCTAssertFalse(t.isEmpty, "caveat-lang-vectors.json: primitives.\(name) is empty")
        return t
    }

    /// A verifier clock as the vectors give it: a non-integer clock becomes a value the safe-integer check refuses.
    static func clock(_ v: JSONValue?) -> Int64 { IV.int(v) ?? Int64.max }

    static func k1Input(_ j: JSONValue?) -> K1Input {
        K1Input(pins: (j?.get("pins")?.asArray ?? []).compactMap { DischargePin.fromJSON($0) },
                discharges: j?.get("discharges")?.asArray ?? [],
                narrow: j?.get("narrow"),
                actionDigest: j?.get("action_digest")?.asString,
                revokedDischarges: j?.get("revoked_discharges")?.asArray?.compactMap { $0.asString },
                spiffeId: j?.get("spiffe_id")?.asString,
                history: j?.get("history")?.asArray)
    }

    func testVectorFileShape() throws {
        XCTAssertGreaterThanOrEqual(try Self.table("discharge_verify").count, 54)
        XCTAssertGreaterThanOrEqual(try Self.table("k1_eval").count, 102)
        XCTAssertGreaterThanOrEqual(try Self.table("caveat_shape").count, 50)
        XCTAssertGreaterThanOrEqual(try Self.table("uses_key").count, 5)
        XCTAssertGreaterThanOrEqual(try Self.table("uses_reserve").count, 12)
        XCTAssertGreaterThanOrEqual(try Self.table("spiffe_id").count, 24)
        XCTAssertGreaterThanOrEqual(try Self.table("k1_unconfigured").count, 9)
        XCTAssertGreaterThanOrEqual(try Self.table("consume_once_ttl").count, 9)
        XCTAssertGreaterThanOrEqual(try Self.table("k1_headers").count, 15)
    }

    func testK1UnconfiguredVectors() throws {
        var ran = 0
        for v in try Self.table("k1_unconfigured") {
            let n = v.get("name")?.asString ?? "?"
            let i = v.get("input")
            let r = PCA.evaluateCaveatsK1(grant: i?.get("grant") ?? .null, chain: i?.get("chain"), k1: nil, context: i?.get("context") ?? .null)
            let e = v.get("expect")
            XCTAssertEqual(r.allow, e?.get("allow") == .bool(true), "\(n): \(r.failed)")
            XCTAssertEqual(r.failed, (e?.get("failed")?.asArray ?? []).compactMap { $0.asString }.sorted(by: IV.utf8Less), n)
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 9)
    }

    func testConsumeOnceTtlVectors() throws {
        var ran = 0
        for v in try Self.table("consume_once_ttl") {
            let n = v.get("name")?.asString ?? "?"
            let store = MemoryStateStore()
            let want = (v.get("expect")?.get("results")?.asArray ?? []).compactMap { $0.asString }
            let steps = v.get("input")?.get("steps")?.asArray ?? []
            XCTAssertEqual(steps.count, want.count, n)
            for (k, st) in steps.enumerated() where k < want.count {
                let got: String
                do {
                    got = try store.consumeOnce(key: st.get("key")?.asString ?? "", retainUntil: IV.int(st.get("retain_until")) ?? Int64.min,
                                                now: IV.int(st.get("now")) ?? Int64.max) ? "true" : "false"
                } catch { got = "error" }
                XCTAssertEqual(got, want[k], "\(n)#\(k)")
            }
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 9)
    }

    func testK1HeadersVectors() throws {
        var ran = 0
        for v in try Self.table("k1_headers") {
            let n = v.get("name")?.asString ?? "?"
            var h: [String: String] = [:]
            for (k, x) in v.get("input")?.get("headers")?.asObject ?? [:] { h[k.s] = x.asString ?? "" }
            let e = v.get("expect")
            do {
                let r = try PCA.presentedK1(headers: h)
                XCTAssertEqual(e?.get("ok"), .bool(true), n)
                let value = e?.get("value")
                XCTAssertEqual(r.discharges.map { JSONValue.array($0) }, value?.get("discharges"), n)
                XCTAssertEqual(r.narrow, value?.get("narrow"), n)
            } catch {
                XCTAssertEqual(e?.get("ok"), .bool(false), "\(n): \(error)")
            }
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 15)
    }

    func testAmbiguousHeaderCaseVariantsReadAsAbsent() throws {
        // W10 = [], W1tdfQ is a different valid array: two spellings with different values are never picked between
        let r = try PCA.presentedK1(headers: ["PCA-Discharges": "W10", "pca-discharges": "W1tdXQ"])
        XCTAssertNil(r.discharges)
        XCTAssertEqual(try PCA.presentedK1(headers: ["PCA-Discharges": "W10", "pca-discharges": "W10"]).discharges, [])
    }

    func testConsumeOnceDefaultFallsBackToClaimAndRefusesBadArguments() throws {
        struct ClaimOnly: PCAStateStore {
            let inner = MemoryStateStore()
            func claim(key: String, counter: Int64) throws -> ClaimResult { inner.claim(key: key, counter: counter) }
        }
        let s = ClaimOnly()
        XCTAssertTrue(try s.consumeOnce(key: "k", retainUntil: 5, now: 1))
        XCTAssertFalse(try s.consumeOnce(key: "k", retainUntil: 5, now: 1))
        XCTAssertThrowsError(try s.consumeOnce(key: "", retainUntil: 5, now: 1))
        XCTAssertThrowsError(try s.consumeOnce(key: "j", retainUntil: 0, now: 1))
        XCTAssertTrue(try s.consumeOnce(key: "j", retainUntil: 1, now: 1), "a refused call leaves nothing behind")
    }

    func testMaxUsesSlotExpiresWithTheCaveat() {
        let c: JSONValue = .object(["type": .string("max_uses"), "id": .string("u"), "n": .int(1), "until": .int(100)])
        let b = [BoundCaveat(caveat: c, hop: 0, capHash: "h")]
        let store = MemoryStateStore()
        XCTAssertTrue(PCA.reserveMaxUses(store: store, bound: b, now: 1).ok)
        XCTAssertFalse(PCA.reserveMaxUses(store: store, bound: b, now: 99).ok)
        // the slot is retained through `until`; the caveat itself is expired after it
        XCTAssertEqual(PCA.reserveMaxUses(store: store, bound: b, now: 100).reason, "max_uses 'u' has expired")
        XCTAssertEqual(try? store.consumeOnce(key: PCA.maxUsesSlotKey(capHash: "h", id: "u", i: 0), retainUntil: 200, now: 101), true)
    }

    func testNoK1InputRefusesEveryK1CaveatButEmptyInputIsConfigured() {
        let g: JSONValue = .object(["id": .string("g"), "caveats": .array([.object(["type": .string("sealed")])])])
        let none = PCA.evaluateK1(grant: g, chain: nil, k1: nil, now: 1, action: nil)
        XCTAssertEqual(none.failed, ["sealed"])
        XCTAssertEqual(none.reasons, ["the caveat language is not configured (no k1 input)"])
        XCTAssertTrue(PCA.evaluateK1(grant: g, chain: nil, k1: K1Input(), now: 1, action: nil).ok)
    }

    func testDischargeVectors() throws {
        let supported = Set(PCASuites.supported)
        var ran = 0
        for v in try Self.table("discharge_verify") {
            let n = v.get("name")?.asString ?? "?"
            let i = v.get("input")
            let b = i?.get("binding")
            let bind = DischargeBinding(capHash: b?.get("cap_hash")?.asString ?? "", actionDigest: b?.get("action_digest")?.asString,
                                        pins: (b?.get("pins")?.asArray ?? []).compactMap { DischargePin.fromJSON($0) },
                                        now: Self.clock(b?.get("now")), revoked: b?.get("revoked")?.asArray?.compactMap { $0.asString })
            let r = PCA.verifyDischarge(i?.get("discharge"), i?.get("caveat"), bind)
            ran += 1
            if let need = v.get("requires_suite")?.asString, !supported.contains(need) {
                // a suite this build cannot run is refused, never accepted and never mistaken for a bad signature
                XCTAssertTrue(!r.ok && r.reason.contains(IV.UNSUPPORTED_SUITE), "\(n): suite \(need) is not built: want unsupported_suite, got \(r)")
                continue
            }
            let e = v.get("expect")
            XCTAssertEqual(r.ok, e?.get("ok") == .bool(true), "\(n): \(r.reason)")
            if r.ok {
                XCTAssertEqual(r.digest, e?.get("digest")?.asString, n)
                XCTAssertEqual(r.claims, e?.get("claims")?.asObject, n)
            } else {
                let want = e?.get("reason_contains")?.asString ?? "\u{0}"
                XCTAssertTrue(r.reason.contains(want), "\(n): reason '\(r.reason)' lacks '\(want)'")
            }
        }
        XCTAssertGreaterThanOrEqual(ran, 54)
    }

    func testK1EvalVectors() throws {
        var ran = 0
        for v in try Self.table("k1_eval") {
            let n = v.get("name")?.asString ?? "?"
            let i = v.get("input")
            let r = PCA.evaluateCaveatsK1(grant: i?.get("grant") ?? .null, chain: i?.get("chain"), k1: Self.k1Input(i?.get("k1")), context: i?.get("context") ?? .null)
            let e = v.get("expect")
            XCTAssertEqual(r.allow, e?.get("allow") == .bool(true), "\(n): \(r.failed)")
            XCTAssertEqual(r.failed, (e?.get("failed")?.asArray ?? []).compactMap { $0.asString }.sorted(by: IV.utf8Less), n)
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 102)
    }

    func testCaveatShapeVectors() throws {
        var ran = 0
        for v in try Self.table("caveat_shape") {
            let n = v.get("name")?.asString ?? "?"
            let c = v.get("input")?.get("caveat")
            let err: String?
            switch c?.get("type")?.asString {
            case "needs_discharge"?: err = PCA.needsDischargeError(c)
            case "max_uses"?: err = PCA.maxUsesError(c)
            case "derive"?: err = PCA.deriveError(c)
            case "spiffe_bound"?: err = PCA.spiffeBoundError(c)
            default: err = "unknown type"
            }
            XCTAssertEqual(err == nil, v.get("expect")?.get("valid") == .bool(true), "\(n): \(err ?? "valid")")
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 50)
    }

    func testUsesKeyVectors() throws {
        var ran = 0
        for v in try Self.table("uses_key") {
            let i = v.get("input")
            let got = PCA.maxUsesSlotKey(capHash: i?.get("cap_hash")?.asString ?? "", id: i?.get("id")?.asString ?? "", i: Int(IV.int(i?.get("i")) ?? -1))
            XCTAssertEqual(got, v.get("expect")?.get("key")?.asString, v.get("name")?.asString ?? "?")
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 5)
    }

    func testUsesReserveVectors() throws {
        var ran = 0
        for v in try Self.table("uses_reserve") {
            let n = v.get("name")?.asString ?? "?"
            let i = v.get("input")
            let bound = (i?.get("bound")?.asArray ?? []).map {
                BoundCaveat(caveat: $0.get("caveat") ?? .null, hop: 0, capHash: $0.get("cap_hash")?.asString ?? "")
            }
            let store = MemoryStateStore()
            let calls = i?.get("calls")?.asArray ?? []
            let want = v.get("expect")?.get("results")?.asArray ?? []
            XCTAssertEqual(calls.count, want.count, n)
            for (k, call) in calls.enumerated() where k < want.count {
                let r = PCA.reserveMaxUses(store: store, bound: bound, now: Self.clock(call.get("now")))
                let e = want[k]
                XCTAssertEqual(r.ok, e.get("ok") == .bool(true), "\(n)#\(k): \(r.reason)")
                if r.ok {
                    XCTAssertEqual(Int64(r.spent), IV.int(e.get("spent")), "\(n)#\(k)")
                } else {
                    let w = e.get("reason_contains")?.asString ?? "\u{0}"
                    XCTAssertTrue(r.reason.contains(w), "\(n)#\(k): reason '\(r.reason)' lacks '\(w)'")
                }
            }
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 12)
    }

    func testSpiffeVectors() throws {
        var ran = 0
        for v in try Self.table("spiffe_id") {
            let id = v.get("input")?.get("id")
            XCTAssertEqual(PCA.spiffeIdError(id) == nil, v.get("expect")?.get("valid") == .bool(true), v.get("name")?.asString ?? "?")
            ran += 1
        }
        XCTAssertGreaterThanOrEqual(ran, 24)
    }

    // ---- exact outcomes beyond the shared vectors ----

    func testHostileInputsAreRefusalsNotTraps() {
        let junk: [JSONValue?] = [nil, .null, .bool(true), .int(1), .double(1.5), .string("x"), .array([]), .array([.null]), .object([:])]
        let bind = DischargeBinding(capHash: "", pins: [], now: 1)
        for j in junk {
            XCTAssertFalse(PCA.verifyDischarge(j, j, bind).ok)
            XCTAssertFalse(PCA.verifyNarrow(j, grant: j ?? .null, chain: j, now: 1).ok)
            XCTAssertNotNil(PCA.needsDischargeError(j))
            XCTAssertNotNil(PCA.maxUsesError(j))
            XCTAssertNotNil(PCA.deriveError(j))
            XCTAssertNotNil(PCA.spiffeBoundError(j))
            XCTAssertNotNil(PCA.dischargeShapeError(j))
            XCTAssertNotNil(PCA.narrowShapeError(j))
            let r = PCA.evaluateK1(grant: j ?? .null, chain: j, k1: K1Input(narrow: j), now: 1, action: j)
            XCTAssertFalse(r.ok)
        }
        XCTAssertEqual(PCA.spiffeIdError(.int(1)), "SPIFFE ID must be a non-empty string")
        XCTAssertEqual(PCA.deriveError(.array([])), "caveat must be an object")
    }

    func testClockIsCheckedWithoutOverflow() {
        XCTAssertEqual(PCA.verifyDischarge(.null, .null, DischargeBinding(capHash: "", pins: [], now: Int64.min)).reason, "the verifier clock is not a safe integer (fail closed)")
        XCTAssertEqual(PCA.reserveMaxUses(store: MemoryStateStore(), bound: [], now: Int64.max).reason, "the verifier clock is not a safe integer (fail closed)")
        let r = PCA.evaluateK1(grant: .object(["caveats": .array([])]), chain: nil, k1: K1Input(), now: Int64.min, action: nil)
        XCTAssertEqual(r.failed, ["<malformed>"])
        XCTAssertEqual(r.reasons, ["the verifier clock is not a safe integer (fail closed)"])
    }

    func testSealedHopIsOnlyOkAtTheLeaf() {
        let sealed: JSONValue = .object(["type": .string("sealed")])
        let root: JSONValue = .object(["id": .string("r"), "caveats": .array([sealed])])
        let child: JSONValue = .object(["id": .string("c"), "caveats": .array([sealed, .object(["type": .string("expires"), "at": .int(5)])])])
        let alone = PCA.evaluateK1(grant: root, chain: .array([root]), k1: K1Input(), now: 1, action: nil)
        XCTAssertTrue(alone.ok)
        let below = PCA.evaluateK1(grant: root, chain: .array([root, child]), k1: K1Input(), now: 1, action: nil)
        XCTAssertEqual(below.failed, ["sealed"])
        XCTAssertEqual(below.reasons, ["a hop was appended below a sealed hop"])
        XCTAssertEqual(below.bound.map { $0.hop }, [0])
    }

    func testMaxUsesSpendsThroughAThrowingStoreAsARefusal() {
        struct Broken: PCAStateStore, Error {
            func claim(key: String, counter: Int64) throws -> ClaimResult { throw self }
        }
        let c: JSONValue = .object(["type": .string("max_uses"), "id": .string("u"), "n": .int(1), "until": .int(100)])
        let r = PCA.reserveMaxUses(store: Broken(), bound: [BoundCaveat(caveat: c, hop: 0, capHash: "h")], now: 1)
        XCTAssertFalse(r.ok)
        XCTAssertEqual(r.reason, "max_uses error (fail closed): the replay store failed")
    }

    func testDeriveIsKleeneAndNeverCoerces() {
        func run(_ check: JSONValue) -> [String] {
            let c: JSONValue = .object(["type": .string("derive"), "id": .string("d"), "defs": .array([]), "check": check])
            let g: JSONValue = .object(["id": .string("g"), "caveats": .array([c])])
            return PCA.evaluateK1(grant: g, chain: nil, k1: K1Input(), now: 1, action: nil).reasons
        }
        func cmp(_ op: String, _ a: JSONValue, _ b: JSONValue) -> JSONValue {
            .object(["op": .string(op), "a": .object(["const": a]), "b": .object(["const": b])])
        }
        XCTAssertEqual(run(cmp("eq", .int(1), .int(1))), [])
        XCTAssertEqual(run(cmp("eq", .int(1), .bool(true))), ["derive check is false"])
        XCTAssertEqual(run(cmp("eq", .int(1), .string("1"))), ["derive check is false"])
        XCTAssertEqual(run(cmp("lt", .string("a"), .string("b"))), ["derive check is unknown (a fact is missing)"])
        XCTAssertEqual(run(.object(["const": .bool(true)])), [])
    }

    // ---- PCA.authorize with the optional `k1` input ----

    func testAuthorizeRefusesK1CaveatsWithoutK1AndAdmitsThemWithIt() {
        let sealed: JSONValue = .object(["type": .string("sealed")])
        let s = AZ.signed(rootCaveats: [sealed])
        // default off: the caveat type is unknown to the stock evaluator, so the chain stays refused
        let off = AZ.run(s)
        XCTAssertFalse(off.allow)
        XCTAssertTrue(off.reasons.contains { $0.contains("the caveat language is not configured (no k1 input)") }, "\(off.reasons)")
        let r = AZ.run(s) { $0.k1 = K1Input() }
        XCTAssertTrue(r.allow, "\(r.reasons)")
        // an ordinary grant is untouched by the new input
        XCTAssertTrue(AZ.run(AZ.signed()) { $0.k1 = K1Input() }.allow)
    }

    func testAuthorizeRefusesAnUndischargedCaveat() {
        let nd: JSONValue = .object(["type": .string("needs_discharge"), "id": .string("kyc"), "issuer": .string("risk-team"), "issuer_class": .string("human"),
                                     "bind": .string("chain_hop"), "ttl_ms": .int(600_000), "require": .array([])])
        let r = AZ.run(AZ.signed(rootCaveats: [nd])) { $0.k1 = K1Input() }
        XCTAssertFalse(r.allow)
        XCTAssertTrue(r.failedChecks.contains("delegated_caveats"), "\(r.failedChecks)")
        XCTAssertTrue(r.reasons.contains { $0.contains("no discharge presented") }, "\(r.reasons)")
    }

    func testAuthorizeSpendsMaxUsesOnlyAfterTheCounterClaim() {
        let mu: JSONValue = .object(["type": .string("max_uses"), "id": .string("u"), "n": .int(1), "until": .int(AZ.NOW + 100_000)])
        let counters = MemoryStateStore()
        let uses = MemoryStateStore()
        func go(_ s: AZ.Signed, _ store: (any PCAStateStore)?) -> PCA.AuthorizeResult {
            AZ.run(s) {
                $0.stateStore = counters
                $0.k1 = K1Input()
                $0.usesStore = store
            }
        }
        // one grant (its hash keys the use slots), a new counter per action
        let base = AZ.signed(rootCaveats: [mu])
        func at(_ counter: Int64) -> AZ.Signed {
            AZ.Signed(grant: base.grant, pcactn: AZ.proof(base.grant, params: base.params, declared: "irreversible", counter: counter, now: AZ.NOW, aud: AZ.AUD),
                      params: base.params)
        }
        // no usesStore: refused with a clear reason (fail closed)
        let none = go(at(1), nil)
        XCTAssertFalse(none.allow)
        XCTAssertEqual(none.failedChecks, ["max_uses"])
        XCTAssertTrue(none.reasons.contains("max_uses: the chain carries a max_uses caveat and this guard has no usesStore (fail closed)"), "\(none.reasons)")
        // the one use is spent by the first admitted action, the next is refused
        let first = go(at(2), uses)
        XCTAssertTrue(first.allow, "\(first.reasons)")
        let second = go(at(3), uses)
        XCTAssertFalse(second.allow)
        XCTAssertEqual(second.failedChecks, ["max_uses"])
        XCTAssertTrue(second.reasons.contains("max_uses: max_uses 'u' is exhausted"), "\(second.reasons)")
    }
}
