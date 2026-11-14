import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Kills the ReadVault.swift survivors of round 2, sheet surv1. Pinned to packages/pca/src/read-vault.ts (same bounds, same order of checks).
final class S2R1ReadVaultKillTests: XCTestCase {
    typealias F = V2F
    private static let key = F.key("s2r1-agg")
    private static var pub: String { F.pub(key) }
    private static let rkey = F.key("s2r1-read")
    private static var rpub: String { F.pub(rkey) }
    private func s(_ x: String) -> JSONValue { .string(x) }
    private func rep(_ n: Int, _ c: String = "a") -> String { String(repeating: c, count: n) }
    private func names(_ p: String, _ n: Int) -> [String] { (0..<n).map { "\(p)\($0 < 10 ? "0" : "")\($0)" } }

    // ---- uniform: rejection sampling (lines 123, 124, 127) ----

    func testUniformRejectsADrawAtTheLimit() throws {
        // n = 3: 2^48 mod 3 = 1, so limit = 2^48 - 1. A draw equal to the limit is rejected (strict <); the next draw 5 gives 5 mod 3 = 2.
        let d = ReadVault.seededDraws("s2r1")
        d.buf = [5, (Int64(1) << 48) - 1] // reversed: the last element is drawn first
        let r = try d.uniform(3)
        XCTAssertEqual(r, 2, "lines 123/124/127: the draw 2^48-1 is rejected, the next one is used")
        XCTAssertTrue(d.buf.isEmpty)
    }

    // ---- MAX_STEPS (lines 157, 309, 330) ----

    func testBernExpSmallRunsExactlyMaxStepsDraws() {
        // every draw is 0, so every Bernoulli(5 / k) is true: the loop never ends by itself and stops at k = MAX_STEPS, one draw per k.
        let d = ReadVault.seededDraws("s2r1")
        d.buf = [Int64](repeating: 0, count: 100_010)
        XCTAssertThrowsError(try ReadVault.bernExpSmall(d, 5, 1))
        XCTAssertEqual(d.buf.count, 10, "lines 157/309: exactly 100000 draws were consumed")
        XCTAssertEqual(ReadVault.MAX_STEPS, 100_000)
    }

    func testDiscreteLaplaceAllowsExactlyMaxStepsGeometricSteps() throws {
        // Crafted draws: u = 0; the first Bernoulli is true; then MAX_STEPS "true" Bernoullis (3 draws each), then one false; sign draw 0.
        var seq: [Int64] = [0, 0]
        for _ in 0..<100_000 { seq += [0, 0, 1] }
        seq += [0, 1, 0]
        let d = ReadVault.seededDraws("s2r1")
        d.buf = Array(seq.reversed())
        let y = try ReadVault.discreteLaplace(d, 1, 1)
        XCTAssertEqual(y, 100_000, "line 330: v = MAX_STEPS is still allowed (the check is v > MAX_STEPS)")
        XCTAssertTrue(d.buf.isEmpty)
        // one more step is refused
        var seq2: [Int64] = [0, 0]
        for _ in 0..<100_001 { seq2 += [0, 0, 1] }
        seq2 += [0, 1, 0]
        let e = ReadVault.seededDraws("s2r1")
        e.buf = Array(seq2.reversed())
        XCTAssertThrowsError(try ReadVault.discreteLaplace(e, 1, 1))
    }

    // ---- safeInt (line 160) ----

    func testSafeIntBounds() {
        let m = Canonical.MAX_SAFE
        XCTAssertEqual(ReadVault.safeInt(JSONValue.int(m)), m, "line 160: upper bound is inclusive")
        XCTAssertEqual(ReadVault.safeInt(JSONValue.int(-m)), -m, "line 160: lower bound is inclusive")
        XCTAssertNil(ReadVault.safeInt(JSONValue.int(m + 1)))
        XCTAssertNil(ReadVault.safeInt(JSONValue.int(-m - 1)))
        XCTAssertEqual(ReadVault.safeInt(JSONValue.int(0)), 0)
        XCTAssertNil(ReadVault.safeInt(JSONValue.string("1")))
    }

    // ---- secureDraws seed length (line 293) ----

    func testSecureSeedIs32Bytes() {
        let d = ReadVault.secureDraws()
        XCTAssertEqual(d.seed.count, 43, "line 293: 32 bytes are 43 base64url characters")
        XCTAssertEqual(Base64URLStrict.decode(d.seed, length: 32)?.count, 32)
    }

    // ---- redactReadWithVault records only token masks (line 170) ----

    func testOnlyTokenMasksAreStored() {
        let entry: JObject = ["verb": s("v"), "resource_prefix": s("/"), "purposes": .array([s("p")]),
                              "modes": .object(["pan": s("last4"), "sec": s("token")]), "default_mode": s("drop")]
        let body: JObject = ["v": .int(1), "id": s("g1"), "principal": s(Self.rpub), "issued_at": .int(0), "expires_at": .int(10_000),
                             "reads": .array([.object(entry)]), "caps": .object([:]), "sinks": .object([:])]
        let grant: JSONValue = .object(["body": .object(body), "sig": s(F.sign(Self.rkey, IV.message(ReadSide.READ_GRANT_DOMAIN, .object(body))!))])
        let input: JSONValue = .object([
            "principal": s(Self.rpub), "now": .int(1000), "verb": s("v"), "resource": s("/r"), "purpose": s("p"),
            "schema": .object(["fields": .object(["card": s("pan"), "ssn": s("sec")]), "required": .array([])]),
            "record": .object(["card": s("abcde"), "ssn": s("123-45")]), "tighten": .object([:]), "salt": s(rep(16)), "counts": .object([:]),
        ])
        let store = MemoryVault()
        let r = ReadVault.redactReadWithVault(grant: grant, input: input, store: store)
        XCTAssertEqual(r.decision, "allow")
        XCTAssertEqual(r.view["card"], s("****bcde"), "a masked non-token field")
        let tok = r.view["ssn"]?.asString ?? ""
        XCTAssertTrue(tok.hasPrefix("tok_"))
        XCTAssertEqual(store.get(tok)?.value, s("123-45"), "the token mask is stored")
        XCTAssertEqual(store.get(tok)?.cls, "sec")
        XCTAssertNil(store.get("****bcde"), "line 170: a masked field that is not a token is never stored")
    }

    // ---- detokenize: an entry that expires exactly now (line 186) ----

    func testDetokenizeEntryExpiresAtNow() throws {
        let V = try ConformanceTests.load("vault-aggregate-vectors.json")
        let grant = V.get("grants")?.get("vault")?.get("main")
        let principal = V.get("keys")?.get("principal")
        let g = ReadSide.parseGrant(grant?.get("body"))
        XCTAssertNotNil(g)
        let digest = ReadSide.readGrantDigest(g!.raw)!
        let now: Int64 = 1_800_000_000_000
        let store = MemoryVault()
        store.put("tok_edge", VaultEntry(cls: "ref", value: s("v"), grant: digest, exp: now))
        store.put("tok_live", VaultEntry(cls: "ref", value: s("v"), grant: digest, exp: now + 1))
        let a = ReadVault.detokenize(grant: grant, principal: principal, now: .int(now), sink: s("payments"), token: s("tok_edge"), store: store)
        XCTAssertEqual(a.decision, "deny", "line 186: now == exp is expired")
        XCTAssertEqual(a.code, "expired")
        let b = ReadVault.detokenize(grant: grant, principal: principal, now: .int(now), sink: s("payments"), token: s("tok_live"), store: store)
        XCTAssertEqual(b.decision, "allow")
        XCTAssertEqual(b.value, s("v"))
    }

    // ---- parseRule bounds (lines 197-201) ----

    private func rule(verb: String = "v", prefix: String = "/", purposes: [String] = ["p"], fns: [String] = ["count", "sum"], mg: Int64 = 1,
                      clamp: Int64 = 100, eps: Int64 = 0, dp: Bool = false) -> JObject {
        ["verb": s(verb), "resource_prefix": s(prefix), "purposes": .array(purposes.map { s($0) }), "fns": .array(fns.map { s($0) }),
         "min_group": .int(mg), "clamp": .int(clamp), "epsilon_micro": .int(eps), "dp": .bool(dp)]
    }
    private func ok(_ r: JObject) -> Bool { ReadVault.parseRule(.object(r)) != nil }

    func testRuleBounds() {
        XCTAssertTrue(ok(rule()))
        XCTAssertTrue(ok(rule(verb: rep(128))), "line 197")
        XCTAssertFalse(ok(rule(verb: rep(129))), "line 197")
        XCTAssertTrue(ok(rule(prefix: rep(512))), "line 197")
        XCTAssertFalse(ok(rule(prefix: rep(513))), "line 197")
        XCTAssertTrue(ok(rule(purposes: names("p", 16))), "line 198")
        XCTAssertFalse(ok(rule(purposes: names("p", 17))), "line 198")
        XCTAssertFalse(ok(rule(purposes: [])))
        XCTAssertTrue(ok(rule(fns: ["count", "sum"])), "line 199")
        XCTAssertFalse(ok(rule(fns: ["count", "sum", "sum"])), "line 199")
        XCTAssertTrue(ok(rule(mg: 1)), "line 200: min_group 1 is the least")
        XCTAssertFalse(ok(rule(mg: 0)), "line 200")
        XCTAssertTrue(ok(rule(clamp: 1_000_000)), "line 200: clamp bound is inclusive")
        XCTAssertFalse(ok(rule(clamp: 1_000_001)), "line 200")
        XCTAssertTrue(ok(rule(clamp: 999_999)))
        XCTAssertTrue(ok(rule(eps: 1_073_741_824)), "line 201: epsilon bound is inclusive")
        XCTAssertFalse(ok(rule(eps: 1_073_741_825)), "line 201")
        XCTAssertTrue(ok(rule(eps: 1_073_741_823)))
        XCTAssertTrue(ok(rule(eps: 1, dp: true)), "line 201: dp needs at least 1 micro-epsilon")
        XCTAssertFalse(ok(rule(eps: 0, dp: true)), "line 201")
        XCTAssertTrue(ok(rule(eps: 0, dp: false)), "line 201: a non-dp rule may have epsilon 0")
        XCTAssertTrue(ok(rule(eps: 2, dp: true)))
    }

    // ---- parseAggGrant rule count (line 211) ----

    func testGrantRuleCount() {
        func body(_ n: Int) -> JSONValue {
            .object(["v": .int(1), "id": s("ag"), "principal": s(Self.pub), "issued_at": .int(100), "expires_at": .int(200),
                     "rules": .array(Array(repeating: JSONValue.object(rule()), count: n)), "epsilon_budget_micro": .int(0), "max_queries": .int(5)])
        }
        XCTAssertNotNil(ReadVault.parseAggGrant(body(16)), "line 211")
        XCTAssertNotNil(ReadVault.parseAggGrant(body(1)))
        XCTAssertNil(ReadVault.parseAggGrant(body(17)), "line 211")
        XCTAssertNil(ReadVault.parseAggGrant(body(0)))
    }

    // ---- aggregate request checks (lines 244-249) ----

    private func signedAgg(verb: String = "v", iat: Int64 = 100, exp: Int64 = 200) -> JSONValue {
        let body: JObject = ["v": .int(1), "id": s("ag"), "principal": s(Self.pub), "issued_at": .int(iat), "expires_at": .int(exp),
                             "rules": .array([.object(rule(verb: verb))]), "epsilon_budget_micro": .int(0), "max_queries": .int(5)]
        return .object(["body": .object(body), "sig": s(F.sign(Self.key, IV.message(ReadVault.AGGREGATE_DOMAIN, .object(body))!))])
    }

    private func read(_ grant: JSONValue, now: Int64 = 150, verb: String = "v", resource: String = "/r", salt: String? = nil,
                      values: [JSONValue]? = nil) -> AggregateResult {
        ReadVault.aggregateRead(grant: grant, principal: s(Self.pub), now: .int(now), verb: s(verb), resource: s(resource), purpose: s("p"), fn: s("count"),
                                values: .array(values ?? [.int(1), .int(2), .int(3)]), salt: s(salt ?? rep(16)), noise: s("seeded"), state: .empty)
    }

    func testIssuedAtIsInclusive() {
        let g = signedAgg(iat: 100, exp: 200)
        let at = read(g, now: 100)
        XCTAssertEqual(at.decision, "allow", "line 244: valid from issued_at")
        XCTAssertEqual(at.value, 3)
        XCTAssertEqual(read(g, now: 99).code, "not_yet")
        XCTAssertEqual(read(g, now: 200).code, "expired")
        XCTAssertEqual(read(g, now: 199).decision, "allow")
    }

    func testRequestStringBounds() {
        let g = signedAgg(verb: rep(128))
        XCTAssertEqual(read(g, verb: rep(128)).decision, "allow", "line 246: verb of 128")
        XCTAssertEqual(read(g, verb: rep(129)).code, "bad_request", "line 246: verb of 129")
        XCTAssertEqual(read(g, verb: rep(128), resource: "/" + rep(511)).decision, "allow", "line 246: resource of 512")
        XCTAssertEqual(read(g, verb: rep(128), resource: "/" + rep(512)).code, "bad_request", "line 246: resource of 513")
    }

    func testSaltMinimum() {
        let g = signedAgg()
        XCTAssertEqual(read(g, salt: rep(16)).decision, "allow", "line 248: a salt of SALT_MIN units")
        XCTAssertEqual(read(g, salt: rep(15)).code, "bad_request", "line 248")
    }

    func testValuesCap() {
        let g = signedAgg()
        var vs = [JSONValue](repeating: JSONValue.int(1), count: 1_000_000)
        let a = read(g, values: vs)
        XCTAssertEqual(a.decision, "allow", "line 249: 1000000 rows are accepted")
        XCTAssertEqual(a.value, 1_000_000)
        vs.append(JSONValue.int(1))
        XCTAssertEqual(read(g, values: vs).code, "bad_request", "line 249: 1000001 rows are refused")
    }
}
