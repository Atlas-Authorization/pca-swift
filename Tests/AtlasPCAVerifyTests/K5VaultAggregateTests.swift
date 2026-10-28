import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replays the SHARED vault and aggregate vectors (packages/pca/conformance/vault-aggregate-vectors.json). A missing file FAILS (load throws).
final class K5VaultAggregateTests: XCTestCase {
    func vectors() throws -> JSONValue { try ConformanceTests.load("vault-aggregate-vectors.json") }

    func testSamplerStreams() throws {
        let V = try vectors()
        var f: [String] = []
        let us = V.get("sampler")?.get("uniform")?.asArray ?? []
        let ls = V.get("sampler")?.get("laplace")?.asArray ?? []
        if us.isEmpty || ls.isEmpty { f.append("sampler: no cases") }
        for u in us {
            let d = ReadVault.seededDraws(u.get("seed")?.asString ?? "")
            let bounds = (u.get("bounds")?.asArray ?? []).map { $0.safeInt ?? -1 }
            let want = (u.get("draws")?.asArray ?? []).map { $0.safeInt ?? -1 }
            let got = bounds.map { (try? d.uniform($0)) ?? -2 }
            if got != want || want.isEmpty { f.append("uniform \(u.get("seed")?.asString ?? "?"): got \(got) want \(want)") }
        }
        for l in ls {
            let d = ReadVault.seededDraws(l.get("seed")?.asString ?? "")
            let want = (l.get("values")?.asArray ?? []).map { $0.safeInt ?? Int64.min }
            let s = l.get("s")?.safeInt ?? 0, t = l.get("t")?.safeInt ?? 0
            let got = want.map { _ in (try? ReadVault.discreteLaplace(d, s, t)) ?? Int64.min }
            if got != want || want.isEmpty { f.append("laplace \(l.get("seed")?.asString ?? "?"): got \(got) want \(want)") }
        }
        // bad bounds are errors, never traps
        let d = ReadVault.seededDraws("x")
        let badBounds: [Int64] = [0, -1, (Int64(1) << 47) + 1, Int64.max, Int64.min]
        for n in badBounds where (try? d.uniform(n)) != nil { f.append("uniform(\(n)) did not throw") }
        let badPairs: [(Int64, Int64)] = [(0, 5), (-1, 5), (5, 0), (5, Int64.max)]
        for (s, t) in badPairs where (try? ReadVault.discreteLaplace(d, s, t)) != nil { f.append("laplace(\(s),\(t)) did not throw") }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }

    func testVault() throws {
        let V = try vectors()
        let cases = V.get("vault")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 13)
        let grants = V.get("grants")?.get("vault")
        var f: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            let store = MemoryVault()
            let red = ReadVault.redactReadWithVault(grant: grants?.get(c.get("redact_grant")?.asString ?? ""), input: c.get("redact"), store: store)
            var token = red.view[JKey(c.get("field")?.asString ?? "")]
            if let t = c.get("token"), !t.isNull { token = t }
            let d = c.get("detok")
            let got = ReadVault.detokenize(grant: grants?.get(c.get("detok_grant")?.asString ?? ""), principal: d?.get("principal"), now: d?.get("now"),
                                           sink: d?.get("sink"), token: token, store: store)
            if got.json != c.get("expect") { f.append("vault \(name): got \(got.json)") }
        }
        // hostile input never traps and always denies
        let hostile: [JSONValue?] = [nil, .null, .int(1), .string("x"), .array([]), .object([:])]
        for x in hostile where ReadVault.detokenize(grant: x, principal: x, now: x, sink: x, token: x, store: MemoryVault()).decision != "deny" { f.append("hostile detokenize") }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }

    func testAggregate() throws {
        let V = try vectors()
        let cases = V.get("aggregate")?.asArray ?? []
        XCTAssertGreaterThanOrEqual(cases.count, 10)
        let grants = V.get("grants")?.get("aggregate")
        var f: [String] = []
        for c in cases {
            let name = c.get("name")?.asString ?? "?"
            guard var state = AggregateState.parse(c.get("initial_state")) else { f.append("\(name): bad initial_state"); continue }
            for (i, s) in (c.get("steps")?.asArray ?? []).enumerated() {
                var inp: JObject = [
                    "principal": V.get("keys")?.get("principal") ?? .null, "now": .int(1_800_000_000_000), "verb": .string("orders.stats"),
                    "resource": .string("orders/eu"), "purpose": .string("analytics"), "fn": .string("sum"),
                    "values": .array([.int(10), .int(20), .int(500), .int(-900)]), "salt": .string("a-per-read-secret-salt"), "noise": .string("seeded"),
                ]
                let over = s.get("input")?.asObject ?? [:]
                for (k, v) in over where k.s != "grant" { inp[k] = v }
                let r = ReadVault.aggregateRead(
                    grant: grants?.get(over["grant"]?.asString ?? ""), principal: inp["principal"], now: inp["now"], verb: inp["verb"], resource: inp["resource"],
                    purpose: inp["purpose"], fn: inp["fn"], values: inp["values"], salt: inp["salt"], noise: inp["noise"], state: state)
                if r.json != s.get("expect") { f.append("aggregate \(name)[\(i)]: got \(r.json)") }
                state = r.state
            }
        }
        XCTAssertTrue(f.isEmpty, f.joined(separator: "\n"))
    }

    func testBadStateIsEmptyAndHostileInputDenies() throws {
        let V = try vectors()
        let g = V.get("grants")?.get("aggregate")?.get("main")
        let p = V.get("keys")?.get("principal")
        let bad = AggregateState(spentMicro: -1, queries: 0, answered: [:])
        let r = ReadVault.aggregateRead(grant: g, principal: p, now: .int(1_800_000_000_000), verb: .string("orders.stats"), resource: .string("orders/eu"),
                                        purpose: .string("analytics"), fn: .string("sum"), values: .array([.int(1), .int(2), .int(3)]),
                                        salt: .string("a-per-read-secret-salt"), noise: .string("seeded"), state: bad)
        XCTAssertEqual(r.code, "bad_request")
        XCTAssertEqual(r.state, .empty)
        let hostile: [JSONValue?] = [nil, .null, .int(1), .string("x"), .array([]), .object([:])]
        let st = AggregateState(spentMicro: 5, queries: 1, answered: [:])
        for x in hostile {
            let h = ReadVault.aggregateRead(grant: x, principal: x, now: x, verb: x, resource: x, purpose: x, fn: x, values: x, salt: x, noise: x, state: st)
            XCTAssertEqual(h.decision, "deny")
            XCTAssertEqual(h.state, st)
        }
    }

    func testSecureNoiseDiffersPerCall() throws {
        let a = ReadVault.secureDraws(), b = ReadVault.secureDraws()
        let da = try (0..<8).map { _ in try a.uniform(Int64(1) << 40) }
        let db = try (0..<8).map { _ in try b.uniform(Int64(1) << 40) }
        XCTAssertNotEqual(da, db)
        let V = try vectors()
        let r = ReadVault.aggregateRead(grant: V.get("grants")?.get("aggregate")?.get("main"), principal: V.get("keys")?.get("principal"),
                                        now: .int(1_800_000_000_000), verb: .string("orders.stats"), resource: .string("orders/eu"), purpose: .string("analytics"),
                                        fn: .string("sum"), values: .array([.int(10), .int(20), .int(30)]), salt: .string("a-per-read-secret-salt"),
                                        noise: .string("secure"), state: .empty)
        XCTAssertEqual(r.decision, "allow")
        XCTAssertEqual(r.chargedMicro, 500_000)
    }
}
