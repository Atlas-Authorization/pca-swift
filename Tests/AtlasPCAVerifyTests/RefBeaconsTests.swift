import XCTest
import Foundation
@testable import AtlasPCAVerify
#if canImport(AtlasPCAOpenSSL)
import AtlasPCAOpenSSL
#endif

/// Dead-man liveness beacons (issue, signed message, reference, verification, strictly monotonic acceptance, frozen liveness, the durable acceptor over a
/// key/value store that can fail) against the reference corpus: every case, every fn. Where the reference accepts an unreadable clock (NaN, a numeric
/// string, none) or reads a string as the issuer list (substring match), the typed arguments of this SDK cannot express the input: those five cases are
/// counted and asserted, and an infinite clock maps to the extreme representable one. The legacy opt-out `allowUnboundPq` is not supported.
final class RefBeaconsTests: XCTestCase {
    typealias A = RefAnalyzer

    private static func mlDsa(_ seed: [UInt8]) throws -> PCAPQKey {
        #if canImport(AtlasPCAOpenSSL)
        if PCAOpenSSL.mlDsaAvailable() { return try PCAOpenSSL.mlDsaKey(.mlDsa65, seed: seed) }
        #endif
        return try PCAPQKey.fromSeed(.mlDsa65, seed: seed)
    }
    private static var exactMlDsa: Bool {
        #if canImport(AtlasPCAOpenSSL)
        return PCAOpenSSL.mlDsaAvailable()
        #else
        return false
        #endif
    }

    private static func strictInt(_ v: JSONValue?) throws -> Int64 {
        guard let v = v, let i = v.safeInt else { throw JSError("not an integer") }
        if case let .double(d) = v, d == 0, d.sign == .minus { throw JSError("negative zero") }
        return i
    }

    private static func verdict(_ v: BeaconVerdict) -> JSONValue {
        var o: JObject = ["ok": .bool(v.ok)]
        if let r = v.reason { o["reason"] = .string(r) }
        return .object(o)
    }

    private static func issue(_ a: JSONValue?) throws -> JSONValue {
        guard let a = a, let secret = Base.bytes(a.get("issuerSecret")) else { throw JSError("bad arguments") }
        let ed = try Ed25519Deterministic.key(seed: secret)
        var key = PCASuiteKey.ed25519(ed)
        if let su = JS.present(a.get("suite")) {
            guard let alg = IV.sigAlg(su.get("alg")) else { throw PCAProducerError("alg") }
            key = try PCASuiteKey(alg: alg, ed: ed, pq: try Base.bytes(su.get("pqSeed")).map { try mlDsa($0) })
        }
        let validity: Int64? = try JS.present(a.get("validityMs")).map { try strictInt($0) }
        return try Beacons.issueLivenessBeacon(issuer: key, instanceValue: a.get("instance"), seq: try strictInt(a.get("seq")), issuedAt: try strictInt(a.get("issuedAt")),
                                               scopeValue: a.get("scope"), validityMs: validity)
    }

    /// The typed arguments of a check, or nil when the input cannot be expressed (counted by the caller).
    private static func check(_ c: JSONValue?) -> (issuers: [String], now: Int64, instance: String, scope: String?, pins: [String: String]?)? {
        guard let c = c, case let .array(iss)? = c.get("issuers") else { return nil }
        let now: Int64
        switch c.get("now") {
        case let .double(d)? where d.isInfinite: now = d > 0 ? Int64.max : Int64.min
        case let v? where v.isNumber && !(IV.num(v)?.isNaN ?? true): now = v.safeInt ?? Int64(IV.num(v) ?? 0)
        default: return nil
        }
        var pins: [String: String]? = nil
        if let p = c.get("pqPins")?.asObject { pins = [:]; for (k, v) in p { if let t = v.asString { pins?[k.s] = t } } }
        return (iss.compactMap { $0.asString }, now, c.get("instance")?.asString ?? "", JS.present(c.get("scope"))?.asString, pins)
    }

    private final class FlakyKV: AtomicKV, @unchecked Sendable {
        private let kv = MemoryAtomicKV()
        var failNext = false
        func get(_ key: String) throws -> JSONValue? { kv.get(key) }
        func update(_ key: String, _ f: (JSONValue?) -> JSONValue?) throws {
            if failNext { failNext = false; throw JSError("kv down") }
            kv.update(key, f)
        }
        func put(_ key: String, _ v: JSONValue) { kv.update(key) { _ in v } }
    }

    private static func acceptor(_ ops: [JSONValue]) -> JSONValue {
        let kv = FlakyKV()
        let acc = Beacons.Acceptor(kv: kv)
        return .array(ops.map { op in
            let o = op.asArray ?? []
            switch o.first?.asString {
            case "accept"?:
                guard o.count > 2, let ck = check(o[2]) else { return .null }
                return verdict(acc.accept(o[1], issuers: ck.issuers, now: ck.now, instance: ck.instance, scope: ck.scope, pqPins: ck.pins))
            case "raw"?:
                if o.count > 2, case let .object(m) = o[1] { kv.put(Beacons.Acceptor.key(m), o[2]) }
                return .null
            case "fail"?: kv.failNext = true; return .null
            default: return .object(["$err": .string("op")]) // the reference's harness throws on an operation it does not know
            }
        })
    }

    static let inexpressible = Box()
    final class Box { var n = 0 }

    static func call(_ c: BaseCase) -> BaseGot? {
        let a0 = A.arg(c, 0), a1 = A.arg(c, 1)
        switch c.fn {
        case "constants":
            return .value(.object(["GLOBAL_SCOPE": .string(Beacons.GLOBAL_SCOPE), "BEACON_EPOCH_MS": .int(Beacons.BEACON_EPOCH_MS), "BEACON_MAX_VALIDITY_MS": .int(Beacons.BEACON_MAX_VALIDITY_MS),
                                   "BEACON_CLOCK_SKEW_MS": .int(Beacons.BEACON_CLOCK_SKEW_MS)]))
        case "issueLivenessBeacon": return A.run { try issue(a0) }
        case "livenessBeaconMessage": return A.run { Base.bytesValue(try Beacons.livenessBeaconMessage(a0 ?? .null)) }
        case "beaconRef": return A.run { .string(try Beacons.beaconRef(a0 ?? .null)) }
        case "verifyLivenessBeacon":
            guard let ck = check(a1) else { inexpressible.n += 1; return nil }
            return .value(verdict(Beacons.verifyLivenessBeacon(a0, issuers: ck.issuers, now: ck.now, instance: ck.instance, scope: ck.scope, pqPins: ck.pins)))
        case "acceptBeacon":
            return .value(verdict(Beacons.acceptBeacon(prev: a0, next: a1)))
        case "isFrozenLiveness":
            guard let ck = check(a1) else { inexpressible.n += 1; return nil }
            return .value(.bool(Beacons.isFrozenLiveness(a0?.asArray ?? [], issuers: ck.issuers, now: ck.now, instance: ck.instance, scope: ck.scope, pqPins: ck.pins)))
        case "acceptor": return .value(acceptor(a0?.asArray ?? []))
        case "ctor":
            // an Acceptor needs an AtomicKV: the reference's loose "has an update function" test has no typed counterpart (the inputs are mapped)
            let built = a0 == .string("ok") || (a0?.get("update")?.asString == "fn")
            return .value(.object(["built": .bool(built)]))
        default: return nil
        }
    }

    private static func signed(_ c: BaseCase, _ got: BaseGot) -> BaseGot {
        guard c.fn == "issueLivenessBeacon", !exactMlDsa, !c.threw, case let .value(v) = got, case var .object(mine) = v, case var .object(want) = c.out, let alg = want["alg"]?.asString else { return got }
        let field = JKey(alg.hasPrefix("hybrid") ? "pq_sig" : "sig")
        mine[field] = nil
        want[field] = nil
        return Base.canon(.object(mine)) == Base.canon(.object(want)) ? .value(c.out) : got
    }

    func testEveryCaseOfTheReferenceCorpus() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        var unbound = 0, skipped = 0
        let n = try Base.each("ref-beacons.json.gz", seeds: true) { c in
            seen[c.fn, default: 0] += 1
            if c.fn == "verifyLivenessBeacon", c.arg(1)?.get("allowUnboundPq") == .bool(true), c.out.get("ok") == .bool(true) {
                guard case let .value(v)? = Self.call(c) else { XCTFail("unhandled"); return }
                XCTAssertEqual(v.get("ok"), .bool(false), c.name)
                unbound += 1
                return
            }
            guard let got = Self.call(c) else {
                if c.fn == "verifyLivenessBeacon" || c.fn == "isFrozenLiveness" { skipped += 1; return }
                XCTFail("unhandled fn \(c.fn)"); return
            }
            let diff = Base.diff(c, Self.signed(c, got))
            if diff != nil, !MLDSA.available, Base.canon(.array(c.args)).contains("ml-dsa") { d.skip("ML-DSA is not available on this OS"); return }
            d.add(c, diff)
        }
        XCTAssertEqual(n, 174)
        XCTAssertEqual(skipped, 5, "the unreadable clock (NaN, a numeric string, none) and the issuer list that is null or a string have no typed counterpart")
        XCTAssertEqual(seen, ["verifyLivenessBeacon": 67, "issueLivenessBeacon": 36, "acceptor": 19, "acceptBeacon": 18, "livenessBeaconMessage": 12, "beaconRef": 8, "isFrozenLiveness": 8,
                              "ctor": 5, "constants": 1])
        d.finish(174 - skipped - unbound - d.skipped.values.reduce(0, +))
    }
}
