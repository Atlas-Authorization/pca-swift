import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the guardian high-availability module (liveness, quorum, degrade mode, signer selection, failover, the fenced
/// lease, the fence guard, the key-value lease store) against the reference: every case of the shared corpus.
final class RefHaTests: XCTestCase {
    /// A lease store over an in-memory cell with injectable faults and a settable clock (the corpus's `fault` / `clock` / `raw` operations).
    final class FaultStore: PCAHa.LeaseStore {
        let kv = PCAHa.MemoryKv()
        lazy var inner = PCAHa.KvLeaseStore(kv)
        var clock = 0.0
        var fault = "none"
        var loseNext = false
        func read() throws -> JSONValue? { if fault == "read" { throw JSError("boom") }; return try inner.read() }
        func now() throws -> Double { if fault == "now" { throw JSError("boom") }; return clock }
        func cas(_ expected: JSONValue?, _ next: JSONValue) throws -> Bool {
            if fault == "cas" { throw JSError("boom") }
            if loseNext { loseNext = false; return false }
            return try inner.cas(expected, next)
        }
    }

    private func runLease(_ ops: [JSONValue]) -> JSONValue {
        let store = FaultStore()
        var refs: [String: JSONValue] = [:]
        func resolve(_ v: JSONValue?) -> JSONValue? { if case let .string(s)? = v { return refs[s] }; return v }
        var out: [JSONValue] = []
        for op in ops {
            guard let a = op.asArray, let name = a.first?.asString else { out.append(.null); continue }
            func arg(_ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }
            switch name {
            case "clock": store.clock = JS.toNumber(arg(1)); out.append(.null)
            case "fault":
                let k = arg(1)?.asString ?? "none"
                if k == "loseCas" { store.loseNext = true } else { store.fault = k }
                out.append(.null)
            case "raw": store.kv.set("ha/lease", arg(1)); out.append(.null)
            case "read": out.append(store.kv.get("ha/lease") ?? .null)
            case "acquire":
                let r = PCAHa.acquireLease(store, arg(2), arg(3))
                if r.get("ok") == .bool(true), let ref = arg(1)?.asString, let l = r.get("lease") { refs[ref] = l }
                out.append(r)
            case "renew": out.append(PCAHa.renewLease(store, resolve(arg(1)), arg(2)))
            case "release":
                let r = PCAHa.releaseLease(store, resolve(arg(1)))
                if r.get("ok") == .bool(true), let ref = arg(1)?.asString, let l = r.get("lease") { refs[ref] = l }
                out.append(r)
            case "fence": out.append(PCAHa.assertFence(store, resolve(arg(1)), JS.present(arg(2))))
            case "signer":
                let lease = resolve(JS.present(arg(1)))
                let advance = JS.toNumber(arg(3)), boom = JS.truthy(arg(4))
                let run = PCAHa.fencedSigner(store, getLease: { lease }, sign: { () throws -> String in
                    store.clock += advance
                    if boom { throw JSError("sign") }
                    return "signed"
                }, skewMs: JS.present(arg(2)))
                do {
                    let r = try run()
                    out.append(.object(["ok": .bool(true), "result": .string(r.result), "epoch": r.epoch]))
                } catch let e as PCAHa.FenceError { out.append(.object(["ok": .bool(false), "reason": .string(e.reason)]))
                } catch { out.append(.object(["ok": .bool(false), "error": .string("sign")])) }
            // the reference's scenario driver throws `bad op` for an op it does not know, and the step is recorded as that error
            default: out.append(.object(["$err": .string("bad op")]))
            }
        }
        return .array(out)
    }

    func testReplay() throws {
        let d = Base.Diffs()
        var seen: [String: Int] = [:]
        let n = try Base.each("ref-ha.json.gz") { c in
            seen[c.fn, default: 0] += 1
            let a = c.args.map { RefAnalyzer.revive($0) }
            func arg(_ i: Int) -> JSONValue? { i < a.count ? JS.present(a[i]) : nil }
            func ids(_ v: [JSONValue]) -> JSONValue { .array(v) }
            let got = Base.run({ ($0 as? JSError)?.code }) { () -> JSONValue in
                switch c.fn {
                case "liveGuardians": return .array(PCAHa.liveGuardians(arg(0), arg(1), arg(2)))
                case "quorumStatus": return PCAHa.quorumStatus(arg(0), arg(1), arg(2))
                case "degradeMode": return .string(PCAHa.degradeMode(arg(0), arg(1)))
                case "selectSigners": return .array(try PCAHa.selectSigners(arg(0), arg(1), arg(2)))
                case "failoverPlan": return try PCAHa.failoverPlan(arg(0), arg(1), arg(2))
                case "validateGuardianSet": return PCAHa.validateGuardianSet(arg(0)).map { .string($0) } ?? .null
                case "fenceGuard":
                    let g = PCAHa.FenceGuard(initial: arg(0))
                    let admits = (a[1].asArray ?? []).map { JSONValue.bool(g.admit($0)) }
                    return .object(["admits": .array(admits), "highest": .int(g.highest())])
                case "lease": return runLease(a[0].asArray ?? [])
                case "kvCas":
                    let kv = PCAHa.MemoryKv()
                    if let prev = arg(0) { kv.set("ha/lease", prev) }
                    let ok = try PCAHa.KvLeaseStore(kv).cas(arg(1), a[2])
                    return .object(["ok": .bool(ok), "stored": kv.get("ha/lease") ?? .null])
                case "constants": return .object(["MAX_LEASE_TTL_MS": .int(PCAHa.MAX_LEASE_TTL_MS), "DEFAULT_LEASE_SKEW_MS": .int(PCAHa.DEFAULT_LEASE_SKEW_MS)])
                default: XCTFail("unhandled fn \(c.fn)"); return .null
                }
            }
            if case let .value(v) = got { d.add(c, Base.diff(c, .value(RefAnalyzer.out(v)))) } else { d.add(c, Base.diff(c, got)) }
        }
        XCTAssertEqual(n, 753)
        XCTAssertEqual(seen, ["liveGuardians": 144, "quorumStatus": 144, "degradeMode": 70, "selectSigners": 144, "failoverPlan": 144, "validateGuardianSet": 33,
                              "fenceGuard": 11, "lease": 45, "kvCas": 17, "constants": 1])
        d.finish(753)
    }
}
