import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Replay of chain compaction (hop handles, compact chains, the verified-chain memo), the receipt log, the trust-budget algebra and the standing-approval
/// helpers of core pca against the TypeScript reference (ref-core-sweep-java).
final class RefCoreSweepTests: XCTestCase {
    static let file = "ref-core-sweep-java.json.gz"
    static let err: JSONValue = .object(["$err": .string("Error")])

    func num(_ v: JSONValue?) -> Double { JS.toNumber(v) }
    func list(_ v: JSONValue?) throws -> [JSONValue] { guard let a = v?.asArray else { throw JSError("array expected") }; return a }

    func memoOps(_ ops: [JSONValue]) -> JSONValue {
        var memo = PCAChainCompact.Memo()
        var out: [JSONValue] = []
        for op in ops {
            guard let o = op.asArray, let name = o.first?.asString else { out.append(Self.err); continue }
            do {
                var v: JSONValue = .null
                switch name {
                case "new":
                    let c = o.count > 1 ? o[1] : .null
                    memo = PCAChainCompact.Memo(maxEntries: c.get("maxEntries").flatMap { IV.num($0) }.map { Int($0) }, ttlMs: c.get("ttlMs").flatMap { IV.num($0) })
                case "remember": v = try memo.rememberVerified(try list(o[1]), expectedRootIssuer: o[2].asString, now: num(o[3]))
                case "resolve":
                    let r = memo.resolve(o[1], now: num(o[2]))
                    var res: JObject = ["ok": .bool(r.ok)]
                    if let view = r.view, r.ok {
                        res["view"] = .object(["n": .int(Int64(view.n)), "hashes": .array((0..<view.n).map { .string(view.hash($0)) }),
                                               "counts": .array((0..<view.n).map { .int(Int64(view.count($0))) }), "leaf": view.leaf])
                    } else { res["reason"] = .string(r.reason ?? "") }
                    v = .object(res)
                case "prune": memo.prune(num(o[1]))
                case "forget": v = .bool(memo.forget(o[1].asString ?? ""))
                case "size": v = .int(Int64(memo.size))
                default: throw JSError("op")
                }
                out.append(v)
            } catch { out.append(Self.err) }
        }
        return .array(out)
    }

    func receiptOps(_ ops: [JSONValue]) -> JSONValue {
        var log: [JSONValue] = []
        var out: [JSONValue] = []
        func checks(_ v: JSONValue) -> JSONValue? { v.isObject ? v.get("checks") : nil }
        for op in ops {
            guard let o = op.asArray, let name = o.first?.asString else { out.append(Self.err); continue }
            do {
                var v: JSONValue = .null
                switch name {
                case "append":
                    log = try PCAReceipts.appendReceipt(log, pcactn: o[1], allow: o[2].get("allow") == .bool(true), checks: checks(o[2]), at: IV.num(o[3]))
                    v = log[log.count - 1]
                case "head": v = .string(PCAReceipts.receiptHead(log))
                case "verify":
                    if log.contains(.null) { throw JSError("Cannot read properties of null") } // the reference reads a member of every entry
                    v = PCAReceipts.verifyReceiptChain(log)
                    // The reference's strict canonical hash THROWS on a receipt body with an absent member (undefined); the native's verifier returns a typed refusal for the same
                    // log (a hash mismatch at that entry). Both refuse: pinned as equivalent, the native's refusal asserted.
                    if v.get("ok") == .bool(false), v.get("reason")?.asString?.hasPrefix("hash mismatch") == true, let at = v.get("brokenAt")?.safeInt, log.indices.contains(Int(at)),
                       ["at", "actionDigest", "verb", "resource", "outcome"].contains(where: { log[Int(at)].get($0) == nil }) {
                        throw JSError("canonicalBytes: undefined member")
                    }
                case "set": log = try list(o[1])
                case "tamper":
                    guard let i = o[1].safeInt, log.indices.contains(Int(i)), var r = log[Int(i)].asObject else { throw JSError("tamper") }
                    if o[3].asString == "$del" { r.removeValue(forKey: JKey(o[2].asString ?? "")) } else { r[JKey(o[2].asString ?? "")] = o[3] }
                    log[Int(i)] = .object(r)
                case "swap":
                    guard let i = o[1].safeInt, let j = o[2].safeInt, log.indices.contains(Int(i)), log.indices.contains(Int(j)) else { throw JSError("swap") }
                    log.swapAt(Int(i), Int(j))
                case "drop":
                    guard let i = o[1].safeInt, log.indices.contains(Int(i)) else { throw JSError("drop") }
                    log.remove(at: Int(i))
                case "truncate":
                    guard let i = o[1].safeInt, i >= 0, Int(i) <= log.count else { throw JSError("truncate") }
                    log = Array(log[..<Int(i)])
                default: throw JSError("op")
                }
                out.append(v)
            } catch { out.append(Self.err) }
        }
        return .array(out)
    }

    func testSweepAgainstTheReference() throws {
        let d = Base.Diffs()
        let fns: Set<String> = ["hopsRoot", "compactChain", "hopLeaf", "compactChainShapeError", "chainMemo", "receiptFor", "receiptChain", "subBudget",
                                "debitConsolidated", "debitConsolidatedPath", "rechargeFull", "approveClass", "classApprovalCovers", "coveredByAny",
                                "recordDecision", "pendingRequests", "applyCosign", "semanticSignal", "progressSignal", "objectiveSignal", "tightenRiskInputs"]
        let n = try Base.each(Self.file, fns) { c in
            let got: BaseGot = Base.run {
                switch c.fn {
                case "hopsRoot": return .string(try PCAChainCompact.hopsRoot(try list(c.arg(0))))
                case "compactChain": return try PCAChainCompact.compactChain(try list(c.arg(0)))
                case "hopLeaf": return PCAChainCompact.hopLeaf(c.arg(0) ?? .null)
                case "compactChainShapeError": return Base.opt(PCAChainCompact.compactChainShapeError(c.arg(0)))
                case "chainMemo": return memoOps(try list(c.arg(0)))
                case "receiptFor":
                    guard let seq = c.arg(1)?.safeInt, let prev = c.arg(0)?.asString else { throw JSError("args") }
                    return try PCAReceipts.receiptFor(prevHash: prev, seq: seq, pcactn: c.arg(2) ?? .null, allow: c.arg(3)?.get("allow") == .bool(true),
                                                      checks: c.arg(3)?.get("checks"), at: IV.num(c.arg(4)))
                case "receiptChain": return receiptOps(try list(c.arg(0)))
                case "subBudget": return PCARiskBudgets.subBudget(c.arg(0) ?? .null, alloc: num(c.arg(1)))
                case "debitConsolidated": return PCARiskBudgets.debitConsolidated(c.arg(0) ?? .null, c.arg(1) ?? .null, num(c.arg(2)))
                case "debitConsolidatedPath": return PCARiskBudgets.debitConsolidatedPath(try list(c.arg(0)), num(c.arg(1)))
                case "rechargeFull": return PCARiskBudgets.rechargeFull(bMax: num(c.arg(0)), now: num(c.arg(1)))
                case "approveClass":
                    return PCAApprovals.approveClass(try list(c.arg(0)).map { $0.asString ?? "" }, ttlMs: num(c.arg(1)), by: c.arg(2)?.asString ?? "", now: c.arg(3)?.safeInt,
                                                     resource: c.arg(4)?.asString)
                case "classApprovalCovers":
                    return .bool(PCAApprovals.classApprovalCovers(c.arg(0) ?? .null, verb: c.arg(1)?.asString ?? "", resource: c.arg(2)?.asString ?? "", now: num(c.arg(3))))
                case "coveredByAny":
                    return .bool(PCAApprovals.coveredByAny(try list(c.arg(0)), verb: c.arg(1)?.asString ?? "", resource: c.arg(2)?.asString ?? "", now: num(c.arg(3))))
                case "recordDecision":
                    return PCAApprovals.recordDecision(c.arg(0) ?? .null, decision: c.arg(1)?.asString ?? "", by: c.arg(2)?.asString ?? "", at: IV.num(c.arg(3)))
                case "pendingRequests": return .array(PCAApprovals.pendingRequests(try list(c.arg(0))))
                case "applyCosign": return PCAApprovals.applyCosign(c.arg(0) ?? .null, policy: c.arg(1) ?? .null, now: num(c.arg(2)), full: c.arg(3) == .bool(true))
                case "semanticSignal", "progressSignal", "objectiveSignal", "tightenRiskInputs":
                    guard let r = try RefFrontierSignalsTests.run(c) else { throw JSError("unhandled \(c.fn)") }
                    return r
                default: throw JSError("unhandled \(c.fn)")
                }
            }
            d.add(c, Base.diff(c, got))
        }
        // the other 473 cases of the file (reputation, coverage quotes, pool, policy recommendation) are replayed by RefReputationTests: 2167 in all
        XCTAssertEqual(n, 1694)
        d.finish(1500)
    }
}
