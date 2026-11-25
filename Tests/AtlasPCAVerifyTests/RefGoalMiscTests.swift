import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the goal reference semantics (refDecide / refExplain), the policy card text, the round-trip checks and
/// widening mutations, the drift monitor, the conformal risk control numerics and the legacy lift against the reference
/// (@atlasauth/pca-goal). A reference throw requires a native refusal.
final class RefGoalMiscTests: XCTestCase {
    private func obj(_ v: JSONValue?) throws -> JSONValue {
        guard let v = v, v.isObject else { throw JSError("object expected") }
        return v
    }

    private func text(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("string expected") }
        return s
    }

    private func explainer(_ mode: String) -> ([String]) throws -> String {
        return { lines in
            if mode == "throw" { throw JSError("boom") }
            return PCAGoalRoundTrip.deterministicExplain(lines)
        }
    }

    private func comparator(_ mode: String) -> (String, String) throws -> JSONValue {
        return { _, e in
            if mode == "throw" { throw JSError("boom") }
            if mode == "ok" { return .object(["equivalent": .bool(true)]) }
            if mode == "no" { return .object(["equivalent": .bool(false)]) }
            let sub = String(mode.dropFirst(9))
            return .object(["equivalent": .bool(sub.isEmpty || e.range(of: sub, options: .literal) != nil)])
        }
    }

    private func key(_ v: JSONValue?) throws -> [UInt8] {
        let s = try text(v)
        if s.isEmpty { return [] }
        guard let b = Base64URLStrict.decode(s) else { throw JSError("bad key") }
        return b
    }

    func flow(_ a: [JSONValue]) throws -> JSONValue {
        let goal = try obj(a[0])
        let opts = a[1].isObject ? a[1] : nil
        var mon = PCAGoalDrift.Monitor(goal, opts)
        var last: JSONValue? = nil
        var lastOrder: [String] = []
        var out: [JSONValue] = []
        for so in a[2].asArray ?? [] {
            let s = try obj(so)
            switch try text(s.get("op")) {
            case "observe": out.append(try mon.observe(try obj(s.get("act")), s.get("t")))
            case "state": out.append(mon.state())
            case "seal":
                let sealed = mon.seal(try key(s.get("key")))
                last = sealed
                lastOrder = mon.seenOrder
                out.append(sealed)
            case "restoreLast":
                guard var sealed = last?.asObject else { throw JSError("nothing sealed") }
                let mode = try text(s.get("mode"))
                if mode == "state" {
                    var st = try obj(sealed[JKey("state")]).asObject ?? [:]
                    st[JKey("strikes")] = .int(0)
                    sealed[JKey("state")] = .object(st)
                }
                if mode == "mac" {
                    let mac = try text(sealed[JKey("mac")])
                    sealed[JKey("mac")] = .string((mac.hasPrefix("0") ? "1" : "0") + String(mac.dropFirst()))
                }
                if mode == "badmac" { sealed[JKey("mac")] = .string("zz") }
                mon = try PCAGoalDrift.Monitor.restore(goal, .object(sealed), try key(s.get("key")), opts, lastOrder)
                out.append(mon.state())
            default:
                out.append(try PCAGoalDrift.guardedDecide(goal, try obj(s.get("ont")), mon, try obj(s.get("case")), s.get("t")))
            }
        }
        return .array(out)
    }

    func testGoalMiscAgainstTheReference() throws {
        let d = Base.Diffs()
        let files: [(String, Set<String>)] = [
            ("ref-goal.json.gz", ["refDecide", "refExplain", "renderCard", "renderCond"]),
            ("ref-goal-roundtrip.json.gz", ["cardRoundTrips", "mutateGoal", "roundTrip", "measureDetection"]),
            ("ref-goal-drift.json.gz", ["flow", "applyDrift", "alphaOf", "calibrate", "assertMonotone", "cpUpper95", "renderReportMarkdown"]),
            ("ref-goal-legacy.json.gz", ["liftLegacy"]),
        ]
        for (file, fns) in files {
            try Base.each(file, fns) { c in
                let a: [JSONValue] = (0..<8).map { c.arg($0) ?? .null }
                let got: BaseGot = Base.run {
                    switch c.fn {
                    case "refDecide": return .int(Int64(try PCAGoalRefsem.refDecide(try self.obj(a[0]), try self.obj(a[1]), try self.obj(a[2]), try self.obj(a[3]))))
                    case "refExplain": return try PCAGoalRefsem.refExplain(try self.obj(a[0]), try self.obj(a[1]), try self.obj(a[2]), try self.obj(a[3]))
                    case "renderCard": return try PCAGoalCard.renderCard(try self.obj(a[0]))
                    case "renderCond": return .string(try PCAGoalCard.cond(try self.obj(a[0])))
                    case "cardRoundTrips": return .bool(try PCAGoalRoundTrip.cardRoundTrips(try self.obj(a[0])))
                    case "mutateGoal": return try PCAGoalRoundTrip.mutateGoal(try self.obj(a[0]), try self.text(a[1]), a.count > 2 && a[2].isObject ? a[2] : nil) ?? .null
                    case "roundTrip":
                        return .string(PCAGoalRoundTrip.roundTrip(try self.obj(a[0]), try self.text(a[1]), self.explainer(try self.text(a[2])), self.comparator(try self.text(a[3]))))
                    case "measureDetection":
                        return try PCAGoalRoundTrip.measureDetection(a[0], a[1].isObject ? a[1] : nil, self.explainer(try self.text(a[2])), self.comparator(try self.text(a[3])))
                    case "flow": return try self.flow(a)
                    case "applyDrift": return .string(PCAGoalDrift.applyDrift(try self.text(a[0]), try self.obj(a[1])))
                    case "alphaOf":
                        guard let x = Double(JS.toString(a[0])) else { throw JSError("not a number") }
                        return PCAGoalCrc.alphaOf(x)
                    case "calibrate":
                        let gate = try self.text(a[2])
                        if gate == "none" { return try PCAGoalCrc.calibrate(a[0], try self.obj(a[1])) }
                        guard let capN = Double(gate.dropFirst(2)) else { throw JSError("bad gate") }
                        let cap = capN / 1e5
                        return try PCAGoalCrc.calibrate(a[0], try self.obj(a[1]), { k, n in try PCAGoalCrc.cpUpper95(k, n) <= cap })
                    case "assertMonotone":
                        try PCAGoalCrc.assertMonotone(a[0])
                        return .null
                    case "cpUpper95":
                        guard let k = Int64(JS.toString(a[0])), let n = Int64(JS.toString(a[1])) else { throw JSError("not an integer") }
                        return PCAFacade.jsNum(try PCAGoalCrc.cpUpper95(k, n))
                    case "renderReportMarkdown":
                        let o = try self.obj(a[1])
                        return .string(try PCAGoalCrc.renderReportMarkdown(a[0], try self.text(o.get("source")), try self.text(o.get("modelSet"))))
                    case "liftLegacy":
                        guard a[0].isObject else { throw JSError("permissions must be an object") }
                        let limits: JSONValue? = a[1].isObject ? a[1] : nil
                        return try PCAGoalLegacy.liftLegacy(a[0], limits, nil, try self.text(a[2]), a[3].safeInt, a[4].safeInt, a[5].asString)
                    default: throw JSError("not mapped")
                    }
                }
                d.add(c, Base.diff(c, got))
            }
        }
        d.finish(500)
    }
}
