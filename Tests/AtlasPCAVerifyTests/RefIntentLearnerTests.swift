import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the intent learner (PCAIntentLearner: exact posterior over the box / union / decision-list classes, the
/// observation log, probes, next question, metrics, cells, synthesis, replay, the elicitation loop with seeds and the audit round),
/// the hypothesis cell sets, the class names and the box cover against the reference (@atlasauth/pca-intent). A reference throw
/// requires a native refusal. Doubles are compared bit for bit first and within 1e-12 relative otherwise (the reference's fdlibm and
/// the platform libm may round log2 / exp / pow differently); the count of the latter is printed.
final class RefIntentLearnerTests: XCTestCase {
    typealias L = PCAIntentLearner
    static let file = "ref-intent-learner.json.gz"
    static let tol = 1e-12
    var inexact = 0

    func close(_ a: JSONValue?, _ b: JSONValue?) -> Bool {
        switch (a, b) {
        case let (.object(x)?, .object(y)?): return Set(x.keys) == Set(y.keys) && x.allSatisfy { close($0.value, y[$0.key]) }
        case let (.array(x)?, .array(y)?): return x.count == y.count && zip(x, y).allSatisfy { close($0, $1) }
        default:
            if let p = IV.num(a), let q = IV.num(b) {
                if p == q || (p.isNaN && q.isNaN) { return true }
                inexact += 1
                return abs(p - q) <= Self.tol * max(abs(p), abs(q)) + 1e-15
            }
            return Base.canon(a) == Base.canon(b)
        }
    }

    static func ints(_ v: JSONValue?) throws -> [Int] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { guard let i = IV.int($0) else { throw JSError("not an integer") }; return Int(i) }
    }

    static func options(_ opts: JSONValue?) throws -> L.Options {
        var o = try L.Options(json: opts)
        if opts?.get("nullMassFn")?.asString == "byRev" { o.nullMassFn = { $0.reversibility == "reversible" ? 0.1 : 0.3 } }
        if let pm = opts?.get("priorMix") {
            guard let beta = IV.num(pm.get("beta")) else { throw JSError("priorMix.beta") }
            let kind = pm.get("weight")?.asString
            o.priorMix = (beta, { _, has in
                switch kind {
                case "size"?: var k = 1.0; for c in 0..<64 where has(c) { k += 1 }; return k
                case "neg"?: return -1
                default: return 0
                }
            })
        }
        return o
    }

    static func scenario(_ omega: JSONValue?, _ opts: JSONValue?, _ ops: JSONValue?) throws -> JSONValue {
        let options = try Self.options(opts)
        let l = try L(omega: omega, options: options)
        var out: [JSONValue] = []
        for op in ops?.asArray ?? [] {
            switch op.get("op")?.asString {
            case "observe"?:
                guard let y = IV.int(op.get("y")) else { throw JSError("bad answer") }
                let oc: JSONValue = .object(["verb": op.get("verb") ?? .null, "values": op.get("values") ?? .null])
                let r = try l.observe(oc, y: Int(y), source: op.get("source")?.asString ?? "elicitation", region: op.get("region"))
                out.append(r?.json ?? .null)
            case "probe"?:
                let oc: JSONValue = .object(["verb": op.get("verb") ?? .null, "values": op.get("values") ?? .null])
                out.append(.array([.double(l.acceptance(oc)), .bool(l.admitsOutcome(oc)), .bool(l.isVetoed(oc))]))
            case "next"?: out.append(l.nextQuestion()?.json ?? .null)
            case "metrics"?: out.append(l.metrics().json)
            case "cells"?: out.append(.array(l.cells().map { $0.json }))
            case "unconfirmed"?:
                out.append(.array(l.unconfirmedGrantCells().map {
                    .object(["verb": .string($0.verb), "cell": .array($0.cell.map { .int(Int64($0)) }), "weight": .double($0.weight)])
                }))
            case "synth"?: out.append(l.synthesize())
            case "vetoed"?: out.append(.array(l.vetoedCells().map { .string($0) }))
            case "observations"?: out.append(.array(l.observations.map { $0.json }))
            case "replay"?: out.append(try L.replay(omega: omega, options: options, observations: l.observations).metrics().json)
            case "elicit"?:
                let adm = try PCAIntentAdmitter(op.get("policy"))
                var k = 0
                let flip = IV.num(op.get("flipEvery")) ?? 0
                let answer: (L.Question) -> Int = { q in
                    let vs = l.omega.verbs.first { IV.same($0.verb, q.verb) }
                    let y = vs.map { adm.admits($0, q.outcome) ? 1 : 0 } ?? 0
                    k += 1
                    return flip != 0 && Double(k).truncatingRemainder(dividingBy: flip) == 0 ? 1 - y : y
                }
                guard let er = IV.num(op.get("epsRisk")), let eb = IV.num(op.get("epsBurden")), let mq = IV.num(op.get("maxQuestions")) else { throw JSError("elicit options") }
                var eo = L.ElicitOptions(epsRisk: er, epsBurden: eb, maxQuestions: mq)
                eo.audit = op.get("audit") == .bool(true)
                for s in op.get("seed")?.asArray ?? [] {
                    guard let verb = s.get("verb")?.asString else { throw JSError("seed verb") }
                    eo.seed.append((verb, try Self.ints(s.get("cell"))))
                }
                let r = try l.elicit(answer, eo)
                out.append(.object(["stop": .string(r.stop), "questions": .int(Int64(r.questions)), "auditQuestions": .int(Int64(r.auditQuestions)),
                                    "seedQuestions": .int(Int64(r.seedQuestions)), "asked": .array(r.asked.map { $0.json }), "metrics": l.metrics().json]))
            default: throw JSError("bad op")
            }
        }
        return .array(out)
    }

    func testIntentLearnerAgainstTheReference() throws {
        try K042.requireCovers(["IntentLearner", "WalletOmega", "Predicates"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "scenario": return try Self.scenario(a[0], a[1], a[2])
                case "hypothesisClassName":
                    return .string(L.hypothesisClassName(try L.Options(json: .object(["hypothesisClass": a.first ?? .null])).hypothesisClass))
                case "hypothesisCellSets":
                    var hc = L.HypothesisClass.box
                    if a.count > 1 && !a[1].isNull { hc = try L.Options(json: .object(["hypothesisClass": a[1]])).hypothesisClass }
                    let caps = a.count > 2 ? a[2] : nil
                    let r = try L.hypothesisCellSets(a[0], hc, maxHypotheses: IV.num(caps?.get("maxHypotheses")), maxEnumeration: IV.num(caps?.get("maxEnumeration")))
                    if caps != nil || a.count < 2 || a[1].isNull { return .int(Int64(r.sets.count)) }
                    return .object(["sets": .array(r.sets.map { .array($0.map { .int(Int64($0)) }) }), "complexity": .array(r.complexity.map { .int(Int64($0)) })])
                case "boxesToPredicates":
                    guard let vs = try? L.verbSpace(a[0]) else { throw JSError("bad verb space") }
                    let allowed = try Self.ints(a[1]).map { UInt8($0) }
                    return .array(L.boxesToPredicates(vs, allowed))
                default: throw JSError("not mapped")
                }
            }
            if case let .value(v) = got, !c.threw {
                if close(c.out, v) { d.add(c, nil) }
                else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
            } else { d.add(c, Base.diff(c, got)) }
        }
        print("intent learner: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(300)
    }
}
