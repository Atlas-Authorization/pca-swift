import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the k-compiler pipeline (prompts, strict slot parsing, panel runs, structural disagreement, the
/// natural-language facade compiler), the frame and side-effect checks, and cut refinement with partial answers and adaptive
/// elicitation against the reference (@atlasauth/pca-intent). A reference throw requires a native refusal. Doubles are compared bit for
/// bit first and within 1e-12 relative otherwise (the reference's fdlibm and the platform libm may round log2 / exp / pow differently);
/// the count of the latter is printed.
final class RefIntentCompilersTests: XCTestCase {
    typealias L = PCAIntentLearner
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

    func replay(_ file: String, _ label: String, _ min: Int, _ body: (BaseCase) throws -> JSONValue) throws {
        inexact = 0
        let d = Base.Diffs()
        try Base.each(file) { c in
            let got: BaseGot = Base.run { try body(c) }
            if case let .value(v) = got, !c.threw {
                if close(c.out, v) { d.add(c, nil) }
                else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
            } else { d.add(c, Base.diff(c, got)) }
        }
        print("\(label): \(d.run) cases compared, \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(min)
    }

    // ---- compilers ----

    static func compiler(_ so: JSONValue?) throws -> PCAIntentCompiler {
        guard let s = so, let id = s.get("id")?.asString, let kind = s.get("kind")?.asString else { throw JSError("bad compiler spec") }
        let family = s.get("family")?.asString ?? ""
        switch kind {
        case "captured": return PCAIntentCompilers.capturedSlotsCompiler(id)
        case "fixed": return PCAIntentCompilers.fixedCompiler(id, family) { _ in s.get("policy") }
        case "throws": return PCAIntentCompilers.fixedCompiler(id, family) { _ in throw JSError("boom") }
        case "slots":
            let raw = s.get("raw")?.asString
            return PCAIntentCompilers.slotsCompiler(id, family) { _ in
                guard let r = raw else { throw JSError("no raw output") }
                return r
            }
        default: return PCAIntentCompilers.slotsCompiler(id, family) { _ in throw JSError("llm down") }
        }
    }

    static func compilers(_ specs: JSONValue?) throws -> [PCAIntentCompiler] {
        guard let a = specs?.asArray else { throw JSError("compilers must be an array") }
        return try a.map { try compiler($0) }
    }

    static func text(_ v: JSONValue?) throws -> String {
        guard let s = v?.asString else { throw JSError("not a string") }
        return s
    }

    func testCompilersAgainstTheReference() throws {
        try replay("ref-intent-compilers.json.gz", "intent compilers", 200) { c in
            let a = c.args
            switch c.fn {
            case "slotsPrompt": return .string(PCAIntentCompilers.slotsPrompt(try Self.text(a[0]), nil))
            case "parseSlotsJSON": return PCAIntentCompilers.parseSlotsJSON(try Self.text(a[0]), nil)
            case "runScenario": return .array(PCAIntentCompilers.runCompilers(a[0], try Self.compilers(a[1])))
            case "analyze": return try PCAIntentCompilers.analyzeDisagreement(try IntentTree.arr(a[0]), a[1])
            case "flags": return .bool(try PCAIntentCompilers.panelFlags(try PCAIntentCompilers.analyzeDisagreement(try IntentTree.arr(a[0]), a[1])))
            case "anchors": return .array(try PCAIntentCompilers.committeeAnchors(try IntentTree.arr(a[0]), try IntentTree.dbl(a[1])))
            case "compareScenario": return try PCAIntentCompilers.compileAndCompare(a[0], try Self.compilers(a[1]), a[2])
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    // ---- natural-language facade compiler ----

    static func catalog(_ extras: JSONValue?) throws -> PCACatalog {
        guard let e = extras, !e.isNull else { return PCACatalog.default }
        var specs: [PCACatalogAction] = PCACatalog.builtin
        for eo in try IntentTree.arr(e) {
            let m = try IntentTree.obj(eo)
            let connector = try IntentTree.str(m["connector"])
            let action = try IntentTree.str(m["action"])
            var aliases: [String] = []
            if let al = IntentTree.present(m["aliases"]) { aliases = try IntentTree.arr(al).map { try IntentTree.str($0) } }
            specs.append(PCACatalogAction(connector: connector, action: action, verb: connector + "." + action, reversibility: try IntentTree.str(m["reversibility"]),
                                          blastRadius: try IntentTree.dbl(m["blastRadius"]), amountField: m["amountField"]?.asString,
                                          description: try IntentTree.str(m["description"]), aliases: aliases))
        }
        return PCACatalog(specs)
    }

    static func nlCompiler(_ raw: String, _ prompt: PromptBox) -> PCAIntentCompiler {
        PCAIntentCompilers.nlFacadeCompiler("nl", "fam") { p in
            prompt.text = p
            if raw == "THROWS" { throw JSError("llm down") }
            return raw
        }
    }

    final class PromptBox { var text = "" }

    func testNaturalLanguageCompilerAgainstTheReference() throws {
        try replay("ref-intent-nl-java.json.gz", "intent nl compiler", 240) { c in
            let a = c.args
            switch c.fn {
            case "nlPrompt": return .string(PCAIntentCompilers.nlPrompt(try Self.text(a[0]), try Self.catalog(a.count > 1 ? a[1] : nil)))
            case "parseNLPolicy": return PCAIntentCompilers.parseNLPolicy(try Self.text(a[0]), try Self.catalog(a.count > 1 ? a[1] : nil))
            case "nlCompile":
                let cat = try Self.catalog(a.count > 2 ? a[2] : nil)
                let box = PromptBox()
                let out = try Self.nlCompiler(try Self.text(a[1]), box).compile(.object(["text": a[0]]), cat)
                return .object(["prompt": .string(box.text), "output": out])
            case "nlRun":
                let cat = try Self.catalog(a.count > 2 ? a[2] : nil)
                return .array(PCAIntentCompilers.runCompilers(.object(["text": a[0]]), [Self.nlCompiler(try Self.text(a[1]), PromptBox())], cat))
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    // ---- frames ----

    static func outcomeOf(_ x: JSONValue?) -> JSONValue { .object(["verb": x?.get("verb") ?? .null, "values": x?.get("values") ?? .null]) }

    static func build(_ omega: JSONValue?, _ mapOpts: JSONValue?, _ obs: JSONValue?, regions: Bool) throws -> L {
        let l = try PCAIntentMap.createLearner(omega: omega, options: mapOpts)
        for x in try IntentTree.arr(obs) {
            guard let y = IV.int(x.get("y")), let source = x.get("source")?.asString else { throw JSError("bad observation") }
            let region: JSONValue? = regions ? IntentTree.present(x.get("region")) : nil
            try l.observe(outcomeOf(x), y: Int(y), source: source, region: region)
        }
        return l
    }

    func testFramesAgainstTheReference() throws {
        try replay("ref-intent-frames.json.gz", "intent frames", 80) { c in
            let a = c.args
            switch c.fn {
            case "stateDigest": return .string(PCAIntentFrames.stateDigest(a.first))
            case "snapshotState": return try PCAIntentFrames.snapshotState(a[0], a.count < 2 || a[1] != .bool(false))
            case "checkFrame": return PCAIntentFrames.checkFrame(a[0], a[1], a[2], a[3], a[4])
            case "applyScenario":
                let l = try Self.build(a[0], a[1], a[2], regions: false)
                let metrics = l.metrics().json
                return .object(["result": try PCAIntentFrames.applyFrameReport(l, Self.outcomeOf(a[3]), a[4]), "metrics": metrics])
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }

    // ---- refinement ----

    static func cellsJson(_ l: L) -> JSONValue {
        .array(l.cells().map { .object(["verb": .string($0.verb), "cell": .array($0.cell.map { .int(Int64($0)) }), "p": .double($0.p)]) })
    }

    static func ints(_ v: JSONValue?) throws -> [Int] {
        try IntentTree.arr(v).map { Int(try IntentTree.dbl($0)) }
    }

    func testRefinementAgainstTheReference() throws {
        try replay("ref-intent-refine.json.gz", "intent refine", 170) { c in
            let a = c.args
            switch c.fn {
            case "refineOmega": return try PCAIntentRefine.refineOmega(a[0], try PCAIntentRefine.Refinement.fromJson(a[1]))
            case "regionsOf":
                let l = try Self.build(a[0], a[1], a[2], regions: true)
                var om: WalletOmega = l.omega
                if a[3] == .bool(true) { om = try WalletOmega(.object(["verbs": .array([])])) }
                return .array(try l.observations.map { try PCAIntentRefine.regionOfObservation(om, $0) })
            case "refineScenario":
                let l = try Self.build(a[0], a[1], a[2], regions: true)
                let nl = try PCAIntentRefine.refineLearner(l, try PCAIntentRefine.Refinement.fromJson(a[3]), nil)
                return .object(["omega": PCAIntentRefine.omegaJson(nl), "observations": .array(nl.observations.map { $0.json }),
                                "metrics": nl.metrics().json, "cells": Self.cellsJson(nl)])
            case "partialScenario":
                let l = try Self.build(a[0], a[1], a[2], regions: true)
                guard let verb = a[3].get("verb")?.asString else { throw JSError("question has no verb") }
                let cell = try Self.ints(a[3].get("cell"))
                var oc: JSONValue = .object(["verb": .string(verb), "values": .object([:])])
                if let vs = l.omega.verbs.last(where: { IV.same($0.verb, verb) }) {
                    guard cell.count == vs.dims.count, zip(cell, vs.dims).allSatisfy({ $0 >= 0 && $0 < WalletOmegaMath.cellCount($1) }) else { throw JSError("cell out of range") }
                    oc = WalletOmegaMath.cellRep(vs, cell)
                }
                let q = L.Question(verb: verb, cell: cell, outcome: oc, p: l.acceptance(oc), score: 0.0)
                let r = try PCAIntentRefine.answerPartial(l, q, try PCAIntentRefine.PartialAnswer.fromJson(a[4]))
                return .object(["omega": PCAIntentRefine.omegaJson(r.learner), "added": .array(r.added.map { $0.json }),
                                "observations": .array(r.learner.observations.map { $0.json }), "metrics": r.learner.metrics().json,
                                "synth": r.learner.synthesize()])
            case "adaptiveScenario":
                let l0 = try PCAIntentMap.createLearner(omega: a[0], options: a[1])
                let adm = try PCAIntentPolicy.admitter(a[2])
                let ps = try IntentTree.arr(a[3]).map { try PCAIntentRefine.PartialAnswer.fromJson($0) }
                guard let ev = IV.int(a[4]), ev != 0 else { throw JSError("bad answer cadence") }
                let oo = a[5]
                var asks = 0
                var used = 0
                let answer: (L.Question, L) throws -> PCAIntentRefine.Answer = { q, l in
                    asks += 1
                    if Int64(asks) % ev == 0 && used < ps.count && IV.same(q.verb, "stripe.refund") {
                        used += 1
                        return .partial(ps[used - 1])
                    }
                    guard let vs = l.omega.verbs.last(where: { IV.same($0.verb, q.verb) }) else { throw JSError("no such verb") }
                    return .label(adm.admits(vs, q.outcome) ? 1 : 0)
                }
                var eo = L.ElicitOptions(epsRisk: 0.001, epsBurden: 0.01, maxQuestions: IV.num(oo.get("maxQuestions")) ?? 25)
                eo.audit = oo.get("audit") == .bool(true)
                for s in oo.get("seed")?.asArray ?? [] {
                    guard let verb = s.get("verb")?.asString else { throw JSError("seed verb") }
                    eo.seed.append((verb, try Self.ints(s.get("cell"))))
                }
                var maxRef: Int?
                if let m = IntentTree.present(oo.get("maxRefinements")) { maxRef = Int(try IntentTree.dbl(m)) }
                let r = try PCAIntentRefine.elicitAdaptive(l0, answer, eo, maxRef)
                return .object(["stop": .string(r.stop), "questions": .int(Int64(r.questions)), "auditQuestions": .int(Int64(r.auditQuestions)),
                                "seedQuestions": .int(Int64(r.seedQuestions)), "refinements": .int(Int64(r.refinements)),
                                "asked": .array(r.asked.map { $0.json }), "omega": PCAIntentRefine.omegaJson(r.learner),
                                "metrics": r.learner.metrics().json, "observations": .array(r.learner.observations.map { $0.json })])
            default: throw JSError("not mapped: \(c.fn)")
            }
        }
    }
}
