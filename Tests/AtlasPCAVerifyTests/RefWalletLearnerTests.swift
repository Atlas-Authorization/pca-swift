import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the wallet's view over an intent learner (learnerView) and priorAdmittedPpm with a released population prior
/// against the reference (@atlasauth/pca-wallet over @atlasauth/pca-intent), from two corpora. A reference throw requires a native
/// refusal. Doubles are compared bit for bit first, then within 1e-12 relative (platform libm vs the reference's fdlibm).
final class RefWalletLearnerTests: XCTestCase {
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
                return false // every value here is compared exactly (the deterministic math of the reference); no tolerance
            }
            return Base.canon(a) == Base.canon(b)
        }
    }

    static func ints(_ v: JSONValue?) throws -> [Int] {
        guard let a = v?.asArray else { throw JSError("not an array") }
        return try a.map { guard let i = IV.int($0) else { throw JSError("not an integer") }; return Int(i) }
    }

    static func idx(_ xs: [Int]) -> JSONValue { .array(xs.map { .int(Int64($0)) }) }

    static func observations(_ v: JSONValue?) throws -> [L.Observation] {
        try (v?.asArray ?? []).map { x in
            guard let verb = x.get("verb")?.asString, let y = IV.int(x.get("y")) else { throw JSError("bad observation") }
            return L.Observation(verb: verb, values: x.get("values") ?? .null, cell: [], y: Int(y), source: x.get("source")?.asString ?? "elicitation", region: nil)
        }
    }

    static func confirmed(_ view: PCAWalletLearnerView) -> JSONValue {
        .array(view.confirmed().map { .object(["verb": .string($0.verb), "idx": idx($0.idx)]) })
    }

    static func release(_ omega: JSONValue?, _ schema: String, _ qOf: Int, _ hi: Bool) throws -> JSONValue {
        let w = try WalletOmega(omega)
        var cells = JObject()
        for vs in w.verbs {
            for c in 0..<WalletOmegaMath.verbCellCount(vs) {
                let raw = hi ? 0.98 - 0.04 * Double(c % qOf) : 0.05 + 0.04 * Double(c % qOf)
                let q = min(0.98, max(0.02, raw))
                cells[JKey(try PCAWalletPopulation.populationCellKey(schema, vs, WalletOmegaMath.decodeCell(vs, c)))] = .object(["q": .double(q), "n": .int(50)])
            }
        }
        return .object(["v": .int(1), "kind": .string("pca-intent-population-prior"), "schema": .string(schema), "period": .int(1),
                        "epsilon": .double(0.9), "delta": .double(1e-5), "sigma": .int(1), "sensitivity": .int(8), "cells": .object(cells)])
    }

    func run(_ file: String, _ body: (BaseCase) throws -> JSONValue, min: Int) throws {
        let d = Base.Diffs()
        try Base.each(file) { c in
            let got = Base.run { try body(c) }
            if case let .value(v) = got, !c.threw {
                if close(c.out, v) { d.add(c, nil) }
                else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
            } else { d.add(c, Base.diff(c, got)) }
        }
        print("\(file): \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(min)
    }

    func testLearnerViewAndPriorFromTheFirstCorpus() throws {
        try K042.requireCovers(["WalletLearner", "IntentLearner", "IntentMapKit", "WalletPopulation"])
        try run("ref-wallet-learner-py.json.gz", { c in
            let a = c.args
            func learner(_ omega: JSONValue?, _ mo: JSONValue?, _ obs: JSONValue?) throws -> L {
                let l = try PCAIntentMap.createLearner(omega: omega, options: mo)
                for x in try Self.observations(obs) { try l.observe(.object(["verb": .string(x.verb), "values": x.values]), y: x.y, source: x.source) }
                return l
            }
            switch c.fn {
            case "viewScenario":
                let l = try learner(a[0], a[1], a[2])
                let ceiling = a[3].asString ?? "none"
                var inside: ((String, [Int]) -> Bool)?
                switch ceiling {
                case "all": inside = { (_: String, _: [Int]) -> Bool in true }
                case "idx0": inside = { (_: String, i: [Int]) -> Bool in i.first == 0 }
                case "never": inside = { (_: String, _: [Int]) -> Bool in false }
                default: inside = nil
                }
                let view = PCAWalletLearnerView(l, insideCeiling: inside)
                let probes: [JSONValue] = try (a[4].asArray ?? []).map { p in
                    guard let verb = p.get("verb")?.asString else { throw JSError("probe verb") }
                    let i = try Self.ints(p.get("idx"))
                    return .array([.double(try view.p(verb, i)), .bool(try view.vetoed(verb, i)), .bool(view.outsideCeiling(verb, i))])
                }
                return .object(["probes": .array(probes), "confirmed": Self.confirmed(view)])
            case "viewUnknownVerb":
                let view = PCAWalletLearnerView(try learner(a[0], .object([:]), .array([])))
                guard let verb = a[1].asString else { throw JSError("verb") }
                return .double(try view.p(verb, try Self.ints(a[2])))
            case "priorScenario":
                guard let beta = IV.num(a[3]), let schema = a[4].asString, let qOf = IV.int(a[5]) else { throw JSError("bad scenario") }
                let hi = a.count > 6 && a[6] == .bool(true)
                let base = try L.Options(json: a[1])
                let prior = try PCAWalletPopulation.populationPrior(try Self.release(a[0], schema, Int(qOf), hi), beta)
                return .int(Int64(try PCAWalletLearner.priorAdmittedPpm(omega: a[0], base: base, observations: try Self.observations(a[2]), mix: prior)))
            default: throw JSError("not mapped")
            }
        }, min: 100)
    }

    func testLearnerViewAndPriorFromTheSecondCorpus() throws {
        try K042.requireCovers(["WalletLearner", "IntentLearner", "WalletPopulation"])
        try run("ref-wallet-learner-java.json.gz", { c in
            let a = c.args
            switch c.fn {
            case "view":
                let l = try L(omega: a[0])
                for x in try Self.observations(a[1]) { try l.observe(.object(["verb": .string(x.verb), "values": x.values]), y: x.y) }
                let ceiling = IV.num(a[2])
                var inside: ((String, [Int]) -> Bool)?
                if let k = ceiling { inside = { (_: String, i: [Int]) -> Bool in Double(i.first ?? 0) <= k } }
                let view = PCAWalletLearnerView(l, insideCeiling: inside)
                var cells: [JSONValue] = []
                for vs in l.omega.verbs {
                    for f in 0..<WalletOmegaMath.verbCellCount(vs) {
                        let i = WalletOmegaMath.decodeCell(vs, f)
                        cells.append(.array([.string(vs.verb), Self.idx(i), .double(try view.p(vs.verb, i)), .bool(try view.vetoed(vs.verb, i)),
                                             .bool(view.outsideCeiling(vs.verb, i))]))
                    }
                }
                return .object(["cells": .array(cells), "confirmed": Self.confirmed(view)])
            case "probe":
                guard let verb = a[1].asString else { throw JSError("verb") }
                return .double(try PCAWalletLearnerView(try L(omega: a[0])).p(verb, [0, 0]))
            case "ppm":
                guard let beta = IV.num(a[4]) else { throw JSError("beta") }
                let prior = try PCAWalletPopulation.populationPrior(a[3], beta)
                return .int(Int64(try PCAWalletLearner.priorAdmittedPpm(omega: a[0], base: try L.Options(json: a[1]), observations: try Self.observations(a[2]), mix: prior)))
            default: throw JSError("not mapped")
            }
        }, min: 100)
    }
}
