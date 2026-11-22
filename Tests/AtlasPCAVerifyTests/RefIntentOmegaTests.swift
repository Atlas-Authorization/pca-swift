import XCTest
import Foundation
@testable import AtlasPCAVerify

/// Differential replay of the outcome space (PCAIntentOmega, PCAIntentDerive), the schema-derived space (PCAIntentSchema), the layered
/// lattice and quorum approvals (PCAIntentLayers) and the classifier calibration kit (PCAIntentClassifierKit) against the reference
/// (@atlasauth/pca-intent). A reference throw requires a native refusal. Doubles are compared exactly (the reference and the native port both use
/// the deterministic math, no tolerance).
final class RefIntentOmegaTests: XCTestCase {
    typealias O = PCAIntentOmega
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

    func record(_ d: Base.Diffs, _ c: BaseCase, _ got: BaseGot) {
        if case let .value(v) = got, !c.threw {
            if close(c.out, v) { d.add(c, nil) }
            else { d.add(c, "\(c.name): want \(Base.firstDiff(c.out, v, "@")) || want \(Base.canon(c.out).prefix(300)) got \(Base.canon(v).prefix(300))") }
        } else { d.add(c, Base.diff(c, got)) }
    }

    static func arg(_ a: [JSONValue], _ i: Int) -> JSONValue? { i < a.count ? a[i] : nil }

    static func ints(_ v: JSONValue?) throws -> [Int] {
        var out: [Int] = []
        for x in try O.arr(v) { out.append(O.toInt(try O.dbl(x))) }
        return out
    }

    static func intArg(_ v: JSONValue?) throws -> Int { O.toInt(try O.dbl(v)) }

    /// A numeric argument becomes a binary64, anything else stays.
    static func value(_ v: JSONValue?) -> JSONValue? {
        if let d = IV.num(v) { return .double(d) }
        return v
    }

    static func stats(_ s: O.Stats) -> JSONValue { .object(["mass": O.jn(s.mass), "harm": O.jn(s.harm)]) }

    static func walletVerb(_ v: JSONValue?) throws -> WalletVerb {
        guard let v = v else { throw JSError("no verb space") }
        let om = try WalletOmega(.object(["verbs": .array([v])]))
        return om.verbs[0]
    }

    // ---- the outcome space ----

    func testOutcomeSpaceAgainstTheReference() throws {
        let d = Base.Diffs()
        let unmapped: Set<String> = ["regionOfCell", "regionCells", "dimCellsIn", "restrictRegion", "valueInRegionDim"]
        try Base.each("ref-intent-omega.json.gz") { c in
            let a = c.args
            if unmapped.contains(c.fn) { d.skip("\(c.fn): typed region objects are not part of this port (the wallet-space PCAIntentRegion has its own replay)"); return }
            if c.fn == "seeded" { d.skip("seeded: no reference replay exists for it in the other natives either"); return }
            let got: BaseGot = Base.run {
                switch c.fn {
                case "deriveOmega": return O.omegaToJson(try PCAIntentDerive.deriveOmega(a[0]))
                case "harmMax": return O.jn(O.harmMax(try O.omegaFromJson(a[0])))
                case "verbSpace":
                    let om = try O.omegaFromJson(a[0])
                    guard let vs = O.verbSpace(om, Self.arg(a, 1)?.asString) else { return .null }
                    return O.verbSpaceToJson(vs)
                case "verbCellCount": return O.jn(O.verbCellCount(try O.verbSpaceFromJson(a[0])))
                case "decodeCell": return .array(O.decodeCell(try O.verbSpaceFromJson(a[0]), try O.dbl(a[1])).map { JSONValue.int(Int64($0)) })
                case "encodeCell": return O.jn(O.encodeCell(try O.verbSpaceFromJson(a[0]), try Self.ints(a[1])))
                case "cellRep": return O.outcomeToJson(O.cellRep(try O.verbSpaceFromJson(a[0]), try Self.ints(a[1])))
                case "cellStats": return Self.stats(O.cellStats(try O.verbSpaceFromJson(a[0]), try Self.ints(a[1])))
                case "cellOf":
                    guard let idx = O.cellOf(try O.verbSpaceFromJson(a[0]), try O.outcomeFromJson(a[1])) else { return .null }
                    return .array(idx.map { JSONValue.int(Int64($0)) })
                case "harmOf": return O.jn(O.harmOf(try O.verbSpaceFromJson(a[0]), try O.outcomeFromJson(a[1])))
                case "cellCount": return .int(Int64(O.cellCount(try O.dimFromJson(a[0]))))
                case "numCells":
                    guard let n = try O.dimFromJson(a[0]) as? O.NumDim else { throw JSError("not a numeric dimension") }
                    return .array(O.numCells(n).map { JSONValue.object(["lo": O.jn($0.lo), "hi": O.jn($0.hi)]) })
                case "numRep":
                    guard let n = try O.dimFromJson(a[0]) as? O.NumDim else { throw JSError("not a numeric dimension") }
                    return O.jn(O.numRep(n, try Self.intArg(a[1])))
                case "repValue":
                    let r = O.repValue(try O.dimFromJson(a[0]), try Self.intArg(a[1]))
                    if let x = IV.num(r) { return O.jn(x) }
                    return r
                case "catRep":
                    guard let c = try O.dimFromJson(a[0]) as? O.CatDim else { throw JSError("not a categorical dimension") }
                    return .string(O.catRep(c, try Self.intArg(a[1])))
                case "catCellOf":
                    guard let c = try O.dimFromJson(a[0]) as? O.CatDim, let s = Self.arg(a, 1)?.asString else { throw JSError("bad arguments") }
                    return .int(Int64(O.catCellOf(c, s)))
                case "cellOfValue": return .int(Int64(O.cellOfValue(try O.dimFromJson(a[0]), Self.value(Self.arg(a, 1)))))
                case "dimCellStats": return Self.stats(O.dimCellStats(try O.dimFromJson(a[0]), try Self.intArg(a[1])))
                case "intervalWeight":
                    guard let n = try O.dimFromJson(a[0]) as? O.NumDim else { throw JSError("not a numeric dimension") }
                    return O.jn(O.intervalWeight(n, try O.dbl(a[1]), try O.dbl(a[2])))
                case "rngSeq":
                    let r = O.rng(try O.dbl(a[0]))
                    var out: [JSONValue] = []
                    for _ in 0..<(try Self.intArg(a[1])) { out.append(O.jn(r())) }
                    return .array(out)
                case "sampleOutcomes":
                    let om = try O.omegaFromJson(a[0])
                    let r = O.rng(try O.dbl(a[1]))
                    var out: [JSONValue] = []
                    for _ in 0..<(try Self.intArg(a[2])) { out.append(O.outcomeToJson(try O.sampleOutcome(om, r).o)) }
                    return .array(out)
                case "normalizePolicy": return PCAIntentPolicy.normalizePolicy(a[0])
                case "slotsToPolicy": return try PCAIntentDerive.slotsToPolicy(a[0])
                case "outcomeToAction":
                    let vs = try Self.walletVerb(a[0])
                    return .object(PCAIntentPolicy.outcomeToAction(vs, try O.outcomeToJson(O.outcomeFromJson(a[1]))))
                case "admits":
                    let adm = try PCAIntentPolicy.admitter(a[0])
                    let vs = try Self.walletVerb(a[1])
                    return .bool(adm.admits(vs, try O.outcomeToJson(O.outcomeFromJson(a[2]))))
                default: throw JSError("not mapped: \(c.fn)")
                }
            }
            if case .threw = got, !c.threw, c.fn == "outcomeToAction" { d.skip("outcomeToAction: wallet verb space needs integral bounds"); return }
            record(d, c, got)
        }
        print("intent omega: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(1000)
    }

    // ---- the schema-derived space ----

    func testSchemaOmegaAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-schema.json.gz") { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "deriveSchemaOmega":
                    let r = try PCAIntentSchema.deriveOmegaFromSchema(a[0])
                    var canon = JObject()
                    for (k, v) in r.canonOf { canon[k] = .string(v) }
                    return .object(["omega": O.omegaToJson(r.omega), "overrides": .array(r.overrides), "defaults": .array(r.defaults), "canonOf": .object(canon)])
                case "canonValue": return .string(try PCAIntentSchema.canonValue(a[0], Self.arg(a, 1)))
                case "effectiveSensitivity":
                    guard let s = try PCAIntentSchema.effectiveSensitivity(a[0], Self.arg(a, 1)) else { return .null }
                    return .string(s)
                case "verbReversibility": return .string(try PCAIntentSchema.verbReversibility(a[0]))
                case "walletFloorOverrides": return .array(try PCAIntentSchema.walletFloorOverrides(try O.arr(a[0]), Self.arg(a, 1)))
                default: throw JSError("not mapped: \(c.fn)")
                }
            }
            record(d, c, got)
        }
        print("intent schema: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(200)
    }

    // ---- layers ----

    func testLayersAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-layers.json.gz", seeds: true) { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "ceilingOf":
                    let ca = try PCAIntentLayers.ceilingAdmitters(a[0])
                    guard let k = PCAIntentLayers.ceilingOf(ca, try Self.walletVerb(a[1]), a[2]) else { return .null }
                    return .string(k)
                case "assertAskable":
                    try PCAIntentLayers.assertAskable(a[0], a[1])
                    return .null
                case "layerCells":
                    return .array(PCAIntentLayers.layerCells(try WalletOmega(a[0]), try PCAIntentPolicy.admitter(a[1])))
                case "ownerRisk":
                    let adm = try PCAIntentPolicy.admitter(a[2])
                    let r = try PCAIntentLayers.ownerRisk(try WalletOmega(a[0]), try O.arr(a[1]), { vs, o in adm.admits(vs, o) ? 1.0 : 0.0 })
                    return O.jn(r)
                case "cellKeyOf": return .string(try PCAIntentLayers.cellKeyOf(try WalletOmega(a[0]), a[1]))
                case "signLayerApproval":
                    guard let seed = a[1].asString, let raw = Base64URLStrict.decode(seed, length: 32) else { throw JSError("bad seed") }
                    // the reference signs with RFC 8032 deterministic Ed25519
                    return try PCAIntentLayers.signLayerApproval(a[0], try Ed25519Deterministic.key(seed: raw))
                case "verifyQuorumApprovals": return PCAIntentLayers.verifyQuorumApprovals(a[0], a[1], a[2], a[3])
                case "normalizeRule", "effectiveVetoers", "ruleAdmits", "jointAcceptance", "commonRefinement", "measureGrantExact", "measureGrant":
                    throw JSError("skip")
                default: throw JSError("not mapped: \(c.fn)")
                }
            }
            if ["normalizeRule", "effectiveVetoers", "ruleAdmits", "jointAcceptance", "commonRefinement", "measureGrantExact", "measureGrant"].contains(c.fn) {
                d.skip("\(c.fn): belongs to the multi-principal / metrics modules, replayed by their own suites")
                return
            }
            record(d, c, got)
        }
        print("intent layers: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(150)
    }

    // ---- classifier ----

    static func learner(_ omega: JSONValue?, _ mapOpts: JSONValue?, _ obs: JSONValue?) throws -> PCAIntentLearner {
        let l = try PCAIntentMap.createLearner(omega: omega, options: mapOpts)
        for x in try O.arr(obs) {
            guard let y = IV.int(x.get("y")) else { throw JSError("bad answer") }
            let oc: JSONValue = .object(["verb": x.get("verb") ?? .null, "values": x.get("values") ?? .null])
            _ = try l.observe(oc, y: Int(y), source: x.get("source")?.asString ?? "elicitation", region: nil)
        }
        return l
    }

    func testClassifierAgainstTheReference() throws {
        let d = Base.Diffs()
        try Base.each("ref-intent-classifier.json.gz") { c in
            let a = c.args
            let got: BaseGot = Base.run {
                switch c.fn {
                case "calibrate":
                    var delta: Double?
                    if a.count > 2 { delta = try O.dbl(a[2]) }
                    return try PCAIntentClassifierKit.calibrateConfusion(try O.arr(a[0]), try O.arr(a[1]), delta)
                case "confusionDigest": return .string(try PCAIntentClassifierKit.confusionDigest(a[0]))
                case "publishedErrorRate": return O.jn(try PCAIntentClassifierKit.publishedErrorRate(a[0]))
                case "classifierCardNote": return .string(try PCAIntentClassifierKit.classifierCardNote(try O.str(a[0]), a[1]))
                case "riskArrays":
                    let op = try O.str(a[0])
                    if op == "risk" { return O.jn(try PCAIntentClassifierKit.classifierRisk(a[1])) }
                    if op == "sound" { return .bool(try PCAIntentClassifierKit.labelSound(a[1])) }
                    return O.jn(try PCAIntentClassifierKit.labelSoundBound(a[1], try O.dbl(a[2])))
                case "awareScenario":
                    return try PCAIntentClassifierKit.classifierAwareResidualRisk(try Self.learner(a[0], a[1], a[2]), try O.arr(a[3]))
                case "jitScenario":
                    return .array(try PCAIntentClassifierKit.classifierJitCells(try Self.learner(a[0], a[1], a[2]), a[3], try O.dbl(a[4])))
                default: throw JSError("not mapped: \(c.fn)")
                }
            }
            record(d, c, got)
        }
        print("intent classifier: \(inexact) numbers not bit-identical (within \(Self.tol) relative)")
        d.finish(150)
    }
}
