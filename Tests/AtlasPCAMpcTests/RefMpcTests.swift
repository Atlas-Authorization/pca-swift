import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCAMpc

/// Differential replay of the deterministic layer of the MPC package against the reference (@atlasauth/pca-mpc): field arithmetic, the seeded SplitMix64
/// field generator, additive sharing, Beaver multiplication, GF(2^128), the thermometer encoding and the cleartext composition. Big integers travel as
/// decimal strings; every draw comes from the seeded generator, so shares and transcripts compare byte for byte. The malicious runner replays in
/// trusted-dealer mode (the no-dealer oblivious-transfer offline phase is replayed by RefMpcOtTests).
final class RefMpcTests: XCTestCase {
    typealias M = PCAMpc
    static let file = "ref-mpc.json.gz"

    struct Bad: Error {}

    /// A bigint argument (a decimal string) reduced into the field.
    static func B(_ v: JSONValue?) throws -> UInt64 { guard let s = v?.asString, let x = M.Field.parse(s) else { throw Bad() }; return x }
    static func BA(_ v: JSONValue?) throws -> [UInt64?] {
        guard let a = v?.asArray else { throw Bad() }
        return try a.map { $0 == .null ? nil : try B($0) }
    }
    static func BAs(_ v: JSONValue?) throws -> [UInt64] {
        try BA(v).map { guard let x = $0 else { throw Bad() }; return x }
    }
    /// A JavaScript integer argument; beyond 1e9 it saturates like the other lanes (every consumer refuses it anyway).
    static func I(_ v: JSONValue?) throws -> Int {
        guard let d = IV.num(v), d.isFinite, d == d.rounded() else { throw Bad() }
        if abs(d) > 1e9 { return d > 0 ? Int(Int32.max) : Int(Int32.min) }
        return Int(d)
    }
    static func rng(_ v: JSONValue?) throws -> M.Field.Rng {
        guard let s = v?.asString, let x = M.Field.low64(s) else { throw Bad() }
        return M.Field.Rng(seed: x)
    }
    static func S(_ x: UInt64) -> JSONValue { .string(String(x)) }
    static func SL(_ xs: [UInt64]) -> JSONValue { .array(xs.map(S)) }
    static func G(_ v: JSONValue?) throws -> M.Gf128 { guard let s = v?.asString, let x = M.Gf128(decimal: s) else { throw Bad() }; return x }

    static func vectors(_ v: JSONValue?) throws -> [M.DecisionVector?] {
        guard let a = v?.asArray else { throw Bad() }
        return try a.map { e in
            guard e.asObject != nil else { return nil }
            return M.DecisionVector(allow: try I(e.get("allow")), t: try I(e.get("t")), rQuant: try I(e.get("rQuant")))
        }
    }

    static func openedJSON(_ o: [M.Beaver.Opened]) -> JSONValue {
        .array(o.map { .object(["label": .string($0.label), "value": S($0.value), "shares": SL($0.shares)]) })
    }


    typealias SP = PCAMpc.Spdz

    static func A(_ v: JSONValue?) throws -> [JSONValue] { guard let a = v?.asArray else { throw Bad() }; return a }
    static func IA(_ v: JSONValue?) throws -> [Int] { guard let a = v?.asArray else { throw Bad() }; return try a.map { try I($0) } }
    static func bitsJSON(_ b: [Int]) -> JSONValue { .array(b.map { .int(Int64($0)) }) }
    static func encJSON(_ e: M.Enc.EncShare) -> JSONValue { .object(["value": S(e.value), "bits": bitsJSON(e.bits)]) }
    static func svJSON(_ x: SP.AuthSV) -> JSONValue { .object(["value": SL(x.value), "mac": SL(x.mac), "extraMac": .array(x.extraMac.map(SL))]) }
    static func tripleJSON(_ t: SP.AuthTriple) -> JSONValue { .object(["a": svJSON(t.a), "b": svJSON(t.b), "c": svJSON(t.c)]) }
    static func ctxJSON(_ c: SP.MacContext) -> JSONValue {
        .object(["n": .int(Int64(c.n)), "alphaShares": SL(c.alphaShares), "alpha": S(c.alpha),
                 "extraKeys": .array(c.extraKeys.map { .object(["alphaShares": SL($0.alphaShares), "alpha": S($0.alpha)]) })])
    }
    static func decisionJSON(_ d: M.DecisionVector) -> JSONValue { .object(["allow": .int(Int64(d.allow)), "t": .int(Int64(d.t)), "rQuant": .int(Int64(d.rQuant))]) }
    static func partneredJSON(_ t: SP.TripleWithPartners) -> JSONValue { .object(["keep": tripleJSON(t.keep), "partners": .array(t.partners.map(tripleJSON))]) }

    static func devs(_ v: JSONValue?) throws -> [SP.Deviation] {
        guard let a = v?.asArray else { throw Bad() }
        return try a.map { e in
            guard let d = e.asArray, d.count >= 5 else { throw Bad() }
            return SP.Deviation(openIndex: try I(d[0]), party: try I(d[1]), valueDelta: d[2] == .null ? nil : try B(d[2]), macDelta: d[3] == .null ? nil : try B(d[3]), macKey: d[4] == .null ? nil : try I(d[4]))
        }
    }

    static func fault(_ v: JSONValue?) throws -> SP.DealerFault? {
        guard let v = v, v != .null else { return nil }
        guard v.asObject != nil else { throw Bad() }
        var f = SP.DealerFault()
        if let k = v.get("keepCDelta"), k != .null { f.keepCDelta = try B(k) }
        if let p = v.get("partnerCDelta"), p != .null {
            guard let a = p.asArray else { throw Bad() }
            f.partnerCDelta = try a.map { $0 == .null ? nil : try B($0) }
        }
        return f
    }

    /// Reduces a decimal integer modulo an arbitrary p (below 2^63), for the MAC-residual arithmetic core.
    static func modP(_ v: JSONValue?, _ p: UInt64) throws -> UInt64 {
        guard let s = v?.asString else { throw Bad() }
        var u = Array(s.utf8)
        var negative = false
        if let f = u.first, f == UInt8(ascii: "-") || f == UInt8(ascii: "+") { negative = f == UInt8(ascii: "-"); u.removeFirst() }
        guard !u.isEmpty else { throw Bad() }
        var r: UInt64 = 0
        for c in u {
            guard c >= 48 && c <= 57 else { throw Bad() }
            let w = r.multipliedFullWidth(by: 10)
            let (lo, carry) = w.low.addingReportingOverflow(UInt64(c - 48))
            r = p.dividingFullWidth((w.high &+ (carry ? 1 : 0), lo)).remainder
        }
        return negative ? (r == 0 ? 0 : p - r) : r
    }

    static let supported: Set<String> = ["mod", "fneg", "fadd", "fsub", "fmul", "fieldRng", "fieldRngDefault", "share", "reconstruct", "shareConstant", "sv", "gf", "genTriple", "beaverMul",
                                         "thermometerEncode", "thermometerDecode", "quantizeR", "composeClear", "assertDecisionVectors",
                                         "encBits", "makeGadget", "plainShare", "plainGadget", "randomBits", "sampleEnc", "encValue", "composeSecure", "setupMac", "macSoundnessBits",
                                         "authShare", "authConstant", "authOp", "genAuthTriple", "genTripleWithPartners", "engineRun", "macResiduals", "sacrifice", "beaverAuth",
                                         "composeSecureMalicious"]

    func testDeterministicLayer() throws {
        try K042.requireCovers(["Mpc"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            guard Self.supported.contains(c.fn) else { d.skip("\(c.fn): not carried"); return }
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2)
            let got: BaseGot = Ref.v {
                switch c.fn {
                case "mod":
                    guard let s = a0?.asString, let r = M.mod(s) else { throw Bad() }
                    return Self.S(r)
                case "fneg": return Self.S(M.fneg(try Self.B(a0)))
                case "fadd": return Self.S(M.fadd(try Self.B(a0), try Self.B(a1)))
                case "fsub": return Self.S(M.fsub(try Self.B(a0), try Self.B(a1)))
                case "fmul": return Self.S(M.fmul(try Self.B(a0), try Self.B(a1)))
                case "fieldRng":
                    var g = try Self.rng(a0)
                    return Self.SL((0..<max(0, try Self.I(a1))).map { _ in g.next() })
                case "fieldRngDefault":
                    var g = M.Field.Rng()
                    return Self.SL((0..<max(0, try Self.I(a0))).map { _ in g.next() })
                case "share":
                    var g = try Self.rng(a2)
                    return Self.SL(try M.Sharing.share(try Self.B(a0), try Self.I(a1), &g))
                case "reconstruct": return Self.S(try M.Sharing.reconstruct(try Self.BA(a0)))
                case "shareConstant": return Self.SL(try M.Sharing.shareConstant(try Self.B(a0), try Self.I(a1)))
                case "sv":
                    let x = try Self.BAs(a1)
                    switch a0?.asString {
                    case "add": return Self.SL(try M.Sharing.add(x, try Self.BAs(a2)))
                    case "sub": return Self.SL(try M.subSV(x, try Self.BAs(a2)))
                    case "neg": return Self.SL(M.negSV(x))
                    case "scale": return Self.SL(M.scaleSV(x, try Self.B(a2)))
                    case "addPublic": return Self.SL(M.addPublicSV(x, try Self.B(a2)))
                    case "notBit": return Self.SL(M.notBitSV(x))
                    default: throw Bad()
                    }
                case "gf":
                    let x = try Self.G(a1)
                    switch a0?.asString {
                    case "add": return .string(M.Gf128.add(x, try Self.G(a2)).decimal)
                    case "mul": return .string(M.Gf128.mul(x, try Self.G(a2)).decimal)
                    case "mulX": return .string(M.gf128MulX(x).decimal)
                    case "mulByXi": return .string(M.gf128MulByXi(x, try Self.I(a2)).decimal)
                    default: throw Bad()
                    }
                case "genTriple":
                    var g = try Self.rng(a1)
                    let t = try M.Beaver.genTriple(try Self.I(a0), &g)
                    return .object(["a": Self.SL(t.a), "b": Self.SL(t.b), "c": Self.SL(t.c)])
                case "beaverMul":
                    let r = try M.Beaver.mul(try Self.BAs(a0), try Self.BAs(a1), M.Beaver.Triple(a: try Self.BAs(a2), b: try Self.BAs(c.arg(3)), c: try Self.BAs(c.arg(4))))
                    return .object(["z": Self.SL(r.z), "opened": Self.openedJSON(r.opened)])
                case "thermometerEncode":
                    guard let v = IV.num(a0) else { throw Bad() }
                    return .array(try M.Thermometer.encode(v, try Self.I(a1)).map { .int(Int64($0)) })
                case "thermometerDecode":
                    guard let a = a0?.asArray else { throw Bad() }
                    return .int(Int64(M.Thermometer.decode(a.map { IV.num($0) == 1 ? 1 : 0 })))
                case "quantizeR":
                    guard let r = IV.num(a0) else { throw Bad() }
                    return .int(Int64(M.quantizeR(r, try Self.I(a1))))
                case "composeClear":
                    let r = try M.composeClear(try Self.vectors(a0), try Self.I(a1))
                    return .object(["allow": .int(Int64(r.allow)), "t": .int(Int64(r.t)), "rQuant": .int(Int64(r.rQuant))])
                case "assertDecisionVectors":
                    try M.assertDecisionVectors(try Self.vectors(a0), try Self.I(a1))
                    return .bool(true)
                case "encBits": return .int(Int64(M.Enc.encBits(try Self.I(a0))))
                case "makeGadget":
                    var g = try Self.rng(a1)
                    return Self.SL(try M.Enc.makeGadget(try Self.I(a0), &g, unsafe: a2 == .bool(true)))
                case "plainShare": return Self.encJSON(M.Enc.plainShare(try Self.B(a0)))
                case "plainGadget": return Self.SL(M.Enc.plainGadget())
                case "randomBits":
                    var g = try Self.rng(a1)
                    return Self.bitsJSON(M.Enc.randomBits(try Self.I(a0), &g))
                case "sampleEnc":
                    var g = try Self.rng(a1)
                    let gad = try M.Enc.makeGadget(try Self.I(a0), &g, unsafe: true)
                    return .object(["gadget": Self.SL(gad), "e": Self.encJSON(try M.Enc.sampleEnc(gad, &g))])
                case "encValue": return Self.S(try M.Enc.encValue(try Self.BAs(a0), try Self.IA(a1)))
                case "composeSecure":
                    guard let seed = a2?.asString.flatMap({ M.Field.low64($0) }) else { throw Bad() }
                    let r = try M.composeSecure(try Self.vectors(a0), Q: try Self.I(a1), seed: seed)
                    return .object(["composed": Self.decisionJSON(r.composed), "parties": .int(Int64(r.parties)), "Q": .int(Int64(r.Q)), "multiplications": .int(Int64(r.multiplications)),
                                    "opened": Self.openedJSON(r.opened),
                                    "sharings": .array(r.sharings.map { .object(["label": .string($0.label), "party": .int(Int64($0.party)), "secret": Self.S($0.secret), "shares": Self.SL($0.shares)]) }),
                                    "heldShares0": Self.SL(r.heldShares0), "viewsLen": .int(Int64(r.parties))])
                case "setupMac":
                    var g = try Self.rng(a1)
                    return Self.ctxJSON(try SP.setupMac(try Self.I(a0), &g, keys: try Self.I(a2)))
                case "macSoundnessBits":
                    let p = c.args.count > 1 ? (a1?.asString.flatMap { Double($0) }) : nil
                    if c.args.count > 1 && p == nil { throw Bad() }
                    return .double(SP.macSoundnessBits(try Self.I(a0), p ?? Double(M.Field.prime)))
                case "authShare":
                    var g = try Self.rng(a1)
                    let ctx = try SP.setupMac(try Self.I(a0), &g)
                    return .object(["ctx": Self.ctxJSON(ctx), "sv": Self.svJSON(try SP.authShare(try Self.B(a2), ctx, &g))])
                case "authConstant":
                    var g = try Self.rng(a1)
                    return Self.svJSON(SP.authConstant(try Self.B(a2), try SP.setupMac(try Self.I(a0), &g)))
                case "authOp":
                    var g = try Self.rng(a2)
                    let ctx = try SP.setupMac(try Self.I(a1), &g)
                    let x = try SP.authShare(try Self.B(c.arg(3)), ctx, &g), y = try SP.authShare(try Self.B(c.arg(4)), ctx, &g)
                    let k = try Self.B(c.arg(5))
                    let res: SP.AuthSV
                    switch a0?.asString {
                    case "open": return .object(["val": Self.S(M.authValue(x))])
                    case "add": res = try M.addAuth(x, y)
                    case "sub": res = try M.subAuth(x, y)
                    case "neg": res = M.negAuth(x)
                    case "scale": res = M.scaleAuth(x, k)
                    case "addPublic": res = try SP.addPublic(x, k, ctx)
                    case "notBit": res = try M.notBitAuth(x, ctx)
                    default: throw Bad()
                    }
                    let val = SP.value(res)
                    let rows = [res.mac] + res.extraMac
                    var ok = true
                    for (l, key) in ctx.macKeys.enumerated() { ok = ok && rows[l].reduce(0, M.Field.add) == M.Field.mul(key.alpha, val) }
                    return .object(["res": Self.svJSON(res), "val": Self.S(val), "okMac": .bool(ok)])
                case "genAuthTriple":
                    var g = try Self.rng(a1)
                    let ctx = try SP.setupMac(try Self.I(a0), &g)
                    return Self.tripleJSON(try SP.genAuthTriple(ctx, &g))
                case "genTripleWithPartners":
                    if c.args.count == 2 {
                        var g = try Self.rng(a1)
                        let ctx = try SP.setupMac(try Self.I(a0), &g)
                        return Self.partneredJSON(try SP.genTripleWithPartners(ctx, &g))
                    }
                    var g = try Self.rng(a0)
                    let ctx = try SP.setupMac(2, &g)
                    return Self.partneredJSON(try SP.genTripleWithPartners(ctx, &g, partners: try Self.I(a1), fault: try Self.fault(a2)))
                case "sacrifice":
                    var g = try Self.rng(a1)
                    let ctx = try SP.setupMac(try Self.I(a0), &g)
                    let f = try Self.fault(c.arg(4))
                    var batch: [SP.TripleWithPartners] = []
                    for i in 0..<max(0, try Self.I(a2)) { batch.append(try SP.genTripleWithPartners(ctx, &g, partners: try Self.I(c.arg(3)), fault: i == 0 ? f : nil)) }
                    return .object(["certified": .array(try SP.sacrificeVerify(batch, ctx, &g, deviations: try Self.devs(c.arg(5))).map(Self.tripleJSON))])
                case "engineRun":
                    var g = try Self.rng(a1)
                    let ctx = try SP.setupMac(try Self.I(a0), &g, keys: c.args.count > 4 ? try Self.I(c.arg(4)) : SP.MAC_KEYS)
                    let e = try SP.Engine(ctx, deviations: try Self.devs(c.arg(3)))
                    guard let values = a2?.asArray else { throw Bad() }
                    var outs: [UInt64] = []
                    for (i, v) in values.enumerated() { outs.append(try e.open(try SP.authShare(try Self.B(v), ctx, &g), "v\(i)")) }
                    try e.macCheck(&g)
                    return .object(["outs": Self.SL(outs), "count": .int(Int64(e.openCount))])
                case "macResiduals":
                    guard let ps = a0?.asString, let p = UInt64(ps) else { throw Bad() }
                    guard let alphas = a1?.asArray, let ops = a2?.asArray, let chs = c.arg(3)?.asArray else { throw Bad() }
                    let alphaShares = try alphas.map { try Self.A($0).map { try Self.modP($0, p) } }
                    let opened = try ops.map { o -> SP.OpenedValue in
                        guard let rows = o.get("macShares")?.asArray else { throw Bad() }
                        return SP.OpenedValue(value: try Self.modP(o.get("value"), p), macShares: try rows.map { try Self.A($0).map { try Self.modP($0, p) } }, label: "")
                    }
                    let challenges = try chs.map { try Self.A($0).map { try Self.modP($0, p) } }
                    return .array(try SP.macResiduals(p, alphaShares, opened, challenges).map(Self.SL))
                case "beaverAuth":
                    var g = try Self.rng(a1)
                    let ctx = try SP.setupMac(try Self.I(a0), &g)
                    let e = try SP.Engine(ctx, deviations: try Self.devs(c.arg(4)))
                    let x = try SP.authShare(try Self.B(a2), ctx, &g), y = try SP.authShare(try Self.B(c.arg(3)), ctx, &g)
                    let t = try SP.genAuthTriple(ctx, &g)
                    let z = try M.beaverMulAuth(x, y, t, ctx, e, "m")
                    let val = M.authValue(z)
                    let out = try e.open(z, "out")
                    try e.macCheck(&g)
                    return .object(["z": Self.svJSON(z), "val": Self.S(val), "out": Self.S(out), "opens": .int(Int64(e.openCount))])
                case "composeSecureMalicious":
                    guard let o = a1, o.asObject != nil else { throw Bad() }
                    var cfg = M.MaliciousConfig()
                    if let q = o.get("Q"), q != .null { cfg.Q = try Self.I(q) }
                    if let sd = o.get("seed"), sd != .null { guard let x = sd.asString.flatMap({ M.Field.low64($0) }) else { throw Bad() }; cfg.seed = x }
                    if let dv = o.get("deviations"), dv != .null { cfg.deviations = try Self.devs(dv) }
                    cfg.insecureTrustedDealer = o.get("insecureTrustedDealer") == .bool(true)
                    if let dl = o.get("dealer"), dl != .null {
                        guard dl.asObject != nil else { throw Bad() }
                        var d = M.DealerOptions()
                        if let v = dl.get("verifyTriples"), v != .null { guard case let .bool(b) = v else { throw Bad() }; d.verifyTriples = b }
                        if let pr = dl.get("partners"), pr != .null { d.partners = try Self.I(pr) }
                        d.fault = try Self.fault(dl.get("fault"))
                        cfg.dealer = d
                    }
                    let r = try M.composeSecureMalicious(try Self.vectors(a0), cfg)
                    return .object(["composed": Self.decisionJSON(r.composed), "parties": .int(Int64(r.parties)), "Q": .int(Int64(r.Q)), "opens": .int(Int64(r.opens)),
                                    "multiplications": .int(Int64(r.multiplications)), "offlineMode": .string(r.offlineMode), "triplesVerified": .bool(r.triplesVerified), "macChecked": .bool(r.macChecked)])
                default: throw Bad()
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(1500)
    }

    func testFieldAnchors() {
        XCTAssertEqual(M.Field.mul(M.Field.prime - 1, M.Field.prime - 1), 1) // (-1)^2
        XCTAssertEqual(M.Field.parse("-1"), M.Field.prime - 1)
        XCTAssertEqual(M.Field.parse("2305843009213693952"), 1) // p + 1
        XCTAssertEqual(M.Gf128(decimal: "340282366920938463463374607431768211455")?.decimal, "340282366920938463463374607431768211455") // 2^128 - 1
        XCTAssertEqual(M.Gf128(decimal: "-1")?.decimal, "340282366920938463463374607431768211455")
    }
}
