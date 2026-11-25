import XCTest
import Foundation
@testable import AtlasPCAVerify
@testable import AtlasPCAMpc

/// Differential replay of the pure parts of the MPC networked runner against the reference (@atlasauth/pca-mpc): the frame codec and envelope checks, the
/// structured abort, pairwise-authenticated shares, the forensic audit / blame / commitment and the canonical codecs. Big integers travel as decimal
/// strings; bytes as {"$bytes": b64url}.
final class RefMpcNetTests: XCTestCase {
    typealias M = PCAMpc
    typealias T = RefMpcTests
    typealias Bad = RefMpcTests.Bad
    static let file = "ref-mpc-net.json.gz"

    static func bytes(_ v: JSONValue?) throws -> [UInt8] { guard let b = Base.bytes(v) else { throw Bad() }; return b }
    static func str(_ s: String) -> JSONValue { .string(s) }
    static func int(_ x: Int) -> JSONValue { .int(Int64(x)) }
    static func nullable(_ x: Int?) -> JSONValue { x.map { .int(Int64($0)) } ?? .null }

    // ---- pairwise-authenticated shares
    static func pa(_ v: JSONValue?) throws -> M.NetPa.PA {
        guard let o = v, o.asObject != nil else { throw Bad() }
        return M.NetPa.PA(x: try T.B(o.get("x")), tag: try T.BAs(o.get("tag")), key: try T.BAs(o.get("key")))
    }
    static func paJ(_ p: M.NetPa.PA) -> JSONValue { .object(["x": T.S(p.x), "tag": T.SL(p.tag), "key": T.SL(p.key)]) }
    static func aw(_ v: JSONValue?) throws -> M.NetPa.AW {
        guard let o = v, o.asObject != nil, let ms = o.get("m")?.asArray else { throw Bad() }
        return M.NetPa.AW(v: try pa(o.get("v")), m: try ms.map { try pa($0) })
    }
    static func awJ(_ a: M.NetPa.AW) -> JSONValue { .object(["v": paJ(a.v), "m": .array(a.m.map(paJ))]) }

    // ---- forensics
    static func sideIn(_ v: JSONValue?) throws -> [M.NetForensics.PeerRow] {
        guard let a = v?.asArray else { throw Bad() }
        return try a.map { e in
            guard let p = e.asArray, p.count == 2 else { throw Bad() }
            return M.NetForensics.PeerRow(peer: try T.I(p[0]), vals: try T.BAs(p[1]))
        }
    }
    static func sideJ(_ rows: [M.NetForensics.PeerRow]) -> JSONValue { .array(rows.map { .array([int($0.peer), T.SL($0.vals)]) }) }
    static func dis(_ v: JSONValue?) throws -> [M.NetForensics.SlotDisclosure] {
        guard let a = v?.asArray else { throw Bad() }
        return try a.map { s in
            M.NetForensics.SlotDisclosure(bits: try T.IA(s.get("bits")), y: try T.B(s.get("y")), z: try T.B(s.get("z")), recv: try sideIn(s.get("recv")), rho: try sideIn(s.get("rho")))
        }
    }

    func testNetPureParts() throws {
        try K042.requireCovers(["Mpc"])
        let d = Base.Diffs()
        try Base.each(Self.file) { c in
            let a0 = c.arg(0), a1 = c.arg(1), a2 = c.arg(2), a3 = c.arg(3)
            let got: BaseGot = Ref.v {
                switch c.fn {
                // ---- wire
                case "encodeFrame":
                    guard a0?.asObject != nil, let ty = a0?.get("ty")?.asString, let sid = a0?.get("sid")?.asString, let rd = a0?.get("rd")?.asString else { throw Bad() }
                    return Base.bytesValue(try M.NetWire.encodeFrame(M.NetWire.Frame(v: a0?.get("v") ?? .null, ty: ty, sid: sid, seq: a0?.get("seq") ?? .null, rd: rd, d: a0?.get("d") ?? .null)))
                case "split":
                    let s = M.NetWire.FrameSplitter()
                    var out: [[UInt8]] = []
                    for ch in try T.A(a0) { out += try s.push(try Self.bytes(ch)) }
                    return .object(["frames": .array(out.map(Base.bytesValue))])
                case "peekVersion": return Self.nullable(M.NetWire.peekVersion(try Self.bytes(a0)).map { Int($0) })
                case "parseFrame": return M.NetWire.parseFrame(try Self.bytes(a0)) ?? .null
                case "versionMismatch": return Self.nullable(M.NetWire.versionMismatch(try Self.bytes(a0)).map { Int($0) })
                case "hx":
                    guard let s = a0?.asString, let p = M.Dec.parse(s, maxLimbs: 8) else { throw Bad() }
                    return Self.str(M.NetWire.hxBig(p.neg, p.mag))
                case "unhx": return M.NetWire.unhx(a0).map { T.S($0) } ?? .null
                case "unhxArray": return M.NetWire.unhxArray(a0, try T.I(a1)).map { T.SL($0) } ?? .null
                case "netAbort":
                    guard let kind = a0?.asString, let detail = a3?.asString else { throw Bad() }
                    let op = c.arg(6)
                    let cb = c.arg(5)
                    let blamed: Int? = a1 == .null ? nil : try T.I(a1)
                    let claimedBlame: Int? = (cb?.isNumber ?? false) ? try T.I(cb) : nil
                    let deadline: Int? = JS.present(op?.get("deadlineMs")) == nil ? nil : try T.I(op?.get("deadlineMs"))
                    let e = M.NetWire.NetAbort(kind: kind, blamed: blamed, reporter: try T.I(a2), detail: detail, claimedKind: c.arg(4)?.asString,
                                               claimedBlame: claimedBlame, reason: op?.get("reason")?.asString, evidence: JS.present(op?.get("evidence")), deadlineMs: deadline)
                    return .object(["message": Self.str(e.message), "name": Self.str("NetAbort"), "kind": Self.str(e.kind), "blamed": Self.nullable(e.blamed), "reporter": Self.int(e.reporter),
                                    "reason": e.reason.map { Self.str($0) } ?? .null, "claimedKind": e.claimedKind.map { Self.str($0) } ?? .null, "claimedBlame": Self.nullable(e.claimedBlame),
                                    "evidence": e.evidence ?? .null, "deadlineMs": Self.nullable(e.deadlineMs)])
                case "abortKinds": return .array(M.NetWire.ABORT_KINDS.sorted().map { Self.str($0) })
                // ---- pairwise-authenticated shares
                case "pa":
                    let p = try Self.pa(a1)
                    let n = p.tag.count
                    switch a0?.asString {
                    case "add": return Self.paJ(try M.NetPa.paAdd(p, try Self.pa(a2)))
                    case "sub": return Self.paJ(try M.NetPa.paSub(p, try Self.pa(a2)))
                    case "neg": return Self.paJ(M.NetPa.paNeg(p))
                    case "scale": return Self.paJ(M.NetPa.paScale(p, try T.B(a2)))
                    case "addPublic0":
                        let env = M.NetPa.PaEnv(id: try T.I(a2), n: n, delta: try T.B(a3), tagged: c.arg(4) == .bool(true))
                        return Self.paJ(try M.NetPa.paAddPublic0(env, p, try T.B(c.arg(5))))
                    case "verify":
                        let env = M.NetPa.PaEnv(id: try T.I(a2), n: n, delta: try T.B(a3), tagged: true)
                        return .bool(try M.NetPa.paVerify(env, p, try T.I(c.arg(4)), try T.B(c.arg(5)), try T.B(c.arg(6))))
                    case "flat":
                        let id = try T.I(a2), tg = a3 == .bool(true)
                        let f = try M.NetPa.paFlat(p, id, n, tg)
                        return .object(["f": T.SL(f), "w": Self.int(M.NetPa.paWidth(n, tg)), "back": Self.paJ(try M.NetPa.paParse(f, 0, id, n, tg))])
                    default: throw Bad()
                    }
                case "aw":
                    if c.args.count == 1 { return Self.int(M.NetCodec.sharingsPerTriple(try T.I(a0))) }
                    if c.args.count == 3 {
                        let x = try Self.aw(a0)
                        let n = x.v.tag.count, keys = x.m.count, id = try T.I(a1), tg = a2 == .bool(true)
                        let f = try M.NetPa.awFlat(x, id, n, tg)
                        return .object(["f": T.SL(f), "w": Self.int(M.NetPa.awWidth(n, keys, tg)), "back": Self.awJ(try M.NetPa.awParse(f, 0, id, n, keys, tg))])
                    }
                    let x = try Self.aw(a0), y = try Self.aw(a1)
                    let n = x.v.tag.count
                    guard let al = a2?.asArray else { throw Bad() }
                    let alpha = try al.map { try Self.pa($0) }
                    let tg = a3 == .bool(true)
                    let cst = try T.B(c.arg(4))
                    return .object(["add": Self.awJ(try M.NetPa.wAdd(x, y)), "sub": Self.awJ(try M.NetPa.wSub(x, y)), "neg": Self.awJ(M.NetPa.wNeg(x)), "scale": Self.awJ(M.NetPa.wScale(x, cst)),
                                    "addPublic": Self.awJ(try M.NetPa.wAddPublic(M.NetPa.PaEnv(id: 1, n: n, delta: 7, tagged: tg), x, cst, alpha)),
                                    "addPublic0": Self.awJ(try M.NetPa.wAddPublic(M.NetPa.PaEnv(id: 0, n: n, delta: 7, tagged: tg), x, cst, alpha))])
                // ---- forensics
                case "forensics":
                    switch c.args.count {
                    case 1: return Self.int(M.NetForensics.slotsFor(try T.I(a0)))
                    case 3:
                        if let o = a0?.asObject {
                            var all: [Int: [M.NetForensics.SlotDisclosure]] = [:]
                            for (k, v) in o { guard let id = Int(k.s) else { throw Bad() }; all[id] = try Self.dis(v) }
                            if let r = a2, r != .null { let rid = try T.I(r); all[rid] = nil }
                            let res = try M.NetForensics.auditDisclosures(all, try T.BAs(a1))
                            return .object(["selfBad": .array(res.selfBad.sorted().map { Self.int($0) }), "pairBad": .array(res.pairBad.map { .array($0.map { Self.int($0) }) }),
                                            "blame": .array((0..<3).map { Self.nullable(M.NetForensics.blameFrom($0, res)) })])
                        }
                        guard let sb = a1?.asArray, let pb = a2?.asArray else { throw Bad() }
                        let res = M.NetForensics.AuditResult(selfBad: Set(try sb.map { try T.I($0) }),
                                                            pairBad: try pb.map { e in guard let p = e.asArray, p.count >= 2 else { throw Bad() }; return [try T.I(p[0]), try T.I(p[1])] })
                        return Self.nullable(M.NetForensics.blameFrom(try T.I(a0), res))
                    case 4:
                        guard let ps = a3?.asArray else { throw Bad() }
                        let dd = try M.NetForensics.parseDisclosure(a0, try T.I(a1), try T.I(a2), try ps.map { try T.I($0) })
                        let ddj: [JSONValue] = dd.map { s in
                            .object(["bits": .array(s.bits.map { Self.int($0) }), "y": T.S(s.y), "z": T.S(s.z), "recv": Self.sideJ(s.recv), "rho": Self.sideJ(s.rho)])
                        }
                        return .object(["dd": .array(ddj), "back": M.NetForensics.wireDisclosure(dd)])
                    case 6:
                        guard let sid = a0?.asString, let nonce = c.arg(4)?.asString, let wire = c.arg(5), let dl = IV.num(a3), dl == dl.rounded(), abs(dl) < 9e15 else { throw Bad() }
                        return Self.str(M.NetForensics.disclosureCommit(sid, try T.I(a1), try T.I(a2), Int64(dl), nonce, wire))
                    default: throw Bad()
                    }
                // ---- codecs
                case "codec":
                    switch a0?.asString {
                    case "unb64":
                        let want: Int = (a2 == nil || a2 == .null) ? -1 : try T.I(a2)
                        return Base.bytesValue(try M.NetCodec.unb64(a1, want))
                    case "b64": return Self.str(M.NetCodec.b64(try Self.bytes(a1)))
                    case "hexBig": return Self.str(try M.NetCodec.hexBig(a1).decimal)
                    case "jPt", "ptJ":
                        let p: M.Ec.Point
                        if a0?.asString == "jPt" { p = try M.NetCodec.jPt(a1) } else { p = try M.Ec.mulBase(try RefMpcOtTests.SC(a1)) }
                        let j = M.NetCodec.ptJ(p)
                        return .object(["x": Self.str(j.x), "y": Self.str(j.y)])
                    case "gadgetCommit":
                        guard let sid = a1?.asString else { throw Bad() }
                        return Self.str(M.NetCodec.gadgetCommit(sid, try T.I(a2), try Self.bytes(a3)))
                    case "gadgetStatement":
                        guard let sid = a1?.asString, let rd = a2?.asString, let v = c.arg(4)?.asString else { throw Bad() }
                        return Base.bytesValue(M.NetCodec.gadgetStatement(sid, rd, try T.I(a3), v))
                    default: throw Bad()
                    }
                default: throw Bad()
                }
            }
            d.add(c, Base.diff(c, got))
        }
        d.finish(300)
    }
}
