import Foundation
import AtlasPCAVerify
import AtlasPCAMpc

private typealias Field = PCAMpc.Field
private typealias Enc = PCAMpc.Enc
private typealias NetOt = PCAMpc.NetOt

/// The NO-DEALER offline phase over the mutual-TLS mesh. Each party holds only its own shares; every party samples its own MAC key shares and triple
/// shares, and the products needed for the triples and MACs are computed by Gilboa OT multiplication between every ordered pair (kappa = 128 base OTs
/// per ordered pair, OT extension with the KOS correlation check). Two multiplication layers (products and the MACs of known values, then the MACs of
/// the products) and a third layer giving every share pairwise tags T_ij = K_ij + Delta_j * x_i, so the online phase can name a party that lies.
/// Receivers choose with the privacy-amplified encoding of their share (selective-failure remedy) under a gadget all parties contribute a signed seed
/// to. The triple sacrifice and the input-consistency check run online. No security proof; a wrong OT operand in the offline triple products is
/// attributable from the OT transcript only after the sacrifice fails (see `PrepForensics`).
public enum NetOffline {
    /// Most OT rows per extension round (bounds frame size and memory).
    static let ROWS_PER_ROUND = 128 * Enc.FIELD_BITS
    static let T_M = 3

    private struct Item { var bits: [Int]; var gad: [UInt64]; var y: UInt64 }
    private struct Kept { var recv: [Int: [Int: [UInt64]]] = [:]; var rho: [Int: [Int: [UInt64]]] = [:] }
    private struct Rows { var recv: [Int: [UInt64]]; var sendSum: [Int: [UInt64]]; var kept: Kept }
    private struct Layer { var z: [UInt64]; var kept: Kept }
    private struct Cipher { var y0: [UInt64]; var y1: [UInt64] }

    private static func le8(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8((v >> UInt64(8 * $0)) & 0xff) } }
    private static func fromLe8(_ b: [UInt8]) -> UInt64 { var v: UInt64 = 0; for i in stride(from: 7, through: 0, by: -1) { v = v << 8 | UInt64(b[i]) }; return v }

    /// The public gadget: H(all seeds in party order, session) expanded by a hash chain; every party contributed a committed seed.
    static func gadgetFromSeeds(_ sessionId: String, _ seeds: [[UInt8]]) -> [UInt64] {
        let seed = NetUtil.sha256([NetUtil.utf8("atlas-pca-mpc/enc-gadget"), NetUtil.utf8(sessionId)] + seeds)
        var ctr: UInt64 = 0
        let mask: UInt64 = (1 << 61) - 1
        func next() -> UInt64 {
            while true {
                let v = fromLe8(NetUtil.sha256([seed, le8(ctr)])) & mask
                ctr += 1
                if v != mask { return v }
            }
        }
        return (0..<Enc.encBits(Enc.STAT_SEC)).map { _ in next() }
    }

    public static func run(_ ctx: OfflineCtx) throws -> Prep { try Run(ctx).go() }

    private static func pairsB64(_ ps: [[[UInt8]]]) -> JSONValue { .array(ps.map { .array([.string(PCAMpc.NetCodec.b64($0[0])), .string(PCAMpc.NetCodec.b64($0[1]))]) }) }

    private static func parsePairs(_ raw: JSONValue?, _ count: Int, _ len: Int) throws -> [[[UInt8]]] {
        guard let arr = raw?.jArr, arr.count == count else { throw NetError("bad pair array") }
        return try arr.map { p in
            guard let pr = p.jArr, pr.count == 2 else { throw NetError("bad pair") }
            return [try PCAMpc.NetCodec.unb64(pr[0], len), try PCAMpc.NetCodec.unb64(pr[1], len)]
        }
    }

    private static func packLe8(_ vs: [UInt64]) -> [UInt8] { vs.flatMap { le8($0) } }
    private static func unpackLe8(_ b: [UInt8], _ m: Int) -> [UInt64] { (0..<m).map { fromLe8(Array(b[($0 * 8)..<($0 * 8 + 8)])) } }

    private static func encodeY(_ c: Cipher) -> JSONValue {
        .object(["y0": .string(PCAMpc.NetCodec.b64(packLe8(c.y0))), "y1": .string(PCAMpc.NetCodec.b64(packLe8(c.y1)))])
    }

    private static func decodeY(_ raw: JSONValue, _ m: Int) throws -> Cipher {
        guard raw.jObj != nil else { throw NetError("bad ciphertext message") }
        return Cipher(y0: unpackLe8(try PCAMpc.NetCodec.unb64(raw.jGet("y0"), m * 8), m), y1: unpackLe8(try PCAMpc.NetCodec.unb64(raw.jGet("y1"), m * 8), m))
    }

    private final class Run {
        let a: OfflineCtx
        let mesh: Mesh
        let id: Int, n: Int, C: Int, K: Int, P: Int
        let io: Exchanger
        var others: [Int] = []
        var frng = Field.Rng.secure()
        let behKind: String
        var delta: UInt64 = 0
        var gadget: [UInt64] = []
        var recvCh: [Int: NetOt.ExtReceiver] = [:]
        var sendCh: [Int: NetOt.ExtSender] = [:]
        let sid: [UInt8]

        init(_ a: OfflineCtx) {
            self.a = a
            mesh = a.mesh
            id = a.id
            n = a.n
            C = a.C
            K = a.keys
            P = a.partners
            io = a.io
            behKind = a.behavior?.kind ?? ""
            sid = NetOt.sessionBytes(a.mesh.sessionId)
            for i in 0..<a.n where i != a.id { others.append(i) }
        }

        /// Binding of the channel whose EXTENSION RECEIVER (= base-OT sender) is `recv` and extension sender is `send`.
        func chan(_ recv: Int, _ send: Int, _ round: String) -> NetOt.Binding { NetOt.Binding(sessionId: sid, sender: recv, receiver: send, round: round) }

        func otGuard<T>(_ peer: Int, _ what: String, _ f: () throws -> T) throws -> T {
            do { return try f() } catch let e as NetAbort { throw e } catch {
                let ne = NetAbort(kind: NetOt.isCheckFailure(error) ? "ot-check" : "malformed", blamed: peer, reporter: id, detail: "\(what): \(error)")
                mesh.fail(ne, nil)
                throw ne
            }
        }

        func arr(_ p: Int, _ raw: JSONValue?, _ len: Int) throws -> [UInt64] {
            guard let r = PCAMpc.NetWire.unhxArray(raw, len) else { throw io.bad(p, "expected \(len) canonical field elements") }
            return r
        }

        func sample() throws -> Enc.EncShare { try Enc.sampleEnc(gadget, &frng) }

        func go() throws -> Prep {
            delta = frng.next()
            while delta == 0 { delta = frng.next() }

            // ---------------------------------------------------------------- base OTs (kappa per ordered pair, both roles)
            var seeds: [Int: [[[UInt8]]]] = [:]
            var mySetup: [Int: NetOt.BaseSender] = [:]
            var selector: [Int: [Int]] = [:]
            for p in others {
                let r = try NetOt.ExtReceiver(bindingBytes: NetOt.bindingBytes(chan(id, p, "iknp-kos")))
                seeds[p] = r.makeSeeds()
                recvCh[p] = r
                mySetup[p] = try NetOt.BaseSender(chan(id, p, "offline-kappa"))
                let s = try NetOt.ExtSender(bindingBytes: NetOt.bindingBytes(chan(p, id, "iknp-kos")))
                selector[p] = s.makeSelector()
                sendCh[p] = s
            }
            let lieProof = behKind == "ot-proof-lie"
            let theirS: [Int: JSONValue] = try io.exchange("ob-S", { peer in mySetup[peer]!.message(lieProof: lieProof) }, { p, raw in
                guard raw.jObj != nil else { throw self.io.bad(p, "bad S message") }
                return raw
            })
            var respond: [Int: NetOt.BaseReceiver] = [:]
            for p in others {
                respond[p] = try otGuard(p, "base OT (receiver)") { try NetOt.BaseReceiver(sMessage: theirS[p], choices: selector[p]!, chan(p, id, "offline-kappa")) }
            }
            let kappa = NetOt.KAPPA
            let theirR: [Int: JSONValue] = try io.exchange("ob-R", { peer in respond[peer]!.message }, { p, raw in
                guard let a = raw.jArr, a.count == kappa else { throw self.io.bad(p, "bad R array") }
                return raw
            })
            var enc: [Int: (ct: [[[UInt8]]], com: [[[UInt8]]])] = [:]
            for p in others {
                enc[p] = try otGuard(p, "base OT (sender)") {
                    let pads = try mySetup[p]!.derive(theirR[p], count: kappa)
                    return try NetOt.encrypt(seeds[p]!, pads)
                }
            }
            let theirCt: [Int: (ct: [[[UInt8]]], com: [[[UInt8]]])] = try io.exchange("ob-C", { peer in
                .object(["ct": NetOffline.pairsB64(enc[peer]!.ct), "com": NetOffline.pairsB64(enc[peer]!.com)])
            }, { p, raw in
                guard raw.jObj != nil else { throw self.io.bad(p, "bad ciphertext message") }
                return (try NetOffline.parsePairs(raw.jGet("ct"), kappa, 16), try NetOffline.parsePairs(raw.jGet("com"), kappa, 32))
            })
            for p in others {
                let m = theirCt[p]!
                let got = try otGuard(p, "base OT (receiver)") { try NetOt.decrypt(selector[p]!, respond[p]!.recvPads, m.ct, m.com) }
                try sendCh[p]!.setSeeds(got)
            }

            // ---------------------------------------------------------------- the jointly contributed choice-bit gadget (signed commit / reveal / echo)
            let seedsAgreed = try NetGadget.agreeGadgetSeeds(mesh, n, io)
            gadget = NetOffline.gadgetFromSeeds(mesh.sessionId, seedsAgreed)

            // ---------------------------------------------------------------- my randomness and the input sharings
            var alphaEnc: [Enc.EncShare] = []
            for _ in 0..<K { alphaEnc.append(try sample()) }
            let alphaShare = alphaEnc.map { $0.value }
            let tb = try PCAMpc.Thermometer.encode(Double(a.input.t), NetOffline.T_M)
            let rb = try PCAMpc.Thermometer.encode(Double(a.input.rQuant), a.Q)
            let myBits = [a.input.allow] + tb + rb
            guard myBits.count == C else { throw NetAbort(kind: "local", blamed: nil, reporter: id, detail: "input chain count mismatch") }
            var outShares: [Int: [UInt64]] = [:]
            for p in others { outShares[p] = (0..<C).map { _ in frng.next() } }
            var myOwn: [UInt64] = []
            for c in 0..<C {
                var s = UInt64(myBits[c])
                for p in others { s = Field.sub(s, outShares[p]![c]) }
                myOwn.append(s)
            }
            let gotShares: [Int: [UInt64]] = try io.exchange("in-share", { peer in NetUtil.hxList(outShares[peer]!) }, { p, raw in try self.arr(p, raw, self.C) })
            var inputValue = [UInt64](repeating: 0, count: n * C) // my value share of every (owner, chain)
            for o in 0..<n { for c in 0..<C { inputValue[o * C + c] = o == id ? myOwn[c] : gotShares[o]![c] } }
            let maskShare = frng.next() // my share of the input-check mask

            let nT = (n - 1) * C
            var aE: [Enc.EncShare] = [], ahE: [[Enc.EncShare]] = []
            var bS: [UInt64] = []
            for _ in 0..<nT {
                aE.append(try sample())
                bS.append(frng.next())
                var row: [Enc.EncShare] = []
                for _ in 0..<P { row.append(try sample()) }
                ahE.append(row)
            }
            let aS = aE.map { $0.value }
            let ahS = ahE.map { $0.map { $0.value } }

            // ---------------------------------------------------------------- layer 1: products and the MACs of known values
            var xs1: [Enc.EncShare] = [], ys1: [UInt64] = []
            func push(_ xs: inout [Enc.EncShare], _ ys: inout [UInt64], _ x: Enc.EncShare, _ y: UInt64) -> Int { xs.append(x); ys.append(y); return xs.count - 1 }
            var iC = [Int](repeating: 0, count: nT)
            var iCh = [[Int]](repeating: [Int](repeating: 0, count: P), count: nT)
            var iMa = [[Int]](repeating: [], count: nT), iMb = [[Int]](repeating: [], count: nT)
            var iMah = [[[Int]]](repeating: [[Int]](repeating: [], count: P), count: nT)
            for t in 0..<nT {
                iC[t] = push(&xs1, &ys1, aE[t], bS[t])
                for r in 0..<P { iCh[t][r] = push(&xs1, &ys1, ahE[t][r], bS[t]) }
                for l in 0..<K { iMa[t].append(push(&xs1, &ys1, alphaEnc[l], aS[t])) }
                for l in 0..<K { iMb[t].append(push(&xs1, &ys1, alphaEnc[l], bS[t])) }
                for r in 0..<P { for l in 0..<K { iMah[t][r].append(push(&xs1, &ys1, alphaEnc[l], ahS[t][r])) } }
            }
            var iIn = [[Int]](repeating: [], count: n * C)
            for q in 0..<(n * C) { for l in 0..<K { iIn[q].append(push(&xs1, &ys1, alphaEnc[l], inputValue[q])) } }
            var iMask: [Int] = []
            for l in 0..<K { iMask.append(push(&xs1, &ys1, alphaEnc[l], maskShare)) }
            var keepItems = Set<Int>()
            for t in 0..<nT {
                keepItems.insert(iC[t])
                for r in 0..<P { keepItems.insert(iCh[t][r]) }
            }
            let l1 = try mulLayer("1", xs1, ys1, behKind == "offline-lie" && nT > 0 ? iC[0] : -1, keepItems)
            let z1 = l1.z

            // ---------------------------------------------------------------- layer 2: the MACs of the products
            var cS: [UInt64] = [], chS: [[UInt64]] = []
            for t in 0..<nT {
                cS.append(z1[iC[t]])
                chS.append((0..<P).map { z1[iCh[t][$0]] })
            }
            var xs2: [Enc.EncShare] = [], ys2: [UInt64] = []
            var iMc = [[Int]](repeating: [], count: nT)
            var iMch = [[[Int]]](repeating: [[Int]](repeating: [], count: P), count: nT)
            for t in 0..<nT {
                for l in 0..<K { iMc[t].append(push(&xs2, &ys2, alphaEnc[l], cS[t])) }
                for r in 0..<P { for l in 0..<K { iMch[t][r].append(push(&xs2, &ys2, alphaEnc[l], chS[t][r])) } }
            }
            let z2 = try mulLayer("2", xs2, ys2, -1, nil).z

            // ---------------------------------------------------------------- assemble, then pairwise-tag every share
            func pa(_ x: UInt64) -> PA { PA(x: x, tag: [UInt64](repeating: 0, count: n), key: [UInt64](repeating: 0, count: n)) }
            func aw(_ value: UInt64, _ macIdx: [Int], _ z: [UInt64]) -> AW { AW(v: pa(value), m: macIdx.map { pa(z[$0]) }) }
            var triples: [[AW]] = []
            for t in 0..<nT {
                var sh: [AW] = [aw(aS[t], iMa[t], z1), aw(bS[t], iMb[t], z1), aw(cS[t], iMc[t], z2)]
                for r in 0..<P {
                    sh.append(aw(ahS[t][r], iMah[t][r], z1))
                    sh.append(aw(chS[t][r], iMch[t][r], z2))
                }
                triples.append(sh)
            }
            var inputs: [AW] = []
            for q in 0..<(n * C) { inputs.append(aw(inputValue[q], iIn[q], z1)) }
            var checkMask = aw(maskShare, iMask, z1)
            var alpha = alphaShare.map { pa($0) }
            var plain: [UInt64] = alpha.map { $0.x }
            func collect(_ w: AW) { plain.append(w.v.x); for m in w.m { plain.append(m.x) } }
            for row in triples { for w in row { collect(w) } }
            for w in inputs { collect(w) }
            collect(checkMask)
            let tk = try tagLayer("3", plain)
            var u = 0
            func tagged(_ x: PA) -> PA {
                var tag = x.tag, key = x.key
                for p in others { tag[p] = tk.tag[p]![u]; key[p] = tk.key[p]![u] }
                u += 1
                return PA(x: x.x, tag: tag, key: key)
            }
            func tagAW(_ w: AW) -> AW { let v = tagged(w.v); return AW(v: v, m: w.m.map { tagged($0) }) }
            alpha = alpha.map { tagged($0) }
            triples = triples.map { $0.map { tagAW($0) } }
            inputs = inputs.map { tagAW($0) }
            checkMask = tagAW(checkMask)
            let myPlain = myBits.map { UInt64($0) }
            let kept1 = l1.kept
            let peers = others
            let slots = 1 + P
            let fx = PrepForensics(gadget: gadget, rows: gadget.count, slots: slots, disclose: { t in
                func slot(_ item: Int, _ x: Enc.EncShare, _ y: UInt64, _ z: UInt64) -> PCAMpc.NetForensics.SlotDisclosure {
                    PCAMpc.NetForensics.SlotDisclosure(bits: x.bits, y: y, z: z,
                                                       recv: peers.map { PCAMpc.NetForensics.PeerRow(peer: $0, vals: kept1.recv[$0]![item]!) },
                                                       rho: peers.map { PCAMpc.NetForensics.PeerRow(peer: $0, vals: kept1.rho[$0]![item]!) })
                }
                var out = [slot(iC[t], aE[t], bS[t], cS[t])]
                for r in 0..<(slots - 1) { out.append(slot(iCh[t][r], ahE[t][r], bS[t], chS[t][r])) }
                return out
            })
            return Prep(mode: "no-dealer", tagged: true, delta: delta, alpha: alpha, triples: triples, inputs: inputs, myPlain: myPlain, checkMask: checkMask, forensics: fx)
        }

        /// The Gilboa OT core. For every peer p: as the OT RECEIVER towards p I choose with the bits of my xs[t] and get
        /// recv[p][t] = x_t*y^p_t + sum(rho^p_t); as the OT SENDER I offer (rho_k, rho_k + gad_k*ys[t]) with fresh masks and keep
        /// sendSum[p][t] = sum(rho). So recv - sendSum over the pair is an additive sharing of x_t*y_t.
        private func otRows(_ layer: String, _ items: [Item], _ keep: Set<Int>?) throws -> Rows {
            let T = items.count
            var recv: [Int: [UInt64]] = [:], sendSum: [Int: [UInt64]] = [:]
            var kept = Kept()
            for p in others {
                recv[p] = [UInt64](repeating: 0, count: T)
                sendSum[p] = [UInt64](repeating: 0, count: T)
                kept.recv[p] = [:]
                kept.rho[p] = [:]
            }
            if T == 0 || others.isEmpty { return Rows(recv: recv, sendSum: sendSum, kept: kept) }
            var rows = 0
            for it in items { rows += it.bits.count }
            var rowItem = [Int](repeating: 0, count: rows)
            var choice = [Int](repeating: 0, count: rows)
            var m0: [Int: [UInt64]] = [:], m1: [Int: [UInt64]] = [:]
            for p in others { m0[p] = [UInt64](repeating: 0, count: rows); m1[p] = [UInt64](repeating: 0, count: rows) }
            var off = 0
            var itemOff = [Int](repeating: 0, count: T)
            for t in 0..<T {
                let it = items[t]
                let len = it.bits.count
                itemOff[t] = off
                let keepIt = keep?.contains(t) ?? false
                if keepIt { for p in others { kept.recv[p]![t] = [UInt64](repeating: 0, count: len) } }
                for k in 0..<len {
                    choice[off + k] = it.bits[k]
                    rowItem[off + k] = t
                }
                for p in others {
                    var sumRho: UInt64 = 0
                    for k in 0..<len {
                        let rho = frng.next()
                        sumRho = Field.add(sumRho, rho)
                        m0[p]![off + k] = rho
                        m1[p]![off + k] = Field.add(rho, Field.mul(it.gad[k], it.y))
                    }
                    sendSum[p]![t] = sumRho
                    if keepIt { kept.rho[p]![t] = Array(m0[p]![off..<(off + len)]) }
                }
                off += len
            }
            var chunk = 0
            var start = 0
            while start < rows {
                let end = min(rows, start + NetOffline.ROWS_PER_ROUND)
                let m = end - start
                let tag = "ox\(layer).\(chunk)"
                if behKind == "ot-u-lie" {
                    // an inconsistent matrix: flip the first row in 64 of the 128 columns only (not a different choice vector)
                    for p in others { recvCh[p]!.tamperFirstColumns(64) }
                }
                var begun: [Int: (message: JSONValue, pending: NetOt.Pending)] = [:]
                for p in others { begun[p] = try recvCh[p]!.begin(Array(choice[start..<end])) }
                let us: [Int: JSONValue] = try io.exchange(tag + ".u", { peer in begun[peer]!.message }, { p, raw in
                    guard raw.jObj != nil else { throw self.io.bad(p, "bad extension message") }
                    return raw
                })
                var ys: [Int: (y0: [UInt64], y1: [UInt64])] = [:]
                for p in others {
                    let s0 = start, e0 = end
                    ys[p] = try otGuard(p, "OT extension (\(tag))") { try sendCh[p]!.respond(us[p], Array(m0[p]![s0..<e0]), Array(m1[p]![s0..<e0])) }
                }
                let cts: [Int: Cipher] = try io.exchange(tag + ".y", { peer in NetOffline.encodeY(Cipher(y0: ys[peer]!.y0, y1: ys[peer]!.y1)) }, { _, raw in try NetOffline.decodeY(raw, m) })
                for p in others {
                    let got = try otGuard(p, "OT extension (\(tag))") { try recvCh[p]!.finish(begun[p]!.pending, cts[p]!.y0, cts[p]!.y1) }
                    for j in 0..<m {
                        let t = rowItem[start + j]
                        recv[p]![t] = Field.add(recv[p]![t], got[j] % Field.prime)
                        if keep?.contains(t) ?? false { kept.recv[p]![t]![start + j - itemOff[t]] = got[j] % Field.prime }
                    }
                }
                start += NetOffline.ROWS_PER_ROUND
                chunk += 1
            }
            return Rows(recv: recv, sendSum: sendSum, kept: kept)
        }

        /// My additive share of X_t*Y_t = (sum x)(sum y): the diagonal x_i*y_i locally plus the Gilboa OT product of every ordered pair.
        private func mulLayer(_ layer: String, _ xs: [Enc.EncShare], _ ys: [UInt64], _ lieAt: Int, _ keep: Set<Int>?) throws -> Layer {
            var z: [UInt64] = []
            var items: [Item] = []
            for t in 0..<xs.count {
                z.append(Field.mul(xs[t].value, ys[t]))
                items.append(Item(bits: xs[t].bits, gad: gadget, y: t == lieAt ? Field.add(ys[t], 1) : ys[t]))
            }
            let r = try otRows(layer, items, keep)
            for p in others {
                let rv = r.recv[p]!, ss = r.sendSum[p]!
                for t in 0..<z.count { z[t] = Field.sub(Field.add(z[t], rv[t]), ss[t]) }
            }
            return Layer(z: z, kept: r.kept)
        }

        /// Pairwise tags for my shares: for every peer j a tag T_ij (mine) and a key K_ji with T_ij = K_ij + Delta_j*x_i. One OT product of my x with j's
        /// Delta per item; each x is split as x = e + d with a fresh encoded e (a derived value has no uniform choice-bit encoding of its own), both halves
        /// multiplied with Delta and added. Returns tag and key by peer.
        private func tagLayer(_ layer: String, _ xs: [UInt64]) throws -> (tag: [Int: [UInt64]], key: [Int: [UInt64]]) {
            var items: [Item] = []
            let plainGadget = Enc.plainGadget()
            for x in xs {
                let e = try sample()
                let d = Enc.plainShare(Field.sub(x, e.value))
                items.append(Item(bits: e.bits, gad: gadget, y: delta))
                items.append(Item(bits: d.bits, gad: plainGadget, y: delta))
            }
            let r = try otRows(layer, items, nil)
            var tag: [Int: [UInt64]] = [:], key: [Int: [UInt64]] = [:]
            for p in others {
                let rv = r.recv[p]!, kv = r.sendSum[p]!
                tag[p] = (0..<xs.count).map { Field.add(rv[2 * $0], rv[2 * $0 + 1]) }
                key[p] = (0..<xs.count).map { Field.add(kv[2 * $0], kv[2 * $0 + 1]) }
            }
            return (tag, key)
        }
    }
}
