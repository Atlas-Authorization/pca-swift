import Foundation

/// A source of the SPDZ offline phase: the MAC key, authenticated triples and authenticated input sharings.
public protocol PCAMpcOfflineProvider: AnyObject {
    var n: Int { get }
    func macContext() -> PCAMpc.Spdz.MacContext
    func genAuthTriple() throws -> PCAMpc.Spdz.AuthTriple
    /// Authenticated sharing of `value` contributed by party `owner`.
    func authInput(_ value: UInt64, _ owner: Int) throws -> PCAMpc.Spdz.AuthSV
}

/// The no-dealer SPDZ offline phase (MASCOT-style): every product of two additively shared values is built from real oblivious transfers (Gilboa
/// multiplication over OT extension), the MAC key is distributed and never reconstructed, and every produced triple is certified by the sacrifice check.
/// When a check fails the OT transcripts are searched to blame the cheating party.
extension PCAMpc {
    public enum Mascot {
        /// A MAC-check abort raised by the offline phase, naming the party the OT transcripts convict (when one can be named).
        public struct OfflineCheatingAbort: Error, CustomStringConvertible {
            public let description: String
            public let blamed: [Int]
            init(_ message: String, _ blamed: [Int]) {
                self.blamed = blamed
                description = blamed.isEmpty ? message : message + "; offline OT transcript names party " + blamed.map { String($0) }.joined(separator: ", ")
            }
        }

        /// TEST-ONLY: the productMul-th product's claimed share is shifted by delta (a cheating party lying about a product).
        public struct OfflineDeviation {
            public var productMul: Int
            public var delta: UInt64
            public init(productMul: Int, delta: UInt64) { self.productMul = productMul; self.delta = delta }
        }

        /// Options (nil fields mean the defaults).
        public struct NoDealerOptions {
            public var sacrifice: Bool?
            public var sacrificePartners: Int?
            public var macKeys: Int?
            public var deviation: OfflineDeviation?
            public var statSec: Int?
            public var unsafeStatSec = false
            public init() {}
        }

        /// One operand of a multiplication request: a plain value or an encoded (value, choice bits) share.
        enum Operand { case enc(Enc.EncShare), plain(UInt64) }
        private struct Req { var x: [Operand]; var y: [UInt64] }
        private struct Part { var bits: [Int]; var gad: [UInt64] }
        private struct Piece { var value: UInt64; var parts: [Part] }
        private struct Seg { var q: Int; var start: Int; var len: Int; var senderSum: UInt64 }
        private struct OtRecord { var receiver: Int; var sender: Int; var msg0: [UInt64]; var msg1: [UInt64]; var received: [UInt64] }
        private struct ProductClaim { var claimed: [UInt64]; var implied: [UInt64] }

        public final class NoDealerOffline: PCAMpcOfflineProvider {
            public let n: Int
            public let statSec: Int
            public var alphaShares: [UInt64] { keyShares[0] }
            private let keyShares: [[UInt64]]
            private let keyEnc: [[Enc.EncShare]]
            private let gadget: [UInt64]
            private let sacrificePartners: Int
            private var rng: Field.Rng
            private let seed: UInt64
            private let deterministic: Bool
            private var channels: [String: Ot.OtChannel] = [:]
            private let sacrificeOn: Bool
            private let deviation: OfflineDeviation?
            private var productMulCount = 0
            private var log: [OtRecord]?
            private var claims: [ProductClaim] = []

            public init(_ n: Int, seed: UInt64?, _ options: NoDealerOptions = NoDealerOptions()) throws {
                guard n >= 1 else { throw MpcError("NoDealerOffline: n must be a positive integer") }
                self.n = n
                deterministic = seed != nil
                self.seed = seed ?? 0xabcdef12345
                var g = Field.Rng.make(seed: seed)
                sacrificeOn = options.sacrifice ?? true
                deviation = options.deviation
                let keys = options.macKeys ?? Spdz.MAC_KEYS
                guard keys >= 1 && keys <= 16 else { throw MpcError("NoDealerOffline: macKeys must be an integer in [1, 16]") }
                let ss = options.statSec ?? Enc.STAT_SEC
                statSec = ss
                let gad = try Enc.makeGadget(ss, &g, unsafe: options.unsafeStatSec)
                var enc: [[Enc.EncShare]] = []
                for _ in 0..<keys {
                    var row: [Enc.EncShare] = []
                    for _ in 0..<n { row.append(try Enc.sampleEnc(gad, &g)) }
                    enc.append(row)
                }
                gadget = gad
                keyEnc = enc
                keyShares = enc.map { $0.map { $0.value } }
                let sp = options.sacrificePartners ?? Spdz.SACRIFICE_PARTNERS
                sacrificePartners = sp
                guard sp >= 1 && sp <= 8 else { throw MpcError("NoDealerOffline: sacrificePartners must be an integer in [1, 8]") }
                rng = g
            }

            /// The MAC context: the shares of each key and (for tests and the check only) their sums.
            public func macContext() -> Spdz.MacContext {
                let keys = keyShares.map { Spdz.MacKey(alphaShares: $0, alpha: $0.reduce(0, Field.add)) }
                return Spdz.MacContext(n: n, alphaShares: keys[0].alphaShares, alpha: keys[0].alpha, extraKeys: Array(keys.dropFirst()))
            }

            private func channel(_ i: Int, _ j: Int) -> Ot.OtChannel {
                let key = "\(i)->\(j)"
                if let ch = channels[key] { return ch }
                let otRng = deterministic
                    ? OtRandom.splitMix(seed: seed ^ (UInt64(i + 1) &* 0x100000001b3) ^ (UInt64(j + 1) &* 0x1000000000))
                    : OtRandom.secure()
                let ch = Ot.OtChannel(otRng)
                channels[key] = ch
                return ch
            }

            private func sampleShare() throws -> Enc.EncShare { try Enc.sampleEnc(gadget, &rng) }

            /// Batched Gilboa multiplication: one OT-extension call per ordered party pair for every request.
            private func mulBatch(_ reqs: [Req]) throws -> [[UInt64]] {
                for r in reqs where r.x.count != n || r.y.count != n { throw MpcError("otShareMultiply: wrong length") }
                var pieces: [[Piece]] = []
                for r in reqs {
                    var row: [Piece] = []
                    for xi in r.x {
                        switch xi {
                        case .enc(let e):
                            row.append(Piece(value: e.value, parts: [Part(bits: e.bits, gad: gadget)]))
                        case .plain(let v0):
                            let v = v0 % Field.prime
                            let e = try Enc.sampleEnc(gadget, &rng)
                            let d = Enc.plainShare(Field.sub(v, e.value))
                            row.append(Piece(value: v, parts: [Part(bits: e.bits, gad: gadget), Part(bits: d.bits, gad: Enc.plainGadget())]))
                        }
                    }
                    pieces.append(row)
                }
                var z = [[UInt64]](repeating: [UInt64](repeating: 0, count: n), count: reqs.count)
                for q in 0..<reqs.count { for i in 0..<n { z[q][i] = Field.mul(pieces[q][i].value, reqs[q].y[i]) } }
                for i in 0..<n {
                    for j in 0..<n where i != j {
                        var rows = 0
                        for q in 0..<reqs.count { for part in pieces[q][i].parts { rows += part.bits.count } }
                        var bits = [Int](repeating: 0, count: rows)
                        var msg0 = [UInt64](repeating: 0, count: rows), msg1 = [UInt64](repeating: 0, count: rows)
                        var segs: [Seg] = []
                        var at = 0
                        for q in 0..<reqs.count {
                            let y = reqs[q].y[j] % Field.prime
                            for part in pieces[q][i].parts {
                                let len = part.bits.count
                                var senderSum: UInt64 = 0
                                for k in 0..<len {
                                    let rho = rng.next()
                                    senderSum = Field.add(senderSum, rho)
                                    bits[at + k] = part.bits[k]
                                    msg0[at + k] = rho
                                    msg1[at + k] = Field.add(rho, Field.mul(part.gad[k], y))
                                }
                                segs.append(Seg(q: q, start: at, len: len, senderSum: senderSum))
                                at += len
                            }
                        }
                        let received = try channel(i, j).extend(bits, msg0, msg1).received
                        if log != nil { log!.append(OtRecord(receiver: i, sender: j, msg0: msg0, msg1: msg1, received: received)) }
                        for sg in segs {
                            var receiverSum: UInt64 = 0
                            for k in 0..<sg.len { receiverSum = Field.add(receiverSum, received[sg.start + k] % Field.prime) }
                            z[sg.q][i] = Field.add(z[sg.q][i], receiverSum)
                            z[sg.q][j] = Field.add(z[sg.q][j], Field.neg(sg.senderSum))
                        }
                    }
                }
                return z
            }

            /// Additive shares of x*y where party i holds x_i and y_i (all cross terms via OT).
            func otShareMultiply(_ x: [UInt64], _ y: [UInt64]) throws -> [UInt64] { try mulBatch([Req(x: x.map { .plain($0) }, y: y)])[0] }

            private func keyReq(_ l: Int) -> [Operand] { keyEnc[l].map { .enc($0) } }

            private func toAuth(_ value: [UInt64], _ macs: [[UInt64]]) -> Spdz.AuthSV {
                Spdz.AuthSV(value: value, mac: macs[0], extraMac: Array(macs.dropFirst()))
            }

            private func authenticate(_ valueShares: [UInt64]) throws -> Spdz.AuthSV {
                var reqs: [Req] = []
                for l in 0..<keyEnc.count { reqs.append(Req(x: keyReq(l), y: valueShares)) }
                return toAuth(valueShares, try mulBatch(reqs))
            }

            private func claimProduct(_ implied: [UInt64]) -> [UInt64] {
                var z = implied
                let idx = productMulCount
                productMulCount += 1
                if let d = deviation, d.productMul == idx { z[0] = Field.add(z[0], d.delta) }
                claims.append(ProductClaim(claimed: z, implied: implied))
                return z
            }

            private func macOf(_ z: [[UInt64]], _ start: Int, _ per: Int, _ off: Int, _ K: Int) -> [[UInt64]] {
                (0..<K).map { z[start + $0 * per + off] }
            }

            private func rawTripleWithPartners(_ partners: Int) throws -> Spdz.TripleWithPartners {
                let K = keyEnc.count
                var aEnc: [Enc.EncShare] = []
                for _ in 0..<n { aEnc.append(try sampleShare()) }
                var bShares: [UInt64] = []
                for _ in 0..<n { bShares.append(rng.next()) }
                var ahEnc: [[Enc.EncShare]] = []
                for _ in 0..<partners {
                    var row: [Enc.EncShare] = []
                    for _ in 0..<n { row.append(try sampleShare()) }
                    ahEnc.append(row)
                }
                let aVal = aEnc.map { $0.value }
                let ahVal = ahEnc.map { $0.map { $0.value } }
                var reqs: [Req] = [Req(x: aEnc.map { .enc($0) }, y: bShares)]
                for r in 0..<partners { reqs.append(Req(x: ahEnc[r].map { .enc($0) }, y: bShares)) }
                let macStart = reqs.count
                for l in 0..<K {
                    reqs.append(Req(x: keyReq(l), y: aVal))
                    reqs.append(Req(x: keyReq(l), y: bShares))
                    for r in 0..<partners { reqs.append(Req(x: keyReq(l), y: ahVal[r])) }
                }
                let z1 = try mulBatch(reqs)
                let cShares = claimProduct(z1[0])
                var chShares: [[UInt64]] = []
                for r in 0..<partners { chShares.append(claimProduct(z1[1 + r])) }
                let per = 2 + partners
                var reqs2: [Req] = []
                for l in 0..<K {
                    reqs2.append(Req(x: keyReq(l), y: cShares))
                    for r in 0..<partners { reqs2.append(Req(x: keyReq(l), y: chShares[r])) }
                }
                let z2 = try mulBatch(reqs2)
                let per2 = 1 + partners
                let b = toAuth(bShares, macOf(z1, macStart, per, 1, K))
                let keep = Spdz.AuthTriple(a: toAuth(aVal, macOf(z1, macStart, per, 0, K)), b: b, c: toAuth(cShares, macOf(z2, 0, per2, 0, K)))
                var parts: [Spdz.AuthTriple] = []
                for r in 0..<partners {
                    parts.append(Spdz.AuthTriple(a: toAuth(ahVal[r], macOf(z1, macStart, per, 2 + r, K)), b: b, c: toAuth(chShares[r], macOf(z2, 0, per2, 1 + r, K))))
                }
                return Spdz.TripleWithPartners(keep: keep, partners: parts)
            }

            private func attribute(_ abort: Spdz.MacCheckAbort) -> OfflineCheatingAbort {
                var blamed = Set<Int>()
                for r in log ?? [] {
                    for k in 0..<r.received.count {
                        let got = r.received[k] % Field.prime
                        if got != r.msg0[k] && got != r.msg1[k] { blamed.insert(r.sender); break }
                    }
                }
                for c in claims { for i in 0..<c.claimed.count where c.claimed[i] != c.implied[i] { blamed.insert(i) } }
                return OfflineCheatingAbort(abort.description, blamed.sorted())
            }

            /// One authenticated triple, certified by the sacrifice check (or raw when sacrifice is switched off).
            public func genAuthTriple() throws -> Spdz.AuthTriple {
                if !sacrificeOn { return try rawTripleWithPartners(0).keep }
                log = []
                claims = []
                defer { log = nil; claims = [] }
                do {
                    let t = try rawTripleWithPartners(sacrificePartners)
                    return try Spdz.sacrificeVerify([t], macContext(), &rng)[0]
                } catch let e as Spdz.MacCheckAbort {
                    throw attribute(e)
                }
            }

            /// An authenticated sharing of a value contributed by `owner`, MACed by OT under the distributed key.
            public func authInput(_ value: UInt64, _ owner: Int) throws -> Spdz.AuthSV {
                guard owner >= 0 && owner < n else { throw MpcError("authInput: owner out of range") }
                return try authenticate(try Sharing.share(value % Field.prime, n, &rng))
            }

            /// Verifies that every supplied input's MAC matches its value via a random combination (aborts otherwise).
            public func checkInputConsistency(_ inputs: [Spdz.AuthSV]) throws {
                if inputs.isEmpty { return }
                for inp in inputs where inp.value.count != n || inp.mac.count != n { throw MpcError("checkInputConsistency: input party count mismatch") }
                let engine = try Spdz.Engine(macContext())
                var rShares: [UInt64] = []
                for _ in 0..<n { rShares.append(rng.next()) }
                var w = try authenticate(rShares)
                for inp in inputs {
                    var e = rng.next()
                    if e == 0 { e = 1 }
                    w = try Spdz.add(w, Spdz.scale(inp, e))
                }
                _ = try engine.open(w, "input-check:w")
                try engine.macCheck(&rng)
            }
        }

        /// The no-dealer offline provider of `n` parties; a non-nil seed makes every draw reproducible (tests only).
        public static func makeNoDealerOffline(_ n: Int, seed: UInt64? = nil, _ options: NoDealerOptions = NoDealerOptions()) throws -> NoDealerOffline {
            try NoDealerOffline(n, seed: seed, options)
        }
    }
}
