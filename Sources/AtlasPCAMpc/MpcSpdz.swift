import Foundation

/// The encrypted-choice-bit gadgets, SPDZ authenticated sharing with the batched MAC-check, the simulated semi-honest runner and the malicious-with-abort
/// runner of the multi-party package, all over `PCAMpc.Field` and driven by an explicit `Field.Rng`. The offline phase is the no-dealer oblivious-transfer
/// one (`PCAMpc.Mascot`) by default, or the explicit trusted dealer (sacrifice-certified triples) behind the `insecureTrustedDealer` opt-in.
extension PCAMpc {
    // MARK: choice-bit gadgets

    public enum Enc {
        public static let FIELD_BITS = 61
        public static let STAT_SEC = 64
        public static let MIN_STAT_SEC = 40

        public static func encBits(_ s: Int) -> Int { FIELD_BITS + 3 * s }

        /// A receiver operand: its field value together with the choice bits that encode it.
        public struct EncShare: Equatable { public var value: UInt64; public var bits: [Int] }

        /// The public gadget vector of statistical security s (0 = the plain binary encoding); s below 40 needs the explicit unsafe flag.
        public static func makeGadget(_ s: Int, _ rng: inout Field.Rng, unsafe: Bool = false) throws -> [UInt64] {
            guard s >= 0 && s <= 64 else { throw MpcError("statSec must be an integer in [0, 64]") }
            if s < MIN_STAT_SEC && !unsafe { throw MpcError("statSec \(s) is below \(MIN_STAT_SEC): refused (tests may pass the explicit unsafe flag)") }
            return (0..<encBits(s)).map { s == 0 ? UInt64(1) << UInt64($0) : rng.next() }
        }

        public static func encValue(_ g: [UInt64], _ bits: [Int]) throws -> UInt64 {
            guard g.count == bits.count else { throw MpcError("encValue: gadget / bits length mismatch") }
            var v: UInt64 = 0
            for k in g.indices where bits[k] == 1 { v = Field.add(v, g[k]) }
            return v
        }

        public static func plainShare(_ v: UInt64) -> EncShare { EncShare(value: v, bits: (0..<FIELD_BITS).map { Int((v >> UInt64($0)) & 1) }) }

        public static func plainGadget() -> [UInt64] { (0..<FIELD_BITS).map { UInt64(1) << UInt64($0) } }

        /// m uniform bits from a field source (the 60 low bits of each draw are uniform).
        public static func randomBits(_ m: Int, _ rng: inout Field.Rng) -> [Int] {
            var out: [Int] = []
            while out.count < m {
                let w = rng.next()
                var i = 0
                while i < 60 && out.count < m { out.append(Int((w >> UInt64(i)) & 1)); i += 1 }
            }
            return out
        }

        public static func sampleEnc(_ g: [UInt64], _ rng: inout Field.Rng) throws -> EncShare {
            let bits = randomBits(g.count, &rng)
            return EncShare(value: try encValue(g, bits), bits: bits)
        }
    }

    // MARK: SPDZ authenticated shares

    public enum Spdz {
        public static let MAC_KEYS = 2
        public static let MIN_MAC_SOUNDNESS_BITS = 100
        public static let SACRIFICE_PARTNERS = 2

        /// Raised (thrown) when the MAC-check detects an inconsistent opening or MAC: the protocol ABORTS, no output.
        public struct MacCheckAbort: Error, CustomStringConvertible { public let description: String }

        public struct MacKey { public var alphaShares: [UInt64]; public var alpha: UInt64 }
        /// The global MAC keys: key 0 is alphaShares / alpha; extraKeys are further independent keys.
        public struct MacContext { public var n: Int; public var alphaShares: [UInt64]; public var alpha: UInt64; public var extraKeys: [MacKey]
            public var macKeys: [MacKey] { [MacKey(alphaShares: alphaShares, alpha: alpha)] + extraKeys }
        }
        /// value shares sum to x, mac shares to alpha*x (key 0), extraMac[l-1] to extraKeys[l-1].alpha*x.
        public struct AuthSV { public var value: [UInt64]; public var mac: [UInt64]; public var extraMac: [[UInt64]] }
        public struct AuthTriple { public var a: AuthSV; public var b: AuthSV; public var c: AuthSV }
        public struct TripleWithPartners { public var keep: AuthTriple; public var partners: [AuthTriple] }
        /// TEST-ONLY lying-dealer fault: the dealer authenticates a wrong product (nil entries mean no delta).
        public struct DealerFault { public var keepCDelta: UInt64?; public var partnerCDelta: [UInt64?]?
            public init(keepCDelta: UInt64? = nil, partnerCDelta: [UInt64?]? = nil) { self.keepCDelta = keepCDelta; self.partnerCDelta = partnerCDelta }
        }
        /// A party's broadcast deviation in the online phase (models an active cheater).
        public struct Deviation { public var openIndex: Int; public var party: Int; public var valueDelta: UInt64?; public var macDelta: UInt64?; public var macKey: Int?
            public init(openIndex: Int, party: Int, valueDelta: UInt64?, macDelta: UInt64?, macKey: Int?) {
                self.openIndex = openIndex; self.party = party; self.valueDelta = valueDelta; self.macDelta = macDelta; self.macKey = macKey
            }
        }
        /// One partial opening as it reaches the MAC-check: the public value and macShares[key][party].
        public struct OpenedValue { public var value: UInt64; public var macShares: [[UInt64]]; public var label: String }

        /// keys * (log2 p - 1): the soundness in bits of the batched MAC-check.
        public static func macSoundnessBits(_ keys: Int, _ p: Double = Double(Field.prime)) -> Double {
            var l = log(p) / log(2.0)
            let r = l.rounded()
            if abs(l - r) < 1e-9 && pow(2.0, r) == p { l = r }
            return Double(keys) * (l - 1)
        }

        private static func mk(_ n: Int, _ rng: inout Field.Rng) throws -> MacKey {
            let alpha = rng.next()
            return MacKey(alphaShares: try Sharing.share(alpha, n, &rng), alpha: alpha)
        }

        public static func setupMac(_ n: Int, _ rng: inout Field.Rng, keys: Int = MAC_KEYS) throws -> MacContext {
            guard n >= 1 else { throw MpcError("setupMac: n must be a positive integer") }
            guard keys >= 1 && keys <= 16 else { throw MpcError("setupMac: keys must be an integer in [1, 16]") }
            let first = try mk(n, &rng)
            var extra: [MacKey] = []
            for _ in 0..<(keys - 1) { extra.append(try mk(n, &rng)) }
            return MacContext(n: n, alphaShares: first.alphaShares, alpha: first.alpha, extraKeys: extra)
        }

        public static func authShare(_ secret: UInt64, _ ctx: MacContext, _ rng: inout Field.Rng) throws -> AuthSV {
            let value = try Sharing.share(secret, ctx.n, &rng)
            let mac = try Sharing.share(Field.mul(ctx.alpha, secret), ctx.n, &rng)
            var extra: [[UInt64]] = []
            for k in ctx.extraKeys { extra.append(try Sharing.share(Field.mul(k.alpha, secret), ctx.n, &rng)) }
            return AuthSV(value: value, mac: mac, extraMac: extra)
        }

        public static func authConstant(_ c: UInt64, _ ctx: MacContext) -> AuthSV {
            var value = [UInt64](repeating: 0, count: ctx.n)
            value[0] = c
            return AuthSV(value: value, mac: Sharing.scale(ctx.alphaShares, c), extraMac: ctx.extraKeys.map { Sharing.scale($0.alphaShares, c) })
        }

        private static func requireSame(_ x: AuthSV, _ y: AuthSV) throws {
            guard x.value.count == y.value.count && x.mac.count == y.mac.count else { throw MpcError("authenticated shared values must have the same party count") }
            guard x.extraMac.count == y.extraMac.count else { throw MpcError("authenticated shared values must carry the same number of MAC keys") }
            for l in x.extraMac.indices where x.extraMac[l].count != y.extraMac[l].count { throw MpcError("authenticated shared values must have the same party count") }
        }

        private static func zip(_ x: AuthSV, _ y: AuthSV, _ f: (UInt64, UInt64) -> UInt64) throws -> AuthSV {
            try requireSame(x, y)
            func z(_ a: [UInt64], _ b: [UInt64]) -> [UInt64] { (0..<a.count).map { f(a[$0], b[$0]) } }
            return AuthSV(value: z(x.value, y.value), mac: z(x.mac, y.mac), extraMac: (0..<x.extraMac.count).map { z(x.extraMac[$0], y.extraMac[$0]) })
        }

        public static func add(_ x: AuthSV, _ y: AuthSV) throws -> AuthSV { try zip(x, y, Field.add) }
        public static func sub(_ x: AuthSV, _ y: AuthSV) throws -> AuthSV { try zip(x, y, Field.sub) }
        public static func neg(_ x: AuthSV) -> AuthSV { AuthSV(value: Sharing.neg(x.value), mac: Sharing.neg(x.mac), extraMac: x.extraMac.map(Sharing.neg)) }
        public static func scale(_ x: AuthSV, _ c: UInt64) -> AuthSV { AuthSV(value: Sharing.scale(x.value, c), mac: Sharing.scale(x.mac, c), extraMac: x.extraMac.map { Sharing.scale($0, c) }) }

        /// x + c for a PUBLIC constant c: c to one party's value share, alpha_i*c to every party's MAC share under every key.
        public static func addPublic(_ x: AuthSV, _ c: UInt64, _ ctx: MacContext) throws -> AuthSV {
            let n = ctx.n
            guard x.value.count == n && x.mac.count == n && ctx.alphaShares.count == n else { throw MpcError("addPublicAuth: shared value and MAC context disagree on the party count") }
            guard x.extraMac.count == ctx.extraKeys.count else { throw MpcError("addPublicAuth: shared value and MAC context disagree on the key count") }
            var value = x.value
            value[0] = Field.add(value[0], c)
            let mac = (0..<n).map { Field.add(x.mac[$0], Field.mul(ctx.alphaShares[$0], c)) }
            var extra: [[UInt64]] = []
            for l in x.extraMac.indices {
                let row = x.extraMac[l], key = ctx.extraKeys[l]
                guard row.count == n && key.alphaShares.count == n else { throw MpcError("addPublicAuth: extra MAC party count mismatch") }
                extra.append((0..<n).map { Field.add(row[$0], Field.mul(key.alphaShares[$0], c)) })
            }
            return AuthSV(value: value, mac: mac, extraMac: extra)
        }

        public static func notBit(_ b: AuthSV, _ ctx: MacContext) throws -> AuthSV { try addPublic(neg(b), 1, ctx) }

        public static func value(_ x: AuthSV) -> UInt64 { x.value.reduce(0, Field.add) }

        public static func genAuthTriple(_ ctx: MacContext, _ rng: inout Field.Rng) throws -> AuthTriple {
            let a = rng.next(), b = rng.next()
            let as_ = try authShare(a, ctx, &rng), bs = try authShare(b, ctx, &rng)
            return AuthTriple(a: as_, b: bs, c: try authShare(Field.mul(a, b), ctx, &rng))
        }

        /// A triple to deliver plus its sacrifice partners (every partner shares keep.b).
        public static func genTripleWithPartners(_ ctx: MacContext, _ rng: inout Field.Rng, partners: Int = SACRIFICE_PARTNERS, fault: DealerFault? = nil) throws -> TripleWithPartners {
            guard partners >= 1 && partners <= 8 else { throw MpcError("genTripleWithPartners: partners must be in [1, 8]") }
            let a = rng.next(), b = rng.next()
            let bSV = try authShare(b, ctx, &rng)
            let kd = fault?.keepCDelta ?? 0
            let keepA = try authShare(a, ctx, &rng)
            let keepC = try authShare(Field.add(Field.mul(a, b), kd), ctx, &rng)
            var ps: [AuthTriple] = []
            for r in 0..<partners {
                let ah = rng.next()
                var pd: UInt64 = 0
                if let d = fault?.partnerCDelta, r < d.count, let x = d[r] { pd = x }
                let pa = try authShare(ah, ctx, &rng)
                let pc = try authShare(Field.add(Field.mul(ah, b), pd), ctx, &rng)
                ps.append(AuthTriple(a: pa, b: bSV, c: pc))
            }
            return TripleWithPartners(keep: AuthTriple(a: keepA, b: bSV, c: keepC), partners: ps)
        }

        /// Arithmetic core of the batched MAC-check over an arbitrary modulus p (below 2^64); returns sigma[key][party].
        public static func macResiduals(_ p: UInt64, _ alphaShares: [[UInt64]], _ opened: [OpenedValue], _ challenges: [[UInt64]]) throws -> [[UInt64]] {
            guard p > 1 else { throw MpcError("macResiduals: modulus must exceed 1") }
            func mm(_ a: UInt64, _ b: UInt64) -> UInt64 { let w = (a % p).multipliedFullWidth(by: b % p); return p.dividingFullWidth((w.high, w.low)).remainder }
            func am(_ a: UInt64, _ b: UInt64) -> UInt64 { let s = (a % p) &+ (b % p); return (s < (a % p) || s >= p) ? s &- p : s }
            var out: [[UInt64]] = []
            for l in alphaShares.indices {
                guard l < challenges.count, challenges[l].count >= opened.count else { throw MpcError("macResiduals: challenges missing") }
                let r = challenges[l]
                var a: UInt64 = 0
                for j in opened.indices { a = am(a, mm(r[j], opened[j].value)) }
                var row: [UInt64] = []
                for i in alphaShares[l].indices {
                    var gamma: UInt64 = 0
                    for j in opened.indices {
                        guard l < opened[j].macShares.count, i < opened[j].macShares[l].count else { throw MpcError("macResiduals: mac shares missing") }
                        gamma = am(gamma, mm(r[j], opened[j].macShares[l][i]))
                    }
                    let sub = mm(alphaShares[l][i], a)
                    row.append(gamma >= sub ? gamma - sub : gamma &+ (p - sub))
                }
                out.append(row)
            }
            return out
        }

        /// The SPDZ online engine: partial openings and the batched MAC-check.
        public final class Engine {
            private let ctx: MacContext
            private let deviations: [Deviation]
            private var opened: [OpenedValue] = []
            private var counter = 0
            public var openCount: Int { counter }

            public init(_ ctx: MacContext, deviations: [Deviation] = []) throws {
                let bits = Spdz.macSoundnessBits(1 + ctx.extraKeys.count)
                guard bits >= Double(Spdz.MIN_MAC_SOUNDNESS_BITS) else {
                    throw MpcError("SpdzEngine: MAC context gives only \(Int(bits.rounded())) bits of statistical soundness (< \(Spdz.MIN_MAC_SOUNDNESS_BITS)); use setupMac(n, rng) with the default \(Spdz.MAC_KEYS) keys")
                }
                self.ctx = ctx
                self.deviations = deviations
            }

            public func open(_ x: AuthSV, _ label: String = "") throws -> UInt64 {
                let idx = counter
                counter += 1
                guard x.extraMac.count == ctx.extraKeys.count else { throw MpcError("open: value and MAC context disagree on the key count") }
                var valueShares = x.value
                var macShares: [[UInt64]] = [x.mac] + x.extraMac
                for d in deviations where d.openIndex == idx {
                    guard d.party >= 0 && d.party < ctx.n else { throw MpcError("Deviation.party out of range") }
                    if let dv = d.valueDelta { valueShares[d.party] = Field.add(valueShares[d.party], dv) }
                    if let dm = d.macDelta {
                        let key = d.macKey ?? 0
                        guard key >= 0 && key < macShares.count else { throw MpcError("Deviation.macKey out of range") }
                        macShares[key][d.party] = Field.add(macShares[key][d.party], dm)
                    }
                }
                let value = valueShares.reduce(0, Field.add)
                opened.append(OpenedValue(value: value, macShares: macShares, label: label))
                return value
            }

            /// Batched MAC-check over every partial open so far; throws `MacCheckAbort` on any inconsistency.
            public func macCheck(_ rng: inout Field.Rng) throws {
                if opened.isEmpty { return }
                let keys = ctx.macKeys
                var challenges: [[UInt64]] = []
                for _ in keys { challenges.append((0..<opened.count).map { _ in rng.next() }) }
                let sigma = try Spdz.macResiduals(Field.prime, keys.map { $0.alphaShares }, opened, challenges)
                // The reference also draws one commitment nonce per party and checks the commitment against itself (always consistent), so only the draws matter here.
                // shortcut: the self-opening of a commitment is not recomputed; revisit if parties ever commit over a channel.
                for row in sigma { for _ in row { _ = rng.next() } }
                for (l, row) in sigma.enumerated() {
                    let residual = row.reduce(0, Field.add)
                    if residual != 0 { throw MacCheckAbort(description: "MAC-check FAILED (key \(l)): residual \(residual) != 0 \u{2014} an actively-malicious party was detected; aborting with no output") }
                }
            }
        }

        /// Sacrifice check: certifies the kept triples or throws `MacCheckAbort`, emitting nothing.
        public static func sacrificeVerify(_ batch: [TripleWithPartners], _ ctx: MacContext, _ rng: inout Field.Rng, deviations: [Deviation] = []) throws -> [AuthTriple] {
            let engine = try Engine(ctx, deviations: deviations)
            var taus: [UInt64] = []
            for t in batch {
                let keep = t.keep
                guard !t.partners.isEmpty else { throw MacCheckAbort(description: "sacrifice: a triple without partners cannot be certified") }
                for sac in t.partners {
                    guard sac.b.value == keep.b.value else { throw MacCheckAbort(description: "sacrifice: partner does not share b with the triple") }
                    var e = rng.next()
                    if e == 0 { e = 1 }
                    let rho = try engine.open(try sub(scale(keep.a, e), sac.a), "sacrifice:rho")
                    var tau = try sub(scale(keep.c, e), sac.c)
                    tau = try sub(tau, scale(keep.b, rho))
                    taus.append(try engine.open(tau, "sacrifice:tau"))
                }
            }
            try engine.macCheck(&rng)
            for t in taus where t != 0 {
                throw MacCheckAbort(description: "Beaver-triple sacrifice FAILED: residual tau=\(t) != 0 - a malformed triple (c != a*b) was delivered; aborting with no triple emitted")
            }
            return batch.map { $0.keep }
        }

        /// Authenticated Beaver multiplication consuming `triple`; the d and e openings are recorded for the MAC-check.
        public static func beaverMul(_ x: AuthSV, _ y: AuthSV, _ t: AuthTriple, _ ctx: MacContext, _ engine: Engine, _ label: String) throws -> AuthSV {
            try requireSame(x, t.a); try requireSame(x, t.b); try requireSame(x, t.c); try requireSame(x, y)
            let d = try engine.open(try sub(x, t.a), label + ":d")
            let e = try engine.open(try sub(y, t.b), label + ":e")
            let z = try add(t.c, try add(scale(t.b, d), scale(t.a, e)))
            return try addPublic(z, Field.mul(d, e), ctx)
        }
    }

    // MARK: composition under MPC

    /// The full additive sharing of one party's secret bit (test inspection only).
    public struct SharingRecord { public var label: String; public var party: Int; public var secret: UInt64; public var shares: [UInt64] }

    public struct MpcResult {
        public var composed: DecisionVector
        public var parties: Int
        public var Q: Int
        public var opened: [Beaver.Opened]
        public var sharings: [SharingRecord]
        public var multiplications: Int
        /// Party 0's held shares, in sharing order (a semi-honest corruption of that party).
        public var heldShares0: [UInt64]
    }

    /// The simulated runner: all N parties in one process. Computes exactly `composeClear` under MPC; `seed` nil draws the sharing randomness from the CSPRNG.
    public static func composeSecure(_ vectors: [DecisionVector?], Q: Int = DEFAULT_Q, seed: UInt64? = nil) throws -> MpcResult {
        let n = vectors.count
        guard n > 0 else { throw MpcError("composeSecure: no parties (fail closed)") }
        try assertDecisionVectors(vectors, Q)
        let vs = vectors.compactMap { $0 }
        var rng = Field.Rng.make(seed: seed)
        var opened: [Beaver.Opened] = []
        var sharings: [SharingRecord] = []
        var mults = 0
        func shareBit(_ bit: Int, _ label: String, _ party: Int) throws -> [UInt64] {
            let s = try Sharing.share(UInt64(bit), n, &rng)
            sharings.append(SharingRecord(label: label, party: party, secret: UInt64(bit), shares: s))
            return s
        }
        func and(_ bits: [[UInt64]]) throws -> [UInt64] {
            guard var acc = bits.first else { return try Sharing.shareConstant(1, n) }
            for i in 1..<max(bits.count, 1) {
                let r = try Beaver.mul(acc, bits[i], try Beaver.genTriple(n, &rng))
                acc = r.z; opened += r.opened; mults += 1
            }
            return acc
        }
        func or(_ bits: [[UInt64]]) throws -> [UInt64] {
            guard let first = bits.first else { return try Sharing.shareConstant(0, n) }
            var prod = Sharing.notBit(first)
            for i in 1..<max(bits.count, 1) {
                let r = try Beaver.mul(prod, Sharing.notBit(bits[i]), try Beaver.genTriple(n, &rng))
                prod = r.z; opened += r.opened; mults += 1
            }
            return Sharing.notBit(prod)
        }
        var allowBits: [[UInt64]] = []
        for p in 0..<n { allowBits.append(try shareBit(vs[p].allow, "p\(p).allow", p)) }
        let allow = try Sharing.reconstruct(try and(allowBits)) == 1 ? 1 : 0
        let tTherm = try vs.map { try Thermometer.encode(Double($0.t), 3) }
        var tGe: [Int] = []
        for k in 0..<3 {
            var bitsAtK: [[UInt64]] = []
            for p in 0..<n { bitsAtK.append(try shareBit(tTherm[p][k], "p\(p).t.ge\(k + 1)", p)) }
            tGe.append(try Sharing.reconstruct(try or(bitsAtK)) == 1 ? 1 : 0)
        }
        let t = min(3, max(1, Thermometer.decode(tGe)))
        let rTherm = try vs.map { try Thermometer.encode(Double($0.rQuant), Q) }
        var rGe: [Int] = []
        for k in 0..<Q {
            var bitsAtK: [[UInt64]] = []
            for p in 0..<n { bitsAtK.append(try shareBit(rTherm[p][k], "p\(p).r.ge\(k + 1)", p)) }
            rGe.append(try Sharing.reconstruct(try or(bitsAtK)) == 1 ? 1 : 0)
        }
        let composed = DecisionVector(allow: allow, t: t, rQuant: Thermometer.decode(rGe))
        return MpcResult(composed: composed, parties: n, Q: Q, opened: opened, sharings: sharings, multiplications: mults, heldShares0: sharings.map { $0.shares[0] })
    }

    /// Trusted-dealer options of the malicious runner (honoured only with `insecureTrustedDealer`).
    public struct DealerOptions {
        public var verifyTriples: Bool?
        public var partners: Int?
        public var fault: Spdz.DealerFault?
        public init(verifyTriples: Bool? = nil, partners: Int? = nil, fault: Spdz.DealerFault? = nil) { self.verifyTriples = verifyTriples; self.partners = partners; self.fault = fault }
    }

    public struct MaliciousConfig {
        public var Q: Int?
        public var seed: UInt64?
        public var deviations: [Spdz.Deviation] = []
        /// An explicit offline provider; the default is the no-dealer (oblivious-transfer) one.
        public var offline: PCAMpcOfflineProvider?
        public var insecureTrustedDealer = false
        public var dealer: DealerOptions?
        public init() {}
    }

    public struct MaliciousResult { public var composed: DecisionVector; public var parties: Int; public var Q: Int; public var opens: Int; public var multiplications: Int
        public var offlineMode: String; public var triplesVerified: Bool; public var macChecked: Bool }

    /// The malicious-secure runner: the same composition as `composeSecure`, but every shared value carries a MAC and nothing is accepted as output until the
    /// batched MAC-check passes (a correct result or `MacCheckAbort`). Offline phase: a no-dealer provider (the default, oblivious-transfer based), or an
    /// explicit trusted dealer with sacrifice-certified triples (`insecureTrustedDealer`).
    public static func composeSecureMalicious(_ vectors: [DecisionVector?], _ cfg: MaliciousConfig = MaliciousConfig()) throws -> MaliciousResult {
        let n = vectors.count
        guard n > 0 else { throw MpcError("composeSecureMalicious: no parties (fail closed)") }
        let Q = cfg.Q ?? DEFAULT_Q
        try assertDecisionVectors(vectors, Q)
        var rng = Field.Rng.make(seed: cfg.seed)
        if cfg.offline != nil && cfg.insecureTrustedDealer { throw MpcError("composeSecureMalicious: offline and insecureTrustedDealer are mutually exclusive (fail closed)") }
        if cfg.dealer != nil && !cfg.insecureTrustedDealer && cfg.offline == nil { throw MpcError("composeSecureMalicious: dealer options require insecureTrustedDealer: true (fail closed)") }
        var offline: PCAMpcOfflineProvider? = cfg.offline
        if offline == nil && !cfg.insecureTrustedDealer { offline = try Mascot.makeNoDealerOffline(n, seed: cfg.seed) }
        if let o = offline, o.n != n { throw MpcError("composeSecureMalicious: offline provider party count != number of vectors") }
        let vs = vectors.compactMap { $0 }
        let ctx: Spdz.MacContext
        if let o = offline { ctx = o.macContext() } else { ctx = try Spdz.setupMac(n, &rng) }
        let engine = try Spdz.Engine(ctx, deviations: cfg.deviations)
        var mults = 0
        let verify = cfg.dealer?.verifyTriples ?? true
        func nextTriple() throws -> Spdz.AuthTriple {
            if let o = offline { return try o.genAuthTriple() }
            if !verify {
                if let f = cfg.dealer?.fault { return try Spdz.genTripleWithPartners(ctx, &rng, partners: 1, fault: f).keep }
                return try Spdz.genAuthTriple(ctx, &rng)
            }
            let dealt = try Spdz.genTripleWithPartners(ctx, &rng, partners: cfg.dealer?.partners ?? Spdz.SACRIFICE_PARTNERS, fault: cfg.dealer?.fault)
            return try Spdz.sacrificeVerify([dealt], ctx, &rng)[0]
        }
        func shareBit(_ bit: Int, _ owner: Int) throws -> Spdz.AuthSV {
            if let o = offline { return try o.authInput(UInt64(bit), owner) }
            return try Spdz.authShare(UInt64(bit), ctx, &rng)
        }
        func and(_ bits: [Spdz.AuthSV]) throws -> Spdz.AuthSV {
            guard var acc = bits.first else { return Spdz.authConstant(1, ctx) }
            for i in 1..<max(bits.count, 1) { acc = try Spdz.beaverMul(acc, bits[i], try nextTriple(), ctx, engine, "and\(i)"); mults += 1 }
            return acc
        }
        func or(_ bits: [Spdz.AuthSV]) throws -> Spdz.AuthSV {
            guard let first = bits.first else { return Spdz.authConstant(0, ctx) }
            var prod = try Spdz.notBit(first, ctx)
            for i in 1..<max(bits.count, 1) { prod = try Spdz.beaverMul(prod, try Spdz.notBit(bits[i], ctx), try nextTriple(), ctx, engine, "or\(i)"); mults += 1 }
            return try Spdz.notBit(prod, ctx)
        }
        var allowBits: [Spdz.AuthSV] = []
        for p in 0..<n { allowBits.append(try shareBit(vs[p].allow, p)) }
        let allowSV = try and(allowBits)
        let tTherm = try vs.map { try Thermometer.encode(Double($0.t), 3) }
        var tGe: [Spdz.AuthSV] = []
        for k in 0..<3 { var bits: [Spdz.AuthSV] = []; for p in 0..<n { bits.append(try shareBit(tTherm[p][k], p)) }; tGe.append(try or(bits)) }
        let rTherm = try vs.map { try Thermometer.encode(Double($0.rQuant), Q) }
        var rGe: [Spdz.AuthSV] = []
        for k in 0..<Q { var bits: [Spdz.AuthSV] = []; for p in 0..<n { bits.append(try shareBit(rTherm[p][k], p)) }; rGe.append(try or(bits)) }
        let allowOpen = try engine.open(allowSV, "out:allow")
        var tOpen: [Int] = []
        for k in 0..<3 { tOpen.append(try engine.open(tGe[k], "out:t.ge\(k + 1)") == 1 ? 1 : 0) }
        var rOpen: [Int] = []
        for k in 0..<Q { rOpen.append(try engine.open(rGe[k], "out:r.ge\(k + 1)") == 1 ? 1 : 0) }
        try engine.macCheck(&rng)
        let composed = DecisionVector(allow: allowOpen == 1 ? 1 : 0, t: min(3, max(1, Thermometer.decode(tOpen))), rQuant: Thermometer.decode(rOpen))
        return MaliciousResult(composed: composed, parties: n, Q: Q, opens: engine.openCount, multiplications: mults, offlineMode: offline != nil ? "no-dealer" : "trusted-dealer", triplesVerified: offline != nil || verify, macChecked: true)
    }
}
