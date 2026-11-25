import Foundation
import AtlasPCAVerify
import CryptoKit

/// The pure parts of the networked MPC runner: the length-prefixed JSON frame codec with strict envelope validation and the structured abort that blames
/// a party only when the evidence names one (`NetWire`); canonical encodings of the OT-over-network messages and the gadget-seed agreement helpers
/// (`NetCodec`); pairwise-authenticated field shares for the identifiable-abort mode (`NetPa`); and the forensic disclosures of a failed offline triple
/// with their cross-check and blame (`NetForensics`). Sockets, TLS and the timed distributed driver are not part of this SDK.
extension PCAMpc {
    // MARK: wire

    public enum NetWire {
        /// Frame envelope version; a peer on another version is rejected as a version mismatch.
        public static let WIRE_VERSION = 2
        /// Largest frame body accepted or produced (4 MiB).
        public static let MAX_FRAME_BYTES = 4 * 1024 * 1024

        public static let ABORT_KINDS: Set<String> = ["timeout", "disconnect", "version", "malformed", "oversize", "duplicate", "out-of-order", "wrong-round",
                                                      "wrong-session", "identity", "commitment", "ot-check", "mac-check", "dealer", "equivocation", "flood", "peer-abort", "local"]
        private static let FRAME_TYPES: Set<String> = ["hello", "msg", "abort"]

        /// A protocol abort; `blamed` is nil when the evidence names no culprit (then `reason` explains why).
        public struct NetAbort: Error, CustomStringConvertible {
            public let kind: String
            public let blamed: Int?
            public let reporter: Int
            public let claimedKind: String?
            public let claimedBlame: Int?
            public let reason: String?
            public let evidence: JSONValue?
            public let deadlineMs: Int?
            public let message: String
            public var description: String { message }

            public init(kind: String, blamed: Int?, reporter: Int, detail: String, claimedKind: String? = nil, claimedBlame: Int? = nil, reason: String? = nil,
                        evidence: JSONValue? = nil, deadlineMs: Int? = nil) {
                self.kind = kind
                self.blamed = blamed
                self.reporter = reporter
                self.claimedKind = claimedKind
                self.claimedBlame = claimedBlame
                if blamed == nil {
                    self.reason = (reason?.isEmpty == false) ? reason : "unattributable: the evidence available to this party does not identify a culprit"
                } else { self.reason = nil }
                self.evidence = evidence
                self.deadlineMs = deadlineMs
                message = "[\(kind)] blamed=\(blamed.map { String($0) } ?? "none") reporter=\(reporter): \(detail)"
            }
        }

        /// JSON text of a value (JSON.stringify semantics: compact; `order` names the members a producer wrote first).
        public static func stringify(_ v: JSONValue, order: [String] = []) -> String { JS.stringify(v, order: order) }

        /// A frame: {v, ty, sid, seq, rd, d}. `v` and `seq` are JSON numbers, carried as parsed values.
        public struct Frame {
            public var v: JSONValue
            public var ty: String
            public var sid: String
            public var seq: JSONValue
            public var rd: String
            public var d: JSONValue
            public init(v: JSONValue, ty: String, sid: String, seq: JSONValue, rd: String, d: JSONValue) { self.v = v; self.ty = ty; self.sid = sid; self.seq = seq; self.rd = rd; self.d = d }
        }

        /// Length-prefixed (4-byte big-endian) JSON frame; throws when the body exceeds MAX_FRAME_BYTES.
        public static func encodeFrame(_ f: Frame) throws -> [UInt8] {
            func q(_ s: String) -> String { JS.stringify(.string(s)) }
            let text = "{\"v\":" + JS.stringify(f.v) + ",\"ty\":" + q(f.ty) + ",\"sid\":" + q(f.sid) + ",\"seq\":" + JS.stringify(f.seq) + ",\"rd\":" + q(f.rd) + ",\"d\":" + JS.stringify(f.d) + "}"
            let body = Array(text.utf8)
            guard body.count <= MAX_FRAME_BYTES else { throw MpcError("frame too large") }
            return MpcHash.u32(Int64(body.count)) + body
        }

        /// Reassembles length-prefixed frames from arbitrary chunking; an oversize length prefix throws.
        public final class FrameSplitter {
            private var data: [UInt8] = []
            public init() {}

            public func push(_ chunk: [UInt8]) throws -> [[UInt8]] {
                data += chunk
                var out: [[UInt8]] = []
                var off = 0
                while data.count - off >= 4 {
                    let len = Int(data[off]) << 24 | Int(data[off + 1]) << 16 | Int(data[off + 2]) << 8 | Int(data[off + 3])
                    if len > MAX_FRAME_BYTES { throw MpcError("oversize") }
                    if data.count - off < 4 + len { break }
                    out.append(Array(data[(off + 4)..<(off + 4 + len)]))
                    off += 4 + len
                }
                if off > 0 { data.removeFirst(off) }
                return out
            }
        }

        // MARK: envelope validation

        private static func parseObject(_ body: [UInt8]) -> JObject? {
            // the reference reads the frame with JSON.parse: a repeated member name keeps its last value
            guard let j = try? StrictJSON.parseLenientLastWins(String(decoding: body, as: UTF8.self)) else { return nil }
            return IV.normalized(j).mpcObject
        }

        private static func num(_ v: JSONValue?) -> Double? { IV.num(v) }
        private static func safeInt(_ d: Double?) -> Bool { d != nil && d!.isFinite && d! == d!.rounded() && abs(d!) <= 9007199254740991.0 }
        private static func negZero(_ d: Double) -> Bool { d == 0 && d.sign == .minus }

        /// The envelope version of a body, or nil when it is not a JSON object with a safe-integer v.
        public static func peekVersion(_ body: [UInt8]) -> Int64? {
            guard let o = parseObject(body), let v = num(o["v"]), safeInt(v), !negZero(v) else { return nil }
            return Int64(v)
        }

        private static func envelopeShapeOk(_ o: JObject) -> Bool {
            guard o.count == 6, o["v"] != nil else { return false }
            guard let ty = o["ty"]?.mpcString, FRAME_TYPES.contains(ty) else { return false }
            guard o["sid"]?.mpcString != nil, o["rd"]?.mpcString != nil else { return false }
            guard let seq = num(o["seq"]), safeInt(seq), seq >= 0, !negZero(seq) else { return false }
            return o["d"] != nil
        }

        /// The frame as an object when it is a well-formed envelope of the current version, else nil.
        public static func parseFrame(_ body: [UInt8]) -> JSONValue? {
            guard let o = parseObject(body), let v = num(o["v"]), v == Double(WIRE_VERSION), envelopeShapeOk(o) else { return nil }
            return .object(o)
        }

        /// The peer's version when the body is a well-formed envelope of a DIFFERENT version, else nil.
        public static func versionMismatch(_ body: [UInt8]) -> Int64? {
            guard let o = parseObject(body), let v = num(o["v"]), safeInt(v), !negZero(v), v != Double(WIRE_VERSION) else { return nil }
            return envelopeShapeOk(o) ? Int64(v) : nil
        }

        // MARK: canonical field-element hex

        public static func hx(_ x: UInt64) -> String { String(x, radix: 16) }

        /// Lowercase hex without leading zeros of a (possibly negative) integer of any width.
        static func hxBig(_ neg: Bool, _ mag: [UInt64]) -> String {
            var s = ""
            for l in mag.reversed() { s += s.isEmpty ? (l == 0 ? "" : String(l, radix: 16)) : String(repeating: "0", count: 16 - String(l, radix: 16).count) + String(l, radix: 16) }
            if s.isEmpty { return "0" }
            return (neg ? "-" : "") + s
        }

        /// Canonical lowercase minimal hex: "0" or a non-zero leading digit, at most `maxDigits` digits.
        static func canonicalHex(_ s: String, _ maxDigits: Int) -> Bool {
            let u = Array(s.utf8)
            if u == [48] { return true }
            guard !u.isEmpty, u.count <= maxDigits, u[0] != 48 else { return false }
            return u.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }
        }

        /// Canonical lowercase hex without leading zeros of an element below the field prime; nil otherwise.
        public static func unhx(_ s: JSONValue?) -> UInt64? {
            guard let str = s?.mpcString, canonicalHex(str, 16), let v = UInt64(str, radix: 16), v < Field.prime else { return nil }
            return v
        }

        public static func unhxArray(_ a: JSONValue?, _ len: Int) -> [UInt64]? {
            guard let arr = a?.mpcArray, arr.count == len else { return nil }
            var out: [UInt64] = []
            for e in arr { guard let v = unhx(e) else { return nil }; out.append(v) }
            return out
        }
    }

    // MARK: codecs

    public enum NetCodec {
        public static func b64(_ u: [UInt8]) -> String { Data(u).base64EncodedString() }

        /// Strict base64: re-encoding must reproduce the input (no trailing-bit or padding aliases); `len` < 0 means any length.
        public static func unb64(_ s: JSONValue?, _ len: Int = -1) throws -> [UInt8] {
            guard let str = s?.mpcString, str.utf8.allSatisfy({ ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57) || $0 == 43 || $0 == 47 || $0 == 61 }),
                  !str.utf8.dropLast(min(2, str.utf8.count)).contains(61), let data = Data(base64Encoded: str) else { throw MpcError("bad base64") }
            guard data.base64EncodedString() == str else { throw MpcError("non-canonical base64") }
            guard len < 0 || data.count == len else { throw MpcError("bad length") }
            return [UInt8](data)
        }

        /// {x, y} canonical hex of a point (affine).
        static func ptJ(_ p: Ec.Point) -> (x: String, y: String) {
            let a = Ec.toAffine(p)
            return (NetWire.hxBig(false, a.x.w), NetWire.hxBig(false, a.y.w))
        }

        /// Canonical lowercase hex without leading zeros of an element below the curve field prime.
        static func hexBig(_ s: JSONValue?) throws -> Fe {
            guard let str = s?.mpcString, NetWire.canonicalHex(str, 64) else { throw MpcError("bad field element") }
            var w = [UInt64](repeating: 0, count: 4)
            for (k, ch) in str.utf8.reversed().enumerated() {
                let d = UInt64(ch <= 57 ? ch - 48 : ch - 87)
                w[k / 16] |= d << UInt64(4 * (k % 16))
            }
            let f = Fe(w: w)
            guard !Fe.geqQ(f) else { throw MpcError("non-canonical field element") }
            return f
        }

        /// A point from {x, y} canonical hex, validated to be a non-identity prime-order-subgroup point.
        static func jPt(_ v: JSONValue?) throws -> Ec.Point {
            guard let o = v?.mpcObject else { throw MpcError("bad point") }
            let x = try hexBig(o["x"]), y = try hexBig(o["y"])
            let p = Ec.Point(x, y, .one, x * y)
            try Ec.assertInSubgroup(p, "received point")
            return p
        }

        public static func sharingsPerTriple(_ partners: Int) -> Int { 3 + 2 * partners }

        static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

        /// Commitment to a party's gadget seed: SHA-256(tag, session, decimal party, seed) as hex.
        public static func gadgetCommit(_ sessionId: String, _ party: Int, _ seed: [UInt8]) -> String {
            hex(MpcHash.sha256([Array("atlas-pca-mpc/gadget-commit".utf8), Array(sessionId.utf8), Array(String(party).utf8), seed]))
        }

        /// The exact bytes a party signs in the gadget seed exchange (round is "gd-c" or "gd-o").
        public static func gadgetStatement(_ sessionId: String, _ round: String, _ signer: Int, _ value: String) -> [UInt8] {
            Array(NetWire.stringify(.array([.string("atlas-pca-mpc/gadget-sig/v1"), .string(sessionId), .string(round), .int(Int64(signer)), .string(value)])).utf8)
        }
    }

    // MARK: pairwise-authenticated shares

    public enum NetPa {
        /// x with tag[j] (my tag for verifier j) and key[j] (my key for verifying j's share).
        public struct PA {
            public var x: UInt64
            public var tag: [UInt64]
            public var key: [UInt64]
            public init(x: UInt64, tag: [UInt64], key: [UInt64]) { self.x = x; self.tag = tag; self.key = key }
        }

        /// An authenticated value: a value share plus one MAC share per global key, each pairwise-authenticated.
        public struct AW {
            public var v: PA
            public var m: [PA]
            public init(v: PA, m: [PA]) { self.v = v; self.m = m }
        }

        public struct PaEnv {
            public var id: Int
            public var n: Int
            public var delta: UInt64
            public var tagged: Bool
            public init(id: Int, n: Int, delta: UInt64, tagged: Bool) { self.id = id; self.n = n; self.delta = delta; self.tagged = tagged }
        }

        private static func zip(_ a: [UInt64], _ b: [UInt64], _ f: (UInt64, UInt64) -> UInt64) throws -> [UInt64] {
            guard a.count == b.count else { throw MpcError("pairwise share tables differ in length") }
            return (0..<a.count).map { f(a[$0], b[$0]) }
        }

        public static func paAdd(_ a: PA, _ b: PA) throws -> PA { PA(x: Field.add(a.x, b.x), tag: try zip(a.tag, b.tag, Field.add), key: try zip(a.key, b.key, Field.add)) }
        public static func paSub(_ a: PA, _ b: PA) throws -> PA { PA(x: Field.sub(a.x, b.x), tag: try zip(a.tag, b.tag, Field.sub), key: try zip(a.key, b.key, Field.sub)) }
        public static func paNeg(_ a: PA) -> PA { PA(x: Field.neg(a.x), tag: a.tag.map(Field.neg), key: a.key.map(Field.neg)) }
        public static func paScale(_ a: PA, _ c: UInt64) -> PA { PA(x: Field.mul(a.x, c), tag: a.tag.map { Field.mul($0, c) }, key: a.key.map { Field.mul($0, c) }) }

        /// Adds a PUBLIC constant to party 0's share (every party applies the same call).
        public static func paAddPublic0(_ env: PaEnv, _ a: PA, _ c: UInt64) throws -> PA {
            if env.id == 0 { return PA(x: Field.add(a.x, c), tag: a.tag, key: a.key) }
            if !env.tagged { return a }
            guard !a.key.isEmpty else { throw MpcError("paAddPublic0: no keys") }
            var key = a.key
            key[0] = Field.sub(key[0], Field.mul(env.delta, c))
            return PA(x: a.x, tag: a.tag, key: key)
        }

        private static func sameKeys(_ a: AW, _ b: AW) throws { guard a.m.count == b.m.count else { throw MpcError("authenticated values carry different key counts") } }

        public static func wAdd(_ a: AW, _ b: AW) throws -> AW { try sameKeys(a, b); return AW(v: try paAdd(a.v, b.v), m: try (0..<a.m.count).map { try paAdd(a.m[$0], b.m[$0]) }) }
        public static func wSub(_ a: AW, _ b: AW) throws -> AW { try sameKeys(a, b); return AW(v: try paSub(a.v, b.v), m: try (0..<a.m.count).map { try paSub(a.m[$0], b.m[$0]) }) }
        public static func wNeg(_ a: AW) -> AW { AW(v: paNeg(a.v), m: a.m.map(paNeg)) }
        public static func wScale(_ a: AW, _ c: UInt64) -> AW { AW(v: paScale(a.v, c), m: a.m.map { paScale($0, c) }) }

        /// x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c.
        public static func wAddPublic(_ env: PaEnv, _ a: AW, _ c: UInt64, _ alpha: [PA]) throws -> AW {
            guard alpha.count >= a.m.count else { throw MpcError("wAddPublic: alpha shares missing") }
            var m: [PA] = []
            for l in 0..<a.m.count { m.append(try paAdd(a.m[l], paScale(alpha[l], c))) }
            return AW(v: try paAddPublic0(env, a.v, c), m: m)
        }

        /// Verifies peer `from`'s opened share x with tag against my key for that peer.
        public static func paVerify(_ env: PaEnv, _ a: PA, _ from: Int, _ x: UInt64, _ tag: UInt64) throws -> Bool {
            guard from >= 0 && from < a.key.count else { throw MpcError("paVerify: peer out of range") }
            return Field.add(a.key[from], Field.mul(env.delta, x)) == tag
        }

        // MARK: wire codec

        public static func paWidth(_ n: Int, _ tagged: Bool) -> Int { tagged ? 1 + 2 * (n - 1) : 1 }

        public static func paFlat(_ a: PA, _ id: Int, _ n: Int, _ tagged: Bool) throws -> [UInt64] {
            var out = [a.x]
            if tagged {
                guard a.tag.count >= n && a.key.count >= n else { throw MpcError("paFlat: tag / key table too short") }
                for j in 0..<n where j != id { out.append(a.tag[j]) }
                for j in 0..<n where j != id { out.append(a.key[j]) }
            }
            return out
        }

        public static func paParse(_ nums: [UInt64], _ off: Int, _ id: Int, _ n: Int, _ tagged: Bool) throws -> PA {
            guard off >= 0 && off < nums.count else { throw MpcError("paParse: out of range") }
            let x = nums[off]
            if !tagged { return PA(x: x, tag: [], key: []) }
            guard n >= 0, off + paWidth(n, true) <= nums.count else { throw MpcError("paParse: out of range") }
            var tag = [UInt64](repeating: 0, count: n), key = [UInt64](repeating: 0, count: n)
            var o = off + 1
            for j in 0..<n where j != id { tag[j] = nums[o]; o += 1 }
            for j in 0..<n where j != id { key[j] = nums[o]; o += 1 }
            return PA(x: x, tag: tag, key: key)
        }

        public static func awWidth(_ n: Int, _ keys: Int, _ tagged: Bool) -> Int { (1 + keys) * paWidth(n, tagged) }

        public static func awFlat(_ a: AW, _ id: Int, _ n: Int, _ tagged: Bool) throws -> [UInt64] {
            var out = try paFlat(a.v, id, n, tagged)
            for p in a.m { out += try paFlat(p, id, n, tagged) }
            return out
        }

        public static func awParse(_ nums: [UInt64], _ off: Int, _ id: Int, _ n: Int, _ keys: Int, _ tagged: Bool) throws -> AW {
            let w = paWidth(n, tagged)
            let v = try paParse(nums, off, id, n, tagged)
            var m: [PA] = []
            for l in 0..<keys { m.append(try paParse(nums, off + (1 + l) * w, id, n, tagged)) }
            return AW(v: v, m: m)
        }
    }

    // MARK: forensics

    public enum NetForensics {
        /// One peer's row of a disclosure table: the peer index and the per-OT values.
        public struct PeerRow { public var peer: Int; public var vals: [UInt64]
            public init(peer: Int, vals: [UInt64]) { self.peer = peer; self.vals = vals } }

        /// One product item's disclosure; recv and rho are keyed by peer index (insertion ordered).
        public struct SlotDisclosure {
            public var bits: [Int]
            public var y: UInt64
            public var z: UInt64
            public var recv: [PeerRow]
            public var rho: [PeerRow]
            public init(bits: [Int], y: UInt64, z: UInt64, recv: [PeerRow], rho: [PeerRow]) { self.bits = bits; self.y = y; self.z = z; self.recv = recv; self.rho = rho }
            func row(_ side: [PeerRow], _ p: Int) -> [UInt64]? { side.first { $0.peer == p }?.vals }
        }

        public static let wireOrder = ["bits", "y", "z", "recv", "rho"]

        public static func slotsFor(_ partners: Int) -> Int { 1 + partners }

        /// The wire (JSON) form of a disclosure.
        public static func wireDisclosure(_ d: [SlotDisclosure]) -> JSONValue {
            func side(_ rows: [PeerRow]) -> JSONValue {
                .array(rows.map { .array([.int(Int64($0.peer)), .array($0.vals.map { .string(NetWire.hx($0)) })]) })
            }
            return .array(d.map { s in
                .object(["bits": .string(s.bits.map { String($0) }.joined()), "y": .string(NetWire.hx(s.y)), "z": .string(NetWire.hx(s.z)), "recv": side(s.recv), "rho": side(s.rho)])
            })
        }

        private static func field(_ s: JSONValue?) throws -> UInt64 {
            guard let v = NetWire.unhx(s) else { throw MpcError("bad field element") }
            return v
        }

        /// Strict parse of a peer's disclosure; throws on any deviation from the expected shape.
        public static func parseDisclosure(_ raw: JSONValue?, _ slots: Int, _ rows: Int, _ peers: [Int]) throws -> [SlotDisclosure] {
            guard let arr = raw?.mpcArray, arr.count == slots else { throw MpcError("bad forensic disclosure") }
            var out: [SlotDisclosure] = []
            for o in arr {
                guard o.mpcObject != nil else { throw MpcError("bad choice bits") }
                guard let bs = o.mpcGet("bits")?.mpcString, bs.utf8.count == rows, bs.utf8.allSatisfy({ $0 == 48 || $0 == 49 }) else { throw MpcError("bad choice bits") }
                let bits = bs.utf8.map { $0 == 49 ? 1 : 0 }
                out.append(SlotDisclosure(bits: bits, y: try field(o.mpcGet("y")), z: try field(o.mpcGet("z")),
                                          recv: try sideParse(o.mpcGet("recv"), rows, peers), rho: try sideParse(o.mpcGet("rho"), rows, peers)))
            }
            return out
        }

        private static func sideParse(_ x: JSONValue?, _ rows: Int, _ peers: [Int]) throws -> [PeerRow] {
            guard let arr = x?.mpcArray, arr.count == peers.count else { throw MpcError("bad peer table") }
            var out: [PeerRow] = []
            for e in arr {
                guard let pair = e.mpcArray, pair.count == 2, let pd = IV.num(pair[0]) else { throw MpcError("bad peer entry") }
                guard pd == pd.rounded(), abs(pd) < 1e9, peers.contains(Int(pd)), !out.contains(where: { $0.peer == Int(pd) }) else { throw MpcError("bad peer entry") }
                guard let vals = pair[1].mpcArray, vals.count == rows else { throw MpcError("bad row table") }
                out.append(PeerRow(peer: Int(pd), vals: try vals.map { try field($0) }))
            }
            return out
        }

        /// selfBad: parties whose own disclosure is inconsistent; pairBad: ordered [receiver, sender] pairs whose OT transcripts disagree.
        public struct AuditResult {
            public var selfBad: Set<Int>
            public var pairBad: [[Int]]
            public init(selfBad: Set<Int>, pairBad: [[Int]]) { self.selfBad = selfBad; self.pairBad = pairBad }
        }

        /// Cross-checks every party's disclosure of one failed triple against the public gadget.
        public static func auditDisclosures(_ all: [Int: [SlotDisclosure]], _ gadget: [UInt64]) throws -> AuditResult {
            var selfBad = Set<Int>()
            var pairBad: [[Int]] = []
            let parties = all.keys.sorted()
            for i in parties {
                let di = all[i]!
                for s in 0..<di.count {
                    let sd = di[s]
                    var value: UInt64 = 0
                    for k in 0..<gadget.count where k < sd.bits.count && sd.bits[k] == 1 { value = Field.add(value, gadget[k] % Field.prime) }
                    var implied = Field.mul(value, sd.y)
                    for p in parties where p != i {
                        guard let rv = sd.row(sd.recv, p), let ho = sd.row(sd.rho, p) else { throw MpcError("audit: peer table missing") }
                        for v in rv { implied = Field.add(implied, v % Field.prime) }
                        for v in ho { implied = Field.sub(implied, v) }
                    }
                    if implied != sd.z { selfBad.insert(i) }
                    for p in parties where p != i {
                        guard let ap = all[p], s < ap.count else { throw MpcError("audit: slot missing") }
                        let sp = ap[s]
                        guard let rho = sp.row(sp.rho, i), let got = sd.row(sd.recv, p), rho.count >= gadget.count, got.count >= gadget.count else { throw MpcError("audit: peer table missing") }
                        let y = sp.y % Field.prime
                        var bad = false
                        var k = 0
                        while k < gadget.count && !bad {
                            let want = Field.add(rho[k], k < sd.bits.count && sd.bits[k] == 1 ? Field.mul(gadget[k], y) : 0)
                            if got[k] % Field.prime != want { bad = true }
                            k += 1
                        }
                        if bad { pairBad.append([i, p]) }
                    }
                }
            }
            return AuditResult(selfBad: selfBad, pairBad: pairBad)
        }

        /// The party the verifier `me` blames, or nil when the evidence cannot name one.
        public static func blameFrom(_ me: Int, _ r: AuditResult) -> Int? {
            if let first = r.selfBad.filter({ $0 != me }).min() { return first }
            for pr in r.pairBad {
                if pr[0] == me { return pr[1] }
                if pr[1] == me { return pr[0] }
            }
            return nil
        }

        public static let DEFAULT_FORENSIC_DEADLINE_MS = 30_000

        /// Binding commitment to a disclosure: session, party, triple index, deadline, a 256-bit nonce and the canonical wire form.
        public static func disclosureCommit(_ sessionId: String, _ party: Int, _ tripleIndex: Int, _ deadlineMs: Int64, _ nonce: String, _ wire: JSONValue) -> String {
            let text = NetWire.stringify(.array([.string(sessionId), .int(Int64(party)), .int(Int64(tripleIndex)), .int(deadlineMs), .string(nonce), wire]), order: wireOrder)
            return NetCodec.hex(MpcHash.sha256([Array("atlas-pca-mpc/forensic-commit/v1\0".utf8), Array(text.utf8)]))
        }
    }
}
