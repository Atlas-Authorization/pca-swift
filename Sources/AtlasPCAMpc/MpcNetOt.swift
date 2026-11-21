import Foundation
import AtlasPCAVerify

/// The public surface of the OT stack for the networked driver (the AtlasPCAMpcNet target): per-party roles of the base OT and the OT extension with
/// their wire codecs, so the driver never re-implements an engine. Every message is the same canonical JSON the codec layer (`NetCodec`) defines.
extension PCAMpc {
    public enum NetOt {
        public static let KAPPA = Ot.KAPPA
        public static let SSEC = Ot.SSEC

        /// The session id of a mesh, hashed to the fixed length the base-OT bindings need.
        public static func sessionBytes(_ sessionId: String) -> [UInt8] {
            MpcHash.sha256([Array("atlas-pca-mpc/net-session/v2".utf8), Array(sessionId.utf8)])
        }

        /// A base-OT or KOS-check failure (a cheating party), as opposed to a malformed message.
        public static func isCheckFailure(_ e: Error) -> Bool { e is BaseOtAbort || e is MalOtAbort || e is PointValidationError }

        /// Who sends, who receives, in which round (indices are uint32).
        public struct Binding {
            public var sessionId: [UInt8]
            public var sender: Int
            public var receiver: Int
            public var round: String
            public init(sessionId: [UInt8], sender: Int, receiver: Int, round: String) { self.sessionId = sessionId; self.sender = sender; self.receiver = receiver; self.round = round }
            var raw: Ot.BaseOtBinding { Ot.BaseOtBinding(sessionId: sessionId, senderIndex: Int64(sender), receiverIndex: Int64(receiver), round: round) }
        }

        public static func bindingBytes(_ b: Binding) throws -> [UInt8] { try Ot.bindingBytes(b.raw) }

        private static func ptJSON(_ p: Ec.Point) -> JSONValue {
            let j = NetCodec.ptJ(p)
            return .object(["x": .string(j.x), "y": .string(j.y)])
        }

        private static func scalarOf(_ v: JSONValue?) throws -> Scalar {
            Dec.bytesLE(try NetCodec.hexBig(v).w, 32)
        }

        // MARK: base OT, sender side (the extension receiver)

        public final class BaseSender {
            private let setup: Ot.SenderSetup
            private let binding: Ot.BaseOtBinding
            private let rng = OtRandom.secure()

            public init(_ b: Binding) throws {
                binding = b.raw
                setup = try Ot.malBaseOtSenderSetup(rng, binding)
            }

            /// {S, U, z}; `lieProof` shifts the proof's response by one (test-only misbehaviour).
            public func message(lieProof: Bool = false) -> JSONValue {
                let z = lieProof ? Sodium.add(setup.proof.z, Sodium.one) : setup.proof.z
                return .object(["S": ptJSON(setup.S), "U": ptJSON(setup.proof.U), "z": .string(NetWire.hxBig(false, Dec.limbs(z)))])
            }

            /// The two pads per index from the receiver's `count` points.
            public func derive(_ r: JSONValue?, count: Int) throws -> [[[UInt8]]] {
                guard let arr = r?.mpcArray, arr.count == count else { throw MpcError("bad R array") }
                let pts = try arr.map { try NetCodec.jPt($0) }
                return try Ot.malBaseOtSenderDerive(setup.y, setup.T, pts, setup.S, binding)
            }
        }

        // MARK: base OT, receiver side (the extension sender)

        public final class BaseReceiver {
            public let recvPads: [[UInt8]]
            private let R: [Ec.Point]

            /// Validates the sender's {S, U, z} and answers for `choices`.
            public init(sMessage: JSONValue?, choices: [Int], _ b: Binding) throws {
                guard let o = sMessage?.mpcObject else { throw MpcError("bad S message") }
                let proof = Ec.SchnorrProof(U: try NetCodec.jPt(o["U"]), z: try NetOt.scalarOf(o["z"]))
                let S = try NetCodec.jPt(o["S"])
                let res = try Ot.malBaseOtReceiverRespond(S, proof, choices, OtRandom.secure(), b.raw)
                R = res.R
                recvPads = res.recvPads
            }

            public var message: JSONValue { .array(R.map { NetOt.ptJSON($0) }) }
        }

        /// One-time-pads the seed pairs under the sender pads and commits to them: (ct, com).
        public static func encrypt(_ messages: [[[UInt8]]], _ pads: [[[UInt8]]]) throws -> (ct: [[[UInt8]]], com: [[[UInt8]]]) { try Ot.baseOtSenderEncrypt(messages, pads) }

        public static func decrypt(_ choices: [Int], _ recvPads: [[UInt8]], _ ct: [[[UInt8]]], _ com: [[[UInt8]]]) throws -> [[UInt8]] {
            try Ot.baseOtReceiverDecrypt(choices, recvPads, ct, com)
        }

        // MARK: OT extension

        /// The receiver's per-round state between `begin` and `finish`.
        public final class Pending { fileprivate let raw: Ot.ExtPending; fileprivate init(_ r: Ot.ExtPending) { raw = r } }

        public final class ExtReceiver {
            private let r: Ot.OtExtReceiver
            public init(bindingBytes: [UInt8]) throws { r = try Ot.OtExtReceiver(OtRandom.secure(), bindingBytes) }

            public func makeSeeds() -> [[[UInt8]]] { r.makeSeeds() }

            /// TEST-ONLY: flip the first bit of the first `columns` columns of every u matrix (an inconsistent extension).
            public func tamperFirstColumns(_ columns: Int) {
                r.tamperU = { u, _ in for i in 0..<min(columns, u.count) { u[i].flipBit(0) } }
            }

            /// The wire message {u, x, t} of one round of `choices.count` rows, and the state to finish it with.
            public func begin(_ choices: [Int]) throws -> (message: JSONValue, pending: Pending) {
                let b = try r.begin(choices)
                let mExt = choices.count + Ot.KAPPA + Ot.SSEC
                let cb = (mExt + 7) / 8
                var bytes: [UInt8] = []
                for c in b.msg.u { bytes += Dec.bytesLE(c.mag, cb) }
                let msg: JSONValue = .object(["u": .string(NetCodec.b64(bytes)), "x": .string(NetOt.gfHex(b.msg.x)), "t": .string(NetOt.gfHex(b.msg.tComb))])
                return (msg, Pending(b.pending))
            }

            public func finish(_ p: Pending, _ y0: [UInt64], _ y1: [UInt64]) throws -> [UInt64] { try r.finish(p.raw, y0, y1) }
        }

        public final class ExtSender {
            private let s: Ot.OtExtSender
            public init(bindingBytes: [UInt8]) throws { s = try Ot.OtExtSender(OtRandom.secure(), bindingBytes) }
            public func makeSelector() -> [Int] { s.makeSelector() }
            public func setSeeds(_ seeds: [[UInt8]]) throws { try s.setSeeds(seeds) }

            /// Checks the receiver's {u, x, t} of a round with `m0.count` rows (the KOS check) and returns the ciphertexts.
            public func respond(_ message: JSONValue?, _ m0: [UInt64], _ m1: [UInt64]) throws -> (y0: [UInt64], y1: [UInt64]) {
                let m = m0.count
                let mExt = m + Ot.KAPPA + Ot.SSEC
                guard let o = message?.mpcObject else { throw MpcError("bad extension message") }
                let cb = (mExt + 7) / 8
                let bytes = try NetCodec.unb64(o["u"], Ot.KAPPA * cb)
                var u: [BigN] = []
                for i in 0..<Ot.KAPPA { u.append(BigN(bytesLE: Array(bytes[(i * cb)..<((i + 1) * cb)]))) }
                let msg = Ot.ExtRoundMsg(u: u, x: try NetOt.gfParse(o["x"]), tComb: try NetOt.gfParse(o["t"]))
                return try s.respond(msg, m0, m1)
            }
        }

        // MARK: GF(2^128) hex (canonical lowercase, no leading zeros, at most 32 digits)

        fileprivate static func gfHex(_ g: Gf128) -> String { NetWire.hxBig(false, [g.lo, g.hi]) }

        fileprivate static func gfParse(_ v: JSONValue?) throws -> Gf128 {
            guard let s = v?.mpcString, NetWire.canonicalHex(s, 32) else { throw MpcError("bad 128-bit value") }
            var hi: UInt64 = 0, lo: UInt64 = 0
            for (k, ch) in s.utf8.reversed().enumerated() {
                let d = UInt64(ch <= 57 ? ch - 48 : ch - 87)
                if k < 16 { lo |= d << UInt64(4 * k) } else { hi |= d << UInt64(4 * (k - 16)) }
            }
            return Gf128(hi: hi, lo: lo)
        }
    }
}
