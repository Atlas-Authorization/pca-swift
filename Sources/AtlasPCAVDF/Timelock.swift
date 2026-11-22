import Foundation
import BigInt
import AtlasPCAVerify

/// PCA timelock: a mandatory, offline-verifiable cooling-off on an irreversible action, enforced by a Wesolowski VDF. The VDF challenge `x` is bound to
/// the action AND to an unpredictable beacon that did not exist when the action was formed, so a proof shows `steps` sequential squarings ran on an input
/// that could not be computed earlier. This package does NOT check that the beacon is genuine or post-dates the action: the verifier must, and pass it in.
public enum PCATimelock {
    static let X_DERIVATION_DOMAIN = Array("atlas-pca/vdf/timelock/input/v2".utf8) + [0]

    public struct Requirement: Equatable {
        public var kind: String
        public var x: BigInt
        public var steps: Int
        public var N: BigInt
        public var actionDigest: String
    }

    public struct Proof: Equatable {
        public var kind: String?
        public var y: BigInt?
        public var pi: BigInt?
        /// The step count the proof claims, as a JavaScript number (nil = not a number).
        public var steps: Double?
        public init(kind: String? = "vdf-timelock-proof", y: BigInt?, pi: BigInt?, steps: Double?) { self.kind = kind; self.y = y; self.pi = pi; self.steps = steps }
    }

    public struct Options {
        /// The required step count (a JavaScript number; nil = absent).
        public var steps: Double?
        public var N: BigInt
        /// The beacon bytes (a text beacon is its UTF-8); nil or empty is refused.
        public var beacon: [UInt8]?
        /// DEV/TEST ONLY: a timelock on a modulus whose factors are known delays nobody who holds them.
        public var allowInsecureDevModulus: Bool
        public init(steps: Double?, N: BigInt, beacon: [UInt8]?, allowInsecureDevModulus: Bool = false) {
            self.steps = steps; self.N = N; self.beacon = beacon; self.allowInsecureDevModulus = allowInsecureDevModulus
        }
    }

    /// The digest a timelock binds to: a string is an opaque precomputed digest; any other value is a PCActn digested like the ledger
    /// (base64url sha256 of the strict canonical form; a value outside the strict profile throws).
    public static func actionDigest(_ action: JSONValue) throws -> String {
        if case let .string(s) = action { return s }
        return PCAWire.b64uEncode(PCAWire.sha256(Array(try PCAWire.canonicalStrict(action).utf8)))
    }

    private static func beaconBytes(_ b: [UInt8]?) throws -> [UInt8] {
        guard let b = b, !b.isEmpty else { throw PCAVdf.VdfError("timelock: a non-empty beacon (unpredictable, post-action value) is required") }
        return b
    }

    /// x in [2, N) bound to the action and the beacon; deterministic.
    public static func deriveTimelockInput(_ action: JSONValue, _ n: BigInt, beacon: [UInt8]?) throws -> BigInt {
        guard n > 3 else { throw PCAVdf.VdfError("deriveTimelockInput: modulus N must be a bigint > 3") }
        let digest = Array(try actionDigest(action).utf8)
        let msg = X_DERIVATION_DOMAIN + PCAVdf.lenPrefixed(digest) + PCAVdf.lenPrefixed(try beaconBytes(beacon))
        let raw = try PCAVdf.rem(PCAVdf.bytesToBigInt(PCAVdf.sha256(msg)), n)
        return raw <= 1 ? raw + 2 : raw
    }

    private static func requireProductionModulus(_ n: BigInt, _ allowInsecure: Bool) throws {
        if allowInsecure { return }
        let check = PCAVdf.checkProductionModulus(n)
        if !check.ok {
            throw PCAVdf.VdfError("timelock: refusing this modulus: \(check.reason ?? ""). Use RSA_2048_CHALLENGE_MODULUS or a ceremony modulus; tests may pass allowInsecureDevModulus: true.")
        }
    }

    private static func requireSteps(_ steps: Double?) throws -> Int {
        guard let d = steps, let s = PCAVdf.safeInt(d), s >= 1 else { throw PCAVdf.VdfError("timelock: steps must be a safe integer >= 1, got \(steps.map { String($0) } ?? "undefined")") }
        return s
    }

    /// The requirement for an action: derives x and records the step count, modulus and digest.
    public static func requireTimelock(_ action: JSONValue, _ o: Options) throws -> Requirement {
        let s = try requireSteps(o.steps)
        try requireProductionModulus(o.N, o.allowInsecureDevModulus)
        let x = try deriveTimelockInput(action, o.N, beacon: o.beacon)
        return Requirement(kind: "vdf-timelock", x: x, steps: s, N: o.N, actionDigest: try actionDigest(action))
    }

    /// Run the VDF: the squarings ARE the cooling-off, so this is deliberately slow.
    public static func proveTimelockElapsed(_ action: JSONValue, steps: Double?, N: BigInt, beacon: [UInt8]?, allowInsecureDevModulus: Bool = false) throws -> Proof {
        let s = try requireSteps(steps)
        try requireProductionModulus(N, allowInsecureDevModulus)
        let x = try deriveTimelockInput(action, N, beacon: beacon)
        let p = try PCAVdf.evalCanonical(x, Double(s), N)
        return Proof(kind: "vdf-timelock-proof", y: p.y, pi: p.pi, steps: Double(s))
    }

    /// Fail closed: any malformed input or refused modulus is false. Offline, no clock.
    public static func verifyTimelock(_ action: JSONValue, _ proof: Proof?, _ o: Options) -> Bool {
        do {
            let required = try requireSteps(o.steps)
            try requireProductionModulus(o.N, o.allowInsecureDevModulus)
            guard let p = proof, p.kind == "vdf-timelock-proof" else { return false }
            guard let claimed = p.steps, PCAVdf.safeInt(claimed) != nil, claimed == Double(required) else { return false }
            guard let y = p.y, let pi = p.pi else { return false }
            let x = try deriveTimelockInput(action, o.N, beacon: o.beacon)
            return PCAVdf.verifyCanonical(x, y, pi, Double(required), o.N)
        } catch {
            return false
        }
    }

    /// Operator helper: squarings measured here times a conservative adversary advantage, so the delay is a floor. `now` is in milliseconds.
    public static func calibrateSteps(N: BigInt, desiredSeconds: Double, sampleSquarings: Double = 50000, adversaryAdvantage: Double = 10,
                                      now: (() -> Double)? = nil) throws -> (steps: Double, measuredSquaringsPerSecond: Double, assumedAdversarySquaringsPerSecond: Double) {
        guard N > 3 else { throw PCAVdf.VdfError("calibrateSteps: modulus N must be a bigint > 3") }
        guard desiredSeconds.isFinite, desiredSeconds > 0 else { throw PCAVdf.VdfError("calibrateSteps: desiredSeconds must be > 0") }
        guard let samples = PCAVdf.safeInt(sampleSquarings), samples >= 1 else { throw PCAVdf.VdfError("calibrateSteps: sampleSquarings must be a safe integer >= 1") }
        guard adversaryAdvantage.isFinite, adversaryAdvantage >= 1 else { throw PCAVdf.VdfError("calibrateSteps: adversaryAdvantage must be >= 1") }
        let clock = now ?? { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000 }
        let m = N.magnitude
        var y = BigUInt(2) % m
        let t0 = clock()
        for _ in 0..<samples { y = (y * y) % m }
        let t1 = clock()
        // a non-finite reading gives NaN steps (or 1 step from an infinite elapsed time): never a floor
        guard t0.isFinite, t1.isFinite else { throw PCAVdf.VdfError("calibrateSteps: the clock must return finite times") }
        let elapsed = max(t1 - t0, 2.220446049250313e-16)
        let perS = Double(samples) / elapsed * 1000
        let adv = perS * adversaryAdvantage
        return (max(1, (adv * desiredSeconds).rounded(.up)), perS, adv)
    }
}
