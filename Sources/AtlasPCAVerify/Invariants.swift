import Foundation

/// The deterministic exports of the invariant harness: Ed25519 key pairs from seeds, the legal-chain builder (a signed,
/// attenuating delegation chain from a model), the risk "worsen" helper and the registry constants. The property generators and the
/// property runner of the reference rest on a property-testing library and are not reproduced here.
public enum PCAInvariants {
    public static let DEFAULT_SEED = 20260108
    public static let DEFAULT_NUM_RUNS = 1000

    /// The registered invariants, in run order.
    public static let INVARIANT_NAMES = ["attenuation-monotonicity", "risk-wellformed-and-monotone", "admission-soundness", "cumulative-budget-bound",
                                         "fail-closed:undecidable-leaf", "fail-closed:undecidable-groups", "fail-closed:member-of-cycle-safe", "fail-closed:unknown-caveat-type",
                                         "fail-closed:forged-chain-rejected", "fail-closed:garbage-chain-rejected", "forbid-monotone", "determinism"]

    /// A key pair derived from a 32-byte seed (any 32 bytes is a valid Ed25519 secret).
    public struct KeyPair {
        public let secretKey: [UInt8]
        public let publicKey: [UInt8]
        /// The base64url public key (the key id).
        public let pub: String
        public let key: PCAEdKey
    }

    /// The key of a seed; a seed that is not 32 bytes is refused. `keyFor` swaps the key constructor (a test seam: the platform
    /// signs with fresh randomness where the reference signs deterministically).
    public static func keyPairFromSeed(_ seed: [UInt8], keyFor: ([UInt8]) throws -> PCAEdKey = { try PCAEdKey(seed: $0) }) throws -> KeyPair {
        guard seed.count == 32 else { throw JSError("keyPairFromSeed: a seed is 32 bytes") }
        let k = try keyFor(seed)
        return KeyPair(secretKey: seed, publicKey: k.pub, pub: Base64URLStrict.encode(k.pub), key: k)
    }

    public struct Hop {
        public var holderSeed: [UInt8]
        public var addedSpecs: [JSONValue]
        public init(holderSeed: [UInt8], addedSpecs: [JSONValue]) { self.holderSeed = holderSeed; self.addedSpecs = addedSpecs }
    }

    /// {principal seed, first holder seed, root caveat specs, hops, predicates}.
    public struct ChainModel {
        public var principalSeed: [UInt8]
        public var holder0Seed: [UInt8]
        public var rootSpecs: [JSONValue]
        public var hops: [Hop]
        public var predicates: JSONValue
        public init(principalSeed: [UInt8], holder0Seed: [UInt8], rootSpecs: [JSONValue], hops: [Hop], predicates: JSONValue) {
            self.principalSeed = principalSeed; self.holder0Seed = holder0Seed; self.rootSpecs = rootSpecs; self.hops = hops; self.predicates = predicates
        }
    }

    /// The signed capabilities (root first), the predicates, the root issuer and each hop's holder.
    public struct Chain {
        public var caps: [JSONValue]
        public var predicates: JSONValue
        public var rootIssuer: String
        public var holders: [String]
    }

    static let BUDGET_ALLOC_BASE = 1_000_000.0

    /// One spec as a concrete caveat, threading the running budget allocation (monotone non-increasing, an integer).
    static func specToCaveat(_ spec: JSONValue, _ running: inout Double) throws -> JSONValue {
        func m(_ k: String) throws -> JSONValue {
            guard let v = spec.get(k) else { throw JSError("invariants: spec member '\(k)' is missing") }
            return v
        }
        switch spec.get("k")?.asString {
        case "expires": return .object(["type": .string("expires"), "at": try m("at")])
        case "not_before": return .object(["type": .string("not_before"), "at": try m("at")])
        case "rate": return .object(["type": .string("rate"), "max": try m("max"), "per_secs": try m("per_secs")])
        case "max_blast_radius": return .object(["type": .string("max_blast_radius"), "max": try m("max")])
        case "reversibility_max": return .object(["type": .string("reversibility_max"), "class": try m("cls")])
        case "delegation_depth": return .object(["type": .string("delegation_depth"), "max": try m("max")])
        case "budget_frac":
            let base = running.isFinite ? running : BUDGET_ALLOC_BASE
            guard let frac = IV.num(try m("frac")) else { throw JSError("invariants: budget_frac without a number") }
            // frac in [0,1] and base a non-negative integer: an integer <= the previous allocation (monotone, canonical-wire-safe)
            let limit = (base * frac).rounded(.down)
            guard limit.isFinite, abs(limit) <= Double(Canonical.MAX_SAFE) else { throw JSError("invariants: budget_frac out of range") }
            running = limit
            return .object(["type": .string("budget_alloc"), "limit": .int(Int64(limit))])
        default: throw JSError("invariants: unknown caveat spec")
        }
    }

    /// A signed, legally attenuating chain from a model (each hop is signed by the key the parent is bound to).
    public static func buildChain(_ m: ChainModel, keyFor: ([UInt8]) throws -> PCAEdKey = { try PCAEdKey(seed: $0) }) throws -> Chain {
        var running = Double.infinity
        let principal = try keyPairFromSeed(m.principalSeed, keyFor: keyFor)
        let holder0 = try keyPairFromSeed(m.holder0Seed, keyFor: keyFor)
        let rootCaveats = try m.rootSpecs.map { try specToCaveat($0, &running) }
        let root = try PCAIssue.mintRoot(principal: .ed25519(principal.key), holder: holder0.pub, caveats: rootCaveats)
        var caps = [root], holders = [holder0.pub]
        var prev = root, signer = holder0
        for hop in m.hops {
            let to = try keyPairFromSeed(hop.holderSeed, keyFor: keyFor)
            let added = try hop.addedSpecs.map { try specToCaveat($0, &running) }
            let cap = try PCAIssue.delegate(parent: prev, toHolder: to.pub, added: added, signer: .ed25519(signer.key))
            caps.append(cap); holders.append(to.pub)
            prev = cap; signer = to
        }
        return Chain(caps: caps, predicates: m.predicates, rootIssuer: principal.pub, holders: holders)
    }

    static func clamp01(_ x: Double) -> Double { x < 0 ? 0 : x > 1 ? 1 : x }

    static func number(_ d: Double) -> JSONValue {
        d == d.rounded() && abs(d) <= Double(Canonical.MAX_SAFE) ? .int(Int64(d)) : .double(d)
    }

    /// A risk input that is >= `base` in every risk-increasing axis and <= in every protective axis (all six clamped).
    public static func worsen(_ base: JSONValue, _ d: JSONValue) throws -> JSONValue {
        func v(_ o: JSONValue, _ k: String) throws -> Double {
            guard let x = IV.num(o.get(k)) else { throw JSError("invariants: \(k) is not a number") }
            return x
        }
        return .object([
            "semanticDistance": number(clamp01(try v(base, "semanticDistance") + v(d, "dSem"))),
            "blastRadius": number(clamp01(try v(base, "blastRadius") + v(d, "dBlast"))),
            "taint": number(clamp01(try v(base, "taint") + v(d, "dTaint"))),
            "age": number(clamp01(try v(base, "age") + v(d, "dAge"))),
            "reversibility": number(clamp01(try v(base, "reversibility") - v(d, "dRev"))),
            "confidence": number(clamp01(try v(base, "confidence") - v(d, "dConf"))),
        ])
    }
}
