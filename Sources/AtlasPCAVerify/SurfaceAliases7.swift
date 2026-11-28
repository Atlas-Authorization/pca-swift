import Foundation
import CryptoKit

/// What a guarded dispatch receives so it can carry the proof to the resource server: the PCActn, its wire form, ready-to-spread headers and the
/// provenance bundle (the reference's `PcaCall`).
public typealias PcaCall = PCAActResult

extension PCAAdapters {
    /// Provenance by default: wrap a model call that takes `{messages}` (`messages.create`) so every turn first records the conversation's new messages in the
    /// agent's provenance chain (user text is the principal; `tool_result` blocks are untrusted).
    public static func withPCAMessages<R>(_ agent: PCAFacadeAgent?, _ create: @escaping (JSONValue) throws -> R) -> (JSONValue) throws -> R {
        { params in
            if let rec = agent?.provenance, let ms = params.get("messages")?.asArray { try recordMessages(rec, ms) }
            return try create(params)
        }
    }

    /// The OpenAI spelling of `withPCAMessages` (`chat.completions.create`).
    public static func withPCACompletions<R>(_ agent: PCAFacadeAgent?, _ create: @escaping (JSONValue) throws -> R) -> (JSONValue) throws -> R { withPCAMessages(agent, create) }
}

extension PCADoctor {
    /// Decides a payment of `amount` USD under a root grant carrying `rootCaveat` (a REAL envelope grant: the caveat is appended outside the envelope, the task
    /// hop delegates to a fresh agent key): the native counterpart of probing a loaded module (the reference's `probeDecision`).
    public static func probeDecision(_ rootCaveat: JObject, _ amount: Double, now: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) throws -> (allowed: Bool, reasons: [String]) {
        let principal = try PCAEdKey.generate()
        let pPub = principal.id
        let envelope: JObject = ["predicates": .array([.object(["verb": .string("pay"), "resource": .string("invoice:*")])]),
                                 "caveats": .array([.object(["type": .string("expires"), "at": .int(now + 3_600_000)])]),
                                 "agent_binding": .object([:]), "risk_policy": .object(PCAFacade.DEFAULT_RISK_POLICY)]
        let g0 = try PCAIssue.mintGrant(principal: .ed25519(principal), holder: pPub, envelope: envelope, goal: "pca-doctor root caveat probe")
        let grant = try PCAIssue.mintRoot(principal: .ed25519(principal), holder: pPub, caveats: (g0.grant.get("caveats")?.asArray ?? []) + [.object(rootCaveat)])
        let task = try PCAIssue.delegate(parent: grant, toHolder: try PCAEdKey.generate().id, added: [], signer: .ed25519(principal))
        let amountV: JSONValue = amount.rounded() == amount && abs(amount) < 9_007_199_254_740_992 ? .int(Int64(amount)) : .double(amount)
        let d = try PCAPolicyVm.decide(.object([
            "grant": grant, "chain": .array([grant, task]),
            "action": .object(["action": .object(["verb": .string("pay"), "resource": .string("invoice:42"), "params": .object(["amount": amountV, "currency": .string("usd")]),
                                                   "reversibility_class": .string("reversible")])]),
            "risk": .object(["reversibility": .int(1), "blastRadius": .int(0), "confidence": .int(1), "semanticDistance": .int(0), "taint": .int(0)]),
            "budget": .object(["B": .int(1_000_000_000), "tau": .int(now), "asOf": .int(now)]), "now": .int(now),
        ]))
        return (d.get("releaseGuardianShare") == .bool(true), (d.get("reasons")?.asArray ?? []).map { JS.toString($0) })
    }

    /// A loader for `checkRootCaveats` that probes this very library: its own version and `probeDecision`.
    public static func nativeLoader(version: String, path: String = "native") -> (String?) throws -> LoadedPca {
        { _ in LoadedPca(version: version, path: path, probe: { caveat, amount in try probeDecision(caveat, amount) }) }
    }
}

extension PCAAttestEat {
    /// An EAT signing key pair: the signer for `buildEAT` and the key `verifyEAT` checks with.
    public struct EatKeyPair {
        public let alg: String
        public let verifyKey: Jose.Key
        private let signInput: ([UInt8]) throws -> [UInt8]
        init(alg: String, verifyKey: Jose.Key, sign: @escaping ([UInt8]) throws -> [UInt8]) { self.alg = alg; self.verifyKey = verifyKey; self.signInput = sign }
        /// The `sign` argument of `buildEAT`; it throws when asked for another algorithm than this key's.
        public func sign(_ alg: String, _ input: [UInt8]) throws -> [UInt8] {
            guard alg == self.alg else { throw JSError("EAT key does not fit alg '\(alg)'") }
            return try signInput(input)
        }
    }

    /// Generate an EAT signing key pair for `alg` (`EdDSA` -> Ed25519, `ES256` -> EC P-256, the signature raw r || s).
    public static func generateEatKeyPair(_ alg: String = DEFAULT_EAT_ALG) throws -> EatKeyPair {
        switch alg {
        case "EdDSA":
            let k = try PCAEdKey.generate()
            return EatKeyPair(alg: alg, verifyKey: .ed25519(k.pub), sign: { try k.sign($0) })
        case "ES256":
            let k = P256.Signing.PrivateKey()
            return EatKeyPair(alg: alg, verifyKey: .ec(curve: "P-256", point: Array(k.publicKey.x963Representation)), sign: { Array(try k.signature(for: Data($0)).rawRepresentation) })
        default: throw JSError("generateEatKeyPair: unsupported alg '\(alg)'")
        }
    }
}
