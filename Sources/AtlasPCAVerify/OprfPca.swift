import Foundation

/// The PCA layer over PCAOprf (reference: @atlasauth/pca-oprf pca.ts): a private revocation check (the service never learns which capability
/// id is asked about) and private rate tokens (identifier hidden, window public). Identifiers are encoded as strict UTF-8 (a Swift String
/// is always well-formed, so the reference's unpaired-surrogate refusal cannot arise here).
public enum PCAOprfPca {
    public typealias O = PCAOprf
    public typealias BlindEvaluator = ([UInt8]) throws -> O.EvaluateResult
    public typealias RateBlindEvaluator = ([UInt8], String) throws -> O.EvaluateResult

    public struct RevocationSet {
        public let outputs: Set<String>
        public let mode: O.Mode
        public let publicKey: [UInt8]?
        public init(outputs: Set<String>, mode: O.Mode, publicKey: [UInt8]?) { self.outputs = outputs; self.mode = mode; self.publicKey = publicKey }
    }

    private static func baseOnly(_ m: O.Mode) throws { guard m != .poprf else { throw JSError("revocation mode must be oprf or voprf") } }

    public static func buildRevocationSet(secretKey: [UInt8], revokedCapIds: [String], mode: O.Mode = .oprf) throws -> RevocationSet {
        try baseOnly(mode)
        var outputs = Set<String>()
        for id in revokedCapIds { outputs.insert(O.toHex(try O.evaluate(secretKey: secretKey, input: Array(id.utf8), mode: mode))) }
        return try RevocationSet(outputs: outputs, mode: mode, publicKey: mode == .voprf ? O.publicKeyFor(secretKey) : nil)
    }

    public static func makeRevocationEvaluator(secretKey: [UInt8], mode: O.Mode = .oprf) throws -> BlindEvaluator {
        try baseOnly(mode)
        let pk = try mode == .voprf ? O.publicKeyFor(secretKey) : nil
        return { try O.blindEvaluate(secretKey: secretKey, blindedElement: $0, mode: mode, publicKey: pk) }
    }

    /// Is `capId` in the published set, learned obliviously? A VOPRF set verifies the service's DLEQ proof; a missing proof or key throws.
    public static func isRevokedPrivate(_ capId: String, blindEval: BlindEvaluator, revokedSet: RevocationSet) throws -> Bool {
        let input = Array(capId.utf8)
        let mode = revokedSet.mode
        try baseOnly(mode)
        let b = try O.blind(input: input, mode: mode)
        let res = try blindEval(b.blindedElement)
        let out: [UInt8]
        if mode == .voprf {
            guard let proof = res.proof, let pk = revokedSet.publicKey else { throw JSError("isRevokedPrivate(voprf): missing DLEQ proof or service public key") }
            out = try O.finalize(input: input, blind: b.blind, evaluatedElement: res.evaluatedElement, mode: .voprf, proof: proof, publicKey: pk,
                                 blindedElement: b.blindedElement)
        } else {
            out = try O.finalize(input: input, blind: b.blind, evaluatedElement: res.evaluatedElement, mode: .oprf)
        }
        return revokedSet.outputs.contains(O.toHex(out))
    }

    public static func rateToken(secretKey: [UInt8], identifier: String, window: String) throws -> [UInt8] {
        try O.evaluatePoprf(secretKey: secretKey, input: Array(identifier.utf8), info: Array(window.utf8))
    }

    public static func rateTokenHex(secretKey: [UInt8], identifier: String, window: String) throws -> String {
        O.toHex(try rateToken(secretKey: secretKey, identifier: identifier, window: window))
    }

    public static func makeRateEvaluator(secretKey: [UInt8]) -> RateBlindEvaluator {
        { try O.blindEvaluatePoprf(secretKey: secretKey, blindedElement: $0, info: Array($1.utf8)) }
    }

    /// The rate token for (identifier, window) without revealing the identifier; equals `rateToken` for the same key.
    public static func privateRateToken(_ identifier: String, _ window: String, blindEval: RateBlindEvaluator, publicKey: [UInt8]) throws -> [UInt8] {
        let input = Array(identifier.utf8), info = Array(window.utf8)
        let b = try O.blindPoprf(input: input, info: info, publicKey: publicKey)
        let res = try blindEval(b.blindedElement, window)
        guard let proof = res.proof else { throw JSError("privateRateToken: POPRF blind-evaluation did not return a DLEQ proof") }
        return try O.finalizePoprf(input: input, blind: b.blind, evaluatedElement: res.evaluatedElement, info: info, proof: proof,
                                   blindedElement: b.blindedElement, tweakedKey: b.tweakedKey)
    }

    /// In-memory per-token counter (not thread-safe; guard it externally or swap in a shared store for a fleet).
    public final class RateWindowCounter {
        private var counts: [String: Int] = [:]
        private let limit: Int

        public init(limit: Int) throws {
            guard limit >= 1 else { throw JSError("RateWindowCounter: limit must be a positive integer") }
            self.limit = limit
        }

        public func hit(_ token: [UInt8]) -> (count: Int, allowed: Bool) {
            let key = O.toHex(token)
            let c = (counts[key] ?? 0) + 1
            counts[key] = c
            return (c, c <= limit)
        }

        public func count(_ token: [UInt8]) -> Int { counts[O.toHex(token)] ?? 0 }
        public func reset() { counts.removeAll() }
    }
}
