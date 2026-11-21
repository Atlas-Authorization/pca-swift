import Foundation

/// A bounded set of nonces already seen: `claim(key)` is false when the key was seen or the window is full.
public final class PCAFheNonceGuard {
    private var seen = Set<String>()
    private let maxEntries: Int
    public init(maxEntries: Int = 100_000) { self.maxEntries = maxEntries }
    public func claim(_ key: String) -> Bool {
        if seen.contains(key) || seen.count >= maxEntries { return false }
        seen.insert(key)
        return true
    }
}

/// Origin authentication of an encrypted risk claim (scheme-independent): the encryptor signs the ciphertext, the binding to one action, the
/// gate policy, a context and a one-time nonce; the verifier checks the signature, the context, the binding, the policy and a replay guard
/// BEFORE spending any evaluator work; the key holder signs the verdict over the exact claim and gate output it opened. A claim and an
/// attestation are parsed JSON objects (`JSONValue`).
public enum PCAFheOrigin {
    private static let claimDomain = "atlas-pca-fhe/signed-claim/v1\0"
    private static let verdictDomain = "atlas-pca-fhe/verdict-attestation/v1\0"
    private static let nonceBytes = 16
    private static let maxContextLen = 512

    private static func bytesDigest(_ s: String) -> String { Base64URLStrict.encode(Canonical.sha256(Array(s.utf8))) }

    /// base64url(sha256(strict canonical(v))): Pca.hashCanonical of the reference.
    private static func strictDigest(_ v: JSONValue) throws -> String { Base64URLStrict.encode(Canonical.sha256(try Canonical.canonicalBytes(v))) }

    private static func prefixed(_ domain: String, _ body: JSONValue) throws -> [UInt8] { Array(domain.utf8) + (try Canonical.canonicalBytes(body)) }

    private static func str(_ v: JSONValue?, _ what: String) throws -> String {
        guard let s = v?.asString else { throw PCAProducerError("\(what) must be a string") }
        return s
    }

    private static func claimStatement(_ claim: JSONValue, _ context: String, _ nonce: String, _ signer: String) throws -> [UInt8] {
        try prefixed(claimDomain, .object([
            "v": .int(1), "context": .string(context), "nonce": .string(nonce), "signer": .string(signer),
            "binding": claim.get("binding") ?? .null,
            "policy": .string(try strictDigest(claim.get("policy") ?? .null)),
            "enc_inputs": .string(bytesDigest(try str(claim.get("encInputs"), "encInputs"))),
        ]))
    }

    /// The content digest of a signed claim (what the key holder's attestation commits to).
    public static func signedClaimDigest(_ signed: JSONValue) throws -> String { try strictDigest(signed) }

    /// Signs an encrypted risk claim; a fresh random one-time nonce unless one is supplied (tests and replay of recorded vectors).
    public static func signRiskClaim(_ claim: JSONValue, key: PCAEdKey, context: String, nonce: [UInt8]? = nil) throws -> JSONValue {
        if context.isEmpty || context.utf16.count > maxContextLen { throw PCAProducerError("context must be a non-empty string of at most \(maxContextLen) characters") }
        let n = nonce ?? (0..<nonceBytes).map { _ in UInt8.random(in: 0...255) }
        if n.allSatisfy({ $0 == 0 }) { throw PCAProducerError("signRiskClaim: random source returned all zeros (RNG failure)") }
        let nonceS = Base64URLStrict.encode(n)
        let signer = key.id
        return .object([
            "claim": claim, "context": .string(context), "nonce": .string(nonceS), "signer": .string(signer),
            "sig": .string(Base64URLStrict.encode(try key.sign(try claimStatement(claim, context, nonceS, signer)))),
        ])
    }

    /// What the verifier expects: trusted encryptor keys, the grant context, the action binding, the gate policy and the replay guard.
    public struct ClaimExpectations {
        public var trustedSigners: [String], context: String, binding: JSONValue, policy: JSONValue, nonces: PCAFheNonceGuard
        public init(trustedSigners: [String], context: String, binding: JSONValue, policy: JSONValue, nonces: PCAFheNonceGuard) {
            self.trustedSigners = trustedSigners; self.context = context; self.binding = binding; self.policy = policy; self.nonces = nonces
        }
    }

    /// ok with the claim and its digest, or not ok with a reason.
    public struct ClaimCheck: Equatable {
        public let ok: Bool, claim: JSONValue?, digest: String?, reason: String?
    }

    private static func fail(_ r: String) -> ClaimCheck { ClaimCheck(ok: false, claim: nil, digest: nil, reason: r) }

    private static func isObjectOrArray(_ v: JSONValue?) -> Bool { (v?.isObject ?? false) || (v?.isArray ?? false) }

    /// Verifies a signed claim; never throws (a malformed or hostile input is a not-ok result).
    public static func verifySignedRiskClaim(_ s: JSONValue, _ exp: ClaimExpectations) -> ClaimCheck {
        guard s.isObject, let claim = s.get("claim"), claim.isObject, let context = s.get("context")?.asString, let nonce = s.get("nonce")?.asString,
              let signer = s.get("signer")?.asString, let sig = s.get("sig")?.asString, claim.get("encInputs")?.asString != nil,
              isObjectOrArray(claim.get("binding")), isObjectOrArray(claim.get("policy")) else { return fail("claim is not signed: malformed envelope") }
        do {
            if Base64URLStrict.decode(nonce, length: nonceBytes) == nil { return fail("malformed nonce") }
            if Base64URLStrict.decode(signer, length: 32) == nil || Base64URLStrict.decode(sig, length: 64) == nil { return fail("malformed signer key or signature") }
            if !exp.trustedSigners.contains(where: { Array($0.utf8) == Array(signer.utf8) }) { return fail("signer is not a trusted encryptor") }
            if !Ed25519Strict.verifyB64u(signer, try claimStatement(claim, context, nonce, signer), sig) {
                return fail("signature does not verify (ciphertext, binding, policy, context or nonce was altered, or wrong signer)")
            }
            if Array(context.utf8) != Array(exp.context.utf8) { return fail("context mismatch: claim was signed for a different grant/policy") }
            if try strictDigest(claim.get("binding") ?? .null) != strictDigest(exp.binding) { return fail("binding mismatch: claim is bound to a different action") }
            if try strictDigest(claim.get("policy") ?? .null) != strictDigest(exp.policy) { return fail("policy mismatch: claim was signed for a different gate policy") }
            if !exp.nonces.claim("\(signer):\(nonce)") { return fail("replay: nonce already used (or the replay window is full)") }
            return ClaimCheck(ok: true, claim: claim, digest: try signedClaimDigest(s), reason: nil)
        } catch {
            return fail("claim could not be verified (malformed)")
        }
    }

    private static func verdictStatement(_ claimDigest: String, _ gateDigest: JSONValue, _ admit: Bool, _ holder: String) throws -> [UInt8] {
        try prefixed(verdictDomain, .object(["v": .int(1), "claim": .string(claimDigest), "gate": gateDigest, "admit": .bool(admit), "holder": .string(holder)]))
    }

    /// The key holder's signed attestation of the verdict it opened, bound to the exact claim and gate output.
    public static func attestVerdict(key: PCAEdKey, signed: JSONValue, gate: JSONValue, admit: Bool) throws -> JSONValue {
        let gateDigest: JSONValue = .object([
            "encRiskRaw": .string(bytesDigest(try str(gate.get("encRiskRaw"), "encRiskRaw"))),
            "encSlack": .string(bytesDigest(try str(gate.get("encSlack"), "encSlack"))),
        ])
        let claimDigest = try signedClaimDigest(signed)
        let holder = key.id
        return .object([
            "claimDigest": .string(claimDigest), "gateDigest": gateDigest, "admit": .bool(admit), "holder": .string(holder),
            "sig": .string(Base64URLStrict.encode(try key.sign(try verdictStatement(claimDigest, gateDigest, admit, holder)))),
        ])
    }

    /// ok with the attested admit bit, or not ok with a reason.
    public struct AttestationCheck: Equatable {
        public let ok: Bool, admit: Bool, reason: String?
    }

    private static func afail(_ r: String) -> AttestationCheck { AttestationCheck(ok: false, admit: false, reason: r) }

    /// Verifies an attestation: trusted holder, signature, the expected claim digest and (when given) the expected gate output.
    public static func verifyVerdictAttestation(_ a: JSONValue, trustedHolders: [String], claimDigest: String, gate: JSONValue?) -> AttestationCheck {
        guard a.isObject, let cd = a.get("claimDigest")?.asString, let holder = a.get("holder")?.asString, let sig = a.get("sig")?.asString,
              case .bool(let admit)? = a.get("admit"), let gd = a.get("gateDigest"), gd.isObject,
              let raw = gd.get("encRiskRaw")?.asString, let slack = gd.get("encSlack")?.asString else { return afail("malformed attestation") }
        if !trustedHolders.contains(where: { Array($0.utf8) == Array(holder.utf8) }) { return afail("attestation holder is not trusted") }
        if Base64URLStrict.decode(holder, length: 32) == nil || Base64URLStrict.decode(sig, length: 64) == nil { return afail("malformed holder key or signature") }
        do {
            if !Ed25519Strict.verifyB64u(holder, try verdictStatement(cd, gd, admit, holder), sig) { return afail("attestation signature does not verify") }
            if Array(cd.utf8) != Array(claimDigest.utf8) { return afail("attestation is for a different claim") }
            if let g = gate {
                guard let gr = g.get("encRiskRaw")?.asString, let gs = g.get("encSlack")?.asString,
                      Array(raw.utf8) == Array(bytesDigest(gr).utf8), Array(slack.utf8) == Array(bytesDigest(gs).utf8) else { return afail("attestation is for a different gate output") }
            }
            return AttestationCheck(ok: true, admit: admit, reason: nil)
        } catch {
            return afail("attestation could not be verified (malformed)")
        }
    }
}
