import Foundation

extension PCASandbox {
    /// Run an existing hardware attestation verifier over the evidence; only if it says `ok` and `bound` is the evidence's digest admitted into
    /// the trust. Anything else (a refusal, not bound) leaves the list empty, so every claim is `none`. `evidence` is the vendor wire object the
    /// verifier reads (the attestation document carries it); the digest admitted is that of `document`. The result is the trust object
    /// `verifiedRuntimeClass` reads: `{pinnedAttestors, passportDigest, verifiedEvidenceDigests, now}`.
    public static func trustFromAttestation(document: JSONValue, evidence: JSONValue?, verifier: HardwareAttestationVerifier, expected: AttestationBinding, nowMs: Int64,
                                            pinnedAttestors: [String], passportDigest: String) throws -> JSONValue {
        let r = verifier.verify(evidence: evidence, expected: expected, nowMs: nowMs)
        let ok = r.ok && r.bound
        return .object([
            "pinnedAttestors": .array(pinnedAttestors.map { .string($0) }),
            "passportDigest": .string(passportDigest),
            "verifiedEvidenceDigests": .array(ok ? [.string(try evidenceDigest(document))] : []),
            "now": .int(nowMs),
        ])
    }
}
