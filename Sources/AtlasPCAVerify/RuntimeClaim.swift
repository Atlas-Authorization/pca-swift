import Foundation

/// Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class.
/// Valid only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
/// `verifiedEvidence`), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is
/// "none". Total.
public enum RuntimeClaim {
    public static let DOMAIN = "atlas-pca/runtime-class-claim/v1\u{0}"
    static let CLASSES = ["none", "os_confined", "egress_default_deny", "wasi_no_ambient"]
    static let KEYS = ["v", "class", "passport_digest", "evidence_digest", "iat", "exp", "attestor", "sig"]

    public static func verifiedClass(_ v: JSONValue?, pinnedAttestors: [String], passportDigest: String, verifiedEvidence: [String], now: JSONValue?) -> String {
        guard let c = v?.asObject, c.count == KEYS.count, KEYS.allSatisfy({ c[JKey($0)] != nil }),
              c[JKey("v")]?.safeInt == 1,
              let cls = c[JKey("class")]?.asString, CLASSES.contains(cls),
              let attestor = K3Sig.str(c[JKey("attestor")], 128), let pd = K3Sig.str(c[JKey("passport_digest")], 128),
              let ev = K3Sig.str(c[JKey("evidence_digest")], 128),
              let iat = K3Sig.safeInt(c[JKey("iat")]), let exp = K3Sig.safeInt(c[JKey("exp")]), let t = K3Sig.safeInt(now),
              pinnedAttestors.contains(where: { K3Sig.eq(attestor, $0) }), K3Sig.eq(pd, passportDigest),
              verifiedEvidence.contains(where: { K3Sig.eq(ev, $0) }), iat <= t, t < exp else { return "none" }
        var body = c
        body[JKey("sig")] = nil
        return K3Sig.verifyBody(DOMAIN, .object(body), signer: attestor, sig: c[JKey("sig")]) ? cls : "none"
    }
}
