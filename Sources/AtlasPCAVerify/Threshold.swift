import Foundation

/// Risk-adaptive threshold multi-signatures, mirroring `threshold.ts`. A t-of-n multi-signature is a bag
/// of `t` INDEPENDENT Ed25519 signatures, each by a distinct allowed role over the SAME canonical message
/// (`thresholdMessage(pcactn)`). Verification counts DISTINCT valid KEYS and accepts iff that count >= t.
///
/// These shares are server-side and not exercised by the CORE conformance verdicts (which stop at the
/// agent-leaf `sig`); they are implemented for full parity with `threshold.ts` and validated against the
/// `primitives.threshold_share` vectors.
enum Threshold {
    enum Role: String, CaseIterable { case agent, guardian, principal }

    struct Signer { let role: Role; let publicKey: String }
    struct Share { let role: Role; let publicKey: String; let sig: String }
    struct Verdict { let ok: Bool; let count: Int; let roles: [Role]; let reason: String? }

    static let SIGNER_SET_DOMAIN: [UInt8] = Canonical.utf8("atlas-pca/signerset/v1") + [0x00]

    static func isValidT(_ t: Int) -> Bool { t == 1 || t == 2 || t == 3 }

    /// sha256(DOMAIN ‖ canonical(sorted [{publicKey, role}])), sorted bytewise by (role, publicKey).
    static func signerSetHash(_ signerSet: [Signer]) -> [UInt8] {
        let rows = signerSet
            .map { (publicKey: $0.publicKey, role: $0.role.rawValue) }
            .sorted {
                let r = Canonical.compareUtf8($0.role, $1.role)
                return r != 0 ? r < 0 : Canonical.compareUtf8($0.publicKey, $1.publicKey) < 0
            }
            .map { JSONValue.object(["publicKey": .string($0.publicKey), "role": .string($0.role)]) }
        return Canonical.sha256(SIGNER_SET_DOMAIN + Canonical.utf8(Canonical.canonicalize(.array(rows))))
    }

    /// The bytes a guardian / principal SHARE signs:
    /// `"atlas-pca/share/<role>\0" ‖ sha256(thresholdMessage) ‖ signerSetHash ‖ t` (t = one byte, 1..3).
    static func shareMessage(_ role: Role, _ message: [UInt8], _ signerSet: [Signer], _ t: Int) -> [UInt8] {
        precondition(isValidT(t), "shareMessage: t must be 1, 2 or 3")
        return Canonical.utf8("atlas-pca/share/\(role.rawValue)") + [0x00]
            + Canonical.sha256(message) + signerSetHash(signerSet) + [UInt8(t)]
    }

    /// v2.1 agent-leaf share binding. Verify a SINGLE `primitives.threshold_share[]` entry, FAIL-CLOSED.
    /// RECOMPUTES the bound message from scratch (does NOT trust the stored `share_message` / `signer_set_hash`):
    ///   `"atlas-pca/share/<role>\0" ‖ sha256(thresholdMessage) ‖ signerSetHash(signer_set) ‖ t(1 byte)`
    /// and confirms `share.sig` verifies over it under `share.publicKey` (routed through the SAME suite seam
    /// as the leaf, so a PQ/hybrid share would use `share.pq_pk`/`share.pq_sig`). Returns `false` on any
    /// malformed input; never throws. The PRE-v2.1 bare agent share (a `sig` over the bare threshold message)
    /// and a cross-signer-set replay (a share bound to a DIFFERENT signer set) therefore BOTH fail — the clean
    /// break the v2.1 binding mandates. `entry` is a `primitives.threshold_share[]` object.
    static func verifyShare(_ entry: JSONValue) -> Bool {
        guard let o = entry.asObject,
              let role = o["role"]?.asString,
              let t = o["t"]?.safeInt, t >= 0, t <= 255,
              let setArr = o["signer_set"]?.asArray,
              let tmB64 = o["threshold_message"]?.asString,
              let tm = Base64URLStrict.decode(tmB64),
              let share = o["share"]?.asObject,
              let pk = share["publicKey"]?.asString else { return false }
        let signers = setArr.map { s -> Signer? in
            guard let r = s.get("role")?.asString, let rr = Role(rawValue: r),
                  let p = s.get("publicKey")?.asString else { return nil }
            return Signer(role: rr, publicKey: p)
        }
        guard !signers.contains(where: { $0 == nil }) else { return false }
        let ssh = signerSetHash(signers.compactMap { $0 })
        // Bound share message: domain(role) ‖ sha256(thresholdMessage) ‖ signerSetHash ‖ t.
        let msg = Canonical.utf8("atlas-pca/share/\(role)") + [0x00] + Canonical.sha256(tm) + ssh + [UInt8(t)]
        return PQ.verifyLeaf(alg: share["alg"]?.asString, holder: pk, pqPublicKey: share["pq_pk"]?.asString,
                             message: msg, sig: share["sig"]?.asString, pqSig: share["pq_sig"]?.asString)
    }

    /// Verify a t-of-n multi-signature over `message` (= `thresholdMessage(pcactn)`). Total; never throws.
    /// The signer set is validated first (each role exactly one key; no key under two roles); a share counts
    /// iff its role+key are registered and its signature verifies over that role's message; counts DISTINCT keys.
    static func verify(_ shares: [Share], _ message: [UInt8], _ signerSet: [Signer], _ t: Int) -> Verdict {
        func fail(_ r: String) -> Verdict { Verdict(ok: false, count: 0, roles: [], reason: r) }
        if !isValidT(t) { return fail("invalid threshold t=\(t) (must be 1, 2 or 3)") }

        var keyOfRole: [Role: String] = [:]
        var roleOfKey: [String: Role] = [:]
        for s in signerSet {
            if Base64URLStrict.decode(s.publicKey, length: 32) == nil { return fail("malformed signer set") }
            if let prev = keyOfRole[s.role], prev != s.publicKey {
                return fail("signer set registers more than one key for role \(s.role.rawValue)")
            }
            if let prev = roleOfKey[s.publicKey], prev != s.role {
                return fail("signer set registers one key under two roles")
            }
            keyOfRole[s.role] = s.publicKey
            roleOfKey[s.publicKey] = s.role
        }

        var validKeys = Set<String>()
        var validRoles: [Role] = []
        var reason: String?
        func note(_ r: String) { if reason == nil { reason = r } }

        for share in shares {
            if validKeys.contains(share.publicKey) { continue }
            guard let registered = keyOfRole[share.role] else {
                note("role \(share.role.rawValue) is not in the signer set"); continue
            }
            if share.publicKey != registered {
                note("share for role \(share.role.rawValue) uses a key not registered for that role"); continue
            }
            // v2.1 agent-leaf binding: EVERY role (agent included) signs the role/signerSetHash/t-bound
            // share message — the clean break from the pre-v2.1 bare-threshold-message agent share.
            let signed = shareMessage(share.role, message, signerSet, t)
            if !Ed25519Strict.verifyB64u(share.publicKey, signed, share.sig) {
                note("invalid signature for role \(share.role.rawValue)"); continue
            }
            validKeys.insert(share.publicKey)
            validRoles.append(share.role)
        }

        let count = validKeys.count
        if count >= t { return Verdict(ok: true, count: count, roles: validRoles, reason: nil) }
        return Verdict(ok: false, count: count, roles: validRoles,
                       reason: reason ?? "only \(count) distinct valid key(s), need \(t)")
    }
}
