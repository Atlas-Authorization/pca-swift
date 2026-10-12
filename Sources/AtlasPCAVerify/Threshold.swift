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

    struct Signer { let role: Role; let publicKey: String; var pqPk: String? = nil }
    struct Share { let role: Role; let publicKey: String; let sig: String }
    struct Verdict { let ok: Bool; let count: Int; let roles: [Role]; let reason: String? }

    static let SIGNER_SET_DOMAIN: [UInt8] = Canonical.utf8("atlas-pca/signerset/v1") + [0x00]

    static func isValidT(_ t: Int) -> Bool { t == 1 || t == 2 || t == 3 }

    /// sha256(DOMAIN ‖ canonical(sorted [{publicKey, role}])), sorted bytewise by (role, publicKey).
    static func signerSetHash(_ signerSet: [Signer]) -> [UInt8] {
        let rows = signerSet
            .map { (publicKey: $0.publicKey, role: $0.role.rawValue, pqPk: $0.pqPk) }
            .sorted {
                let r = Canonical.compareUtf8($0.role, $1.role)
                return r != 0 ? r < 0 : Canonical.compareUtf8($0.publicKey, $1.publicKey) < 0
            }
            .map { r -> JSONValue in
                var row: JObject = ["publicKey": .string(r.publicKey), "role": .string(r.role)]
                if let q = r.pqPk { row["pq_pk"] = .string(q) } // additive: a registered PQ key is part of the bound set
                return JSONValue.object(row)
            }
        return Canonical.sha256(SIGNER_SET_DOMAIN + Canonical.utf8(Canonical.canonicalize(.array(rows))))
    }

    /// The bytes a guardian / principal SHARE signs:
    /// `"atlas-pca/share/<role>\0" ‖ sha256(thresholdMessage) ‖ signerSetHash ‖ t` (t = one byte, 1..3).
    static func shareMessage(_ role: Role, _ message: [UInt8], _ signerSet: [Signer], _ t: Int, alg: String? = nil) -> [UInt8] {
        precondition(isValidT(t), "shareMessage: t must be 1, 2 or 3")
        var out: [UInt8] = Canonical.utf8("atlas-pca/share/\(role.rawValue)")
        out.append(0x00)
        out += Canonical.sha256(message)
        out += signerSetHash(signerSet)
        out.append(UInt8(t))
        out += shareSuiteTag(alg)
        return out
    }

    static let SHARE_SUITE_TAG = "\u{0}atlas-pca/share-suite/v1\u{0}"

    /// Empty for ed25519 / absent / unknown, else `SHARE_SUITE_TAG || suite.alg`.
    static func shareSuiteTag(_ alg: String?) -> [UInt8] {
        guard let s = PQ.resolve(alg), s.alg != .ed25519 else { return [] }
        return Canonical.utf8(SHARE_SUITE_TAG + s.alg.rawValue)
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
              let t = o["t"]?.safeInt, isValidT(Int(t)), // R6-04: t is exactly 1, 2 or 3 (was 0..255)
              let setArr = o["signer_set"]?.asArray,
              let tmB64 = o["threshold_message"]?.asString,
              let tm = Base64URLStrict.decode(tmB64),
              let share = o["share"]?.asObject,
              let pk = share["publicKey"]?.asString else { return false }
        // R6-03: the WHOLE signer set is validated like the reference before the share is looked at.
        guard let registry = validatedRegistry(setArr) else { return false }
        guard let ssh = signerSetHashJSON(setArr) else { return false }
        // share.role is required and must name the verified role (reference: a share without a string role is malformed).
        guard share["role"]?.asString == role, let roleEnum = Role(rawValue: role) else { return false }
        // R5-A1: the share must be for the ONE key the verifier's signer set registers for `role`; the share's
        // own publicKey / pq_pk never vouch for themselves.
        guard let reg = registry[roleEnum], reg.publicKey == pk else { return false }
        let algStr = share["alg"]?.asString
        if share["alg"] != nil && algStr == nil { return false }
        var pqPk = share["pq_pk"]?.asString
        // A share that NAMES a pq_pk must name exactly its role's registered one (any suite; a role registering none has
        // nothing it could equal). The key used is always the registered one.
        if share["pq_pk"] != nil && (reg.pqPk == nil || pqPk != reg.pqPk) { return false }
        var tag: [UInt8] = []
        if let suite = PQ.resolve(algStr), suite.alg == .ed25519 {
            // R6-02: a role that registers a pq_pk REQUIRES a PQ (pure or hybrid) share.
            if reg.pqPk != nil { return false }
        } else {
            // PQ key = the signer set's registered pq_pk, never the share's own.
            guard let rq = reg.pqPk else { return false }
            pqPk = rq
            tag = shareSuiteTag(algStr)
        }
        // Bound share message: domain(role) ‖ sha256(thresholdMessage) ‖ signerSetHash ‖ t [‖ suite tag].
        var msg: [UInt8] = Canonical.utf8("atlas-pca/share/\(role)")
        msg.append(0x00)
        msg += Canonical.sha256(tm)
        msg += ssh
        msg.append(UInt8(t))
        msg += tag
        return PQ.verifyLeaf(alg: algStr, holder: pk, pqPublicKey: pqPk,
                             message: msg, sig: share["sig"]?.asString, pqSig: share["pq_sig"]?.asString)
    }

    /// Registered PQ public-key lengths of every suite (ml-dsa-65/87, slh-dsa-128f/256s, fn-dsa-512/1024, less-cat1).
    static let PQ_PK_LENGTHS: Set<Int> = [1952, 2592, 32, 64, 897, 1793, 97484]

    /// R6-03: the reference's signer-set validation (decideThreshold BuildReg). Every entry is an object with a known role
    /// (case-sensitive) and a canonical 32-byte publicKey; a PRESENT pq_pk (JSON null is present) is canonical base64url of a
    /// registered PQ key length; one key per role; one role per key; a duplicate (role, key) only with the same pq_pk.
    /// Returns role -> registered signer, or nil when the set is malformed.
    static func validatedRegistry(_ setArr: [JSONValue]) -> [Role: Signer]? {
        var reg: [Role: Signer] = [:]
        for e in setArr {
            guard let o = e.asObject else { return nil }
            guard let r = o["role"]?.asString, let role = Role(rawValue: r) else { return nil }
            guard let pk = o["publicKey"]?.asString, Base64URLStrict.decode(pk, length: 32) != nil else { return nil }
            var pq: String? = nil
            if let pv = o["pq_pk"] {
                guard let ps = pv.asString, let pb = Base64URLStrict.decode(ps), PQ_PK_LENGTHS.contains(pb.count) else { return nil }
                pq = ps
            }
            if let prev = reg[role] {
                if !sameBytes(prev.publicKey, pk) { return nil }   // two keys for one role
                if !sameOptionalBytes(prev.pqPk, pq) { return nil } // duplicate (role, key) with a conflicting pq_pk
                continue
            }
            for (_, other) in reg where sameBytes(other.publicKey, pk) { return nil } // one key under two roles
            reg[role] = Signer(role: role, publicKey: pk, pqPk: pq)
        }
        return reg
    }

    /// Byte (not canonical-equivalence) string equality.
    static func sameBytes(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }
    static func sameOptionalBytes(_ a: String?, _ b: String?) -> Bool {
        if let x = a, let y = b { return sameBytes(x, y) }
        return a == nil && b == nil
    }

    /// The signer-set hash over RAW JSON entries (the reference hashes whatever role / publicKey strings it is given):
    /// rows `{publicKey, role[, pq_pk]}` sorted by the UTF-8 BYTES of (role, publicKey), `pq_pk` carried whenever it is a
    /// string (including ""). nil on a non-object entry or a non-string role / publicKey.
    static func signerSetHashJSON(_ setArr: [JSONValue]) -> [UInt8]? {
        var rows: [(role: String, publicKey: String, pqPk: String?)] = []
        for e in setArr {
            guard let o = e.asObject, let r = o["role"]?.asString, let p = o["publicKey"]?.asString else { return nil }
            rows.append((role: r, publicKey: p, pqPk: o["pq_pk"]?.asString))
        }
        rows.sort { a, b in
            let c = Canonical.compareUtf8(a.role, b.role)
            if c != 0 { return c < 0 }
            return Canonical.compareUtf8(a.publicKey, b.publicKey) < 0
        }
        var out: [JSONValue] = []
        for r in rows {
            var row: JObject = ["publicKey": .string(r.publicKey), "role": .string(r.role)]
            if let q = r.pqPk { row["pq_pk"] = .string(q) }
            out.append(.object(row))
        }
        return Canonical.sha256(SIGNER_SET_DOMAIN + Canonical.utf8(Canonical.canonicalize(.array(out))))
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
            if let q = s.pqPk {
                guard let qb = Base64URLStrict.decode(q), PQ_PK_LENGTHS.contains(qb.count) else { return fail("malformed signer set (pq_pk)") }
            }
            // R6-03: a duplicate (role, key) entry must register the same pq_pk (or none on both).
            if let prev = keyOfRole[s.role], sameBytes(prev, s.publicKey),
               let first = signerSet.first(where: { $0.role == s.role }), !sameOptionalBytes(first.pqPk, s.pqPk) {
                return fail("malformed signer set (pq_pk)")
            }
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
            // R6-02: this path verifies Ed25519 shares only; a role that registers a pq_pk REQUIRES a PQ (pure or
            // hybrid) share, so an Ed25519 share never satisfies it (fail-closed; use `verifyShare` for PQ shares).
            if signerSet.contains(where: { $0.role == share.role && $0.pqPk != nil }) {
                note("invalid signature for role \(share.role.rawValue)"); continue
            }
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
