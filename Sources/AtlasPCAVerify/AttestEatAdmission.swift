import Foundation

// EAT evidence for blueprint admission, the running-image digest of an accepted EAT, and the artifact attestation verifier that
// joins Sigstore build provenance to that digest and issues a discharge (the reference's `admission` and `provenance`). The Sigstore
// bundle check is Sigstore.swift, the provenance gate is ProvenanceGate.swift, the discharge signature is Issue.swift.

extension PCAAttestEat {
    /// RFC 7638 thumbprint (base64url SHA-256) of an Ed25519 public key given as unpadded base64url. The reference interpolates the
    /// value into the canonical member text as is, so a non-string is its JavaScript string form.
    public static func ed25519Jkt(_ holderPub: JSONValue?) -> String {
        let canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"\(JS.toString(holderPub))\"}"
        return Base64URLStrict.encode(Canonical.sha256(Array(canonical.utf8)))
    }

    static let TIER_RANK: [String: Int] = ["rejected": 0, "contraindicated": 0, "warning": 1, "affirming": 2, "affirming-hw-rooted": 3]

    static func admissionNo(_ bound: Bool, _ reason: String) -> JSONValue {
        .object(["ok": .bool(false), "bound": .bool(bound), "reason": .string(reason)])
    }

    /// Admission evidence for one instance key: the token's signature, issuer, freshness (the server-issued `nonce`) and RATS
    /// appraisal must pass, and its `cnf.jkt` must be the thumbprint of `instanceKey` (an unpadded base64url Ed25519 public key).
    /// `minTier` is `affirming` (default) or `affirming-hw-rooted`; anything else is refused before verification. The identity
    /// returned is the measured identity the verifier established. `o` also carries the options of `verifyFreshAttestedEAT`.
    /// Result: ok, bound, identity?, reason?.
    public static func eatAdmissionEvidence(_ eat: JSONValue?, verifyKey: Jose.Key, _ o: JSONValue?) -> JSONValue {
        do {
            var minTier = "affirming"
            if let m = try EatJS.prop(o, "minTier") {
                guard let s = EatJS.string(m), s == "affirming" || s == "affirming-hw-rooted" else { return admissionNo(false, "invalid minTier") }
                minTier = s
            }
            var rest: JObject = o?.asObject ?? [:]
            rest["instanceKey"] = nil
            rest["minTier"] = nil
            let instanceKey = try EatJS.prop(o, "instanceKey")
            rest["channelBinding"] = .object(["jkt": .string(ed25519Jkt(instanceKey))])
            let v = try verifyFreshAttestedEAT(eat, verifyKey: verifyKey, .object(rest))
            guard v.get("ok") == JSONValue.bool(true), let tier = EatJS.string(v.get("tier")) else {
                let last = v.get("reasons")?.asArray?.last.flatMap { EatJS.string($0) }
                return admissionNo(false, last ?? "EAT rejected")
            }
            if (TIER_RANK[tier] ?? -1) < (TIER_RANK[minTier] ?? Int.max) { return admissionNo(true, "appraisal tier \(tier) is below the minimum") }
            // verifyFreshAttestedEAT checked cnf.jkt against the instance key, so a pass means bound
            guard case let .object(m)? = EatJS.opt(v.get("claims"), "measured") else { return .object(["ok": .bool(true), "bound": .bool(true)]) }
            var identity: JObject = [:]
            for k in ["runtime_measurement", "model_id", "weights_digest", "operator"] { if let x = m[JKey(k)] { identity[JKey(k)] = x } }
            return .object(["ok": .bool(true), "bound": .bool(true), "identity": .object(identity)])
        } catch {
            return admissionNo(false, (error as? JSError)?.code == "TypeError" ? "TypeError" : "Error")
        }
    }

    /// The running image's digest from an ACCEPTED verdict (`verifyFreshAttestedEAT`): exactly one `measurements` entry labelled
    /// `slot` (default `image`), lowercase hex of the algorithm's length (`sha256`: 64, any other `alg`: 128). Nil when the verdict is
    /// not ok, the slot is missing or repeated, or the value is malformed (no case folding). Result: `{alg, digest}`.
    public static func runtimeDigestFromEat(_ verdict: JSONValue?, _ o: JSONValue? = nil) throws -> JSONValue? {
        guard JS.truthy(verdict), try EatJS.prop(verdict, "ok") == JSONValue.bool(true) else { return nil }
        let claims = try EatJS.prop(verdict, "claims")
        guard JS.truthy(claims) else { return nil }
        let opts: JSONValue = o ?? JSONValue.object([:])
        let slotV = try EatJS.prop(opts, "slot")
        let algV = try EatJS.prop(opts, "alg")
        let slot: JSONValue = JS.present(slotV) ?? JSONValue.string("image")
        let alg: JSONValue = JS.present(algV) ?? JSONValue.string("sha256")
        let msV = try EatJS.prop(claims, "measurements")
        var list: [JSONValue] = []
        if let ms = JS.present(msV) {
            guard case let .array(a) = ms else { throw EatJS.typeError("(verdict.claims.measurements ?? []).filter is not a function") }
            list = a
        }
        var hits: [JSONValue] = []
        for m in list {
            let t = try EatJS.prop(m, "type")
            if EatJS.svz(t, slot) { hits.append(m) }
        }
        if hits.count != 1 { return nil }
        guard let v = EatJS.string(try EatJS.prop(hits[0], "value")) else { return nil }
        let want = alg == JSONValue.string("sha256") ? 64 : 128
        let isLowerHex = v.utf16.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
        guard v.utf16.count == want, isLowerHex else { return nil }
        return .object(["alg": alg, "digest": .string(v)])
    }

    /// The artifact attestation verifier: the Sigstore bundle against the pinned roots, the join of its subjects to the running
    /// digest (`runtime`, from `runtimeDigestFromEat`; an explicit null is a failed join), the verifier's own provenance policy, and
    /// then the signed discharge the request asks for. `i`: bundle, policy, runtime?, request, now (epoch ms), ttl_ms?. `nonce` is
    /// the discharge nonce (random when omitted). Any failure is `{ok: false, stage, code}` (a thrown refusal for a malformed
    /// request or a body the discharge signer refuses): no discharge, so the caveat refuses.
    /// Result: `{ok: true, discharge, facts, level}`.
    public static func issueArtifactDischarge(_ i: JSONValue?, roots: SigstoreRoots, issuer: PCASuiteKey, nonce: String? = nil) throws -> JSONValue {
        let bundle = try EatJS.prop(i, "bundle") ?? JSONValue.null
        let v = PCA.verifySigstoreBundle(bundle, roots: roots)
        if !v.ok {
            return .object(["ok": .bool(false), "stage": .string("sigstore"), "code": .string(v.code), "detail": .string(v.detail)])
        }
        let runtime = try EatJS.prop(i, "runtime")
        if runtime == JSONValue.null { return .object(["ok": .bool(false), "stage": .string("gate"), "code": .string("no_runtime")]) }
        let nowV = try EatJS.prop(i, "now")
        let nowN = JS.toNumber(nowV)
        var input: JObject = ["facts": v.facts, "now": nowN.isFinite ? EatJS.jn((nowN / 1000).rounded(.down)) : JSONValue.null]
        if let p = try EatJS.prop(i, "policy") { input["policy"] = p }
        if let r = runtime { input["runtime"] = r }
        let gate = PCA.provenanceGate(.object(input))
        if !gate.ok { return .object(["ok": .bool(false), "stage": .string("gate"), "code": .string(gate.code)]) }

        // provenanceDischargeBody
        let request = try EatJS.prop(i, "request")
        let reqTtl = try EatJS.prop(request, "ttl_ms")
        let ttlV = try EatJS.prop(i, "ttl_ms")
        guard let ttl = IV.num(JS.present(ttlV) ?? reqTtl), let cap = IV.num(reqTtl), let iat = IV.num(nowV) else {
            throw JSError("provenanceDischargeBody: ttl_ms and iat must be numbers")
        }
        if ttl > cap { throw JSError("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts") }
        var body: JObject = ["v": .int(1), "kind": .string("pca-discharge"), "claims": .object(gate.claims), "iat": EatJS.jn(iat),
                             "not_after": EatJS.jn(iat + ttl)]
        for k in ["caveat_id", "issuer", "cap_hash", "bind", "action_digest"] { if let x = try EatJS.prop(request, k) { body[JKey(k)] = x } }
        var nonceText = nonce ?? ""
        if nonce == nil {
            var r = [UInt8](repeating: 0, count: 16)
            for j in 0..<16 { r[j] = UInt8.random(in: 0...255) }
            nonceText = Base64URLStrict.encode(r)
        }
        body["nonce"] = .string(nonceText)
        let discharge = try PCAIssue.signDischarge(.object(body), issuer: issuer)
        return .object(["ok": .bool(true), "discharge": discharge, "facts": v.facts, "level": .int(gate.level)])
    }
}
