import Foundation

// The post-quantum co-signature of a verified attestation verdict (the reference's `pqcosign`): once the classical AMD hardware root
// has been verified, the verdict that PCA records is bound under an ML-DSA signature (ML-DSA-65 by default), so the record stays
// trustworthy after a quantum break of the classical root. The suites are the ML-DSA and hybrid Ed25519 + ML-DSA suites this SDK
// implements; the SLH-DSA suites are accepted as names (`isPqCoSignSuite`) but refused as `unsupported_suite` (no vetted
// SLH-DSA implementation), exactly as the suite registry refuses them everywhere else.

extension PCAAttestEat {
    public static let PQCOSIGN_DOMAIN = "atlas-pca/attest-cosign/v1"
    public static let DEFAULT_PQ_COSIGN_SUITE = "ml-dsa-65"
    public static let PQ_COSIGN_SUITES: [String] = [
        "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-128f", "slh-dsa-sha2-256s", "hybrid-ed25519-ml-dsa-65", "hybrid-nested-ed25519-ml-dsa-65",
        "hybrid-ed25519-ml-dsa-87", "hybrid-ed25519-slh-dsa-sha2-128f", "hybrid-ed25519-slh-dsa-sha2-256s",
    ]

    /// Member order of the canonical verdict JSON the reference signs.
    static let VERDICT_ORDER = ["typ", "tier", "trustworthy", "measurement", "measured", "nonce", "iat", "issuer", "cosignedAt",
                                "model_id", "weights_digest", "weights_measured", "runtime_measurement", "operator", "system_prompt_digest", "tool_manifest_digest"]

    /// The key material of a co-signature: an Ed25519 key (hybrid suites) and an ML-DSA key.
    public struct CoSignKeys {
        public var ed: PCAEdKey?
        public var pq: PCAPQKey?
        public init(ed: PCAEdKey? = nil, pq: PCAPQKey? = nil) { self.ed = ed; self.pq = pq }
    }

    public static func isPqCoSignSuite(_ x: JSONValue?) -> Bool {
        guard let s = EatJS.string(x) else { return false }
        return PQ_COSIGN_SUITES.contains(s)
    }

    static func canonicalMeasured(_ m: JSONValue) throws -> JSONValue {
        var c: JObject = [:]
        if let v = try EatJS.prop(m, "model_id") { c["model_id"] = v }
        if let v = try EatJS.prop(m, "weights_digest") { c["weights_digest"] = v }
        let wm = try EatJS.prop(m, "weights_measured")
        if let w = wm, case .bool = w { c["weights_measured"] = w } else { c["weights_measured"] = .null }
        if let v = try EatJS.prop(m, "runtime_measurement") { c["runtime_measurement"] = v }
        if let v = try EatJS.prop(m, "operator") { c["operator"] = v }
        if let s = EatJS.string(try EatJS.prop(m, "system_prompt_digest")) { c["system_prompt_digest"] = .string(s) } else { c["system_prompt_digest"] = .null }
        if let s = EatJS.string(try EatJS.prop(m, "tool_manifest_digest")) { c["tool_manifest_digest"] = .string(s) } else { c["tool_manifest_digest"] = .null }
        return .object(c)
    }

    /// The bytes a co-signature covers: the verdict in a fixed shape (domain, tier, trustworthy, measurement, measured, nonce, iat,
    /// issuer) and the co-signing time, as JSON in a fixed member order.
    public static func canonicalVerdictBytes(_ verdict: JSONValue?, _ cosignedAt: JSONValue?) throws -> [UInt8] {
        var o: JObject = ["typ": .string(PQCOSIGN_DOMAIN)]
        if let t = try EatJS.prop(verdict, "tier") { o["tier"] = t }
        let trustworthy = try EatJS.prop(verdict, "trustworthy") == JSONValue.bool(true)
        o["trustworthy"] = .bool(trustworthy)
        if let s = EatJS.string(try EatJS.prop(verdict, "measurement")) { o["measurement"] = .string(s) } else { o["measurement"] = .null }
        if let m = try EatJS.prop(verdict, "measured") { o["measured"] = try canonicalMeasured(m) } else { o["measured"] = .null }
        if let s = EatJS.string(try EatJS.prop(verdict, "nonce")) { o["nonce"] = .string(s) } else { o["nonce"] = .null }
        if let d = EatJS.finite(try EatJS.prop(verdict, "iat")) { o["iat"] = EatJS.jn(d) } else { o["iat"] = .null }
        if let s = EatJS.string(try EatJS.prop(verdict, "issuer")) { o["issuer"] = .string(s) } else { o["issuer"] = .null }
        if let c = cosignedAt { o["cosignedAt"] = c }
        return Array(JS.stringify(.object(o), order: VERDICT_ORDER).utf8)
    }

    /// The verdict a co-signature records for an appraisal result and the claims it was made from.
    public static func verdictFromAppraisal(_ result: JSONValue?, _ claims: JSONValue?) throws -> JSONValue {
        var v: JObject = [:]
        if let t = try EatJS.prop(result, "tier") { v["tier"] = t }
        if let w = try EatJS.prop(result, "trustworthy") { v["trustworthy"] = w }
        let measured = try EatJS.prop(claims, "measured")
        if let m = measured { v["measured"] = m }
        // claims.measured?.runtime_measurement && claims.measured.runtime_measurement.length > 0 ? it : claims.sevsnp?.measurement
        let rm = EatJS.opt(measured, "runtime_measurement")
        var lengthPositive = false
        if JS.truthy(rm), let r = rm {
            switch r {
            case let .string(s): lengthPositive = !s.isEmpty
            case let .array(a): lengthPositive = !a.isEmpty
            default: lengthPositive = false
            }
        }
        let sevsnp = try EatJS.prop(claims, "sevsnp")
        let measurement: JSONValue? = lengthPositive ? rm : EatJS.opt(sevsnp, "measurement")
        if let m = EatJS.string(measurement), !m.isEmpty { v["measurement"] = .string(m) }
        if let n = EatJS.string(try EatJS.prop(claims, "eat_nonce")) { v["nonce"] = .string(n) }
        if let d = EatJS.finite(try EatJS.prop(claims, "iat")) { v["iat"] = EatJS.jn(d) }
        if let i = EatJS.string(try EatJS.prop(claims, "iss")) { v["issuer"] = .string(i) }
        return .object(v)
    }

    /// Co-sign a verdict under a post-quantum suite (default ML-DSA-65). `now` pins the co-signing time. Refuses an unknown suite, a
    /// suite whose key material is missing or of another level, and a suite this SDK cannot sign. Result: verdict, cosig, suite,
    /// signer_pub.
    public static func coSignAttestation(_ verdict: JSONValue?, suite: JSONValue? = nil, keys: CoSignKeys?, now: JSONValue? = nil) throws -> JSONValue {
        let name: JSONValue = JS.present(suite) ?? JSONValue.string(DEFAULT_PQ_COSIGN_SUITE)
        guard isPqCoSignSuite(name), let alg = EatJS.string(name) else {
            throw JSError("coSignAttestation: '\(JS.toString(name))' is not an accepted post-quantum co-sign suite")
        }
        guard let k = keys else { throw EatJS.typeError("coSignAttestation: secretKey material is required") }
        let signer = try PCASuiteKey(alg: alg, ed: k.ed, pq: k.pq)
        guard let pq = k.pq else { throw EatJS.typeError("coSignAttestation: suite '\(alg)' requires post-quantum key material") }
        let at = EatJS.jn(EatJS.finite(now) ?? EatJS.clockMs())
        let msg = try canonicalVerdictBytes(verdict, at)
        let parts = try signer.sign(msg)
        var signerPub: JObject = ["pq": .string(pq.pkB64u)]
        if alg.hasPrefix("hybrid"), let e = k.ed { signerPub["ed"] = .string(e.id) }
        var cosig: JObject = ["cosignedAt": at, "sig": .string(parts.sig)]
        if let q = parts.pqSig { cosig["pq_sig"] = .string(q) }
        var out: JObject = ["cosig": .object(cosig), "suite": .string(alg), "signer_pub": .object(signerPub)]
        if let v = verdict { out["verdict"] = v }
        return .object(out)
    }

    static func signerMatches(_ expected: JSONValue, _ pq: String, _ ed: String?) throws -> Bool {
        var expPq: JSONValue? = nil
        var isString = false
        if case .string = expected { expPq = expected; isString = true } else { expPq = try EatJS.prop(expected, "pq") }
        guard let ep = EatJS.string(expPq), EatJS.utf8Eq(ep, pq) else { return false }
        if !isString, let ee = EatJS.string(try EatJS.prop(expected, "ed")) {
            guard let g = ed, EatJS.utf8Eq(ee, g) else { return false }
        }
        return true
    }

    /// Verify a co-signed verdict: the shape, the suite, an optional pinned signer (`expectedSigner`: the ML-DSA public key, or
    /// `{pq, ed?}`), an optional maximum age, and the signature(s) over the canonical verdict. The artifact's own key is used
    /// when no signer is pinned. Never throws. Result: ok, reason?, suite?, verdict?, signer_pub?, cosignedAt?, ageMs?.
    public static func verifyCoSignedAttestation(_ cosigned: JSONValue?, _ opts: JSONValue? = nil) -> JSONValue {
        func fail(_ reason: String, _ partial: JObject = [:]) -> JSONValue {
            var o = partial
            o["ok"] = .bool(false)
            o["reason"] = .string(reason)
            return .object(o)
        }
        do {
            guard EatJS.isRecord(cosigned) else { return fail("co-signed attestation is not an object") }
            let verdict = try EatJS.prop(cosigned, "verdict")
            guard EatJS.isRecord(verdict), EatJS.string(EatJS.opt(verdict, "tier")) != nil, case .bool? = EatJS.opt(verdict, "trustworthy") else {
                return fail("verdict is missing or has a non-string tier / non-boolean trustworthy")
            }
            let cosig = try EatJS.prop(cosigned, "cosig")
            guard EatJS.isRecord(cosig), let atV = EatJS.opt(cosig, "cosignedAt"), let at = EatJS.finite(atV), let sig = EatJS.string(EatJS.opt(cosig, "sig")) else {
                return fail("cosig is missing or has a non-numeric cosignedAt / non-string sig")
            }
            let suiteV = try EatJS.prop(cosigned, "suite")
            guard isPqCoSignSuite(suiteV), let alg = EatJS.string(suiteV) else {
                return fail("suite '\(JS.toString(suiteV))' is not an accepted post-quantum co-sign suite")
            }
            let sp = try EatJS.prop(cosigned, "signer_pub")
            guard EatJS.isRecord(sp), let pq = EatJS.string(EatJS.opt(sp, "pq")), !pq.isEmpty else {
                return fail("signer_pub is missing or has no post-quantum public key")
            }
            var ed: String? = nil
            if let e = EatJS.string(EatJS.opt(sp, "ed")), !e.isEmpty { ed = e }
            var signerOut: JObject = ["pq": .string(pq)]
            if let e = ed { signerOut["ed"] = .string(e) }

            let o: JSONValue = opts ?? JSONValue.object([:])
            let now = EatJS.finite(try EatJS.prop(o, "now")) ?? EatJS.clockMs()
            let age = now - at
            var partial: JObject = ["suite": .string(alg), "signer_pub": .object(signerOut), "cosignedAt": atV, "ageMs": EatJS.jn(age)]
            if let v = verdict { partial["verdict"] = v }

            if let ex = try EatJS.prop(o, "expectedSigner") {
                let matches = try signerMatches(ex, pq, ed)
                if !matches { return fail("co-signer public key does not match the expected signer", partial) }
            }
            if let mv = try EatJS.prop(o, "maxAgeMs") {
                guard let m = EatJS.finite(mv), m > 0 else { return fail("invalid maxAgeMs", partial) }
                if !(at <= now) { return fail("co-sign timestamp is in the future", partial) }
                if !(age <= m) { return fail("co-signature is stale (older than maxAgeMs)", partial) }
            }
            let msg = try canonicalVerdictBytes(verdict, atV)
            let pqSig = EatJS.string(EatJS.opt(cosig, "pq_sig"))
            if !PQ.verifyLeaf(alg: alg, holder: ed ?? "", pqPublicKey: pq, message: msg, sig: sig, pqSig: pqSig) {
                return fail("post-quantum co-signature does not verify (tampered verdict, wrong key, or bad signature)", partial)
            }
            partial["ok"] = .bool(true)
            return .object(partial)
        } catch {
            return fail("co-signature verification error (fail closed): " + ((error as? JSError)?.message ?? "unknown"))
        }
    }
}
