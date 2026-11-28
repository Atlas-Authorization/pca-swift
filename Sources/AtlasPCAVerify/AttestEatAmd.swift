import Foundation

// The AMD SEV-SNP hardware-root step of an EAT pipeline and the composed `verifyFreshAttestedEAT`: signature, freshness, channel
// binding, optional silicon verification, appraisal. The certificate chain, report signature and VCEK binding are the package's own
// AMD verifier (AttestAmd.swift); this file composes them with the reference's input handling and reason texts.

extension PCAAttestEat {
    /// `{"$bytes": b64url}`: the JSON form of a binary value inside an options object.
    public static func bytesValue(_ b: [UInt8]) -> JSONValue { .object(["$bytes": .string(Base64URLStrict.encode(b))]) }

    /// A certificate as the reference takes it: one PEM block (string) or DER (`{"$bytes"}`).
    static func certDer(_ v: JSONValue?) throws -> [UInt8] {
        if case let .string(s)? = v {
            let blocks = Cert.pemBlocks(s)
            if blocks.count != 1 { throw JSError("expected exactly one PEM certificate, found \(blocks.count)") }
            let block = blocks[0]
            let body = String(block.dropFirst(Cert.BEGIN.count).dropLast(Cert.END.count))
            if body.isEmpty { throw JSError("pemToDer: no certificate found") }
            return Attest.nodeB64(Attest.stripJSSpace(body))
        }
        if let b = EatJS.bytesOf(v) { return b }
        throw JSError("invalid certificate input")
    }

    /// DER -> one PEM block, base64 with a line break after every full 64 characters (as the reference writes it).
    static func derToPem(_ der: [UInt8]) -> String {
        let b64 = Array(Data(der).base64EncodedString().utf8)
        var body = ""
        var i = 0
        while i + 64 <= b64.count {
            body += String(decoding: b64[i..<(i + 64)], as: UTF8.self) + "\n"
            i += 64
        }
        body += String(decoding: b64[i...], as: UTF8.self)
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n"
    }

    /// Verify an AMD SEV-SNP report against its VCEK -> ASK -> ARK chain: exactly one of `family` (`milan` | `genoa` | `turin`) or
    /// `trustAnchorArkSpkiSha384`, the verifier clock `nowMs`, optional `clockSkewMs`, `expectedMeasurement`, `allowDebug`. `vcek`,
    /// `ask` and `ark` are a PEM string or DER (`{"$bytes"}`); `rawReport` is `{"$bytes"}`. Result: ok, hardwareRoot, reason?,
    /// evidence?, measured?. Fails closed; never throws.
    public static func verifyAmdAttestation(_ rawReport: JSONValue?, _ opts: JSONValue?) -> JSONValue {
        let root = AMD_SEV_SNP_HARDWARE_ROOT_LABEL
        func fail(_ reason: String) -> JSONValue { .object(["ok": .bool(false), "reason": .string(reason), "hardwareRoot": .string(root)]) }
        do {
            let family = try EatJS.prop(opts, "family")
            let pinV = try EatJS.prop(opts, "trustAnchorArkSpkiSha384")
            if (family != nil) == (pinV != nil) {
                return fail("exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)")
            }
            var pin = ""
            if let f = family {
                guard let p = AmdVerifier.ARK_SPKI_SHA384[JS.toString(f)] else { return fail("unknown AMD family \(JS.toString(f)) (expected milan | genoa | turin)") }
                pin = p
            } else if let p = EatJS.string(pinV) {
                pin = p
            } else {
                return fail("AMD attestation verification error (fail closed): trustAnchorArkSpkiSha384 must be a string")
            }
            let vcekDer: [UInt8]
            let askArkPem: String
            do {
                vcekDer = try certDer(try EatJS.prop(opts, "vcek"))
                let ask = try certDer(try EatJS.prop(opts, "ask"))
                let ark = try certDer(try EatJS.prop(opts, "ark"))
                askArkPem = derToPem(ask) + derToPem(ark)
            } catch let e as JSError {
                return fail("certificate parse failed: \(e.message)")
            }
            var measurements: [String] = []
            if let m = EatJS.string(try EatJS.prop(opts, "expectedMeasurement")), !m.isEmpty { measurements = [m.lowercased()] }
            let allowDebug = try EatJS.prop(opts, "allowDebug") == JSONValue.bool(true)
            let nowV = try EatJS.prop(opts, "nowMs")
            let skew = try EatJS.prop(opts, "clockSkewMs")

            // verifyGenuineSevSnpReport
            guard let raw = EatJS.bytesOf(rawReport) else { return fail("report parse failed: parseSevSnpReport: expected Uint8Array") }
            let rep: AmdVerifier.Report
            do { rep = try AmdVerifier.parseReport(raw) } catch { return fail("report parse failed: " + AmdVerifier.msg(error)) }
            if raw.count != AmdVerifier.REPORT_LEN { return fail("report length \(raw.count) is not the canonical \(AmdVerifier.REPORT_LEN)") }
            let rTail = raw[(AmdVerifier.OFF_SIG_R + 48)..<AmdVerifier.OFF_SIG_S]
            let sTail = raw[(AmdVerifier.OFF_SIG_S + 48)...]
            if rTail.contains(where: { $0 != 0 }) || sTail.contains(where: { $0 != 0 }) { return fail("report signature block has non-zero reserved bytes") }
            guard let nowMs = EatJS.finite(nowV) else { return fail("cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check") }
            let clamped = Int64(max(-9_007_199_254_740_991, min(9_007_199_254_740_991, nowMs.rounded(.towardZero))))
            let chain = AmdVerifier.verifyChain(vcekDer, askArkPem, pin, clamped, skew)
            guard chain.reason.isEmpty, let point = chain.point, let tbs = chain.tbs else { return fail("cert chain invalid: " + chain.reason) }
            if !AmdVerifier.verifySignature(rep, point: point) { return fail("report signature does not verify under VCEK") }
            let bind = AmdVerifier.checkVcekReportBinding(tbs, rep)
            if !bind.isEmpty { return fail(bind) }
            var policy = AmdVerifier.Policy(allowDebug: allowDebug, requireEcdsaP384: true)
            policy.measurements = measurements
            let pol = policy.check(rep)
            if !pol.isEmpty { return fail(pol) }
            return .object(["ok": .bool(true), "hardwareRoot": .string(root), "evidence": fullEvidence(raw), "measured": measuredFromReportBytes(raw)])
        } catch {
            return fail("AMD attestation verification error (fail closed): " + ((error as? JSError)?.message ?? "unknown"))
        }
    }

    static func verdictJSON(_ ok: Bool, _ tier: String?, _ reasons: [String], _ claims: JSONValue?) -> JSONValue {
        var o: JObject = ["ok": .bool(ok), "reasons": .array(reasons.map { JSONValue.string($0) })]
        if let t = tier { o["tier"] = .string(t) }
        if let c = claims { o["claims"] = c }
        return .object(o)
    }

    /// The end-to-end gate: the EAT's signature, then freshness (nonce + iat), channel binding (cnf vs the live channel), the
    /// optional AMD silicon verification (`amd`: rawReport, vcek, ask, ark, family | trustAnchorArkSpkiSha384, ...) and finally the
    /// RATS appraisal of `policy` (`referenceValues`, `endorsements`). The first failing gate stops the pipeline and names the reason.
    /// `opts`: nonce, channelId / channelBinding, policy, now, maxAgeMs, clockSkewMs, issuer, algorithms, typ, requireTyp, amd.
    /// Result: ok, tier?, reasons, claims?.
    public static func verifyFreshAttestedEAT(_ eat: JSONValue?, verifyKey: Jose.Key, _ opts: JSONValue?) throws -> JSONValue {
        var reasons: [String] = []
        let claims: JSONValue
        do {
            var vo: JObject = [:]
            for k in ["issuer", "algorithms", "typ", "requireTyp"] { if let v = try EatJS.prop(opts, k) { vo[JKey(k)] = v } }
            claims = try verifyEAT(eat, key: verifyKey, .object(vo))
        } catch {
            return verdictJSON(false, nil, ["EAT signature/claims invalid: " + ((error as? JSError)?.message ?? "unknown")], nil)
        }
        reasons.append("signature + typ/iss verified")

        let now = EatJS.finite(try EatJS.prop(opts, "now")) ?? EatJS.clockMs()
        let maxAgeV = try EatJS.prop(opts, "maxAgeMs")
        var fo: JObject = ["now": EatJS.jn(now), "maxAgeMs": JS.present(maxAgeV) ?? EatJS.jn(DEFAULT_MAX_AGE_MS)]
        if let n = try EatJS.prop(opts, "nonce") { fo["expectedNonce"] = n }
        if let s = try EatJS.prop(opts, "clockSkewMs") { fo["clockSkewMs"] = s }
        let fresh = try verifyFreshness(claims, .object(fo))
        if fresh.get("ok") != JSONValue.bool(true) {
            return verdictJSON(false, nil, reasons + [EatJS.string(fresh.get("reason")) ?? "not fresh"], claims)
        }
        reasons.append("fresh (nonce + iat within window)")

        var co: JObject = [:]
        if let c = try EatJS.prop(opts, "channelId") { co["channelId"] = c }
        if let b = try EatJS.prop(opts, "channelBinding") { co["expectedCnf"] = b }
        let chan = try verifyChannelBinding(claims, .object(co))
        if chan.get("ok") != JSONValue.bool(true) {
            return verdictJSON(false, nil, reasons + [EatJS.string(chan.get("reason")) ?? "channel binding failed"], claims)
        }
        reasons.append("channel-bound (cnf matches live channel)")

        var extras: JSONValue? = nil
        if let amd = try EatJS.prop(opts, "amd") {
            let em = try EatJS.prop(amd, "expectedMeasurement")
            let expected = try JS.present(em) ?? launchMeasurement(claims)
            var ao: JObject = ["nowMs": EatJS.jn(now)]
            for k in ["vcek", "ask", "ark", "family", "trustAnchorArkSpkiSha384", "clockSkewMs", "allowDebug"] {
                if let v = try EatJS.prop(amd, k) { ao[JKey(k)] = v }
            }
            if let e = expected { ao["expectedMeasurement"] = e }
            let rawReport = try EatJS.prop(amd, "rawReport")
            let hw = verifyAmdAttestation(rawReport, .object(ao))
            if hw.get("ok") != JSONValue.bool(true) {
                return verdictJSON(false, "contraindicated", reasons + ["AMD hardware root verification failed: " + (EatJS.string(hw.get("reason")) ?? "unknown")], claims)
            }
            let label = EatJS.string(hw.get("hardwareRoot")) ?? AMD_SEV_SNP_HARDWARE_ROOT_LABEL
            reasons.append("AMD SEV-SNP hardware root verified (\(label))")
            extras = .object(["hardwareVerified": .bool(true), "hardwareRootLabel": .string(label)])
        }

        let policy = try EatJS.prop(opts, "policy")
        let rv = JS.present(try EatJS.prop(policy, "referenceValues")) ?? JSONValue.object([:])
        let en = JS.present(try EatJS.prop(policy, "endorsements")) ?? JSONValue.object([:])
        let app = try appraise(claims, rv, en, extras)
        var all = reasons
        for r in app.get("reasons")?.asArray ?? [] { if let s = r.asString { all.append(s) } }
        return verdictJSON(app.get("trustworthy") == JSONValue.bool(true), EatJS.string(app.get("tier")), all, claims)
    }
}
